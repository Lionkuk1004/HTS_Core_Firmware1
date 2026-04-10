// =========================================================================
// HTS_Rx_Matched_Filter.cpp
// B-CDMA 교차 상관 정합 필터 구현부 (Pimpl 은닉)
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
#include "HTS_Rx_Matched_Filter.h"

// 내부 전용 includes (헤더에 미노출)
#include "HTS_Dynamic_Config.h"
#include "HTS_Secure_Memory.h"

// ── Self-Contained 표준 헤더 (<atomic>, <cstdint> 등) ────────────────
#include <atomic>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>   // memcpy
#include <cstdlib>   // std::abort (비-ARM 시뮬)
#include <new>

namespace {
/// 소멸자: 짧은 스핀 후 미획득 시 AIRCR 시스템 리셋(강제 파쇄·UAF 경로 없음). PC는 abort.
constexpr uint32_t kDestructorSpinTries = 8u;

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || \
    defined(__ARM_ARCH)
// HTS_Hardware_Init::Terminal_Fault_Action 과 동일 순서 (기준서 AIRCR → DBGMCU → dsb/isb → 대기)
[[noreturn]] static void HTS_Rx_MF_Destructor_Lock_Contention_Fault() noexcept {
    static constexpr uintptr_t ADDR_AIRCR = 0xE000ED0Cu;
    static constexpr uint32_t  AIRCR_RESET =
        (0x05FAu << 16) | (1u << 2);
    volatile uint32_t* const aircr =
        reinterpret_cast<volatile uint32_t*>(ADDR_AIRCR);
    *aircr = AIRCR_RESET;
#if defined(__GNUC__) || defined(__clang__)
    static constexpr uintptr_t ADDR_DBGMCU_FZ = 0xE0042008u;
    static constexpr uint32_t DBGMCU_WWDG_STOP = (1u << 11);
    static constexpr uint32_t DBGMCU_IWDG_STOP = (1u << 12);
    volatile uint32_t* const dbgmcu_fz =
        reinterpret_cast<volatile uint32_t*>(ADDR_DBGMCU_FZ);
    *dbgmcu_fz &= ~(DBGMCU_WWDG_STOP | DBGMCU_IWDG_STOP);
    __asm__ __volatile__("dsb sy\n\tisb\n\t" ::: "memory");
#endif
    for (;;) {
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("wfi");
#else
        __asm__ __volatile__("nop");
#endif
    }
}
#endif
} // namespace

namespace ProtectedEngine {

    namespace {

        /// Set_Reference_Sequence / Apply_Filter 상호 배제 (N-1, A-3)
        struct OpBusyGuard final {
            std::atomic_flag* f_;
            explicit OpBusyGuard(std::atomic_flag& fl) noexcept : f_(&fl) {
                while (f_->test_and_set(std::memory_order_acquire)) {
                }
            }
            ~OpBusyGuard() noexcept { f_->clear(std::memory_order_release); }
            OpBusyGuard(const OpBusyGuard&) = delete;
            OpBusyGuard& operator=(const OpBusyGuard&) = delete;
        };

        constexpr int64_t kClampMaxI32 = static_cast<int64_t>(INT32_MAX);
        constexpr int64_t kClampMinI32 = static_cast<int64_t>(INT32_MIN);
    } // namespace

    // =====================================================================
    //  Pimpl 구현 구조체
    //   Walsh-64 정합 필터: 최대 64 칩 참조 시퀀스
    //   64 × 4B = 256B 정적 배열 → 힙 0, 파편화 0
    // =====================================================================
    struct HTS_Rx_Matched_Filter::Impl {
        static constexpr size_t MAX_REF_SEQ = 64u;

        HTS_Sys_Config current_config = {};
        int32_t        reference_sequence[MAX_REF_SEQ] = {};
        size_t         ref_len = 0u;

        explicit Impl(HTS_Sys_Tier tier) noexcept
            : current_config(
                HTS_Sys_Config_Factory::Get_Tier_Profile(tier))
            , ref_len(0u) {
        }

        ~Impl() noexcept {
            SecureMemory::secureWipe(
                static_cast<void*>(reference_sequence),
                MAX_REF_SEQ * sizeof(int32_t));
            ref_len = 0u;
        }
    };

    // =====================================================================
    // =====================================================================
    HTS_Rx_Matched_Filter::Impl*
        HTS_Rx_Matched_Filter::get_impl() noexcept {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE(320B)를 초과합니다 — 버퍼 크기를 늘려주세요");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 요구가 impl_buf_ alignas(8)을 초과합니다");
        return impl_valid_.load(std::memory_order_acquire)
            ? std::launder(reinterpret_cast<Impl*>(impl_buf_)) : nullptr;
    }

    const HTS_Rx_Matched_Filter::Impl*
        HTS_Rx_Matched_Filter::get_impl() const noexcept {
        return impl_valid_.load(std::memory_order_acquire)
            ? reinterpret_cast<const Impl*>(impl_buf_)
            : nullptr;
    }

    // =====================================================================
    //
    //  impl_buf_ SecWipe → ::new Impl(tier) → impl_valid_ = true
    //  Impl(tier) 생성자는 noexcept → 예외 없이 안전
    // =====================================================================
    HTS_Rx_Matched_Filter::HTS_Rx_Matched_Filter(
        HTS_Sys_Tier tier) noexcept
        : impl_valid_(false)
    {
        SecureMemory::secureWipe(static_cast<void*>(impl_buf_), sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl(tier);
        impl_valid_.store(true, std::memory_order_release);
    }

    // =====================================================================
    // =====================================================================
    HTS_Rx_Matched_Filter::~HTS_Rx_Matched_Filter() noexcept {
        uint32_t spins = 0;
        while (op_busy_.test_and_set(std::memory_order_acquire)) {
            if (++spins >= kDestructorSpinTries) {
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || \
    defined(__ARM_ARCH)
                HTS_Rx_MF_Destructor_Lock_Contention_Fault();
#else
                std::abort();
#endif
            }
        }
        Impl* const p = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        const bool was_valid = impl_valid_.exchange(false, std::memory_order_acq_rel);
        if (was_valid) { p->~Impl(); }
        SecureMemory::secureWipe(static_cast<void*>(impl_buf_), sizeof(impl_buf_));
        op_busy_.clear(std::memory_order_release);
    }

    // =====================================================================
    //  Set_Reference_Sequence — Copy-and-Swap (alias-safe)
    // =====================================================================
    bool HTS_Rx_Matched_Filter::Set_Reference_Sequence(
        const int32_t* seq_data, size_t size) noexcept
    {
        // 락 선행: get_impl() 전에 획득 — 소멸자와의 TOCTOU/UAF 차단
        OpBusyGuard guard(op_busy_);

        Impl* p = get_impl();
        if (p == nullptr || seq_data == nullptr || size == 0u) {
            return false;
        }

        if (size > Impl::MAX_REF_SEQ) { return false; }

        int32_t shadow[Impl::MAX_REF_SEQ] = {};
        std::memcpy(shadow, seq_data, size * sizeof(int32_t));

        SecureMemory::secureWipe(
            static_cast<void*>(p->reference_sequence),
            Impl::MAX_REF_SEQ * sizeof(int32_t));

        std::memcpy(p->reference_sequence, shadow,
            size * sizeof(int32_t));
        SecureMemory::secureWipe(static_cast<void*>(shadow), sizeof(shadow));
        p->ref_len = size;
        return true;
    }

    // =====================================================================
    //  Apply_Filter — Q16 교차 상관 (탭마다 곱 → 라운딩 → >>16 후 누적)
    //
    //  오버플로: 탭당 (rx*ref + bias)>>16 을 int64에 누적, ref_len ≤ 64 → int64 안전
    // =====================================================================
    static_assert((-1 >> 1) == -1,
        "[HTS_FATAL] Compiler does not use arithmetic right shift (ASR) "
        "for signed integers. Q16 MAC requires ASR guarantee.");

    bool HTS_Rx_Matched_Filter::Apply_Filter(
        const int32_t* __restrict rx_q16_data, size_t rx_size,
        int32_t* __restrict out_correlation) noexcept
    {
        // 락 선행: get_impl() 전에 획득 — 소멸자와의 TOCTOU/UAF 차단
        OpBusyGuard guard(op_busy_);

        Impl* p = get_impl();
        if (p == nullptr || rx_q16_data == nullptr
            || out_correlation == nullptr || rx_size == 0u) {
            return false;
        }

        if (p->ref_len == 0u) { return false; }

        const size_t seq_len = p->ref_len;
        if (rx_size < seq_len) { return false; }

        const size_t num_outputs = rx_size - seq_len + static_cast<size_t>(1u);
        const int32_t* __restrict ref = p->reference_sequence;

        static constexpr int64_t Q16_ROUND_BIAS = 0x8000LL;

        for (size_t i = 0u; i < num_outputs; ++i) {
            int64_t acc = 0LL;

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC ivdep
#endif
            for (size_t j = 0u; j < seq_len; ++j) {
                const int64_t rxv = static_cast<int64_t>(
                    rx_q16_data[static_cast<size_t>(i + j)]);
                const int64_t rf = static_cast<int64_t>(
                    ref[static_cast<size_t>(j)]);
                const int64_t prod = rxv * rf;
                acc += (prod + Q16_ROUND_BIAS) >> 16;
            }

            if (acc > kClampMaxI32) { acc = kClampMaxI32; }
            else if (acc < kClampMinI32) { acc = kClampMinI32; }
            out_correlation[static_cast<size_t>(i)] = static_cast<int32_t>(acc);
        }

        return true;
    }

} // namespace ProtectedEngine
