// =========================================================================
// HTS_Rx_Matched_Filter.cpp
// B-CDMA 교차 상관 정합 필터 구현부 (Pimpl 은닉)
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
#include "HTS_Rx_Matched_Filter.h"

// 내부 전용 includes (헤더에 미노출)
#include "HTS_Dynamic_Config.h"

// ── Self-Contained 표준 헤더 [BUG-08] ───────────────────────────────
#include <atomic>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>   // [FIX-C] memcpy
#include <new>

namespace ProtectedEngine {

    // =====================================================================
    //  보안 메모리 소거 (volatile void* + asm clobber + seq_cst)
    // =====================================================================
    static void Secure_Wipe_MF(volatile void* ptr, size_t size) noexcept {
        if (ptr == nullptr || size == 0u) { return; }
        volatile unsigned char* p =
            static_cast<volatile unsigned char*>(ptr);
        for (size_t i = 0u; i < size; ++i) { p[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

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
            Secure_Wipe_MF(reference_sequence,
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
            ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }

    const HTS_Rx_Matched_Filter::Impl*
        HTS_Rx_Matched_Filter::get_impl() const noexcept {
        return impl_valid_.load(std::memory_order_acquire)
            ? reinterpret_cast<const Impl*>(impl_buf_)
            : nullptr;
    }

    // =====================================================================
    //
    //  기존: std::make_unique<Impl>(tier) + try-catch
    //  수정: impl_buf_ SecWipe → ::new Impl(tier) → impl_valid_ = true
    //  Impl(tier) 생성자는 noexcept → 예외 없이 안전
    // =====================================================================
    HTS_Rx_Matched_Filter::HTS_Rx_Matched_Filter(
        HTS_Sys_Tier tier) noexcept
        : impl_valid_(false)
    {
        Secure_Wipe_MF(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl(tier);
        impl_valid_.store(true, std::memory_order_release);
    }

    // =====================================================================
    // =====================================================================
    HTS_Rx_Matched_Filter::~HTS_Rx_Matched_Filter() noexcept {
        Impl* const p = reinterpret_cast<Impl*>(impl_buf_);
        const bool was_valid = impl_valid_.exchange(false, std::memory_order_acq_rel);
        if (was_valid) { p->~Impl(); }
        Secure_Wipe_MF(impl_buf_, sizeof(impl_buf_));
    }

    // =====================================================================
    //  Set_Reference_Sequence — [BUG-12] Copy-and-Swap: 예외 안전성
    //  기존: Wipe → assign → aliasing 시 원본 증발
    //  수정: 임시 벡터에 먼저 복사 → 성공 시 기존 소거 → swap
    // =====================================================================
    bool HTS_Rx_Matched_Filter::Set_Reference_Sequence(
        const int32_t* seq_data, size_t size) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr || seq_data == nullptr || size == 0u) {
            return false;
        }

        if (size > Impl::MAX_REF_SEQ) { return false; }

        // Alias-safe 복사: 입력이 내부 버퍼를 가리켜도 데이터 붕괴 방지
        int32_t shadow[Impl::MAX_REF_SEQ] = {};
        std::memcpy(shadow, seq_data, size * sizeof(int32_t));

        // 기존 데이터 보안 소거
        Secure_Wipe_MF(p->reference_sequence,
            Impl::MAX_REF_SEQ * sizeof(int32_t));

        // 복사 (zero-heap)
        std::memcpy(p->reference_sequence, shadow,
            size * sizeof(int32_t));
        Secure_Wipe_MF(shadow, sizeof(shadow));
        p->ref_len = size;
        return true;
    }

    // =====================================================================
    //  Apply_Filter — Q16 교차 상관
    //
    //
    //  오버플로 안전성 검증:
    //    ref = PN코드 → |ref| ≤ 65536 (Q16 1.0)
    //    rx = 최악 INT32_MAX = 2^31
    //    |rx × ref| ≤ 2^47
    //    4096회 누적: 2^47 × 2^12 = 2^59 << 2^63 (INT64_MAX) → 안전
    // =====================================================================
    static_assert((-1 >> 1) == -1,
        "[HTS_FATAL] Compiler does not use arithmetic right shift (ASR) "
        "for signed integers. Q16 MAC requires ASR guarantee.");

    bool HTS_Rx_Matched_Filter::Apply_Filter(
        const int32_t* __restrict rx_q16_data, size_t rx_size,
        int32_t* __restrict out_correlation) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr || rx_q16_data == nullptr
            || out_correlation == nullptr || rx_size == 0u) {
            return false;
        }

        if (p->ref_len == 0u) { return false; }

        const size_t seq_len = p->ref_len;
        if (rx_size < seq_len) { return false; }

        const size_t num_outputs = rx_size - seq_len + 1u;
        const int32_t* __restrict ref = p->reference_sequence;

        static constexpr int64_t Q16_ROUND_BIAS = 0x8000LL;

        for (size_t i = 0u; i < num_outputs; ++i) {
            int64_t acc = 0;

            // 순수 MAC 루프 → Cortex-M4 SMLAL 자동 생성
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC ivdep
#endif
            for (size_t j = 0u; j < seq_len; ++j) {
                acc += static_cast<int64_t>(rx_q16_data[i + j]) * ref[j];
            }

            // 루프 후 1회 >>16 + 반올림 바이어스 (항별 누산 → 정확도 최대)
            acc = (acc + Q16_ROUND_BIAS) >> 16;

            // int64 → int32 포화 클램핑
            if (acc > INT32_MAX) { acc = INT32_MAX; }
            else if (acc < INT32_MIN) { acc = INT32_MIN; }
            out_correlation[i] = static_cast<int32_t>(acc);
        }

        return true;
    }

} // namespace ProtectedEngine
