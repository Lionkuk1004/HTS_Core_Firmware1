// =========================================================================
// HTS_Rx_Matched_Filter.cpp
// B-CDMA 교차 상관 정합 필터 구현부 (Pimpl 은닉)
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// [양산 수정 이력 — 12건]
//  BUG-01~11 (이전 세션)
//  BUG-12 [CRIT] unique_ptr + make_unique + try-catch(ctor) → placement new
//         · impl_buf_[256] alignas(8) 정적 배치
//           Impl = HTS_Sys_Config(32B) + vector(24B) ≈ 64B → 여유 충분
//         · 생성자: impl_buf_ SecWipe → ::new Impl(tier) → impl_valid_=true
//           Impl 생성자는 noexcept → 예외 없이 안전
//         · 소멸자: = default 제거 → 명시적 p->~Impl() + Secure_Wipe_MF
// =========================================================================
#include "HTS_Rx_Matched_Filter.h"

// 내부 전용 includes (헤더에 미노출)
#include "HTS_Dynamic_Config.h"

// ── Self-Contained 표준 헤더 [BUG-08] ───────────────────────────────
#include <atomic>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <new>
#include <vector>

namespace ProtectedEngine {

    // =====================================================================
    //  보안 메모리 소거 (volatile void* + asm clobber + seq_cst)
    //  [BUG-11] volatile void* 시그니처 (강제 캐스팅 UB 방지)
    // =====================================================================
    static void Secure_Wipe_MF(volatile void* ptr, size_t size) noexcept {
        if (ptr == nullptr || size == 0u) { return; }
        volatile unsigned char* p =
            static_cast<volatile unsigned char*>(ptr);
        for (size_t i = 0u; i < size; ++i) { p[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        // [BUG-13] seq_cst → release (소거 배리어 정책 통일)
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  Pimpl 구현 구조체
    // =====================================================================
    struct HTS_Rx_Matched_Filter::Impl {
        HTS_Sys_Config       current_config = {};
        std::vector<int32_t> reference_sequence;

        explicit Impl(HTS_Sys_Tier tier) noexcept
            : current_config(
                HTS_Sys_Config_Factory::Get_Tier_Profile(tier)) {
        }

        ~Impl() noexcept {
            if (!reference_sequence.empty()) {
                Secure_Wipe_MF(reference_sequence.data(),
                    reference_sequence.size() * sizeof(int32_t));
            }
        }
    };

    // =====================================================================
    //  [BUG-12] 컴파일 타임 크기·정렬 검증 + get_impl()
    // =====================================================================
    HTS_Rx_Matched_Filter::Impl*
        HTS_Rx_Matched_Filter::get_impl() noexcept {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE(256B)를 초과합니다 — 버퍼 크기를 늘려주세요");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 요구가 impl_buf_ alignas(8)을 초과합니다");
        return impl_valid_ ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }

    const HTS_Rx_Matched_Filter::Impl*
        HTS_Rx_Matched_Filter::get_impl() const noexcept {
        return impl_valid_
            ? reinterpret_cast<const Impl*>(impl_buf_)
            : nullptr;
    }

    // =====================================================================
    //  [BUG-12] 생성자 — placement new (zero-heap)
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
        impl_valid_ = true;
    }

    // =====================================================================
    //  [BUG-12] 소멸자 — 명시적 (= default 제거)
    // =====================================================================
    HTS_Rx_Matched_Filter::~HTS_Rx_Matched_Filter() noexcept {
        Impl* p = get_impl();
        if (p != nullptr) { p->~Impl(); }
        Secure_Wipe_MF(impl_buf_, sizeof(impl_buf_));
        impl_valid_ = false;
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

        // [BUG-13] try-catch 삭제 — 직접 실행
        // Copy-and-Swap: 예외 안전성 유지 (vector swap = noexcept)
        std::vector<int32_t> new_seq(seq_data, seq_data + size);

        if (!p->reference_sequence.empty()) {
            Secure_Wipe_MF(p->reference_sequence.data(),
                p->reference_sequence.size() * sizeof(int32_t));
        }

        p->reference_sequence.swap(new_seq);
        return true;
    }

    // =====================================================================
    //  Apply_Filter — Q16 교차 상관
    //
    //  [BUG-09] 컴파일 타임 ASR 검증 (MISRA 5-0-21)
    //  [BUG-13] 순수 MAC 루프 → SMLAL 자동 생성 + 루프 후 1회 >>16
    //  [BUG-14] __restrict 앨리어싱 힌트 → 레지스터 최적화
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

        const auto& ref_seq = p->reference_sequence;
        if (ref_seq.empty()) { return false; }

        const size_t seq_len = ref_seq.size();
        if (rx_size < seq_len) { return false; }

        const size_t num_outputs = rx_size - seq_len + 1u;
        const int32_t* __restrict ref = ref_seq.data();

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