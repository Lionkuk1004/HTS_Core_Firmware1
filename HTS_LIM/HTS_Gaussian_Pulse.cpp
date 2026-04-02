// =========================================================================
// HTS_Gaussian_Pulse.cpp
// 가우시안 펄스 셰이핑 엔진 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
//

#include "HTS_Gaussian_Pulse.h"
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

// [NOTE] ARM: fp32/fp64 사용 금지. 펄스 계수는 정수 고정소수점으로 생성.

namespace ProtectedEngine {

    // ASR 컴파일 타임 검증 (MISRA Rule 5-0-21)
    static_assert((-1 >> 1) == -1,
        "[HTS_FATAL] Compiler does not use arithmetic right shift (ASR). "
        "IIR DC blocker requires ASR for signed >> 16.");

    // =====================================================================
    //  보안 소거 — volatile + asm clobber + release fence
    //
    // =====================================================================
    static void Secure_Wipe_Pulse(volatile void* ptr, size_t size) noexcept {
        if (!ptr || size == 0) return;
        volatile unsigned char* p =
            static_cast<volatile unsigned char*>(ptr);
        for (size_t i = 0; i < size; ++i) p[i] = 0;
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  생성자 — 가우시안 필터 계수 생성
    //
    //
    //  알고리즘 로직 100% 원본 유지:
    //   alpha = sqrt(ln(2)/2) / bt
    //   H0[i] = exp(-(alpha * (i-center) * PI)²) × scale
    //   H1[i] = 2 × normalized_t × H0[i] / 4 × scale
    // =====================================================================
    Gaussian_Pulse_Shaper::Gaussian_Pulse_Shaper(
        size_t taps, uint32_t bt_q16) noexcept
        : num_taps(taps)
        , scale_factor(32768)
        , prev_in(0)
        , prev_out(0) {

        if (taps == 0 || (taps & 1u) == 0) {
            num_taps = 31;
        }

        // MAX_TAPS 상한 클램프
        if (num_taps > MAX_TAPS) { num_taps = MAX_TAPS; }

        static constexpr uint32_t BT_Q16_0P3 = 19661u; // round(0.3 * 65536)
        uint32_t bt = (bt_q16 == 0u) ? BT_Q16_0P3 : bt_q16;


        // [OPT-1] std::log(2)/std::sqrt → 컴파일 타임 상수화
        //  std::sqrt(...) → ARM fp64 에뮬 유발 위험
        //  sqrt(ln(2)/2) = 0.5887054816... 하드코딩
        //  부팅 1회 연산이지만 -fno-math-errno 없는 환경에서 fp64 fallback 차단
        // sqrt(ln(2)/2) ~= 0.5887054816 in Q16 (정수 근사)
        static constexpr int32_t SQRT_LN2_OVER_2_Q16 = 38582;
        static constexpr int32_t PI_Q16 = 205887;
        // center는 taps 홀수에 의해 정수.
        const int32_t center_i =
            static_cast<int32_t>((num_taps - 1u) >> 1u);
        // alpha in Q16: alpha = SQRT_LN2_OVER_2 / bt
        const int32_t alpha_q16 = static_cast<int32_t>(
            (static_cast<int64_t>(SQRT_LN2_OVER_2_Q16) << 16) /
            static_cast<int64_t>(bt));

        for (size_t i = 0; i < num_taps; ++i) {
            const int32_t t = static_cast<int32_t>(
                static_cast<int32_t>(i) - center_i);

            // normalized_t in Q16: normalized_t = alpha * t * PI
            const int32_t normalized_t_q16 =
                static_cast<int32_t>(
                    (static_cast<int64_t>(alpha_q16) *
                        static_cast<int64_t>(t) *
                        static_cast<int64_t>(PI_Q16)) >> 16);

            const uint32_t abs_norm_q16 =
                static_cast<uint32_t>(
                    (normalized_t_q16 < 0)
                        ? -normalized_t_q16
                        : normalized_t_q16);

            // x in Q16: x = normalized_t^2
            const uint32_t x_q16 = static_cast<uint32_t>(
                ((static_cast<uint64_t>(abs_norm_q16) *
                    static_cast<uint64_t>(abs_norm_q16)) >> 16));

            // exp(-x) in Q16 (정수 고정소수점 Taylor 근사):
            // exp(-x) < 1/65536 이면 계수 반올림으로 0이므로 fail-safe로 절단.
            static constexpr uint32_t X_MAX_Q16 = 11u * 65536u;
            int32_t exp_neg_x_q16 = 0;
            if (x_q16 < X_MAX_Q16) {
                // K-term Taylor series: exp(-x) ≈ sum_{k=0..K} (-x)^k / k!
                static constexpr int K = 8;
                int32_t exp_q16 = (1 << 16);
                int32_t term_q16 = (1 << 16);
                for (int k = 1; k <= K; ++k) {
                    // term *= x  (Q16*Q16 >> 16)
                    term_q16 = static_cast<int32_t>(
                        (static_cast<int64_t>(term_q16) *
                            static_cast<int64_t>(x_q16) + 0x8000LL) >> 16);
                    term_q16 = static_cast<int32_t>(
                        term_q16 / static_cast<int32_t>(k));
                    if ((k & 1) != 0) { exp_q16 -= term_q16; }
                    else { exp_q16 += term_q16; }
                }
                if (exp_q16 < 0) { exp_q16 = 0; }
                exp_neg_x_q16 = exp_q16;
            }

            // H0: round(exp(-x) * scale_factor) where scale_factor=32768=2^15
            // exp_neg_x_q16 = exp(-x) * 2^16 => H0 = exp_neg_x_q16 / 2
            filter_coeffs[i] = static_cast<int32_t>(
                (static_cast<uint32_t>(exp_neg_x_q16) + 1u) >> 1u);

            // H1: round(normalized_t * exp(-x) * scale_factor / 2)
            // normalized_t_q16 (Q16) * exp_neg_x_q16 (Q16) => Q32
            // multiply by scale_factor/2 = 2^14 => divide by 2^18.
            if (exp_neg_x_q16 == 0) {
                filter_coeffs_H1[i] = 0;
            }
            else {
                const uint32_t exp_u = static_cast<uint32_t>(exp_neg_x_q16);
                const uint64_t product_q32 =
                    static_cast<uint64_t>(abs_norm_q16) *
                    static_cast<uint64_t>(exp_u);
                const uint32_t h1_abs =
                    static_cast<uint32_t>((product_q32 + (1ull << 17)) >> 18);
                filter_coeffs_H1[i] = (normalized_t_q16 < 0)
                    ? -static_cast<int32_t>(h1_abs)
                    : static_cast<int32_t>(h1_abs);
            }
        }
    }

    // =====================================================================
    // =====================================================================
    Gaussian_Pulse_Shaper::~Gaussian_Pulse_Shaper() noexcept {
        Secure_Wipe_Pulse(filter_coeffs, sizeof(filter_coeffs));
        Secure_Wipe_Pulse(filter_coeffs_H1, sizeof(filter_coeffs_H1));
        Secure_Wipe_Pulse(&prev_in, sizeof(prev_in));
        Secure_Wipe_Pulse(&prev_out, sizeof(prev_out));
    }

    // =====================================================================
    //  IIR DC 블로커 상태 초기화
    // =====================================================================
    void Gaussian_Pulse_Shaper::Reset_Filter_State() noexcept {
        Secure_Wipe_Pulse(&prev_in, sizeof(prev_in));
        Secure_Wipe_Pulse(&prev_out, sizeof(prev_out));
        prev_in = 0;
        prev_out = 0;
    }

    // =====================================================================
    // =====================================================================
    const int32_t* Gaussian_Pulse_Shaper::Get_Filter_Coeffs() const noexcept {
        return (num_taps > 0) ? filter_coeffs : nullptr;
    }

    size_t Gaussian_Pulse_Shaper::Get_Num_Taps() const noexcept {
        return num_taps;
    }

    // =====================================================================
    //  8-Way 무손실 텐서 다중화 + Q16 IIR DC 제거 (Raw 포인터 API)
    //
    //  [OPT-2] 루프 역전 (scatter → gather) + FIR/IIR 1-Pass 융합
    //   입력 기준 scatter — output[c+j] += 매 칩×탭 = ~26만 R/W
    //   출력 기준 gather — acc 레지스터 누적, output[n] 1회 기록
    //   SRAM 접근: ~262,000 → ~4,126 (98% 감소)
    //   memset: 제거 (덮어쓰기 = 로 충분)
    //   IIR DC 블로커: FIR 결과 즉시 융합 (2-Pass → 1-Pass)
    // =====================================================================
    size_t Gaussian_Pulse_Shaper::Apply_Pulse_Shaping_Tensor_Raw(
        const uint32_t* tensor, size_t t_len,
        int32_t* output, size_t out_cap) noexcept {

        if (!tensor || !output || t_len == 0 || num_taps == 0) return 0;
        // ASIC/ARM 포팅 안전성: 32비트 워드 접근 정렬 강제
        const uintptr_t tensor_addr = reinterpret_cast<uintptr_t>(tensor);
        const uintptr_t output_addr = reinterpret_cast<uintptr_t>(output);
        if ((tensor_addr & (alignof(uint32_t) - 1u)) != 0u) return 0;
        if ((output_addr & (alignof(int32_t) - 1u)) != 0u) return 0;

        if (t_len > std::numeric_limits<size_t>::max() / 8u) return 0;
        const size_t total_chips = t_len * 8u;

        if (total_chips > std::numeric_limits<size_t>::max() - num_taps) return 0;
        const size_t out_len = total_chips + num_taps - 1;

        if (out_len > out_cap) return 0;

        // [OPT-2] memset 제거 — gather 루프가 output[n]을 = 로 덮어씀

        const int32_t* __restrict coeff_h0 = filter_coeffs;
        const int32_t* __restrict coeff_h1 = filter_coeffs_H1;

        // ── IIR DC 블로커 상태 ──
        const int64_t ALPHA_Q16 = 62259;  // 0.95 × 65536
        int64_t p_in = prev_in;
        int64_t p_out = prev_out;

        // ── FIR gather + IIR 융합 1-Pass ──
        //  output[n] = Σ (symbol[c] × h0[n-c] + w1[c] × h1[n-c])
        //  c ∈ [max(0, n-T+1), min(n, total_chips-1)]
        //  T = num_taps
        const size_t T = num_taps;

        for (size_t n = 0u; n < out_len; ++n) {
            int64_t acc = 0;

            // 기여 칩 범위
            const size_t c_start = (n >= T - 1u) ? (n - T + 1u) : 0u;
            const size_t c_end = (n < total_chips) ? (n + 1u) : total_chips;

            for (size_t c = c_start; c < c_end; ++c) {
                // 칩 → 텐서 워드/니블 추출 (>>,& = 0~1cyc)
                const uint32_t block = tensor[c >> 3u];
                const uint32_t ki = c & 7u;
                const uint8_t chunk =
                    static_cast<uint8_t>((block >> (ki * 4u)) & 0x0Fu);

                const uint32_t sign_bit = (chunk >> 3u) & 1u;
                const int32_t symbol =
                    static_cast<int32_t>(sign_bit << 1u) - 1;
                const int32_t w1_weight =
                    static_cast<int32_t>(chunk & 0x07u) - 3;

                const size_t tap = n - c;
                acc += static_cast<int64_t>(symbol) * coeff_h0[tap]
                    + static_cast<int64_t>(w1_weight) * coeff_h1[tap];
            }

            // ── IIR DC 블로커 즉시 융합 (2-Pass 제거) ──
            const int64_t fir_out = acc;
            int64_t iir_out =
                fir_out - p_in +
                ((ALPHA_Q16 * p_out + 0x8000LL) >> 16);

            if (iir_out > INT32_MAX) iir_out = INT32_MAX;
            else if (iir_out < INT32_MIN) iir_out = INT32_MIN;

            output[n] = static_cast<int32_t>(iir_out);  // 1회 기록

            p_in = fir_out;
            p_out = iir_out;
        }

        prev_in = p_in;
        prev_out = p_out;

        return out_len;
    }

} // namespace ProtectedEngine
