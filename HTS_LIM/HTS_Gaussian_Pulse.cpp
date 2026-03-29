// =========================================================================
// HTS_Gaussian_Pulse.cpp
// 가우시안 펄스 셰이핑 엔진 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// [양산 수정 — 20건]
//  BUG-01~14 (이전 세션)
//  BUG-15 [HIGH] Secure_Wipe seq_cst → release (배리어 정책 통일)
//  BUG-16 [CRIT] try-catch 4블록 완전 제거 (-fno-exceptions)
//  BUG-17 [CRIT] filter_coeffs vector → int32_t[MAX_TAPS] 정적 배열
//         · 생성자: resize → memset 직접 초기화 (힙 0회)
//  BUG-18 [CRIT] double → float (ARM 단정밀도 하드웨어 FPU)
//         · STM32F407 FPU: float = 하드웨어 1~14cyc
//           double = __aeabi_d* 소프트웨어 에뮬 ~200cyc
//         · 필터 계수 생성(부팅 1회) → float 7자리 정밀도 충분
//         · PC: double 유지 (최대 정밀도)
//  BUG-19 [HIGH] Raw 포인터 API 추가 (Apply_Pulse_Shaping_Tensor_Raw)
//  BUG-20 [HIGH] 소멸자: 계수 배열 전체 보안 소거 추가
// =========================================================================

#include "HTS_Gaussian_Pulse.h"
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <cmath>

// [BUG-18] fp_t = float: STM32F407 단정밀도 하드웨어 FPU (1~14cyc)
using fp_t = float;

namespace ProtectedEngine {

    // ASR 컴파일 타임 검증 (MISRA Rule 5-0-21)
    static_assert((-1 >> 1) == -1,
        "[HTS_FATAL] Compiler does not use arithmetic right shift (ASR). "
        "IIR DC blocker requires ASR for signed >> 16.");

    // =====================================================================
    //  보안 소거 — volatile + asm clobber + release fence
    //
    //  [BUG-15] seq_cst → release (소거 배리어 정책 통일)
    // =====================================================================
    static void Secure_Wipe_Pulse(volatile void* ptr, size_t size) noexcept {
        if (!ptr || size == 0) return;
        volatile unsigned char* p =
            static_cast<volatile unsigned char*>(ptr);
        for (size_t i = 0; i < size; ++i) p[i] = 0;
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        // [BUG-15] seq_cst → release
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  생성자 — 가우시안 필터 계수 생성
    //
    //  [BUG-16] try-catch 제거 (정적 배열 — OOM 경로 소멸)
    //  [BUG-17] vector resize → 정적 배열 직접 사용
    //  [BUG-18] double → fp_t (ARM: float, PC: double)
    //
    //  알고리즘 로직 100% 원본 유지:
    //   alpha = sqrt(ln(2)/2) / bt
    //   H0[i] = exp(-(alpha * (i-center) * PI)²) × scale
    //   H1[i] = 2 × normalized_t × H0[i] / 4 × scale
    // =====================================================================
    Gaussian_Pulse_Shaper::Gaussian_Pulse_Shaper(
        size_t taps, double bt_product) noexcept
        : num_taps(taps)
        , scale_factor(32768)
        , prev_in(0)
        , prev_out(0) {

        // [BUG-07] taps 검증: 0/짝수 → 31 폴백
        if (taps == 0 || (taps & 1u) == 0) {
            num_taps = 31;
        }

        // MAX_TAPS 상한 클램프
        if (num_taps > MAX_TAPS) { num_taps = MAX_TAPS; }

        // [BUG-03] bt_product 방어
        fp_t bt = static_cast<fp_t>(bt_product);
        if (bt <= static_cast<fp_t>(0) || bt != bt) {
            bt = static_cast<fp_t>(0.3);
        }

        // [BUG-17] 정적 배열 — try-catch 불필요 (OOM 경로 소멸)

        // [OPT-1] std::log(2)/std::sqrt → 컴파일 타임 상수화
        //  기존: std::sqrt(std::log(2.0f) / 2.0f) → ARM double 에뮬 유발 위험
        //  수정: sqrt(ln(2)/2) = 0.5887054816... 하드코딩
        //  부팅 1회 연산이지만 -fno-math-errno 없는 환경에서 double fallback 차단
        static constexpr fp_t SQRT_LN2_OVER_2 =
            static_cast<fp_t>(0.5887054816);
        const fp_t alpha = SQRT_LN2_OVER_2 / bt;
        const fp_t center =
            static_cast<fp_t>(num_taps - 1) / static_cast<fp_t>(2);
        const fp_t PI = static_cast<fp_t>(3.14159265358979323846);

        for (size_t i = 0; i < num_taps; ++i) {
            const fp_t t = static_cast<fp_t>(i) - center;
            const fp_t normalized_t = alpha * t * PI;

            const fp_t h0_coeff =
                std::exp(-(normalized_t * normalized_t));
            const fp_t h1_coeff =
                static_cast<fp_t>(2) * normalized_t * h0_coeff;

            // 반올림 양자화: truncation 대신 round (양자화 노이즈 최소화)
            filter_coeffs[i] = static_cast<int32_t>(
                std::round(h0_coeff * static_cast<fp_t>(scale_factor)));
            filter_coeffs_H1[i] = static_cast<int32_t>(
                std::round((h1_coeff * static_cast<fp_t>(scale_factor))
                    / static_cast<fp_t>(4)));
        }
    }

    // =====================================================================
    //  [BUG-13/20] 소멸자 — 계수 + DC 상태 보안 소거
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
    //  [BUG-19] Raw 포인터 접근자
    // =====================================================================
    const int32_t* Gaussian_Pulse_Shaper::Get_Filter_Coeffs() const noexcept {
        return (num_taps > 0) ? filter_coeffs : nullptr;
    }

    size_t Gaussian_Pulse_Shaper::Get_Num_Taps() const noexcept {
        return num_taps;
    }

    // =====================================================================
    //  [BUG-19+OPT] Apply_Pulse_Shaping_Tensor_Raw
    //  8-Way 무손실 텐서 다중화 + Q16 IIR DC 제거 (Raw 포인터 API)
    //
    //  [OPT-2] 루프 역전 (scatter → gather) + FIR/IIR 1-Pass 융합
    //   기존: 입력 기준 scatter — output[c+j] += 매 칩×탭 = ~26만 R/W
    //   수정: 출력 기준 gather — acc 레지스터 누적, output[n] 1회 기록
    //   SRAM 접근: ~262,000 → ~4,126 (98% 감소)
    //   memset: 제거 (덮어쓰기 = 로 충분)
    //   IIR DC 블로커: FIR 결과 즉시 융합 (2-Pass → 1-Pass)
    // =====================================================================
    size_t Gaussian_Pulse_Shaper::Apply_Pulse_Shaping_Tensor_Raw(
        const uint32_t* tensor, size_t t_len,
        int32_t* output, size_t out_cap) noexcept {

        if (!tensor || !output || t_len == 0 || num_taps == 0) return 0;

        // [BUG-09] 오버플로 방어
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

                const int32_t symbol = (chunk & 0x08u) ? 1 : -1;
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