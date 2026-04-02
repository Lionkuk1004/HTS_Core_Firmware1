// =========================================================================
// HTS_Gaussian_Pulse.h
// 가우시안 펄스 셰이핑 엔진 (GMSK/GFSK 기반 8-Way 텐서 다중화)
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [파이프라인 위치]
//   Security_Pipeline → FEC → Interleaver → ★Pulse Shaping★ → DMA Tx
//
//  [필터 설계]
//   H0: 가우시안 메인 로브 (GMSK 기저대역 성형)
//   H1: 1차 도함수 (주파수 편이 보강 — 직교 성분)
//   8-Way: 32비트 → 8개 4비트 니블 → 독립 아날로그 파동
//   IIR DC 제거: α=0.95 단극 고역통과 (Q16 고정소수점)
//
//  [사용법]
//   Gaussian_Pulse_Shaper shaper(31, 0.3);
//   int32_t out[8192];
//   size_t n = shaper.Apply_Pulse_Shaping_Tensor_Raw(
//       tensor, t_len, out, 8192);
//
//  [메모리]
//   filter_coeffs[128] + filter_coeffs_H1[128] = 1KB (정적, 힙 0회)
//   IIR 상태: prev_in(8B) + prev_out(8B) = 16B
//
//  [양산 수정 이력 — 20건]
//   BUG-15 [HIGH] seq_cst → release
//   BUG-16 [CRIT] try-catch 4블록 제거
//   BUG-17 [CRIT] filter_coeffs vector → int32_t[128] 정적 배열
//   BUG-18 [CRIT] fp64 -> fp32 (ARM 단정밀도 하드웨어 FPU)
//   BUG-19 [HIGH] Raw 포인터 API 추가 (ARM Zero-Heap)
//   BUG-20 [HIGH] 소멸자: 계수 배열 보안 소거 추가
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    class Gaussian_Pulse_Shaper {
    public:
        /// @brief 필터 탭 최대 수 (정적 배열 상한)
        static constexpr size_t MAX_TAPS = 128u;

        /// @brief 가우시안 필터 생성
        /// @param taps        필터 탭 수 (홀수, 0/짝수 → 31 폴백)
        /// @param bt_q16      대역폭×심볼 주기 Q16 (0.3 => 19661)
        /// @note              유효 범위 밖/0 입력은 0.3 폴백
        Gaussian_Pulse_Shaper(size_t taps, uint32_t bt_q16) noexcept;

        /// @brief 소멸자 — 계수 + DC 상태 보안 소거
        ~Gaussian_Pulse_Shaper() noexcept;

        /// 필터 상태 복제/분기 방지
        Gaussian_Pulse_Shaper(const Gaussian_Pulse_Shaper&) = delete;
        Gaussian_Pulse_Shaper& operator=(const Gaussian_Pulse_Shaper&) = delete;
        Gaussian_Pulse_Shaper(Gaussian_Pulse_Shaper&&) = delete;
        Gaussian_Pulse_Shaper& operator=(Gaussian_Pulse_Shaper&&) = delete;

        // ── Raw 포인터 API (ARM/PC 공용) ─────────────────────────────

        /// @brief 정합 필터 계수 포인터 (시간 반전은 호출자 책임)
        [[nodiscard]] const int32_t* Get_Filter_Coeffs() const noexcept;

        /// @brief 필터 탭 수
        [[nodiscard]] size_t Get_Num_Taps() const noexcept;

        /// @brief 32비트 텐서 8-Way 다중화 + Q16 IIR DC 제거
        /// @param tensor   32비트 텐서 배열
        /// @param t_len    텐서 길이
        /// @param output   출력 배열 (최소 t_len*8 + num_taps - 1)
        /// @param out_cap  출력 배열 용량
        /// @return 출력 샘플 수 (0 = 실패)
        size_t Apply_Pulse_Shaping_Tensor_Raw(
            const uint32_t* tensor, size_t t_len,
            int32_t* output, size_t out_cap) noexcept;

        /// @brief IIR DC 블로커 상태 초기화 (패킷 간 State Bleed 방지)
        void Reset_Filter_State() noexcept;

    private:
        int32_t filter_coeffs[MAX_TAPS] = {};     ///< H0 가우시안 메인 로브
        int32_t filter_coeffs_H1[MAX_TAPS] = {};   ///< H1 1차 도함수
        size_t  num_taps = 0;                       ///< 유효 탭 수
        int32_t scale_factor = 32768;               ///< Q15 스케일링 팩터

        int64_t prev_in = 0;    ///< IIR DC 블로커 입력 상태
        int64_t prev_out = 0;   ///< IIR DC 블로커 출력 상태
    };

} // namespace ProtectedEngine
