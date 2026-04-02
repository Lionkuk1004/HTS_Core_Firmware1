// =========================================================================
// HTS_Adaptive_BPS_Controller.h
// HTS 적응형 BPS 히스테리시스 컨트롤러 — 공개 인터페이스
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [목적]
//  HTS_RF_Metrics에서 SNR 프록시와 AJC 에너지를 읽어
//  히스테리시스 제어로 BPS를 3~6 사이에서 동적 전환합니다.
//
//  [설계 원칙: 올라갈 때는 천천히, 내려올 때는 즉시]
//
//   HEAVY 상태 (재밍 강) ──────────────────────────────────── BPS = 3 (즉시)
//   ajc_nf ≥ 2000 OR snr < 5
//
//   HOLD 구간 (경계 상태) ───────────────────────────── BPS 유지 + count 리셋
//   ajc_nf 500~2000 OR snr 5~10
//
//   QUIET 상태 (깨끗한 채널) ─── HYST_UP_COUNT(8) 연속 프레임 → BPS++ (최대 6)
//   ajc_nf < 500 AND snr ≥ 10
//
//  [임계값 근거]
//   AJC_IDLE_THR  =  500 : ECCM 캘리브레이션 기준값(100)의 5배  → 경미한 간섭
//   AJC_HEAVY_THR = 2000 : 기준값의 20배 → 강한 재밍 감지
//   QUIET_SNR_THR =   10 : 피크가 노이즈 플로어 10배 이상 → 동기 매우 안정
//   NOISY_SNR_THR =    5 : 피크가 노이즈 플로어 5배 미만  → 채널 열화
//   HYST_UP_COUNT =    8 : 168MHz @~4ms/프레임 → 약 32ms 안정 유지 시 상향
//
//  [사용법]
//   1. 전역(또는 정적) HTS_RF_Metrics 생성
//   2. 각 모듈에 &metrics 주입 (Sync_Detector, ECCM_Core, Dispatcher)
//   3. 컨트롤러 생성: HTS_Adaptive_BPS_Controller ctrl(metrics)
//   4. 매 프레임 처리 후: ctrl.Update()
//   5. Dispatcher에서: dispatcher.Tick_Adaptive_BPS()
//
//  [메모리]
//   sizeof(HTS_Adaptive_BPS_Controller) = 16B (참조 8B + count 1B + padding)
//   Pimpl 없음 — 상태가 작으므로 직접 멤버로 저장
//
//  [보안]
//   BPS 값은 암호 키가 아니므로 보안 소거 불필요
//   복사 = delete (참조 멤버가 있으므로 자연스럽게 금지됨)
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include "HTS_RF_Metrics.h"
#include <cstdint>

namespace ProtectedEngine {

    class HTS_Adaptive_BPS_Controller {
    public:
        // ── 임계값 상수 (확정 수치) ────────────────────────────────────
        /// ECCM nf_q16 >> 16 이 이 값 미만 → 채널 양호 (BPS 상향 허용 조건 ①)
        static constexpr uint32_t AJC_IDLE_THR = 500u;

        /// ECCM nf_q16 >> 16 이 이 값 이상 → 강한 재밍 (즉시 BPS = BPS_MIN)
        static constexpr uint32_t AJC_HEAVY_THR = 2000u;

        /// SNR 프록시 이 값 이상 → 채널 양호 (BPS 상향 허용 조건 ②)
        static constexpr int32_t  QUIET_SNR_THR = 10;

        /// SNR 프록시 이 값 미만 → 채널 열화 (즉시 BPS = BPS_MIN)
        static constexpr int32_t  NOISY_SNR_THR = 5;

        /// QUIET 조건 연속 충족 횟수 → BPS 한 단계 상향
        static constexpr uint8_t  HYST_UP_COUNT = 8u;

        /// BPS 최솟값 (변전소 +20dB 재밍 대응 확정값)
        static constexpr uint8_t  BPS_MIN = 3u;

        /// BPS 최댓값 (깨끗한 채널 최고 처리량)
        static constexpr uint8_t  BPS_MAX = 6u;

        // ── 생성자 / 소멸자 ────────────────────────────────────────────
        /// @brief 컨트롤러 생성
        /// @param metrics  공유 측정값 컨테이너 참조 (수명이 컨트롤러보다 길어야 함)
        explicit HTS_Adaptive_BPS_Controller(
            HTS_RF_Metrics& metrics) noexcept;

        ~HTS_Adaptive_BPS_Controller() noexcept = default;

        /// 참조 멤버 보유 → 복사/이동 자동 금지 (명시적으로도 차단)
        HTS_Adaptive_BPS_Controller(
            const HTS_Adaptive_BPS_Controller&) = delete;
        HTS_Adaptive_BPS_Controller& operator=(
            const HTS_Adaptive_BPS_Controller&) = delete;
        HTS_Adaptive_BPS_Controller(
            HTS_Adaptive_BPS_Controller&&) = delete;
        HTS_Adaptive_BPS_Controller& operator=(
            HTS_Adaptive_BPS_Controller&&) = delete;

        // ── 핵심 API ───────────────────────────────────────────────────

        /// @brief 매 프레임 호출 — 측정값 읽기 → BPS 판단 → metrics 갱신
        ///
        /// [판단 우선순위]
        ///  1순위: HEAVY 조건 (즉시 BPS_MIN)
        ///  2순위: QUIET 조건 (카운터 누적 → 임계 도달 시 BPS++)
        ///  3순위: HOLD 구간 (카운터 리셋, BPS 유지)
        ///
        /// @note  STM32F407 메인 루프에서 매 64칩 처리 후 1회 호출 권장
        /// @note  ISR에서 호출하지 마십시오 (측정값이 아직 최신이 아님)
        /// @warning 메인 루프(또는 동일 우선순위 단일 컨텍스트) 전용 계약.
        ///          ISR·다른 스레드와의 동시 호출은 지원하지 않습니다.
        ///          (단일 코어에서 try-lock은 ISR 선점 시 갱신 누락을 유발할 수 있어 미사용)
        void Update() noexcept;

        /// @brief 강제 BPS_MIN 리셋 (통신 단절 / 모드 전환 / 세션 재시작 시)
        /// @post  metrics.current_bps = BPS_MIN, quiet_count_ = 0
        void Reset() noexcept;

        /// @brief 현재 히스테리시스 카운터 반환 (디버그/진단용)
        [[nodiscard]] uint8_t Get_Quiet_Count() const noexcept {
            return quiet_count_;
        }

    private:
        HTS_RF_Metrics& metrics_;
        uint8_t         quiet_count_{ 0u };
    };

} // namespace ProtectedEngine