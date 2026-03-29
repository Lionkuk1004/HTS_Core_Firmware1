// =========================================================================
// HTS_RF_Metrics.h
// HTS 적응형 BPS — RF 측정값 공유 컨테이너
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [단방향 데이터 흐름]
//
//   HTS_Rx_Sync_Detector  ──→  snr_proxy
//   HTS64_Native_ECCM_Core ──→  ajc_nf
//                               ↓
//                  HTS_Adaptive_BPS_Controller  ──→  current_bps
//                                                       ↓
//                                         HTS_V400_Dispatcher
//
//  쓰는 쪽과 읽는 쪽이 완전히 분리됩니다.
//  각 모듈은 자신이 쓰는 필드 외에는 건드리지 않습니다.
//
//  [필드별 갱신 주기]
//   snr_proxy  : Detect_Sync_Peak 호출 시 (수신 동기화마다)
//   ajc_nf     : ECCM Decode_BareMetal_IQ / Decode_Soft_IQ 호출 시
//   current_bps: HTS_Adaptive_BPS_Controller::Update() 호출 시 (매 프레임)
//
//  [임계값 해설]
//   snr_proxy  = max_correlation_peak / noise_floor (순수 정수비, 단위 없음)
//                QUIET_SNR_THR = 10 이상 → 채널 양호, BPS 상향 허용
//                NOISY_SNR_THR =  5 미만 → 채널 열화, BPS 즉시 하강
//
//   ajc_nf     = ECCM nf_q16 >> 16 (상위 16비트, 에너지 정수 단위)
//                캘리브레이션 기준값 100 (nf_q16 초기값 100 << 16)
//                AJC_IDLE_THR  =  500 (5배  → 경미한 간섭, BPS 상향 허용)
//                AJC_HEAVY_THR = 2000 (20배 → 강한 재밍,  즉시 BPS=3)
//
//   current_bps: 3 ~ 6 (BPS_MIN ~ BPS_MAX)
//                3 = 최고 강인도 (변전소 +20dB 재밍 대응)
//                6 = 최고 처리량 (깨끗한 채널)
//
//  [스레드 안전성]
//   모든 멤버 std::atomic — ISR, 메인 루프, 컨트롤러 컨텍스트 모두 안전
//   STM32F407은 단일 코어이므로 실질적 데이터 레이스 없음
//   PC 멀티스레드 시뮬레이션에서도 atomic 보장
//
// =========================================================================
#pragma once

#include <atomic>
#include <cstdint>

namespace ProtectedEngine {

    /// @brief RF 측정값 공유 컨테이너
    ///
    /// Pimpl 없음, 메서드 없음 — 순수 데이터 전달 구조체.
    /// 생성 후 각 모듈에 포인터로 주입하여 사용합니다.
    ///
    /// @note 전역 또는 정적 스토리지에 배치 권장
    ///       (여러 모듈이 동시에 참조하는 공유 상태)
    struct HTS_RF_Metrics {

        /// SNR 프록시 = max_peak / noise_floor (정수비)
        /// @par 갱신: HTS_Rx_Sync_Detector::Detect_Sync_Peak
        /// @par QUIET ≥ 10, NOISY < 5
        std::atomic<int32_t> snr_proxy{ 0 };

        /// ECCM 노이즈 플로어 에너지 = nf_q16 >> 16 (상위 16비트)
        /// @par 갱신: HTS64_Native_ECCM_Core::Decode_BareMetal_IQ /
        ///           Decode_Soft_IQ
        /// @par 기준값 100, IDLE < 500, HEAVY > 2000
        std::atomic<uint32_t> ajc_nf{ 100u };

        /// 현재 BPS (3 ~ 6)
        /// @par 갱신: HTS_Adaptive_BPS_Controller::Update
        /// @par 읽기: HTS_V400_Dispatcher::Tick_Adaptive_BPS
        std::atomic<uint8_t> current_bps{ 3u };
    };

} // namespace ProtectedEngine