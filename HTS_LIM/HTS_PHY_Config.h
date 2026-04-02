// =========================================================================
// HTS_PHY_Config.h
// 통신 물리 계층(PHY) 체급별 설정 팩토리
// Target: STM32F407 (Cortex-M4, 168MHz)
//
#pragma once
// ─────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────
//  [사용법] 기본 사용 예시를 여기에 기재하세요.
//  [메모리] sizeof(클래스명) 확인 후 전역/정적 배치 필수.
//  [보안]   복사/이동 연산자 = delete (키 소재 복제 차단).
//
//  ⚠ [파트너사 필수 확인]
//    HW 레지스터 주소(UART/WDT 등)는 보드 설계에 맞게 교체.
//    IRQ 번호는 STM32F407 RM0090 벡터 테이블 기준으로 교체.
// ─────────────────────────────────────────────────────────

#include <cstdint>

namespace ProtectedEngine {

    /// 통신 물리 계층(PHY) 체급
    enum class HTS_PHY_Tier : uint8_t {
        TIER_32_IQ = 0u,   ///< 32칩 IQ 모드
        TIER_64_ECCM = 1u,   ///< 64칩 ECCM(전자전 대응) 모드
    };

    /// PHY 계층 설정 구조체
    struct HTS_PHY_Config {
        uint8_t  chip_count;           ///< 칩 수 (32 또는 64)
        uint8_t  min_valid_chips;      ///< 최소 유효 칩 수 (PLL 판정)
        uint32_t noise_floor_init_q16; ///< 초기 잡음 바닥 (Q16 고정소수점)
        uint32_t calib_frames;         ///< 캘리브레이션 프레임 수
        int32_t  kp;                   ///< PLL 비례 계수 (0=PLL 비활성)
        int32_t  ki;                   ///< PLL 적분 계수 (0=PLL 비활성)
        uint32_t jamming_margin;       ///< 재밍 판정 마진
        int32_t  squelch_threshold;    ///< 스쿼치 임계값
        int32_t  cfar_default_mult;    ///< CFAR 기본 배율
    };

    /// PHY 설정 팩토리
    struct HTS_PHY_Config_Factory {
        static HTS_PHY_Config make(HTS_PHY_Tier tier) noexcept {
            switch (tier) {
            case HTS_PHY_Tier::TIER_32_IQ:
                return HTS_PHY_Config{ 32u, 16u, 100u << 16u, 72u, 30, 2, 4000u, 8, 4 };
            case HTS_PHY_Tier::TIER_64_ECCM:
                // → 전자전 환경에서 PLL 추적 루프가 재밍에 의해 오히려 왜곡될 수 있음
                // → 에너지 검출(비동기) 방식으로 동작하므로 PLL 불필요
                return HTS_PHY_Config{ 64u, 32u, 100u << 16u, 72u, 0, 0, 4000u, 8, 4 };
            default:
                // 손상된 enum 값·미래 확장: ECCM 프로파일로 폴백 (상수 동일)
                return HTS_PHY_Config{ 64u, 32u, 100u << 16u, 72u, 0, 0, 4000u, 8, 4 };
            }
        }
    };

} // namespace ProtectedEngine
