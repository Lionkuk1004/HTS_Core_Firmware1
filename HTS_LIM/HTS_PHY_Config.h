// =========================================================================
// HTS_PHY_Config.h
// 통신 물리 계층(PHY) 체급별 설정 팩토리
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// [양산 수정]
//  BUG-01 [LOW] #pragma once 중복 제거
//  BUG-04 [MED] TIER_64_ECCM kp/ki=0 의도 주석
//  BUG-05 [LOW] 닫는 네임스페이스 주석
// =========================================================================
#pragma once

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
        int32_t  squelch_threshold;    ///< 스켈치 임계값
        int32_t  cfar_default_mult;    ///< CFAR 기본 배율
    };

    /// PHY 설정 팩토리
    struct HTS_PHY_Config_Factory {
        static HTS_PHY_Config make(HTS_PHY_Tier tier) noexcept {
            switch (tier) {
            case HTS_PHY_Tier::TIER_32_IQ:
                return HTS_PHY_Config{ 32u, 16u, 100u << 16u, 72u, 30, 2, 4000u, 8, 4 };
            case HTS_PHY_Tier::TIER_64_ECCM:
            default:
                // [BUG-04] kp=0, ki=0: ECCM 모드에서는 PLL 의도적 비활성
                // → 전자전 환경에서 PLL 추적 루프가 재밍에 의해 오히려 왜곡될 수 있음
                // → 에너지 검출(비동기) 방식으로 동작하므로 PLL 불필요
                return HTS_PHY_Config{ 64u, 32u, 100u << 16u, 72u, 0, 0, 4000u, 8, 4 };
            }
        }
    };

} // namespace ProtectedEngine