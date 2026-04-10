// =============================================================================
/// @file HTS_AJ_Stats.h
/// @brief 이항 비율 Wilson 95% 신뢰구간 — 정수·Q8 출력 (고정소수점)
// =============================================================================
#ifndef HTS_AJ_STATS_H
#define HTS_AJ_STATS_H

#include <cstdint>

/// @brief 성공률 Q8 (0~256 ≈ 0~100%)
inline uint16_t AJ_Rate_Q8(uint32_t n, uint32_t k) noexcept {
    if (n == 0u) {
        return 0u;
    }
    return static_cast<uint16_t>((static_cast<uint64_t>(k) * 256u) /
                                 static_cast<uint64_t>(n));
}

/// @brief Wilson score 95% (z=1.96) 구간을 Q8로 근사 (분모·제곱근은 정수 스케일)
void AJ_Wilson95_Q8(uint32_t n, uint32_t k, uint16_t* lo_q8,
                    uint16_t* hi_q8) noexcept;

#endif
