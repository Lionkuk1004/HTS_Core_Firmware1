// =============================================================================
/// @file HTS_AJ_TestRunner.h
/// @brief 단일/전체 매트릭스 시험 실행 (V400·FEC 경로 래핑)
// =============================================================================
#ifndef HTS_AJ_TESTRUNNER_H
#define HTS_AJ_TESTRUNNER_H

#include "HTS_AJ_TestMatrix.h"
#include <cstdint>

struct AJ_TestResult {
    uint16_t test_id{};
    uint16_t frames_total{};
    uint16_t crc_pass{};
    uint16_t crc_fail{};
    uint16_t success_rate_q8{}; ///< 성공률×256/100 근사 (Q8)
    uint16_t ci_lower_q8{};
    uint16_t ci_upper_q8{};
    uint8_t pass_fail{}; ///< 단일 시드 기준
    uint32_t seed_used{};
};

/// @brief 단일 (케이스 × 시드) 실행
void Run_Single_Test(const AJ_TestCase& tc, uint32_t seed,
                     AJ_TestResult& result) noexcept;

/// @brief 144×시드 전체 실행 + CSV·요약
void Run_Full_Matrix(const uint32_t* seeds, uint8_t seed_count) noexcept;

/// @brief 마지막 Run_Full_Matrix 결과 버퍼 (요약용, 최대 144×8)
const AJ_TestResult* AJ_LastBatchPtr(uint16_t case_idx, uint8_t seed_idx) noexcept;
uint8_t AJ_LastSeedCount() noexcept;

#endif
