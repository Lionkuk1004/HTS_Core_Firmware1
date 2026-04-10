// =============================================================================
/// @file HTS_AJ_TestReport.h
/// @brief CSV 행 포맷·결과 파일 기록
// =============================================================================
#ifndef HTS_AJ_TESTREPORT_H
#define HTS_AJ_TESTREPORT_H

#include "HTS_AJ_TestMatrix.h"
#include "HTS_AJ_TestRunner.h"
#include <cstdint>

/// @return 기록 바이트 수
uint16_t Format_CSV_Row(const AJ_TestResult& result, const AJ_TestCase& tc,
                        char* buf, uint16_t buf_size) noexcept;

void AJ_WriteResultsCsv(const char* path, const AJ_TestCase* matrix,
                        const AJ_TestResult store_144x8[][8], uint16_t n_cases,
                        uint8_t seed_count) noexcept;

#endif
