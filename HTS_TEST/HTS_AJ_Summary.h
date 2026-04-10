// =============================================================================
/// @file HTS_AJ_Summary.h
/// @brief 콘솔 요약 + 워터폴용 CSV
// =============================================================================
#ifndef HTS_AJ_SUMMARY_H
#define HTS_AJ_SUMMARY_H

#include "HTS_AJ_TestMatrix.h"
#include "HTS_AJ_TestRunner.h"
#include <cstdint>

void AJ_PrintSummary(const AJ_TestCase* matrix,
                     const AJ_TestResult store_144x8[][8], uint16_t n_cases,
                     uint8_t seed_count) noexcept;

void AJ_WriteWaterfallCsv(const char* path,
                          const AJ_TestResult store_144x8[][8], uint16_t n_cases,
                          uint8_t seed_count) noexcept;

#endif
