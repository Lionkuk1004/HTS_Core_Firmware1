// =============================================================================
/// @file HTS_AJ_TestEnv.h
/// @brief HTS 항재밍 공인시험급 하네스 — 빌드·환경 상수 (재현성)
/// @note PC 전용 시험 TU. 펌웨어 코어 미수정.
// =============================================================================
#ifndef HTS_AJ_TESTENV_H
#define HTS_AJ_TESTENV_H

#include <cstdint>

#ifndef BUILD_HASH
#define BUILD_HASH 0u
#endif

namespace AJ_TestEnv {

constexpr const char* SYSTEM_NAME = "INNOViD HTS B-CDMA";
constexpr const char* MCU_TARGET = "STM32F407VGT6 (Cortex-M4F, 168MHz)";
constexpr const char* COMPILER_NOTE = "arm-none-eabi-g++ / MSVC / g++ (see build log)";
constexpr uint32_t BUILD_HASH_VAL = static_cast<uint32_t>(BUILD_HASH);
constexpr const char* BUILD_DATE = __DATE__;
constexpr const char* BUILD_TIME = __TIME__;

/// J/S 정의 (시험 규격서 기재용)
constexpr const char* JS_DEFINITION =
    "Chip-level J/S: 10*log10(P_jam/P_signal) before Walsh despreading "
    "(simulation harness, PC)";

/// 시드 다중 검증 (변경 시 전 시험 무효·재시험)
constexpr uint32_t SEEDS[] = {0xA3B1C2D4u, 0x17F2E8A9u, 0x5C3D9B0Eu,
                              0x8E4F1A2Bu, 0xD6C70539u};
constexpr uint8_t SEED_COUNT =
    static_cast<uint8_t>(sizeof(SEEDS) / sizeof(SEEDS[0]));

} // namespace AJ_TestEnv

#endif
