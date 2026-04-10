// =============================================================================
/// @file HTS_AJ_Main.cpp
/// @brief 공인시험급 항재밍 매트릭스 하네스 — 콘솔 진입점 (PC 전용)
// =============================================================================
#if defined(__arm__) && !defined(HTS_ALLOW_HOST_BUILD)
#error "HTS_AJ_Main — PC/host build only"
#endif

#include "HTS_AJ_TestEnv.h"
#include "HTS_AJ_TestRunner.h"

#include <cstdio>

int main() {
    std::printf("%s — Anti-Jam matrix (%u seeds)\n",
                AJ_TestEnv::SYSTEM_NAME,
                static_cast<unsigned>(AJ_TestEnv::SEED_COUNT));
    Run_Full_Matrix(AJ_TestEnv::SEEDS, AJ_TestEnv::SEED_COUNT);
    return 0;
}
