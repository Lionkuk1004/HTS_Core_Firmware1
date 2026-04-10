// =============================================================================
/// @file HTS_AJ_Summary.cpp
// =============================================================================
#include "HTS_AJ_Summary.h"
#include "HTS_AJ_TestMatrix.h"

#include <cstdio>
#include <cstring>

/// @brief AJ_MakeCase 역매핑: idx = ch + 4*(js_idx + 9*r2), r2=2*harq+chip64
static uint16_t aj_case_index(uint8_t ch, uint8_t js_idx, uint8_t chip64,
                              uint8_t harq) noexcept {
    const uint16_t r2 = static_cast<uint16_t>(
        static_cast<uint16_t>(chip64 & 1u) |
        (static_cast<uint16_t>(harq & 1u) << 1u));
    const uint16_t r1 = static_cast<uint16_t>(
        static_cast<uint16_t>(js_idx) + static_cast<uint16_t>(9u) * r2);
    return static_cast<uint16_t>(static_cast<uint16_t>(ch) +
                                 static_cast<uint16_t>(4u) * r1);
}

static uint32_t aj_avg_rate_q8_seed0(const AJ_TestResult store[][8],
                                    uint16_t idx, uint8_t nseed) noexcept {
    if (nseed == 0u) {
        return 0u;
    }
    uint32_t s = 0u;
    for (uint8_t i = 0u; i < nseed && i < 8u; ++i) {
        s += static_cast<uint32_t>(store[idx][i].success_rate_q8);
    }
    return s / static_cast<uint32_t>(nseed);
}

void AJ_WriteWaterfallCsv(const char* path,
                          const AJ_TestResult store_144x8[][8], uint16_t n_cases,
                          uint8_t seed_count) noexcept {
    if (path == nullptr || store_144x8 == nullptr) {
        return;
    }
    (void)n_cases;
#if defined(_WIN32)
    FILE* fp = nullptr;
    if (fopen_s(&fp, path, "w") != 0 || fp == nullptr) {
        return;
    }
#else
    FILE* fp = std::fopen(path, "w");
    if (fp == nullptr) {
        return;
    }
#endif
    std::fprintf(fp,
                 "js_dB,chip16_harq_off,chip16_harq_on,chip64_harq_off,chip64_"
                 "harq_on\n");
    for (uint8_t ji = 0u; ji < 9u; ++ji) {
        const uint8_t js = AJ_JS_TABLE[ji];
        uint32_t a = 0u, b = 0u, c = 0u, d = 0u;
        for (uint8_t ch = 0u; ch < 4u; ++ch) {
            a += aj_avg_rate_q8_seed0(
                store_144x8, aj_case_index(ch, ji, 0u, 0u), seed_count);
            b += aj_avg_rate_q8_seed0(
                store_144x8, aj_case_index(ch, ji, 0u, 1u), seed_count);
            c += aj_avg_rate_q8_seed0(
                store_144x8, aj_case_index(ch, ji, 1u, 0u), seed_count);
            d += aj_avg_rate_q8_seed0(
                store_144x8, aj_case_index(ch, ji, 1u, 1u), seed_count);
        }
        a /= 4u;
        b /= 4u;
        c /= 4u;
        d /= 4u;
        const unsigned pa = static_cast<unsigned>((a * 100u) / 256u);
        const unsigned pb = static_cast<unsigned>((b * 100u) / 256u);
        const unsigned pc = static_cast<unsigned>((c * 100u) / 256u);
        const unsigned pd = static_cast<unsigned>((d * 100u) / 256u);
        std::fprintf(fp, "%u,%u.%u,%u.%u,%u.%u,%u.%u\n",
                     static_cast<unsigned>(js), pa / 10u, pa % 10u, pb / 10u,
                     pb % 10u, pc / 10u, pc % 10u, pd / 10u, pd % 10u);
    }
    std::fclose(fp);
}

void AJ_PrintSummary(const AJ_TestCase* matrix,
                     const AJ_TestResult store_144x8[][8], uint16_t n_cases,
                     uint8_t seed_count) noexcept {
    if (matrix == nullptr || store_144x8 == nullptr) {
        return;
    }
    uint16_t pass_all = 0u;
    uint16_t fail_any = 0u;
    for (uint16_t ci = 0u; ci < n_cases && ci < 144u; ++ci) {
        uint8_t allp = 1u;
        for (uint8_t si = 0u; si < seed_count && si < 8u; ++si) {
            if (store_144x8[ci][si].pass_fail == 0u) {
                allp = 0u;
            }
        }
        if (allp != 0u) {
            ++pass_all;
        } else {
            ++fail_any;
        }
    }
    std::printf("\n========== HTS Anti-Jam Test Summary ==========\n");
    std::printf("Total: %u | ALL_SEED_PASS: %u | FAIL(any seed): %u\n",
                static_cast<unsigned>(n_cases), static_cast<unsigned>(pass_all),
                static_cast<unsigned>(fail_any));
    std::printf("FAIL list (first 16):\n");
    uint16_t shown = 0u;
    for (uint16_t ci = 0u; ci < n_cases && ci < 144u && shown < 16u; ++ci) {
        uint8_t bad = 0u;
        for (uint8_t si = 0u; si < seed_count && si < 8u; ++si) {
            if (store_144x8[ci][si].pass_fail == 0u) {
                bad = 1u;
            }
        }
        if (bad != 0u) {
            const AJ_TestResult& r = store_144x8[ci][0];
            std::printf(
                "  T-%03u: js=%u chip=%u HARQ=%u → %u%% pass (thr %u%%)\n",
                static_cast<unsigned>(matrix[ci].test_id),
                static_cast<unsigned>(matrix[ci].js_dB),
                static_cast<unsigned>(matrix[ci].chip_mode),
                static_cast<unsigned>(matrix[ci].harq_on),
                static_cast<unsigned>((r.crc_pass * 100u) /
                                      (r.frames_total ? r.frames_total : 1u)),
                static_cast<unsigned>(matrix[ci].pass_threshold_pct));
            ++shown;
        }
    }
    std::printf("================================================\n");
}
