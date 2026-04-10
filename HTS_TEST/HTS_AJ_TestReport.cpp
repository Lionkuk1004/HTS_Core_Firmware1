// =============================================================================
/// @file HTS_AJ_TestReport.cpp
// =============================================================================
#include "HTS_AJ_TestReport.h"
#include "HTS_AJ_TestEnv.h"

#include <cstdio>

#include <cstring>

static const char* aj_ch_name(uint8_t c) noexcept {
    switch (c) {
    case 0u:
        return "AWGN";
    case 1u:
        return "BARRAGE";
    case 2u:
        return "CW";
    case 3u:
        return "EMP";
    default:
        return "?";
    }
}

static uint32_t aj_crc32_date_time() noexcept {
    const char* p = __DATE__;
    const char* q = __TIME__;
    uint32_t c = 0xFFFFFFFFu;
    while (*p != '\0') {
        c ^= static_cast<uint32_t>(static_cast<unsigned char>(*p++));
        for (int k = 0; k < 8; ++k) {
            const uint32_t m = 0u - (c & 1u);
            c = (c >> 1u) ^ (0xEDB88320u & m);
        }
    }
    while (*q != '\0') {
        c ^= static_cast<uint32_t>(static_cast<unsigned char>(*q++));
        for (int k = 0; k < 8; ++k) {
            const uint32_t m = 0u - (c & 1u);
            c = (c >> 1u) ^ (0xEDB88320u & m);
        }
    }
    return c ^ 0xFFFFFFFFu;
}

uint16_t Format_CSV_Row(const AJ_TestResult& result, const AJ_TestCase& tc,
                        char* buf, uint16_t buf_size) noexcept {
    if (buf == nullptr || buf_size < 64u) {
        return 0u;
    }
    const uint32_t bh =
        (AJ_TestEnv::BUILD_HASH_VAL != 0u) ? AJ_TestEnv::BUILD_HASH_VAL
                                           : aj_crc32_date_time();
    const unsigned sr_pct =
        (result.frames_total > 0u)
            ? static_cast<unsigned>(
                  (static_cast<uint32_t>(result.crc_pass) * 100u) /
                  static_cast<uint32_t>(result.frames_total))
            : 0u;
    const unsigned lo_pct =
        static_cast<unsigned>((static_cast<uint32_t>(result.ci_lower_q8) *
                               100u) /
                              256u);
    const unsigned hi_pct =
        static_cast<unsigned>((static_cast<uint32_t>(result.ci_upper_q8) *
                               100u) /
                              256u);
    const int n = std::snprintf(
        buf, static_cast<size_t>(buf_size),
        "T-%03u,%s,%s,%u,%u,%u,%s,%u,%u,%u,%u.%u,%u.%u,%u.%u,%s,0x%08X,%08X",
        static_cast<unsigned>(tc.test_id), aj_ch_name(tc.channel_type),
        aj_ch_name(tc.jam_type), static_cast<unsigned>(tc.js_dB),
        static_cast<unsigned>(tc.chip_mode), static_cast<unsigned>(tc.bps),
        (tc.harq_on != 0u) ? "ON" : "OFF", static_cast<unsigned>(result.frames_total),
        static_cast<unsigned>(result.crc_pass),
        static_cast<unsigned>(result.crc_fail), sr_pct / 10u, sr_pct % 10u,
        lo_pct / 10u, lo_pct % 10u, hi_pct / 10u, hi_pct % 10u,
        (result.pass_fail != 0u) ? "PASS" : "FAIL",
        static_cast<unsigned>(result.seed_used), static_cast<unsigned>(bh));
    if (n <= 0) {
        return 0u;
    }
    return static_cast<uint16_t>(n > 0xFFFF ? 0xFFFF : n);
}

void AJ_WriteResultsCsv(const char* path, const AJ_TestCase* matrix,
                        const AJ_TestResult store_144x8[][8], uint16_t n_cases,
                        uint8_t seed_count) noexcept {
    if (path == nullptr || matrix == nullptr || store_144x8 == nullptr) {
        return;
    }
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
    std::fprintf(
        fp,
        "test_id,channel,jam_type,js_dB,chip_mode,bps,harq_on,frames,crc_pass,"
        "crc_fail,success_rate_pct,ci_lo_pct,ci_hi_pct,pass_fail,seed,build_"
        "hash\n");
    char line[384];
    for (uint16_t ci = 0u; ci < n_cases && ci < 144u; ++ci) {
        for (uint8_t si = 0u; si < seed_count && si < 8u; ++si) {
            const uint16_t n = Format_CSV_Row(store_144x8[ci][si], matrix[ci],
                                              line, static_cast<uint16_t>(sizeof(line)));
            if (n > 0u) {
                std::fwrite(line, 1u, static_cast<size_t>(n), fp);
                std::fputc('\n', fp);
            }
        }
    }
    std::fclose(fp);
}
