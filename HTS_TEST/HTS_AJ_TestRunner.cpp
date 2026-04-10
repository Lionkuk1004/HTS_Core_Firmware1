// =============================================================================
/// @file HTS_AJ_TestRunner.cpp
/// @brief V400 디스패처·FEC 래핑 시험 (힙 미사용, 테스트 폴더 전용)
// =============================================================================
#if defined(__arm__) && !defined(HTS_ALLOW_HOST_BUILD)
#error "HTS_AJ_TestRunner — PC/host build only"
#endif

#include "HTS_AJ_TestRunner.h"
#include "HTS_AJ_Prng.h"
#include "HTS_AJ_Stats.h"
#include "HTS_AJ_TestReport.h"
#include "HTS_AJ_Summary.h"
#include "HTS_FEC_HARQ.hpp"
#include "HTS_V400_Dispatcher.hpp"

#include <cstdio>
#include <cstring>

using ProtectedEngine::DecodedPacket;
using ProtectedEngine::FEC_HARQ;
using ProtectedEngine::HTS_V400_Dispatcher;
using ProtectedEngine::PayloadMode;
using ProtectedEngine::SoftClipPolicy;

static constexpr int16_t kAmp = 2000;
static constexpr int kMaxFeeds = 32;

/// 칩 스트림 최대 길이 (NSYM64·C64 — 호스트 BPS3 시 상한 ~15k)
static constexpr int AJ_NMAX = 256 + FEC_HARQ::NSYM64 * 64;

alignas(64) static int16_t g_oI[AJ_NMAX];
alignas(64) static int16_t g_oQ[AJ_NMAX];
alignas(64) static int32_t g_dbl[AJ_NMAX];

/// J/S(dB) 스텝별 칩 도메인 재밍 진폭 (kAmp·sqrt(10^(J/10)) 근사 정수)
static constexpr uint32_t kJamAmp[9u] = {
    2000u,   6325u,   20000u,  35588u, 63246u,
    112403u, 200000u, 355588u, 632456u};

static ProtectedEngine::DecodedPacket g_aj_last{};

static void aj_on_pkt(const DecodedPacket& p) noexcept { g_aj_last = p; }

static uint8_t aj_js_index(uint8_t js_db) noexcept {
    for (uint8_t i = 0u; i < 9u; ++i) {
        if (AJ_JS_TABLE[i] == js_db) {
            return i;
        }
    }
    return 0u;
}

static void aj_agc(const int32_t* in, int16_t* oI, int16_t* oQ, int n) noexcept {
    int32_t pk = 0;
    for (int i = 0; i < n; ++i) {
        int32_t a = in[i];
        if (a < 0) {
            a = -a;
        }
        if (a > pk) {
            pk = a;
        }
    }
    const int32_t kAgcTarget = 26000;
    int64_t g = 1;
    if (pk > kAgcTarget) {
        g = (static_cast<int64_t>(kAgcTarget) * 65536) / static_cast<int64_t>(pk);
    }
    for (int i = 0; i < n; ++i) {
        int64_t v = (static_cast<int64_t>(in[i]) * g) / 65536;
        if (v > 32767) {
            v = 32767;
        }
        if (v < -32768) {
            v = -32768;
        }
        oI[i] = static_cast<int16_t>(v);
        oQ[i] = oI[i];
    }
}

/// AWGN/BARRAGE: 가우시안 바라지 + 미세 열잡음
static void aj_ch_awgn_barrage(uint8_t js_idx, int n, Xoshiro128* rng) noexcept {
    const uint32_t ja = kJamAmp[js_idx];
    for (int c = 0; c < n; ++c) {
        const int32_t g1 = xoshiro_gauss_i16(rng);
        const int32_t g2 = xoshiro_gauss_i16(rng);
        int64_t v =
            static_cast<int64_t>(g_oI[c]) + (static_cast<int64_t>(ja) * g1) / 32768 +
            (20ll * g2) / 32768;
        if (v > 2147483647LL) {
            v = 2147483647LL;
        }
        if (v < -2147483648LL) {
            v = -2147483648LL;
        }
        g_dbl[c] = static_cast<int32_t>(v);
    }
    aj_agc(g_dbl, g_oI, g_oQ, n);
}

static constexpr int16_t kSin64[64] = {
    0,     3212,  6393,  9512,  12540, 15447, 18205, 20788,
    23170, 25330, 27246, 28898, 30274, 31357, 32138, 32610,
    32767, 32610, 32138, 31357, 30274, 28898, 27246, 25330,
    23170, 20788, 18205, 15447, 12540, 9512,  6393,  3212,
    0,     -3212, -6393, -9512, -12540, -15447, -18205, -20788,
    -23170, -25330, -27246, -28898, -30274, -31357, -32138, -32610,
    -32767, -32610, -32138, -31357, -30274, -28898, -27246, -25330,
    -23170, -20788, -18205, -15447, -12540, -9512, -6393, -3212};

static void aj_ch_cw(uint8_t js_idx, int n, Xoshiro128* rng) noexcept {
    aj_ch_awgn_barrage(js_idx, n, rng);
    const uint32_t cw = kJamAmp[js_idx] / 4u;
    for (int c = 0; c < n; ++c) {
        const int32_t add =
            static_cast<int32_t>((static_cast<int64_t>(cw) * kSin64[c & 63]) >> 15);
        int32_t v = static_cast<int32_t>(g_oI[c]) + add;
        if (v > 32767) {
            v = 32767;
        }
        if (v < -32768) {
            v = -32768;
        }
        g_oI[c] = static_cast<int16_t>(v);
        g_oQ[c] = g_oI[c];
    }
    (void)rng;
}

static void aj_ch_emp(uint8_t js_idx, int n, Xoshiro128* rng) noexcept {
    aj_ch_awgn_barrage(js_idx, n, rng);
    const uint8_t pct = (AJ_JS_TABLE[js_idx] > 50u) ? 50u : AJ_JS_TABLE[js_idx];
    for (int c = 0; c < n; ++c) {
        const uint32_t r = xoshiro128_next(rng) % 100u;
        if (r < pct) {
            g_oI[c] = 0;
            g_oQ[c] = 0;
        }
    }
}

static void aj_apply_channel(uint8_t ch, uint8_t js_idx, int n,
                             Xoshiro128* rng) noexcept {
    switch (ch) {
    case 0u:
    case 1u:
        aj_ch_awgn_barrage(js_idx, n, rng);
        break;
    case 2u:
        aj_ch_cw(js_idx, n, rng);
        break;
    case 3u:
        aj_ch_emp(js_idx, n, rng);
        break;
    default:
        aj_ch_awgn_barrage(js_idx, n, rng);
        break;
    }
}

static AJ_TestResult g_matrix_store[144][8];
static uint8_t g_seeds_used = 0u;

void Run_Single_Test(const AJ_TestCase& tc, uint32_t seed,
                     AJ_TestResult& result) noexcept {
    std::memset(&result, 0, sizeof(result));
    result.test_id = tc.test_id;
    result.seed_used = seed;

    const uint16_t frames = (tc.frame_count == 0u) ? 1u : tc.frame_count;
    result.frames_total = frames;

    const PayloadMode mode =
        (tc.chip_mode == 64u) ? PayloadMode::DATA : PayloadMode::VOICE;
    const uint8_t js_idx = aj_js_index(tc.js_dB);
    const uint8_t thr = (tc.pass_threshold_pct != 0u)
                            ? tc.pass_threshold_pct
                            : AJ_PassThresholdPct(tc);

    uint16_t pass_n = 0u;

    for (uint16_t fr = 0u; fr < frames; ++fr) {
        g_aj_last = DecodedPacket{};
        Xoshiro128 rng{};
        const uint32_t ds =
            seed ^ static_cast<uint32_t>(fr) * 0x9E3779B9u;
        xoshiro128_seed(&rng, ds ^ 0x85EBCA6Bu);

        HTS_V400_Dispatcher disp{};
        disp.Set_IR_Mode(tc.harq_on != 0u);
        disp.Set_Seed(ds);
        disp.Set_Preamble_Boost(1);
        disp.Set_IR_SIC_Enabled(false);
        disp.Set_CW_Cancel(false);
        disp.Set_AJC_Enabled(false);
        disp.Set_SoftClip_Policy(SoftClipPolicy::NEVER);
        disp.Set_Packet_Callback(aj_on_pkt);
        disp.Set_Lab_IQ_Mode_Jam_Harness();
        disp.Set_Lab_BPS64(static_cast<int>(tc.bps));
        FEC_HARQ::Set_IR_Erasure_Enabled(tc.harq_on != 0u);
        FEC_HARQ::Set_IR_Rs_Post_Enabled(tc.harq_on != 0u);

        uint8_t info[8] = {};
        for (int b = 0; b < 8; ++b) {
            info[b] = static_cast<uint8_t>(
                static_cast<unsigned>(ds >> static_cast<unsigned>(b * 4)) ^
                static_cast<unsigned>(fr + b));
        }

        int success = 0;
        for (int feed = 0; feed < kMaxFeeds && success == 0; ++feed) {
            int n = 0;
            if (feed == 0 || !disp.Is_Retx_Ready()) {
                n = disp.Build_Packet(mode, info, 8, kAmp, g_oI, g_oQ, AJ_NMAX);
            } else {
                n = disp.Build_Retx(mode, info, 8, kAmp, g_oI, g_oQ, AJ_NMAX);
            }
            if (n <= 0) {
                break;
            }
            aj_apply_channel(tc.channel_type, js_idx, n, &rng);

            if (feed == 0 || !disp.Is_Retx_Ready()) {
                for (int i = 0; i < n; ++i) {
                    disp.Feed_Chip(g_oI[i], g_oQ[i]);
                }
            } else {
                for (int i = 0; i < n; ++i) {
                    disp.Feed_Retx_Chip(g_oI[i], g_oQ[i]);
                }
            }
            if (g_aj_last.success_mask == DecodedPacket::DECODE_MASK_OK) {
                success = 1;
            }
        }
        if (success != 0) {
            ++pass_n;
        }
    }

    result.crc_pass = pass_n;
    result.crc_fail = static_cast<uint16_t>(frames - pass_n);
    result.success_rate_q8 = AJ_Rate_Q8(frames, pass_n);
    AJ_Wilson95_Q8(frames, pass_n, &result.ci_lower_q8, &result.ci_upper_q8);

    const uint32_t lhs = static_cast<uint32_t>(pass_n) * 100u;
    const uint32_t rhs =
        static_cast<uint32_t>(frames) * static_cast<uint32_t>(thr);
    result.pass_fail = (lhs >= rhs) ? 1u : 0u;
}

const AJ_TestResult* AJ_LastBatchPtr(uint16_t case_idx,
                                     uint8_t seed_idx) noexcept {
    if (case_idx >= 144u || seed_idx >= 8u) {
        return nullptr;
    }
    return &g_matrix_store[case_idx][seed_idx];
}

uint8_t AJ_LastSeedCount() noexcept { return g_seeds_used; }

void Run_Full_Matrix(const uint32_t* seeds, uint8_t seed_count) noexcept {
    if (seeds == nullptr || seed_count == 0u) {
        return;
    }
    if (seed_count > 8u) {
        seed_count = 8u;
    }
    g_seeds_used = seed_count;

    AJ_TestCase matrix[144];
    AJ_FillMatrix(matrix, 144);

    for (uint16_t ci = 0u; ci < 144u; ++ci) {
        for (uint8_t si = 0u; si < seed_count; ++si) {
            Run_Single_Test(matrix[ci], seeds[si], g_matrix_store[ci][si]);
        }
    }

    AJ_WriteResultsCsv("HTS_AJ_Results.csv", matrix, g_matrix_store, 144u,
                       seed_count);
    AJ_WriteWaterfallCsv("HTS_AJ_Waterfall.csv", g_matrix_store, 144u,
                         seed_count);
    AJ_PrintSummary(matrix, g_matrix_store, 144u, seed_count);
}
