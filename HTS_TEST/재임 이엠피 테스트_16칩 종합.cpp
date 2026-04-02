/// @file  test_holo_v2.cpp
/// @brief HTS_Holo_Tensor_4D + HTS_Holo_Dispatcher Unit Test (Profile-Fixed)
#include "HTS_Holo_Tensor_4D.h"
#include "HTS_Holo_Dispatcher.h"
#include <cstddef>
#include <cstdio>
#include <cstring>

using namespace ProtectedEngine;

static int g_pass = 0, g_fail = 0;
static void CHECK(bool c, const char* n) {
    if (c) { g_pass++; printf("  [PASS] %s\n", n); }
    else { g_fail++; printf("  [FAIL] %s\n", n); }
}

// ── TEST 1: K=16 N=64 L=1 roundtrip (zero loss) ──
static void test_01_roundtrip_k16() {
    printf("\n[TEST 01] K=16 N=64 L=1 encode-decode (zero loss)\n");
    HTS_Holo_Tensor_4D eng;
    uint32_t seed[4] = { 0xDEADBEEF, 0x12345678, 0xABCDABCD, 0x99887766 };
    HoloTensor_Profile p = { 16, 64, 1, {0,0,0} };
    CHECK(eng.Initialize(seed, &p) == HTS_Holo_Tensor_4D::SECURE_TRUE, "Initialize");
    CHECK(eng.Get_State() == HoloState::READY, "State=READY");

    int8_t data[16];
    for (int i = 0; i < 16; i++) data[i] = (i & 1) ? 1 : -1;
    int8_t chips[64];
    CHECK(eng.Encode_Block(data, 16, chips, 64) == HTS_Holo_Tensor_4D::SECURE_TRUE, "Encode");

    int16_t rx[64];
    for (int i = 0; i < 64; i++) rx[i] = static_cast<int16_t>(chips[i] * 127);
    int8_t rec[16];
    CHECK(eng.Decode_Block(rx, 64, 0xFFFFFFFFFFFFFFFFull, rec, 16) == HTS_Holo_Tensor_4D::SECURE_TRUE, "Decode");

    int ok = 0;
    for (int i = 0; i < 16; i++) if (rec[i] == data[i]) ok++;
    printf("    %d/16 correct\n", ok);
    CHECK(ok == 16, "Perfect 16/16");
    eng.Shutdown();
    CHECK(eng.Get_State() == HoloState::OFFLINE, "Shutdown->OFFLINE");
}

// ── TEST 2: K=16 N=64 L=2 self-healing 50% loss ──
static void test_02_heal_50pct() {
    printf("\n[TEST 02] Self-healing 50%% chip loss (K=16 L=2)\n");
    HTS_Holo_Tensor_4D eng;
    uint32_t seed[4] = { 0x11111111, 0x22222222, 0x33333333, 0x44444444 };
    HoloTensor_Profile p = { 16, 64, 2, {0,0,0} };
    eng.Initialize(seed, &p);

    int8_t data[16] = { 1,-1,1,1,-1,-1,1,-1, 1,1,-1,1,-1,1,-1,-1 };
    int8_t chips[64];
    eng.Encode_Block(data, 16, chips, 64);

    int16_t rx[64];
    for (int i = 0; i < 64; i++)
        rx[i] = ((i & 1) == 0) ? static_cast<int16_t>(chips[i] * 100) : 0;

    int8_t rec[16];
    eng.Decode_Block(rx, 64, 0x5555555555555555ull, rec, 16);
    int ok = 0;
    for (int i = 0; i < 16; i++) if (rec[i] == data[i]) ok++;
    printf("    %d/16 with 50%% loss\n", ok);
    CHECK(ok >= 12, ">=75%% recovery (12/16)");
    eng.Shutdown();
}

// ── TEST 3: K=16 N=64 L=3 self-healing 50% → perfect ──
static void test_03_heal_50pct_L3() {
    printf("\n[TEST 03] Self-healing 50%% loss with L=3\n");
    HTS_Holo_Tensor_4D eng;
    uint32_t seed[4] = { 0x11111111, 0x22222222, 0x33333333, 0x44444444 };
    HoloTensor_Profile p = { 16, 64, 3, {0,0,0} };
    eng.Initialize(seed, &p);

    int8_t data[16] = { 1,-1,1,1,-1,-1,1,-1, 1,1,-1,1,-1,1,-1,-1 };
    int8_t chips[64];
    eng.Encode_Block(data, 16, chips, 64);

    int16_t rx[64];
    for (int i = 0; i < 64; i++)
        rx[i] = ((i & 1) == 0) ? static_cast<int16_t>(chips[i] * 100) : 0;

    int8_t rec[16];
    eng.Decode_Block(rx, 64, 0x5555555555555555ull, rec, 16);
    int ok = 0;
    for (int i = 0; i < 16; i++) if (rec[i] == data[i]) ok++;
    printf("    %d/16 with 50%% loss, L=3\n", ok);
    CHECK(ok == 16, "Perfect recovery with L=3");
    eng.Shutdown();
}

// ── TEST 4: K=8 N=64 L=4 self-healing 75% loss ──
static void test_04_heal_75pct() {
    printf("\n[TEST 04] Self-healing 75%% chip loss (K=8 L=4 RESILIENT)\n");
    HTS_Holo_Tensor_4D eng;
    uint32_t seed[4] = { 0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD };
    HoloTensor_Profile p = { 8, 64, 4, {0,0,0} };  // N/K=8
    eng.Initialize(seed, &p);

    int8_t data[8] = { 1,-1,1,1,-1,-1,1,-1 };
    int8_t chips[64];
    eng.Encode_Block(data, 8, chips, 64);

    int16_t rx[64];
    for (int i = 0; i < 64; i++)
        rx[i] = ((i & 3) == 0) ? static_cast<int16_t>(chips[i] * 100) : 0;

    int8_t rec[8];
    eng.Decode_Block(rx, 64, 0x1111111111111111ull, rec, 8);
    int ok = 0;
    for (int i = 0; i < 8; i++) if (rec[i] == data[i]) ok++;
    printf("    %d/8 with 75%% loss, K=8 L=4 (N/K=8)\n", ok);
    CHECK(ok == 8, "Perfect recovery at 75%% loss (N/K=8)");
    eng.Shutdown();
}

// ── TEST 5: Different seeds ──
static void test_05_seed_independence() {
    printf("\n[TEST 05] Different seeds -> different chips\n");
    HTS_Holo_Tensor_4D e1, e2;
    uint32_t s1[4] = { 1,2,3,4 }, s2[4] = { 5,6,7,8 };
    HoloTensor_Profile p = { 16, 64, 1, {0,0,0} };
    e1.Initialize(s1, &p); e2.Initialize(s2, &p);

    int8_t data[16]; for (int i = 0; i < 16; i++) data[i] = 1;
    int8_t c1[64], c2[64];
    e1.Encode_Block(data, 16, c1, 64);
    e2.Encode_Block(data, 16, c2, 64);

    int diff = 0;
    for (int i = 0; i < 64; i++) if (c1[i] != c2[i]) diff++;
    printf("    Chip diff: %d/64\n", diff);
    CHECK(diff > 20, "Significantly different (>20/64)");
    e1.Shutdown(); e2.Shutdown();
}

// ── TEST 6: Wrong seed fails ──
static void test_06_wrong_seed() {
    printf("\n[TEST 06] Wrong seed cannot decode\n");
    uint32_t s1[4] = { 0xAA,0xBB,0xCC,0xDD }, s2[4] = { 0x11,0x22,0x33,0x44 };
    HoloTensor_Profile p = { 16, 64, 2, {0,0,0} };
    HTS_Holo_Tensor_4D tx, rx;
    tx.Initialize(s1, &p); rx.Initialize(s2, &p);

    int8_t data[16] = { 1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,1,-1,1,-1 };
    int8_t chips[64];
    tx.Encode_Block(data, 16, chips, 64);

    int16_t soft[64];
    for (int i = 0; i < 64; i++) soft[i] = static_cast<int16_t>(chips[i] * 127);
    int8_t rec[16];
    rx.Decode_Block(soft, 64, 0xFFFFFFFFFFFFFFFFull, rec, 16);

    int ok = 0;
    for (int i = 0; i < 16; i++) if (rec[i] == data[i]) ok++;
    printf("    Wrong seed: %d/16 (expect ~8 random)\n", ok);
    CHECK(ok < 14, "Near-random (<14/16)");
    tx.Shutdown(); rx.Shutdown();
}

// ── TEST 7: Time slot diversity ──
static void test_07_time_diversity() {
    printf("\n[TEST 07] Time slot changes output\n");
    HTS_Holo_Tensor_4D eng;
    uint32_t seed[4] = { 0x55,0x66,0x77,0x88 };
    HoloTensor_Profile p = { 16, 64, 1, {0,0,0} };
    eng.Initialize(seed, &p);

    int8_t data[16]; for (int i = 0; i < 16; i++) data[i] = 1;
    int8_t c0[64], c1[64];
    eng.Encode_Block(data, 16, c0, 64);
    (void)eng.Advance_Time_Slot();
    eng.Encode_Block(data, 16, c1, 64);

    int diff = 0;
    for (int i = 0; i < 64; i++) if (c0[i] != c1[i]) diff++;
    printf("    Time diff: %d/64\n", diff);
    CHECK(diff > 15, "Different across time (>15/64)");
    eng.Shutdown();
}

// ── TEST 8: Null safety ──
static void test_08_null_safety() {
    printf("\n[TEST 08] Null pointer safety\n");
    HTS_Holo_Tensor_4D eng;
    CHECK(eng.Initialize(nullptr, nullptr) == HTS_Holo_Tensor_4D::SECURE_FALSE, "null seed -> false");
    uint32_t seed[4] = { 1,2,3,4 };
    eng.Initialize(seed, nullptr);
    CHECK(eng.Encode_Block(nullptr, 16, nullptr, 64) == HTS_Holo_Tensor_4D::SECURE_FALSE, "null encode -> false");
    CHECK(eng.Decode_Block(nullptr, 64, 0, nullptr, 16) == HTS_Holo_Tensor_4D::SECURE_FALSE, "null decode -> false");
    eng.Shutdown();
}

// ── TEST 9: Dispatcher mode selection ──
static void test_09_mode_select() {
    printf("\n[TEST 09] Dispatcher auto mode selection\n");
    HTS_Holo_Dispatcher d;
    uint32_t seed[4] = { 0xAA,0xBB,0xCC,0xDD };
    CHECK(d.Initialize(seed) == HTS_Holo_Dispatcher::SECURE_TRUE, "Dispatcher init");

    HTS_RF_Metrics m;
    m.snr_proxy.store(15, std::memory_order_relaxed);
    m.ajc_nf.store(200, std::memory_order_relaxed);
    CHECK(d.Select_Mode(&m) == HoloPayload::VOICE_HOLO, "Quiet->VOICE_HOLO");

    m.snr_proxy.store(7, std::memory_order_relaxed);
    m.ajc_nf.store(800, std::memory_order_relaxed);
    CHECK(d.Select_Mode(&m) == HoloPayload::DATA_HOLO, "Moderate->DATA_HOLO");

    m.snr_proxy.store(3, std::memory_order_relaxed);
    m.ajc_nf.store(3000, std::memory_order_relaxed);
    CHECK(d.Select_Mode(&m) == HoloPayload::RESILIENT_HOLO, "Heavy->RESILIENT");

    CHECK(d.Select_Mode(nullptr) == HoloPayload::DATA_HOLO, "null->DATA_HOLO");
    d.Shutdown();
}

// ── TEST 10: Dispatcher multi-block TX/RX roundtrip ──
static void test_10_dispatcher_roundtrip() {
    printf("\n[TEST 10] Dispatcher multi-block TX/RX roundtrip\n");
    HTS_Holo_Dispatcher tx_d, rx_d;
    uint32_t seed[4] = { 0x11,0x22,0x33,0x44 };
    tx_d.Initialize(seed);
    rx_d.Initialize(seed);

    // DATA_HOLO: K=16, 2 bytes/block, 4 bytes -> 2 blocks -> 128 chips
    uint8_t info[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    int16_t outI[512], outQ[512];
    size_t chips = tx_d.Build_Holo_Packet(
        HoloPayload::DATA_HOLO, info, 4u, 300, outI, outQ, 512u);
    printf("    Built %zu chips (expect 128 = 2 blocks x 64)\n", chips);
    CHECK(chips == 128u, "2 blocks x 64 = 128 chips");

    uint8_t rec[16]; size_t out_len = 0u;
    rx_d.Set_Current_Mode(HoloPayload::DATA_HOLO);  // RX must know TX mode (from header)
    const uint32_t ok = rx_d.Decode_Holo_Block(outI, outQ,
        static_cast<uint16_t>(chips), 0xFFFFFFFFFFFFFFFFull, rec, &out_len);
    CHECK(ok == HTS_Holo_Dispatcher::SECURE_TRUE, "Decode success");
    printf("    Recovered %zu bytes: ", out_len);
    for (size_t i = 0u; i < out_len && i < 4u; i++) printf("%02X ", rec[i]);
    printf("\n");

    bool match = (out_len >= 4);
    if (match) {
        for (int i = 0; i < 4; i++) if (rec[i] != info[i]) match = false;
    }
    CHECK(match, "0xDEADBEEF roundtrip match");

    tx_d.Shutdown(); rx_d.Shutdown();
}

// ── TEST 11: RESILIENT multi-block ──
static void test_11_resilient_roundtrip() {
    printf("\n[TEST 11] RESILIENT_HOLO multi-block (K=8 L=4)\n");
    HTS_Holo_Dispatcher tx_d, rx_d;
    uint32_t seed[4] = { 0xCA,0xFE,0xBA,0xBE };
    tx_d.Initialize(seed); rx_d.Initialize(seed);

    uint8_t info[8] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08 };
    int16_t outI[1024], outQ[1024];
    size_t chips = tx_d.Build_Holo_Packet(
        HoloPayload::RESILIENT_HOLO, info, 8u, 300, outI, outQ, 1024u);
    printf("    Built %zu chips (expect 512 = 8 blocks x 64)\n", chips);
    CHECK(chips == 512u, "8 blocks x 64 = 512 chips");

    uint8_t rec[16]; size_t out_len = 0u;
    rx_d.Set_Current_Mode(HoloPayload::RESILIENT_HOLO);  // RX must know TX mode
    rx_d.Decode_Holo_Block(outI, outQ,
        static_cast<uint16_t>(chips), 0xFFFFFFFFFFFFFFFFull, rec, &out_len);
    printf("    Recovered %zu bytes: ", out_len);
    for (size_t i = 0u; i < out_len && i < 8u; i++) printf("%02X ", rec[i]);
    printf("\n");

    bool match = (out_len >= 8);
    if (match) {
        for (int i = 0; i < 8; i++) if (rec[i] != info[i]) match = false;
    }
    CHECK(match, "8-byte RESILIENT roundtrip match");
    tx_d.Shutdown(); rx_d.Shutdown();
}

// ── TEST 12: Seed rotation ──
static void test_12_seed_rotation() {
    printf("\n[TEST 12] Seed rotation\n");
    HTS_Holo_Tensor_4D eng;
    uint32_t s1[4] = { 1,2,3,4 }, s2[4] = { 5,6,7,8 };
    HoloTensor_Profile p = { 16, 64, 1, {0,0,0} };
    eng.Initialize(s1, &p);

    int8_t data[16]; for (int i = 0; i < 16; i++) data[i] = 1;
    int8_t c1[64]; eng.Encode_Block(data, 16, c1, 64);
    eng.Rotate_Seed(s2);
    int8_t c2[64]; eng.Encode_Block(data, 16, c2, 64);

    int diff = 0;
    for (int i = 0; i < 64; i++) if (c1[i] != c2[i]) diff++;
    printf("    Diff after rotation: %d/64\n", diff);
    CHECK(diff > 20, "Rotation changes output (>20/64)");
    eng.Shutdown();
}

// ── TEST 13: N/K ratio law verification ──
static void test_13_nk_ratio_law() {
    printf("\n[TEST 13] Holographic law: N/K >= 4 required\n");
    uint32_t seed[4] = { 0xCAFE, 0xBABE, 0xFACE, 0xFEED };

    struct { uint16_t K; uint8_t L; int expect_min; } cases[] = {
        { 8,  2, 8  },   // N/K=8 -> perfect
        { 16, 2, 16 },   // N/K=4 -> perfect
        { 32, 2, 24 },   // N/K=2 -> degraded
        { 64, 2, 40 },   // N/K=1 -> poor
    };
    for (auto& c : cases) {
        HTS_Holo_Tensor_4D eng;
        HoloTensor_Profile p = { c.K, 64, c.L, {0,0,0} };
        eng.Initialize(seed, &p);

        int8_t data[128];
        for (int i = 0; i < c.K; i++) data[i] = ((i * 7 + 3) & 1) ? 1 : -1;
        int8_t chips[64];
        eng.Encode_Block(data, c.K, chips, 64);

        int16_t rx[64];
        for (int i = 0; i < 64; i++) rx[i] = static_cast<int16_t>(chips[i] * 127);
        int8_t rec[128];
        eng.Decode_Block(rx, 64, 0xFFFFFFFFFFFFFFFFull, rec, c.K);

        int ok = 0;
        for (int i = 0; i < c.K; i++) if (rec[i] == data[i]) ok++;
        printf("    K=%d N=64 (N/K=%d): %d/%d", c.K, 64 / c.K, ok, c.K);

        char label[64];
        snprintf(label, sizeof(label), "K=%d: >= %d/%d", c.K, c.expect_min, c.K);
        bool pass = (ok >= c.expect_min);
        if (pass) printf(" OK\n"); else printf(" INSUFFICIENT\n");
        CHECK(pass, label);
        eng.Shutdown();
    }
}

int main() {
    printf("=============================================\n");
    printf(" HTS_Holo_Tensor_4D + Dispatcher Test v2\n");
    printf(" (Profile-fixed: N/K>=4 law enforced)\n");
    printf("=============================================\n");

    test_01_roundtrip_k16();
    test_02_heal_50pct();
    test_03_heal_50pct_L3();
    test_04_heal_75pct();
    test_05_seed_independence();
    test_06_wrong_seed();
    test_07_time_diversity();
    test_08_null_safety();
    test_09_mode_select();
    test_10_dispatcher_roundtrip();
    test_11_resilient_roundtrip();
    test_12_seed_rotation();
    test_13_nk_ratio_law();

    printf("\n=============================================\n");
    printf(" Result: %d / %d PASS", g_pass, g_pass + g_fail);
    if (g_fail == 0) printf("  *** ALL CLEAR ***");
    printf("\n=============================================\n");
    return g_fail;
}