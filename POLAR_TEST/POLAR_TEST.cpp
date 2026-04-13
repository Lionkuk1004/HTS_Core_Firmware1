// =============================================================================
// POLAR_TEST.cpp — HTS Polar Codec 검증 테스트
//
// [테스트 항목]
//  L0: 인코더 왕복 (클린 채널)
//  L1: SC 디코더 AWGN BER
//  L2: Conv+REP4 대비 성능 비교
//
// [빌드] POLAR_TEST 프로젝트에 HTS_Polar_Codec.cpp 포함
//
// [격리 단계] POLAR_TEST_STEP (vcxproj 기본 3, 또는 MSBuild 전달)
//   /p:PolarTestStep=1  → L0 + L1 (SC 왕복)
//   /p:PolarTestStep=2  → L0 + L1 + L2 (AWGN, SC+SCL)
//   /p:PolarTestStep=3  → 전체 (+ L3 타이밍)
// =============================================================================
#include "HTS_Polar_Codec.h"
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#if !defined(POLAR_TEST_STEP) || POLAR_TEST_STEP < 1 || POLAR_TEST_STEP > 3
#error POLAR_TEST_STEP must be 1, 2, or 3 (see file header; vcxproj defines default)
#endif
using Polar = ProtectedEngine::HTS_Polar_Codec;
// ── 유틸리티 ──────────────────────────────────────────────
static void gen_info(uint32_t seed, uint8_t *info, int len) {
    uint32_t s = seed;
    for (int i = 0; i < len; ++i) {
        s ^= s << 13u;
        s ^= s >> 17u;
        s ^= s << 5u;
        info[i] = static_cast<uint8_t>(s & 0xFFu);
    }
}
static void print_hex(const char *label, const uint8_t *data, int len) {
    std::printf("  %s: ", label);
    for (int i = 0; i < len; ++i)
        std::printf("%02X ", data[i]);
    std::printf("\n");
}
// ── BPSK 변조: bit → ±1.0 (double) ──────────────────────
static void bpsk_modulate(const uint8_t *coded_bytes, int n_bits,
                          double *signal) {
    for (int i = 0; i < n_bits; ++i) {
        const int byte_idx = i >> 3;
        const int bit_idx = 7 - (i & 7);
        const uint8_t bit = (coded_bytes[byte_idx] >> bit_idx) & 1u;
        signal[i] = (bit == 0u) ? +1.0 : -1.0;
    }
}
// ── AWGN 채널 ─────────────────────────────────────────────
static void add_awgn(double *signal, int n, double snr_db, std::mt19937 &rng) {
    // Eb/N0 → σ  (BPSK: Eb/N0 = SNR for rate=1)
    // 코드 레이트 R = K/N = 80/512
    const double R =
        static_cast<double>(Polar::K) / static_cast<double>(Polar::N);
    const double ebn0_lin = std::pow(10.0, snr_db / 10.0);
    const double sigma = std::sqrt(1.0 / (2.0 * R * ebn0_lin));
    std::normal_distribution<double> nd(0.0, sigma);
    for (int i = 0; i < n; ++i) {
        signal[i] += nd(rng);
    }
}
// ── LLR 변환: 수신 신호 → int16 LLR ─────────────────────
//  LLR = 2y/σ² (BPSK), 양수 = bit 0 쪽
//  스케일: ×256 (Q8 고정소수) → int16
static void signal_to_llr(const double *signal, int n, double snr_db,
                          int16_t *llr) {
    const double R =
        static_cast<double>(Polar::K) / static_cast<double>(Polar::N);
    const double ebn0_lin = std::pow(10.0, snr_db / 10.0);
    const double sigma2 = 1.0 / (2.0 * R * ebn0_lin);
    const double scale = 2.0 / sigma2;
    for (int i = 0; i < n; ++i) {
        double val = signal[i] * scale * 64.0; // Q6 스케일
        if (val > 32767.0)
            val = 32767.0;
        if (val < -32768.0)
            val = -32768.0;
        llr[i] = static_cast<int16_t>(std::lround(val));
    }
}
// ═════════════════════════════════════════════════════════
//  L0: 인코더 기본 검증
// ═════════════════════════════════════════════════════════
static bool test_L0_encoder() {
    std::printf("\n=== L0: 인코더 기본 검증 ===\n");
    // L0-1: frozen mask K=80 검증
    int info_count = 0;
    for (int i = 0; i < Polar::N; ++i) {
        if (Polar::Is_Info_Bit(i))
            info_count++;
    }
    std::printf("  Info bits: %d (expect %d) %s\n", info_count, Polar::K,
                (info_count == Polar::K) ? "OK" : "FAIL");
    if (info_count != Polar::K)
        return false;
    // L0-2: 인코딩 출력 길이
    uint8_t info[8] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    uint8_t coded[Polar::N / 8] = {};
    int n = Polar::Encode(info, 8, coded);
    std::printf("  Encode length: %d (expect %d) %s\n", n, Polar::N,
                (n == Polar::N) ? "OK" : "FAIL");
    if (n != Polar::N)
        return false;
    // L0-3: 두 번 인코딩 동일성 (결정론적)
    uint8_t coded2[Polar::N / 8] = {};
    (void)Polar::Encode(info, 8, coded2);
    bool deterministic =
        (std::memcmp(coded, coded2, static_cast<std::size_t>(Polar::N / 8)) ==
         0);
    std::printf("  Deterministic: %s\n", deterministic ? "OK" : "FAIL");
    if (!deterministic)
        return false;
    // L0-4: 다른 입력 → 다른 출력
    uint8_t info2[8] = {0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12};
    uint8_t coded3[Polar::N / 8] = {};
    (void)Polar::Encode(info2, 8, coded3);
    bool different =
        (std::memcmp(coded, coded3, static_cast<std::size_t>(Polar::N / 8)) !=
         0);
    std::printf("  Different input → different output: %s\n",
                different ? "OK" : "FAIL");
    if (!different)
        return false;
    // L0-5: CRC 검증
    uint16_t crc = Polar::CRC16(info, 8);
    std::printf("  CRC16(info): 0x%04X\n", crc);
    std::printf("  L0: PASS\n");
    return true;
}
// ═════════════════════════════════════════════════════════
//  L1: 클린 채널 왕복 (Encode → 완벽 LLR → Decode)
// ═════════════════════════════════════════════════════════
static bool test_L1_roundtrip() {
    std::printf("\n=== L1: 클린 채널 왕복 ===\n");
    int pass = 0, fail = 0;
    for (uint32_t seed = 1; seed <= 20; ++seed) {
        uint8_t info[8];
        gen_info(seed, info, 8);
        // 인코딩
        uint8_t coded[Polar::N / 8] = {};
        int n = Polar::Encode(info, 8, coded);
        if (n != Polar::N) {
            fail++;
            continue;
        }
        // 완벽 LLR 생성: bit=0 → +1000, bit=1 → -1000
        static int16_t llr[Polar::N];
        for (int i = 0; i < Polar::N; ++i) {
            const int byte_idx = i >> 3;
            const int bit_idx = 7 - (i & 7);
            const uint8_t bit = (coded[byte_idx] >> bit_idx) & 1u;
            llr[i] = (bit == 0u) ? static_cast<int16_t>(1000)
                                 : static_cast<int16_t>(-1000);
        }
        // SC 디코딩
        uint8_t out[8] = {};
        int olen = 0;
        bool ok = Polar::Decode_SC(llr, out, &olen);
        if (ok && olen == 8 && std::memcmp(info, out, 8) == 0) {
            pass++;
        } else {
            fail++;
            if (fail <= 3) {
                std::printf("  [%2u] FAIL: ok=%d olen=%d\n", seed, (int)ok,
                            olen);
                print_hex("TX ", info, 8);
                print_hex("RX ", out, 8);
            }
        }
    }
    std::printf("  L1: %d/20 %s\n", pass, (pass == 20) ? "PASS" : "FAIL");
    return (pass == 20);
}
// ═════════════════════════════════════════════════════════
//  L2: AWGN BER 커브 (SC + SCL 비교)
// ═════════════════════════════════════════════════════════
static void test_L2_awgn_ber() {
    std::printf("\n=== L2: AWGN BER (N=%d, K=%d) — SC vs SCL-%d ===\n",
                Polar::N, Polar::K, Polar::SCL_L);
    std::printf("  Eb/N0  |  SC BLER  |  SCL BLER |  Frames\n");
    std::printf("  -------+-----------+-----------+--------\n");
    const double snr_list[] = {-1, 0, 1, 2, 3, 4, 5, 6, 7, 8};
    const int n_snr = sizeof(snr_list) / sizeof(snr_list[0]);
    for (int si = 0; si < n_snr; ++si) {
        const double snr = snr_list[si];
        const int max_frames = 500;
        const int max_errors = 50;
        int frames = 0, err_sc = 0, err_scl = 0;
        std::mt19937 rng(42u + static_cast<uint32_t>(si * 1000));
        for (int f = 0;
             f < max_frames && (err_sc < max_errors || err_scl < max_errors);
             ++f) {
            uint8_t info[8];
            gen_info(static_cast<uint32_t>(f + si * 10000), info, 8);
            uint8_t coded[Polar::N / 8] = {};
            int n = Polar::Encode(info, 8, coded);
            if (n != Polar::N) {
                err_sc++;
                err_scl++;
                frames++;
                continue;
            }
            static double signal[Polar::N];
            bpsk_modulate(coded, Polar::N, signal);
            // 동일 잡음으로 SC/SCL 공정 비교
            double sig_copy[Polar::N];
            std::memcpy(sig_copy, signal, sizeof(signal));
            add_awgn(signal, Polar::N, snr, rng);
            // SCL도 동일 잡음 사용
            std::memcpy(sig_copy, signal, sizeof(signal));
            static int16_t llr[Polar::N];
            signal_to_llr(signal, Polar::N, snr, llr);
            frames++;
            // SC
            {
                uint8_t out[8] = {};
                int olen = 0;
                bool ok = Polar::Decode_SC(llr, out, &olen);
                if (!ok || olen != 8 || std::memcmp(info, out, 8) != 0)
                    err_sc++;
            }
            // SC vs SCL-%d
            {
                uint8_t out[8] = {};
                int olen = 0;
                bool ok = Polar::Decode_SCL(llr, out, &olen);
                if (!ok || olen != 8 || std::memcmp(info, out, 8) != 0)
                    err_scl++;
            }
        }
        double bler_sc = (frames > 0) ? (double)err_sc / frames : 1.0;
        double bler_scl = (frames > 0) ? (double)err_scl / frames : 1.0;
        std::printf("  %4.1f dB |  %6.3f   |  %6.3f   |  %5d\n", snr, bler_sc,
                    bler_scl, frames);
        if (err_sc == 0 && err_scl == 0 && frames >= 100) {
            std::printf("    (이하 0 오류, 중단)\n");
            break;
        }
    }
}
// ═════════════════════════════════════════════════════════
//  L3: CPU 성능 측정
// ═════════════════════════════════════════════════════════
static void test_L3_cpu_timing() {
    std::printf("\n=== L3: CPU 타이밍 ===\n");
    uint8_t info[8] = {0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89};
    uint8_t coded[Polar::N / 8] = {};
    static int16_t llr[Polar::N];
    // 인코딩 타이밍
    const int iters = 10000;
    auto t0 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iters; ++i) {
        (void)Polar::Encode(info, 8, coded);
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    double enc_us = std::chrono::duration<double, std::micro>(t1 - t0).count() /
                    static_cast<double>(iters);
    // 클린 LLR 생성
    for (int i = 0; i < Polar::N; ++i) {
        const int byte_idx = i >> 3;
        const int bit_idx = 7 - (i & 7);
        const uint8_t bit = (coded[byte_idx] >> bit_idx) & 1u;
        llr[i] = (bit == 0u) ? static_cast<int16_t>(500)
                             : static_cast<int16_t>(-500);
    }
    // 디코딩 타이밍 — SC
    uint8_t out[8] = {};
    int olen = 0;
    t0 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iters; ++i) {
        (void)Polar::Decode_SC(llr, out, &olen);
    }
    t1 = std::chrono::high_resolution_clock::now();
    double dec_sc_us =
        std::chrono::duration<double, std::micro>(t1 - t0).count() /
        static_cast<double>(iters);
    // 디코딩 타이밍 — SC vs SCL-%d
    t0 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i) {
        (void)Polar::Decode_SCL(llr, out, &olen);
    }
    t1 = std::chrono::high_resolution_clock::now();
    double dec_scl_us =
        std::chrono::duration<double, std::micro>(t1 - t0).count() / 1000.0;
    std::printf("  Encode:      %.1f µs\n", enc_us);
    std::printf("  Decode SC:   %.1f µs\n", dec_sc_us);
    std::printf("  Decode SCL4: %.1f µs\n", dec_scl_us);
    std::printf("  SCL/SC 비율: %.1fx\n", dec_scl_us / dec_sc_us);
}
// ═════════════════════════════════════════════════════════
//  메인
// ═════════════════════════════════════════════════════════
int main() {
    std::printf("╔══════════════════════════════════════════════╗\n");
    std::printf("║  HTS Polar Codec Test                        ║\n");
    std::printf("║  N=%d, K=%d, R=%.3f                        ║\n", Polar::N,
                Polar::K,
                static_cast<double>(Polar::K) / static_cast<double>(Polar::N));
    std::printf("╚══════════════════════════════════════════════╝\n");
    std::printf("  [격리] POLAR_TEST_STEP=%d\n", POLAR_TEST_STEP);
    bool all_pass = true;
    // L0: 인코더 기본 검증 (항상)
    if (!test_L0_encoder())
        all_pass = false;
#if POLAR_TEST_STEP >= 1
    // L1: 클린 채널 왕복 (Decode_SC) — Step1에서 크래시 시 SC 의심
    if (!test_L1_roundtrip())
        all_pass = false;
#endif
#if POLAR_TEST_STEP >= 2
    // L2: AWGN BER (SC+SCL) — Step2에서만 크래시 시 SCL 경로 의심
    test_L2_awgn_ber();
#endif
#if POLAR_TEST_STEP >= 3
    test_L3_cpu_timing();
#endif
    std::printf("\n═══════════════════════════════════════════\n");
    std::printf("  최종: %s\n", all_pass ? "ALL PASS" : "FAIL DETECTED");
    std::printf("═══════════════════════════════════════════\n");
    return all_pass ? 0 : 1;
}
