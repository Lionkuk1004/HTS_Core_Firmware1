// HTS_FEC_Layer_Test.cpp — 에러정정 레이어별 독립 검증
//
// [테스트 방법론]
//   연구실 기준: 각 레이어를 독립적으로 검증하여 이득을 측정.
//   디스패처(프리앰블/헤더)를 우회하여 순수 FEC 성능만 측정.
//
//   Layer 0: Encode→Decode 왕복 (채널 없음) → 코덱 무결성
//   Layer 1: Walsh PG만 (Conv/REP/HARQ 없음) → 18.1dB/12.0dB 확인
//   Layer 2: Walsh + Conv+REP (1라운드) → 코딩이득 확인
//   Layer 3: Walsh + Conv+REP + IR-HARQ (N라운드) → HARQ 이득 확인
//   Layer 4: 전체 스택 (디스패처 경유) → 프리앰블/헤더 포함 통합
//
//   각 레이어의 한계 J/S를 측정하면 이득 분리 가능:
//     Layer 2 한계 - Layer 1 한계 = Conv+REP 코딩이득
//     Layer 3 한계 - Layer 2 한계 = HARQ 누적이득
//
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) ||                          \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#error "[HTS_FATAL] PC 전용"
#endif
#include "HTS_FEC_HARQ.hpp"
#include "HTS_V400_Dispatcher.hpp"
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>
namespace {
using ProtectedEngine::DecodedPacket;
using ProtectedEngine::FEC_HARQ;
using ProtectedEngine::HTS_V400_Dispatcher;
using ProtectedEngine::PayloadMode;
using ProtectedEngine::SoftClipPolicy;
static constexpr int16_t kAmp = 2000;
static constexpr double kAmpD = 2000.0;
static constexpr double kAgcTarget = 26000.0;
// ── popcount (Walsh 인코딩용) ──
static constexpr uint32_t popc32(uint32_t x) noexcept {
    x = x - ((x >> 1u) & 0x55555555u);
    x = (x & 0x33333333u) + ((x >> 2u) & 0x33333333u);
    return (((x + (x >> 4u)) & 0x0F0F0F0Fu) * 0x01010101u) >> 24u;
}
// ── Walsh 인코딩 (I=Q 동일) ──
static void walsh_enc_iq(uint8_t sym, int nc, int16_t amp, int16_t *oI,
                         int16_t *oQ) noexcept {
    for (int j = 0; j < nc; ++j) {
        const uint32_t p =
            popc32(static_cast<uint32_t>(sym) & static_cast<uint32_t>(j)) & 1u;
        const int16_t ch = static_cast<int16_t>(
            static_cast<int32_t>(amp) * (1 - 2 * static_cast<int32_t>(p)));
        oI[j] = ch;
        oQ[j] = ch;
    }
}
// ── BARRAGE 채널 (double) ──
static void add_barrage(const int16_t *tx, double *out, int n, double js_db,
                        std::mt19937 &rng) noexcept {
    const double js_lin = std::pow(10.0, js_db / 10.0);
    const double sigma = kAmpD * std::sqrt(js_lin);
    std::normal_distribution<double> nd(0.0, 1.0);
    for (int i = 0; i < n; ++i)
        out[i] = static_cast<double>(tx[i]) + sigma * nd(rng);
}
// ── AGC + 양자화 ──
static void agc_quantize(const double *in, int16_t *oI, int16_t *oQ,
                         int n) noexcept {
    double pk = 0.0;
    for (int i = 0; i < n; ++i) {
        double a = std::fabs(in[i]);
        if (a > pk)
            pk = a;
    }
    double g = (pk > kAgcTarget) ? (kAgcTarget / pk) : 1.0;
    for (int i = 0; i < n; ++i) {
        long r = std::lround(in[i] * g);
        if (r > 32767L)
            r = 32767L;
        if (r < -32768L)
            r = -32768L;
        oI[i] = static_cast<int16_t>(r);
        oQ[i] = oI[i];
    }
}
// ================================================================
//  Layer 0: Encode → Decode 왕복 (채널 없음)
//  목적: 코덱 자체의 무결성 검증
// ================================================================
static bool test_layer0() noexcept {
    std::printf("\n=== Layer 0: 코덱 왕복 검증 (채널 없음) ===\n");
    FEC_HARQ::WorkBuf wb{};
    bool all_ok = true;
    std::printf("  BPS64_MIN_OPERABLE=%d, NSYM64=%d\n",
                FEC_HARQ::BPS64_MIN_OPERABLE, FEC_HARQ::NSYM64);
    // 64칩 DATA: Encode64_IR → 칩 생성 → (잡음 없음) → Decode64_IR
    for (int bps = FEC_HARQ::BPS64_MIN_OPERABLE; bps <= 6; ++bps) {
        const int nsym = FEC_HARQ::nsym_for_bps(bps);
        const int nc = 64;
        uint8_t info[8] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
        uint8_t syms[FEC_HARQ::NSYM64]{};
        std::memset(&wb, 0, sizeof(wb));
        int enc_n =
            FEC_HARQ::Encode64_IR(info, 8, syms, 0xABCD1234u, bps, 0, wb);
        if (enc_n <= 0) {
            std::printf("  BPS=%d: Encode FAIL (enc_n=%d) — 지원 범위 외\n",
                        bps, enc_n);
            // 지원 범위 밖이면 SKIP (FAIL 아님)
            continue;
        }
        // Walsh 인코딩 → int16_t 칩
        std::vector<int16_t> chipI(static_cast<size_t>(nsym * nc));
        std::vector<int16_t> chipQ(static_cast<size_t>(nsym * nc));
        for (int s = 0; s < nsym; ++s) {
            walsh_enc_iq(syms[s], nc, kAmp, &chipI[static_cast<size_t>(s * nc)],
                         &chipQ[static_cast<size_t>(s * nc)]);
        }
        // 잡음 없이 바로 디코딩
        FEC_HARQ::IR_RxState ir{};
        FEC_HARQ::IR_Init(ir);
        FEC_HARQ::Set_IR_Erasure_Enabled(false);
        FEC_HARQ::Set_IR_Rs_Post_Enabled(true);
        uint8_t out[8]{};
        int olen = 0;
        std::memset(&wb, 0, sizeof(wb));
        bool ok =
            FEC_HARQ::Decode64_IR(chipI.data(), chipQ.data(), nsym, nc, bps,
                                  0xABCD1234u, 0, ir, out, &olen, wb);
        bool match = ok && (olen == 8) && (std::memcmp(out, info, 8) == 0);
        std::printf("  BPS=%d nsym=%d: Encode=%d Decode=%s Match=%s\n", bps,
                    nsym, enc_n, ok ? "OK" : "FAIL", match ? "OK" : "FAIL");
        if (!match)
            all_ok = false;
    }
    // 16칩 VOICE
    {
        uint8_t info[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22};
        uint8_t syms[FEC_HARQ::NSYM16]{};
        std::memset(&wb, 0, sizeof(wb));
        int enc_n = FEC_HARQ::Encode16_IR(info, 8, syms, 0x12345678u, 0, wb);
        std::vector<int16_t> chipI(static_cast<size_t>(FEC_HARQ::NSYM16 * 16));
        std::vector<int16_t> chipQ(static_cast<size_t>(FEC_HARQ::NSYM16 * 16));
        for (int s = 0; s < FEC_HARQ::NSYM16; ++s) {
            walsh_enc_iq(syms[s], 16, kAmp, &chipI[static_cast<size_t>(s * 16)],
                         &chipQ[static_cast<size_t>(s * 16)]);
        }
        FEC_HARQ::IR_RxState ir{};
        FEC_HARQ::IR_Init(ir);
        uint8_t out[8]{};
        int olen = 0;
        std::memset(&wb, 0, sizeof(wb));
        bool ok = FEC_HARQ::Decode16_IR(chipI.data(), chipQ.data(),
                                        FEC_HARQ::NSYM16, 16, FEC_HARQ::BPS16,
                                        0x12345678u, 0, ir, out, &olen, wb);
        bool match = ok && (olen == 8) && (std::memcmp(out, info, 8) == 0);
        std::printf("  16chip BPS=4 nsym=%d: Decode=%s Match=%s\n",
                    FEC_HARQ::NSYM16, ok ? "OK" : "FAIL",
                    match ? "OK" : "FAIL");
        if (!match)
            all_ok = false;
    }
    std::printf("  Layer 0: %s\n", all_ok ? "PASS" : "FAIL");
    return all_ok;
}
// ================================================================
//  Layer 2+3 통합: Walsh + FEC + IR-HARQ (디스패처 우회)
//
//  디스패처를 거치지 않고 FEC만 직접 호출.
//  프리앰블/헤더 문제를 완전히 배제하고 순수 FEC 성능 측정.
//
//  절차:
//   1. Encode64_IR → syms
//   2. Walsh 인코딩 → chips
//   3. BARRAGE 잡음 가산 + AGC
//   4. Decode64_IR (직접 호출)
//   5. 실패 시 2-4 반복 (RV 순환, LLR 누적)
// ================================================================
struct LayerResult {
    double js_db;
    int trials;
    int crc_ok;
    double avg_rounds;
    int max_rounds;
};
static LayerResult test_fec_direct(int nc, int bps, double js_db,
                                   int max_rounds, int trials, bool erasure,
                                   bool rs_post, uint32_t seed_base) noexcept {
    FEC_HARQ::Set_IR_Erasure_Enabled(erasure);
    FEC_HARQ::Set_IR_Rs_Post_Enabled(rs_post);
    const int nsym =
        (nc == 64) ? FEC_HARQ::nsym_for_bps(bps) : FEC_HARQ::NSYM16;
    const int total_chips = nsym * nc;
    LayerResult res{};
    res.js_db = js_db;
    res.trials = trials;
    std::vector<int16_t> txI(static_cast<size_t>(total_chips));
    std::vector<int16_t> txQ(static_cast<size_t>(total_chips));
    std::vector<int16_t> rxI(static_cast<size_t>(total_chips));
    std::vector<int16_t> rxQ(static_cast<size_t>(total_chips));
    std::vector<double> dbl(static_cast<size_t>(total_chips));
    for (int t = 0; t < trials; ++t) {
        const uint32_t trial_seed =
            seed_base ^ static_cast<uint32_t>(t * 0x9E3779B9u);
        const uint32_t il = 0xA5A5A5A5u ^ trial_seed;
        // 랜덤 페이로드
        uint8_t info[8]{};
        uint32_t s = trial_seed;
        for (int b = 0; b < 8; ++b) {
            s ^= s << 13u;
            s ^= s >> 17u;
            s ^= s << 5u;
            info[b] = static_cast<uint8_t>(s & 0xFFu);
        }
        FEC_HARQ::IR_RxState ir{};
        FEC_HARQ::IR_Init(ir);
        FEC_HARQ::WorkBuf wb{};
        bool decoded = false;
        int rounds_used = 0;
        for (int rv = 0; rv < max_rounds && !decoded; ++rv) {
            // Encode (RV별 인터리빙)
            uint8_t syms[FEC_HARQ::NSYM64]{};
            std::memset(&wb, 0, sizeof(wb));
            int enc_n = 0;
            if (nc == 64) {
                enc_n =
                    FEC_HARQ::Encode64_IR(info, 8, syms, il, bps, rv & 3, wb);
            } else {
                enc_n = FEC_HARQ::Encode16_IR(info, 8, syms, il, rv & 3, wb);
            }
            if (enc_n <= 0)
                break;
            // Walsh 인코딩
            for (int sym = 0; sym < nsym; ++sym) {
                walsh_enc_iq(syms[sym], nc, kAmp,
                             &txI[static_cast<size_t>(sym * nc)],
                             &txQ[static_cast<size_t>(sym * nc)]);
            }
            // 채널: BARRAGE 잡음
            std::mt19937 rng(trial_seed ^
                             static_cast<uint32_t>(rv * 0x85EBCA6Bu));
            if (js_db >= 0.0) {
                add_barrage(txI.data(), dbl.data(), total_chips, js_db, rng);
                agc_quantize(dbl.data(), rxI.data(), rxQ.data(), total_chips);
            } else {
                std::memcpy(rxI.data(), txI.data(),
                            static_cast<size_t>(total_chips) * sizeof(int16_t));
                std::memcpy(rxQ.data(), txQ.data(),
                            static_cast<size_t>(total_chips) * sizeof(int16_t));
            }
            // Decode (LLR 누적)
            uint8_t out[8]{};
            int olen = 0;
            std::memset(&wb, 0, sizeof(wb));
            if (nc == 64) {
                decoded =
                    FEC_HARQ::Decode64_IR(rxI.data(), rxQ.data(), nsym, nc, bps,
                                          il, rv & 3, ir, out, &olen, wb);
            } else {
                decoded = FEC_HARQ::Decode16_IR(rxI.data(), rxQ.data(), nsym,
                                                nc, FEC_HARQ::BPS16, il, rv & 3,
                                                ir, out, &olen, wb);
            }
            rounds_used = rv + 1;
            if (decoded) {
                // 데이터 무결성 확인
                if (olen != 8 || std::memcmp(out, info, 8) != 0) {
                    decoded = false; // CRC 통과했지만 데이터 불일치
                }
            }
        }
        if (decoded) {
            res.crc_ok++;
            res.avg_rounds += rounds_used;
            if (rounds_used > res.max_rounds)
                res.max_rounds = rounds_used;
        }
    }
    if (res.crc_ok > 0)
        res.avg_rounds /= res.crc_ok;
    return res;
}
// ================================================================
//  Layer 4: 전체 스택 (디스패처 경유)
//  기존 테스트와 동일하되 BPS 설정 포함
// ================================================================
DecodedPacket g_last{};
static void on_pkt(const DecodedPacket &p) noexcept { g_last = p; }
static LayerResult test_full_stack(PayloadMode mode, double js_db,
                                   int max_feeds, int trials, int target_bps,
                                   bool erasure, bool rs_post,
                                   uint32_t seed_base) noexcept {
    FEC_HARQ::Set_IR_Erasure_Enabled(erasure);
    FEC_HARQ::Set_IR_Rs_Post_Enabled(rs_post);
    const int nc = (mode == PayloadMode::DATA) ? 64 : 16;
    static constexpr int kMaxC = 256 + (FEC_HARQ::NSYM64 + 12) * 64;
    std::vector<int16_t> oI(static_cast<size_t>(kMaxC));
    std::vector<int16_t> oQ(static_cast<size_t>(kMaxC));
    std::vector<double> dbl(static_cast<size_t>(kMaxC));
    LayerResult res{};
    res.js_db = js_db;
    res.trials = trials;
    for (int t = 0; t < trials; ++t) {
        g_last = DecodedPacket{};
        const uint32_t ds = seed_base ^ static_cast<uint32_t>(t * 0x9E3779B9u);
        const uint32_t ns =
            (seed_base << 1) ^ static_cast<uint32_t>(t * 0x85EBCA6Bu);
        HTS_V400_Dispatcher disp;
        disp.Set_IR_Mode(true);
        disp.Set_Seed(ds);
        disp.Set_Preamble_Boost(16);
        disp.Set_Preamble_Reps(8);
        disp.Set_IR_SIC_Enabled(false);
        disp.Set_CW_Cancel(false);
        disp.Set_AJC_Enabled(false);
        disp.Set_SoftClip_Policy(SoftClipPolicy::NEVER);
        disp.Set_Packet_Callback(on_pkt);
        // BPS 설정
        if (mode == PayloadMode::DATA) {
            uint32_t nf = 0;
            switch (target_bps) {
            case 3:
                nf = 3000;
                break;
            case 4:
                nf = 1000;
                break;
            case 5:
                nf = 300;
                break;
            default:
                nf = 100;
                break;
            }
            disp.Update_Adaptive_BPS(nf);
        }
        uint8_t info[8]{};
        for (int b = 0; b < 8; ++b)
            info[b] = static_cast<uint8_t>(
                static_cast<unsigned>(ds >> static_cast<unsigned>(b * 4)) ^
                static_cast<unsigned>(t + b));
        int success = 0;
        int rounds_used = 0;
        std::mt19937 rng(ns);
        for (int feed = 0; feed < max_feeds && success == 0; ++feed) {
            int n = 0;
            if (feed == 0 || !disp.Is_Retx_Ready())
                n = disp.Build_Packet(mode, info, 8, kAmp, oI.data(), oQ.data(),
                                      kMaxC);
            else
                n = disp.Build_Retx(mode, info, 8, kAmp, oI.data(), oQ.data(),
                                    kMaxC);
            if (n <= 0)
                break;
            if (js_db >= 0.0) {
                add_barrage(oI.data(), dbl.data(), n, js_db, rng);
                agc_quantize(dbl.data(), oI.data(), oQ.data(), n);
            }
            if (feed == 0 || !disp.Is_Retx_Ready()) {
                for (int i = 0; i < n; ++i)
                    disp.Feed_Chip(oI[static_cast<size_t>(i)],
                                   oQ[static_cast<size_t>(i)]);
            } else {
                for (int i = 0; i < n; ++i)
                    disp.Feed_Retx_Chip(oI[static_cast<size_t>(i)],
                                        oQ[static_cast<size_t>(i)]);
            }
            rounds_used = feed + 1;
            if (g_last.success_mask == DecodedPacket::DECODE_MASK_OK)
                success = 1;
        }
        if (success) {
            res.crc_ok++;
            res.avg_rounds += rounds_used;
            if (rounds_used > res.max_rounds)
                res.max_rounds = rounds_used;
        }
    }
    if (res.crc_ok > 0)
        res.avg_rounds /= res.crc_ok;
    return res;
}
// ── 결과 출력 ──
static void print_row(const char *label, const LayerResult &r) noexcept {
    const double pct = (r.trials > 0) ? 100.0 * r.crc_ok / r.trials : 0.0;
    std::printf("  %5.0f dB | %6.1f%% | avg %5.1fR | maxR=%2d | %s\n", r.js_db,
                pct, r.avg_rounds, r.max_rounds, label);
}
} // namespace
#if defined(HTS_BARRAGE30_RUN_FEC_LAYER_INSTEAD)
int main() {
    static constexpr int kTrials = 24;
    static constexpr int kMaxRounds = 32;
    static constexpr uint32_t kSeed = 0xB40730u;
    static constexpr double js_sweep[] = {-1, 0,  5,  10, 15, 20,
                                          25, 30, 35, 40, 45, 50};
    // ====================================================
    //  Layer 0: 코덱 무결성
    // ====================================================
    if (!test_layer0()) {
        std::printf("\n[FATAL] Layer 0 실패 — 코덱 자체에 결함. 중단.\n");
        return 1;
    }
    // ====================================================
    //  Layer 2+3: FEC 직접 호출 (디스패처 우회)
    //  프리앰블/헤더 문제를 완전히 배제
    // ====================================================
    std::printf("\n");
    std::printf(
        "================================================================\n");
    std::printf("  Layer 2+3: FEC 직접 호출 (디스패처 우회)\n");
    std::printf("  순수 FEC 성능만 측정. 프리앰블/헤더 문제 배제.\n");
    std::printf(
        "================================================================\n");
    // ── 64칩 DATA ──
    for (int bps : {FEC_HARQ::BPS64_MIN_OPERABLE, 5, 6}) {
        std::printf("\n── 64chip BPS=%d (nsym=%d, 검색 %d빈) ──\n", bps,
                    FEC_HARQ::nsym_for_bps(bps), 1 << bps);
        std::printf("  %5s   | %7s | %9s | %6s | %s\n", "J/S", "CRC", "avgR",
                    "maxR", "");
        for (double js : js_sweep) {
            LayerResult r = test_fec_direct(
                64, bps, js, kMaxRounds, kTrials, false, true,
                kSeed ^ static_cast<uint32_t>(static_cast<int>(js * 100)));
            print_row("", r);
            std::fflush(stdout);
        }
    }
    // ── 16칩 VOICE ──
    std::printf("\n── 16chip BPS=4 (nsym=%d, 검색 16빈) ──\n",
                FEC_HARQ::NSYM16);
    std::printf("  %5s   | %7s | %9s | %6s | %s\n", "J/S", "CRC", "avgR",
                "maxR", "");
    for (double js : js_sweep) {
        LayerResult r = test_fec_direct(
            16, FEC_HARQ::BPS16, js, kMaxRounds, kTrials, false, true,
            kSeed ^ static_cast<uint32_t>(static_cast<int>(js * 100)));
        print_row("", r);
        std::fflush(stdout);
    }
    // ====================================================
    //  Layer 2+3 변형: Erasure ON 비교
    // ====================================================
    std::printf("\n── 64chip BPS=%d Erasure=ON 비교 ──\n",
                FEC_HARQ::BPS64_MIN_OPERABLE);
    std::printf("  %5s   | %7s | %9s | %6s | %s\n", "J/S", "CRC", "avgR",
                "maxR", "");
    for (double js : js_sweep) {
        LayerResult r = test_fec_direct(
            64, FEC_HARQ::BPS64_MIN_OPERABLE, js, kMaxRounds, kTrials, true,
            true, kSeed ^ static_cast<uint32_t>(static_cast<int>(js * 100)));
        print_row("ER=ON", r);
        std::fflush(stdout);
    }
    // ====================================================
    //  Layer 4: 전체 스택 (디스패처 경유)
    //  BUG-FIX-BPS-SYNC 적용된 디스패처 사용
    // ====================================================
    std::printf("\n");
    std::printf(
        "================================================================\n");
    std::printf("  Layer 4: 전체 스택 (디스패처 경유)\n");
    std::printf("  프리앰블/헤더 + FEC 통합. BPS 적응 포함.\n");
    std::printf(
        "================================================================\n");
    std::printf("\n── 64chip DATA via Dispatcher (기본 BPS=6) ──\n");
    std::printf("  기존 디스패처 그대로 사용. FEC직접과 비교하여 손실 측정.\n");
    std::printf("  %5s   | %7s | %9s | %6s | %s\n", "J/S", "CRC", "avgR",
                "maxR", "");
    for (double js : js_sweep) {
        LayerResult r = test_full_stack(
            PayloadMode::DATA, js, kMaxRounds, kTrials, 6, false, true,
            kSeed ^ static_cast<uint32_t>(static_cast<int>(js * 100)));
        print_row("Disp BPS6", r);
        std::fflush(stdout);
    }
    std::printf(
        "\n── 64chip DATA via Dispatcher (BPS=4, SIC OFF, PRE×8) ──\n");
    std::printf("  %5s   | %7s | %9s | %6s | %s\n", "J/S", "CRC", "avgR",
                "maxR", "");
    for (double js : js_sweep) {
        LayerResult r = test_full_stack(
            PayloadMode::DATA, js, kMaxRounds, kTrials, 4, false, true,
            kSeed ^ static_cast<uint32_t>(static_cast<int>(js * 100)));
        print_row("Disp B4", r);
        std::fflush(stdout);
    }
    std::printf("\n── 16chip VOICE via Dispatcher ──\n");
    std::printf("  %5s   | %7s | %9s | %6s | %s\n", "J/S", "CRC", "avgR",
                "maxR", "");
    for (double js : js_sweep) {
        LayerResult r = test_full_stack(
            PayloadMode::VOICE, js, kMaxRounds, kTrials, 4, false, true,
            kSeed ^ static_cast<uint32_t>(static_cast<int>(js * 100)));
        print_row("Disp", r);
        std::fflush(stdout);
    }
    // ====================================================
    //  Layer 5: FHSS + 부분대역 재밍 (주파수 다이버시티)
    //  재머 128채널 중 30% 점유. FHSS 유/무 비교.
    // ====================================================
    std::printf("\n");
    std::printf(
        "================================================================\n");
    std::printf("  Layer 5: FHSS + 부분대역 재밍 (주파수 다이버시티)\n");
    std::printf("  재머 128채널 중 30%% 점유. FHSS 유/무 비교.\n");
    std::printf(
        "================================================================\n");
    // FHSS 부분대역 Conv+REP 테스트 람다
    auto test_fhss_conv = [&](double js_db, int max_rounds, int trials,
                              double jam_frac, bool fhss_on,
                              uint32_t seed_base) -> LayerResult {
        FEC_HARQ::Set_IR_Erasure_Enabled(false);
        FEC_HARQ::Set_IR_Rs_Post_Enabled(true);
        const int bps = FEC_HARQ::BPS64_MIN_OPERABLE;
        const int nsym = FEC_HARQ::nsym_for_bps(bps);
        const int total_chips = nsym * 64;
        std::vector<int16_t> txI(static_cast<size_t>(total_chips));
        std::vector<int16_t> txQ(static_cast<size_t>(total_chips));
        std::vector<int16_t> rxI(static_cast<size_t>(total_chips));
        std::vector<int16_t> rxQ(static_cast<size_t>(total_chips));
        std::vector<double> dbuf(static_cast<size_t>(total_chips));
        const int jam_ch = static_cast<int>(128.0 * jam_frac + 0.5);
        LayerResult res{};
        res.js_db = js_db;
        res.trials = trials;
        for (int t = 0; t < trials; ++t) {
            const uint32_t ts =
                seed_base ^ static_cast<uint32_t>(t * 0x9E3779B9u);
            const uint32_t il = 0xA5A5A5A5u ^ ts;
            uint8_t info[8]{};
            uint32_t s = ts;
            for (int b = 0; b < 8; ++b) {
                s ^= s << 13u;
                s ^= s >> 17u;
                s ^= s << 5u;
                info[b] = static_cast<uint8_t>(s & 0xFFu);
            }
            const uint8_t fixed_ch =
                HTS_V400_Dispatcher::FHSS_Derive_Channel(ts, 0u);
            FEC_HARQ::IR_RxState ir{};
            FEC_HARQ::IR_Init(ir);
            FEC_HARQ::WorkBuf wb{};
            bool decoded = false;
            int rounds_used = 0;
            for (int rv = 0; rv < max_rounds && !decoded; ++rv) {
                const uint8_t ch =
                    fhss_on ? HTS_V400_Dispatcher::FHSS_Derive_Channel(
                                  ts, static_cast<uint32_t>(rv))
                            : fixed_ch;
                const double eff_js =
                    (static_cast<int>(ch) < jam_ch) ? js_db : -1.0;
                uint8_t syms[FEC_HARQ::NSYM64]{};
                std::memset(&wb, 0, sizeof(wb));
                int enc_n =
                    FEC_HARQ::Encode64_IR(info, 8, syms, il, bps, rv & 3, wb);
                if (enc_n <= 0)
                    break;
                for (int sym = 0; sym < nsym; ++sym)
                    walsh_enc_iq(syms[sym], 64, kAmp,
                                 &txI[static_cast<size_t>(sym * 64)],
                                 &txQ[static_cast<size_t>(sym * 64)]);
                std::mt19937 rng(ts ^ static_cast<uint32_t>(rv * 0x85EBCA6Bu));
                if (eff_js >= 0.0) {
                    add_barrage(txI.data(), dbuf.data(), total_chips, eff_js,
                                rng);
                    agc_quantize(dbuf.data(), rxI.data(), rxQ.data(),
                                 total_chips);
                } else {
                    std::memcpy(rxI.data(), txI.data(),
                                static_cast<size_t>(total_chips) *
                                    sizeof(int16_t));
                    std::memcpy(rxQ.data(), txQ.data(),
                                static_cast<size_t>(total_chips) *
                                    sizeof(int16_t));
                }
                uint8_t out[8]{};
                int olen = 0;
                std::memset(&wb, 0, sizeof(wb));
                decoded =
                    FEC_HARQ::Decode64_IR(rxI.data(), rxQ.data(), nsym, 64, bps,
                                          il, rv & 3, ir, out, &olen, wb);
                rounds_used = rv + 1;
                if (decoded && (olen != 8 || std::memcmp(out, info, 8) != 0))
                    decoded = false;
            }
            if (decoded) {
                res.crc_ok++;
                res.avg_rounds += rounds_used;
                if (rounds_used > res.max_rounds)
                    res.max_rounds = rounds_used;
            }
        }
        if (res.crc_ok > 0)
            res.avg_rounds /= res.crc_ok;
        return res;
    };
    // ── Conv+REP: FHSS OFF/ON 비교 ──
    for (bool fhss : {false, true}) {
        std::printf("\n── 64chip BPS=4, 부분대역 30%%, FHSS=%s ──\n",
                    fhss ? "ON(도약)" : "OFF(고정)");
        std::printf("  %5s   | %7s | %9s | %6s | %s\n", "J/S", "CRC", "avgR",
                    "maxR", "");
        for (double js : js_sweep) {
            LayerResult r = test_fhss_conv(
                js, kMaxRounds, kTrials, 0.3, fhss,
                kSeed ^ static_cast<uint32_t>(static_cast<int>(js * 100)));
            print_row(fhss ? "FHSS" : "FIXED", r);
            std::fflush(stdout);
        }
    }
    // ====================================================
    //  이득 분리 요약
    // ====================================================
    std::printf("\n");
    std::printf(
        "================================================================\n");
    std::printf("  이득 분리 요약\n");
    std::printf(
        "================================================================\n");
    std::printf("  각 모드에서 CRC≥80%% 달성하는 최대 J/S를 비교:\n");
    std::printf("    Walsh PG만 (이론):  64chip=18.1dB, 16chip=12.0dB\n");
    std::printf("    FEC직접 1R:        위 Layer2+3에서 maxR=1인 최대 J/S\n");
    std::printf(
        "    FEC직접 32R:       위 Layer2+3에서 32R까지 사용한 최대 J/S\n");
    std::printf("    전체 스택:          위 Layer4에서 최대 J/S\n");
    std::printf("    차이 = 디스패처 손실 (프리앰블/헤더/양자화 등)\n");
    std::printf("\n  → FEC직접 >> 전체스택 이면 디스패처 경로에 문제\n");
    std::printf("  → FEC직접도 낮으면 FEC 자체에 문제\n");
    std::printf("\n=== 테스트 완료 ===\n");
    return 0;
}
#endif // HTS_BARRAGE30_RUN_FEC_LAYER_INSTEAD
