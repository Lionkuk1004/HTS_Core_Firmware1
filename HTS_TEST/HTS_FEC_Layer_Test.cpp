// HTS_FEC_Layer_Test.cpp — 에러정정 레이어별 독립 검증
//
// [테스트 방법론]
//   연구실 기준: 각 레이어를 독립적으로 검증하여 이득을 측정.
//   디스패처(프리앰블/헤더)를 우회하여 순수 FEC 성능만 측정.
//
//   Layer 0: Encode→Decode 왕복 (채널 없음) → 코덱 무결성
//   Layer 2+3: FEC 직접 호출 → 순수 FEC 성능
//   Layer 4: 전체 스택 (기존) → 기준선
//   Layer 4-V2: 블록AGC + 동기재시도 → 구조적 손실 분리
//   Layer 4-V3: TX/RX 분리, 패킷 1회 빌드 + 라운드별 신규 잡음 (tx_seq 일관)
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
static constexpr uint32_t popc32(uint32_t x) noexcept {
    x = x - ((x >> 1u) & 0x55555555u);
    x = (x & 0x33333333u) + ((x >> 2u) & 0x33333333u);
    return (((x + (x >> 4u)) & 0x0F0F0F0Fu) * 0x01010101u) >> 24u;
}
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
static void add_barrage(const int16_t *tx, double *out, int n, double js_db,
                        std::mt19937 &rng) noexcept {
    const double js_lin = std::pow(10.0, js_db / 10.0);
    const double sigma = kAmpD * std::sqrt(js_lin);
    std::normal_distribution<double> nd(0.0, 1.0);
    for (int i = 0; i < n; ++i)
        out[i] = static_cast<double>(tx[i]) + sigma * nd(rng);
}
// ── AGC: 패킷 전체 (기존) ──
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
// ── AGC: 블록 단위 (V2) ──
//  실제 HW: AGC는 심볼(64칩) 단위로 추적
//  프리앰블 고진폭 → AGC 이득 낮춤 (프리앰블 구간만)
//  페이로드 저진폭 → AGC 이득 복원 (페이로드 구간만)
static void agc_quantize_block(const double *in, int16_t *oI, int16_t *oQ,
                               int n, int block_size) noexcept {
    for (int blk = 0; blk < n; blk += block_size) {
        int end = blk + block_size;
        if (end > n)
            end = n;
        double pk = 0.0;
        for (int i = blk; i < end; ++i) {
            double a = std::fabs(in[i]);
            if (a > pk)
                pk = a;
        }
        double g = (pk > kAgcTarget) ? (kAgcTarget / pk) : 1.0;
        for (int i = blk; i < end; ++i) {
            long r = std::lround(in[i] * g);
            if (r > 32767L)
                r = 32767L;
            if (r < -32768L)
                r = -32768L;
            oI[i] = static_cast<int16_t>(r);
            oQ[i] = oI[i];
        }
    }
}
// ── 결과 구조 ──
struct LayerResult {
    double js_db;
    int trials;
    int crc_ok;
    double avg_rounds;
    int max_rounds;
};
static void print_row(const char *label, const LayerResult &r) noexcept {
    const double pct = (r.trials > 0) ? 100.0 * r.crc_ok / r.trials : 0.0;
    std::printf("  %5.0f dB | %6.1f%% | avg %5.1fR | maxR=%2d | %s\n", r.js_db,
                pct, r.avg_rounds, r.max_rounds, label);
}
DecodedPacket g_last{};
static void on_pkt(const DecodedPacket &p) noexcept { g_last = p; }
// ================================================================
//  Layer 0: 코덱 왕복 검증
// ================================================================
static bool test_layer0() noexcept {
    std::printf("\n=== Layer 0: 코덱 왕복 검증 ===\n");
    FEC_HARQ::WorkBuf wb{};
    bool all_ok = true;
    std::printf("  BPS64_MIN_OPERABLE=%d, NSYM64=%d\n",
                FEC_HARQ::BPS64_MIN_OPERABLE, FEC_HARQ::NSYM64);
    for (int bps = FEC_HARQ::BPS64_MIN_OPERABLE; bps <= 6; ++bps) {
        const int nsym = FEC_HARQ::nsym_for_bps(bps);
        const int nc = 64;
        uint8_t info[8] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
        uint8_t syms[FEC_HARQ::NSYM64]{};
        std::memset(&wb, 0, sizeof(wb));
        int enc_n =
            FEC_HARQ::Encode64_IR(info, 8, syms, 0xABCD1234u, bps, 0, wb);
        if (enc_n <= 0) {
            std::printf("  BPS=%d: SKIP\n", bps);
            continue;
        }
        std::vector<int16_t> cI(static_cast<size_t>(nsym * nc));
        std::vector<int16_t> cQ(static_cast<size_t>(nsym * nc));
        for (int s = 0; s < nsym; ++s)
            walsh_enc_iq(syms[s], nc, kAmp, &cI[static_cast<size_t>(s * nc)],
                         &cQ[static_cast<size_t>(s * nc)]);
        FEC_HARQ::IR_RxState ir{};
        FEC_HARQ::IR_Init(ir);
        FEC_HARQ::Set_IR_Erasure_Enabled(false);
        FEC_HARQ::Set_IR_Rs_Post_Enabled(true);
        uint8_t out[8]{};
        int olen = 0;
        std::memset(&wb, 0, sizeof(wb));
        bool ok = FEC_HARQ::Decode64_IR(cI.data(), cQ.data(), nsym, nc, bps,
                                        0xABCD1234u, 0, ir, out, &olen, wb);
        bool match = ok && (olen == 8) && (std::memcmp(out, info, 8) == 0);
        std::printf("  BPS=%d nsym=%d: %s\n", bps, nsym, match ? "OK" : "FAIL");
        if (!match)
            all_ok = false;
    }
    {
        uint8_t info[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22};
        uint8_t syms[FEC_HARQ::NSYM16]{};
        std::memset(&wb, 0, sizeof(wb));
        FEC_HARQ::Encode16_IR(info, 8, syms, 0x12345678u, 0, wb);
        std::vector<int16_t> cI(static_cast<size_t>(FEC_HARQ::NSYM16 * 16));
        std::vector<int16_t> cQ(static_cast<size_t>(FEC_HARQ::NSYM16 * 16));
        for (int s = 0; s < FEC_HARQ::NSYM16; ++s)
            walsh_enc_iq(syms[s], 16, kAmp, &cI[static_cast<size_t>(s * 16)],
                         &cQ[static_cast<size_t>(s * 16)]);
        FEC_HARQ::IR_RxState ir{};
        FEC_HARQ::IR_Init(ir);
        uint8_t out[8]{};
        int olen = 0;
        std::memset(&wb, 0, sizeof(wb));
        bool ok = FEC_HARQ::Decode16_IR(cI.data(), cQ.data(), FEC_HARQ::NSYM16,
                                        16, FEC_HARQ::BPS16, 0x12345678u, 0, ir,
                                        out, &olen, wb);
        bool match = ok && (olen == 8) && (std::memcmp(out, info, 8) == 0);
        std::printf("  16chip: %s\n", match ? "OK" : "FAIL");
        if (!match)
            all_ok = false;
    }
    std::printf("  Layer 0: %s\n", all_ok ? "PASS" : "FAIL");
    return all_ok;
}
// ================================================================
//  Layer 2+3: FEC 직접 호출
// ================================================================
static LayerResult test_fec_direct(int nc, int bps, double js_db,
                                   int max_rounds, int trials,
                                   uint32_t seed_base) noexcept {
    FEC_HARQ::Set_IR_Erasure_Enabled(false);
    FEC_HARQ::Set_IR_Rs_Post_Enabled(true);
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
        const uint32_t ts = seed_base ^ static_cast<uint32_t>(t * 0x9E3779B9u);
        const uint32_t il = 0xA5A5A5A5u ^ ts;
        uint8_t info[8]{};
        uint32_t s = ts;
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
            uint8_t syms[FEC_HARQ::NSYM64]{};
            std::memset(&wb, 0, sizeof(wb));
            int enc_n =
                (nc == 64)
                    ? FEC_HARQ::Encode64_IR(info, 8, syms, il, bps, rv & 3, wb)
                    : FEC_HARQ::Encode16_IR(info, 8, syms, il, rv & 3, wb);
            if (enc_n <= 0)
                break;
            for (int sym = 0; sym < nsym; ++sym)
                walsh_enc_iq(syms[sym], nc, kAmp,
                             &txI[static_cast<size_t>(sym * nc)],
                             &txQ[static_cast<size_t>(sym * nc)]);
            std::mt19937 rng(ts ^ static_cast<uint32_t>(rv * 0x85EBCA6Bu));
            if (js_db >= 0.0) {
                add_barrage(txI.data(), dbl.data(), total_chips, js_db, rng);
                agc_quantize(dbl.data(), rxI.data(), rxQ.data(), total_chips);
            } else {
                std::memcpy(rxI.data(), txI.data(),
                            static_cast<size_t>(total_chips) * sizeof(int16_t));
                std::memcpy(rxQ.data(), txQ.data(),
                            static_cast<size_t>(total_chips) * sizeof(int16_t));
            }
            uint8_t out[8]{};
            int olen = 0;
            std::memset(&wb, 0, sizeof(wb));
            if (nc == 64)
                decoded =
                    FEC_HARQ::Decode64_IR(rxI.data(), rxQ.data(), nsym, nc, bps,
                                          il, rv & 3, ir, out, &olen, wb);
            else
                decoded = FEC_HARQ::Decode16_IR(rxI.data(), rxQ.data(), nsym,
                                                nc, FEC_HARQ::BPS16, il, rv & 3,
                                                ir, out, &olen, wb);
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
}
// ================================================================
//  Layer 4: 전체 스택 (기존)
// ================================================================
static LayerResult test_full_stack(PayloadMode mode, double js_db,
                                   int max_feeds, int trials, int target_bps,
                                   uint32_t seed_base) noexcept {
    FEC_HARQ::Set_IR_Erasure_Enabled(false);
    FEC_HARQ::Set_IR_Rs_Post_Enabled(true);
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
        if (mode == PayloadMode::DATA) {
            uint32_t nf = (target_bps == 3)   ? 3000
                          : (target_bps == 4) ? 1000
                          : (target_bps == 5) ? 300
                                              : 100;
            disp.Update_Adaptive_BPS(nf);
        }
        uint8_t info[8]{};
        for (int b = 0; b < 8; ++b)
            info[b] = static_cast<uint8_t>(
                static_cast<unsigned>(ds >> static_cast<unsigned>(b * 4)) ^
                static_cast<unsigned>(t + b));
        int success = 0, rounds_used = 0;
        std::mt19937 rng(ns);
        for (int feed = 0; feed < max_feeds && success == 0; ++feed) {
            int n = (feed == 0 || !disp.Is_Retx_Ready())
                        ? disp.Build_Packet(mode, info, 8, kAmp, oI.data(),
                                            oQ.data(), kMaxC)
                        : disp.Build_Retx(mode, info, 8, kAmp, oI.data(),
                                          oQ.data(), kMaxC);
            if (n <= 0)
                break;
            if (js_db >= 0.0) {
                add_barrage(oI.data(), dbl.data(), n, js_db, rng);
                agc_quantize(dbl.data(), oI.data(), oQ.data(), n);
            }
            if (feed == 0 || !disp.Is_Retx_Ready())
                for (int i = 0; i < n; ++i)
                    disp.Feed_Chip(oI[static_cast<size_t>(i)],
                                   oQ[static_cast<size_t>(i)]);
            else
                for (int i = 0; i < n; ++i)
                    disp.Feed_Retx_Chip(oI[static_cast<size_t>(i)],
                                        oQ[static_cast<size_t>(i)]);
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
// ================================================================
//  Layer 4-V2: 블록AGC + 동기재시도
//
//  [V2 핵심] 매 라운드마다 동일 시드로 디스패처 재생성
//   → sync 실패해도 다음 라운드에서 새 잡음으로 재시도
//   → il seed 항상 일치
//   → 블록AGC: 프리앰블/페이로드 독립 정규화
// ================================================================
static LayerResult test_full_stack_v2(PayloadMode mode, double js_db,
                                      int max_feeds, int trials, int target_bps,
                                      uint32_t seed_base, bool use_block_agc,
                                      int pre_boost_val) noexcept {
    FEC_HARQ::Set_IR_Erasure_Enabled(false);
    FEC_HARQ::Set_IR_Rs_Post_Enabled(true);
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
        uint8_t info[8]{};
        for (int b = 0; b < 8; ++b)
            info[b] = static_cast<uint8_t>(
                static_cast<unsigned>(ds >> static_cast<unsigned>(b * 4)) ^
                static_cast<unsigned>(t + b));
        int success = 0, rounds_used = 0;
        std::mt19937 rng(ns);
        for (int feed = 0; feed < max_feeds && success == 0; ++feed) {
            // [V2] 매 라운드: 동일 시드 디스패처 재생성
            HTS_V400_Dispatcher disp;
            disp.Set_IR_Mode(true);
            disp.Set_Seed(ds);
            disp.Set_Preamble_Boost(pre_boost_val);
            disp.Set_Preamble_Reps(8);
            disp.Set_IR_SIC_Enabled(false);
            disp.Set_CW_Cancel(false);
            disp.Set_AJC_Enabled(false);
            disp.Set_SoftClip_Policy(SoftClipPolicy::NEVER);
            disp.Set_Packet_Callback(on_pkt);
            if (mode == PayloadMode::DATA) {
                uint32_t nf = (target_bps == 3)   ? 3000
                              : (target_bps == 4) ? 1000
                              : (target_bps == 5) ? 300
                                                  : 100;
                disp.Update_Adaptive_BPS(nf);
            }
            int n = disp.Build_Packet(mode, info, 8, kAmp, oI.data(), oQ.data(),
                                      kMaxC);
            if (n <= 0)
                break;
            if (js_db >= 0.0) {
                add_barrage(oI.data(), dbl.data(), n, js_db, rng);
                if (use_block_agc)
                    agc_quantize_block(dbl.data(), oI.data(), oQ.data(), n, 64);
                else
                    agc_quantize(dbl.data(), oI.data(), oQ.data(), n);
            }
            for (int i = 0; i < n; ++i)
                disp.Feed_Chip(oI[static_cast<size_t>(i)],
                               oQ[static_cast<size_t>(i)]);
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
// ============================================================
//  test_full_stack_v3 — 동일 패킷, 다중 잡음 실현
//
//  [핵심 변경]
//   기존: 동기 실패 시 Build_Packet 재호출 → tx_seq 불일치
//   수정: Build_Packet 1회 → 칩 저장 → 매 라운드 새 잡음 가산 후 Feed
//
//  [실제 시나리오 모델링]
//   TX는 동일 패킷을 반복 전송 (같은 il seed)
//   RX는 매번 독립적인 잡음 실현을 받음
//   동기 실패해도 다음 전송에서 재시도 가능
// ============================================================
static LayerResult test_full_stack_v3(PayloadMode mode, double js_db,
                                      int max_feeds, int trials, int target_bps,
                                      bool erasure, bool rs_post,
                                      uint32_t seed_base,
                                      int boost_val) noexcept {
    FEC_HARQ::Set_IR_Erasure_Enabled(erasure);
    FEC_HARQ::Set_IR_Rs_Post_Enabled(rs_post);

    static constexpr int kMaxC = 256 + (FEC_HARQ::NSYM64 + 12) * 64;
    std::vector<int16_t> txI(static_cast<size_t>(kMaxC));  // 원본 TX 칩 (보존)
    std::vector<int16_t> txQ(static_cast<size_t>(kMaxC));
    std::vector<int16_t> rxI(static_cast<size_t>(kMaxC));  // 잡음 가산 후 RX
    std::vector<int16_t> rxQ(static_cast<size_t>(kMaxC));
    std::vector<double>  dbl(static_cast<size_t>(kMaxC));

    LayerResult res{};
    res.js_db = js_db;
    res.trials = trials;

    for (int t = 0; t < trials; ++t) {
        g_last = DecodedPacket{};
        const uint32_t ds = seed_base ^ static_cast<uint32_t>(t * 0x9E3779B9u);
        const uint32_t ns =
            (seed_base << 1) ^ static_cast<uint32_t>(t * 0x85EBCA6Bu);

        uint8_t info[8]{};
        for (int b = 0; b < 8; ++b)
            info[b] = static_cast<uint8_t>(
                static_cast<unsigned>(ds >> static_cast<unsigned>(b * 4)) ^
                static_cast<unsigned>(t + b));

        // ── 1단계: Build_Packet 1회 → TX 칩 보존 ──
        HTS_V400_Dispatcher tx_disp;  // TX용 디스패처
        tx_disp.Set_IR_Mode(true);
        tx_disp.Set_Seed(ds);
        tx_disp.Set_Preamble_Boost(boost_val);
        tx_disp.Set_Preamble_Reps(8);
        tx_disp.Set_IR_SIC_Enabled(false);
        tx_disp.Set_CW_Cancel(false);
        tx_disp.Set_AJC_Enabled(false);
        tx_disp.Set_SoftClip_Policy(SoftClipPolicy::NEVER);
        if (mode == PayloadMode::DATA) {
            uint32_t nf = 0;
            switch (target_bps) {
            case 3: nf = 3000; break;
            case 4: nf = 1000; break;
            case 5: nf = 300;  break;
            default: nf = 100; break;
            }
            tx_disp.Update_Adaptive_BPS(nf);
        }

        const int pkt_chips = tx_disp.Build_Packet(
            mode, info, 8, kAmp, txI.data(), txQ.data(), kMaxC);
        if (pkt_chips <= 0) continue;

        // ── 2단계: Retx 칩 (프리앰블/헤더 없음) 보존 ──
        std::vector<int16_t> retxI(static_cast<size_t>(kMaxC));
        std::vector<int16_t> retxQ(static_cast<size_t>(kMaxC));
        const int retx_chips = tx_disp.Build_Retx(
            mode, info, 8, kAmp, retxI.data(), retxQ.data(), kMaxC);

        // ── 3단계: RX 디스패처 — 매 라운드 새 잡음으로 Feed ──
        HTS_V400_Dispatcher rx_disp;  // RX용 디스패처
        rx_disp.Set_IR_Mode(true);
        rx_disp.Set_Seed(ds);
        rx_disp.Set_Preamble_Boost(boost_val);
        rx_disp.Set_Preamble_Reps(8);
        rx_disp.Set_IR_SIC_Enabled(false);
        rx_disp.Set_CW_Cancel(false);
        rx_disp.Set_AJC_Enabled(false);
        rx_disp.Set_SoftClip_Policy(SoftClipPolicy::NEVER);
        rx_disp.Set_Packet_Callback(on_pkt);
        if (mode == PayloadMode::DATA) {
            uint32_t nf = 0;
            switch (target_bps) {
            case 3: nf = 3000; break;
            case 4: nf = 1000; break;
            case 5: nf = 300;  break;
            default: nf = 100; break;
            }
            rx_disp.Update_Adaptive_BPS(nf);
        }

        int success = 0;
        int rounds_used = 0;
        std::mt19937 rng(ns);

        for (int feed = 0; feed < max_feeds && success == 0; ++feed) {
            // 사용할 칩 선택
            const int16_t* src_I;
            const int16_t* src_Q;
            int src_n;
            bool use_retx;

            if (feed == 0 || !rx_disp.Is_Retx_Ready()) {
                // 첫 라운드 또는 동기 실패 → 전체 패킷(프리앰블+헤더+페이로드)
                src_I = txI.data();
                src_Q = txQ.data();
                src_n = pkt_chips;
                use_retx = false;

                // 동기 실패 후 재시도: RX 디스패처 리셋 (rx_seq_ 유지하지 않음)
                if (feed > 0) {
                    rx_disp.Reset();
                    rx_disp.Set_IR_Mode(true);
                    rx_disp.Set_Seed(ds);
                    rx_disp.Set_Preamble_Boost(boost_val);
                    rx_disp.Set_Preamble_Reps(8);
                    rx_disp.Set_IR_SIC_Enabled(false);
                    rx_disp.Set_CW_Cancel(false);
                    rx_disp.Set_AJC_Enabled(false);
                    rx_disp.Set_SoftClip_Policy(SoftClipPolicy::NEVER);
                    rx_disp.Set_Packet_Callback(on_pkt);
                    if (mode == PayloadMode::DATA) {
                        uint32_t nf = 0;
                        switch (target_bps) {
                        case 3: nf = 3000; break;
                        case 4: nf = 1000; break;
                        case 5: nf = 300;  break;
                        default: nf = 100; break;
                        }
                        rx_disp.Update_Adaptive_BPS(nf);
                    }
                }
            } else {
                // HARQ 재전송 → 페이로드만
                src_I = retxI.data();
                src_Q = retxQ.data();
                src_n = retx_chips;
                use_retx = true;
            }

            if (src_n <= 0) break;

            // 채널: 새 잡음 실현
            if (js_db >= 0.0) {
                // I 채널 잡음
                add_barrage(src_I, dbl.data(), src_n, js_db, rng);
                agc_quantize(dbl.data(), rxI.data(), rxQ.data(), src_n);
            } else {
                std::memcpy(rxI.data(), src_I,
                            static_cast<size_t>(src_n) * sizeof(int16_t));
                std::memcpy(rxQ.data(), src_Q,
                            static_cast<size_t>(src_n) * sizeof(int16_t));
            }

            // Feed
            if (use_retx) {
                for (int i = 0; i < src_n; ++i)
                    rx_disp.Feed_Retx_Chip(
                        rxI[static_cast<size_t>(i)],
                        rxQ[static_cast<size_t>(i)]);
            } else {
                for (int i = 0; i < src_n; ++i)
                    rx_disp.Feed_Chip(
                        rxI[static_cast<size_t>(i)],
                        rxQ[static_cast<size_t>(i)]);
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
// ============================================================
//  V4: 동기 우회 — 페이로드만 디스패처 경유 HARQ 테스트
//
//  프리앰블/헤더를 건너뛰고 페이로드 칩만 Feed.
//  FEC 직접과 동일한 조건이지만 디스패처의 on_sym_→try_decode_ 경로 사용.
//  → FEC 직접과 동일 결과가 나오면 디스패처 FEC 경로 정상 확인.
//  → 차이가 있으면 on_sym_ 또는 try_decode_에 버그 존재.
// ============================================================
static LayerResult test_full_stack_v4(PayloadMode mode, double js_db,
                                      int max_feeds, int trials, int target_bps,
                                      uint32_t seed_base) noexcept {
    FEC_HARQ::Set_IR_Erasure_Enabled(false);
    FEC_HARQ::Set_IR_Rs_Post_Enabled(true);

    const int nc = (mode == PayloadMode::DATA) ? 64 : 16;
    const int bps = (nc == 64) ? target_bps : FEC_HARQ::BPS16;
    const int nsym = (nc == 64) ? FEC_HARQ::nsym_for_bps(bps) : FEC_HARQ::NSYM16;
    const int total_chips = nsym * nc;

    std::vector<int16_t> txI(static_cast<size_t>(total_chips));
    std::vector<int16_t> txQ(static_cast<size_t>(total_chips));
    std::vector<int16_t> rxI(static_cast<size_t>(total_chips));
    std::vector<int16_t> rxQ(static_cast<size_t>(total_chips));
    std::vector<double>  dbl(static_cast<size_t>(total_chips));

    LayerResult res{};
    res.js_db = js_db;
    res.trials = trials;

    for (int t = 0; t < trials; ++t) {
        g_last = DecodedPacket{};
        const uint32_t ds = seed_base ^ static_cast<uint32_t>(t * 0x9E3779B9u);
        const uint32_t ns =
            (seed_base << 1) ^ static_cast<uint32_t>(t * 0x85EBCA6Bu);
        const uint32_t il = ds ^ (0u * 0xA5A5A5A5u); // tx_seq=0 → il=ds

        uint8_t info[8]{};
        for (int b = 0; b < 8; ++b)
            info[b] = static_cast<uint8_t>(
                static_cast<unsigned>(ds >> static_cast<unsigned>(b * 4)) ^
                static_cast<unsigned>(t + b));

        // RX 디스패처 — 동기 우회
        HTS_V400_Dispatcher rx_disp;
        rx_disp.Set_IR_Mode(true);
        rx_disp.Set_Seed(ds);
        rx_disp.Set_CW_Cancel(false);
        rx_disp.Set_AJC_Enabled(false);
        rx_disp.Set_SoftClip_Policy(SoftClipPolicy::NEVER);
        rx_disp.Set_Packet_Callback(on_pkt);
        rx_disp.Inject_Payload_Phase(mode, target_bps);

        int success = 0;
        int rounds_used = 0;
        std::mt19937 rng(ns);
        FEC_HARQ::WorkBuf wb{};

        for (int rv = 0; rv < max_feeds && success == 0; ++rv) {
            // TX: 매 라운드 새 RV로 인코딩
            uint8_t syms[FEC_HARQ::NSYM64]{};
            std::memset(&wb, 0, sizeof(wb));
            int enc_n = (nc == 64)
                ? FEC_HARQ::Encode64_IR(info, 8, syms, il, bps, rv & 3, wb)
                : FEC_HARQ::Encode16_IR(info, 8, syms, il, rv & 3, wb);
            if (enc_n <= 0) break;

            for (int sym = 0; sym < nsym; ++sym)
                walsh_enc_iq(syms[sym], nc, kAmp,
                             &txI[static_cast<size_t>(sym * nc)],
                             &txQ[static_cast<size_t>(sym * nc)]);

            // 채널: 잡음 가산
            if (js_db >= 0.0) {
                add_barrage(txI.data(), dbl.data(), total_chips, js_db, rng);
                agc_quantize(dbl.data(), rxI.data(), rxQ.data(), total_chips);
            } else {
                std::memcpy(rxI.data(), txI.data(),
                            static_cast<size_t>(total_chips) * sizeof(int16_t));
                std::memcpy(rxQ.data(), txQ.data(),
                            static_cast<size_t>(total_chips) * sizeof(int16_t));
            }

            // Feed: 페이로드 칩만 (프리앰블/헤더 없음)
            if (rv == 0) {
                for (int i = 0; i < total_chips; ++i)
                    rx_disp.Feed_Chip(rxI[static_cast<size_t>(i)],
                                      rxQ[static_cast<size_t>(i)]);
            } else {
                for (int i = 0; i < total_chips; ++i)
                    rx_disp.Feed_Retx_Chip(rxI[static_cast<size_t>(i)],
                                           rxQ[static_cast<size_t>(i)]);
            }

            rounds_used = rv + 1;
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
} // namespace
int main() {
    static constexpr int kTrials = 24;
    static constexpr int kMaxRounds = 32;
    static constexpr uint32_t kSeed = 0xB40730u;
    static constexpr double js_sweep[] = {-1, 0,  5,  10, 15, 20,
                                          25, 30, 35, 40, 45, 50};
    if (!test_layer0()) {
        std::printf("\n[FATAL] Layer 0 FAIL\n");
        return 1;
    }
    // ── Layer 2+3: FEC 직접 ──
    std::printf(
        "\n================================================================\n");
    std::printf("  Layer 2+3: FEC 직접 (디스패처 우회)\n");
    std::printf(
        "================================================================\n");
    std::printf("\n── 64chip BPS=4 ──\n");
    for (double js : js_sweep) {
        print_row("FEC",
                  test_fec_direct(64, 4, js, kMaxRounds, kTrials,
                                  kSeed ^ static_cast<uint32_t>(
                                              static_cast<int>(js * 100))));
        std::fflush(stdout);
    }
    // ── Layer 4: 기존 (패킷AGC, boost=16) ──
    std::printf(
        "\n================================================================\n");
    std::printf("  Layer 4: 기존 (패킷AGC, boost=16)\n");
    std::printf(
        "================================================================\n");
    for (double js : js_sweep) {
        print_row("기존",
                  test_full_stack(PayloadMode::DATA, js, kMaxRounds, kTrials, 4,
                                  kSeed ^ static_cast<uint32_t>(
                                              static_cast<int>(js * 100))));
        std::fflush(stdout);
    }
    // ── Layer 4-V2A: 블록AGC + boost=16 ──
    std::printf(
        "\n================================================================\n");
    std::printf("  V2A: 블록AGC(64칩) + boost=16\n");
    std::printf(
        "================================================================\n");
    for (double js : js_sweep) {
        print_row("V2A",
                  test_full_stack_v2(
                      PayloadMode::DATA, js, kMaxRounds, kTrials, 4,
                      kSeed ^ static_cast<uint32_t>(static_cast<int>(js * 100)),
                      true, 16));
        std::fflush(stdout);
    }
    // ── Layer 4-V2B: 블록AGC + boost=4 ──
    std::printf(
        "\n================================================================\n");
    std::printf("  V2B: 블록AGC + boost=4\n");
    std::printf(
        "================================================================\n");
    for (double js : js_sweep) {
        print_row("V2B",
                  test_full_stack_v2(
                      PayloadMode::DATA, js, kMaxRounds, kTrials, 4,
                      kSeed ^ static_cast<uint32_t>(static_cast<int>(js * 100)),
                      true, 4));
        std::fflush(stdout);
    }
    // ── Layer 4-V2C: 블록AGC + boost=1 ──
    std::printf(
        "\n================================================================\n");
    std::printf("  V2C: 블록AGC + boost=1 (부스트 없음)\n");
    std::printf(
        "================================================================\n");
    for (double js : js_sweep) {
        print_row("V2C",
                  test_full_stack_v2(
                      PayloadMode::DATA, js, kMaxRounds, kTrials, 4,
                      kSeed ^ static_cast<uint32_t>(static_cast<int>(js * 100)),
                      true, 1));
        std::fflush(stdout);
    }
    // ── Layer 4-V2D: 16칩 VOICE 블록AGC+boost=4 ──
    std::printf(
        "\n================================================================\n");
    std::printf("  V2D: 16칩 VOICE 블록AGC + boost=4\n");
    std::printf(
        "================================================================\n");
    for (double js : js_sweep) {
        print_row("V2D",
                  test_full_stack_v2(
                      PayloadMode::VOICE, js, kMaxRounds, kTrials, 4,
                      kSeed ^ static_cast<uint32_t>(static_cast<int>(js * 100)),
                      true, 4));
        std::fflush(stdout);
    }
    // ── Layer 4-V3: TX/RX 분리 + 동일 il seed 재전송 ──
    std::printf(
        "\n================================================================\n");
    std::printf("  V3: TX/RX 분리 + 동일 il seed 재전송\n");
    std::printf(
        "================================================================\n");

    std::printf("\n── V3 boost=16 ──\n");
    std::printf("  %5s   | %7s | %9s | %6s | %s\n", "J/S", "CRC", "avgR",
                "maxR", "");
    for (double js : js_sweep) {
        print_row("V3-b16",
                  test_full_stack_v3(
                      PayloadMode::DATA, js, kMaxRounds, kTrials, 4, false,
                      true,
                      kSeed ^ static_cast<uint32_t>(static_cast<int>(js * 100)),
                      16));
        std::fflush(stdout);
    }

    std::printf("\n── V3 boost=4 ──\n");
    std::printf("  %5s   | %7s | %9s | %6s | %s\n", "J/S", "CRC", "avgR",
                "maxR", "");
    for (double js : js_sweep) {
        print_row("V3-b4",
                  test_full_stack_v3(
                      PayloadMode::DATA, js, kMaxRounds, kTrials, 4, false,
                      true,
                      kSeed ^ static_cast<uint32_t>(static_cast<int>(js * 100)),
                      4));
        std::fflush(stdout);
    }

    std::printf("\n── V3 boost=16 VOICE ──\n");
    std::printf("  %5s   | %7s | %9s | %6s | %s\n", "J/S", "CRC", "avgR",
                "maxR", "");
    for (double js : js_sweep) {
        print_row("V3-voice",
                  test_full_stack_v3(
                      PayloadMode::VOICE, js, kMaxRounds, kTrials, 4, false,
                      true,
                      kSeed ^ static_cast<uint32_t>(static_cast<int>(js * 100)),
                      16));
        std::fflush(stdout);
    }
    // ── V4: 동기 우회 — 디스패처 FEC 경로만 테스트 ──
    std::printf(
        "\n================================================================\n");
    std::printf("  V4: 동기 우회 (Inject_Payload_Phase)\n");
    std::printf(
        "================================================================\n");

    std::printf("\n── V4 64chip DATA BPS=4 ──\n");
    for (double js : js_sweep) {
        print_row("V4-64",
                  test_full_stack_v4(
                      PayloadMode::DATA, js, kMaxRounds, kTrials, 4,
                      kSeed ^ static_cast<uint32_t>(static_cast<int>(js * 100))));
        std::fflush(stdout);
    }

    std::printf("\n── V4 16chip VOICE ──\n");
    for (double js : js_sweep) {
        print_row("V4-16",
                  test_full_stack_v4(
                      PayloadMode::VOICE, js, kMaxRounds, kTrials, 4,
                      kSeed ^ static_cast<uint32_t>(static_cast<int>(js * 100))));
        std::fflush(stdout);
    }
    // ── FHSS (기존 유지) ──
    std::printf(
        "\n================================================================\n");
    std::printf("  FHSS + 부분대역 30%%\n");
    std::printf(
        "================================================================\n");
    auto test_fhss = [&](double js_db, bool fhss_on,
                         uint32_t sb) -> LayerResult {
        FEC_HARQ::Set_IR_Erasure_Enabled(false);
        FEC_HARQ::Set_IR_Rs_Post_Enabled(true);
        const int bps = FEC_HARQ::BPS64_MIN_OPERABLE,
                  nsym = FEC_HARQ::nsym_for_bps(bps), tc = nsym * 64;
        const int jam_ch = static_cast<int>(128.0 * 0.3 + 0.5);
        std::vector<int16_t> txI(static_cast<size_t>(tc)),
            txQ(static_cast<size_t>(tc));
        std::vector<int16_t> rxI(static_cast<size_t>(tc)),
            rxQ(static_cast<size_t>(tc));
        std::vector<double> db(static_cast<size_t>(tc));
        LayerResult r2{};
        r2.js_db = js_db;
        r2.trials = kTrials;
        for (int t = 0; t < kTrials; ++t) {
            uint32_t ts = sb ^ static_cast<uint32_t>(t * 0x9E3779B9u);
            uint32_t il = 0xA5A5A5A5u ^ ts;
            uint8_t info[8]{};
            uint32_t s2 = ts;
            for (int b = 0; b < 8; ++b) {
                s2 ^= s2 << 13u;
                s2 ^= s2 >> 17u;
                s2 ^= s2 << 5u;
                info[b] = static_cast<uint8_t>(s2 & 0xFFu);
            }
            uint8_t fixed_ch = HTS_V400_Dispatcher::FHSS_Derive_Channel(ts, 0u);
            FEC_HARQ::IR_RxState ir{};
            FEC_HARQ::IR_Init(ir);
            FEC_HARQ::WorkBuf wb{};
            bool dec = false;
            int ru = 0;
            for (int rv = 0; rv < kMaxRounds && !dec; ++rv) {
                uint8_t ch = fhss_on ? HTS_V400_Dispatcher::FHSS_Derive_Channel(
                                           ts, static_cast<uint32_t>(rv))
                                     : fixed_ch;
                double ejs = (static_cast<int>(ch) < jam_ch) ? js_db : -1.0;
                uint8_t syms[FEC_HARQ::NSYM64]{};
                std::memset(&wb, 0, sizeof(wb));
                int en =
                    FEC_HARQ::Encode64_IR(info, 8, syms, il, bps, rv & 3, wb);
                if (en <= 0)
                    break;
                for (int sym = 0; sym < nsym; ++sym)
                    walsh_enc_iq(syms[sym], 64, kAmp,
                                 &txI[static_cast<size_t>(sym * 64)],
                                 &txQ[static_cast<size_t>(sym * 64)]);
                std::mt19937 rng2(ts ^ static_cast<uint32_t>(rv * 0x85EBCA6Bu));
                if (ejs >= 0.0) {
                    add_barrage(txI.data(), db.data(), tc, ejs, rng2);
                    agc_quantize(db.data(), rxI.data(), rxQ.data(), tc);
                } else {
                    std::memcpy(rxI.data(), txI.data(),
                                static_cast<size_t>(tc) * 2);
                    std::memcpy(rxQ.data(), txQ.data(),
                                static_cast<size_t>(tc) * 2);
                }
                uint8_t out[8]{};
                int ol = 0;
                std::memset(&wb, 0, sizeof(wb));
                dec = FEC_HARQ::Decode64_IR(rxI.data(), rxQ.data(), nsym, 64,
                                            bps, il, rv & 3, ir, out, &ol, wb);
                ru = rv + 1;
                if (dec && (ol != 8 || std::memcmp(out, info, 8) != 0))
                    dec = false;
            }
            if (dec) {
                r2.crc_ok++;
                r2.avg_rounds += ru;
                if (ru > r2.max_rounds)
                    r2.max_rounds = ru;
            }
        }
        if (r2.crc_ok > 0)
            r2.avg_rounds /= r2.crc_ok;
        return r2;
    };
    for (bool fhss : {false, true}) {
        std::printf("\n── FHSS=%s ──\n", fhss ? "ON" : "OFF");
        for (double js : js_sweep) {
            print_row(fhss ? "FHSS" : "FIXED",
                      test_fhss(js, fhss,
                                kSeed ^ static_cast<uint32_t>(
                                            static_cast<int>(js * 100))));
            std::fflush(stdout);
        }
    }
    // ── 요약 ──
    std::printf(
        "\n================================================================\n");
    std::printf("  이득 분리 요약\n");
    std::printf(
        "================================================================\n");
    std::printf("  FEC직접:   Layer 2+3 결과 (프리앰블/헤더 없음)\n");
    std::printf("  기존:      패킷AGC + boost=16\n");
    std::printf("  V2A:       블록AGC + boost=16 (AGC 분리 효과)\n");
    std::printf("  V2B:       블록AGC + boost=4  (부스트 축소 효과)\n");
    std::printf("  V2C:       블록AGC + boost=1  (부스트 없음)\n");
    std::printf("  V3:        TX/RX 분리, 패킷 1회 생성 + 라운드별 신규 잡음\n");
    std::printf("\n  V2 > 기존 → AGC 모델이 핵심 원인\n");
    std::printf("  V2B > V2A → boost 축소 효과적\n");
    std::printf("  V2C ≈ FEC직접 → 구조적 손실 해소\n");
    std::printf("\n=== 완료 ===\n");
    return 0;
}
