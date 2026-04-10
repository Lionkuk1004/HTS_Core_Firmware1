// HTS_Sensitivity_Test.cpp — 설정값 민감도 테스트
//
// [목적] 디스패처+FEC 설정 조합별 성능 변화를 체계적으로 측정
//
// [측정 항목]
//   A) pre_boost: 1, 4, 8, 16 (AGC 압축 영향)
//   B) pre_reps: 1, 4, 8 (프리앰블 검출 신뢰도)
//   C) soft_clip: ALWAYS, SYNC_ONLY, NEVER
//   D) AJC + CW cancel 조합: 4가지
//   E) BPS: 3, 4, 5, 6 (64칩 DATA)
//   F) SIC: on/off (IR-HARQ 연속 모드)
//
// [방법론]
//   각 설정 조합에서 J/S 5개 포인트(15, 20, 25, 30, 35dB) × 50트라이얼
//   디스패처 경유 전체 스택 (Layer 4)
//   기준선: FEC 직접 호출 (디스패처 우회) 동일 조건
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
static constexpr int kTrials = 50;
static constexpr int kMaxRounds = 32;
static constexpr uint32_t kSeedBase = 0xB40730u;
// ── 채널 모델 ──
static void add_barrage(const int16_t *tx, double *out, int n, double js_db,
                        std::mt19937 &rng) noexcept {
    const double js_lin = std::pow(10.0, js_db / 10.0);
    const double sigma = kAmpD * std::sqrt(js_lin);
    std::normal_distribution<double> nd(0.0, 1.0);
    for (int i = 0; i < n; ++i)
        out[i] = static_cast<double>(tx[i]) + sigma * nd(rng);
}
static void add_cw_jammer(double *buf, int n, double js_db, double freq_ratio,
                          std::mt19937 & /*rng*/) noexcept {
    const double js_lin = std::pow(10.0, js_db / 10.0);
    const double cw_amp = kAmpD * std::sqrt(js_lin * 2.0);
    for (int i = 0; i < n; ++i) {
        buf[i] += cw_amp * std::sin(2.0 * 3.14159265358979323846 * freq_ratio *
                                    static_cast<double>(i));
    }
}
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
// ── 결과 구조 ──
struct SensResult {
    double js_db;
    int trials;
    int sync_ok; // 프리앰블+헤더 동기 성공
    int crc_ok;  // 최종 디코딩 성공
    double avg_rounds;
    int max_rounds;
};
DecodedPacket g_last{};
static void on_pkt(const DecodedPacket &p) noexcept { g_last = p; }
// ── 설정 구조 ──
struct DispConfig {
    const char *label;
    int pre_boost;
    int pre_reps;
    SoftClipPolicy clip;
    bool ajc_on;
    bool cw_on;
    int bps;
    bool sic_on;
};
static const char *clip_str(SoftClipPolicy p) noexcept {
    switch (p) {
    case SoftClipPolicy::ALWAYS:
        return "ALWAYS";
    case SoftClipPolicy::SYNC_ONLY:
        return "SYNC";
    case SoftClipPolicy::NEVER:
        return "NEVER";
    default:
        return "?";
    }
}
// ── 코어 테스트 함수 ──
enum class JamType { BARRAGE, CW, NONE };
static SensResult run_one(const DispConfig &cfg, PayloadMode mode, double js_db,
                          JamType jam, int trials) noexcept {
    FEC_HARQ::Set_IR_Erasure_Enabled(false);
    FEC_HARQ::Set_IR_Rs_Post_Enabled(true);
    const int nc = (mode == PayloadMode::DATA) ? 64 : 16;
    static constexpr int kMaxC = 256 + (FEC_HARQ::NSYM64 + 12) * 64;
    std::vector<int16_t> oI(static_cast<size_t>(kMaxC));
    std::vector<int16_t> oQ(static_cast<size_t>(kMaxC));
    std::vector<double> dbl(static_cast<size_t>(kMaxC));
    SensResult res{};
    res.js_db = js_db;
    res.trials = trials;
    HTS_V400_Dispatcher disp;
    for (int t = 0; t < trials; ++t) {
        disp.Reset();
        g_last = DecodedPacket{};
        const uint32_t ds =
            kSeedBase ^ static_cast<uint32_t>(t * 0x9E3779B9u) ^
            static_cast<uint32_t>(static_cast<int>(js_db * 100));
        const uint32_t ns =
            (kSeedBase << 1) ^ static_cast<uint32_t>(t * 0x85EBCA6Bu);
        disp.Set_IR_Mode(true);
        disp.Set_Seed(ds);
        disp.Set_Preamble_Boost(cfg.pre_boost);
        disp.Set_Preamble_Reps(cfg.pre_reps);
        disp.Set_IR_SIC_Enabled(cfg.sic_on);
        disp.Set_CW_Cancel(cfg.cw_on);
        disp.Set_AJC_Enabled(cfg.ajc_on);
        disp.Set_SoftClip_Policy(cfg.clip);
        disp.Set_Packet_Callback(on_pkt);
        if (mode == PayloadMode::DATA) {
            // BPS 설정: nf 값으로 간접 제어
            uint32_t nf = 0;
            switch (cfg.bps) {
            case 3:
                nf = 5000;
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
        for (int feed = 0; feed < kMaxRounds && success == 0; ++feed) {
            int n = 0;
            if (feed == 0 || !disp.Is_Retx_Ready())
                n = disp.Build_Packet(mode, info, 8, kAmp, oI.data(), oQ.data(),
                                      kMaxC);
            else
                n = disp.Build_Retx(mode, info, 8, kAmp, oI.data(), oQ.data(),
                                    kMaxC);
            if (n <= 0)
                break;
            // 채널 적용
            if (jam != JamType::NONE && js_db >= 0.0) {
                for (int i = 0; i < n; ++i)
                    dbl[static_cast<size_t>(i)] =
                        static_cast<double>(oI[static_cast<size_t>(i)]);
                if (jam == JamType::BARRAGE) {
                    add_barrage(oI.data(), dbl.data(), n, js_db, rng);
                } else if (jam == JamType::CW) {
                    // CW: 먼저 신호 복사, 그 위에 CW 가산
                    add_cw_jammer(dbl.data(), n, js_db, 0.125, rng);
                }
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
            if (g_last.success_mask == DecodedPacket::DECODE_MASK_OK) {
                success = 1;
                // 동기 성공 (디코딩까지 도달했으므로)
                res.sync_ok++;
            }
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
// ── 출력 ──
static void print_header(const char *title) noexcept {
    std::printf("\n── %s ──\n", title);
    std::printf("  %5s | %6s | %6s | %5s | %4s\n", "J/S", "CRC%", "avgR",
                "maxR", "sync");
    std::printf("  ------+--------+--------+-------+-----\n");
}
static void print_row(const SensResult &r) noexcept {
    const double pct = (r.trials > 0) ? 100.0 * r.crc_ok / r.trials : 0.0;
    std::printf("  %5.0f | %5.1f%% | %5.1fR | %4d | %3d/%d\n", r.js_db, pct,
                r.avg_rounds, r.max_rounds, r.sync_ok, r.trials);
}
static void run_sweep(const DispConfig &cfg, PayloadMode mode, JamType jam,
                      const double *js_list, int js_count) noexcept {
    char title[256];
    std::snprintf(title, sizeof(title),
                  "boost=%d reps=%d clip=%s ajc=%s cw=%s bps=%d sic=%s [%s]",
                  cfg.pre_boost, cfg.pre_reps, clip_str(cfg.clip),
                  cfg.ajc_on ? "ON" : "OFF", cfg.cw_on ? "ON" : "OFF", cfg.bps,
                  cfg.sic_on ? "ON" : "OFF",
                  (jam == JamType::BARRAGE) ? "BARRAGE"
                  : (jam == JamType::CW)    ? "CW"
                                            : "CLEAN");
    print_header(title);
    for (int j = 0; j < js_count; ++j) {
        SensResult r = run_one(cfg, mode, js_list[j], jam, kTrials);
        print_row(r);
        std::fflush(stdout);
    }
}
} // namespace
#if !defined(HTS_BARRAGE30_RUN_FEC_LAYER_INSTEAD)
int main() {
    static constexpr double js_points[] = {15, 20, 25, 30, 35};
    static constexpr int js_count = 5;
    std::printf(
        "================================================================\n");
    std::printf("  HTS B-CDMA 설정값 민감도 테스트\n");
    std::printf("  트라이얼: %d / 최대 라운드: %d / 모드: 64칩 DATA IR-HARQ\n",
                kTrials, kMaxRounds);
    std::printf(
        "================================================================\n");
    // ================================================================
    //  TEST A: pre_boost 민감도 (1, 4, 8, 16)
    //  고정: reps=8, clip=NEVER, ajc=OFF, cw=OFF, bps=4, sic=OFF
    //  목적: AGC 압축이 성능에 미치는 영향 분리
    // ================================================================
    std::printf("\n\n=== TEST A: pre_boost 민감도 ===\n");
    for (int boost : {1, 4, 8, 16}) {
        DispConfig cfg = {"boost", boost, 8, SoftClipPolicy::NEVER,
                          false,   false, 4, false};
        run_sweep(cfg, PayloadMode::DATA, JamType::BARRAGE, js_points,
                  js_count);
    }
    // ================================================================
    //  TEST B: pre_reps 민감도 (1, 4, 8)
    //  고정: boost=4, clip=NEVER, ajc=OFF, cw=OFF, bps=4, sic=OFF
    //  목적: 프리앰블 반복이 동기 확률에 미치는 영향
    // ================================================================
    std::printf("\n\n=== TEST B: pre_reps 민감도 ===\n");
    for (int reps : {1, 4, 8}) {
        DispConfig cfg = {"reps", 4,     reps, SoftClipPolicy::NEVER,
                          false,  false, 4,    false};
        run_sweep(cfg, PayloadMode::DATA, JamType::BARRAGE, js_points,
                  js_count);
    }
    // ================================================================
    //  TEST C: soft_clip 민감도
    //  고정: boost=4, reps=8, ajc=OFF, cw=OFF, bps=4, sic=OFF
    //  목적: 소프트 클리핑이 IR-HARQ LLR 품질에 미치는 영향
    // ================================================================
    std::printf("\n\n=== TEST C: soft_clip 민감도 ===\n");
    for (SoftClipPolicy p : {SoftClipPolicy::ALWAYS, SoftClipPolicy::SYNC_ONLY,
                             SoftClipPolicy::NEVER}) {
        DispConfig cfg = {"clip", 4, 8, p, false, false, 4, false};
        run_sweep(cfg, PayloadMode::DATA, JamType::BARRAGE, js_points,
                  js_count);
    }
    // ================================================================
    //  TEST D: AJC + CW cancel 조합 (BARRAGE)
    //  고정: boost=4, reps=8, clip=NEVER, bps=4, sic=OFF
    //  목적: 간섭 제거 엔진이 BARRAGE에서 오히려 해치는지 확인
    // ================================================================
    std::printf("\n\n=== TEST D: AJC+CW 조합 (BARRAGE) ===\n");
    for (int ajc : {0, 1}) {
        for (int cw : {0, 1}) {
            DispConfig cfg = {"ajc_cw",
                              4,
                              8,
                              SoftClipPolicy::NEVER,
                              static_cast<bool>(ajc),
                              static_cast<bool>(cw),
                              4,
                              false};
            run_sweep(cfg, PayloadMode::DATA, JamType::BARRAGE, js_points,
                      js_count);
        }
    }
    // ================================================================
    //  TEST D-2: AJC + CW cancel 조합 (CW 재밍)
    //  목적: CW 재밍 시 CW cancel의 실제 효과 측정
    // ================================================================
    std::printf("\n\n=== TEST D-2: AJC+CW 조합 (CW 재밍) ===\n");
    for (int ajc : {0, 1}) {
        for (int cw : {0, 1}) {
            DispConfig cfg = {"ajc_cw",
                              4,
                              8,
                              SoftClipPolicy::NEVER,
                              static_cast<bool>(ajc),
                              static_cast<bool>(cw),
                              4,
                              false};
            run_sweep(cfg, PayloadMode::DATA, JamType::CW, js_points, js_count);
        }
    }
    // ================================================================
    //  TEST E: BPS 민감도 (3, 4, 5, 6)
    //  고정: boost=4, reps=8, clip=NEVER, ajc=OFF, cw=OFF, sic=OFF
    //  목적: BPS별 한계 J/S 확인
    // ================================================================
    std::printf("\n\n=== TEST E: BPS 민감도 ===\n");
    static constexpr double js_bps[] = {10, 15, 20, 25, 30, 35, 40};
    for (int bps : {3, 4, 5, 6}) {
        DispConfig cfg = {"bps", 4,     8,   SoftClipPolicy::NEVER,
                          false, false, bps, false};
        run_sweep(cfg, PayloadMode::DATA, JamType::BARRAGE, js_bps, 7);
    }
    // ================================================================
    //  TEST F: SIC on/off (IR-HARQ 연속 모드)
    //  고정: boost=4, reps=8, clip=NEVER, ajc=OFF, cw=OFF, bps=4
    //  목적: SIC가 고 J/S에서 오히려 해치는지 확인
    // ================================================================
    std::printf("\n\n=== TEST F: SIC on/off ===\n");
    for (bool sic : {false, true}) {
        DispConfig cfg = {"sic", 4,     8, SoftClipPolicy::NEVER,
                          false, false, 4, sic};
        run_sweep(cfg, PayloadMode::DATA, JamType::BARRAGE, js_points,
                  js_count);
    }
    // ================================================================
    //  TEST G: 16칩 VOICE 기준선
    //  고정: boost=4, reps=8, clip=NEVER, ajc=OFF, cw=OFF, sic=OFF
    // ================================================================
    std::printf("\n\n=== TEST G: 16칩 VOICE 기준선 ===\n");
    {
        DispConfig cfg = {"voice", 4,     8, SoftClipPolicy::NEVER,
                          false,   false, 4, false};
        run_sweep(cfg, PayloadMode::VOICE, JamType::BARRAGE, js_points,
                  js_count);
    }
    // ================================================================
    //  TEST H: FEC 직접 기준선 (디스패처 우회)
    //  디스패처 손실 분리를 위한 참조
    // ================================================================
    std::printf("\n\n=== TEST H: FEC 직접 기준선 (디스패처 우회) ===\n");
    {
        FEC_HARQ::Set_IR_Erasure_Enabled(false);
        FEC_HARQ::Set_IR_Rs_Post_Enabled(true);
        static constexpr int bps = 4;
        constexpr int nsym = FEC_HARQ::nsym_for_bps(bps);
        const int nc = 64;
        const int total_chips = nsym * nc;
        std::printf("\n── 64chip BPS=%d FEC직접 (프리앰블/헤더 없음) ──\n",
                    bps);
        std::printf("  %5s | %6s | %6s | %5s\n", "J/S", "CRC%", "avgR", "maxR");
        std::printf("  ------+--------+--------+------\n");
        static constexpr double js_ref[] = {15, 20, 25, 30, 35, 40};
        static std::vector<int16_t> txI;
        static std::vector<int16_t> txQ;
        static std::vector<int16_t> rxI;
        static std::vector<int16_t> rxQ;
        static std::vector<double> dbl;
        const size_t chip_n = static_cast<size_t>(total_chips);
        txI.resize(chip_n);
        txQ.resize(chip_n);
        rxI.resize(chip_n);
        rxQ.resize(chip_n);
        dbl.resize(chip_n);
        for (double js : js_ref) {
            int ok_count = 0;
            double sum_rounds = 0.0;
            int max_r = 0;
            for (int t = 0; t < kTrials; ++t) {
                const uint32_t ts =
                    kSeedBase ^ static_cast<uint32_t>(t * 0x9E3779B9u) ^
                    static_cast<uint32_t>(static_cast<int>(js * 100));
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
                auto walsh_enc = [&](uint8_t sym, int n, int16_t amp,
                                     int16_t *I, int16_t *Q) {
                    for (int j = 0; j < n; ++j) {
                        uint32_t x = static_cast<uint32_t>(sym) &
                                     static_cast<uint32_t>(j);
                        x ^= (x >> 16u);
                        x ^= (x >> 8u);
                        x ^= (x >> 4u);
                        x ^= (x >> 2u);
                        x ^= (x >> 1u);
                        const int32_t w = 1 - 2 * static_cast<int32_t>(x & 1u);
                        I[j] =
                            static_cast<int16_t>(static_cast<int32_t>(amp) * w);
                        Q[j] = I[j];
                    }
                };
                for (int rv = 0; rv < kMaxRounds && !decoded; ++rv) {
                    uint8_t syms[FEC_HARQ::NSYM64]{};
                    std::memset(&wb, 0, sizeof(wb));
                    int enc_n = FEC_HARQ::Encode64_IR(info, 8, syms, il, bps,
                                                      rv & 3, wb);
                    if (enc_n <= 0)
                        break;
                    for (int sym = 0; sym < nsym; ++sym)
                        walsh_enc(syms[sym], nc, kAmp,
                                  &txI[static_cast<size_t>(sym * nc)],
                                  &txQ[static_cast<size_t>(sym * nc)]);
                    std::mt19937 rng(ts ^
                                     static_cast<uint32_t>(rv * 0x85EBCA6Bu));
                    add_barrage(txI.data(), dbl.data(), total_chips, js, rng);
                    agc_quantize(dbl.data(), rxI.data(), rxQ.data(),
                                 total_chips);
                    uint8_t out[8]{};
                    int olen = 0;
                    std::memset(&wb, 0, sizeof(wb));
                    decoded = FEC_HARQ::Decode64_IR(rxI.data(), rxQ.data(),
                                                    nsym, nc, bps, il, rv & 3,
                                                    ir, out, &olen, wb);
                    rounds_used = rv + 1;
                    if (decoded &&
                        (olen != 8 || std::memcmp(out, info, 8) != 0))
                        decoded = false;
                }
                if (decoded) {
                    ok_count++;
                    sum_rounds += rounds_used;
                    if (rounds_used > max_r)
                        max_r = rounds_used;
                }
            }
            double pct = 100.0 * ok_count / kTrials;
            double avg = (ok_count > 0) ? sum_rounds / ok_count : 0.0;
            std::printf("  %5.0f | %5.1f%% | %5.1fR | %4d\n", js, pct, avg,
                        max_r);
            std::fflush(stdout);
        }
    }
    // ================================================================
    //  요약
    // ================================================================
    std::printf(
        "\n================================================================\n");
    std::printf("  민감도 테스트 완료\n");
    std::printf(
        "================================================================\n");
    std::printf("  비교 기준:\n");
    std::printf(
        "    TEST H(FEC직접) vs TEST A~G(디스패처) 차이 = 디스패처 손실\n");
    std::printf("    TEST A 내 boost 변화 = AGC 압축 영향\n");
    std::printf("    TEST B 내 reps 변화 = 동기 신뢰도\n");
    std::printf("    TEST C 내 clip 변화 = LLR 품질 영향\n");
    std::printf("    TEST D 내 ajc/cw 변화 = 간섭 제거 효과/부작용\n");
    std::printf("    TEST E 내 bps 변화 = 처리이득 vs 전송률 트레이드오프\n");
    std::printf("    TEST F 내 sic 변화 = 연속간섭제거 효과\n");
    std::printf("\n=== 완료 ===\n");
    return 0;
}
#endif // !HTS_BARRAGE30_RUN_FEC_LAYER_INSTEAD
