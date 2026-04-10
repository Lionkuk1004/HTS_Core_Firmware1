// HTS_AMI_CommSpec_Barrage30_Matrix_Test.cpp
//
// Barrage30 / FEC·V400 검증 — 프로필 기반 (전수 조합 탐색 제거)
//
// 이전 방식: 128조합 × 2모드 × 6구간 × (J/S 2점) × 12 trial → 수만 회 run_one (과도한 시간)
// 현재 방식:
//   · fast (기본): 단일 기준 설정 + 희소 J/S 사다리 — 스모크·회귀용 (수십 초 목표)
//   · standard: (1) 기준선 대비 옵션 민감도 1차원, (2) BPS 사다리 — 공정용
//   · full: 앵커 J/S에서만 전 조합 랭킹 (구간 루프 없음) — 깊은 비교용
//
// 실행: AMI_Barrage30_Spec.exe           → fast
//       AMI_Barrage30_Spec.exe standard  → standard
//       AMI_Barrage30_Spec.exe full      → full
//
// 고정: CW_Cancel=OFF, AJC=OFF, IR-HARQ=ON (콜백 경로)
// J/S·PG·기준면 설명은 파일 하단 주석 블록 참고.
//
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) ||                          \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#error "[HTS_FATAL] PC 전용"
#endif

#include "HTS_FEC_HARQ.hpp"
#include "HTS_V400_Dispatcher.hpp"

#include <algorithm>
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
using ProtectedEngine::RxPhase;
using ProtectedEngine::SoftClipPolicy;

static constexpr int16_t kAmp = 2000;
static constexpr double kAmpD = 2000.0;
static constexpr double kBaseNoise = 0.01;
static constexpr double kAgcTarget = 26000.0;
static constexpr int kMaxChips = 256 + FEC_HARQ::NSYM64 * 64;

DecodedPacket g_last{};
static void on_pkt(const DecodedPacket& p) noexcept { g_last = p; }

static void barrage_dbl(const int16_t* tx, double* out, int n, double js_db,
                        std::mt19937& rng) noexcept {
    const double js_lin = std::pow(10.0, js_db / 10.0);
    const double jam_s = kAmpD * std::sqrt(js_lin);
    const double base_s = kAmpD * kBaseNoise;
    std::normal_distribution<double> nd(0.0, 1.0);
    for (int i = 0; i < n; ++i) {
        out[i] = static_cast<double>(tx[i]) + jam_s * nd(rng) +
                 base_s * nd(rng);
    }
}

static void agc_q(const double* in, int16_t* oI, int16_t* oQ, int n) noexcept {
    double pk = 0.0;
    for (int i = 0; i < n; ++i) {
        const double a = std::fabs(in[i]);
        if (a > pk) {
            pk = a;
        }
    }
    const double g = (pk > kAgcTarget) ? (kAgcTarget / pk) : 1.0;
    for (int i = 0; i < n; ++i) {
        long r = std::lround(in[i] * g);
        if (r > 32767L) {
            r = 32767L;
        }
        if (r < -32768L) {
            r = -32768L;
        }
        oI[i] = static_cast<int16_t>(r);
        oQ[i] = oI[i];
    }
}

// 재사용 버퍼 (run_one 호출마다 vector 재할당 제거)
static std::vector<int16_t> g_buf_i;
static std::vector<int16_t> g_buf_q;
static std::vector<double> g_buf_dbl;

static void ensure_chip_bufs() {
    const size_t n = static_cast<size_t>(kMaxChips);
    if (g_buf_i.size() < n) {
        g_buf_i.resize(n);
        g_buf_q.resize(n);
        g_buf_dbl.resize(n);
    }
}

struct FecConfig {
    int bps;
    bool erasure;
    bool sic;
    bool rs_post;
    SoftClipPolicy clip;
    int boost;

    void print_label(char* buf, int sz, int bps_act) const noexcept {
        std::snprintf(buf, static_cast<size_t>(sz),
                      "BPS_req=%d act=%d ER=%d SIC=%d RS=%d SC=%s B=%d", bps,
                      bps_act, erasure ? 1 : 0, sic ? 1 : 0, rs_post ? 1 : 0,
                      (clip == SoftClipPolicy::NEVER) ? "N" : "A", boost);
    }
};

struct SweepResult {
    FecConfig cfg{};
    double crc_pct{};
    double avg_rounds{};
    int max_harq{};
    int bps_act{};
    uint32_t fail_wait_sync{};
    uint32_t fail_read_header{};
    uint32_t fail_read_payload{};
};

static SweepResult run_one(PayloadMode mode, const FecConfig& cfg, double js_db,
                           int max_feeds, int trials,
                           uint32_t seed_base) noexcept {
    ensure_chip_bufs();
    int16_t* oI = g_buf_i.data();
    int16_t* oQ = g_buf_q.data();
    double* dbl = g_buf_dbl.data();

    FEC_HARQ::Set_IR_Erasure_Enabled(cfg.erasure);
    FEC_HARQ::Set_IR_Rs_Post_Enabled(cfg.rs_post);

    int crc_ok = 0;
    long long sum_h = 0;
    int max_h = 0;
    int bps_act_acc = 0;
    uint32_t n_fail_sync = 0;
    uint32_t n_fail_hdr = 0;
    uint32_t n_fail_pay = 0;

    for (int t = 0; t < trials; ++t) {
        g_last = DecodedPacket{};
        const uint32_t ds = seed_base ^ static_cast<uint32_t>(t * 0x9E3779B9u);
        const uint32_t ns =
            (seed_base << 1) ^ static_cast<uint32_t>(t * 0x85EBCA6Bu);

        HTS_V400_Dispatcher disp;
        disp.Set_IR_Mode(true);
        disp.Set_Seed(ds);
        disp.Set_Preamble_Boost(cfg.boost);
        disp.Set_IR_SIC_Enabled(cfg.sic);
        disp.Set_CW_Cancel(false);
        disp.Set_AJC_Enabled(false);
        disp.Set_SoftClip_Policy(cfg.clip);
        disp.Set_Packet_Callback(on_pkt);
        disp.Set_Lab_IQ_Mode_Jam_Harness();
        disp.Set_Lab_BPS64(cfg.bps);
        bps_act_acc += disp.Get_Current_BPS64();

        uint8_t info[8]{};
        for (int b = 0; b < 8; ++b) {
            info[b] = static_cast<uint8_t>(
                static_cast<unsigned>(ds >> static_cast<unsigned>(b * 4)) ^
                static_cast<unsigned>(t + b));
        }

        int success = 0;
        std::mt19937 rng(ns);
        for (int feed = 0; feed < max_feeds && success == 0; ++feed) {
            int n = 0;
            if (feed == 0 || !disp.Is_Retx_Ready()) {
                n = disp.Build_Packet(mode, info, 8, kAmp, oI, oQ, kMaxChips);
            } else {
                n = disp.Build_Retx(mode, info, 8, kAmp, oI, oQ, kMaxChips);
            }
            if (n <= 0) {
                break;
            }
            if (js_db >= 0.0) {
                barrage_dbl(oI, dbl, n, js_db, rng);
                agc_q(dbl, oI, oQ, n);
            }
            if (feed == 0 || !disp.Is_Retx_Ready()) {
                for (int i = 0; i < n; ++i) {
                    disp.Feed_Chip(oI[i], oQ[i]);
                }
            } else {
                for (int i = 0; i < n; ++i) {
                    disp.Feed_Retx_Chip(oI[i], oQ[i]);
                }
            }
            if (g_last.success_mask == DecodedPacket::DECODE_MASK_OK) {
                success = 1;
            }
        }

        if (success != 0) {
            ++crc_ok;
            sum_h += g_last.harq_k;
            if (g_last.harq_k > max_h) {
                max_h = g_last.harq_k;
            }
        } else {
            const RxPhase ph = disp.Get_Phase();
            if (ph == RxPhase::WAIT_SYNC) {
                ++n_fail_sync;
            } else if (ph == RxPhase::READ_HEADER) {
                ++n_fail_hdr;
            } else if (ph == RxPhase::READ_PAYLOAD) {
                ++n_fail_pay;
            }
        }
    }

    SweepResult r{};
    r.cfg = cfg;
    r.crc_pct = (trials > 0) ? 100.0 * static_cast<double>(crc_ok) / trials : 0.0;
    r.avg_rounds =
        (crc_ok > 0) ? static_cast<double>(sum_h) / static_cast<double>(crc_ok) : 0.0;
    r.max_harq = max_h;
    r.bps_act = (trials > 0) ? bps_act_acc / trials : cfg.bps;
    r.fail_wait_sync = n_fail_sync;
    r.fail_read_header = n_fail_hdr;
    r.fail_read_payload = n_fail_pay;
    return r;
}

// ── 프로필 공통 상수 ──
static constexpr double kPg64Db = 18.061799739838887;
static constexpr double kPg16Db = 12.041199826559246;
static constexpr uint32_t kSeed = 0xB40730u;

enum class Profile { Fast, Standard, Full };

static Profile parse_profile(int argc, char** argv) {
    if (argc >= 2) {
        if (std::strcmp(argv[1], "full") == 0) {
            return Profile::Full;
        }
        if (std::strcmp(argv[1], "standard") == 0) {
            return Profile::Standard;
        }
    }
    return Profile::Fast;
}

// 권장 기준선 (Barrage + IR, 중간 BPS)
static FecConfig baseline_config() {
    return FecConfig{4, true, false, true, SoftClipPolicy::NEVER, 1};
}

static const char* mode_label(PayloadMode m) {
    return (m == PayloadMode::DATA) ? "64chip(DATA)" : "16chip(VOICE)";
}

static double pg_for_mode(PayloadMode m) {
    return (m == PayloadMode::DATA) ? kPg64Db : kPg16Db;
}

// ========== FAST: 기준 설정, 희소 J/S 사다리 ==========
static void run_profile_fast(int max_feeds) {
    static constexpr int kTrials = 5;
    static constexpr double kJsLadder[] = {0.0, 15.0, 30.0, 40.0, 50.0};
    static constexpr PayloadMode kModes[] = {PayloadMode::DATA, PayloadMode::VOICE};

    const FecConfig base = baseline_config();

    std::printf("=== Barrage30 profile=FAST (baseline only, sparse J/S) ===\n");
    std::printf("trials=%d max_feeds=%d | Set_Lab_BPS64 + Jam harness\n\n",
                kTrials, max_feeds);

    for (PayloadMode mode : kModes) {
        std::printf("--- %s  PG=%.2f dB ---\n", mode_label(mode), pg_for_mode(mode));
        std::printf("%6s %8s %10s %8s %6s  %s\n", "J/S_dB", "J/S_eff~", "CRC%%",
                    "avgHARQ", "maxH", "fail:sync/hdr/pay");
        for (double js : kJsLadder) {
            const uint32_t seed =
                kSeed ^ static_cast<uint32_t>(static_cast<int>(js * 17.0));
            const SweepResult sr =
                run_one(mode, base, js, max_feeds, kTrials, seed);
            const double eff = js - pg_for_mode(mode);
            std::printf("%6.0f %8.1f %9.1f%% %8.2f %6d  %u/%u/%u\n", js, eff,
                        sr.crc_pct, sr.avg_rounds, sr.max_harq,
                        sr.fail_wait_sync, sr.fail_read_header,
                        sr.fail_read_payload);
        }
        std::printf("\n");
    }
    char lbl[80];
    base.print_label(lbl, 80, FEC_HARQ::bps_clamp_runtime(base.bps));
    std::printf("Baseline: %s\n", lbl);
}

// ========== STANDARD: 민감도(한 차원) + BPS 사다리 ==========
static void run_profile_standard(int max_feeds) {
    static constexpr int kTrials = 6;
    static constexpr double kJsSense[] = {25.0, 40.0};
    const FecConfig base = baseline_config();

    struct VarRow {
        const char* name;
        FecConfig cfg;
    };
    const VarRow variants[] = {
        {"baseline", base},
        {"ER_off", FecConfig{base.bps, false, base.sic, base.rs_post, base.clip,
                             base.boost}},
        {"SIC_on", FecConfig{base.bps, base.erasure, true, base.rs_post, base.clip,
                             base.boost}},
        {"RS_off", FecConfig{base.bps, base.erasure, base.sic, false, base.clip,
                             base.boost}},
        {"SC_ALWAYS",
         FecConfig{base.bps, base.erasure, base.sic, base.rs_post,
                   SoftClipPolicy::ALWAYS, base.boost}},
        {"Boost4",
         FecConfig{base.bps, base.erasure, base.sic, base.rs_post, base.clip, 4}},
    };

    std::printf("=== Barrage30 profile=STANDARD ===\n");
    std::printf("A) Option sensitivity @ J/S = 25, 40 dB (DATA mode)\n");
    std::printf("trials=%d\n\n", kTrials);

    for (double js : kJsSense) {
        std::printf("-- J/S_chip=%.0f (eff~%.1f dB) DATA ---\n", js,
                    js - kPg64Db);
        std::printf("%-12s %8s %8s %8s\n", "variant", "CRC%%", "avgR", "maxH");
        const uint32_t seed = kSeed ^ static_cast<uint32_t>(static_cast<int>(js * 31.0));
        for (const VarRow& v : variants) {
            const SweepResult sr =
                run_one(PayloadMode::DATA, v.cfg, js, max_feeds, kTrials, seed ^ 0x111u);
            std::printf("%-12s %7.1f%% %8.2f %8d\n", v.name, sr.crc_pct,
                        sr.avg_rounds, sr.max_harq);
        }
        std::printf("\n");
    }

    std::printf("B) BPS ladder @ J/S=35 dB, DATA (other flags = baseline)\n");
    std::printf("%6s %10s %8s\n", "BPS", "CRC%%", "avgR");
    const uint32_t seed_b = kSeed ^ 0xB505u;
    for (int bps : {3, 4, 5, 6}) {
        FecConfig c = base;
        c.bps = bps;
        const SweepResult sr =
            run_one(PayloadMode::DATA, c, 35.0, max_feeds, kTrials, seed_b ^ static_cast<uint32_t>(bps * 997u));
        std::printf("%6d %9.1f%% %8.2f\n", bps, sr.crc_pct, sr.avg_rounds);
    }
    std::printf("\nC) VOICE mode spot @ J/S=30 (baseline)\n");
    {
        const SweepResult sr = run_one(PayloadMode::VOICE, base, 30.0, max_feeds,
                                       kTrials, kSeed ^ 0x01CEu);
        std::printf("CRC%%=%.1f avgR=%.2f maxH=%d\n", sr.crc_pct, sr.avg_rounds,
                    sr.max_harq);
    }
}

// ========== FULL: 앵커 J/S 두 점에서만 128조합 랭킹 (구간 이중 루프 제거) ==========
static void run_profile_full(int max_feeds) {
    static constexpr int kTrials = 8;
    static constexpr int bps_vals[] = {3, 4, 5, 6};
    static constexpr bool bool_vals[] = {false, true};
    static constexpr SoftClipPolicy clip_vals[] = {SoftClipPolicy::NEVER,
                                                   SoftClipPolicy::ALWAYS};
    static constexpr int boost_vals[] = {1, 4};
    static constexpr double kAnchorJs[] = {30.0, 45.0};

    std::vector<FecConfig> configs;
    for (int bps : bps_vals) {
        for (bool er : bool_vals) {
            for (bool sic : bool_vals) {
                for (bool rs : bool_vals) {
                    for (SoftClipPolicy sc : clip_vals) {
                        for (int bo : boost_vals) {
                            configs.push_back({bps, er, sic, rs, sc, bo});
                        }
                    }
                }
            }
        }
    }

    std::printf("=== Barrage30 profile=FULL (128 configs × anchor J/S only) ===\n");
    std::printf("anchors: 30 & 45 dB chip | trials=%d | modes: DATA+VOICE\n\n",
                kTrials);

    for (PayloadMode mode : {PayloadMode::DATA, PayloadMode::VOICE}) {
        for (double js : kAnchorJs) {
            struct Row {
                int idx;
                double crc_pct;
                double avg_r;
            };
            std::vector<Row> rows;
            rows.reserve(configs.size());
            const uint32_t seed_js =
                kSeed ^ static_cast<uint32_t>(static_cast<int>(js * 13.0)) ^
                ((mode == PayloadMode::DATA) ? 1u : 2u);

            std::printf("[%s] J/S=%.0f dB  ranking %zu configs...\n",
                        mode_label(mode), js, configs.size());
            std::fflush(stdout);

            for (size_t ci = 0; ci < configs.size(); ++ci) {
                const uint32_t seed = seed_js ^ static_cast<uint32_t>(ci * 0x9E37u);
                const SweepResult sr =
                    run_one(mode, configs[ci], js, max_feeds, kTrials, seed);
                rows.push_back(
                    Row{static_cast<int>(ci), sr.crc_pct, sr.avg_rounds});
            }

            std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
                if (a.crc_pct != b.crc_pct) {
                    return a.crc_pct > b.crc_pct;
                }
                return a.avg_r < b.avg_r;
            });

            std::printf("  top 5:\n");
            const int nshow =
                (static_cast<int>(rows.size()) < 5) ? static_cast<int>(rows.size()) : 5;
            for (int i = 0; i < nshow; ++i) {
                const Row& rw = rows[static_cast<size_t>(i)];
                char lbl[72];
                configs[static_cast<size_t>(rw.idx)].print_label(
                    lbl, 72,
                    FEC_HARQ::bps_clamp_runtime(configs[static_cast<size_t>(rw.idx)].bps));
                std::printf("   #%d CRC=%.1f%% avgR=%.2f  %s\n", i + 1,
                            rw.crc_pct, rw.avg_r, lbl);
            }
            std::printf("\n");
        }
    }
}

} // namespace

int main(int argc, char** argv) {
    static constexpr int kMaxFeeds = 32;
    const Profile p = parse_profile(argc, argv);

    std::printf("AMI Barrage30 matrix (revised). argv[1]: fast | standard | full\n");
    std::printf("PG_64=%.2f dB  PG_16=%.2f dB\n\n", kPg64Db, kPg16Db);

    switch (p) {
    case Profile::Fast:
        run_profile_fast(kMaxFeeds);
        break;
    case Profile::Standard:
        run_profile_standard(kMaxFeeds);
        break;
    case Profile::Full:
        run_profile_full(kMaxFeeds);
        break;
    }

    std::printf("=== done ===\n");
    return 0;
}

/*
 * ── J/S·이득·표 출력 (요약) ───────────────────────────────────────────
 *  · js_db: barrage_dbl 칩 스트림 기준 J/S(dB) (하네스 정의).
 *  · 표의 "J/S_eff~" = 칩 J/S − Walsh PG(dB) 만 반영한 1차 직관용 열이다.
 *    HTS 전체 이득(Conv R=1/2, REP, IR-HARQ LLR 누적 등)은 이 숫자에 포함되지
 *    않는다. FEC·HARQ 이득은 CRC%%·avg HARQ·라운드 분포로만 나타난다.
 *  · RX 버그(과거): PRE_SYM0=63 인데 walsh_dec_full_ 탐색을 2^BPS로 제한하면
 *    BPS<6 시 프리앰블 불검출. Feed_Chip 동기/헤더 경로는 64빈 전체 탐색으로
 *    분리됨(HTS_V400_Dispatcher — cap_search_to_bps=false).
 *  · CommSpec의 J/S 정의(칩/복조 후/EbN0)가 하네스와 다르면 같은 dB라도 결과가
 *    달라질 수 있으니 스펙 기준면과 스케일을 맞출 것.
 */
