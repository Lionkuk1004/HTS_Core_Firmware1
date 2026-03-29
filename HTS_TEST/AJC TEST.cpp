// =========================================================================
//  HTS_CW_Cancel_E2E_Test.cpp — CW 소거기 E2E 효과 측정 Rev.7
//
//  [Rev.7 핵심 — AJC 워밍업 패킷으로 수렴 문제 해결]
//
//  [이전 버전들의 근본 문제]
//   AJC는 연속 스트림에서 점진적으로 학습하도록 설계되어 있습니다.
//   매 시도마다 Reset()을 호출하면 AJC가 항상 cold start 상태에서
//   시작하므로 230심볼 패킷 한 개를 받는 동안 수렴하지 못합니다.
//   수렴 전의 AJC는 간섭을 제거하는 것이 아니라 오히려 신호를
//   왜곡하므로 측정값이 0%로 나옵니다.
//
//  [워밍업 설계]
//   실제 수신기는 리셋 없이 연속 동작합니다. 따라서 벤치마크도
//   다음과 같이 현실을 반영해야 합니다.
//
//   1) g_rx를 한 번만 Reset()하고 워밍업 시작
//   2) 동일한 CW 환경에서 워밍업 패킷 N_WARMUP개를 연속 수신
//      → AJC가 CW 패턴을 학습하고 수렴
//   3) 수렴 완료 후부터 trials개의 패킷 성공률을 집계
//
//   워밍업 패킷 수: 10개 (경험적으로 AJC는 5~10 패킷에서 수렴)
//   워밍업 패킷은 성공/실패 무관 — 학습 목적으로만 사용
//
//  [wb_tx_ / wb_rx_ 오염 문제 해결]
//   Reset()이 wb_tx_/wb_rx_를 초기화하지 않아서 발생하는 오염을
//   측정 구간 사이에 g_rx를 완전히 재생성하는 방식으로 해결합니다.
//   전역 g_rx를 각 dB 구간 시작 시 소멸자 호출 후 placement new로
//   재구성합니다 (이것이 유일하게 완전한 초기화 방법입니다).
//
//  [빌드]
//   cl /EHsc /O2 /std:c++17 /MP HTS_CW_Cancel_E2E_Test.cpp
//      HTS_V400_Dispatcher.cpp HTS_FEC_HARQ.cpp HTS_AntiJam_Engine.cpp
//      HTS64_Native_ECCM_Core.cpp
// =========================================================================
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <cstring>
#include <cstdio>
#include <iostream>
#include <new>
#include <chrono>
#include <algorithm>

#include "HTS_V400_Dispatcher.hpp"
#include "HTS_FEC_HARQ.hpp"

using namespace ProtectedEngine;

// ── 전역 Dispatcher 버퍼 — placement new로 완전 재초기화 가능 ──
alignas(HTS_V400_Dispatcher) static uint8_t g_tx_buf[sizeof(HTS_V400_Dispatcher)];
alignas(HTS_V400_Dispatcher) static uint8_t g_rx_buf[sizeof(HTS_V400_Dispatcher)];
static HTS_V400_Dispatcher* g_tx = nullptr;
static HTS_V400_Dispatcher* g_rx = nullptr;

// 워밍업 패킷 수 — AJC 수렴에 필요한 최소 패킷 수
static constexpr int N_WARMUP = 10;

static constexpr int E2E_MAX_CHIPS = 16000;
static int16_t g_base_I[E2E_MAX_CHIPS];
static int16_t g_base_Q[E2E_MAX_CHIPS];
static int16_t g_jam_I[E2E_MAX_CHIPS];
static int16_t g_jam_Q[E2E_MAX_CHIPS];
static int     g_base_count = 0;

// 프리앰블+헤더 256칩: CW 미주입 → 동기 보장
// 페이로드부터 CW 전체 주입 → 소거기 측정
static constexpr int PREAMBLE_CHIPS = 256;

static constexpr int16_t k_lut8[8] = {
    0, 181, 256, 181, 0, -181, -256, -181
};

static const uint8_t k_test_info[8] = {
    0x12u, 0x34u, 0x56u, 0x78u, 0x9Au, 0xBCu, 0xDEu, 0xF0u
};

static bool g_cb_decoded = false;
static int  g_cb_harq_k = 0;

static void rx_packet_cb(const DecodedPacket& pkt) {
    if (pkt.success &&
        pkt.data_len == static_cast<int>(sizeof(k_test_info)) &&
        std::memcmp(pkt.data, k_test_info, sizeof(k_test_info)) == 0) {
        g_cb_decoded = true;
        g_cb_harq_k = pkt.harq_k;
    }
}

// =====================================================================
//  Dispatcher 완전 재생성
//
//  Reset()은 wb_tx_/wb_rx_를 초기화하지 않으므로 구간 사이에
//  소멸자 호출 후 placement new로 완전한 cold state를 만듭니다.
// =====================================================================
static void rebuild_rx(bool cw_cancel_on) {
    if (g_rx) { g_rx->~HTS_V400_Dispatcher(); }
    g_rx = new (g_rx_buf) HTS_V400_Dispatcher();
    g_rx->Set_Seed(0x12345678u);
    g_rx->Update_Adaptive_BPS(3000u);
    g_rx->Set_CW_Cancel(cw_cancel_on);
    g_rx->Set_Packet_Callback(rx_packet_cb);
}

static void rebuild_tx(uint32_t seed) {
    if (g_tx) { g_tx->~HTS_V400_Dispatcher(); }
    g_tx = new (g_tx_buf) HTS_V400_Dispatcher();
    g_tx->Set_Seed(seed);
    g_tx->Update_Adaptive_BPS(3000u);
}

// =====================================================================
//  CW 주입 칩 배열 사전 계산 — LUT 기반, sin() 없음
// =====================================================================
static void precompute_jammed(int32_t ja) {
    for (int i = 0; i < g_base_count; ++i) {
        if (i < PREAMBLE_CHIPS) {
            g_jam_I[i] = g_base_I[i];
            g_jam_Q[i] = g_base_Q[i];
        }
        else {
            const int32_t lut = static_cast<int32_t>(k_lut8[i & 7u]);
            const int32_t cw = (ja * lut) >> 8;
            const int32_t vI = static_cast<int32_t>(g_base_I[i]) + cw;
            const int32_t vQ = static_cast<int32_t>(g_base_Q[i]) + cw;
            g_jam_I[i] = static_cast<int16_t>(
                std::max(-32767, std::min(32767, vI)));
            g_jam_Q[i] = static_cast<int16_t>(
                std::max(-32767, std::min(32767, vQ)));
        }
    }
}

static bool build_chips(uint32_t seed, int16_t amp) {
    rebuild_tx(seed);
    g_base_count = g_tx->Build_Packet(
        PayloadMode::DATA, k_test_info,
        static_cast<int>(sizeof(k_test_info)),
        amp, g_base_I, g_base_Q, E2E_MAX_CHIPS);
    return (g_base_count > 0);
}

// =====================================================================
//  칩 스트림 한 라운드 전송 — g_rx에 Feed_Chip() 반복 호출
// =====================================================================
static void feed_one_round(int max_harq) {
    for (int k = 0; k < max_harq && !g_cb_decoded; ++k) {
        for (int i = 0; i < g_base_count; ++i) {
            g_rx->Feed_Chip(g_jam_I[i], g_jam_Q[i]);
            if (g_cb_decoded) break;
        }
    }
}

// =====================================================================
//  배치 측정 — 워밍업 → 측정 구조
//
//  [동작 순서]
//   1) dB 구간별로 g_rx를 완전 재생성 (wb 오염 완전 제거)
//   2) 워밍업 패킷 N_WARMUP개를 연속 수신
//      - 동일한 CW 환경, 동일한 패킷 데이터
//      - 결과 무관 → AJC 수렴 목적
//   3) 워밍업 완료 후 trials개의 패킷 성공률 집계
//      - 수렴된 AJC 상태에서 측정하므로 실제 운용 성능 반영
//
//  [시드 설계]
//   워밍업: seed_base ^ warmup_index
//   측정:   seed_base ^ (N_WARMUP + trial_index)
//   → 워밍업과 측정 패킷이 서로 다른 인터리빙 패턴을 가짐
//   → 특정 패턴에 대한 편향 없이 범용 수렴 달성
// =====================================================================
struct E2EResult { double pct; double avg_k; int max_k; };

static E2EResult run_e2e_warmed(uint32_t seed_base, int16_t amp,
    double cw_db, int max_harq, bool cw_cancel_on, int trials) {

    const double  jl = std::pow(10.0, cw_db / 20.0);
    const int32_t ja = std::max(1, std::min(32767,
        static_cast<int32_t>(300.0 * jl)));

    // dB 구간 시작 시 g_rx 완전 재생성 (wb 오염 방지)
    rebuild_rx(cw_cancel_on);

    // ── 워밍업: AJC를 CW 환경에 수렴시킵니다 ──
    for (int w = 0; w < N_WARMUP; ++w) {
        const uint32_t ws = seed_base ^ static_cast<uint32_t>(w);
        if (!build_chips(ws, amp)) continue;
        precompute_jammed(ja);

        // g_rx는 재생성하지 않음 — 워밍업 패킷 간 AJC 상태 유지
        // rx_seq_와 harq 누적은 패킷 성공/실패에 따라 자동 관리됨
        g_cb_decoded = false; g_cb_harq_k = 0;
        feed_one_round(max_harq);
        // 결과는 무시 — AJC 수렴이 목적
    }

    // ── 측정: 수렴된 AJC 상태에서 성공률 집계 ──
    int pass = 0, ksum = 0, kmax = 0;
    for (int t = 0; t < trials; ++t) {
        const uint32_t ts = seed_base ^
            static_cast<uint32_t>(N_WARMUP + t);
        if (!build_chips(ts, amp)) continue;
        precompute_jammed(ja);

        g_cb_decoded = false; g_cb_harq_k = 0;
        feed_one_round(max_harq);

        if (g_cb_decoded) {
            pass++; ksum += g_cb_harq_k;
            if (g_cb_harq_k > kmax) kmax = g_cb_harq_k;
        }
    }

    const double avg = pass > 0
        ? static_cast<double>(ksum) / pass : 0.0;
    return { 100.0 * pass / trials, avg, kmax };
}

static void div(const char* t) {
    std::cout << "\n" << std::string(78, '=') << "\n  " << t
        << "\n" << std::string(78, '=') << "\n";
}

int main() {
    const auto T0 = std::chrono::high_resolution_clock::now();

    // 전역 Dispatcher 초기 생성
    g_tx = new (g_tx_buf) HTS_V400_Dispatcher();
    g_rx = new (g_rx_buf) HTS_V400_Dispatcher();
    g_rx->Set_Packet_Callback(rx_packet_cb);

    std::cout << std::string(78, '=') << "\n";
    std::cout << "  HTS CW 소거기 E2E 효과 측정 Rev.7 — AJC 워밍업\n";
    std::cout << "  워밍업 " << N_WARMUP << "패킷 → AJC 수렴 후 측정\n";
    std::cout << "  핵심 구간(17~19dB) 20회 / 나머지 10회\n";
    std::cout << std::string(78, '=') << "\n";

    static constexpr int16_t  AMP = 300;
    static constexpr uint32_t SEED = 0x12345678u;

    // ================================================================
    //  Phase 1: 무간섭 동작 확인
    //  워밍업 구조에서도 파이프라인이 정상인지 확인합니다.
    // ================================================================
    div("Phase 1: 무간섭 동작 확인 (AJC ON + 워밍업)");
    std::cout << "  모드       |  ON   |  OFF  | 판정\n";
    std::cout << "  " << std::string(40, '-') << "\n";
    {
        auto r_on = run_e2e_warmed(SEED, AMP, -100.0, 1, true, 20);
        auto r_off = run_e2e_warmed(SEED, AMP, -100.0, 1, false, 20);
        std::printf("  무간섭 K=1 | %5.1f%% | %5.1f%% | %s\n",
            r_on.pct, r_off.pct,
            (r_on.pct >= 90.0 && r_off.pct >= 90.0)
            ? "OK (파이프라인 정상)" : "FAIL");
    }

    // ================================================================
    //  Phase 2: CW 13~20dB — 소거기 ON vs OFF (K=1, BPS=3)
    //
    //  각 dB 구간마다:
    //   1) g_rx 완전 재생성
    //   2) 워밍업 10패킷으로 AJC 수렴
    //   3) 수렴 후 측정 시작
    //
    //  핵심 질문: 17~19dB에서 ON이 OFF보다 높은가?
    //   YES → cw_cancel_64_()가 AJC 수렴 품질을 개선
    //   NO  → AJC 단독으로 이미 충분히 처리
    // ================================================================
    div("Phase 2: CW 13~20dB — 소거기 ON vs OFF (K=1, AJC+워밍업)");
    std::cout << "  dB  | 시료 |  ON K=1 |  OFF K=1 | 개선     | 판정\n";
    std::cout << "  " << std::string(62, '-') << "\n";

    for (int db = 13; db <= 20; ++db) {
        const int trials = (db >= 17 && db <= 19) ? 20 : 10;
        auto r_on = run_e2e_warmed(SEED, AMP, db, 1, true, trials);
        auto r_off = run_e2e_warmed(SEED, AMP, db, 1, false, trials);
        const double delta = r_on.pct - r_off.pct;
        const char* verdict =
            (db >= 17 && db <= 19)
            ? (delta >= 30.0 ? "★ 소거기 효과!" :
                delta >= 10.0 ? "△ 부분 개선" :
                delta > 0.0 ? "▲ 미약 개선" : "✗ 효과 미미")
            : (r_on.pct >= 80.0 ? "OK" : "참고");
        std::printf("  %2ddB | %4d | %6.1f%% | %6.1f%%   | %+6.1f%% | %s\n",
            db, trials, r_on.pct, r_off.pct, delta, verdict);
    }

    // ================================================================
    //  Phase 3: CW K=1~2 — 소거기 ON 기준 HARQ 기여
    //
    //  워밍업 완료 후 K=2까지 HARQ가 추가로 기여하는지 확인합니다.
    //  이상적 AJC 참조값(100%)과의 격차가 얼마인지가 핵심입니다.
    // ================================================================
    div("Phase 3: CW K=1~2 — 소거기 ON + 워밍업 (AJC ON)");
    std::cout << "  dB  | 시료 |   K=1  |   K=2  | 이상AJC\n";
    std::cout << "  " << std::string(50, '-') << "\n";

    static const double k_ideal[] = {
        100.0, 100.0, 100.0, 100.0, 100.0, 100.0
    };
    for (int db = 15; db <= 20; ++db) {
        const int trials = (db >= 17 && db <= 19) ? 20 : 10;
        auto r1 = run_e2e_warmed(SEED, AMP, db, 1, true, trials);
        auto r2 = run_e2e_warmed(SEED, AMP, db, 2, true, trials);
        std::printf("  %2ddB | %4d | %5.1f%% | %5.1f%% | %5.1f%%\n",
            db, trials, r1.pct, r2.pct, k_ideal[db - 15]);
    }

    // ================================================================
    //  Phase 4: 소거기 퇴행 없음 확인
    //  워밍업 후에도 무간섭/저간섭에서 ON ≈ OFF 인지 확인합니다.
    // ================================================================
    div("Phase 4: 소거기 퇴행 없음 확인 (AJC ON + 워밍업)");
    std::cout << "  조건       |  ON  |  OFF | 차이  | 판정\n";
    std::cout << "  " << std::string(48, '-') << "\n";

    for (double db : {-100.0, 10.0}) {
        auto r_on = run_e2e_warmed(SEED, AMP, db, 1, true, 20);
        auto r_off = run_e2e_warmed(SEED, AMP, db, 1, false, 20);
        const double delta = std::abs(r_on.pct - r_off.pct);
        const char* label = (db < 0.0) ? "무간섭   " : "CW 10dB  ";
        std::printf("  %s | %5.1f%% | %5.1f%% | %4.1f%% | %s\n",
            label, r_on.pct, r_off.pct, delta,
            delta < 15.0 ? "OK (퇴행 없음)" : "주의 필요");
    }

    // 소멸자 명시 호출
    if (g_rx) { g_rx->~HTS_V400_Dispatcher(); g_rx = nullptr; }
    if (g_tx) { g_tx->~HTS_V400_Dispatcher(); g_tx = nullptr; }

    div("종합 해석 가이드");
    std::cout << "  Phase 2 — 17~19dB ON >> OFF  : 소거기가 AJC 수렴 품질 향상 ✓\n";
    std::cout << "  Phase 2 — 17~19dB ON ≈ OFF   : AJC 단독으로 충분히 처리\n";
    std::cout << "                                  → 소거기 추가 가치 없음\n";
    std::cout << "  Phase 3 — K=2 ≈ 100%          : 소거기+AJC 조합 이론 상한 ✓\n";
    std::cout << "  Phase 4 — |ON-OFF| < 15%       : 정상 환경 소거기 무해 ✓\n";
    std::cout << "\n  [시료 수 주의] 20회 기준 ±22% 오차\n";
    std::cout << "  방향성 확인 후 확정 수치는 trials=100으로 재측정하세요.\n";

    const auto T1 = std::chrono::high_resolution_clock::now();
    const double ms =
        std::chrono::duration<double, std::milli>(T1 - T0).count();
    div("실행 시간");
    std::printf("  Total: %.1fms (%.1fs)\n", ms, ms / 1000.0);
    std::cout << std::string(78, '=') << "\n";
    return 0;
}