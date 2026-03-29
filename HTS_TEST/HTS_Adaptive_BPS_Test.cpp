// =========================================================================
// HTS_Adaptive_BPS_Test.cpp
// 적응형 BPS 컨트롤러 단위 테스트
// Target: PC 전용 (ARM 빌드 제외)
//
// 테스트 항목:
//  T-01: 부팅 직후 BPS = BPS_MIN(3) 확인
//  T-02: QUIET 8프레임 연속 → BPS 3→4 상향
//  T-03: QUIET 16프레임 → BPS 4→5 상향
//  T-04: HEAVY 발생 → BPS 즉시 3 복귀
//  T-05: HOLD 구간 진입 → quiet_count 리셋, BPS 유지
//  T-06: QUIET 도중 HEAVY 1회 → count 리셋, BPS 즉시 3
//  T-07: BPS 최대값(6) 초과 시도 → BPS 6 유지 (클램핑)
//  T-08: Reset() 호출 → BPS_MIN, count=0
// =========================================================================
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#error "[HTS_FATAL] Adaptive BPS 테스트는 PC 전용입니다."
#endif

#include "HTS_Adaptive_BPS_Controller.h"
#include <cstdio>

using namespace ProtectedEngine;

static void feed_quiet(HTS_RF_Metrics& m,
    HTS_Adaptive_BPS_Controller& ctrl, int n) {
    m.ajc_nf.store(100u, std::memory_order_relaxed);
    m.snr_proxy.store(15, std::memory_order_relaxed);
    for (int i = 0; i < n; ++i) { ctrl.Update(); }
}
static void feed_heavy(HTS_RF_Metrics& m,
    HTS_Adaptive_BPS_Controller& ctrl) {
    m.ajc_nf.store(3000u, std::memory_order_relaxed);
    m.snr_proxy.store(2, std::memory_order_relaxed);
    ctrl.Update();
}
static void feed_hold(HTS_RF_Metrics& m,
    HTS_Adaptive_BPS_Controller& ctrl, int n) {
    m.ajc_nf.store(1000u, std::memory_order_relaxed);
    m.snr_proxy.store(7, std::memory_order_relaxed);
    for (int i = 0; i < n; ++i) { ctrl.Update(); }
}

int main() {
    std::printf("[HTS_Adaptive_BPS_Controller] 단위 테스트\n\n");
    int pass = 0, fail = 0;

#define CHECK(label, cond) \
    do { if (cond) { std::printf("  PASS  %s\n", label); ++pass; } \
         else      { std::printf("  FAIL  %s\n", label); ++fail; } \
    } while (false)

    // T-01
    {
        HTS_RF_Metrics m; HTS_Adaptive_BPS_Controller c(m);
        CHECK("T-01: 부팅 직후 BPS=3", m.current_bps.load() == 3u);
    }

    // T-02
    {
        HTS_RF_Metrics m; HTS_Adaptive_BPS_Controller c(m);
        feed_quiet(m, c, 7);
        CHECK("T-02a: 7프레임 BPS 아직 3", m.current_bps.load() == 3u);
        feed_quiet(m, c, 1);
        CHECK("T-02b: 8프레임 BPS→4", m.current_bps.load() == 4u);
        CHECK("T-02c: count 리셋=0", c.Get_Quiet_Count() == 0u);
    }

    // T-03
    {
        HTS_RF_Metrics m; HTS_Adaptive_BPS_Controller c(m);
        feed_quiet(m, c, 8); feed_quiet(m, c, 8);
        CHECK("T-03: 16프레임 BPS→5", m.current_bps.load() == 5u);
    }

    // T-04
    {
        HTS_RF_Metrics m; HTS_Adaptive_BPS_Controller c(m);
        feed_quiet(m, c, 8); feed_heavy(m, c);
        CHECK("T-04a: HEAVY → BPS=3", m.current_bps.load() == 3u);
        CHECK("T-04b: HEAVY count=0", c.Get_Quiet_Count() == 0u);
    }

    // T-05
    {
        HTS_RF_Metrics m; HTS_Adaptive_BPS_Controller c(m);
        feed_quiet(m, c, 8); feed_quiet(m, c, 4); feed_hold(m, c, 3);
        CHECK("T-05a: HOLD 후 count=0", c.Get_Quiet_Count() == 0u);
        CHECK("T-05b: HOLD 후 BPS=4", m.current_bps.load() == 4u);
    }

    // T-06
    {
        HTS_RF_Metrics m; HTS_Adaptive_BPS_Controller c(m);
        feed_quiet(m, c, 5); feed_heavy(m, c); feed_quiet(m, c, 8);
        CHECK("T-06: HEAVY 후 재상향 BPS=4", m.current_bps.load() == 4u);
    }

    // T-07
    {
        HTS_RF_Metrics m; HTS_Adaptive_BPS_Controller c(m);
        feed_quiet(m, c, 24);
        CHECK("T-07a: BPS 최대=6", m.current_bps.load() == 6u);
        feed_quiet(m, c, 8);
        CHECK("T-07b: 6 초과 없음", m.current_bps.load() == 6u);
    }

    // T-08
    {
        HTS_RF_Metrics m; HTS_Adaptive_BPS_Controller c(m);
        feed_quiet(m, c, 16); c.Reset();
        CHECK("T-08a: Reset BPS=3", m.current_bps.load() == 3u);
        CHECK("T-08b: Reset count=0", c.Get_Quiet_Count() == 0u);
    }

#undef CHECK

    std::printf("\n결과: %d/%d PASS\n", pass, pass + fail);
    std::printf(fail == 0 ? "✅ 전체 통과\n" : "❌ %d건 실패\n", fail);
    return (fail == 0) ? 0 : 1;
}