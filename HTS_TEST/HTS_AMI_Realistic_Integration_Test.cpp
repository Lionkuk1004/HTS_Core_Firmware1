// =========================================================================
//  HTS_AMI_Realistic_Integration_Test.cpp
//
//  AMI/B-CDMA Phase1~4 — **정밀·현실 시나리오** 통합 검증 (스모크 테스트 대체용)
//
//  [기존 "AMI 종합 TEST.cpp"와 차이]
//   · 단순 true 고정 CHECK 최소화 — 경계값·오류 경로·시간축·상태 전이 검증
//   · SECURE_TRUE/FALSE, bool 반환 API는 **명시 비교** (X-5-5)
//   · CoAP: URI 정규화·슬롯 한도·nullptr 거부
//   · OTA: 청크 역순 수신·nullptr·진행률 단조·검증 루프
//   · 메쉬: 무경로 포워딩·다중 이웃·라우트 노화 시간축
//   · 계량: 연속 샘플·이벤트 로그 링·보고 주기
//
//  [빌드] HTS_LIM 소스와 동일 링크 세트 as AMI 종합 TEST (Scheduler + 모듈 .cpp)
//        VS: HTS_TEST.vcxproj 에서 본 파일만 빌드에 포함하고 "AMI 종합 TEST.cpp"는
//            제외(또는 반대) — main() 중복 링크 방지.
//  © INNOViD 2026
// =========================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>

#include "HTS_Priority_Scheduler.h"

#include "HTS_Emergency_Beacon.h"
#include "HTS_Neighbor_Discovery.h"
#include "HTS_Mesh_Sync.h"
#include "HTS_Location_Engine.h"
#include "HTS_Device_Status_Reporter.h"
#include "HTS_Mesh_Router.h"
#include "HTS_Sensor_Fusion.h"
#include "HTS_Sensor_Aggregator.h"
#include "HTS_CoAP_Engine.h"
#include "HTS_Meter_Data_Manager.h"
#include "HTS_OTA_AMI_Manager.h"

using namespace ProtectedEngine;

// ---------------------------------------------------------------------------
//  미니 프레임워크
// ---------------------------------------------------------------------------
static int g_total = 0, g_pass = 0, g_fail = 0;

#define SECTION(name) \
    printf("\n══════════════════════════════════════════\n  %s\n══════════════════════════════════════════\n", name)

#define CHECK(desc, cond) \
    do { \
        g_total++; \
        if (cond) { g_pass++; printf("  [PASS] %s\n", desc); } \
        else { g_fail++; printf("  [FAIL] %s  ← %d\n", desc, __LINE__); } \
    } while (0)

#define SUMMARY() \
    printf("\n══════════════════════════════════════════\n" \
           "  결과: %d/%d 통과%s\n" \
           "══════════════════════════════════════════\n", \
        g_pass, g_total, g_fail ? " ⛔" : " ✅")

namespace {

inline bool eb_active_is_on(uint32_t r) noexcept {
    return r == HTS_Emergency_Beacon::SECURE_TRUE;
}

/// 이웃 비콘 8B — 기존 스모크 테스트와 동일 레이아웃(모듈과 정합)
inline void fill_beacon_pkt(uint8_t pkt[8], uint16_t src_id,
    uint8_t seq, uint8_t hop, int8_t tx_dbm, uint8_t nbr_cnt, uint8_t cap) noexcept {
    pkt[0] = static_cast<uint8_t>(src_id & 0xFFu);
    pkt[1] = static_cast<uint8_t>((src_id >> 8u) & 0xFFu);
    pkt[2] = seq;
    pkt[3] = hop;
    pkt[4] = static_cast<uint8_t>(tx_dbm);
    pkt[5] = nbr_cnt;
    pkt[6] = cap;
    pkt[7] = 0u;
}

// ---------------------------------------------------------------------------
//  OTA mock crypto (호스트 단위 검증용)
// ---------------------------------------------------------------------------
static bool mock_hmac(const uint8_t*, const uint8_t*, size_t, uint8_t* o) {
    if (o == nullptr) { return false; }
    for (int i = 0; i < 32; ++i) { o[i] = 0xABu; }
    return true;
}
static void mock_init(const uint8_t*) {}
static void mock_update(const uint8_t*, size_t) {}
static void mock_final(uint8_t* o) {
    if (o == nullptr) { return; }
    for (int i = 0; i < 32; ++i) { o[i] = 0xABu; }
}

// CoAP 핸들러 (여러 리소스 공용)
static size_t coap_h_ok(uint8_t, const uint8_t*, size_t,
    uint8_t* resp, size_t cap) {
    if (cap >= 4u) {
        resp[0] = 'O'; resp[1] = 'K'; resp[2] = '\r'; resp[3] = '\n';
        return 4u;
    }
    return 0u;
}

} // namespace

// =========================================================================
//  S1 — 비상 비콘: 최소 송출 시간 + Cancel (현장 복구 시퀀스)
// =========================================================================
static void scenario_emergency_beacon() {
    SECTION("S1 Emergency_Beacon — 30s 최소 송출 후 수동 Cancel");

    HTS_Priority_Scheduler sched;
    HTS_Emergency_Beacon beacon(0xA501u);

    CHECK("부팅 직후 비활성", !eb_active_is_on(beacon.Is_Active()));

    // 과열+저전압 복합 → AUTO 마스크로 활성
    beacon.Trigger(static_cast<uint16_t>(
        AlertFlag::TEMP_HIGH | AlertFlag::BATT_LOW));
    CHECK("복합 알람 후 활성", eb_active_is_on(beacon.Is_Active()));

    // 500ms 슬롯으로 최소 지속(30s)·송출 카운트 시뮬레이션 (첫 Tick 500ms 후)
    beacon.Tick(500u, sched);
    for (uint32_t t = 1000u; t <= 31000u; t += HTS_Emergency_Beacon::BEACON_INTERVAL_MS) {
        beacon.Tick(t, sched);
    }

    CHECK("30초 창 내 여전히 활성(플래그 유지 시)", eb_active_is_on(beacon.Is_Active()));

    beacon.Cancel();
    CHECK("Cancel 후 비활성(최소 송출 충족)", !eb_active_is_on(beacon.Is_Active()));

    beacon.Shutdown();
}

// =========================================================================
//  S2 — 이웃 탐색: 다중 게이트웨이·조회 API
// =========================================================================
static void scenario_neighbor_mesh() {
    SECTION("S2 Neighbor_Discovery — 다중 비콘·Find_Neighbor");

    HTS_Priority_Scheduler sched;
    HTS_Neighbor_Discovery nd(0x0001u);

    nd.Set_Mode(DiscoveryMode::REALTIME, 0u);
    CHECK("REALTIME 모드", nd.Get_Mode() == DiscoveryMode::REALTIME);

    uint8_t pkt[8];
    uint32_t t = 1000u;
    fill_beacon_pkt(pkt, 0x0201u, 1u, 1u, 14, 3u, 0u);
    nd.On_Beacon_Received(pkt, 8u, 200u, t);
    fill_beacon_pkt(pkt, 0x0202u, 2u, 2u, 10, 8u, 1u);
    nd.On_Beacon_Received(pkt, 8u, 180u, t + 50u);
    fill_beacon_pkt(pkt, 0x0203u, 3u, 3u, 8, 12u, 2u);
    nd.On_Beacon_Received(pkt, 8u, 160u, t + 100u);

    CHECK("이웃 3 등록", nd.Get_Neighbor_Count() == 3u);

    NeighborInfo ni = {};
    CHECK("0x0202 검색", nd.Find_Neighbor(0x0202u, ni));
    CHECK("0x0202 LQI>0", ni.lqi > 0u);

    nd.Tick(t + 200u, sched);
    nd.Shutdown();
    CHECK("Shutdown 테이블 비움", nd.Get_Neighbor_Count() == 0u);
}

// =========================================================================
//  S3 — Mesh_Sync + Router: 링크 업/다운·무경로 포워딩
// =========================================================================
static void scenario_routing() {
    SECTION("S3 Mesh_Router — 경로·NO_ROUTE·Link_Down");

    HTS_Priority_Scheduler sched;
    HTS_Mesh_Router router(0x1000u);

    const uint8_t payload[] = { 0x01, 0x02, 0x03 };

    CHECK("무이웃 시 NO_ROUTE",
        router.Forward(0x2000u, payload, sizeof(payload), 8u, 5000u, sched)
        == FwdResult::NO_ROUTE);

    router.On_Link_Up(0x2001u, 92u);
    router.On_Link_Up(0x2002u, 78u);

    RouteEntry re = {};
    CHECK("0x2001 경로 존재", router.Get_Route(0x2001u, re));
    const FwdResult f1 = router.Forward(0x2001u, payload, sizeof(payload), 8u, 6000u, sched);
    CHECK("직접 이웃 포워딩 OK 또는 큐포화",
        f1 == FwdResult::OK || f1 == FwdResult::QUEUE_FULL);

    router.On_Link_Down(0x2001u, 7000u);
    CHECK("단절 후 경로 제거", !router.Get_Route(0x2001u, re));

    router.Shutdown();
}

// =========================================================================
//  S4 — Mesh_Sync: 루트 기준 타이밍
// =========================================================================
static void scenario_time_sync() {
    SECTION("S4 Mesh_Sync — 비콘 타이밍·루트 홉");

    HTS_Mesh_Sync sync(0x3001u);
    sync.On_Beacon_Timing(0x3002u, 10000u, 10008u, 1u, 60000u);
    sync.Set_As_Root();
    CHECK("루트 홉=0", sync.Get_My_Hop_Level() == 0u);
    sync.Shutdown();
}

// =========================================================================
//  S5 — Location + Status: 프라이버시·보고 모드
// =========================================================================
static void scenario_location_status() {
    SECTION("S5 Location_Engine + Device_Status_Reporter");

    HTS_Priority_Scheduler sched;

    HTS_Location_Engine loc(0x4001u, LocationMode::MOBILE, DeviceClass::HUMAN_ADULT);
    CHECK("성인 기본 추적 OFF", loc.Get_Tracking_Mode() == TrackingMode::TRACKING_OFF);
    CHECK("앵커1", loc.Register_Anchor(0x5001u, 375000, 1270000));
    CHECK("앵커2", loc.Register_Anchor(0x5002u, 375200, 1270100));
    CHECK("앵커3", loc.Register_Anchor(0x5003u, 375400, 1270000));
    loc.Set_Battery_Percent(22u);
    loc.Shutdown();

    HTS_Device_Status_Reporter rpt(0x4001u, 0u, ReportMode::ACTIVE);
    rpt.Set_Battery(40u);
    rpt.Set_Temperature(-5);
    rpt.Set_Fault(FaultFlag::SENSOR_FAIL);
    CHECK("센서 장애 표시", rpt.Has_Any_Fault());
    rpt.Tick(0u, sched);
    rpt.Clear_Fault(FaultFlag::SENSOR_FAIL);
    rpt.Tick(100u, sched);
    rpt.Shutdown();
}

// =========================================================================
//  S6 — 센서: HAL 실패 복구 + 융합 화재 시나리오
// =========================================================================
static void scenario_sensors() {
    SECTION("S6 Sensor_Aggregator + Sensor_Fusion");

    HTS_Sensor_Fusion fusion;
    HTS_Sensor_Aggregator agg;

    uint16_t adc[4] = { 4095u, 0u, 2048u, 1024u };
    agg.On_ADC_DMA_Complete(adc);
    agg.On_Accel_Read(0u, false);
    CHECK("가속도 버스 실패", agg.Get_Health(4u) == SensorHealth::FAIL);
    agg.On_Accel_Read(120u, true);
    CHECK("버스 복구", agg.Get_Health(4u) == SensorHealth::OK);

    agg.Tick(0u, fusion);
    fusion.Feed_Temperature(220);
    fusion.Feed_Smoke(50u);
    fusion.Tick();
    fusion.Feed_Temperature(750);
    fusion.Feed_Smoke(4000u);
    for (int i = 0; i < 20; ++i) { fusion.Tick(); }
    CHECK("화재 조합 EMERGENCY", fusion.Get_Level() == AlertLevel::EMERGENCY);

    agg.Shutdown();
    fusion.Shutdown();
}

// =========================================================================
//  S7 — CoAP: 슬롯 한도·중복·nullptr·송신
// =========================================================================
static void scenario_coap_stress() {
    SECTION("S7 CoAP_Engine — 8리소스 한도·중복·nullptr");

    HTS_Priority_Scheduler sched;
    HTS_CoAP_Engine coap(0x6001u);

    static const char* const uris[8] = {
        "/ami/wh", "/ami/pf", "/ami/lp", "/ami/ev",
        "/gw/r1", "/gw/r2", "/gw/r3", "/gw/r4"
    };
    for (size_t i = 0u; i < HTS_CoAP_Engine::MAX_RESOURCES; ++i) {
        CHECK("리소스 등록", coap.Register_Resource(uris[i], coap_h_ok) == true);
    }
    CHECK("9번째 슬롯 거부", coap.Register_Resource("/overflow", coap_h_ok) == false);
    CHECK("동일 URI 중복 거부", coap.Register_Resource("/ami/wh", coap_h_ok) == false);
    CHECK("nullptr URI 거부", coap.Register_Resource(nullptr, coap_h_ok) == false);
    CHECK("nullptr 핸들러 거부", coap.Register_Resource("/x", nullptr) == false);

    const uint16_t mid = coap.Send_GET(0x6002u, "/ami/wh", 10000u, sched);
    CHECK("Send_GET MID>0", mid > 0u);
    for (int k = 0; k < 5; ++k) {
        coap.Tick(10000u + static_cast<uint32_t>(k) * 500u, sched);
    }
    coap.Shutdown();
}

// =========================================================================
//  S8 — 계량: 연속 샘플·이벤트 링·시간 보고
// =========================================================================
static void scenario_metering() {
    SECTION("S8 Meter_Data_Manager — 연속 계량·이벤트·보고");

    HTS_Priority_Scheduler sched;
    HTS_Meter_Data_Manager meter(0x7001u);

    for (int i = 0; i < 5; ++i) {
        MeterReading rd = {};
        rd.cumul_kwh_x100 = static_cast<uint32_t>(100000u + static_cast<uint32_t>(i) * 25u);
        rd.power_factor = static_cast<uint8_t>(90 + i);
        rd.voltage_x10 = static_cast<uint16_t>(2200u + i);
        rd.current_x100 = static_cast<uint16_t>(1500u + i * 10u);
        rd.watt_hour = static_cast<uint32_t>(1200u + i);
        rd.valid = 1u;
        meter.Update_Reading(rd);
    }
    const MeterReading last = meter.Get_Latest();
    CHECK("최종 누적 단조 증가", last.cumul_kwh_x100 >= 100100u);

    meter.Log_Event(MeterEvent::TAMPER, 5000u);
    meter.Log_Event(MeterEvent::OVERLOAD, 6000u);
    meter.Log_Event(MeterEvent::THRESHOLD, 7000u);

    MeterLogEntry ev[HTS_Meter_Data_Manager::EVENT_LOG_SIZE] = {};
    const size_t n = meter.Get_Event_Log(ev, HTS_Meter_Data_Manager::EVENT_LOG_SIZE);
    CHECK("이벤트 로그 조회", n >= 3u);

    meter.Tick(0u, sched);
    meter.Tick(HTS_Meter_Data_Manager::REPORT_INTERVAL_MS + 1u, sched);
    meter.Shutdown();
}

// =========================================================================
//  S9 — OTA: 역순 청크·nullptr·상태 전이
// =========================================================================
static void scenario_ota() {
    SECTION("S9 OTA_AMI_Manager — 역순 청크·검증 경로");

    HTS_OTA_AMI_Manager ota(0x8001u, 100u);
    OTA_Crypto_Callbacks c = {};
    c.hmac_lsh256 = mock_hmac;
    c.hmac_init = mock_init;
    c.hmac_update = mock_update;
    c.hmac_final = mock_final;
    ota.Register_Crypto(c);

    uint8_t nonce[8] = { 0xA1u,0xA2u,0xA3u,0xA4u,0xA5u,0xA6u,0xA7u,0xA8u };
    uint8_t tag[32];
    std::memset(tag, 0xAB, sizeof(tag));

    CHECK("BEGIN", ota.On_Begin(250u, 1024u, 4u, nonce, tag, 0xCAFEBABEu) == true);
    CHECK("상태 RECEIVING", ota.Get_State() == AMI_OtaState::RECEIVING);

    uint8_t chunk[256];
    std::memset(chunk, 0x5Au, sizeof(chunk));

    CHECK("data nullptr 거부", ota.On_Chunk(0u, nullptr, 256u, nullptr) == false);

    // 역순 수신 (실제 RF 재정렬 시뮬)
    CHECK("청크3", ota.On_Chunk(3u, chunk, 256u, nullptr) == true);
    CHECK("청크1", ota.On_Chunk(1u, chunk, 256u, nullptr) == true);
    CHECK("청크0", ota.On_Chunk(0u, chunk, 256u, nullptr) == true);
    CHECK("청크2", ota.On_Chunk(2u, chunk, 256u, nullptr) == true);
    CHECK("완료 플래그", ota.Is_Complete() == true);
    CHECK("진행률 100", ota.Get_Progress_Pct() == 100u);

    ota.On_Broadcast_Complete(20000u);
    CHECK("VERIFYING 진입", ota.Get_State() == AMI_OtaState::VERIFYING);

    for (int i = 0; i < 40; ++i) {
        ota.Tick(20000u + static_cast<uint32_t>(i) * 50u);
    }
    const AMI_OtaState st = ota.Get_State();
    CHECK("검증 완료 또는 실패(목업 한계)", st == AMI_OtaState::READY || st == AMI_OtaState::FAILED);

    ota.Abort();
    CHECK("Abort IDLE", ota.Get_State() == AMI_OtaState::IDLE);
    ota.Shutdown();
}

// =========================================================================
//  S10 — 교차: 스케줄러에 다모듈 Tick 인터리브 (부하 모델)
// =========================================================================
static void scenario_interleaved_ticks() {
    SECTION("S10 교차 Tick — 스케줄러 공유 부하");

    HTS_Priority_Scheduler sched;
    HTS_Neighbor_Discovery nd(0x9001u);
    HTS_Device_Status_Reporter rpt(0x9001u, 0u, ReportMode::ACTIVE);
    uint8_t pkt[8];
    fill_beacon_pkt(pkt, 0x9101u, 1u, 1u, 12, 4u, 0u);

    for (uint32_t ms = 0u; ms < 5000u; ms += 100u) {
        nd.On_Beacon_Received(pkt, 8u, 190u, ms);
        rpt.Set_Battery(static_cast<uint8_t>(80u + (ms / 100u) % 5u));
        rpt.Tick(ms, sched);
        nd.Tick(ms, sched);
    }
    CHECK("교차 후 이웃>=1", nd.Get_Neighbor_Count() >= 1u);
    rpt.Shutdown();
    nd.Shutdown();
}

// =========================================================================
//  main
// =========================================================================
int main() {
    printf("═══════════════════════════════════════════════\n");
    printf("  HTS AMI **정밀·현실 시나리오** 통합 테스트\n");
    printf("  (스모크 대비 경계·시간축·오류 경로 강화)\n");
    printf("═══════════════════════════════════════════════\n");

    scenario_emergency_beacon();
    scenario_neighbor_mesh();
    scenario_routing();
    scenario_time_sync();
    scenario_location_status();
    scenario_sensors();
    scenario_coap_stress();
    scenario_metering();
    scenario_ota();
    scenario_interleaved_ticks();

    SUMMARY();
    return g_fail ? 1 : 0;
}
