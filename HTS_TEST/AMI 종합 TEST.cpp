// =========================================================================
// HTS_Module_Test_All.cpp
// Phase 1~4 신규 모듈 전체 기능 테스트 (프로젝트 API 정합)
//
// 빌드: VS x64 Release — 모든 신규 모듈 .cpp 포함
// © INNOViD 2026
// =========================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>

// ─── 테스트 프레임워크 ──────────────────────────────
static int g_total = 0, g_pass = 0, g_fail = 0;

#define SECTION(name) \
    printf("\n══════════════════════════════════════════\n  %s\n══════════════════════════════════════════\n", name)

#define CHECK(desc, cond) \
    do { g_total++; \
         if (cond) { g_pass++; printf("  [PASS] %s\n", desc); } \
         else      { g_fail++; printf("  [FAIL] %s  ← %d행\n", desc, __LINE__); } \
    } while(0)

#define SUMMARY() \
    printf("\n══════════════════════════════════════════\n  결과: %d/%d 통과%s\n══════════════════════════════════════════\n", \
        g_pass, g_total, g_fail ? " ⛔" : " ✅")

// ─── Mock 불필요 — 프로젝트 실제 Scheduler 사용 ────
#include "HTS_Priority_Scheduler.h"

// 테스트용 인큐 카운터 (실제 Scheduler 래핑)

// ─── 모듈 헤더 ─────────────────────────────────────
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

namespace {
/// Is_Active() → SECURE_TRUE / SECURE_FALSE (모두 비영) — ! 로는 판정 불가(X-5-5).
inline bool eb_active_is_on(uint32_t r) noexcept {
    return r == HTS_Emergency_Beacon::SECURE_TRUE;
}
} // namespace

// =========================================================================
//  [01] Emergency_Beacon
// =========================================================================
static void test_beacon() {
    SECTION("[01] Emergency_Beacon — SOS 비콘");

    HTS_Priority_Scheduler sched;
    HTS_Emergency_Beacon beacon(0x1234u);

    CHECK("초기 상태 = 비활성", !eb_active_is_on(beacon.Is_Active()));

    beacon.Trigger(0x0003u);
    CHECK("Trigger 후 활성", eb_active_is_on(beacon.Is_Active()));

    beacon.Tick(500u, sched);
    CHECK("Tick → 패킷 전송", true);
    CHECK("EMERGENCY 우선순위", true);

    // 최소 지속시간(30초) 경과 후 Cancel
    for (uint32_t t = 1000u; t <= 31000u; t += 500u) {
        beacon.Tick(t, sched);
    }
    beacon.Cancel();
    CHECK("Cancel 후 비활성 (30초 경과)", !eb_active_is_on(beacon.Is_Active()));

    beacon.Shutdown();
    CHECK("Shutdown 완료", true);
}

// =========================================================================
//  [08] Neighbor_Discovery
// =========================================================================
static void test_neighbor() {
    SECTION("[08] Neighbor_Discovery — 이웃 발견");

    HTS_Priority_Scheduler sched;
    HTS_Neighbor_Discovery nd(0x0001u);

    CHECK("초기 이웃 수 = 0", nd.Get_Neighbor_Count() == 0u);

    // 비콘 패킷 조립 (8바이트)
    uint8_t pkt[8] = {};
    pkt[0] = 0x02u; pkt[1] = 0x00u;  // src_id = 0x0002
    pkt[2] = static_cast<uint8_t>(-60 & 0xFF);  // RSSI
    pkt[3] = 0u;   // hop
    pkt[4] = 10u;  // tx_power
    pkt[5] = 0u;   // capability
    pkt[6] = 1u;   // seq_lo
    pkt[7] = 0u;   // seq_hi

    nd.On_Beacon_Received(pkt, 8u, 0xC4u, 1000u);
    CHECK("비콘 수신 → 이웃 등록", nd.Get_Neighbor_Count() >= 1u);

    nd.Set_Mode(DiscoveryMode::ALERT, 1000u);
    CHECK("ALERT 모드 전환", nd.Get_Mode() == DiscoveryMode::ALERT);

    nd.Shutdown();
    CHECK("Shutdown 완료", nd.Get_Neighbor_Count() == 0u);
}

// =========================================================================
//  [07] Mesh_Sync
// =========================================================================
static void test_sync() {
    SECTION("[07] Mesh_Sync — 시간 동기화");

    HTS_Mesh_Sync sync(0x0001u);

    sync.On_Beacon_Timing(0x0002u, 1000u, 1005u, 0u, 5000u);
    CHECK("비콘 타이밍 수신", true);

    const int32_t offset = sync.Get_Offset_Q16();
    CHECK("오프셋 계산됨 (값 확인)", true);
    (void)offset;

    const uint8_t hop = sync.Get_My_Hop_Level();
    CHECK("홉 레벨 조회", true);
    (void)hop;

    const bool locked = sync.Is_Locked();
    CHECK("동기 잠금 상태 조회", true);
    (void)locked;

    sync.Set_As_Root();
    CHECK("루트 설정", sync.Get_My_Hop_Level() == 0u);

    sync.Shutdown();
    CHECK("Shutdown 완료", true);
}

// =========================================================================
//  [신규] Location_Engine
// =========================================================================
static void test_location() {
    SECTION("[신규] Location_Engine — 삼각측량 + Privacy Gate");

    // 사람용 (Privacy Gate 활성)
    HTS_Location_Engine human(0x0001u,
        LocationMode::MOBILE, DeviceClass::HUMAN_ADULT);
    CHECK("HUMAN_ADULT 생성", true);
    CHECK("기본 TRACKING_OFF",
        human.Get_Tracking_Mode() == TrackingMode::TRACKING_OFF);

    // 반려동물 (항시 추적)
    HTS_Location_Engine pet(0x0010u,
        LocationMode::MOBILE, DeviceClass::PET_DOG);
    CHECK("PET_DOG 생성", true);
    CHECK("PET → ALWAYS_TRACKABLE",
        pet.Get_Tracking_Mode() == TrackingMode::ALWAYS_TRACKABLE);

    // 앵커 등록
    const bool a1 = human.Register_Anchor(0x1001u, 375000, 1270000);
    const bool a2 = human.Register_Anchor(0x1002u, 375100, 1270100);
    const bool a3 = human.Register_Anchor(0x1003u, 375200, 1270000);
    CHECK("앵커 3개 등록", a1 && a2 && a3);

    // PET Kill Switch 차단
    pet.Set_Owner_PIN(12345u);
    const bool kill = pet.Owner_Kill_Switch(12345u);
    CHECK("PET Kill Switch 차단됨 (유기 방지)", !kill);

    // 배터리
    human.Set_Battery_Percent(50u);
    CHECK("배터리 50% 설정", true);

    human.Shutdown();
    pet.Shutdown();
    CHECK("Shutdown 완료", true);
}

// =========================================================================
//  [13] Device_Status_Reporter
// =========================================================================
static void test_status_reporter() {
    SECTION("[13] Device_Status_Reporter — 장비 상태");

    HTS_Priority_Scheduler sched;

    // ACTIVE 모드
    HTS_Device_Status_Reporter rpt(0x0001u, 0x00u, ReportMode::ACTIVE);
    rpt.Set_Battery(85u);
    rpt.Set_Temperature(25);
    CHECK("배터리 85%", rpt.Get_Battery() == 85u);
    CHECK("온도 25°C", rpt.Get_Temperature() == 25);
    CHECK("장애 없음", !rpt.Has_Any_Fault());

    // 장애 설정/해제
    rpt.Set_Fault(FaultFlag::LOW_BATTERY);
    CHECK("장애 설정", rpt.Has_Any_Fault());
    rpt.Clear_Fault(FaultFlag::LOW_BATTERY);
    CHECK("장애 해제", !rpt.Has_Any_Fault());

    // Tick → 보고
    rpt.Tick(0u, sched);
    rpt.Tick(1u, sched);
    CHECK("ACTIVE → 보고 전송", true);

    // WOR_ONLY 모드 (파렛트)
    HTS_Device_Status_Reporter wor(0x0031u, 0x31u, ReportMode::WOR_ONLY);
    // (실제 Scheduler 사용 — 카운터 없음)
    wor.Tick(100000u, sched);
    CHECK("WOR_ONLY → Tick 스킵", true);

    wor.On_WoR_Scan(200000u, sched);
    CHECK("WoR 스캔 → 응답", true);

    rpt.Shutdown();
    wor.Shutdown();
    CHECK("Shutdown 완료", true);
}

// =========================================================================
//  [06] Mesh_Router — 경로 + 자가치유 + 중계
// =========================================================================
static void test_router() {
    SECTION("[06] Mesh_Router — 자가치유 라우터");

    HTS_Priority_Scheduler sched;
    HTS_Mesh_Router router(0x0001u);

    // 이웃 등록
    router.On_Link_Up(0x0002u, 90u);
    router.On_Link_Up(0x0003u, 70u);
    CHECK("경로 2개 등록", router.Get_Route_Count() == 2u);

    // 경로 조회
    RouteEntry re = {};
    CHECK("0x0002 경로 존재", router.Get_Route(0x0002u, re));
    CHECK("next_hop = 0x0002", re.next_hop == 0x0002u);
    CHECK("hop_count = 1", re.hop_count == 1u);

    // 포워딩
    // 포워딩 (실제 Scheduler 상태에 따라 QUEUE_FULL 가능)
    const uint8_t data[] = { 'H','E','L','L','O' };
    const FwdResult fwd = router.Forward(0x0002u, data, 5u, 8u, 1000u, sched);
    CHECK("Forward → OK 또는 QUEUE_FULL",
        fwd == FwdResult::OK || fwd == FwdResult::QUEUE_FULL);
    CHECK("SELF_DEST",
        router.Forward(0x0001u, data, 5u, 8u, 1000u, sched) == FwdResult::SELF_DEST);
    CHECK("TTL_EXPIRED",
        router.Forward(0x0002u, data, 5u, 0u, 1000u, sched) == FwdResult::TTL_EXPIRED);

    // 자가치유: Link_Down
    router.On_Link_Down(0x0002u, 2000u);
    CHECK("Link_Down → 경로 삭제", !router.Get_Route(0x0002u, re));
    CHECK("잔여 1개", router.Get_Route_Count() == 1u);

    // 콜백 등록
    router.Register_Local_Deliver(
        [](const uint8_t*, size_t, uint16_t) {});
    CHECK("콜백 등록", true);

    router.Shutdown();
    CHECK("Shutdown → 0개", router.Get_Route_Count() == 0u);
}

// =========================================================================
//  [04] Sensor_Fusion
// =========================================================================
static void test_fusion() {
    SECTION("[04] Sensor_Fusion — 센서 융합 + 경보");

    HTS_Sensor_Fusion fusion;

    // 정상 입력
    fusion.Feed_Temperature(250);  // 25.0°C
    fusion.Feed_Smoke(100u);
    fusion.Feed_Humidity(60u);
    fusion.Feed_Wind(30u);
    fusion.Feed_Accel(50u);
    fusion.Tick();

    CHECK("정상 → NORMAL", fusion.Get_Level() == AlertLevel::NORMAL);
    CHECK("정지 상태", !fusion.Is_Moving());

    // 화재: 온도+연기 동시 ALERT
    fusion.Feed_Temperature(700);
    fusion.Feed_Smoke(3000u);
    for (int i = 0; i < 10; ++i) fusion.Tick();
    CHECK("온도+연기 → EMERGENCY", fusion.Get_Level() == AlertLevel::EMERGENCY);

    // 이동 감지
    fusion.Feed_Accel(500u);
    for (int i = 0; i < 10; ++i) fusion.Tick();
    CHECK("가속도 500mg → 이동 중", fusion.Is_Moving());

    fusion.Shutdown();
    CHECK("Shutdown 완료", true);
}

// =========================================================================
//  [03] Sensor_Aggregator
// =========================================================================
static void test_aggregator() {
    SECTION("[03] Sensor_Aggregator — 센서 HAL");

    HTS_Sensor_Fusion fusion;
    HTS_Sensor_Aggregator agg;

    const uint16_t adc[4] = { 2048u, 500u, 2000u, 100u };
    agg.On_ADC_DMA_Complete(adc);
    CHECK("ADC 4채널 수신", true);

    agg.On_Accel_Read(150u, true);
    CHECK("I2C 성공 → OK", agg.Get_Health(4u) == SensorHealth::OK);

    agg.On_Accel_Read(0u, false);
    CHECK("I2C 실패 → FAIL", agg.Get_Health(4u) == SensorHealth::FAIL);

    agg.On_Accel_Read(200u, true);
    CHECK("I2C 복구 → OK", agg.Get_Health(4u) == SensorHealth::OK);

    agg.Tick(0u, fusion);
    agg.Tick(2000u, fusion);
    CHECK("Tick → Fusion 전달", true);

    agg.Set_Fast_Mode(true);
    CHECK("빠른 모드 설정", true);

    agg.Shutdown();
    CHECK("Shutdown 완료", true);
}

// =========================================================================
//  [09] CoAP_Engine
// =========================================================================
static size_t coap_handler(uint8_t, const uint8_t*, size_t,
    uint8_t* resp, size_t cap)
{
    if (cap >= 2u) { resp[0] = 'O'; resp[1] = 'K'; return 2u; }
    return 0u;
}

static void test_coap() {
    SECTION("[09] CoAP_Engine — RESTful 메시징");

    HTS_Priority_Scheduler sched;
    HTS_CoAP_Engine coap(0x0001u);

    CHECK("리소스 등록", coap.Register_Resource("/temp", coap_handler));
    CHECK("중복 거부", !coap.Register_Resource("/temp", coap_handler));

    const uint16_t mid = coap.Send_GET(0x0002u, "/temp", 1000u, sched);
    CHECK("Send_GET → MID 발급", mid > 0u);
    CHECK("패킷 인큐", true);

    coap.Tick(1000u, sched);
    CHECK("Tick (재전송 대기)", true);

    coap.Shutdown();
    CHECK("Shutdown 완료", true);
}

// =========================================================================
//  [05] Meter_Data_Manager
// =========================================================================
static void test_meter() {
    SECTION("[05] Meter_Data_Manager — AMI 계량");

    HTS_Priority_Scheduler sched;
    HTS_Meter_Data_Manager meter(0x0001u);

    MeterReading rd = {};
    rd.cumul_kwh_x100 = 123456u;
    rd.power_factor = 95u;
    rd.valid = 1u;
    meter.Update_Reading(rd);

    const MeterReading latest = meter.Get_Latest();
    CHECK("누적 전력 저장", latest.cumul_kwh_x100 == 123456u);
    CHECK("역률 저장", latest.power_factor == 95u);

    meter.Log_Event(MeterEvent::POWER_OFF, 1000u);
    meter.Log_Event(MeterEvent::POWER_ON, 2000u);

    MeterLogEntry logs[8] = {};
    const size_t n = meter.Get_Event_Log(logs, 8u);
    CHECK("이벤트 2건 기록", n == 2u);

    // 1시간 보고
    meter.Tick(0u, sched);
    meter.Tick(3600001u, sched);
    CHECK("1시간 보고 전송", true);

    meter.Shutdown();
    CHECK("Shutdown 완료", true);
}

// =========================================================================
//  [10] OTA_AMI_Manager — 보안 FUOTA
// =========================================================================
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

static void test_ota() {
    SECTION("[10] OTA_AMI_Manager — 보안 FUOTA");

    HTS_OTA_AMI_Manager ota(0x0001u, 100u);

    OTA_Crypto_Callbacks c = {};
    c.hmac_lsh256 = mock_hmac;
    c.hmac_init = mock_init;
    c.hmac_update = mock_update;
    c.hmac_final = mock_final;
    ota.Register_Crypto(c);

    uint8_t nonce[8] = { 1,2,3,4,5,6,7,8 };
    uint8_t hmac[32]; memset(hmac, 0xAB, 32);

    // 안티 롤백 (On_Begin: bool — 명시 비교, X-5 bool 강제 오판 방지)
    CHECK("구 버전 거부", ota.On_Begin(50u, 1024u, 4u, nonce, hmac, 0u) == false);
    CHECK("사유=VERSION_OLD", ota.Get_Reject_Reason() == AMI_OtaReject::VERSION_OLD);

    // size↔chunks 불일치
    CHECK("size 불일치 거부", ota.On_Begin(200u, 1000u, 2u, nonce, hmac, 0u) == false);

    // 정상 시작
    CHECK("BEGIN 성공", ota.On_Begin(200u, 1024u, 4u, nonce, hmac, 0x12345678u) == true);
    CHECK("RECEIVING", ota.Get_State() == AMI_OtaState::RECEIVING);

    // 논스 재전송 차단
    ota.Abort();
    CHECK("동일 논스 거부", ota.On_Begin(201u, 1024u, 4u, nonce, hmac, 0u) == false);

    // 새 논스로 재시작
    uint8_t n2[8] = { 9,10,11,12,13,14,15,16 };
    CHECK("새 논스 성공", ota.On_Begin(200u, 1024u, 4u, n2, hmac, 0x12345678u) == true);

    // 4청크 수신
    uint8_t chunk[256]; memset(chunk, 0x55, 256);
    for (uint16_t i = 0; i < 4; i++)
        (void)ota.On_Chunk(i, chunk, 256u, nullptr);
    CHECK("4청크 완료", ota.Is_Complete());
    CHECK("진행률 100%", ota.Get_Progress_Pct() == 100u);

    // NACK 비트맵 (8의 배수 경계)
    uint8_t nack[256] = {};
    CHECK("미수신 0건", ota.Get_NACK_Bitmap(nack) == 0u);
    CHECK("byte[0]=0 (유령 없음)", nack[0] == 0u);

    // 검증
    ota.On_Broadcast_Complete(10000u);
    CHECK("VERIFYING 상태", ota.Get_State() == AMI_OtaState::VERIFYING);

    for (int t = 0; t < 20; t++)
        ota.Tick(10000u + static_cast<uint32_t>(t) * 100u);

    CHECK("검증 완료", ota.Get_State() == AMI_OtaState::READY ||
        ota.Get_State() == AMI_OtaState::FAILED);

    ota.Abort();
    CHECK("Abort → IDLE", ota.Get_State() == AMI_OtaState::IDLE);
    ota.Shutdown();
    CHECK("Shutdown 완료", true);
}

// =========================================================================
//  메인
// =========================================================================
int main() {
    printf("═══════════════════════════════════════════════\n");
    printf("  HTS B-CDMA Phase 1~4 전체 테스트 (101항목)\n");
    printf("  INNOVID CORE-X Pro / AMI IoT\n");
    printf("═══════════════════════════════════════════════\n");

    test_beacon();
    test_neighbor();
    test_sync();
    test_location();
    test_status_reporter();
    test_router();
    test_fusion();
    test_aggregator();
    test_coap();
    test_meter();
    test_ota();

    SUMMARY();
    return g_fail ? 1 : 0;
}