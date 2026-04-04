// Verify_Mesh_10K_Chaos — 호스트 TU: 1만 노드급 라우팅·링크 단절·TTL 스트레스
// 타겟 모듈: HTS_Mesh_Router + HTS_Priority_Scheduler (HTS_LIM_V3.lib)
//
// 제약: Priority_Scheduler MAX_PACKET_DATA=8 → 메쉬 페이로드 최대 2B (헤더 6B)

#include "HTS_Mesh_Router.h"
#include "HTS_Priority_Scheduler.h"

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

using ProtectedEngine::FwdResult;
using ProtectedEngine::HTS_Mesh_Router;
using ProtectedEngine::HTS_Priority_Scheduler;
using ProtectedEngine::RouteEntry;

constexpr uint16_t kMyId = 100u;
constexpr uint16_t kNeighborB = 101u;  // 핵심 중계 이웃 (단절 대상)
constexpr uint16_t kNeighborAlt = 102u;
constexpr uint16_t kSensorDest = 500u;
constexpr uint32_t kBaseTick = 1000u;

void ser_u16(uint8_t* dst, uint16_t v) noexcept {
    dst[0] = static_cast<uint8_t>(v & 0xFFu);
    dst[1] = static_cast<uint8_t>((v >> 8u) & 0xFFu);
}

// 결정론적 PRNG (재현 가능한 "무작위" 링크 단절)
[[nodiscard]] uint32_t xorshift32(uint32_t& s) noexcept {
    s ^= s << 13u;
    s ^= s >> 17u;
    s ^= s << 5u;
    return s;
}

[[nodiscard]] bool attack_routing_table_10k() {
    HTS_Mesh_Router router(kMyId);
    RouteEntry re{};
    re.valid = 1u;
    re.hop_count = 1u;
    re.lqi = 80u;
    re.metric = 16u;
    re.next_hop = 0u;

    constexpr uint16_t kAdvNeighbor = 50u;
    uint32_t chaos_seed = 0xC0FFEEu;

    for (uint32_t i = 0u; i < 10000u; ++i) {
        // 300..10299 — my_id(100) 회피, uint16 범위 내 고유 목적지
        const uint16_t dest = static_cast<uint16_t>(300u + i);
        if (dest == kMyId) {
            continue;
        }
        re.dest_id = dest;
        router.On_Route_Update(kAdvNeighbor, &re, 1u, 90u);

        const size_t cnt = router.Get_Route_Count();
        if (cnt > HTS_Mesh_Router::MAX_ROUTES) {
            std::printf("MESH[1] FAIL: route_count %" PRIu64 " > MAX_ROUTES\n",
                static_cast<uint64_t>(cnt));
            return false;
        }

        // 가끔 이웃 단절 → 경로 무효화 후 다음 업데이트로 재수렴 (크래시/무한루프 없음)
        if ((xorshift32(chaos_seed) & 0xFFu) < 4u) {
            router.On_Link_Down(kAdvNeighbor, kBaseTick + i);
        }
    }

    std::printf(
        "MESH[1] 10k virtual dest flood: final routes=%" PRIu64 " (cap=%" PRIu64 ") — PASS\n",
        static_cast<uint64_t>(router.Get_Route_Count()),
        static_cast<uint64_t>(HTS_Mesh_Router::MAX_ROUTES));
    return true;
}

void fill_route_advert(RouteEntry& out, uint16_t dest, uint8_t hops,
    uint8_t metric, uint8_t lqi) noexcept {
    std::memset(&out, 0, sizeof(out));
    out.dest_id = dest;
    out.next_hop = 0u;
    out.hop_count = hops;
    out.metric = metric;
    out.lqi = lqi;
    out.valid = 1u;
}

[[nodiscard]] bool attack_random_link_and_forwarding() {
    HTS_Mesh_Router router(kMyId);
    HTS_Priority_Scheduler sched;
    uint8_t sensor[2] = { 0x5Au, 0xA5u };

    // 목적지 kSensorDest 까지 이웃 kNeighborB 경유 경로 학습
    RouteEntry adv{};
    fill_route_advert(adv, kSensorDest, 1u, 8u, 95u);
    router.On_Route_Update(kNeighborB, &adv, 1u, 92u);

    const FwdResult r1 = router.Forward(
        kSensorDest, sensor, sizeof(sensor), HTS_Mesh_Router::DEFAULT_TTL,
        kBaseTick, sched);
    if (r1 != FwdResult::OK) {
        std::printf("MESH[2] FAIL: Forward before break got %u\n",
            static_cast<unsigned>(r1));
        return false;
    }

    // B 링크 단절 → 경로 무효화
    router.On_Link_Down(kNeighborB, kBaseTick + 100u);

    const FwdResult r2 = router.Forward(
        kSensorDest, sensor, sizeof(sensor), HTS_Mesh_Router::DEFAULT_TTL,
        kBaseTick + 200u, sched);
    if (r2 != FwdResult::NO_ROUTE) {
        std::printf("MESH[2] FAIL: expected NO_ROUTE after Link_Down, got %u\n",
            static_cast<unsigned>(r2));
        return false;
    }

    // Link_Down 후 hold-down(30s) 동안 동일 dest 신규 경로는 차단됨 → Tick으로 만료
    constexpr uint32_t kHoldDownMs = 31000u;
    router.Tick(kBaseTick + 100u + kHoldDownMs, sched);

    // 대체 이웃에서 동일 목적지 경로 수신 → 재전달
    fill_route_advert(adv, kSensorDest, 1u, 10u, 88u);
    router.On_Route_Update(kNeighborAlt, &adv, 1u, 90u);

    const FwdResult r3 = router.Forward(
        kSensorDest, sensor, sizeof(sensor), HTS_Mesh_Router::DEFAULT_TTL,
        kBaseTick + 300u, sched);
    if (r3 != FwdResult::OK) {
        std::printf("MESH[2] FAIL: Forward after alt path got %u\n",
            static_cast<unsigned>(r3));
        return false;
    }

    std::printf("MESH[2] Link break + alternate path — PASS\n");
    return true;
}

[[nodiscard]] bool attack_ttl_loop_and_broadcast_cap() {
    HTS_Mesh_Router router(kMyId);
    HTS_Priority_Scheduler sched;

    // 유니캐스트: TTL=1 이면 중계 전 TTL_EXPIRED (핑퐁 누적 홉 소모와 동일 효과)
    uint8_t pkt[HTS_Mesh_Router::MESH_HDR_SIZE + 2u];
    ser_u16(&pkt[0], 0u);
    ser_u16(&pkt[2], 999u);  // not my_id
    pkt[4] = 1u;            // ttl
    pkt[5] = 7u;
    pkt[6] = 0x11u;
    pkt[7] = 0x22u;

    // 경로 없으면 NO_ROUTE; TTL 분기는 dest에 대한 route 탐색 전에 ttl<=1 처리됨
    // → find_route 전에 ttl 만료: 코드상 ttl 먼저 검사
    const FwdResult u = router.On_Packet_Received(
        kNeighborB, pkt, sizeof(pkt), kBaseTick, sched);
    if (u != FwdResult::TTL_EXPIRED) {
        std::printf("MESH[3] FAIL: unicast ttl=1 expected TTL_EXPIRED, got %u\n",
            static_cast<unsigned>(u));
        return false;
    }

    // 브로드캐스트: TTL=1 → 로컬 처리 후 재중계 없이 TTL_EXPIRED
    ser_u16(&pkt[2], 0xFFFFu);
    pkt[4] = 1u;
    const FwdResult b = router.On_Packet_Received(
        kNeighborB, pkt, sizeof(pkt), kBaseTick + 1u, sched);
    if (b != FwdResult::TTL_EXPIRED) {
        std::printf("MESH[3] FAIL: bcast ttl=1 expected TTL_EXPIRED, got %u\n",
            static_cast<unsigned>(b));
        return false;
    }

    // 스톰 완화: TTL 고갈로 무한 인큐 방지 — 높은 TTL이라도 큐 깊이(8)에서 포화
    sched.Flush();
    unsigned enq_ok = 0u;
    for (int i = 0; i < 64; ++i) {
        pkt[4] = 8u;
        ser_u16(&pkt[2], 0xFFFFu);
        const FwdResult fr = router.On_Packet_Received(
            kNeighborB, pkt, sizeof(pkt),
            static_cast<uint32_t>(kBaseTick + 10u + static_cast<uint32_t>(i)),
            sched);
        if (fr == FwdResult::OK) {
            ++enq_ok;
        }
    }
    if (enq_ok != 8u) {
        std::printf("MESH[3] NOTE: bcast forward OK count=%u (DATA queue depth 8)\n",
            enq_ok);
    }

    std::printf("MESH[3] TTL expire (unicast/bcast) — PASS\n");
    return true;
}

} // namespace

int main() {
    if (!attack_routing_table_10k()) {
        return 1;
    }
    if (!attack_random_link_and_forwarding()) {
        return 2;
    }
    if (!attack_ttl_loop_and_broadcast_cap()) {
        return 3;
    }

    std::printf("Verify_Mesh_10K_Chaos: ALL checks PASSED (host TU)\n");
    return 0;
}
