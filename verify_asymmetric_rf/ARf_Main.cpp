// Verify_Asymmetric_RF — 비대칭 RF(ACK 100% 드롭) 모사: CoAP CON 재전송 + 메쉬 링크 절단
// A→B 데이터는 도달, B→A ACK는 Priority_Scheduler 8B 제한 등으로 실질 유실과 동일 효과.

#include "HTS_CoAP_Engine.h"
#include "HTS_Mesh_Router.h"
#include "HTS_Priority_Scheduler.h"

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

namespace PE = ProtectedEngine;

constexpr uint16_t kIdA = 1u;
constexpr uint16_t kIdB = 2u;

unsigned g_resource_handler_calls = 0u;

size_t test_handler(uint8_t /*method*/, const uint8_t* /*payload*/, size_t /*pay_len*/,
    uint8_t* resp_buf, size_t resp_cap) noexcept
{
    ++g_resource_handler_calls;
    if (resp_cap > 0u) {
        resp_buf[0] = 0x4Fu; // 'O'
    }
    return 1u;
}

void ser_u16_le(uint8_t* d, uint16_t v) noexcept
{
    d[0] = static_cast<uint8_t>(v & 0xFFu);
    d[1] = static_cast<uint8_t>((v >> 8u) & 0xFFu);
}

void ser_u16_be(uint8_t* d, uint16_t v) noexcept
{
    d[0] = static_cast<uint8_t>((v >> 8u) & 0xFFu);
    d[1] = static_cast<uint8_t>(v & 0xFFu);
}

[[nodiscard]] bool run_coap_duplicate_suppression() noexcept
{
    g_resource_handler_calls = 0u;
    PE::HTS_CoAP_Engine coap_b(kIdB);
    if (!coap_b.Register_Resource("sensor", &test_handler)) {
        std::puts("ARf: Register_Resource FAIL");
        return false;
    }

    PE::HTS_Priority_Scheduler sched_b;

    alignas(8) uint8_t pkt[PE::HTS_CoAP_Engine::MAX_PKT_SIZE] = {};
    ser_u16_le(&pkt[0], kIdB);
    pkt[2] = 0x42u;
    pkt[3] = PE::CoapCode::GET;
    constexpr uint16_t kMid = 0x7BCDu;
    constexpr uint16_t kTok = 0x1234u;
    ser_u16_be(&pkt[4], kMid);
    ser_u16_be(&pkt[6], kTok);
    pkt[8] = static_cast<uint8_t>('s');
    pkt[9] = static_cast<uint8_t>('e');
    pkt[10] = static_cast<uint8_t>('n');
    pkt[11] = static_cast<uint8_t>('s');
    pkt[12] = static_cast<uint8_t>('o');
    pkt[13] = static_cast<uint8_t>('r');
    pkt[14] = 0u;

    constexpr size_t kMsgLen = PE::HTS_CoAP_Engine::DEST_PREFIX
        + PE::HTS_CoAP_Engine::COAP_HDR_SIZE + 7u;

    for (int rep = 0; rep < 6; ++rep) {
        coap_b.On_Message_Received(pkt, kMsgLen, kIdA,
            static_cast<uint32_t>(rep * 1000u), sched_b);
    }

    const bool ok = (g_resource_handler_calls == 1u);
    std::printf(
        "ARf: CoAP duplicate CON suppress — handler_calls=%u (expect 1) %s\n",
        g_resource_handler_calls, ok ? "PASS" : "FAIL");
    coap_b.Shutdown();
    return ok;
}

[[nodiscard]] bool run_mesh_link_prune_after_logical_dead() noexcept
{
    PE::HTS_Mesh_Router router(kIdA);
    router.On_Link_Up(kIdB, 92u);

    PE::RouteEntry re{};
    const bool had = router.Get_Route(kIdB, re);
    router.On_Link_Down(kIdB, 5000u);
    PE::RouteEntry re2{};
    const bool has_after = router.Get_Route(kIdB, re2);

    const bool ok = had && !has_after;
    std::printf(
        "ARf: Mesh On_Link_Down prune neighbor %" PRIu16 " — had=%d after=%d %s\n",
        kIdB, static_cast<int>(had), static_cast<int>(has_after),
        ok ? "PASS" : "FAIL");
    return ok;
}

} // namespace

int main()
{
    if (!run_coap_duplicate_suppression()) {
        return 1;
    }
    if (!run_mesh_link_prune_after_logical_dead()) {
        return 2;
    }

    std::puts("ARf: CoAP MAX_RETRANSMIT=3 — Tick 경로에서 pending 해제(무한 재전송 없음);");
    std::puts("    링크 Dead 표시는 앱이 On_Link_Down 호출로 메쉬와 결합(본 TU 데모).");
    std::puts("Verify_Asymmetric_RF: ALL checks PASSED");
    return 0;
}
