// Verify_AMI_Avalanche_Storm — AMI/미터/메시/OTA-AMI/네트워크 브릿지 4중 스트레스 (호스트)
// 조기 차단: 메시 패킷은 HTS_Mesh_Router::On_Packet_Received 가 final_dest≠my_id 이면
//           라우트 미존재 시 FwdResult::NO_ROUTE 로 즉시 반환(깊은 AMI 복호화 없음).

#include "HTS_Hardware_Init.h"
#include "HTS_IPC_Protocol.h"
#include "HTS_Mesh_Router.h"
#include "HTS_Meter_Data_Manager.h"
#include "HTS_Network_Bridge.h"
#include "HTS_Network_Bridge_Defs.h"
#include "HTS_OTA_AMI_Manager.h"
#include "HTS_Priority_Scheduler.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>

namespace {

using namespace ProtectedEngine;

constexpr uint16_t kMyMeshId = 0xF00Du;
constexpr uint32_t kAvalancheForeign = 4999u;
constexpr uint32_t kKickInterval = 256u;

std::atomic<uint32_t> g_mesh_local_count{0u};
std::atomic<uint32_t> g_mesh_target_hits{0u};

void mesh_local_cb(const uint8_t* payload, size_t len, uint16_t src_id) noexcept {
    (void)src_id;
    g_mesh_local_count.fetch_add(1u, std::memory_order_relaxed);
    if (len >= 5u && payload[0] == 'V' && payload[1] == 'A' && payload[2] == 'L'
        && payload[3] == 'I' && payload[4] == 'D') {
        g_mesh_target_hits.fetch_add(1u, std::memory_order_relaxed);
    }
}

void fill_mesh_hdr(uint8_t* pkt, uint16_t next_hop, uint16_t final_dest,
    uint8_t ttl, uint8_t src_lo) noexcept {
    pkt[0] = static_cast<uint8_t>(next_hop & 0xFFu);
    pkt[1] = static_cast<uint8_t>((next_hop >> 8u) & 0xFFu);
    pkt[2] = static_cast<uint8_t>(final_dest & 0xFFu);
    pkt[3] = static_cast<uint8_t>((final_dest >> 8u) & 0xFFu);
    pkt[4] = ttl;
    pkt[5] = src_lo;
}

std::atomic<bool> g_mon_stop{false};
std::atomic<bool> g_wdt_starved{false};

void wdt_monitor_fn() {
    uint64_t last_k = Hardware_Init_Manager::Debug_Host_WdtKick_Count();
    auto last_prog = std::chrono::steady_clock::now();
    while (!g_mon_stop.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(40));
        const uint64_t k = Hardware_Init_Manager::Debug_Host_WdtKick_Count();
        if (k != last_k) {
            last_k = k;
            last_prog = std::chrono::steady_clock::now();
            continue;
        }
        if (std::chrono::steady_clock::now() - last_prog > std::chrono::milliseconds(300)) {
            g_wdt_starved.store(true, std::memory_order_release);
            std::fputs("AA: WDT surrogate starvation\n", stderr);
            break;
        }
    }
}

[[nodiscard]] bool attack_time_warp_meter(HTS_Meter_Data_Manager& meter) {
    meter.Log_Event(MeterEvent::POWER_OFF, 0x80000000u);
    meter.Log_Event(MeterEvent::TAMPER, 0xFFFFFFFFu);
    meter.Log_Event(MeterEvent::POWER_ON, 0u);
    meter.Log_Event(MeterEvent::OVERLOAD, 1u);
    std::puts("AA: [1] Time-warping event timestamps injected");
    return true;
}

[[nodiscard]] bool attack_mesh_avalanche(
    HTS_Mesh_Router& router,
    HTS_Priority_Scheduler& sched) {
    g_mesh_local_count.store(0u, std::memory_order_relaxed);
    g_mesh_target_hits.store(0u, std::memory_order_relaxed);

    alignas(8) uint8_t pkt[HTS_Mesh_Router::MESH_HDR_SIZE + 16u]{};
    const char* junk = "STORM";
    std::memcpy(&pkt[HTS_Mesh_Router::MESH_HDR_SIZE], junk, 6u);
    const size_t pkt_len = HTS_Mesh_Router::MESH_HDR_SIZE + 6u;

    uint32_t no_route_cnt = 0u;
    uint32_t tick = 0u;

    for (uint32_t i = 0u; i < kAvalancheForeign; ++i) {
        const uint16_t foreign =
            static_cast<uint16_t>(0x1000u + static_cast<uint16_t>(i % 4000u));
        fill_mesh_hdr(pkt, 0u, foreign, 8u, static_cast<uint8_t>(i & 0xFFu));
        const FwdResult r = router.On_Packet_Received(
            1u, pkt, pkt_len, tick, sched);
        if (r == FwdResult::NO_ROUTE) {
            ++no_route_cnt;
        }
        ++tick;
        if ((i % kKickInterval) == 0u) {
            Hardware_Init_Manager::Kick_Watchdog();
            std::this_thread::yield();
        }
    }

    const char* good = "VALID";
    std::memcpy(&pkt[HTS_Mesh_Router::MESH_HDR_SIZE], good, 6u);
    fill_mesh_hdr(pkt, 0u, kMyMeshId, 8u, 0x77u);
    const FwdResult r_ok = router.On_Packet_Received(
        1u, pkt, pkt_len, tick, sched);
    Hardware_Init_Manager::Kick_Watchdog();

    std::printf(
        "AA: [4] Mesh avalanche — NO_ROUTE=%u (expect %u), last Fwd=%u, local_cb=%u target=%u\n",
        no_route_cnt,
        kAvalancheForeign,
        static_cast<unsigned>(r_ok),
        g_mesh_local_count.load(std::memory_order_relaxed),
        g_mesh_target_hits.load(std::memory_order_relaxed));

    if (no_route_cnt != kAvalancheForeign) {
        return false;
    }
    if (r_ok != FwdResult::SELF_DEST) {
        return false;
    }
    if (g_mesh_local_count.load(std::memory_order_relaxed) != 1u) {
        return false;
    }
    if (g_mesh_target_hits.load(std::memory_order_relaxed) != 1u) {
        return false;
    }
    return true;
}

[[nodiscard]] bool attack_bridge_half_open(HTS_Network_Bridge& bridge) {
    alignas(8) uint8_t frag[BRIDGE_FRAG_HEADER_SIZE + 32u]{};
    frag[2] = 7u;
    frag[3] = 0u;
    frag[0] = static_cast<uint8_t>(FragFlag::FIRST | FragFlag::MORE_FRAGMENTS);
    uint32_t t = 1000u;
    for (uint32_t i = 0u; i < 3000u; ++i) {
        frag[1] = static_cast<uint8_t>(i & 0xFFu);
        for (uint32_t j = 0u; j < 8u; ++j) {
            frag[BRIDGE_FRAG_HEADER_SIZE + j] =
                static_cast<uint8_t>(static_cast<uint8_t>(i) + static_cast<uint8_t>(j));
        }
        (void)bridge.Feed_Fragment(
            frag,
            static_cast<uint16_t>(BRIDGE_FRAG_HEADER_SIZE + 8u),
            t);
        t += 50u;
        if ((i % kKickInterval) == 0u) {
            Hardware_Init_Manager::Kick_Watchdog();
            std::this_thread::yield();
        }
    }
    bridge.Tick(t + BRIDGE_REASSEMBLY_TIMEOUT + 1000u);
    std::printf("AA: [2] Bridge half-open storm — timeouts=%u\n",
        bridge.Get_Timeout_Count());
    std::puts("AA: [2] Bridge slots evict / timeout path exercised");
    return true;
}

[[nodiscard]] bool attack_ota_meter_contend(
    HTS_OTA_AMI_Manager& ota,
    HTS_Meter_Data_Manager& meter,
    HTS_Priority_Scheduler& sched) {
    OTA_Crypto_Callbacks z{};
    ota.Register_Crypto(z);

    alignas(8) uint8_t nonce[OTA_NONCE_SIZE] = {
        0xA1u, 0xA2u, 0xA3u, 0xA4u, 0xA5u, 0xA6u, 0xA7u, 0xA8u
    };
    alignas(8) uint8_t hmac[OTA_HMAC_SIZE]{};
    const bool began = ota.On_Begin(
        2u,
        512u,
        2u,
        nonce,
        hmac,
        0xDEADBEEFu);
    if (!began) {
        std::fputs("AA: OTA On_Begin failed\n", stderr);
        return false;
    }

    alignas(8) uint8_t chunk[HTS_OTA_AMI_Manager::CHUNK_SIZE]{};
    for (size_t x = 0u; x < sizeof(chunk); ++x) {
        chunk[x] = static_cast<uint8_t>(x & 0xFFu);
    }

    MeterReading mr{};
    mr.watt_hour = 100u;
    mr.cumul_kwh_x100 = 200u;
    mr.voltage_x10 = 2200u;
    mr.current_x100 = 50u;
    mr.power_factor = 99u;
    mr.valid = 1u;

    for (uint32_t k = 0u; k < 12000u; ++k) {
        mr.watt_hour = k;
        meter.Update_Reading(mr);
        (void)ota.On_Chunk(0u, chunk, HTS_OTA_AMI_Manager::CHUNK_SIZE, nullptr);
        (void)ota.On_Chunk(1u, chunk, HTS_OTA_AMI_Manager::CHUNK_SIZE, nullptr);
        (void)ota.On_Chunk(999u, chunk, 16u, nullptr);
        if ((k % kKickInterval) == 0u) {
            Hardware_Init_Manager::Kick_Watchdog();
            std::this_thread::yield();
        }
    }

    meter.Tick(500u, sched);
    ota.Abort();
    std::puts("AA: [3] OTA chunk + meter Update/Tick interleave — completed (OTA Aborted)");
    return true;
}

} // namespace

int main() {
    HTS_IPC_Protocol ipc_stub;
    HTS_Network_Bridge bridge;
    if (bridge.Initialize(&ipc_stub) != IPC_Error::OK) {
        std::fputs("AA: bridge init failed\n", stderr);
        return 3;
    }

    HTS_Priority_Scheduler sched;
    HTS_Mesh_Router router(kMyMeshId);
    router.Register_Local_Deliver(mesh_local_cb);

    HTS_Meter_Data_Manager meter(kMyMeshId);
    HTS_OTA_AMI_Manager ota(kMyMeshId, 1u);

    Hardware_Init_Manager::Kick_Watchdog();
    g_mon_stop.store(false, std::memory_order_relaxed);
    g_wdt_starved.store(false, std::memory_order_relaxed);
    std::thread mon(wdt_monitor_fn);

    bool ok = true;
    ok = ok && attack_time_warp_meter(meter);
    ok = ok && attack_mesh_avalanche(router, sched);
    ok = ok && attack_bridge_half_open(bridge);
    ok = ok && attack_ota_meter_contend(ota, meter, sched);

    g_mon_stop.store(true, std::memory_order_release);
    mon.join();

    if (g_wdt_starved.load(std::memory_order_acquire)) {
        ok = false;
    }

    meter.Shutdown();
    ota.Shutdown();
    router.Shutdown();
    bridge.Shutdown();

    if (!ok) {
        std::fputs("AA: FAILED\n", stderr);
        return 1;
    }

    std::printf("AA: host WDT surrogate kicks = %llu\n",
        static_cast<unsigned long long>(Hardware_Init_Manager::Debug_Host_WdtKick_Count()));
    std::puts("Verify_AMI_Avalanche_Storm: ALL checks PASSED");
    return 0;
}
