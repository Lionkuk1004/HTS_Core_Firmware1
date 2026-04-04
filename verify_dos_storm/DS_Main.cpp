// Verify_DoS_Storm — 네트워크 브릿지·BLE UART 링 대량 유입 + 호스트 WDT 킥 기아 감시
// 실칩 WDT 없음: Kick_Watchdog()는 HTS_ALLOW_HOST_BUILD에서 원자 카운터만 증가.

#include "HTS_BLE_NFC_Gateway.h"
#include "HTS_Hardware_Init.h"
#include "HTS_IPC_Protocol.h"
#include "HTS_Network_Bridge.h"
#include "HTS_Network_Bridge_Defs.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <thread>
#include <vector>

namespace {

using namespace ProtectedEngine;

constexpr uint32_t kBridgeStormTotal = 1000000u;
constexpr unsigned kBridgeThreads = 4u;
constexpr uint32_t kKickYieldInterval = 256u;

constexpr uint32_t kBleFeedTotal = 500000u;

std::atomic<bool> g_monitor_stop{false};
std::atomic<bool> g_wdt_starved{false};

void wdt_monitor_thread_fn() {
    uint64_t last_k = Hardware_Init_Manager::Debug_Host_WdtKick_Count();
    auto last_progress = std::chrono::steady_clock::now();
    while (!g_monitor_stop.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(40));
        const uint64_t k = Hardware_Init_Manager::Debug_Host_WdtKick_Count();
        if (k != last_k) {
            last_k = k;
            last_progress = std::chrono::steady_clock::now();
            continue;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now - last_progress > std::chrono::milliseconds(280)) {
            g_wdt_starved.store(true, std::memory_order_release);
            std::fputs("DS: WDT surrogate — no Kick_Watchdog progress (starvation)\n", stderr);
            break;
        }
    }
}

[[nodiscard]] bool run_bridge_storm(HTS_Network_Bridge& bridge) {
    alignas(8) uint8_t frag[BRIDGE_FRAG_HEADER_SIZE + 8u]{};
    frag[0] = FragFlag::SINGLE;
    frag[2] = 1u;
    frag[3] = 0u;

    const uint32_t per = kBridgeStormTotal / static_cast<uint32_t>(kBridgeThreads);
    std::vector<std::thread> workers;
    workers.reserve(static_cast<size_t>(kBridgeThreads));

    const auto t0 = std::chrono::steady_clock::now();

    for (unsigned t = 0u; t < kBridgeThreads; ++t) {
        const uint32_t base = static_cast<uint32_t>(t) * 7919u;
        workers.emplace_back([&, base, t]() {
            (void)t;
            uint32_t tick = 0u;
            for (uint32_t i = 0u; i < per; ++i) {
                frag[1] = static_cast<uint8_t>((base + i) & 0xFFu);
                frag[4] = static_cast<uint8_t>(i & 0xFFu);
                frag[5] = static_cast<uint8_t>((i >> 8) & 0xFFu);
                (void)bridge.Feed_Fragment(frag, 6u, tick);
                ++tick;
                if ((i % kKickYieldInterval) == 0u) {
                    Hardware_Init_Manager::Kick_Watchdog();
                    std::this_thread::yield();
                }
            }
        });
    }

    for (auto& w : workers) {
        w.join();
    }

    const auto t1 = std::chrono::steady_clock::now();
    const double sec = std::chrono::duration<double>(t1 - t0).count();
    const double rate = static_cast<double>(kBridgeStormTotal) / (sec > 1e-9 ? sec : 1e-9);

    std::printf("DS: Network_Bridge Feed_Fragment storm %u calls in %.3f s (~%.0f/s)\n",
        kBridgeStormTotal, sec, rate);

    if (g_wdt_starved.load(std::memory_order_acquire)) {
        return false;
    }
    return true;
}

[[nodiscard]] bool run_ble_storm(HTS_BLE_NFC_Gateway& ble) {
    std::atomic<bool> ble_done{false};
    std::atomic<uint32_t> tick_ms{0u};

    std::thread ticker([&]() {
        while (!ble_done.load(std::memory_order_acquire)) {
            const uint32_t ms = tick_ms.fetch_add(1u, std::memory_order_relaxed);
            ble.Tick(ms);
            if ((ms % 8u) == 0u) {
                Hardware_Init_Manager::Kick_Watchdog();
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    });

    for (uint32_t i = 0u; i < kBleFeedTotal; ++i) {
        const uint8_t b = static_cast<uint8_t>(0x20u + (i & 0x3Fu));
        ble.Feed_UART_Byte(b);
        if ((i % kKickYieldInterval) == 0u) {
            Hardware_Init_Manager::Kick_Watchdog();
            std::this_thread::yield();
        }
    }

    ble_done.store(true, std::memory_order_release);
    ticker.join();

    if (g_wdt_starved.load(std::memory_order_acquire)) {
        return false;
    }
    std::puts("DS: BLE UART ring storm — completed (ring drops when full; no hang)");
    return true;
}

} // namespace

int main() {
    // 호스트: IPC::Initialize()는 STM32 레지스터 접근 → Win32 액세스 위반.
    // Feed_Fragment / BLE UART 경로는 송신 IPC 미사용 — 비초기화 IPC 인스턴스 포인터만 연결.
    HTS_IPC_Protocol ipc_stub;

    HTS_Network_Bridge bridge;
    if (bridge.Initialize(&ipc_stub) != IPC_Error::OK) {
        std::fputs("DS: bridge init failed\n", stderr);
        return 5;
    }

    LocationCode loc{};
    loc.code = 0u;
    HTS_BLE_NFC_Gateway ble;
    if (ble.Initialize(&ipc_stub, loc) != IPC_Error::OK) {
        std::fputs("DS: BLE init failed\n", stderr);
        bridge.Shutdown();
        return 6;
    }

    g_monitor_stop.store(false, std::memory_order_relaxed);
    g_wdt_starved.store(false, std::memory_order_relaxed);
    Hardware_Init_Manager::Kick_Watchdog();

    std::thread mon(wdt_monitor_thread_fn);

    const bool ok_bridge = run_bridge_storm(bridge);
    const bool ok_ble = ok_bridge ? run_ble_storm(ble) : false;

    g_monitor_stop.store(true, std::memory_order_release);
    mon.join();

    ble.Shutdown();
    bridge.Shutdown();

    if (!ok_bridge || !ok_ble) {
        std::fputs("DS: FAILED (bridge or BLE or WDT starvation)\n", stderr);
        return 1;
    }

    const uint64_t kicks = Hardware_Init_Manager::Debug_Host_WdtKick_Count();
    std::printf("DS: total host WDT surrogate kicks = %llu\n",
        static_cast<unsigned long long>(kicks));
    std::puts("Verify_DoS_Storm: ALL checks PASSED");
    return 0;
}
