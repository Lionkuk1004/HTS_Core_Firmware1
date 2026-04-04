// Verify_Stack_Watermark — 호스트 스택 워터마크(0xAA)로 Worst-case 경로 최대 사용 깊이 계측
// 대상: Secure Boot + KAT + POST + 세션/KDF/로테이터 + Holo 텐서(4K IQ) + IPC + Network Bridge
//
// Windows x64: 스택은 주소 감소 방향 성장. 스택 Limit~현재 프레임 사이 미사용 구간을 마킹한 뒤,
// 반복 부하 후 가장 낮은 주소부터 스캔하여 첫 잔류 0xAA 경계로 침범 깊이를 역산한다.
//
// 주의: Windows.h는 ERROR 등 매크로를 정의하므로 HTS 헤더보다 뒤에 둔다.

#ifdef NDEBUG
#undef NDEBUG
#endif

#include "HTS_Crypto_KAT.h"
#include "HTS_Holo_Dispatcher.h"
#include "HTS_IPC_Protocol_Defs.h"
#include "HTS_Key_Rotator.h"
#include "HTS_Network_Bridge.h"
#include "HTS_Network_Bridge_Defs.h"
#include "HTS_POST_Manager.h"
#include "HTS_Secure_Boot_Verify.h"
#include "HTS_Secure_Memory.h"
#include "HTS_Session_Gateway.hpp"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <process.h>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace {

using ProtectedEngine::Crypto_KAT;
using ProtectedEngine::DynamicKeyRotator;
using ProtectedEngine::HTS_Holo_Dispatcher;
using ProtectedEngine::HTS_Secure_Boot_Verify;
using ProtectedEngine::POST_Manager;
using ProtectedEngine::SecureMemory;
using ProtectedEngine::Session_Gateway;

// 반복 횟수 (수천 회 부하)
constexpr unsigned kHeavyIterations = 3500u;

constexpr uint8_t kWatermark = 0xAAu;

struct StackMeasureResult {
    unsigned long long probe_bytes = 0u;
    unsigned long long min_idx_non_watermark = 0u;   // 첫 비-워터마크 (낮은 주소 쪽 스캔)
    unsigned long long max_idx_non_watermark = 0u;
    unsigned long long count_non_watermark = 0u;
    int error_code = 0;
};

StackMeasureResult g_thread_result{};

void FillProbeVolatile(volatile unsigned char* p, size_t len) noexcept {
    for (size_t i = 0u; i < len; ++i) {
        p[i] = kWatermark;
    }
#if defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
}

/// E2E와 동일한 무거운 스택 사용 경로(세션 왕복 + Holo 4K IQ + 대형 IPC 버퍼) 1회.
__declspec(noinline) void RunOneHeavyCycle(uint8_t (&block_seed)[32]) {
    using namespace ProtectedEngine;

    Session_Gateway::Open_Session();
    assert(Session_Gateway::Is_Session_Active());

    alignas(8) uint8_t session_key[32] = {};
    const size_t sk_len = Session_Gateway::Derive_Session_Material(
        Session_Gateway::DOMAIN_ANCHOR_HMAC,
        session_key,
        sizeof(session_key));
    assert(sk_len == sizeof(session_key));

    DynamicKeyRotator rotator(session_key, sizeof(session_key));
    size_t derived_len = 0u;
    assert(rotator.deriveNextSeed(
        0u, block_seed, sizeof(block_seed), derived_len));
    assert(derived_len == 32u);
    SecureMemory::secureWipe(session_key, sizeof(session_key));

    uint32_t hseed[4] = {};
    static_assert(sizeof(hseed) <= 32u, "hseed fits block_seed");
    std::memcpy(hseed, block_seed, sizeof(hseed));

    HTS_Holo_Dispatcher holo;
    assert(holo.Initialize(hseed) == HTS_Holo_Dispatcher::SECURE_TRUE);

    alignas(8) uint8_t sensor_blob[16] = {
        0x01u, 0x02u, 0x03u, 0x04u, 0x55u, 0xAAu, 0x5Au, 0xA5u,
        0x10u, 0x20u, 0x30u, 0x40u, 0x50u, 0x60u, 0x70u, 0x80u
    };
    alignas(8) int16_t oI[4096] = {};
    alignas(8) int16_t oQ[4096] = {};

    holo.Set_Current_Mode(HoloPayload::DATA_HOLO);
    const size_t n_chips = holo.Build_Holo_Packet(
        HoloPayload::DATA_HOLO,
        sensor_blob,
        sizeof(sensor_blob),
        12345,
        oI,
        oQ,
        sizeof(oI) / sizeof(oI[0]));
    assert(n_chips > 0u);
    (void)holo.Shutdown();

    alignas(8) uint8_t ipc_payload[16] = {
        0xC0u, 0xDEu, 0xFAu, 0x11u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u
    };
    alignas(4) uint8_t wire[IPC_MAX_FRAME_SIZE] = {};
    uint32_t frame_len = 0u;
    assert(IPC_Serialize_Frame(
        wire,
        3u,
        IPC_Command::DATA_TX,
        ipc_payload,
        static_cast<uint16_t>(sizeof(ipc_payload)),
        frame_len) == IPC_Error::OK);

    uint8_t out_seq = 0u;
    IPC_Command out_cmd = IPC_Command::PING;
    alignas(4) uint8_t round_payload[IPC_MAX_PAYLOAD] = {};
    uint16_t out_plen = 0u;
    assert(IPC_Parse_Frame(
        wire,
        frame_len,
        out_seq,
        out_cmd,
        round_payload,
        static_cast<uint16_t>(sizeof(round_payload)),
        out_plen) == IPC_Error::OK);

    HTS_Network_Bridge bridge;
    alignas(4) uint8_t frag[BRIDGE_FRAG_HEADER_SIZE + 8] = {};
    frag[0] = 0u;
    frag[1] = 1u;
    frag[2] = 1u;
    frag[3] = 0u;
    const uint32_t feed_ret = bridge.Feed_Fragment(
        frag,
        static_cast<uint16_t>(sizeof(frag)),
        0u);
    assert(feed_ret != BRIDGE_SECURE_TRUE);

    Session_Gateway::Close_Session();
    assert(!Session_Gateway::Is_Session_Active());
}

__declspec(noinline) void RunHeavyLoop(uint8_t (&block_seed)[32]) {
    for (unsigned n = 0u; n < kHeavyIterations; ++n) {
        RunOneHeavyCycle(block_seed);
        if ((n & 0x3FFu) == 0u && n != 0u) {
            std::fprintf(stderr, "SW: iterations %u / %u\r", n, kHeavyIterations);
        }
    }
    std::fputs("\n", stderr);
}

unsigned __stdcall StackWatermarkThread(void* /*ctx*/) {
    StackMeasureResult out{};
    ULONG_PTR low_limit = 0u;
    ULONG_PTR high_limit = 0u;
    GetCurrentThreadStackLimits(&low_limit, &high_limit);

    constexpr ULONG_PTR kBottomReserve = 65536u;
    // 부트·KAT 이후 앵커를 잡으므로 상단 여유는 작게(실제 호출 프레임이 프로브와 겹치게)
    constexpr ULONG_PTR kTopReserve = 4096u;

    alignas(8) uint8_t block_seed[32] = {};

    // 1회: 부팅·KAT·POST — 워터마크 전에 수행(초기 SP와 무관한 1회 비용)
    {
        HTS_Secure_Boot_Verify boot;
        alignas(8) uint8_t pc_expected_hash[32] = {};
        for (size_t i = 0u; i < 32u; ++i) {
            pc_expected_hash[i] = 0xAAu;
        }
        assert(boot.Provision_Expected_Hash(pc_expected_hash, 32u));
        assert(HTS_Secure_Boot_Check() == 0);
        assert(HTS_Secure_Boot_Is_Verified() == 1);
        assert(Crypto_KAT::Run_All_Crypto_KAT());
        POST_Manager::executePowerOnSelfTest();
    }

    volatile int stack_anchor_after_boot = 0;
    (void)stack_anchor_after_boot;
    const uintptr_t here2 = reinterpret_cast<uintptr_t>(&stack_anchor_after_boot);

    const uintptr_t fill_lo = static_cast<uintptr_t>(low_limit) + kBottomReserve;
    const uintptr_t fill_hi = (here2 > kTopReserve + kBottomReserve + 4096u)
        ? (here2 - kTopReserve)
        : 0u;

    if (fill_hi <= fill_lo + 4096u) {
        out.error_code = 3;
        std::fputs("SW: probe range too small (stack limits vs frame)\n", stderr);
        g_thread_result = out;
        return 3u;
    }

    const size_t probe_len = static_cast<size_t>(fill_hi - fill_lo);
    volatile unsigned char* const probe = reinterpret_cast<volatile unsigned char*>(fill_lo);

    FillProbeVolatile(probe, probe_len);
#if defined(_MSC_VER)
    _ReadWriteBarrier();
#endif

    RunHeavyLoop(block_seed);
    SecureMemory::secureWipe(block_seed, sizeof(block_seed));

#if defined(_MSC_VER)
    _ReadWriteBarrier();
#endif

    out.probe_bytes = static_cast<unsigned long long>(probe_len);
    size_t min_non = probe_len;
    size_t max_non = 0u;
    size_t count_non = 0u;
    for (size_t i = 0u; i < probe_len; ++i) {
        if (probe[i] != kWatermark) {
            ++count_non;
            if (i < min_non) {
                min_non = i;
            }
            if (i > max_non) {
                max_non = i;
            }
        }
    }

    if (count_non == 0u) {
        min_non = 0u;
        max_non = 0u;
    }

    out.min_idx_non_watermark = static_cast<unsigned long long>(min_non);
    out.max_idx_non_watermark = static_cast<unsigned long long>(max_non);
    out.count_non_watermark = static_cast<unsigned long long>(count_non);

    const unsigned long long max_depth_from_probe_base =
        (count_non == 0u) ? 0ull : (out.probe_bytes - out.min_idx_non_watermark);
    const unsigned long long remaining_watermark = (count_non == 0u) ? out.probe_bytes : out.min_idx_non_watermark;

    std::printf(
        "SW: stack limits low=0x%llX high=0x%llX probe_span=%llu bytes\n",
        static_cast<unsigned long long>(low_limit),
        static_cast<unsigned long long>(high_limit),
        static_cast<unsigned long long>(probe_len));
    std::printf(
        "SW: after %u iterations — min_clobber_idx=%llu max_clobber_idx=%llu non-AA count=%llu\n",
        kHeavyIterations,
        out.min_idx_non_watermark,
        out.max_idx_non_watermark,
        out.count_non_watermark);
    std::printf(
        "SW: estimated max stack consumption into probe (from high-SP side) = %llu bytes\n",
        max_depth_from_probe_base);
    std::printf(
        "SW: remaining intact watermark from probe base (low addr) = %llu bytes\n",
        remaining_watermark);

    if (count_non > 0u && min_non == 0u) {
        std::fputs("SW: [WARN] watermark touched from probe base — increase thread stack or reduce locals\n", stderr);
        out.error_code = 1;
    }

    g_thread_result = out;
    return (out.error_code >= 2) ? static_cast<unsigned>(out.error_code) : 0u;
}

} // namespace

int main() {
    constexpr unsigned kThreadStackBytes = 4u * 1024u * 1024u;
    const uintptr_t th = _beginthreadex(
        nullptr,
        kThreadStackBytes,
        StackWatermarkThread,
        nullptr,
        0,
        nullptr);
    if (th == 0u) {
        std::perror("_beginthreadex");
        return 4;
    }

    WaitForSingleObject(reinterpret_cast<HANDLE>(th), INFINITE);
    DWORD exit_code = 1u;
    GetExitCodeThread(reinterpret_cast<HANDLE>(th), &exit_code);
    CloseHandle(reinterpret_cast<HANDLE>(th));

    if (exit_code != 0u) {
        std::fprintf(stderr, "SW: watermark thread exit %lu\n", static_cast<unsigned long>(exit_code));
        return static_cast<int>(exit_code);
    }

    std::puts("Verify_Stack_Watermark: completed (see SW: lines above for max stack usage)");
    return 0;
}
