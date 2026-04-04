// Verify_KT_DSN_Disaster — KT 재난안전망(DSN) 극한: 스플릿 브레인·EMP 노이즈·P0(SOS) 선점
// 타겟: HTS_Mesh_Router, HTS_Priority_Scheduler, IPC 프레임 검증(Network/IPC 경계 모델)

#include "HTS_IPC_Protocol_Defs.h"
#include "HTS_Mesh_Router.h"
#include "HTS_Priority_Scheduler.h"

#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

namespace PE = ProtectedEngine;

using PE::EnqueueResult;
using PE::FwdResult;
using PE::HTS_Mesh_Router;
using PE::HTS_Priority_Scheduler;
using PE::IPC_Command;
using PE::IPC_Error;
using PE::PacketPriority;
using PE::RouteEntry;

using clock_hr = std::chrono::high_resolution_clock;

constexpr uint16_t kMyId = 3000u;
constexpr uint16_t kRemoteDest = 4000u;
constexpr uint16_t kIslandA = 401u;
constexpr uint16_t kIslandB = 402u;
constexpr uint32_t kBaseTick = 1'000'000u;

[[nodiscard]] uint32_t xorshift32(uint32_t& s) noexcept
{
    s ^= s << 13u;
    s ^= s >> 17u;
    s ^= s << 5u;
    return s;
}

void ser_u16(uint8_t* d, uint16_t v) noexcept
{
    d[0] = static_cast<uint8_t>(v & 0xFFu);
    d[1] = static_cast<uint8_t>((v >> 8u) & 0xFFu);
}

void fill_route(RouteEntry& o, uint16_t dest, uint8_t hops, uint8_t metric,
    uint8_t lqi) noexcept
{
    std::memset(&o, 0, sizeof(o));
    o.dest_id = dest;
    o.next_hop = 0u;
    o.hop_count = hops;
    o.metric = metric;
    o.lqi = lqi;
    o.valid = 1u;
}

[[nodiscard]] bool test_priority_l0_no_inversion()
{
    HTS_Priority_Scheduler sched;
    constexpr int64_t kBudgetUs = 3000; /* 호스트: 3ms 이내 SOS 인큐+디큐 (1ms 목표 여유) */
    uint32_t rng = 0x4B1Du;

    for (uint32_t i = 0u; i < 800u; ++i) {
        sched.Flush();
        uint8_t blob[8] = { 0xD0u, 0xD1u, 0u, 0u, 0u, 0u, 0u, 0u };

        for (size_t d = 0u; d < HTS_Priority_Scheduler::DATA_QUEUE_DEPTH; ++d) {
            blob[2] = static_cast<uint8_t>(d);
            const EnqueueResult er = sched.Enqueue(
                PacketPriority::DATA, blob, 3u, kBaseTick + i);
            if (er != EnqueueResult::OK) {
                std::printf("DSN[P0] FAIL: DATA fill @%zu got %u\n",
                    d, static_cast<unsigned>(er));
                return false;
            }
        }
        if (sched.Enqueue(PacketPriority::DATA, blob, 3u, kBaseTick + i)
            != EnqueueResult::QUEUE_FULL) {
            std::printf("DSN[P0] FAIL: DATA queue not full\n");
            return false;
        }

        for (size_t v = 0u; v < HTS_Priority_Scheduler::VOICE_QUEUE_DEPTH; ++v) {
            blob[2] = static_cast<uint8_t>(v | 0x80u);
            if (sched.Enqueue(PacketPriority::VOICE, blob, 3u, kBaseTick + i)
                != EnqueueResult::OK) {
                std::printf("DSN[P0] FAIL: VOICE fill\n");
                return false;
            }
        }

        /* 재밍 억제 ON — DATA 디큐 스킵, SOS 는 여전히 최우선 */
        sched.Tick(kBaseTick + i + 10u, 600u);

        const auto t0 = clock_hr::now();
        blob[0] = 0xE0u;
        if (sched.Enqueue(PacketPriority::SOS, blob, 2u, kBaseTick + i + 11u)
            != EnqueueResult::OK) {
            std::printf("DSN[P0] FAIL: SOS enqueue\n");
            return false;
        }

        uint8_t out[8]{};
        size_t olen = 0u;
        PacketPriority pr = PacketPriority::DATA;
        const bool got = sched.Dequeue(out, olen, pr);
        const auto t1 = clock_hr::now();
        const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
            t1 - t0).count();

        if (!got || pr != PacketPriority::SOS || olen < 2u || out[0] != 0xE0u) {
            std::printf("DSN[P0] FAIL: expected SOS first got pr=%u len=%zu\n",
                static_cast<unsigned>(pr), olen);
            return false;
        }
        if (us > kBudgetUs) {
            std::printf("DSN[P0] FAIL: SOS path too slow %" PRId64 " us\n",
                static_cast<int64_t>(us));
            return false;
        }
        (void)xorshift32(rng);
    }
    std::printf("DSN[P0] SOS over full DATA+VOICE + NF suppress — PASS (800 iters)\n");
    return true;
}

[[nodiscard]] bool test_split_brain_merge_and_loop_guard()
{
    HTS_Mesh_Router router(kMyId);
    HTS_Priority_Scheduler sched;
    RouteEntry re{};

    /* Island A 경로 */
    fill_route(re, kRemoteDest, 1u, 8u, 92u);
    router.On_Route_Update(kIslandA, &re, 1u, 93u);

    RouteEntry q{};
    if (!router.Get_Route(kRemoteDest, q) || q.next_hop != kIslandA) {
        std::printf("DSN[SPLIT] FAIL: initial route via A\n");
        return false;
    }

    /* 스플릿: A 단절 */
    router.On_Link_Down(kIslandA, kBaseTick + 100u);
    if (router.Get_Route(kRemoteDest, q)) {
        std::printf("DSN[SPLIT] FAIL: route should vanish after A down\n");
        return false;
    }

    /* hold-down(30s) 만료 전에는 동일 dest 신규 경로 거부 → 재난망 병합 전 시간 전진 */
    router.Tick(kBaseTick + 100u + 31'000u, sched);

    /* Island B 단독 재수렴 */
    fill_route(re, kRemoteDest, 1u, 12u, 80u);
    router.On_Route_Update(kIslandB, &re, 1u, 82u);
    if (!router.Get_Route(kRemoteDest, q) || q.next_hop != kIslandB) {
        std::printf("DSN[SPLIT] FAIL: B island route\n");
        return false;
    }

    /* 병합: A 복구 + 더 나은 메트릭 */
    router.On_Link_Up(kIslandA, 95u);
    fill_route(re, kRemoteDest, 1u, 6u, 94u);
    router.On_Route_Update(kIslandA, &re, 1u, 96u);
    router.Tick(kBaseTick + 200'000u, sched);

    if (!router.Get_Route(kRemoteDest, q)) {
        std::printf("DSN[SPLIT] FAIL: merge lost route\n");
        return false;
    }
    if (q.next_hop != kIslandA) {
        std::printf("DSN[SPLIT] FAIL: merge expected next_hop A=%u got %u\n",
            static_cast<unsigned>(kIslandA),
            static_cast<unsigned>(q.next_hop));
        return false;
    }

    /* 루프 가드: 테이블이 '다음 홉 = B'일 때 B에서 들어온 유니캐스트를 B로 되돌리지 않음 */
    router.Shutdown();
    fill_route(re, kRemoteDest, 1u, 10u, 85u);
    router.On_Route_Update(kIslandB, &re, 1u, 86u);
    if (!router.Get_Route(kRemoteDest, q) || q.next_hop != kIslandB) {
        std::printf("DSN[SPLIT] FAIL: B-only route for loop test\n");
        return false;
    }
    uint8_t pkt[HTS_Mesh_Router::MESH_HDR_SIZE + 2u]{};
    ser_u16(&pkt[0], 0u);
    ser_u16(&pkt[2], kRemoteDest);
    pkt[4] = 6u;
    pkt[5] = static_cast<uint8_t>(kMyId & 0xFFu);
    pkt[6] = 0x11u;
    pkt[7] = 0x22u;

    const FwdResult loop = router.On_Packet_Received(
        kIslandB, pkt, sizeof(pkt), kBaseTick + 300u, sched);
    if (loop != FwdResult::NO_ROUTE) {
        std::printf("DSN[SPLIT] FAIL: loop-back relay got %u\n",
            static_cast<unsigned>(loop));
        return false;
    }

    /* 브로드캐스트 스톰 상한: 연속 Tick으로 DATA 큐가 깊이 초과하지 않음 */
    sched.Flush();
    for (uint32_t k = 0u; k < 60u; ++k) {
        fill_route(re, static_cast<uint16_t>(8000u + (k % 25u)), 1u,
            static_cast<uint8_t>(10u + static_cast<uint8_t>(k & 7u)), 75u);
        router.On_Route_Update(static_cast<uint16_t>(500u + (k % 5u)), &re, 1u, 78u);
        router.Tick(kBaseTick + 400'000u + k, sched);
        if (sched.Get_DATA_Count() > HTS_Priority_Scheduler::DATA_QUEUE_DEPTH) {
            std::printf("DSN[STORM] FAIL: DATA depth overflow\n");
            return false;
        }
    }
    std::printf("DSN[SPLIT+STORM] merge + loop NO_ROUTE + DATA cap — PASS\n");
    return true;
}

[[nodiscard]] bool test_emp_ipc_and_mesh_garbage()
{
    uint32_t rng = 0xBADC0DEu;
    uint8_t wire[PE::IPC_MAX_FRAME_SIZE]{};
    uint8_t payload[32]{};
    uint64_t crc_fail = 0u;
    uint64_t len_fail = 0u;
    uint64_t ok_wrong = 0u;

    for (uint32_t i = 0u; i < 35'000u; ++i) {
        for (uint32_t b = 0u; b < sizeof(payload); ++b) {
            payload[b] = static_cast<uint8_t>(
                xorshift32(rng) & 0xFFu);
        }
        uint32_t plen_payload = 8u + (xorshift32(rng) % 17u);
        if (plen_payload > sizeof(payload)) {
            plen_payload = sizeof(payload);
        }
        uint32_t flen = 0u;
        const IPC_Error se = PE::IPC_Serialize_Frame(
            wire,
            static_cast<uint8_t>(i & 0xFFu),
            IPC_Command::DATA_TX,
            payload,
            static_cast<uint16_t>(plen_payload),
            flen);
        if (se != IPC_Error::OK) {
            std::printf("DSN[EMP] FAIL: serialize\n");
            return false;
        }
        const uint32_t flip = xorshift32(rng) % flen;
        wire[flip] = static_cast<uint8_t>(wire[flip] ^ static_cast<uint8_t>(
            1u + (xorshift32(rng) & 0x7Fu)));

        uint8_t out_pl[PE::IPC_MAX_PAYLOAD]{};
        uint8_t seq = 0u;
        IPC_Command cmd = IPC_Command::PING;
        uint16_t opl = 0u;
        const IPC_Error pe = PE::IPC_Parse_Frame(
            wire, flen, seq, cmd, out_pl,
            static_cast<uint16_t>(sizeof(out_pl)), opl);
        if (pe == IPC_Error::OK) {
            ++ok_wrong;
        }
        else if (pe == IPC_Error::CRC_MISMATCH) {
            ++crc_fail;
        }
        else if (pe == IPC_Error::INVALID_LEN) {
            ++len_fail;
        }

        HTS_Mesh_Router router(777u);
        HTS_Priority_Scheduler sched;
        uint8_t junk[72]{};
        const size_t bad_len = static_cast<size_t>(xorshift32(rng) % 80u);
        const FwdResult fr = router.On_Packet_Received(
            1u, junk, bad_len, kBaseTick + i, sched);
        if (bad_len < HTS_Mesh_Router::MESH_HDR_SIZE) {
            if (fr != FwdResult::NO_ROUTE) {
                std::printf("DSN[EMP] FAIL: short mesh len\n");
                return false;
            }
        }
    }
    if (ok_wrong != 0u) {
        std::printf("DSN[EMP] FAIL: corrupted IPC parsed OK count=%" PRIu64 "\n",
            static_cast<uint64_t>(ok_wrong));
        return false;
    }
    std::printf(
        "DSN[EMP] IPC bit-flip %" PRIu32 " (crc_fail=%" PRIu64 " len_fail=%" PRIu64 ") + mesh junk — PASS\n",
        35000u,
        static_cast<uint64_t>(crc_fail),
        static_cast<uint64_t>(len_fail));
    return true;
}

[[nodiscard]] bool test_fusion_loop()
{
    HTS_Mesh_Router router(9000u);
    HTS_Priority_Scheduler sched;
    RouteEntry re{};
    uint32_t rng = 0xC001D00Du;
    uint8_t wire[PE::IPC_MAX_FRAME_SIZE]{};
    uint8_t pl[12]{};

    for (uint32_t wave = 0u; wave < 3'000u; ++wave) {
        fill_route(re, static_cast<uint16_t>(10'000u + (wave % 40u)), 1u,
            static_cast<uint8_t>(8u + static_cast<uint8_t>(wave & 3u)), 70u);
        router.On_Route_Update(static_cast<uint16_t>(300u + (wave % 8u)), &re, 1u, 72u);
        router.Tick(kBaseTick + 500'000u + wave, sched);
        if (sched.Get_DATA_Count() > HTS_Priority_Scheduler::DATA_QUEUE_DEPTH) {
            return false;
        }

        uint8_t pkt[HTS_Mesh_Router::MESH_HDR_SIZE + 2u]{};
        ser_u16(&pkt[2], static_cast<uint16_t>(10'001u + (wave % 5u)));
        pkt[4] = 2u;
        pkt[5] = 1u;
        (void)router.On_Packet_Received(
            static_cast<uint16_t>(301u + (wave % 8u)),
            pkt, sizeof(pkt), kBaseTick + wave, sched);

        pl[0] = static_cast<uint8_t>(wave);
        uint32_t fl = 0u;
        (void)PE::IPC_Serialize_Frame(
            wire, static_cast<uint8_t>(wave & 0xFFu), IPC_Command::STATUS_RSP,
            pl, 6u, fl);
        const uint32_t cut = xorshift32(rng) % fl;
        wire[cut] ^= 0x55u;
        uint8_t o[PE::IPC_MAX_PAYLOAD]{};
        uint8_t seq = 0u;
        IPC_Command cmd = IPC_Command::PING;
        uint16_t ol = 0u;
        if (PE::IPC_Parse_Frame(wire, fl, seq, cmd, o,
                static_cast<uint16_t>(sizeof(o)), ol) == IPC_Error::OK) {
            return false;
        }

        sched.Flush();
        uint8_t b[8]{};
        for (size_t j = 0u; j < HTS_Priority_Scheduler::DATA_QUEUE_DEPTH; ++j) {
            (void)sched.Enqueue(PacketPriority::DATA, b, 2u, kBaseTick + wave);
        }
        b[0] = 0xF0u;
        (void)sched.Enqueue(PacketPriority::SOS, b, 1u, kBaseTick + wave + 1u);
        size_t ln = 0u;
        PacketPriority pr = PacketPriority::DATA;
        if (!sched.Dequeue(b, ln, pr) || pr != PacketPriority::SOS) {
            return false;
        }
    }
    std::printf("DSN[FUSION] 3000 waves mesh+IPC+P0 — PASS\n");
    return true;
}

} // namespace

int main()
{
    std::printf("KT_DSN_Disaster: split-brain + EMP + P0 storm (host TU)\n");
    if (!test_priority_l0_no_inversion()) {
        return 1;
    }
    if (!test_split_brain_merge_and_loop_guard()) {
        return 2;
    }
    if (!test_emp_ipc_and_mesh_garbage()) {
        return 3;
    }
    if (!test_fusion_loop()) {
        std::printf("DSN[FUSION] FAIL\n");
        return 4;
    }
    std::printf("KT_DSN_Disaster: ALL PASS\n");
    return 0;
}
