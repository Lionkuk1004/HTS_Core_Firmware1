// Verify_Apocalypse_All — 12/13 통합 묵시록: 시간·리플레이·브라운아웃·열화 시프트·CFI 퍼징 단일 루프
// 타겟: HTS_TimeSpace_Guard, Key_Rotator, IPC_Defs(CFI+Parse), Crc32Util, Crypto_KAT, Session_Gateway(심볼)

#include "HTS_Crypto_KAT.h"
#include "HTS_Crc32Util.h"
#include "HTS_IPC_Protocol_Defs.h"
#include "HTS_Key_Rotator.h"
#include "HTS_Session_Gateway.hpp"
#include "HTS_TimeSpace_Guard.h"

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

namespace PE = ProtectedEngine;

using PE::AntiReplayWindow64;
using PE::ChronosAnomalyGuardU64;
using PE::Crypto_KAT;
using PE::Crc32Util;
using PE::DynamicKeyRotator;
using PE::IPC_Command;
using PE::IPC_Error;
using PE::Session_Gateway;

constexpr uint32_t kZombieNodes = 1000u;
constexpr uint32_t kReplaysPerNode = 100u;
constexpr uint32_t kAnchorIters = kZombieNodes;
constexpr uint32_t kReplayIters = kZombieNodes * kReplaysPerNode;
constexpr uint32_t kTotalIters = kAnchorIters + kReplayIters;

AntiReplayWindow64 g_zombie[kZombieNodes];

[[nodiscard]] uint32_t xorshift32(uint32_t& s) noexcept
{
    s ^= s << 13u;
    s ^= s >> 17u;
    s ^= s << 5u;
    return s;
}

[[nodiscard]] uint32_t load_u32_le(const uint8_t* d) noexcept
{
    return static_cast<uint32_t>(d[0])
        | (static_cast<uint32_t>(d[1]) << 8u)
        | (static_cast<uint32_t>(d[2]) << 16u)
        | (static_cast<uint32_t>(d[3]) << 24u);
}

void store_u32_le(uint8_t* d, uint32_t v) noexcept
{
    d[0] = static_cast<uint8_t>(v & 0xFFu);
    d[1] = static_cast<uint8_t>((v >> 8u) & 0xFFu);
    d[2] = static_cast<uint8_t>((v >> 16u) & 0xFFu);
    d[3] = static_cast<uint8_t>((v >> 24u) & 0xFFu);
}

[[nodiscard]] bool page256_crc_valid(const uint8_t* p) noexcept
{
    const uint32_t c = Crc32Util::calculate(p, 252u);
    return c == load_u32_le(p + 252u);
}

[[nodiscard]] PE::IPC_State apoc_recover(PE::IPC_State st) noexcept
{
    using PE::IPC_State;
    if (PE::IPC_Is_Legal_Transition(st, IPC_State::ERROR_RECOVERY)) {
        return IPC_State::ERROR_RECOVERY;
    }
    if (PE::IPC_Is_Legal_Transition(st, IPC_State::IDLE)) {
        return IPC_State::IDLE;
    }
    return IPC_State::IDLE;
}

[[nodiscard]] PE::IPC_State apoc_fuzz_step(PE::IPC_State st, uint32_t r) noexcept
{
    using PE::IPC_State;
    const IPC_State to = static_cast<IPC_State>(r & 0xFFu);
    if (!PE::IPC_Is_Valid_State(to)) {
        return apoc_recover(st);
    }
    if (PE::IPC_Is_Legal_Transition(st, to)) {
        return to;
    }
    return apoc_recover(st);
}

struct BrownoutPage {
    uint8_t golden[256]{};
    uint8_t slot[256]{};
    bool    inited = false;

    void init_once() noexcept
    {
        if (inited) {
            return;
        }
        for (size_t i = 0u; i < 252u; ++i) {
            golden[i] = static_cast<uint8_t>(0xB0u ^ static_cast<uint8_t>(i));
        }
        const uint32_t c = Crc32Util::calculate(golden, 252u);
        store_u32_le(golden + 252u, c);
        std::memcpy(slot, golden, sizeof(slot));
        inited = true;
    }

    [[nodiscard]] bool tear_and_rollback(uint32_t iter, uint32_t rr) noexcept
    {
        init_once();
        if ((iter % 29u) != 0u) {
            return true;
        }
        uint8_t cand[256];
        std::memcpy(cand, golden, sizeof(cand));
        cand[16u] ^= static_cast<uint8_t>(iter & 0xFFu);
        cand[17u] ^= static_cast<uint8_t>((rr >> 3u) & 0xFFu);
        const uint32_t c2 = Crc32Util::calculate(cand, 252u);
        store_u32_le(cand + 252u, c2);
        const size_t tear = 16u + static_cast<size_t>(rr % 200u);
        std::memcpy(slot, cand, tear);
        std::memset(slot + tear, 0xFFu, sizeof(slot) - tear);
        if (!page256_crc_valid(slot)) {
            std::memcpy(slot, golden, sizeof(slot));
        }
        if (!page256_crc_valid(slot)) {
            std::memcpy(slot, golden, sizeof(slot));
        }
        return page256_crc_valid(slot);
    }
};

} // namespace

int main()
{
    std::printf(
        "Verify_Apocalypse_All: single loop %" PRIu32 " iters (5 plagues fused)\n",
        kTotalIters);
    std::fflush(stdout);

    uint8_t master[32]{};
    for (uint32_t i = 0u; i < 32u; ++i) {
        master[i] = static_cast<uint8_t>(0xA7u ^ static_cast<uint8_t>(i));
    }
    DynamicKeyRotator kr(master, sizeof(master));

    ChronosAnomalyGuardU64 chronos;
    uint64_t wall_ms = 5'500'000ULL * 86400000ULL;
    BrownoutPage brown{};
    PE::IPC_State cfi = PE::IPC_State::IDLE;
    uint32_t rng = 0xA90Cu;

    for (uint32_t iter = 0u; iter < kTotalIters; ++iter) {
        /* --- 재앙 2: 좀비 리플레이 10만 (앵커 1000 + 거절 1000×100) --- */
        if (iter < kAnchorIters) {
            g_zombie[iter].Reset();
            if (!g_zombie[iter].AcceptSeq(0xF0000000u + iter * 19u)) {
                std::printf("APOC[ZOMBIE] FAIL: anchor %" PRIu32 "\n", iter);
                return 3;
            }
        }
        else {
            const uint32_t j = iter - kAnchorIters;
            const uint32_t z = j / kReplaysPerNode;
            const uint32_t r = j % kReplaysPerNode;
            const uint32_t oldseq = z * 131u + r;
            if (g_zombie[z].AcceptSeq(oldseq)) {
                std::printf(
                    "APOC[ZOMBIE] FAIL: replay accepted z=%" PRIu32 " r=%" PRIu32 "\n",
                    z, r);
                return 4;
            }
        }

        /* --- 재앙 1: 크로노스 (SysTick 대리: uint64_t wall) --- */
        wall_ms += 3u + (iter & 7u);
        if ((iter % 503u) == 0u) {
            (void)chronos.FeedMonotonicWallMs(wall_ms);
            if (!chronos.FeedMonotonicWallMs(
                    wall_ms - (6ULL * 365ULL * 86400000ULL))) {
                chronos.Reset();
            }
            wall_ms += 1u;
            if (!chronos.FeedMonotonicWallMs(
                    wall_ms + (21ULL * 365ULL * 86400000ULL))) {
                chronos.Reset();
            }
        }
        else if (!chronos.FeedMonotonicWallMs(wall_ms)) {
            chronos.Reset();
        }

        /* --- 재앙 3: 플래시 256B 브라운아웃(부분 기록 → CRC 실패 시 golden 롤백) --- */
        if (!brown.tear_and_rollback(iter, xorshift32(rng))) {
            std::printf("APOC[BROWNOUT] FAIL: rollback\n");
            return 9;
        }

        /* --- 재앙 4: 열화 시프트(바이트 밀림) + IPC 파서 즉시 실패·재동기 전제 --- */
        uint8_t wire[PE::IPC_MAX_FRAME_SIZE]{};
        uint8_t pay[24]{};
        for (uint32_t b = 0u; b < sizeof(pay); ++b) {
            pay[b] = static_cast<uint8_t>(xorshift32(rng) & 0xFFu);
        }
        uint32_t flen = 0u;
        const IPC_Error se = PE::IPC_Serialize_Frame(
            wire,
            static_cast<uint8_t>(iter & 0xFFu),
            IPC_Command::CONFIG_RSP,
            pay,
            static_cast<uint16_t>(8u + (iter % 9u)),
            flen);
        if (se != IPC_Error::OK || flen < 8u) {
            std::printf("APOC[IPC] FAIL: serialize\n");
            return 5;
        }
        const uint32_t shift = 1u + (xorshift32(rng) % 11u);
        uint8_t shifted[PE::IPC_MAX_FRAME_SIZE]{};
        if (flen > shift) {
            std::memcpy(shifted, wire + shift, static_cast<size_t>(flen - shift));
        }
        uint8_t o[PE::IPC_MAX_PAYLOAD]{};
        uint8_t seq = 0u;
        IPC_Command cmd = IPC_Command::PING;
        uint16_t ol = 0u;
        const IPC_Error pe = PE::IPC_Parse_Frame(
            shifted,
            (flen > shift) ? (flen - shift) : 0u,
            seq, cmd, o,
            static_cast<uint16_t>(sizeof(o)), ol);
        if (pe == IPC_Error::OK) {
            std::printf("APOC[THERMAL] FAIL: shifted frame OK\n");
            return 6;
        }

        /* --- 재앙 5: CFI 상태 퍼징(SYN/AUTH/DATA 순서 무시 모델) --- */
        for (int k = 0; k < 6; ++k) {
            cfi = apoc_fuzz_step(cfi, xorshift32(rng));
        }

        /* 키 로테이션: 크로노스와 결합해도 derive 경로 데드락 없음 */
        if ((iter & 63u) == 0u) {
            uint8_t out[32]{};
            size_t olr = 0u;
            if (!kr.deriveNextSeed(iter >> 6u, out, sizeof(out), olr)
                || olr == 0u) {
                std::printf("APOC[KEY] FAIL: derive\n");
                return 7;
            }
        }

        if ((iter & 0xFFu) == 0u) {
            (void)Session_Gateway::Is_Session_Active();
        }
    }

    if (!Crypto_KAT::Run_All_Crypto_KAT()) {
        std::printf("APOC FAIL: Crypto_KAT after apocalypse\n");
        return 8;
    }

    std::printf("Verify_Apocalypse_All: ALL PASS\n");
    return 0;
}
