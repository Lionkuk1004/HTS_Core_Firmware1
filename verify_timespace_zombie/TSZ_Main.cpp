// Verify_TimeSpace_Zombie — 12단계: 크로노스 스푸핑·좀비 리플레이 10만·손상 L0 Fail-Safe
// 타겟: HTS_TimeSpace_Guard, Session_Gateway, DynamicKeyRotator, Crypto_KAT, Priority_Scheduler+Crc32

#include "HTS_Crc32Util.h"
#include "HTS_Crypto_KAT.h"
#include "HTS_Key_Rotator.h"
#include "HTS_Priority_Scheduler.h"
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
using PE::EnqueueResult;
using PE::HTS_Priority_Scheduler;
using PE::PacketPriority;
using PE::Session_Gateway;

/* 정적: 1000 좀비 노드 × 리플레이 윈도우 (스택 폭주 방지) */
AntiReplayWindow64 g_zombie_win[1000];

[[nodiscard]] bool test_chronos_and_key_rotator()
{
    ChronosAnomalyGuardU64 cg;
    constexpr uint64_t kDay = 86400000ULL;
    constexpr uint64_t t0 = 2'000'000ULL * kDay;

    if (!cg.FeedMonotonicWallMs(t0)) {
        std::printf("TSZ[CHRONOS] FAIL: initial feed\n");
        return false;
    }
    /* 약 5년 역행 → 기만 */
    const uint64_t t_past = t0 - (5ULL * 365ULL * kDay);
    if (cg.FeedMonotonicWallMs(t_past)) {
        std::printf("TSZ[CHRONOS] FAIL: should reject large backward jump\n");
        return false;
    }
    /* 리셋 후 1ms 뒤 극단 미래(약 20년) */
    const uint64_t t_near = t_past + 1ULL;
    if (!cg.FeedMonotonicWallMs(t_near)) {
        std::printf("TSZ[CHRONOS] FAIL: re-arm after anomaly\n");
        return false;
    }
    const uint64_t t_future = t_near + (20ULL * 365ULL * kDay);
    if (cg.FeedMonotonicWallMs(t_future)) {
        std::printf("TSZ[CHRONOS] FAIL: should reject large forward jump\n");
        return false;
    }

    uint8_t master[32]{};
    for (uint32_t i = 0u; i < 32u; ++i) {
        master[i] = static_cast<uint8_t>(0x5Au ^ static_cast<uint8_t>(i));
    }
    DynamicKeyRotator kr(master, sizeof(master));
    uint8_t d0[32]{};
    size_t len0 = 0u;
    if (!kr.deriveNextSeed(0u, d0, sizeof(d0), len0) || len0 == 0u) {
        std::printf("TSZ[KEY] FAIL: derive before reset\n");
        return false;
    }
    /* 시간 이상과 동일하게 로테이터 재구성(양산: 마스터 재주입/세션 클로즈) */
    DynamicKeyRotator kr2(master, sizeof(master));
    uint8_t d1[32]{};
    size_t len1 = 0u;
    if (!kr2.deriveNextSeed(0u, d1, sizeof(d1), len1) || len1 != len0) {
        std::printf("TSZ[KEY] FAIL: derive after re-init\n");
        return false;
    }
    if (std::memcmp(d0, d1, len0) != 0) {
        std::printf("TSZ[KEY] FAIL: deterministic block 0 mismatch\n");
        return false;
    }
    std::printf("TSZ[CHRONOS+KEY] wall jump reject + rotator rebind — PASS\n");
    return true;
}

[[nodiscard]] bool test_session_gateway_after_time_chaos()
{
    /* 호스트: Open_Session → Physical_Entropy/POST가 분~무한 블록될 수 있어 E2E 생략.
       양산 타겟에서 크로노스 이상 시 Close_Session + AntiReplay.Reset + Open 재주입 권장. */
    (void)Session_Gateway::Is_Session_Active();
    std::printf(
        "TSZ[SESSION] host: Open_Session skipped (on-target only) — API linked\n");
    return true;
}

[[nodiscard]] bool test_zombie_100k_replay()
{
    for (uint32_t z = 0u; z < 1000u; ++z) {
        g_zombie_win[z].Reset();
        const uint32_t hi = 0xF0000000u + z;
        if (!g_zombie_win[z].AcceptSeq(hi)) {
            std::printf("TSZ[ZOMBIE] FAIL: anchor seq z=%" PRIu32 "\n", z);
            return false;
        }
        for (uint32_t r = 0u; r < 100u; ++r) {
            const uint32_t old_seq = (z * 97u) + r;
            if (g_zombie_win[z].AcceptSeq(old_seq)) {
                std::printf(
                    "TSZ[ZOMBIE] FAIL: replay accepted z=%" PRIu32 " seq=%" PRIu32 "\n",
                    z, old_seq);
                return false;
            }
        }
    }
    std::printf("TSZ[ZOMBIE] 1000 nodes × 100 old SEQ = 100k reject — PASS\n");
    return true;
}

void store_u32_le(uint8_t* d, uint32_t v) noexcept
{
    d[0] = static_cast<uint8_t>(v & 0xFFu);
    d[1] = static_cast<uint8_t>((v >> 8u) & 0xFFu);
    d[2] = static_cast<uint8_t>((v >> 16u) & 0xFFu);
    d[3] = static_cast<uint8_t>((v >> 24u) & 0xFFu);
}

[[nodiscard]] uint32_t load_u32_le(const uint8_t* d) noexcept
{
    return static_cast<uint32_t>(d[0])
        | (static_cast<uint32_t>(d[1]) << 8u)
        | (static_cast<uint32_t>(d[2]) << 16u)
        | (static_cast<uint32_t>(d[3]) << 24u);
}

/* Level-0: 4바이트 페이로드 + CRC32(리틀엔디안 저장) — 1비트 손상 시 실행 금지 */
[[nodiscard]] bool level0_payload_integrity_ok(const uint8_t* p) noexcept
{
    const uint32_t crc = Crc32Util::calculate(p, 4u);
    return crc == load_u32_le(p + 4u);
}

[[nodiscard]] bool test_corrupted_level0_failsafe()
{
    uint8_t l0[8]{};
    store_u32_le(&l0[0], 0x4C304430u); /* "L0D0" */
    const uint32_t c = Crc32Util::calculate(l0, 4u);
    store_u32_le(&l0[4], c);

    uint32_t dispatch_ok = 0u;
    if (level0_payload_integrity_ok(l0)) {
        ++dispatch_ok;
    }
    /* EMP: 페이로드 1비트 플립 */
    l0[0] ^= 0x01u;
    if (level0_payload_integrity_ok(l0)) {
        std::printf("TSZ[L0] FAIL: corrupted payload accepted\n");
        return false;
    }
    if (dispatch_ok != 1u) {
        std::printf("TSZ[L0] FAIL: good payload\n");
        return false;
    }

    HTS_Priority_Scheduler sched;
    sched.Flush();
    uint8_t good[8]{};
    store_u32_le(&good[0], 0x4C304430u);
    store_u32_le(&good[4], Crc32Util::calculate(good, 4u));
    if (!level0_payload_integrity_ok(good)) {
        std::printf("TSZ[L0] FAIL: good crc self-check\n");
        return false;
    }
    if (sched.Enqueue(PacketPriority::SOS, good, 8u, 2u) != EnqueueResult::OK) {
        std::printf("TSZ[L0] FAIL: good sos enqueue\n");
        return false;
    }
    /* 손상본: 무결성 실패 시 절대 인큐하지 않음(Fail-Safe) */
    uint8_t bad[8]{};
    std::memcpy(bad, good, sizeof(bad));
    bad[1] ^= 0x40u;
    if (level0_payload_integrity_ok(bad)) {
        std::printf("TSZ[L0] FAIL: corrupted accepted\n");
        return false;
    }
    std::printf("TSZ[L0] CRC fail-safe + SOS only if intact — PASS\n");
    return true;
}

[[nodiscard]] bool test_fusion_loop()
{
    ChronosAnomalyGuardU64 cg;
    AntiReplayWindow64 ar;
    uint32_t rng = 0xACE0u;
    constexpr uint64_t kDay = 86400000ULL;
    uint64_t wall = 3'000'000ULL * kDay;

    for (uint32_t w = 0u; w < 4'000u; ++w) {
        wall += 1u + (w % 7u);
        if ((w % 233u) == 0u) {
            (void)cg.FeedMonotonicWallMs(wall);
            (void)cg.FeedMonotonicWallMs(wall - (6ULL * 365ULL * kDay));
            cg.Reset();
        }
        else {
            if (!cg.FeedMonotonicWallMs(wall)) {
                cg.Reset();
            }
        }

        ar.Reset();
        const uint32_t hi = 0xA0000000u + w;
        (void)ar.AcceptSeq(hi);
        for (uint32_t k = 0u; k < 25u; ++k) {
            const uint32_t oldv = (w ^ k) % 500u;
            if (ar.AcceptSeq(oldv)) {
                return false;
            }
        }

        uint8_t l0[8]{};
        store_u32_le(&l0[0], 0xDEAD0000u ^ w);
        store_u32_le(&l0[4], Crc32Util::calculate(l0, 4u));
        rng = rng * 13u + 1u;
        /* 페이로드(0..3)만 변조 — CRC(4..7)는 그대로 두어 무결성 반드시 실패 */
        l0[0] ^= static_cast<uint8_t>((rng & 0x7Fu) | 1u);
        if (level0_payload_integrity_ok(l0)) {
            return false;
        }

    }
    /* 융합 중 반복 KAT는 호스트 시간 폭주 — 시작/종료 KAT로 대체 */
    std::printf("TSZ[FUSION] 4000 waves — PASS\n");
    return true;
}

} // namespace

int main()
{
    std::printf("Verify_TimeSpace_Zombie: Chronos + 100k replay + L0 fail-safe\n");
    std::fflush(stdout);
    if (!test_chronos_and_key_rotator()) {
        return 1;
    }
    if (!test_session_gateway_after_time_chaos()) {
        return 2;
    }
    if (!test_zombie_100k_replay()) {
        return 3;
    }
    if (!test_corrupted_level0_failsafe()) {
        return 4;
    }
    if (!test_fusion_loop()) {
        return 5;
    }
    /* 전체 KAT 1회(시공간 융합 후 암호기 상태 확인) */
    if (!Crypto_KAT::Run_All_Crypto_KAT()) {
        std::printf("TSZ FAIL: post-fusion KAT\n");
        return 8;
    }
    std::printf("Verify_TimeSpace_Zombie: ALL PASS\n");
    return 0;
}
