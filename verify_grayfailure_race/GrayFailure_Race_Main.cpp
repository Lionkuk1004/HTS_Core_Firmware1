// Verify_GrayFailure_Race — 14단계: 회색 장애(Heartbeat 기만) + 비동기 ISR 레이스 + 암호 Split-Brain
// 호스트(x64) 단일 프로세스: Session_Gateway, DynamicKeyRotator, HTS_Security_Session(MAC), std::atomic

#include "HTS_Key_Rotator.h"
#include "HTS_POST_Manager.h"
#include "HTS_Security_Session.h"
#include "HTS_Session_Gateway.hpp"

#include <atomic>
#include <barrier>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>

namespace {

namespace PE = ProtectedEngine;

using PE::CipherAlgorithm;
using PE::DynamicKeyRotator;
using PE::HTS_Security_Session;
using PE::MacAlgorithm;
using PE::Session_Gateway;

constexpr uint32_t kFusedIters = 50'000u;
constexpr uint32_t kPerThreadIncr = 25'000u;
constexpr uint32_t kMacRetryStorm = 10'000u;
constexpr uint64_t kPendingCapBytes = 256u * 1024u;
constexpr uint32_t kGrayMinBulk = 400u;

[[nodiscard]] uint32_t lcg32(uint64_t& s) noexcept
{
    s = s * 6364136223843003009ULL + 1ULL;
    return static_cast<uint32_t>(s >> 33u);
}

/// 악몽 1: Ping/Heartbeat는 항상 양호(1ms 틱)로 계산. 대용량은 99% 손상 + 5s+ 지터 시뮬레이션.
/// 유효 페이로드 비율이 임계 미만이거나 가상 버퍼가 한계를 넘으면 Eviction(좀비 커넥션 차단).
struct GrayFailureLink {
    uint64_t rng = 0xC0FFEEABAD1DEAULL;
    uint32_t ping_ticks = 0u;
    uint32_t bulk_seen = 0u;
    uint32_t bulk_valid = 0u;
    uint64_t pending_virtual = 0u;
    bool     evicted = false;

    void tick_heartbeat_ok_1ms() noexcept
    {
        if (evicted) {
            return;
        }
        ++ping_ticks;
    }

    void tick_bulk_payload() noexcept
    {
        if (evicted) {
            return;
        }
        ++bulk_seen;
        const uint32_t r = lcg32(rng) % 100u;
        const bool payload_ok = (r == 0u);
        const uint32_t jitter_ms
            = payload_ok ? 1u : (5000u + (lcg32(rng) % 2000u));
        (void)jitter_ms;
        const uint32_t plen = 512u + (lcg32(rng) & 0x3FFu);
        if (payload_ok) {
            ++bulk_valid;
            pending_virtual
                = (pending_virtual > static_cast<uint64_t>(plen))
                ? (pending_virtual - static_cast<uint64_t>(plen))
                : 0u;
        }
        else {
            pending_virtual += static_cast<uint64_t>(plen);
        }
        if (bulk_seen >= kGrayMinBulk) {
            const uint32_t pct_x100
                = (bulk_valid * 100u) / (bulk_seen ? bulk_seen : 1u);
            if (pct_x100 < 5u) {
                evicted = true;
            }
        }
        if (pending_virtual > kPendingCapBytes) {
            evicted = true;
        }
    }
};

[[nodiscard]] bool run_isr_packed_cas_race() noexcept
{
    constexpr uint64_t kMask = (1ULL << 20u) - 1ULL;
    std::atomic<uint64_t> pack{ 0u };

    auto bump_field = [&pack](uint64_t delta) noexcept {
        for (uint32_t n = 0u; n < kPerThreadIncr; ++n) {
            uint64_t exp = pack.load(std::memory_order_relaxed);
            for (;;) {
                const uint64_t cur = exp;
                const uint64_t w = cur & kMask;
                const uint64_t f = (cur >> 20u) & kMask;
                const uint64_t d = (cur >> 40u) & kMask;
                uint64_t nxt = 0u;
                constexpr uint64_t kD0 = 1ULL;
                constexpr uint64_t kD1 = 1ULL << 20u;
                constexpr uint64_t kD2 = 1ULL << 40u;
                if (delta == kD0) {
                    nxt = ((w + 1u) & kMask) | (f << 20u) | (d << 40u);
                }
                else if (delta == kD1) {
                    nxt = (w) | (((f + 1u) & kMask) << 20u) | (d << 40u);
                }
                else if (delta == kD2) {
                    nxt = (w) | (f << 20u) | (((d + 1u) & kMask) << 40u);
                }
                else {
                    nxt = cur;
                }
                if (pack.compare_exchange_weak(
                        exp, nxt, std::memory_order_acq_rel,
                        std::memory_order_relaxed)) {
                    break;
                }
            }
        }
    };

    std::barrier start(3u);
    std::thread t0([&] {
        start.arrive_and_wait();
        bump_field(1ULL);
    });
    std::thread t1([&] {
        start.arrive_and_wait();
        bump_field(1ULL << 20u);
    });
    std::thread t2([&] {
        start.arrive_and_wait();
        bump_field(1ULL << 40u);
    });
    t0.join();
    t1.join();
    t2.join();

    const uint64_t v = pack.load(std::memory_order_acquire);
    const uint64_t w = v & kMask;
    const uint64_t f = (v >> 20u) & kMask;
    const uint64_t d = (v >> 40u) & kMask;
    if (w != static_cast<uint64_t>(kPerThreadIncr)
        || f != static_cast<uint64_t>(kPerThreadIncr)
        || d != static_cast<uint64_t>(kPerThreadIncr)) {
        std::printf(
            "GRAY[ISR_CAS] FAIL: w=%" PRIu64 " f=%" PRIu64 " d=%" PRIu64 "\n",
            w, f, d);
        return false;
    }
    return true;
}

[[nodiscard]] bool run_isr_fetch_add_sanity() noexcept
{
    std::atomic<uint32_t> wdt{ 0u };
    std::atomic<uint32_t> fault{ 0u };
    std::atomic<uint32_t> dma{ 0u };
    std::barrier start(3u);

    std::thread a([&] {
        start.arrive_and_wait();
        for (uint32_t i = 0u; i < kPerThreadIncr; ++i) {
            wdt.fetch_add(1u, std::memory_order_relaxed);
        }
    });
    std::thread b([&] {
        start.arrive_and_wait();
        for (uint32_t i = 0u; i < kPerThreadIncr; ++i) {
            fault.fetch_add(1u, std::memory_order_relaxed);
        }
    });
    std::thread c([&] {
        start.arrive_and_wait();
        for (uint32_t i = 0u; i < kPerThreadIncr; ++i) {
            dma.fetch_add(1u, std::memory_order_relaxed);
        }
    });
    a.join();
    b.join();
    c.join();

    const uint32_t sum = wdt.load(std::memory_order_acquire)
        + fault.load(std::memory_order_acquire)
        + dma.load(std::memory_order_acquire);
    const uint32_t expect = kPerThreadIncr * 3u;
    if (sum != expect) {
        std::printf(
            "GRAY[ISR_ADD] FAIL: sum=%" PRIu32 " expect=%" PRIu32 "\n",
            sum, expect);
        return false;
    }
    return true;
}

[[nodiscard]] bool run_key_rotator_contend(DynamicKeyRotator& kr) noexcept
{
    std::barrier start(3u);
    std::atomic<int> errs{ 0 };
    auto worker = [&] {
        start.arrive_and_wait();
        uint8_t out[32]{};
        for (uint32_t i = 0u; i < 800u; ++i) {
            size_t ol = 0u;
            if (!kr.deriveNextSeed(i & 0x3Fu, out, sizeof(out), ol)
                || ol != 32u) {
                errs.fetch_add(1, std::memory_order_relaxed);
            }
        }
    };
    std::thread x(worker);
    std::thread y(worker);
    std::thread z(worker);
    x.join();
    y.join();
    z.join();
    return errs.load(std::memory_order_acquire) == 0;
}

[[nodiscard]] bool run_split_brain_mac_hard_stop() noexcept
{
    uint8_t enc_v1[32]{};
    uint8_t mac_v1[32]{};
    uint8_t enc_v2[32]{};
    uint8_t mac_v2[32]{};
    uint8_t iv[16]{};
    for (uint32_t i = 0u; i < 32u; ++i) {
        enc_v1[i] = static_cast<uint8_t>(0x11u ^ static_cast<uint8_t>(i));
        mac_v1[i] = static_cast<uint8_t>(0x22u ^ static_cast<uint8_t>(i));
        enc_v2[i] = static_cast<uint8_t>(0xEEu ^ static_cast<uint8_t>(i));
        mac_v2[i] = static_cast<uint8_t>(0xDDu ^ static_cast<uint8_t>(i));
    }
    for (uint32_t i = 0u; i < 16u; ++i) {
        iv[i] = static_cast<uint8_t>(0x55u ^ static_cast<uint8_t>(i));
    }

    HTS_Security_Session sess_tx;
    HTS_Security_Session sess_rx;
    if (!sess_tx.Initialize(
            CipherAlgorithm::LEA_256_CTR, MacAlgorithm::HMAC_SHA256,
            enc_v2, mac_v2, iv)) {
        std::printf("GRAY[SPLIT] FAIL: tx init\n");
        return false;
    }
    if (!sess_rx.Initialize(
            CipherAlgorithm::LEA_256_CTR, MacAlgorithm::HMAC_SHA256,
            enc_v1, mac_v1, iv)) {
        std::printf("GRAY[SPLIT] FAIL: rx init\n");
        return false;
    }

    alignas(8) uint8_t pt[64]{};
    alignas(8) uint8_t ct[64]{};
    uint8_t tag[32]{};
    alignas(8) uint8_t out[64]{};
    for (uint32_t i = 0u; i < sizeof(pt); ++i) {
        pt[i] = static_cast<uint8_t>(0xA5u ^ static_cast<uint8_t>(i));
    }

    if (!sess_tx.Protect_Payload(pt, sizeof(pt), ct, tag)) {
        std::printf("GRAY[SPLIT] FAIL: protect\n");
        return false;
    }
    if (sess_rx.Unprotect_Payload(ct, sizeof(ct), tag, out)) {
        std::printf("GRAY[SPLIT] FAIL: MAC should fail (V1 vs V2)\n");
        return false;
    }
    if (sess_rx.Is_Active()) {
        std::printf("GRAY[SPLIT] FAIL: session still active after MAC fail\n");
        return false;
    }
    for (uint32_t r = 0u; r < kMacRetryStorm; ++r) {
        if (sess_rx.Unprotect_Payload(ct, sizeof(ct), tag, out)) {
            std::printf("GRAY[SPLIT] FAIL: retry %" PRIu32 " should fail\n", r);
            return false;
        }
    }
    return true;
}

} // namespace

int main()
{
    std::printf(
        "Verify_GrayFailure_Race: fused %" PRIu32 " iters + ISR + split-brain\n",
        kFusedIters);
    std::fflush(stdout);

    PE::POST_Manager::executePowerOnSelfTest();
    Session_Gateway::Open_Session();
    if (!Session_Gateway::Is_Session_Active()) {
        std::printf("GRAY FAIL: session not active\n");
        return 1;
    }

    alignas(8) uint8_t master[32]{};
    for (uint32_t i = 0u; i < 32u; ++i) {
        master[i] = static_cast<uint8_t>(0x71u ^ static_cast<uint8_t>(i));
    }
    const size_t dlen = Session_Gateway::Derive_Session_Material(
        Session_Gateway::DOMAIN_ANCHOR_HMAC, master, sizeof(master));
    if (dlen != sizeof(master)) {
        std::printf("GRAY FAIL: Derive_Session_Material\n");
        Session_Gateway::Close_Session();
        return 2;
    }

    DynamicKeyRotator kr(master, sizeof(master));
    std::memset(master, 0, sizeof(master));

    GrayFailureLink gray{};

    for (uint32_t iter = 0u; iter < kFusedIters; ++iter) {
        gray.tick_heartbeat_ok_1ms();
        gray.tick_bulk_payload();

        if ((iter & 63u) == 0u) {
            uint8_t out[32]{};
            size_t ol = 0u;
            if (!kr.deriveNextSeed(iter >> 6u, out, sizeof(out), ol)
                || ol != 32u) {
                std::printf("GRAY[KR] FAIL: derive %" PRIu32 "\n", iter);
                Session_Gateway::Close_Session();
                return 3;
            }
        }

        if ((iter & 0xFFu) == 0u) {
            (void)Session_Gateway::Is_Session_Active();
        }
    }

    if (!gray.evicted) {
        std::printf(
            "GRAY[HEARTBEAT_TRAP] FAIL: deceptive node not evicted "
            "(bulk=%" PRIu32 " ok=%" PRIu32 ")\n",
            gray.bulk_seen, gray.bulk_valid);
        Session_Gateway::Close_Session();
        return 4;
    }

    if (!run_isr_fetch_add_sanity()) {
        Session_Gateway::Close_Session();
        return 5;
    }
    if (!run_isr_packed_cas_race()) {
        Session_Gateway::Close_Session();
        return 6;
    }
    if (!run_key_rotator_contend(kr)) {
        std::printf("GRAY[KR_RACE] FAIL\n");
        Session_Gateway::Close_Session();
        return 7;
    }
    if (!run_split_brain_mac_hard_stop()) {
        Session_Gateway::Close_Session();
        return 8;
    }

    Session_Gateway::Close_Session();
    std::printf("Verify_GrayFailure_Race: ALL PASS\n");
    return 0;
}
