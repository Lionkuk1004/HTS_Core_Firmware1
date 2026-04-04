// Verify_Heisenbug_Metastable — 15단계: CAS/ABA, 64b tearing 모사, IPC CFI 메타스테이블 경계
// 호스트 x64: std::atomic + fence; split-store 경로는 Cortex-M4 이중 워드 쓰기를 재현해 torn 샘플을 집계

#include "HTS_IPC_Protocol_Defs.h"

#include <atomic>
#include <barrier>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <thread>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace {

namespace PE = ProtectedEngine;

constexpr uint32_t kMask = PE::IPC_RING_MASK;
constexpr uint64_t kVictimCommits = 10'000'000ull;
constexpr uint64_t kVictimMaxIter = 800'000'000ull;
constexpr uint32_t kTearSamples = 2'000'000u;
constexpr uint32_t kAtomicSoak = 10'000'000u;
constexpr uint32_t kMetaRounds = 50'000u;
constexpr uint32_t kMetaSpinCap = 2'000'000u;

[[nodiscard]] uint64_t pack_head(uint32_t stamp, uint32_t idx) noexcept
{
    return (static_cast<uint64_t>(stamp) << 32u)
        | static_cast<uint64_t>(idx & kMask);
}

void aba_aggressor(
    std::atomic<bool>& stop,
    std::atomic<uint64_t>& head) noexcept
{
    while (!stop.load(std::memory_order_acquire)) {
        const uint64_t h = head.load(std::memory_order_acquire);
        const uint32_t idx = static_cast<uint32_t>(h) & kMask;
        const uint32_t st = static_cast<uint32_t>(h >> 32u);
        const uint64_t h1 = pack_head(st + 1u, idx + 1u);
        uint64_t exp = h;
        if (!head.compare_exchange_strong(
                exp, h1, std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            std::this_thread::yield();
            continue;
        }
        const uint64_t h2 = pack_head(st + 2u, idx);
        uint64_t cur = head.load(std::memory_order_acquire);
        (void)head.compare_exchange_strong(
            cur, h2, std::memory_order_acq_rel, std::memory_order_acquire);
        std::this_thread::yield();
    }
}

[[nodiscard]] bool run_aba_tagged_ring(
    uint64_t& out_cas_fail,
    uint64_t& out_integrity_fail) noexcept
{
    std::atomic<uint64_t> head{ pack_head(1u, 0u) };
    alignas(64) std::atomic<uint32_t> cell[PE::IPC_RING_DEPTH]{};
    for (uint32_t i = 0u; i < PE::IPC_RING_DEPTH; ++i) {
        cell[i].store(0u, std::memory_order_relaxed);
    }

    std::atomic<bool> stop{ false };
    std::thread ag(aba_aggressor, std::ref(stop), std::ref(head));

    uint64_t successes = 0u;
    uint64_t cas_fail = 0u;
    uint64_t integ_fail = 0u;
    uint64_t iter = 0u;

    while (successes < kVictimCommits && iter < kVictimMaxIter) {
        ++iter;
        uint64_t h = head.load(std::memory_order_acquire);
        const uint32_t idx = static_cast<uint32_t>(h) & kMask;
        const uint32_t stamp = static_cast<uint32_t>(h >> 32u);
        const uint32_t val = 0xA5A5A5A5u ^ static_cast<uint32_t>(successes);
        cell[idx].store(val, std::memory_order_relaxed);
        std::atomic_thread_fence(std::memory_order_release);
        std::this_thread::yield();
        const uint64_t want = pack_head(stamp + 1u, idx + 1u);
        if (head.compare_exchange_strong(
                h, want, std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            const uint32_t got = cell[idx].load(std::memory_order_relaxed);
            if (got != val) {
                ++integ_fail;
            }
            ++successes;
        }
        else {
            ++cas_fail;
        }
    }

    stop.store(true, std::memory_order_release);
    ag.join();

    out_cas_fail = cas_fail;
    out_integrity_fail = integ_fail;
    return successes == kVictimCommits && integ_fail == 0u;
}

alignas(8) volatile uint32_t g_tear_hi = 0u;
alignas(8) volatile uint32_t g_tear_lo = 0u;

[[nodiscard]] uint64_t run_tearing_observation() noexcept
{
    std::atomic<uint64_t> torn{ 0u };
    std::atomic<bool> wdone{ false };

    std::thread writer([&] {
        for (uint32_t i = 0u; i < kTearSamples; ++i) {
            const uint32_t lo = i * 0x9E3779B9u;
            const uint32_t hi = lo ^ 0xAAAAAAAAu;
            g_tear_hi = hi;
            std::atomic_thread_fence(std::memory_order_release);
            std::this_thread::yield();
#if defined(_MSC_VER)
            _ReadWriteBarrier();
#endif
            g_tear_lo = lo;
        }
        wdone.store(true, std::memory_order_release);
    });

    std::thread reader([&] {
        uint64_t local = 0u;
        while (!wdone.load(std::memory_order_acquire)) {
            const uint32_t lo = g_tear_lo;
            std::atomic_thread_fence(std::memory_order_acquire);
#if defined(_MSC_VER)
            _ReadWriteBarrier();
#endif
            const uint32_t hi = g_tear_hi;
            if ((hi ^ lo) != 0xAAAAAAAAu) {
                ++local;
            }
        }
        torn.store(local, std::memory_order_release);
    });

    writer.join();
    reader.join();
    return torn.load(std::memory_order_acquire);
}

[[nodiscard]] bool run_atomic64_clean() noexcept
{
    std::atomic<uint64_t> wall{ 0u };
    std::atomic<bool> stop{ false };
    std::atomic<uint32_t> inversions{ 0u };

    std::thread w([&] {
        for (uint32_t i = 0u; i < kAtomicSoak; ++i) {
            wall.store(
                static_cast<uint64_t>(i) * 0x100000001ull,
                std::memory_order_release);
            std::this_thread::yield();
        }
        stop.store(true, std::memory_order_release);
    });

    std::thread r([&] {
        uint64_t last = 0u;
        while (!stop.load(std::memory_order_acquire)) {
            const uint64_t v = wall.load(std::memory_order_acquire);
            if (v < last) {
                inversions.fetch_add(1u, std::memory_order_relaxed);
            }
            last = v;
        }
    });

    w.join();
    r.join();
    return inversions.load(std::memory_order_acquire) == 0u;
}

[[nodiscard]] bool run_metastable_fsm() noexcept
{
    std::atomic<uint32_t> st{
        static_cast<uint32_t>(PE::IPC_State::PROCESSING)
    };
    std::barrier phase_a(3u);
    std::barrier phase_b(3u);
    std::atomic<bool> fatal{ false };

    // PROCESSING(Authenticating) -> IDLE(Disconnect) / ERROR_RECOVERY(Timeout): IPC CFI 허용 전이
    static constexpr uint32_t kProc
        = static_cast<uint32_t>(PE::IPC_State::PROCESSING);
    static constexpr uint32_t kIdle
        = static_cast<uint32_t>(PE::IPC_State::IDLE);
    static constexpr uint32_t kErr
        = static_cast<uint32_t>(PE::IPC_State::ERROR_RECOVERY);

    auto worker_disconnect = [&] {
        for (uint32_t r = 0u; r < kMetaRounds; ++r) {
            phase_a.arrive_and_wait();
            uint32_t spins = 0u;
            for (;;) {
                const uint32_t cur = st.load(std::memory_order_acquire);
                if (cur != kProc) {
                    break;
                }
                uint32_t expected = kProc;
                if (st.compare_exchange_weak(
                        expected, kIdle, std::memory_order_acq_rel,
                        std::memory_order_acquire)) {
                    break;
                }
                ++spins;
                if (spins >= kMetaSpinCap) {
                    fatal.store(true, std::memory_order_release);
                    break;
                }
            }
            phase_b.arrive_and_wait();
        }
    };

    auto worker_timeout = [&] {
        for (uint32_t r = 0u; r < kMetaRounds; ++r) {
            phase_a.arrive_and_wait();
            uint32_t spins = 0u;
            for (;;) {
                const uint32_t cur = st.load(std::memory_order_acquire);
                if (cur != kProc) {
                    break;
                }
                uint32_t expected = kProc;
                if (st.compare_exchange_weak(
                        expected, kErr, std::memory_order_acq_rel,
                        std::memory_order_acquire)) {
                    break;
                }
                ++spins;
                if (spins >= kMetaSpinCap) {
                    fatal.store(true, std::memory_order_release);
                    break;
                }
            }
            phase_b.arrive_and_wait();
        }
    };

    std::thread t1(worker_disconnect);
    std::thread t2(worker_timeout);

    for (uint32_t r = 0u; r < kMetaRounds; ++r) {
        st.store(
            static_cast<uint32_t>(PE::IPC_State::PROCESSING),
            std::memory_order_release);
        phase_a.arrive_and_wait();
        phase_b.arrive_and_wait();
        const uint32_t fin = st.load(std::memory_order_acquire);
        const PE::IPC_State fs = static_cast<PE::IPC_State>(fin);
        if (!PE::IPC_Is_Valid_State(fs)) {
            fatal.store(true, std::memory_order_release);
        }
        if (fin != static_cast<uint32_t>(PE::IPC_State::IDLE)
            && fin != static_cast<uint32_t>(PE::IPC_State::ERROR_RECOVERY)) {
            fatal.store(true, std::memory_order_release);
        }
    }

    t1.join();
    t2.join();
    return !fatal.load(std::memory_order_acquire);
}

} // namespace

int main()
{
    std::printf(
        "Verify_Heisenbug_Metastable: ABA %" PRIu64 " commits, tear/atomic/fsm\n",
        kVictimCommits);
    std::fflush(stdout);

    uint64_t cas_fail = 0u;
    uint64_t integ_fail = 0u;
    if (!run_aba_tagged_ring(cas_fail, integ_fail)) {
        std::printf(
            "HEISEN[ABA] FAIL: integ_fail=%" PRIu64 " cas_fail=%" PRIu64 "\n",
            integ_fail, cas_fail);
        return 1;
    }
    std::printf(
        "HEISEN[ABA] PASS: victim_cas_retries=%" PRIu64 " (stamp-tagged head)\n",
        cas_fail);

    const uint64_t torn_obs = run_tearing_observation();
    std::printf(
        "HEISEN[TEAR] split-store inconsistent_xor_reads=%" PRIu64
        " (Heisenbug 육안·데이터; 방어=atomic64 단일 쓰기)\n",
        torn_obs);

    if (!run_atomic64_clean()) {
        std::printf("HEISEN[ATOMIC64] FAIL: monotonic inversion\n");
        return 2;
    }
    std::printf("HEISEN[ATOMIC64] PASS: %" PRIu32 " loads, 0 inversions\n", kAtomicSoak);

    if (!run_metastable_fsm()) {
        std::printf("HEISEN[METASTABLE] FAIL: spin cap or invalid terminal\n");
        return 3;
    }
    std::printf(
        "HEISEN[METASTABLE] PASS: %" PRIu32
        " rounds PROCESSING + simultaneous DISC/TIMEOUT\n",
        kMetaRounds);

    std::printf("Verify_Heisenbug_Metastable: ALL PASS\n");
    return 0;
}
