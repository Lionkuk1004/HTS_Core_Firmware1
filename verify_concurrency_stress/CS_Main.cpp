// Verify_Concurrency_Stress — 호스트 MPSC IPC TX 링(A55 동일 CAS+commit) + 우선순위 스케줄러 + V400 단일소비자 경로
// STM32 SPSC 링은 설계상 다중 생산자 미지원 — 스트레스 대상은 A55 MPSC 알고리즘 에뮬.

#include "HTS_IPC_Protocol_Defs.h"
#include "HTS_Priority_Scheduler.h"
#include "HTS_V400_Dispatcher.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

namespace {

using namespace ProtectedEngine;

constexpr unsigned kThreads = 100u;
constexpr uint32_t kTotalTx = 100000u;

// MPSC TX 링 (깊이 1024 — 양산 IPC_RING_DEPTH=8 과 별도; 알고리즘 동일 검증용)
constexpr uint32_t kStressDepth = 1024u;
constexpr uint32_t kStressMask = kStressDepth - 1u;
static_assert((kStressDepth & kStressMask) == 0u, "power of 2");

alignas(64) IPC_Ring_Entry g_tx_ring[kStressDepth]{};
std::atomic<uint32_t> g_tx_head{0u};
std::atomic<uint32_t> g_tx_commit{0u};
std::atomic<uint32_t> g_tx_tail{0u};

constexpr uint64_t kFnvOffset = 14695981039346656037ULL;
constexpr uint64_t kFnvPrime = 1099511628211ULL;

[[nodiscard]] static uint64_t fnv1a64(const uint8_t* p, size_t n) noexcept {
    uint64_t h = kFnvOffset;
    for (size_t i = 0u; i < n; ++i) {
        h ^= static_cast<uint64_t>(p[i]);
        h *= kFnvPrime;
    }
    return h;
}

/// 가변 길이 페이로드: LE32 id + 패턴 (IPC_MAX_FRAME_SIZE 이하)
[[nodiscard]] static uint16_t fill_payload(uint32_t id, uint8_t* buf) noexcept {
    const uint32_t span = static_cast<uint32_t>(IPC_MAX_FRAME_SIZE) - 4u;
    const uint16_t extra = static_cast<uint16_t>(id % (span + 1u));
    const uint16_t len = static_cast<uint16_t>(4u + extra);
    buf[0] = static_cast<uint8_t>(id & 0xFFu);
    buf[1] = static_cast<uint8_t>((id >> 8) & 0xFFu);
    buf[2] = static_cast<uint8_t>((id >> 16) & 0xFFu);
    buf[3] = static_cast<uint8_t>((id >> 24) & 0xFFu);
    for (uint16_t i = 4u; i < len; ++i) {
        buf[static_cast<size_t>(i)] =
            static_cast<uint8_t>((static_cast<uint32_t>(id) + static_cast<uint32_t>(i)) * 0x9Eu + 0x5Bu);
    }
    return len;
}

[[nodiscard]] static uint64_t golden_hash_sum() noexcept {
    alignas(8) uint8_t buf[IPC_MAX_FRAME_SIZE]{};
    uint64_t acc = 0u;
    for (uint32_t id = 0u; id < kTotalTx; ++id) {
        const uint16_t len = fill_payload(id, buf);
        acc += fnv1a64(buf, static_cast<size_t>(len));
    }
    return acc;
}

[[nodiscard]] static bool stress_tx_push(const uint8_t* data, uint16_t len) noexcept {
    uint32_t head = 0u;
    uint32_t next_head = 0u;
    do {
        head = g_tx_head.load(std::memory_order_acquire);
        const uint32_t tail = g_tx_tail.load(std::memory_order_acquire);
        if ((head - tail) >= kStressDepth) {
            return false;
        }
        next_head = head + 1u;
    } while (!g_tx_head.compare_exchange_weak(
        head, next_head, std::memory_order_acq_rel, std::memory_order_acquire));

    IPC_Ring_Entry& entry = g_tx_ring[static_cast<size_t>(head & kStressMask)];
    const uint32_t copy_len = (static_cast<uint32_t>(len) <= IPC_MAX_FRAME_SIZE)
        ? static_cast<uint32_t>(len)
        : IPC_MAX_FRAME_SIZE;
    for (uint32_t i = 0u; i < copy_len; ++i) {
        entry.data[i] = data[i];
    }
    entry.length = static_cast<uint16_t>(copy_len);

    while (g_tx_commit.load(std::memory_order_acquire) != head) {
        std::this_thread::yield();
    }
    g_tx_commit.store(next_head, std::memory_order_release);
    return true;
}

[[nodiscard]] static bool stress_tx_pop(uint8_t* data, uint16_t buf_size, uint16_t& out_len) noexcept {
    const uint32_t head = g_tx_commit.load(std::memory_order_acquire);
    const uint32_t tail = g_tx_tail.load(std::memory_order_relaxed);
    if (head == tail) {
        out_len = 0u;
        return false;
    }
    const IPC_Ring_Entry& entry = g_tx_ring[static_cast<size_t>(tail & kStressMask)];
    const uint16_t copy_len = (entry.length <= buf_size) ? entry.length : buf_size;
    if (data != nullptr) {
        for (uint16_t i = 0u; i < copy_len; ++i) {
            data[static_cast<size_t>(i)] = entry.data[static_cast<size_t>(i)];
        }
    }
    out_len = copy_len;
    g_tx_tail.store(tail + 1u, std::memory_order_release);
    return true;
}

[[nodiscard]] static bool run_mpsc_stress() {
    const uint64_t expect_sum = golden_hash_sum();
    g_tx_head.store(0u, std::memory_order_relaxed);
    g_tx_commit.store(0u, std::memory_order_relaxed);
    g_tx_tail.store(0u, std::memory_order_relaxed);
    for (uint32_t i = 0u; i < kStressDepth; ++i) {
        IPC_Secure_Wipe(&g_tx_ring[static_cast<size_t>(i)], static_cast<uint32_t>(sizeof(IPC_Ring_Entry)));
    }

    std::atomic<uint32_t> next_id{0u};
    std::atomic<uint32_t> pop_count{0u};
    std::atomic<uint64_t> recv_hash{0u};
    std::atomic<bool> consumer_done{false};

    std::thread consumer([&]() {
        alignas(8) uint8_t buf[IPC_MAX_FRAME_SIZE]{};
        uint64_t local_acc = 0u;
        while (pop_count.load(std::memory_order_relaxed) < kTotalTx) {
            uint16_t len = 0u;
            if (stress_tx_pop(buf, static_cast<uint16_t>(sizeof(buf)), len) && len > 0u) {
                local_acc += fnv1a64(buf, static_cast<size_t>(len));
                pop_count.fetch_add(1u, std::memory_order_relaxed);
            } else {
                std::this_thread::yield();
            }
        }
        recv_hash.store(local_acc, std::memory_order_release);
        consumer_done.store(true, std::memory_order_release);
    });

    std::vector<std::thread> producers;
    producers.reserve(static_cast<size_t>(kThreads));
    for (unsigned t = 0u; t < kThreads; ++t) {
        (void)t;
        producers.emplace_back([&]() {
            alignas(8) uint8_t buf[IPC_MAX_FRAME_SIZE]{};
            for (;;) {
                const uint32_t id = next_id.fetch_add(1u, std::memory_order_relaxed);
                if (id >= kTotalTx) {
                    break;
                }
                const uint16_t len = fill_payload(id, buf);
                while (!stress_tx_push(buf, len)) {
                    std::this_thread::yield();
                }
            }
        });
    }

    for (auto& th : producers) {
        th.join();
    }
    consumer.join();

    if (!consumer_done.load(std::memory_order_acquire)) {
        std::fputs("CS: consumer flag not set\n", stderr);
        return false;
    }
    if (pop_count.load(std::memory_order_relaxed) != kTotalTx) {
        std::fprintf(stderr, "CS: pop_count=%u expected %u\n",
            pop_count.load(std::memory_order_relaxed), kTotalTx);
        return false;
    }
    const uint64_t got = recv_hash.load(std::memory_order_acquire);
    if (got != expect_sum) {
        std::fprintf(stderr, "CS: MPSC hash mismatch got=%llu expect=%llu\n",
            static_cast<unsigned long long>(got),
            static_cast<unsigned long long>(expect_sum));
        return false;
    }
    std::puts("CS: MPSC TX ring (CAS+commit) — 100 threads, 100k msgs, hash OK");
    return true;
}

[[nodiscard]] static PacketPriority prio_for_id(uint32_t id) noexcept {
    const uint32_t m = id % 3u;
    if (m == 0u) {
        return PacketPriority::SOS;
    }
    if (m == 1u) {
        return PacketPriority::VOICE;
    }
    return PacketPriority::DATA;
}

[[nodiscard]] static bool run_scheduler_stress() {
    HTS_Priority_Scheduler sched;
    std::atomic<uint32_t> next_id{0u};
    std::atomic<uint32_t> deq_n{0u};
    std::vector<uint32_t> collected;
    collected.reserve(static_cast<size_t>(kTotalTx));
    std::mutex col_mu;

    std::vector<std::thread> workers;
    workers.reserve(static_cast<size_t>(kThreads));

    for (unsigned t = 0u; t < kThreads / 2u; ++t) {
        (void)t;
        workers.emplace_back([&]() {
            alignas(8) uint8_t d[HTS_Priority_Scheduler::MAX_PACKET_DATA]{};
            for (;;) {
                const uint32_t id = next_id.fetch_add(1u, std::memory_order_relaxed);
                if (id >= kTotalTx) {
                    break;
                }
                d[0] = static_cast<uint8_t>(id & 0xFFu);
                d[1] = static_cast<uint8_t>((id >> 8) & 0xFFu);
                d[2] = static_cast<uint8_t>((id >> 16) & 0xFFu);
                d[3] = static_cast<uint8_t>((id >> 24) & 0xFFu);
                d[4] = static_cast<uint8_t>(static_cast<uint8_t>(id) ^ 0xA5u);
                d[5] = 0u;
                d[6] = 0u;
                d[7] = 0u;
                const PacketPriority pr = prio_for_id(id);
                while (sched.Enqueue(pr, d, HTS_Priority_Scheduler::MAX_PACKET_DATA, id)
                    != EnqueueResult::OK) {
                    std::this_thread::yield();
                }
            }
        });
    }

    for (unsigned t = 0u; t < kThreads / 2u; ++t) {
        (void)t;
        workers.emplace_back([&]() {
            alignas(8) uint8_t ob[HTS_Priority_Scheduler::MAX_PACKET_DATA]{};
            size_t ol = 0u;
            PacketPriority pr = PacketPriority::DATA;
            for (;;) {
                if (deq_n.load(std::memory_order_relaxed) >= kTotalTx) {
                    break;
                }
                if (sched.Dequeue(ob, ol, pr)) {
                    const uint32_t id = static_cast<uint32_t>(ob[0])
                        | (static_cast<uint32_t>(ob[1]) << 8)
                        | (static_cast<uint32_t>(ob[2]) << 16)
                        | (static_cast<uint32_t>(ob[3]) << 24);
                    {
                        std::lock_guard<std::mutex> lk(col_mu);
                        collected.push_back(id);
                    }
                    deq_n.fetch_add(1u, std::memory_order_relaxed);
                } else {
                    std::this_thread::yield();
                }
            }
        });
    }

    for (auto& th : workers) {
        th.join();
    }

    while (collected.size() < static_cast<size_t>(kTotalTx)) {
        alignas(8) uint8_t ob[HTS_Priority_Scheduler::MAX_PACKET_DATA]{};
        size_t ol = 0u;
        PacketPriority pr = PacketPriority::DATA;
        if (sched.Dequeue(ob, ol, pr)) {
            const uint32_t id = static_cast<uint32_t>(ob[0])
                | (static_cast<uint32_t>(ob[1]) << 8)
                | (static_cast<uint32_t>(ob[2]) << 16)
                | (static_cast<uint32_t>(ob[3]) << 24);
            collected.push_back(id);
            deq_n.fetch_add(1u, std::memory_order_relaxed);
        } else {
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }
    }

    if (collected.size() != static_cast<size_t>(kTotalTx)) {
        std::fprintf(stderr, "CS: scheduler collected %zu expected %u\n",
            collected.size(), kTotalTx);
        return false;
    }
    std::sort(collected.begin(), collected.end());
    for (uint32_t i = 0u; i < kTotalTx; ++i) {
        if (collected[static_cast<size_t>(i)] != i) {
            std::fprintf(stderr, "CS: scheduler order/id mismatch at %u got %u\n",
                i, collected[static_cast<size_t>(i)]);
            return false;
        }
    }
    std::puts("CS: Priority_Scheduler — 50 enq + 50 deq threads, 100k ids multiset OK");
    return true;
}

[[nodiscard]] static bool run_v400_stress() {
    std::mutex disp_mu;
    HTS_V400_Dispatcher disp;
    disp.Set_Seed(0xC0DEF00Du);
    std::atomic<uint32_t> feed_slot{0u};

    std::vector<std::thread> pool;
    pool.reserve(static_cast<size_t>(kThreads));
    for (unsigned t = 0u; t < kThreads; ++t) {
        (void)t;
        pool.emplace_back([&]() {
            for (;;) {
                const uint32_t n = feed_slot.fetch_add(1u, std::memory_order_relaxed);
                if (n >= kTotalTx) {
                    break;
                }
                std::lock_guard<std::mutex> lk(disp_mu);
                disp.Feed_Chip(static_cast<int16_t>(n & 0xFFFFu),
                    static_cast<int16_t>((n >> 16) & 0xFFFFu));
            }
        });
    }
    for (auto& th : pool) {
        th.join();
    }
    std::puts("CS: V400_Dispatcher — 100 mutex-serialized Feed_Chip x 100k (단일 인스턴스) OK");
    return true;
}

} // namespace

int main() {
    if (!run_mpsc_stress()) {
        return 1;
    }
    if (!run_scheduler_stress()) {
        return 2;
    }
    if (!run_v400_stress()) {
        return 3;
    }
    std::puts("Verify_Concurrency_Stress: ALL checks PASSED");
    return 0;
}
