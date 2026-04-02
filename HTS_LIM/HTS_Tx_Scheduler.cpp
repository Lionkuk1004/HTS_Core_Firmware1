// =========================================================================
// HTS_Tx_Scheduler.cpp — B-CDMA TX 전송 스케줄러 (Pimpl 은닉)
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
#include "HTS_Tx_Scheduler.hpp"
#include "HTS_Dynamic_Config.h"
#include "HTS_Secure_Memory.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

namespace ProtectedEngine {
    // ── [BUG-67] 2의 제곱수 올림 (플랫폼별 링 버퍼 상한) ──
    //
    //  ARM (EMBEDDED_MINI): node_count=256 → raw_cap=1024 → ring_size=1024
    //    MAX_RING_POW2 = 2048 (ring_size 1024 수용 + 여유 1024 요소)
    //    tx_ring_buffer[2048] × 4B = 8KB
    //
    //  PC (STANDARD+): node_count=1024+ → ring_size ≤ 16384
    //    MAX_RING_POW2 = 16384
    //    tx_ring_buffer[16384] × 4B = 64KB
    //
#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
    static constexpr size_t MAX_RING_POW2 = static_cast<size_t>(1u) << 11u;  // 2048
#else
    static constexpr size_t MAX_RING_POW2 = static_cast<size_t>(1u) << 14u;  // 16384
#endif

    static_assert(MAX_RING_POW2 <= (SIZE_MAX >> 1u),
        "SPSC Free-running: capacity must be <= SIZE_MAX/2");
    static_assert((MAX_RING_POW2 << 2u) > MAX_RING_POW2,
        "size << 2u must not overflow size_t");

    static size_t Next_Power_Of_Two(size_t v) noexcept {
        if (v == 0u) { return 1u; }
        if (v > MAX_RING_POW2) { return MAX_RING_POW2; }
        v--;
        v |= v >> 1u;  v |= v >> 2u;
        v |= v >> 4u;  v |= v >> 8u;
        v |= v >> 16u;
#if SIZE_MAX > 0xFFFFFFFFu
        v |= v >> 32u;
#endif
        v++;
        return v;
    }

    // ── [BUG-67] 정렬 상수 (플랫폼별) ──
    //  ARM Cortex-M4: 단일 코어, L1 데이터 캐시 없음 → False Sharing 불가
    //                 alignas(4) 충분 → 128B → 8B 절감
    //  PC x86/x64:    멀티 코어, L1 캐시 라인 64B → False Sharing 방어 필요
#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
    static constexpr size_t CACHELINE = 8u;    // Cortex-M4: 단일 코어
#else
    static constexpr size_t CACHELINE = 64u;   // PC: 캐시 라인 64B
#endif

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4324)
#endif
    // ── 정렬된 원자 인덱스 (멀티 코어 환경 False Sharing 차단) ──
    struct alignas(CACHELINE) AlignedIndex {
        std::atomic<size_t> val{ 0 };
    };

    // =====================================================================
    //  Pimpl 구현체 — 링 버퍼 + SPSC 인덱스 완전 은닉
    //
    //  tx_ring_buffer: 정적 배열 MAX_RING_POW2 (B-1 힙금지 준수)
    //  AlignedIndex:   alignas(64) × 2 → Impl 전체 alignof = 64
    //                  → impl_buf_ alignas(64) 필수 (헤더에서 보장)
    // =====================================================================
    struct HTS_Tx_Scheduler::Impl {
        HTS_Sys_Config              current_config = {};
        // MAX_RING_POW2 = 16384 × 4B = 64KB
        // ⚠ sizeof(Impl) ≈ 64KB + metadata → IMPL_BUF_SIZE 확대 필수
        //    전역/정적 배치 필수 (스택 배치 금지)
        int32_t                     tx_ring_buffer[MAX_RING_POW2] = {};
        size_t                      ring_mask = 0u;
        size_t                      ring_capacity = 0u;
        AlignedIndex                write_idx;
        AlignedIndex                read_idx;
        std::atomic<bool>           is_active{ false };

        explicit Impl(HTS_Sys_Tier tier) noexcept
            : current_config(HTS_Sys_Config_Factory::Get_Tier_Profile(tier)) {
        }

        ~Impl() noexcept {
            is_active.store(false, std::memory_order_release);
            std::atomic_thread_fence(std::memory_order_release);

            if (ring_mask > 0u) {
                const size_t nwords = ring_mask + 1u;
                if (nwords <= MAX_RING_POW2) {
                    SecureMemory::secureWipe(
                        static_cast<void*>(tx_ring_buffer), nwords << 2u);
                }
            }

            write_idx.val.store(0, std::memory_order_relaxed);
            read_idx.val.store(0, std::memory_order_relaxed);
            std::atomic_thread_fence(std::memory_order_release);
            // std::atomic 멤버에 memset/바이트 소거는 UB — store(0)만 사용 (V-3-13 유사)

            SecureMemory::secureWipe(
                static_cast<void*>(&current_config), sizeof(current_config));
            std::atomic_thread_fence(std::memory_order_release);
        }
    };
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

    // =====================================================================
    //
    //  static_assert가 get_impl() 내부에 있으므로 Impl 완전 정의 후 평가
    //  → sizeof(Impl), alignof(Impl) 모두 안전하게 접근 가능
    // =====================================================================
    HTS_Tx_Scheduler::Impl* HTS_Tx_Scheduler::get_impl() noexcept {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE를 초과합니다 — IMPL_BUF_SIZE 확대 필요");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 요구가 impl_buf_ alignas(64)를 초과합니다");
        return impl_valid_.load(std::memory_order_acquire)
            ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }

    const HTS_Tx_Scheduler::Impl* HTS_Tx_Scheduler::get_impl() const noexcept {
        return impl_valid_.load(std::memory_order_acquire)
            ? reinterpret_cast<const Impl*>(impl_buf_)
            : nullptr;
    }

    // =====================================================================
    //  Impl(tier) 생성자는 noexcept → 예외 없이 안전
    // =====================================================================
    HTS_Tx_Scheduler::HTS_Tx_Scheduler(HTS_Sys_Tier tier) noexcept
    {
        impl_valid_.store(false, std::memory_order_release);
        SecureMemory::secureWipe(static_cast<void*>(impl_buf_), sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl(tier);
        impl_valid_.store(true, std::memory_order_release);
    }

    // =====================================================================
    //  Impl 소멸자(내부 secureWipe) 호출 → impl_buf_ 전체 SecureMemory::secureWipe → 플래그 무효화
    // =====================================================================
    HTS_Tx_Scheduler::~HTS_Tx_Scheduler() noexcept {
        Impl* p = get_impl();
        if (p != nullptr) {
            p->~Impl();
        }
        SecureMemory::secureWipe(impl_buf_, sizeof(impl_buf_));
        impl_valid_ = false;
    }

    // =====================================================================
    //  Initialize — 링 버퍼 메모리 할당
    // =====================================================================
    [[nodiscard]] bool HTS_Tx_Scheduler::Initialize() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return false; }
        auto& impl = *p;

        impl.is_active.store(false, std::memory_order_release);
        std::atomic_thread_fence(std::memory_order_release);

        if (impl.current_config.temporal_slice_chunk == 0u) { return false; }
        if (impl.current_config.node_count == 0u) { return false; }

        const uint32_t nc = impl.current_config.node_count;
        const size_t raw_cap = (nc > static_cast<uint32_t>(MAX_RING_POW2 >> 2u))
            ? MAX_RING_POW2
            : static_cast<size_t>(nc) << 2u;

        const size_t ring_size = Next_Power_Of_Two(raw_cap);

        // ring_size ≤ MAX_RING_POW2 보장 (Next_Power_Of_Two 클램프)
        if (impl.ring_mask > 0u) {
            const size_t old_phys = impl.ring_mask + 1u;
            if (old_phys > (SIZE_MAX >> 2u)) { return false; }
            const size_t old_bytes = old_phys << 2u;
            SecureMemory::secureWipe(
                static_cast<void*>(impl.tx_ring_buffer), old_bytes);
        }
        if (ring_size > (SIZE_MAX >> 2u)) { return false; }
        const size_t init_bytes = ring_size << 2u;
        SecureMemory::secureWipe(
            static_cast<void*>(impl.tx_ring_buffer), init_bytes);

        impl.ring_mask = ring_size - 1u;
        //  단조 카운터 방식이지만, ISR 컨텍스트 스위칭 중
        //  read/write 동시 접근 시 phy_read==phy_write → 풀/빈 모호성 방어
        //  비용: 1슬롯(4B) 미사용 — 안전성 대비 무시 가능
        impl.ring_capacity = ring_size - 1u;
        std::atomic_thread_fence(std::memory_order_release);

        impl.write_idx.val.store(0, std::memory_order_release);
        impl.read_idx.val.store(0, std::memory_order_release);

        std::atomic_thread_fence(std::memory_order_release);
        impl.is_active.store(true, std::memory_order_release);
        return true;
    }

    // ── Flush (버퍼 완전 초기화) ──────────────────────────────────────────
    void HTS_Tx_Scheduler::Flush() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        auto& impl = *p;

        if (!impl.is_active.load(std::memory_order_acquire)) { return; }

        impl.write_idx.val.store(0, std::memory_order_release);
        impl.read_idx.val.store(0, std::memory_order_release);
        std::atomic_thread_fence(std::memory_order_release);

        // 기존 memset은 컴파일러 DSE 최적화 시 제거 가능 → SecureMemory::secureWipe로 교체
        if (impl.ring_mask > 0u) {
            const size_t nwords = impl.ring_mask + 1u;
            if (nwords <= MAX_RING_POW2) {
                SecureMemory::secureWipe(
                    static_cast<void*>(impl.tx_ring_buffer), nwords << 2u);
            }
        }
    }

    // ── Get_Used_Space (사용 중인 공간 확인) ──────────────────────────────
    [[nodiscard]] size_t HTS_Tx_Scheduler::Get_Used_Space() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) { return 0u; }
        const size_t w = p->write_idx.val.load(std::memory_order_acquire);
        const size_t r = p->read_idx.val.load(std::memory_order_acquire);
        return (w - r); // 언더플로우 발생 시 부호 없는 정수 랩어라운드로 자동 보정
    }

    // ── Get_Available_Space (남은 공간 확인) ──────────────────────────────
    [[nodiscard]] size_t HTS_Tx_Scheduler::Get_Available_Space() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr || p->ring_capacity == 0u) { return 0u; }
        const size_t used = Get_Used_Space();
        return (p->ring_capacity > used) ? (p->ring_capacity - used) : 0u;
    }

    // =====================================================================
    //  Push_Waveform_Chunk — 프로듀서 (메인 루프)
    // =====================================================================
    [[nodiscard]] bool HTS_Tx_Scheduler::Push_Waveform_Chunk(
        const int32_t* q16_data, size_t size) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr || q16_data == nullptr || size == 0u) { return false; }
        auto& impl = *p;

        if (!impl.is_active.load(std::memory_order_acquire)) { return false; }
        if (impl.ring_capacity == 0u) { return false; }

        const uint32_t chunk = impl.current_config.temporal_slice_chunk;
        //  chunk는 프로파일 설계상 항상 2의 거듭제곱 (16, 64 등)
        //  비2의제곱이면 안전 거부 (양산 방어)
        if (chunk == 0u || (chunk & (chunk - 1u)) != 0u) { return false; }
        if ((size & static_cast<size_t>(chunk - 1u)) != 0u) { return false; }

        const size_t cur_write = impl.write_idx.val.load(std::memory_order_relaxed);
        const size_t cur_read = impl.read_idx.val.load(std::memory_order_acquire);

        const size_t used = cur_write - cur_read;
        if (used > impl.ring_capacity) { return false; }
        const size_t available = impl.ring_capacity - used;
        if (size > available) { return false; }

        const size_t mask = impl.ring_mask;
        const size_t phy_write = cur_write & mask;
        const size_t to_end = (impl.ring_mask + 1u) - phy_write;
        if (size > (SIZE_MAX >> 2u)) { return false; }
        const size_t bytes = size << 2u;
        const size_t to_end_bytes = to_end << 2u;

        int32_t* const dst_buf_base = impl.tx_ring_buffer;
        const int32_t* src_ptr = q16_data;

#if defined(__GNUC__) || defined(__clang__)
        int32_t* dst_w = static_cast<int32_t*>(
            __builtin_assume_aligned(&dst_buf_base[phy_write], 4));
        if ((reinterpret_cast<uintptr_t>(q16_data) & 3u) == 0u) {
            src_ptr = static_cast<const int32_t*>(
                __builtin_assume_aligned(q16_data, 4));
        }
#else
        int32_t* dst_w = &dst_buf_base[phy_write];
#endif

        if (size <= to_end) {
            std::memcpy(dst_w, src_ptr, bytes);
            //  컴파일러/CPU 투기적 실행으로 memcpy 완료 전 store 선행 방지
            //  fence(release): memcpy 가시성 보장
            //  store(relaxed): fence가 이미 release 의미 → 이중 배리어 제거
            std::atomic_thread_fence(std::memory_order_release);
            impl.write_idx.val.store(cur_write + size,
                std::memory_order_relaxed);
        }
        else {
            std::memcpy(dst_w, src_ptr, to_end_bytes);

            const size_t rem = size - to_end;
            const int32_t* src_next = src_ptr + to_end;
#if defined(__GNUC__) || defined(__clang__)
            void* dst0 = __builtin_assume_aligned(
                static_cast<void*>(dst_buf_base), 4);
            if ((reinterpret_cast<uintptr_t>(q16_data) & 3u) == 0u) {
                src_next = static_cast<const int32_t*>(
                    __builtin_assume_aligned(src_next, 4));
            }
#else
            void* dst0 = static_cast<void*>(dst_buf_base);
#endif
            std::memcpy(dst0, src_next, rem << 2u);
            std::atomic_thread_fence(std::memory_order_release);
            impl.write_idx.val.store(cur_write + size,
                std::memory_order_relaxed);
        }

        return true;
    }

    // =====================================================================
    //  Pop_Tx_Payload — 컨슈머 (ISR/모뎀)
    // =====================================================================
    [[nodiscard]] bool HTS_Tx_Scheduler::Pop_Tx_Payload(
        int32_t* out_buffer, size_t requested_size) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr || out_buffer == nullptr || requested_size == 0u) {
            return false;
        }
        auto& impl = *p;

        if (!impl.is_active.load(std::memory_order_acquire)) { return false; }
        if (impl.ring_capacity == 0u) { return false; }

        const uint32_t chunk = impl.current_config.temporal_slice_chunk;
        if (chunk == 0u || (chunk & (chunk - 1u)) != 0u) { return false; }
        if ((requested_size & static_cast<size_t>(chunk - 1u)) != 0u) { return false; }

        const size_t cur_read = impl.read_idx.val.load(std::memory_order_relaxed);
        const size_t cur_write = impl.write_idx.val.load(std::memory_order_acquire);

        const size_t used = cur_write - cur_read;
        if (used > impl.ring_capacity) { return false; }
        if (used < requested_size) { return false; }

        const size_t mask = impl.ring_mask;
        const size_t phy_read = cur_read & mask;
        const size_t to_end = (impl.ring_mask + 1u) - phy_read;
        if (requested_size > (SIZE_MAX >> 2u)) { return false; }
        const size_t bytes = requested_size << 2u;
        const size_t to_end_bytes = to_end << 2u;

        const int32_t* const src_buf_base = impl.tx_ring_buffer;
        int32_t* dst_ptr = out_buffer;

#if defined(__GNUC__) || defined(__clang__)
        const int32_t* src_r = static_cast<const int32_t*>(
            __builtin_assume_aligned(&src_buf_base[phy_read], 4));
        if ((reinterpret_cast<uintptr_t>(out_buffer) & 3u) == 0u) {
            dst_ptr = static_cast<int32_t*>(
                __builtin_assume_aligned(out_buffer, 4));
        }
#else
        const int32_t* src_r = &src_buf_base[phy_read];
#endif

        if (requested_size <= to_end) {
            std::memcpy(dst_ptr, src_r, bytes);
            std::atomic_thread_fence(std::memory_order_release);
            impl.read_idx.val.store(cur_read + requested_size,
                std::memory_order_relaxed);
        }
        else {
            std::memcpy(dst_ptr, src_r, to_end_bytes);

            const size_t rem = requested_size - to_end;
            int32_t* dst_next = dst_ptr + to_end;
#if defined(__GNUC__) || defined(__clang__)
            const void* src0 = __builtin_assume_aligned(
                static_cast<const void*>(src_buf_base), 4);
            if ((reinterpret_cast<uintptr_t>(out_buffer) & 3u) == 0u) {
                dst_next = static_cast<int32_t*>(
                    __builtin_assume_aligned(dst_next, 4));
            }
#else
            const void* src0 = static_cast<const void*>(src_buf_base);
#endif
            std::memcpy(dst_next, src0, rem << 2u);
            std::atomic_thread_fence(std::memory_order_release);
            impl.read_idx.val.store(cur_read + requested_size,
                std::memory_order_relaxed);
        }

        return true;
    }

} // namespace ProtectedEngine
