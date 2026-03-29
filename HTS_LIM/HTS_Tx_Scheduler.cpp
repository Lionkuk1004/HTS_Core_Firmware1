// =========================================================================
// HTS_Tx_Scheduler.cpp — B-CDMA TX 전송 스케줄러 (Pimpl 은닉)
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// [양산 수정 이력 — 64건]
//  BUG-01~58 (이전 세션 완료)
//  BUG-59 MAX_RING_POW2 = 1<<14 (SRAM1 112KB 물리 한계 준수)
//  BUG-60 SecWipe Strict Aliasing UB 제거 (표준 memset + asm clobber 복구)
//  BUG-61 [HIGH] Push/Pop 랩어라운드 내 불필요한 Dead Branch(rem > 0) 제거
//  BUG-62 [HIGH] Initialize/Push/Pop 커밋 가시성 배리어 정밀 재배치
//  BUG-63 [ADD] Flush, Get_Used_Space, Get_Available_Space 인터페이스 구현
//  BUG-64 [CRIT] unique_ptr Pimpl → placement new (zero-heap)
//         · impl_buf_[1024] alignas(64) — AlignedIndex(alignas64) 수용
//         · 생성자: ::new(impl_buf_) Impl(tier)  소멸자: p->~Impl() + SecWipe
//         · 힙 OOM 위험 원천 제거 / 결정론적 SRAM 배치 보장
//  BUG-67 [CRIT] MAX_RING_POW2/CACHELINE 플랫폼 분리
//         · ARM: MAX_RING_POW2=2048(8KB), CACHELINE=8 — SRAM 59KB 절감
//         · PC:  MAX_RING_POW2=16384(64KB), CACHELINE=64 — 기존 유지
//         · Flush() memset → SecWipe (Q16 파형 잔존 방지)
// =========================================================================
#include "HTS_Tx_Scheduler.h"
#include "HTS_Dynamic_Config.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

namespace ProtectedEngine {

    // ── 보안 소거 (asm clobber + seq_cst — 임베디드 호환 2중 보호) ──
    // Strict Aliasing 규칙 준수 및 DSE 완벽 차단
    static void SecWipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        std::memset(p, 0, n);
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#elif defined(_MSC_VER)
        volatile uint8_t* vp = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) { vp[i] = 0u; }
#endif
        // [BUG-13] seq_cst → release (소거 배리어 정책 통일)
        std::atomic_thread_fence(std::memory_order_release);
    }

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
        // [BUG-66] unique_ptr 힙 → 정적 배열 (B-1 힙금지 준수)
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

            if (ring_capacity > 0u) {
                SecWipe(tx_ring_buffer, ring_capacity << 2u);
            }

            write_idx.val.store(0, std::memory_order_relaxed);
            read_idx.val.store(0, std::memory_order_relaxed);
            std::atomic_thread_fence(std::memory_order_release);
            SecWipe(&write_idx, sizeof(write_idx));
            SecWipe(&read_idx, sizeof(read_idx));

            SecWipe(&current_config, sizeof(current_config));
            std::atomic_thread_fence(std::memory_order_release);
        }
    };
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

    // =====================================================================
    //  [BUG-64] 컴파일 타임 크기·정렬 검증 + get_impl()
    //
    //  static_assert가 get_impl() 내부에 있으므로 Impl 완전 정의 후 평가
    //  → sizeof(Impl), alignof(Impl) 모두 안전하게 접근 가능
    // =====================================================================
    HTS_Tx_Scheduler::Impl* HTS_Tx_Scheduler::get_impl() noexcept {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE를 초과합니다 — IMPL_BUF_SIZE 확대 필요");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 요구가 impl_buf_ alignas(64)를 초과합니다");
        return impl_valid_ ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }

    const HTS_Tx_Scheduler::Impl* HTS_Tx_Scheduler::get_impl() const noexcept {
        return impl_valid_
            ? reinterpret_cast<const Impl*>(impl_buf_)
            : nullptr;
    }

    // =====================================================================
    //  [BUG-64] 생성자 — placement new (zero-heap)
    //  Impl(tier) 생성자는 noexcept → 예외 없이 안전
    // =====================================================================
    HTS_Tx_Scheduler::HTS_Tx_Scheduler(HTS_Sys_Tier tier) noexcept
        : impl_valid_(false)
    {
        SecWipe(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl(tier);
        impl_valid_ = true;
    }

    // =====================================================================
    //  [BUG-64] 소멸자 — 명시적 (= default 제거)
    //  Impl 소멸자(내부 SecWipe) 호출 → impl_buf_ 전체 SecWipe → 플래그 무효화
    // =====================================================================
    HTS_Tx_Scheduler::~HTS_Tx_Scheduler() noexcept {
        Impl* p = get_impl();
        if (p != nullptr) { p->~Impl(); }
        SecWipe(impl_buf_, sizeof(impl_buf_));
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
        // [BUG-13] seq_cst → release (ISR는 acquire로 확인)
        std::atomic_thread_fence(std::memory_order_release);

        if (impl.current_config.temporal_slice_chunk == 0u) { return false; }
        if (impl.current_config.node_count == 0u) { return false; }

        const uint32_t nc = impl.current_config.node_count;
        const size_t raw_cap = (nc > static_cast<uint32_t>(MAX_RING_POW2 >> 2u))
            ? MAX_RING_POW2
            : static_cast<size_t>(nc) << 2u;

        const size_t ring_size = Next_Power_Of_Two(raw_cap);

        // [BUG-66] 정적 배열 — new 제거 (B-1 힙금지 준수)
        // ring_size ≤ MAX_RING_POW2 보장 (Next_Power_Of_Two 클램프)
        if (impl.ring_capacity > 0u) {
            SecWipe(impl.tx_ring_buffer, impl.ring_capacity << 2u);
        }
        std::memset(impl.tx_ring_buffer, 0, ring_size << 2u);

        impl.ring_mask = ring_size - 1u;
        impl.ring_capacity = ring_size;
        std::atomic_thread_fence(std::memory_order_release);

        impl.write_idx.val.store(0, std::memory_order_release);
        impl.read_idx.val.store(0, std::memory_order_release);

        // [BUG-13] seq_cst → release (초기화 완료 후 활성화)
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
        // [BUG-13] seq_cst → release (인덱스 리셋)
        std::atomic_thread_fence(std::memory_order_release);

        // [BUG-67] Ghost Transmission 방지 — 잔여 Q16 파형 보안 소거
        // 기존 memset은 컴파일러 DSE 최적화 시 제거 가능 → SecWipe로 교체
        if (impl.ring_capacity > 0u) {
            SecWipe(impl.tx_ring_buffer, impl.ring_capacity << 2u);
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
        if (size % chunk != 0u) { return false; }

        const size_t cur_write = impl.write_idx.val.load(std::memory_order_relaxed);
        const size_t cur_read = impl.read_idx.val.load(std::memory_order_acquire);

        const size_t used = cur_write - cur_read;
        if (used > impl.ring_capacity) { return false; }
        const size_t available = impl.ring_capacity - used;
        if (size > available) { return false; }

        const size_t mask = impl.ring_mask;
        const size_t phy_write = cur_write & mask;
        const size_t to_end = impl.ring_capacity - phy_write;
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
        }

        std::atomic_thread_fence(std::memory_order_release);
        impl.write_idx.val.store(cur_write + size, std::memory_order_release);
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
        if (requested_size % chunk != 0u) { return false; }

        const size_t cur_read = impl.read_idx.val.load(std::memory_order_relaxed);
        const size_t cur_write = impl.write_idx.val.load(std::memory_order_acquire);

        const size_t used = cur_write - cur_read;
        if (used > impl.ring_capacity) { return false; }
        if (used < requested_size) { return false; }

        const size_t mask = impl.ring_mask;
        const size_t phy_read = cur_read & mask;
        const size_t to_end = impl.ring_capacity - phy_read;
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
        }

        std::atomic_thread_fence(std::memory_order_release);
        impl.read_idx.val.store(cur_read + requested_size, std::memory_order_release);
        return true;
    }

} // namespace ProtectedEngine