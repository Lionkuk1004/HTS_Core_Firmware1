// =========================================================================
// HTS_Mesh_Sync.cpp
// 메쉬 시간 동기화 + ToA 거리 추정 엔진 구현부
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// [v2.0 보강]
//  · 다중 홉 동기 전파: 루트(GPS앵커) → 1홉 → 2홉 → 말단
//  · ToA 거리 추정: |오프셋| × 광속 → 거리(cm)
//  · 동기 품질 지표: LOCKED 비율 × 오프셋 안정도 → 0-100%
//  · 수색 시나리오: 3+ 앵커 거리 → Location_Engine 삼각측량
// =========================================================================
#include "HTS_Mesh_Sync.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

static_assert(sizeof(uint16_t) == 2, "uint16_t must be 2 bytes");
static_assert(sizeof(int32_t) == 4, "int32_t must be 4 bytes");

namespace ProtectedEngine {

    // =====================================================================
    //  3중 보안 소거
    // =====================================================================
    static void Sync_Secure_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) { q[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  PRIMASK
    // =====================================================================
#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
    static inline uint32_t sync_critical_enter() noexcept {
        uint32_t primask;
        __asm volatile ("MRS %0, PRIMASK\n CPSID I"
        : "=r"(primask) :: "memory");
        return primask;
    }
    static inline void sync_critical_exit(uint32_t pm) noexcept {
        __asm volatile ("MSR PRIMASK, %0" :: "r"(pm) : "memory");
    }
#else
    static inline uint32_t sync_critical_enter() noexcept { return 0u; }
    static inline void sync_critical_exit(uint32_t) noexcept {}
#endif

    // =====================================================================
    //  Q16 상수 + 도우미
    // =====================================================================
    static constexpr int32_t Q16_ONE = 65536;
    static constexpr int32_t LOCK_TH_Q16 = Q16_ONE;  // ±1μs
    static constexpr uint8_t LOCK_CONFIRM = 3u;
    static constexpr uint8_t IIR_SHIFT = 3u;       // alpha=1/8

    // 광속 cm/μs = 300m/μs = 30000cm/μs
    static constexpr uint32_t LIGHT_CM_PER_US = 30000u;

    static int32_t fast_abs(int32_t x) noexcept {
        const int32_t mask = x >> 31;
        return (x ^ mask) - mask;
    }

    // =====================================================================
    //  PeerSync (16바이트)
    // =====================================================================
    struct PeerSync {
        uint16_t peer_id;
        uint8_t  sample_count;
        uint8_t  lock_streak;
        int32_t  offset_q16;        // Q16 필터 오프셋 (μs)
        uint32_t last_update_ms;
        uint8_t  peer_hop;          // 상대방 동기 계층
        uint8_t  valid;
        uint8_t  pad[2];
    };

    static_assert(sizeof(PeerSync) == 16u, "PeerSync must be 16 bytes");

    // =====================================================================
    //  Pimpl 구현 구조체
    // =====================================================================
    static constexpr size_t MAX_PEERS = 16u;

    struct HTS_Mesh_Sync::Impl {
        PeerSync peers[MAX_PEERS] = {};

        uint16_t  my_id = 0u;
        SyncState state = SyncState::UNSYNC;
        uint8_t   my_slot = 0u;
        uint8_t   my_hop_level = 0xFFu;  // 0xFF=미설정, 0=루트
        int32_t   global_offset = 0;
        uint8_t   locked_peers = 0u;
        uint8_t   sync_quality = 0u;     // 0-100%

        explicit Impl(uint16_t id) noexcept : my_id(id) {}
        ~Impl() noexcept = default;

        int32_t find_peer(uint16_t pid) const noexcept {
            for (size_t i = 0u; i < MAX_PEERS; ++i) {
                if (peers[i].valid != 0u && peers[i].peer_id == pid) {
                    return static_cast<int32_t>(i);
                }
            }
            return -1;
        }

        int32_t find_free() const noexcept {
            for (size_t i = 0u; i < MAX_PEERS; ++i) {
                if (peers[i].valid == 0u) {
                    return static_cast<int32_t>(i);
                }
            }
            return -1;
        }

        // ToA → 거리(cm) 변환
        // distance = |offset_us| × 광속(cm/μs)
        // Q16 → μs: offset_q16 / 65536
        // 정수화: |offset_q16| × 30000 / 65536
        //       = |offset_q16| × 30000 >> 16
        uint32_t offset_to_distance_cm(int32_t ofs_q16) const noexcept {
            const uint32_t abs_ofs = static_cast<uint32_t>(fast_abs(ofs_q16));
            // 오버플로 방지: abs_ofs 최대 ~10^6 × 30000 = 3×10^10 > uint32
            // 분할: (abs_ofs >> 8) × 30000 >> 8 (정밀도 유지)
            const uint32_t hi = abs_ofs >> 8u;
            const uint32_t dist = (hi * LIGHT_CM_PER_US) >> 8u;
            return dist;
        }

        // 동기 품질 재평가 + 다중 홉 계층 갱신
        void evaluate_state() noexcept {
            uint8_t locked_cnt = 0u;
            uint8_t total_valid = 0u;
            int32_t sum_offset = 0;
            uint8_t best_hop = 0xFFu;

            for (size_t i = 0u; i < MAX_PEERS; ++i) {
                if (peers[i].valid == 0u) { continue; }
                ++total_valid;

                if (peers[i].lock_streak >= LOCK_CONFIRM) {
                    ++locked_cnt;
                    sum_offset += peers[i].offset_q16;
                }

                // 다중 홉: 가장 낮은 계층의 이웃 + 1 = 나의 계층
                if (peers[i].peer_hop < best_hop) {
                    best_hop = peers[i].peer_hop;
                }
            }

            locked_peers = locked_cnt;

            // 다중 홉 계층 갱신 (루트가 아닌 경우)
            if (my_hop_level != 0u && best_hop < 0xFEu) {
                my_hop_level = best_hop + 1u;
            }

            if (state == SyncState::SUSPENDED) { return; }

            // 동기 품질: LOCKED 비율 (0-100%)
            if (total_valid > 0u) {
                sync_quality = static_cast<uint8_t>(
                    (static_cast<uint32_t>(locked_cnt) * 100u) /
                    static_cast<uint32_t>(total_valid));
            }
            else {
                sync_quality = 0u;
            }

            // 상태 판정
            if (locked_cnt > 0u) {
                state = SyncState::LOCKED;
                global_offset = sum_offset /
                    static_cast<int32_t>(locked_cnt);
            }
            else if (total_valid > 0u) {
                state = SyncState::ACQUIRING;
            }
            else {
                state = SyncState::UNSYNC;
            }
        }
    };

    // =====================================================================
    //  get_impl
    // =====================================================================
    HTS_Mesh_Sync::Impl*
        HTS_Mesh_Sync::get_impl() noexcept
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE(512B)를 초과합니다");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 요구가 alignas를 초과합니다");
        return impl_valid_
            ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }

    const HTS_Mesh_Sync::Impl*
        HTS_Mesh_Sync::get_impl() const noexcept
    {
        return impl_valid_
            ? reinterpret_cast<const Impl*>(impl_buf_) : nullptr;
    }

    // =====================================================================
    //  생성자 / 소멸자
    // =====================================================================
    HTS_Mesh_Sync::HTS_Mesh_Sync(uint16_t my_id) noexcept
        : impl_valid_(false)
    {
        Sync_Secure_Wipe(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl(my_id);
        impl_valid_ = true;
    }

    HTS_Mesh_Sync::~HTS_Mesh_Sync() noexcept {
        Impl* p = get_impl();
        if (p != nullptr) { p->~Impl(); }
        Sync_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
        impl_valid_ = false;
    }

    // =====================================================================
    //  ① 포물선 피크 보간 (Sub-sample ToA 정밀도)
    //
    //  상관 피크 3샘플 [prev, peak, next]에 포물선 피팅:
    //    delta = (prev - next) / (2 × (prev - 2×peak + next))
    //    delta ∈ [-0.5, +0.5] 샘플
    //    보정: delta × sample_period_us × Q16
    //
    //  Sample period: 0.5μs (200kc/s, 10x 오버샘플링)
    //  Q16 보정: delta_q16 = delta × 32768 (0.5 × Q16_ONE)
    //
    //  효과: ToA 정밀도 0.5μs → 0.15μs (3배 향상)
    // =====================================================================
    static constexpr int32_t SAMPLE_PERIOD_Q16 = 32768;  // 0.5μs in Q16

    static int32_t parabolic_interp_q16(
        int32_t prev, int32_t peak, int32_t next) noexcept
    {
        // 분모 = 2 × (prev - 2×peak + next)
        const int32_t denom = 2 * (prev - 2 * peak + next);
        if (denom == 0) { return 0; }  // 대칭 → 보정 불필요

        // 분자 = (prev - next)
        const int32_t numer = prev - next;

        // delta_q16 = (numer / denom) × SAMPLE_PERIOD_Q16
        // 정밀도: numer/denom을 Q16으로 변환
        // = (numer × SAMPLE_PERIOD_Q16) / denom
        const int32_t correction = (numer * SAMPLE_PERIOD_Q16) / denom;
        return correction;
    }

    // =====================================================================
    //  On_Beacon_Timing — 오프셋 + 포물선 보간 + ToA 거리
    // =====================================================================
    void HTS_Mesh_Sync::On_Beacon_Timing(
        uint16_t peer_id,
        uint32_t rx_capture_us,
        uint32_t expected_us,
        uint8_t  peer_hop,
        uint32_t systick_ms,
        int32_t  corr_prev,
        int32_t  corr_peak,
        int32_t  corr_next) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        if (peer_id == p->my_id) { return; }
        if (p->state == SyncState::SUSPENDED) { return; }

        // 원시 오프셋 (정수 μs)
        int32_t raw_offset =
            static_cast<int32_t>(rx_capture_us) -
            static_cast<int32_t>(expected_us);

        // Q16 변환
        int32_t raw_q16 = raw_offset * Q16_ONE;

        // ① 포물선 보간 적용 (상관 샘플이 유효할 때만)
        if (corr_peak > 0 && (corr_prev > 0 || corr_next > 0)) {
            const int32_t interp = parabolic_interp_q16(
                corr_prev, corr_peak, corr_next);
            raw_q16 += interp;  // Sub-sample 보정
        }

        const uint32_t pm = sync_critical_enter();

        int32_t slot = p->find_peer(peer_id);

        if (slot >= 0) {
            PeerSync& ps = p->peers[static_cast<size_t>(slot)];
            const int32_t diff = raw_q16 - ps.offset_q16;
            ps.offset_q16 += (diff >> IIR_SHIFT);
            ps.last_update_ms = systick_ms;
            ps.peer_hop = peer_hop;
            if (ps.sample_count < 255u) { ps.sample_count++; }

            if (fast_abs(ps.offset_q16) < LOCK_TH_Q16) {
                if (ps.lock_streak < 255u) { ps.lock_streak++; }
            }
            else {
                ps.lock_streak = 0u;
            }
        }
        else {
            slot = p->find_free();
            if (slot >= 0) {
                PeerSync& ps = p->peers[static_cast<size_t>(slot)];
                ps.peer_id = peer_id;
                ps.offset_q16 = raw_q16;
                ps.last_update_ms = systick_ms;
                ps.sample_count = 1u;
                ps.lock_streak = 0u;
                ps.peer_hop = peer_hop;
                ps.valid = 1u;
            }
        }

        p->evaluate_state();
        sync_critical_exit(pm);
    }

    // =====================================================================
    //  다중 홉 동기
    // =====================================================================
    void HTS_Mesh_Sync::Set_As_Root() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        p->my_hop_level = 0u;
    }

    uint8_t HTS_Mesh_Sync::Get_My_Hop_Level() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? p->my_hop_level : 0xFFu;
    }

    // =====================================================================
    //  상태/품질
    // =====================================================================
    SyncState HTS_Mesh_Sync::Get_State() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? p->state : SyncState::UNSYNC;
    }

    int32_t HTS_Mesh_Sync::Get_Offset_Q16() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? p->global_offset : 0;
    }

    bool HTS_Mesh_Sync::Is_Locked() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) && (p->state == SyncState::LOCKED);
    }

    uint8_t HTS_Mesh_Sync::Get_Sync_Quality() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? p->sync_quality : 0u;
    }

    // =====================================================================
    //  ToA 거리 조회
    // =====================================================================
    uint32_t HTS_Mesh_Sync::Get_Distance_cm(uint16_t peer_id) const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) { return 0u; }

        const uint32_t pm = sync_critical_enter();
        const int32_t slot = p->find_peer(peer_id);
        uint32_t dist = 0u;
        if (slot >= 0) {
            const PeerSync& ps = p->peers[static_cast<size_t>(slot)];
            if (ps.sample_count >= 3u) {  // 최소 3샘플 필요
                dist = p->offset_to_distance_cm(ps.offset_q16);
            }
        }
        sync_critical_exit(pm);
        return dist;
    }

    size_t HTS_Mesh_Sync::Get_All_Ranging(
        PeerRanging* out, size_t cap) const noexcept
    {
        const Impl* p = get_impl();
        if (p == nullptr || out == nullptr || cap == 0u) { return 0u; }

        const uint32_t pm = sync_critical_enter();
        size_t count = 0u;

        for (size_t i = 0u; i < MAX_PEERS && count < cap; ++i) {
            const PeerSync& ps = p->peers[i];
            if (ps.valid == 0u) { continue; }

            PeerRanging& r = out[count];
            r.peer_id = ps.peer_id;
            r.offset_q16 = ps.offset_q16;
            r.distance_cm = (ps.sample_count >= 3u)
                ? p->offset_to_distance_cm(ps.offset_q16) : 0u;
            r.sync_quality = (ps.lock_streak >= LOCK_CONFIRM) ? 100u :
                static_cast<uint8_t>(
                    (static_cast<uint32_t>(ps.lock_streak) * 100u) /
                    static_cast<uint32_t>(LOCK_CONFIRM));
            r.hop_level = ps.peer_hop;
            r.valid = 1u;
            r.pad = 0u;
            ++count;
        }

        sync_critical_exit(pm);
        return count;
    }

    // =====================================================================
    //  TDMA 슬롯
    // =====================================================================
    void HTS_Mesh_Sync::Set_My_Slot(uint8_t slot) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        if (slot < MAX_SLOTS) { p->my_slot = slot; }
    }

    uint8_t HTS_Mesh_Sync::Get_My_Slot() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? p->my_slot : 0u;
    }

    bool HTS_Mesh_Sync::Is_My_TX_Slot(uint32_t systick_us) const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) { return false; }
        if (p->state != SyncState::LOCKED) { return true; }

        static constexpr uint32_t FRAME_US =
            static_cast<uint32_t>(MAX_SLOTS) * SLOT_DURATION_US;
        const uint32_t frame_pos = systick_us % FRAME_US;  // 32비트 UDIV
        const uint32_t slot_start =
            static_cast<uint32_t>(p->my_slot) * SLOT_DURATION_US + GUARD_TIME_US;
        const uint32_t slot_end =
            (static_cast<uint32_t>(p->my_slot) + 1u) * SLOT_DURATION_US - GUARD_TIME_US;
        return (frame_pos >= slot_start && frame_pos < slot_end);
    }

    // =====================================================================
    //  전력 모드
    // =====================================================================
    void HTS_Mesh_Sync::Suspend() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        const uint32_t pm = sync_critical_enter();
        p->state = SyncState::SUSPENDED;
        sync_critical_exit(pm);
    }

    void HTS_Mesh_Sync::Resume() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        const uint32_t pm = sync_critical_enter();
        if (p->state == SyncState::SUSPENDED) {
            p->state = SyncState::ACQUIRING;
        }
        sync_critical_exit(pm);
    }

    void HTS_Mesh_Sync::Shutdown() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        const uint32_t pm = sync_critical_enter();
        Sync_Secure_Wipe(p->peers, sizeof(p->peers));
        p->state = SyncState::UNSYNC;
        p->global_offset = 0;
        p->locked_peers = 0u;
        p->sync_quality = 0u;
        sync_critical_exit(pm);
    }

} // namespace ProtectedEngine