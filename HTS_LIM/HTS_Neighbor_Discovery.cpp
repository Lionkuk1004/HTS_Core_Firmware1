// =========================================================================
// HTS_Neighbor_Discovery.cpp
// 메쉬 이웃 탐색/토폴로지 관리 구현부 (Pimpl 은닉)
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// [설계]
//  · 5초 주기 비콘 송출 (P2 DATA)
//  · 수신 비콘 → 이웃 테이블 갱신 (최대 32개)
//  · 15초 미수신 → 이웃 제거 + Link_Down 콜백
//  · PRIMASK ISR 보호
//  · 3중 보안 소거
// =========================================================================
#include "HTS_Neighbor_Discovery.h"
#include "HTS_Arm_Irq_Mask_Guard.h"
#include "HTS_Priority_Scheduler.h"

#if defined(_MSC_VER)
#include <intrin.h>
#endif
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

static_assert(sizeof(uint16_t) == 2, "uint16_t must be 2 bytes");

namespace ProtectedEngine {

    // =====================================================================
    //  3중 보안 소거
    // =====================================================================
    static void ND_Secure_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) { q[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(q) : "memory");
#elif defined(_MSC_VER)
        _ReadWriteBarrier();
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  PRIMASK 크리티컬 섹션 — STAGE 3: Armv7m_Irq_Mask_Guard (RAII + release)
    // =====================================================================

    // =====================================================================
    //  엔디안 독립 직렬화/역직렬화
    // =====================================================================
    static void ser_u16(uint8_t* dst, uint16_t v) noexcept {
        dst[0] = static_cast<uint8_t>(v & 0xFFu);
        dst[1] = static_cast<uint8_t>((v >> 8u) & 0xFFu);
    }

    static uint16_t deser_u16(const uint8_t* src) noexcept {
        return static_cast<uint16_t>(src[0])
            | (static_cast<uint16_t>(src[1]) << 8u);
    }

    // =====================================================================
    //  비콘 패킷 인덱스
    // =====================================================================
    static constexpr size_t BCN_SRC_ID = 0u;  // [0-1] uint16_t
    static constexpr size_t BCN_SEQ = 2u;  // [2]   uint8_t
    static constexpr size_t BCN_HOP = 3u;  // [3]   uint8_t
    static constexpr size_t BCN_TX_PWR = 4u;  // [4]   int8_t
    static constexpr size_t BCN_NBR_CNT = 5u;  // [5]   uint8_t
    static constexpr size_t BCN_CAP = 6u;  // [6]   uint8_t
    static constexpr size_t BCN_RESERVED = 7u;  // [7]   uint8_t

    // =====================================================================
    //  내부 이웃 항목 (16바이트)
    // =====================================================================
    struct NbrEntry {
        uint16_t node_id;
        uint8_t  rssi;
        uint8_t  lqi;               // 최근 8비콘 수신률 (0-100)
        uint32_t last_seen_ms;
        uint8_t  hop_from_root;
        int8_t   tx_power_dbm;
        uint8_t  capability;
        uint8_t  beacon_rx_bits;    // 최근 8비콘 수신 비트맵
        uint8_t  seq_last;
        uint8_t  valid;             // 1=유효, 0=빈 슬롯
        uint8_t  decay_applied;     // LQI 감가 횟수 (무한감가 방지)
        uint8_t  pad;
    };

    static_assert(sizeof(NbrEntry) == 16u, "NbrEntry must be 16 bytes");

    // LQI 계산: 비트맵에서 1 비트 수 → 백분율
    static uint8_t calc_lqi(uint8_t bitmap) noexcept {
        // popcount (8비트) → ×12.5 → 0-100
        uint8_t cnt = 0u;
        uint8_t b = bitmap;
        // 비트 카운팅 (8비트이므로 루프 언롤)
        cnt += (b & 1u); b >>= 1u;
        cnt += (b & 1u); b >>= 1u;
        cnt += (b & 1u); b >>= 1u;
        cnt += (b & 1u); b >>= 1u;
        cnt += (b & 1u); b >>= 1u;
        cnt += (b & 1u); b >>= 1u;
        cnt += (b & 1u); b >>= 1u;
        cnt += (b & 1u);
        // cnt ∈ [0,8] → ×12 + (cnt>=4 ? cnt : 0) 근사 → 0~100
        static constexpr uint8_t lqi_table[9] = {
            0, 12, 25, 37, 50, 62, 75, 87, 100
        };
        return lqi_table[static_cast<size_t>(cnt)];
    }

    // =====================================================================
    //  Pimpl 구현 구조체
    //
    //  sizeof: 32×16 + 상태 ≈ 536B (< 1024B IMPL_BUF_SIZE)
    // =====================================================================
    static constexpr size_t MAX_NBR = 32u;

    struct HTS_Neighbor_Discovery::Impl {
        NbrEntry table[MAX_NBR] = {};

        uint16_t my_id = 0u;
        uint8_t  my_hop = 0xFFu;
        int8_t   my_tx_power = 0;
        uint8_t  beacon_seq = 0u;
        uint8_t  neighbor_count = 0u;
        uint32_t last_beacon_ms = 0u;
        bool     first_tick = true;

        DiscoveryMode mode = DiscoveryMode::DEEP_SLEEP;

        LinkDownCallback link_down_cb = nullptr;

        explicit Impl(uint16_t id) noexcept : my_id(id) {}
        ~Impl() noexcept = default;

        // 현재 모드의 비콘 주기 (ms)
        uint32_t get_interval() const noexcept {
            switch (mode) {
            case DiscoveryMode::REALTIME: return 1000u;   // 1초
            case DiscoveryMode::ALERT:    return 5000u;   // 5초
            case DiscoveryMode::WATCH:    return 30000u;  // 30초
            default:                      return 300000u; // 5분
            }
        }

        uint32_t get_timeout() const noexcept {
            switch (mode) {
            case DiscoveryMode::REALTIME: return 3000u;    // 3초
            case DiscoveryMode::ALERT:    return 15000u;   // 15초
            case DiscoveryMode::WATCH:    return 120000u;  // 2분
            default:                      return 1200000u; // 20분
            }
        }

        uint32_t get_rx_window() const noexcept {
            switch (mode) {
            case DiscoveryMode::DEEP_SLEEP: return 0u;  // Is_RX_Window: 항상 false (since_tx < 0 거짓)
            case DiscoveryMode::REALTIME: return 0xFFFFFFFFu; // 항상 ON
            case DiscoveryMode::ALERT:    return 0xFFFFFFFFu; // 항상 ON
            case DiscoveryMode::WATCH:    return get_interval() >> 1u;
            default:                      return 2000u;
            }
        }

        // 빈 슬롯 찾기
        int32_t find_free_slot() const noexcept {
            for (size_t i = 0u; i < MAX_NBR; ++i) {
                if (table[i].valid == 0u) {
                    return static_cast<int32_t>(i);
                }
            }
            return -1;
        }

        // node_id로 슬롯 찾기
        int32_t find_by_id(uint16_t nid) const noexcept {
            for (size_t i = 0u; i < MAX_NBR; ++i) {
                if (table[i].valid != 0u && table[i].node_id == nid) {
                    return static_cast<int32_t>(i);
                }
            }
            return -1;
        }

        // 이웃 수 재계산
        void recount() noexcept {
            uint8_t cnt = 0u;
            for (size_t i = 0u; i < MAX_NBR; ++i) {
                if (table[i].valid != 0u) { ++cnt; }
            }
            neighbor_count = cnt;
        }

        // 비콘 패킷 조립
        void build_beacon(uint8_t* out) const noexcept {
            ser_u16(&out[BCN_SRC_ID], my_id);
            out[BCN_SEQ] = beacon_seq;
            out[BCN_HOP] = my_hop;
            out[BCN_TX_PWR] = static_cast<uint8_t>(my_tx_power);
            out[BCN_NBR_CNT] = neighbor_count;
            out[BCN_CAP] = 0x01u;  // 기본 기능 (B-CDMA 지원)
            out[BCN_RESERVED] = 0u;
        }
    };

    // =====================================================================
    //  get_impl
    // =====================================================================
    HTS_Neighbor_Discovery::Impl*
        HTS_Neighbor_Discovery::get_impl() noexcept
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE(1024B)를 초과합니다");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 요구가 alignas를 초과합니다");
        return impl_valid_.load(std::memory_order_acquire)
            ? std::launder(reinterpret_cast<Impl*>(impl_buf_)) : nullptr;
    }

    const HTS_Neighbor_Discovery::Impl*
        HTS_Neighbor_Discovery::get_impl() const noexcept
    {
        return impl_valid_.load(std::memory_order_acquire)
            ? std::launder(reinterpret_cast<const Impl*>(impl_buf_)) : nullptr;
    }

    // =====================================================================
    //  생성자 / 소멸자
    // =====================================================================
    HTS_Neighbor_Discovery::HTS_Neighbor_Discovery(uint16_t my_id) noexcept
        : impl_valid_(false)
    {
        ND_Secure_Wipe(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl(my_id);
        impl_valid_.store(true, std::memory_order_release);
    }

    HTS_Neighbor_Discovery::~HTS_Neighbor_Discovery() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        // 파괴·소거 전에 공개 경로 차단 — get_impl() UAF 방지
        impl_valid_.store(false, std::memory_order_release);
        p->~Impl();
        ND_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
    }

    // =====================================================================
    //  설정 API
    // =====================================================================
    void HTS_Neighbor_Discovery::Register_Link_Down(
        LinkDownCallback cb) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        Armv7m_Irq_Mask_Guard irq;
        p->link_down_cb = cb;
    }

    // =====================================================================
    //  전력 모드 전환
    // =====================================================================
    void HTS_Neighbor_Discovery::Set_Mode(
        DiscoveryMode mode, uint32_t systick_ms) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        const uint8_t mode_v = static_cast<uint8_t>(mode);
        if (mode_v > static_cast<uint8_t>(DiscoveryMode::REALTIME)) { return; }
        Armv7m_Irq_Mask_Guard irq;

        const DiscoveryMode prev = p->mode;
        const uint32_t old_interval = p->get_interval();
        p->mode = mode;
        const uint32_t new_interval = p->get_interval();

        // 주기 단축(더 빠른 모드): 타임아웃이 바로 줄어 토폴로지 일거 붕괴 방지 — 유효 이웃 last_seen 정렬
        if (new_interval < old_interval) {
            for (size_t j = 0u; j < MAX_NBR; ++j) {
                if (p->table[j].valid != 0u) {
                    p->table[j].last_seen_ms = systick_ms;
                }
            }
        }

        // DEEP_SLEEP → WATCH/ALERT 전환: 즉시 비콘 재개
        //  first_tick=true → 다음 Tick에서 즉시 첫 비콘 송출
        if (prev == DiscoveryMode::DEEP_SLEEP &&
            mode != DiscoveryMode::DEEP_SLEEP)
        {
            p->first_tick = true;
        }
    }

    DiscoveryMode HTS_Neighbor_Discovery::Get_Mode() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) { return DiscoveryMode::DEEP_SLEEP; }
        DiscoveryMode mode = DiscoveryMode::DEEP_SLEEP;
        {
            Armv7m_Irq_Mask_Guard irq;
            mode = p->mode;
        }
        return mode;
    }

    bool HTS_Neighbor_Discovery::Is_RX_Window(
        uint32_t systick_ms) const noexcept
    {
        const Impl* p = get_impl();
        if (p == nullptr) { return false; }

        uint32_t last_beacon_ms = 0u;
        uint32_t rx_win = 0u;
        {
            Armv7m_Irq_Mask_Guard irq;
            last_beacon_ms = p->last_beacon_ms;
            rx_win = p->get_rx_window();
        }

        const uint32_t since_tx = systick_ms - last_beacon_ms;
        return since_tx < rx_win;
    }

    // =====================================================================
    //  설정 API
    // =====================================================================
    void HTS_Neighbor_Discovery::Set_My_Hop(uint8_t hop) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        Armv7m_Irq_Mask_Guard irq;
        p->my_hop = hop;
    }

    void HTS_Neighbor_Discovery::Set_My_TX_Power(int8_t dbm) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        Armv7m_Irq_Mask_Guard irq;
        p->my_tx_power = dbm;
    }

    // =====================================================================
    //  On_Beacon_Received — 수신 비콘 → 이웃 테이블 갱신
    // =====================================================================
    void HTS_Neighbor_Discovery::On_Beacon_Received(
        const uint8_t* pkt, size_t pkt_len,
        uint8_t rx_rssi, uint32_t systick_ms) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr || pkt == nullptr) { return; }
        if (pkt_len < BEACON_PKT_SIZE) { return; }

        // 비콘 파싱
        const uint16_t src_id = deser_u16(&pkt[BCN_SRC_ID]);
        const uint8_t  seq = pkt[BCN_SEQ];
        const uint8_t  hop = pkt[BCN_HOP];
        const int8_t   tx_pwr = static_cast<int8_t>(pkt[BCN_TX_PWR]);
        const uint8_t  cap = pkt[BCN_CAP];

        // 자기 비콘 무시
        if (src_id == p->my_id) { return; }

        Armv7m_Irq_Mask_Guard irq;

        int32_t slot = p->find_by_id(src_id);

        if (slot >= 0) {
            // 이웃 갱신
            NbrEntry& e = p->table[static_cast<size_t>(slot)];
            e.rssi = rx_rssi;
            e.last_seen_ms = systick_ms;
            e.hop_from_root = hop;
            e.tx_power_dbm = tx_pwr;
            e.capability = cap;
            e.seq_last = seq;
            e.decay_applied = 0u;  // 수신 성공 → 감가 카운터 리셋
            // LQI 비트맵: 좌시프트 + 수신 1 기록
            e.beacon_rx_bits = static_cast<uint8_t>(
                (e.beacon_rx_bits << 1u) | 1u);
            e.lqi = calc_lqi(e.beacon_rx_bits);
        }
        else {
            // 신규 이웃 추가
            slot = p->find_free_slot();
            if (slot >= 0) {
                NbrEntry& e = p->table[static_cast<size_t>(slot)];
                e.node_id = src_id;
                e.rssi = rx_rssi;
                e.lqi = 12u;  // 첫 수신: 1/8 = 12%
                e.last_seen_ms = systick_ms;
                e.hop_from_root = hop;
                e.tx_power_dbm = tx_pwr;
                e.capability = cap;
                e.beacon_rx_bits = 0x01u;
                e.seq_last = seq;
                e.valid = 1u;
                e.decay_applied = 0u;
                p->recount();
            }
            // 테이블 풀: 드롭 (가장 약한 RSSI 대체도 가능하나 복잡도 증가)
        }
    }

    // =====================================================================
    //  Tick — 비콘 송출 + 타임아웃 검사
    // =====================================================================
    void HTS_Neighbor_Discovery::Tick(
        uint32_t systick_ms,
        HTS_Priority_Scheduler& scheduler) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        //  TX 차단: RF/PA 미가동 → 배터리 보존
        //  타임아웃 차단: 이웃 테이블 동결 (WATCH 전환 시 재활용)
        //  WATCH/ALERT 전환 시 first_tick=true로 즉시 비콘 재개
        Armv7m_Irq_Mask_Guard irq;
        if (p->mode == DiscoveryMode::DEEP_SLEEP) {
            irq.release();
            return;
        }

        const uint32_t cur_interval = p->get_interval();
        const uint32_t cur_timeout = p->get_timeout();

        // 첫 Tick 초기화
        if (p->first_tick) {
            p->last_beacon_ms = systick_ms - cur_interval;
            p->first_tick = false;
        }

        // ── 1. 타임아웃 검사 (모드별 타임아웃 적용) ──
        //  만료 시 ND_Secure_Wipe는 PRIMASK 안에서 수행 — 락 밖으로 내리면 On_Beacon과 슬롯 재사용 레이스
        uint16_t expired_ids[4] = {};
        uint8_t  expired_count = 0u;

        for (size_t i = 0u; i < MAX_NBR; ++i) {
            if (p->table[i].valid == 0u) { continue; }

            const uint32_t age = systick_ms - p->table[i].last_seen_ms;
            if (age >= cur_timeout) {
                if (expired_count >= 4u) {
                    break;  // 한도 초과 → 남은 만료 이웃은 다음 Tick에서 처리
                }
                expired_ids[static_cast<size_t>(expired_count)] =
                    p->table[i].node_id;
                ++expired_count;
                ND_Secure_Wipe(&p->table[i], sizeof(NbrEntry));
            }
            else {
                // LQI 감가: 비콘 미수신 시 비트맵에 0 기록
                //
                // [방어 1] 최소 경과 가드: 1 인터벌 미만이면 감가 자체 스킵
                //   On_Beacon_Received 직후 Tick → age ≈ 0 → 스킵 ✅
                if (age < cur_interval) { continue; }

                // [방어 2] UDIV 대신 곱셈 임계: floor(age/cur) > decay_applied
                //   ⇔ age >= (decay_applied+1)*cur_interval (Tick당 최대 1회 감가와 동등)
                static constexpr uint8_t MAX_DECAY = 8u;
                const uint8_t da = p->table[i].decay_applied;
                if (da < MAX_DECAY) {
                    const uint32_t next_threshold =
                        (static_cast<uint32_t>(da) + 1u) * cur_interval;
                    if (age >= next_threshold) {
                        p->table[i].beacon_rx_bits = static_cast<uint8_t>(
                            p->table[i].beacon_rx_bits << 1u);
                        p->table[i].lqi = calc_lqi(p->table[i].beacon_rx_bits);
                        p->table[i].decay_applied++;
                    }
                }
            }
        }

        if (expired_count > 0u) {
            p->recount();
        }

        // ── 2. 비콘 송출 (모드별 주기 적용) ──
        uint8_t beacon_pkt[BEACON_PKT_SIZE] = {};
        bool send_beacon = false;

        const uint32_t since_last_tx = systick_ms - p->last_beacon_ms;
        if (since_last_tx >= cur_interval) {
            p->build_beacon(beacon_pkt);
            p->beacon_seq++;
            p->last_beacon_ms = systick_ms;
            send_beacon = true;
        }

        irq.release();

        // ── 크리티컬 밖 ──

        //  콜백 → 인큐 → 콜백의 깊은 스택이 beacon_pkt 오염 위험
        //  인큐 → 콜백 → beacon_pkt 사용 완료 후 콜백 실행
        if (send_beacon) {
            const EnqueueResult enq = scheduler.Enqueue(
                PacketPriority::DATA,
                beacon_pkt, BEACON_PKT_SIZE,
                systick_ms);
            (void)enq;
            ND_Secure_Wipe(beacon_pkt, sizeof(beacon_pkt));
        }

        // 만료 이웃 콜백 (비콘 인큐 후 실행 — 스택 안전)
        if (expired_count > 0u && p->link_down_cb != nullptr) {
            for (uint8_t i = 0u; i < expired_count; ++i) {
                p->link_down_cb(
                    expired_ids[static_cast<size_t>(i)]);
            }
        }
    }

    // =====================================================================
    //  조회 API
    // =====================================================================
    size_t HTS_Neighbor_Discovery::Get_Neighbor_Count() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) { return 0u; }
        size_t c = 0u;
        {
            Armv7m_Irq_Mask_Guard irq;
            c = static_cast<size_t>(p->neighbor_count);
        }
        return c;
    }

    bool HTS_Neighbor_Discovery::Get_Neighbor(
        size_t idx, NeighborInfo& out) const noexcept
    {
        const Impl* p = get_impl();
        if (p == nullptr || idx >= MAX_NBR) { return false; }

        Armv7m_Irq_Mask_Guard irq;
        const NbrEntry& e = p->table[idx];
        if (e.valid == 0u) {
            irq.release();
            return false;
        }
        out.node_id = e.node_id;
        out.rssi = e.rssi;
        out.lqi = e.lqi;
        out.last_seen_ms = e.last_seen_ms;
        out.hop_from_root = e.hop_from_root;
        out.capability = e.capability;
        out.tx_power_dbm = e.tx_power_dbm;
        out.valid = 1u;
        irq.release();
        return true;
    }

    bool HTS_Neighbor_Discovery::Find_Neighbor(
        uint16_t node_id, NeighborInfo& out) const noexcept
    {
        const Impl* p = get_impl();
        if (p == nullptr) { return false; }

        Armv7m_Irq_Mask_Guard irq;
        const int32_t slot = p->find_by_id(node_id);
        if (slot < 0) {
            irq.release();
            return false;
        }
        const NbrEntry& e = p->table[static_cast<size_t>(slot)];
        out.node_id = e.node_id;
        out.rssi = e.rssi;
        out.lqi = e.lqi;
        out.last_seen_ms = e.last_seen_ms;
        out.hop_from_root = e.hop_from_root;
        out.capability = e.capability;
        out.tx_power_dbm = e.tx_power_dbm;
        out.valid = 1u;
        irq.release();
        return true;
    }

    // =====================================================================
    //  Shutdown
    // =====================================================================
    void HTS_Neighbor_Discovery::Shutdown() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        Armv7m_Irq_Mask_Guard irq;
        ND_Secure_Wipe(p->table, sizeof(p->table));
        p->neighbor_count = 0u;
    }

} // namespace ProtectedEngine
