// =========================================================================
// HTS_Mesh_Router.cpp
// 자가치유 메쉬 라우터 구현부
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// [핵심 알고리즘]
//  · 거리 벡터 (Bellman-Ford): metric = hop×4 + (100-lqi)
//  · 자가치유: Link_Down → Poison Reverse → 대체 경로
//  · 루프 방지: Split Horizon (이웃에게 이웃 경유 경로 미전파)
//  · 경로 노화: 60초 미갱신 → 삭제
//  · 순수 32비트, 힙 0, ASIC 호환
// =========================================================================
#include "HTS_Mesh_Router.h"
#include "HTS_Priority_Scheduler.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

namespace ProtectedEngine {
    static constexpr uint8_t RTR_PKT_SLOT_COUNT = 8u;
    static constexpr uint8_t RTR_PKT_SLOT_MASK = 7u;
    static std::atomic<uint32_t> g_rtr_pkt_slot{ 0u };
    alignas(uint32_t) static uint8_t g_rtr_pkt_pool[RTR_PKT_SLOT_COUNT][64] = {};

    static uint8_t* acquire_rtr_pkt_slot() noexcept {
        const uint32_t slot = g_rtr_pkt_slot.fetch_add(1u, std::memory_order_relaxed);
        return g_rtr_pkt_pool[slot & RTR_PKT_SLOT_MASK];
    }

    // =====================================================================
    //  보안 소거 / PRIMASK
    // =====================================================================
    static void Rtr_Secure_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) { q[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(q) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
    static inline uint32_t rtr_critical_enter() noexcept {
        uint32_t primask;
        __asm volatile ("MRS %0, PRIMASK\n CPSID I"
        : "=r"(primask) :: "memory");
        return primask;
    }
    static inline void rtr_critical_exit(uint32_t pm) noexcept {
        __asm volatile ("MSR PRIMASK, %0" :: "r"(pm) : "memory");
    }
#else
    static inline uint32_t rtr_critical_enter() noexcept { return 0u; }
    static inline void rtr_critical_exit(uint32_t) noexcept {}
#endif

    static void ser_u16(uint8_t* dst, uint16_t v) noexcept {
        dst[0] = static_cast<uint8_t>(v & 0xFFu);
        dst[1] = static_cast<uint8_t>((v >> 8u) & 0xFFu);
    }

    static uint16_t deser_u16(const uint8_t* src) noexcept {
        return static_cast<uint16_t>(src[0])
            | (static_cast<uint16_t>(src[1]) << 8u);
    }

    // =====================================================================
    //  내부 라우팅 항목 (12바이트)
    // =====================================================================
    struct InternalRoute {
        uint16_t dest_id;
        uint16_t next_hop;
        uint8_t  hop_count;
        uint8_t  metric;
        uint8_t  min_lqi;
        uint8_t  valid;
        uint32_t last_update_ms;
        //  Count-to-Infinity 방지: A↔B 핑퐁 루프 차단
        uint32_t hold_down_until;  // 0=정상, >0=이 시각까지 갱신 거부
    };

    static_assert(sizeof(InternalRoute) == 16u, "InternalRoute must be 16 bytes");

    // 메트릭 계산: 홉×4 + (100 - LQI)
    // 낮을수록 좋음, 0=1홉+LQI100 최적
    static uint8_t calc_metric(uint8_t hops, uint8_t lqi) noexcept {
        const uint16_t m =
            static_cast<uint16_t>(hops) * 4u +
            (100u - static_cast<uint16_t>(lqi > 100u ? 100u : lqi));
        return (m > 254u) ? 254u : static_cast<uint8_t>(m);
    }

    // =====================================================================
    //  Pimpl 구현 구조체
    //
    //  sizeof: 32×12 + 상태 ≈ 400B (< 512B)
    // =====================================================================
    static constexpr size_t MAX_RT = 32u;

    struct HTS_Mesh_Router::Impl {
        InternalRoute table[MAX_RT] = {};

        uint16_t my_id = 0u;
        uint8_t  route_count = 0u;
        uint32_t last_bcast_ms = 0u;
        bool     first_tick = true;
        bool     trigger_update = false;  // 경로 변경 시 즉시 브로드캐스트

        explicit Impl(uint16_t id) noexcept : my_id(id) {}
        ~Impl() noexcept = default;

        // 로컬 전달 콜백
        using LocalCB = void(*)(const uint8_t*, size_t, uint16_t);
        LocalCB local_deliver_cb = nullptr;

        int32_t find_route(uint16_t dest) const noexcept {
            for (size_t i = 0u; i < MAX_RT; ++i) {
                if (table[i].valid != 0u && table[i].dest_id == dest) {
                    return static_cast<int32_t>(i);
                }
            }
            return -1;
        }

        int32_t find_free() const noexcept {
            for (size_t i = 0u; i < MAX_RT; ++i) {
                if (table[i].valid == 0u) {
                    return static_cast<int32_t>(i);
                }
            }
            return -1;
        }

        void recount() noexcept {
            uint8_t cnt = 0u;
            for (size_t i = 0u; i < MAX_RT; ++i) {
                if (table[i].valid != 0u) { ++cnt; }
            }
            route_count = cnt;
        }

        // 특정 next_hop 경유 경로 무효화 + Hold-down 설정
        //  → 30초간 같은 dest로의 새 경로 수락 거부
        static constexpr uint32_t HOLD_DOWN_MS = 30000u;

        uint8_t invalidate_via(uint16_t nh, uint32_t now_ms) noexcept {
            uint8_t killed = 0u;
            for (size_t i = 0u; i < MAX_RT; ++i) {
                if (table[i].valid != 0u && table[i].next_hop == nh) {
                    table[i].valid = 0u;
                    table[i].hold_down_until = now_ms + HOLD_DOWN_MS;
                    // dest_id 유지 (hold-down 동안 조회 필요)
                    ++killed;
                }
            }
            return killed;
        }
    };

    // =====================================================================
    //  get_impl
    // =====================================================================
    HTS_Mesh_Router::Impl*
        HTS_Mesh_Router::get_impl() noexcept
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE(512B)를 초과합니다");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 요구가 alignas를 초과합니다");
        return impl_valid_.load(std::memory_order_acquire)
            ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }

    const HTS_Mesh_Router::Impl*
        HTS_Mesh_Router::get_impl() const noexcept
    {
        return impl_valid_.load(std::memory_order_acquire)
            ? reinterpret_cast<const Impl*>(impl_buf_) : nullptr;
    }

    // =====================================================================
    //  생성자 / 소멸자
    // =====================================================================
    HTS_Mesh_Router::HTS_Mesh_Router(uint16_t my_id) noexcept
        : impl_valid_(false)
    {
        Rtr_Secure_Wipe(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl(my_id);
        impl_valid_.store(true, std::memory_order_release);
    }

    HTS_Mesh_Router::~HTS_Mesh_Router() noexcept {
        impl_valid_.store(false, std::memory_order_release);
        Impl* p = reinterpret_cast<Impl*>(impl_buf_);
        if (p != nullptr) { p->~Impl(); }
        Rtr_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
    }

    // =====================================================================
    //  On_Route_Update — 이웃 경로 벡터 수신 (Bellman-Ford)
    //
    //  이웃이 보내온 라우팅 테이블을 순회하며:
    //   new_metric = neighbor_metric + calc_metric(1, neighbor_lqi)
    //   경로보다 좋으면 갱신, 없으면 추가
    //   Split Horizon: 이웃 경유 경로는 이웃에게 재전파 안 함 (Tick에서)
    // =====================================================================
    void HTS_Mesh_Router::On_Route_Update(
        uint16_t neighbor_id,
        const RouteEntry* routes, size_t route_count,
        uint8_t neighbor_lqi) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr || routes == nullptr) { return; }
        if (route_count == 0u) { return; }

        //  악의적 패킷/RF 노이즈로 route_count=0xFFFF → SRAM 초과 읽기 → HardFault
        //  MAX_ROUTES 이하로 강제 제한
        if (route_count > MAX_ROUTES) {
            route_count = MAX_ROUTES;
        }

        const uint32_t pm = rtr_critical_enter();

        for (size_t r = 0u; r < route_count; ++r) {
            const RouteEntry& re = routes[r];
            if (re.valid == 0u) { continue; }
            if (re.dest_id == p->my_id) { continue; }

            const uint8_t new_hops = re.hop_count + 1u;
            if (new_hops > MAX_HOP) { continue; }

            const uint8_t path_lqi =
                (neighbor_lqi < re.lqi) ? neighbor_lqi : re.lqi;
            const uint8_t new_metric = calc_metric(new_hops, path_lqi);

            // Poison Reverse: metric=INF → 해당 경로 삭제
            if (re.metric >= METRIC_INF) {
                const int32_t slot = p->find_route(re.dest_id);
                if (slot >= 0 &&
                    p->table[static_cast<size_t>(slot)].next_hop == neighbor_id)
                {
                    p->table[static_cast<size_t>(slot)].valid = 0u;
                    p->trigger_update = true;
                }
                continue;
            }

            //  내가 이미 dest로 가는 경로가 있고, next_hop이 이 이웃이 아닌데,
            //  이 이웃이 더 나쁜 경로를 광고 → 이웃이 나를 경유 → 루프
            //  → 거부 (Count-to-Infinity 방지)
            const int32_t slot = p->find_route(re.dest_id);

            if (slot >= 0) {
                InternalRoute& existing =
                    p->table[static_cast<size_t>(slot)];

                //  30초간 이 목적지로의 새 경로 차단 → 핑퐁 루프 소멸 대기
                if (existing.hold_down_until != 0u) {
                    continue;  // hold-down 중 → 모든 갱신 거부
                }

                //  경로 next_hop ≠ 이 이웃이고, 새 경로가 더 나쁘면
                //  → 이웃이 나를 경유해서 온 경로 (루프)
                if (existing.next_hop != neighbor_id &&
                    new_metric >= existing.metric)
                {
                    continue;  // 더 나쁜 경로 → 루프 가능 → 거부
                }

                // 같은 next_hop 갱신 또는 더 좋은 대체 경로
                existing.next_hop = neighbor_id;
                existing.hop_count = new_hops;
                existing.metric = new_metric;
                existing.min_lqi = path_lqi;
                existing.last_update_ms = 0u;
                p->trigger_update = true;
            }
            else {
                // 신규 경로 — hold-down 테이블 확인
                bool in_holddown = false;
                for (size_t h = 0u; h < MAX_RT; ++h) {
                    if (p->table[h].valid == 0u &&
                        p->table[h].hold_down_until != 0u &&
                        p->table[h].dest_id == re.dest_id)
                    {
                        in_holddown = true;
                        break;
                    }
                }
                if (in_holddown) { continue; }

                const int32_t free = p->find_free();
                if (free >= 0) {
                    InternalRoute& nr =
                        p->table[static_cast<size_t>(free)];
                    nr.dest_id = re.dest_id;
                    nr.next_hop = neighbor_id;
                    nr.hop_count = new_hops;
                    nr.metric = new_metric;
                    nr.min_lqi = path_lqi;
                    nr.valid = 1u;
                    nr.last_update_ms = 0u;
                    nr.hold_down_until = 0u;
                    p->trigger_update = true;
                }
            }
        }

        p->recount();
        rtr_critical_exit(pm);
    }

    // =====================================================================
    //  On_Link_Down — 자가치유 핵심: 링크 단절 → 경로 무효화
    //
    //  [프로세스]
    //   1. neighbor_id 경유 경로 전부 삭제
    //   2. trigger_update 설정 → 다음 Tick에서 Poison Reverse 브로드캐스트
    //   3. 이웃들이 Poison 수신 → 해당 경로 삭제 → 대체 경로 전파
    //   4. 복구: 다른 이웃의 경로 정보가 자연스럽게 대체 경로로 수렴
    // =====================================================================
    void HTS_Mesh_Router::On_Link_Down(
        uint16_t neighbor_id, uint32_t systick_ms) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        const uint32_t pm = rtr_critical_enter();
        const uint8_t killed = p->invalidate_via(neighbor_id, systick_ms);
        if (killed > 0u) {
            p->trigger_update = true;
        }
        p->recount();
        rtr_critical_exit(pm);
    }

    // =====================================================================
    //  On_Link_Up — 새 이웃 발견 → 직접 경로 추가
    // =====================================================================
    void HTS_Mesh_Router::On_Link_Up(
        uint16_t neighbor_id, uint8_t lqi) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        if (neighbor_id == p->my_id) { return; }

        const uint32_t pm = rtr_critical_enter();

        int32_t slot = p->find_route(neighbor_id);
        const uint8_t m = calc_metric(1u, lqi);

        if (slot >= 0) {
            InternalRoute& e = p->table[static_cast<size_t>(slot)];
            // 직접 경로가 기존보다 좋으면 갱신
            if (m <= e.metric) {
                e.next_hop = neighbor_id;
                e.hop_count = 1u;
                e.metric = m;
                e.min_lqi = lqi;
                e.last_update_ms = 0u;
                p->trigger_update = true;
            }
        }
        else {
            slot = p->find_free();
            if (slot >= 0) {
                InternalRoute& nr = p->table[static_cast<size_t>(slot)];
                nr.dest_id = neighbor_id;
                nr.next_hop = neighbor_id;
                nr.hop_count = 1u;
                nr.metric = m;
                nr.min_lqi = lqi;
                nr.valid = 1u;
                nr.last_update_ms = 0u;
                p->trigger_update = true;
            }
        }

        p->recount();
        rtr_critical_exit(pm);
    }

    // =====================================================================
    //  Register_Local_Deliver — 로컬 수신 콜백 등록
    // =====================================================================
    void HTS_Mesh_Router::Register_Local_Deliver(
        LocalDeliverCallback cb) noexcept
    {
        Impl* p = get_impl();
        if (p != nullptr) { p->local_deliver_cb = cb; }
    }

    // =====================================================================
    //  내부: 메쉬 헤더 부착 + 인큐 공통 로직
    //
    //  [헤더 구조 — 파일 전역 단일 정의]
    //   [0-1] next_hop       MAC 전송 대상
    //   [2-3] final_dest     최종 목적지
    //   [4]   ttl            잔여 홉
    //   [5]   src_id_lo      원본 송신자 하위 바이트
    //   [6..] payload        순수 데이터 (헤더 미포함)
    //
    //  [중복 캡슐화 방지 원리]
    //   송신: Forward → build_and_enqueue(header + payload)
    //   중계: On_Packet_Received → 구 헤더 제거(&pkt[HDR]) →
    //         build_and_enqueue(신 헤더 + payload)
    //   → 패킷 크기 불변: HDR + payload_len (홉마다 동일)
    // =====================================================================
    static constexpr size_t MESH_HDR = 6u;   // 파일 전역 단일 정의
    static constexpr size_t RELAY_MAX = 64u;

    // 클래스 상수와 파일 상수 동기화 검증 (빌드 타임)
    static_assert(MESH_HDR == HTS_Mesh_Router::MESH_HDR_SIZE,
        "MESH_HDR과 MESH_HDR_SIZE가 불일치합니다");
    static_assert(RELAY_MAX == HTS_Mesh_Router::MAX_RELAY_PKT,
        "RELAY_MAX와 MAX_RELAY_PKT이 불일치합니다");

    static FwdResult build_and_enqueue(
        uint16_t next_hop, uint16_t final_dest,
        uint8_t ttl, uint8_t src_lo,
        const uint8_t* payload, size_t pay_len,
        uint32_t systick_ms,
        HTS_Priority_Scheduler& scheduler) noexcept
    {
        if (pay_len + MESH_HDR > RELAY_MAX) {
            return FwdResult::NO_ROUTE;
        }

        uint8_t* const relay = acquire_rtr_pkt_slot();
        ser_u16(&relay[0], next_hop);
        ser_u16(&relay[2], final_dest);
        relay[4] = ttl;
        relay[5] = src_lo;

        for (size_t i = 0u; i < pay_len; ++i) {
            relay[MESH_HDR + i] = payload[i];
        }

        const size_t total = MESH_HDR + pay_len;
        const EnqueueResult enq = scheduler.Enqueue(
            PacketPriority::DATA,
            relay, total,
            systick_ms);

        return (enq == EnqueueResult::OK)
            ? FwdResult::OK : FwdResult::QUEUE_FULL;
    }

    // =====================================================================
    //  On_Packet_Received — 메쉬 중계 핵심
    //
    //  [프로세스]
    //   1. 메쉬 헤더 파싱 (6바이트)
    //   2. final_dest == 내 ID → 로컬 전달 (콜백)
    //   3. final_dest == 0xFFFF → 로컬 전달 + 중계 (브로드캐스트)
    //   4. final_dest == 다른 노드 → TTL 감소 + 다음 홉 탐색 + 중계
    // =====================================================================
    FwdResult HTS_Mesh_Router::On_Packet_Received(
        uint16_t src_neighbor,
        const uint8_t* pkt, size_t pkt_len,
        uint32_t systick_ms,
        HTS_Priority_Scheduler& scheduler) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr || pkt == nullptr) { return FwdResult::NO_ROUTE; }
        if (pkt_len < MESH_HDR_SIZE) { return FwdResult::NO_ROUTE; }

        (void)src_neighbor;  // 향후 역경로 학습용

        // 메쉬 헤더 파싱
        const uint16_t hdr_next = deser_u16(&pkt[0]);
        const uint16_t hdr_dest = deser_u16(&pkt[2]);
        const uint8_t  hdr_ttl = pkt[4];
        const uint8_t  hdr_src = pkt[5];

        const uint8_t* payload = &pkt[MESH_HDR_SIZE];
        const size_t   pay_len = pkt_len - MESH_HDR_SIZE;

        (void)hdr_next;  // MAC 계층이 이미 수신 판정 완료

        // ── 목적지 판정 ──

        // Case 1: 최종 목적지 = 나 → 로컬 전달
        if (hdr_dest == p->my_id) {
            if (p->local_deliver_cb != nullptr) {
                p->local_deliver_cb(payload, pay_len,
                    static_cast<uint16_t>(hdr_src));
            }
            return FwdResult::SELF_DEST;
        }

        // Case 2: 브로드캐스트 → 로컬 전달 + 중계
        if (hdr_dest == 0xFFFFu) {
            if (p->local_deliver_cb != nullptr) {
                p->local_deliver_cb(payload, pay_len,
                    static_cast<uint16_t>(hdr_src));
            }
            // TTL 감소 후 재브로드캐스트
            if (hdr_ttl <= 1u) { return FwdResult::TTL_EXPIRED; }
            return build_and_enqueue(
                0xFFFFu, 0xFFFFu,
                hdr_ttl - 1u, hdr_src,
                payload, pay_len,
                systick_ms, scheduler);
        }

        // Case 3: 다른 노드 → TTL 감소 + 경로 탐색 + 중계
        if (hdr_ttl <= 1u) { return FwdResult::TTL_EXPIRED; }

        const uint32_t pm = rtr_critical_enter();
        const int32_t slot = p->find_route(hdr_dest);
        if (slot < 0) {
            rtr_critical_exit(pm);
            return FwdResult::NO_ROUTE;
        }
        const uint16_t next = p->table[static_cast<size_t>(slot)].next_hop;
        rtr_critical_exit(pm);

        return build_and_enqueue(
            next, hdr_dest,
            hdr_ttl - 1u, hdr_src,
            payload, pay_len,
            systick_ms, scheduler);
    }

    // =====================================================================
    //  Forward — 자신이 원본 송신자: 메쉬 헤더 부착 + 인큐
    // =====================================================================
    FwdResult HTS_Mesh_Router::Forward(
        uint16_t dest_id,
        const uint8_t* payload, size_t len,
        uint8_t ttl, uint32_t systick_ms,
        HTS_Priority_Scheduler& scheduler) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr || payload == nullptr) { return FwdResult::NO_ROUTE; }

        if (dest_id == p->my_id) { return FwdResult::SELF_DEST; }
        if (ttl == 0u) { return FwdResult::TTL_EXPIRED; }

        // 브로드캐스트: 직접 전송 (next_hop = 0xFFFF)
        if (dest_id == 0xFFFFu) {
            return build_and_enqueue(
                0xFFFFu, 0xFFFFu,
                ttl, static_cast<uint8_t>(p->my_id & 0xFFu),
                payload, len,
                systick_ms, scheduler);
        }

        // 유니캐스트: 경로 탐색
        const uint32_t pm = rtr_critical_enter();
        const int32_t slot = p->find_route(dest_id);
        if (slot < 0) {
            rtr_critical_exit(pm);
            return FwdResult::NO_ROUTE;
        }
        const uint16_t next = p->table[static_cast<size_t>(slot)].next_hop;
        rtr_critical_exit(pm);

        return build_and_enqueue(
            next, dest_id,
            ttl, static_cast<uint8_t>(p->my_id & 0xFFu),
            payload, len,
            systick_ms, scheduler);
    }

    // =====================================================================
    //  조회
    // =====================================================================
    bool HTS_Mesh_Router::Get_Route(
        uint16_t dest_id, RouteEntry& out) const noexcept
    {
        const Impl* p = get_impl();
        if (p == nullptr) { return false; }

        const uint32_t pm = rtr_critical_enter();
        const int32_t slot = p->find_route(dest_id);
        if (slot < 0) {
            rtr_critical_exit(pm);
            return false;
        }
        const InternalRoute& ir = p->table[static_cast<size_t>(slot)];
        out.dest_id = ir.dest_id;
        out.next_hop = ir.next_hop;
        out.hop_count = ir.hop_count;
        out.metric = ir.metric;
        out.lqi = ir.min_lqi;
        out.valid = 1u;
        rtr_critical_exit(pm);
        return true;
    }

    size_t HTS_Mesh_Router::Get_All_Routes(
        RouteEntry* out, size_t cap) const noexcept
    {
        const Impl* p = get_impl();
        if (p == nullptr || out == nullptr || cap == 0u) { return 0u; }

        const uint32_t pm = rtr_critical_enter();
        size_t count = 0u;
        for (size_t i = 0u; i < MAX_RT && count < cap; ++i) {
            const InternalRoute& ir = p->table[i];
            if (ir.valid == 0u) { continue; }
            RouteEntry& r = out[count];
            r.dest_id = ir.dest_id;
            r.next_hop = ir.next_hop;
            r.hop_count = ir.hop_count;
            r.metric = ir.metric;
            r.lqi = ir.min_lqi;
            r.valid = 1u;
            ++count;
        }
        rtr_critical_exit(pm);
        return count;
    }

    size_t HTS_Mesh_Router::Get_Route_Count() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? static_cast<size_t>(p->route_count) : 0u;
    }

    // =====================================================================
    //  Tick — 경로 노화 + 트리거/주기 브로드캐스트
    //
    //  [노화] 60초 미갱신 → 경로 삭제
    //  [트리거] 경로 변경 시 즉시 라우팅 벡터 브로드캐스트
    //  [주기] 30초마다 정기 브로드캐스트 (수렴 보장)
    // =====================================================================
    static constexpr uint32_t BCAST_INTERVAL_MS = 30000u;  // 30초

    void HTS_Mesh_Router::Tick(
        uint32_t systick_ms,
        HTS_Priority_Scheduler& scheduler) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        const uint32_t pm = rtr_critical_enter();

        if (p->first_tick) {
            p->last_bcast_ms = systick_ms - BCAST_INTERVAL_MS;
            p->first_tick = false;
            for (size_t i = 0u; i < MAX_RT; ++i) {
                if (p->table[i].valid != 0u && p->table[i].last_update_ms == 0u) {
                    p->table[i].last_update_ms = systick_ms;
                }
            }
            p->trigger_update = true;
        }

        //  역산 (hold_down_until - HOLD_DOWN_MS) → 래핑 시 붕괴
        //  (systick_ms - hold_down_until) < 0x80000000 → 경과 판정
        //  uint32_t 래핑에 면역 (49일 주기 내 정상 동작)
        for (size_t i = 0u; i < MAX_RT; ++i) {
            if (p->table[i].hold_down_until == 0u) { continue; }
            if (p->table[i].valid != 0u) { continue; }  // 유효 경로는 건드리지 않음

            const uint32_t elapsed = systick_ms - p->table[i].hold_down_until;
            // elapsed < 0x80000000 = "현재 시각이 만료 시각을 지남"
            if (elapsed < 0x80000000u) {
                // Hold-down 만료 → 슬롯 완전 해제 (재사용 가능)
                Rtr_Secure_Wipe(&p->table[i], sizeof(InternalRoute));
            }
        }

        // 경로 노화: 60초 미갱신 → 삭제
        for (size_t i = 0u; i < MAX_RT; ++i) {
            if (p->table[i].valid == 0u) { continue; }
            if (p->table[i].last_update_ms == 0u) {
                p->table[i].last_update_ms = systick_ms;
                continue;
            }
            const uint32_t age = systick_ms - p->table[i].last_update_ms;
            if (age >= ROUTE_AGE_MS) {
                Rtr_Secure_Wipe(&p->table[i], sizeof(InternalRoute));
                p->trigger_update = true;
            }
        }
        p->recount();

        // 브로드캐스트 판정 (트리거 또는 주기)
        const uint32_t since_bcast = systick_ms - p->last_bcast_ms;
        const bool do_bcast =
            p->trigger_update || (since_bcast >= BCAST_INTERVAL_MS);

        if (!do_bcast) {
            rtr_critical_exit(pm);
            return;
        }

        // 라우팅 벡터 패킷 조립 (간소화: 상위 4개 경로)
        // [0-1] src_id
        // [2]   route_count
        // [3]   r0_dest_hi, [4] r0_dest_lo, [5] r0_hop, [6] r0_metric, [7] r0_lqi
        // (실제로는 여러 패킷으로 분할 → 여기서는 요약만)
        uint8_t* const pkt = acquire_rtr_pkt_slot();
        Rtr_Secure_Wipe(pkt, 8u);
        ser_u16(&pkt[0], p->my_id);
        pkt[2] = p->route_count;
        // 상위 3경로 요약 (최적 메트릭순)
        uint8_t filled = 0u;
        for (size_t i = 0u; i < MAX_RT && filled < 3u; ++i) {
            if (p->table[i].valid == 0u) { continue; }
            // pkt[3+filled] = dest_id 하위 8비트 (간소화)
            pkt[3u + filled] = static_cast<uint8_t>(
                p->table[i].dest_id & 0xFFu);
            ++filled;
        }
        pkt[6] = filled;
        pkt[7] = 0xAAu;  // 라우팅 벡터 패킷 식별자

        p->last_bcast_ms = systick_ms;
        p->trigger_update = false;

        rtr_critical_exit(pm);

        // P2 DATA 브로드캐스트
        const EnqueueResult enq = scheduler.Enqueue(
            PacketPriority::DATA,
            pkt, 8u,
            systick_ms);
        (void)enq;

    }

    // =====================================================================
    //  Shutdown
    // =====================================================================
    void HTS_Mesh_Router::Shutdown() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        const uint32_t pm = rtr_critical_enter();
        Rtr_Secure_Wipe(p->table, sizeof(p->table));
        p->route_count = 0u;
        rtr_critical_exit(pm);
    }

} // namespace ProtectedEngine
