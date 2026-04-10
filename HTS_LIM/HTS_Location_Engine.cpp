// =========================================================================
// HTS_Location_Engine.cpp
// 삼각측량 위치 추적 엔진 구현부
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// [핵심 알고리즘]
//  · 3+ 앵커 ToA 거리 → 선형화 최소제곱 삼각측량
//  · Cramer 규칙 (2×2 연립방정식)
//  · 정수 산술 (미터 단위, 32비트 UDIV)
//  · 위치 보고: 8바이트 패킷 → 상황실 지도
//
// [정밀도]
//  앵커 3개, 거리 ±30m → 위치 ±50m (산악)
//  앵커 4+개 → 최소제곱 → ±30m
// =========================================================================
#include "HTS_Location_Engine.h"
#include "HTS_Arm_Irq_Mask_Guard.h"
#include "HTS_Mesh_Sync.h"
#include "HTS_Priority_Scheduler.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

static_assert(sizeof(int32_t) == 4, "int32_t must be 4 bytes");

namespace ProtectedEngine {

    // =====================================================================
    //  보안 소거 / PRIMASK
    // =====================================================================
    static void Loc_Secure_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) { q[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  좌표 변환 상수
    //
    //  1° 위도 = 111,320m → 1e4 단위 = 11.132m
    //  1° 경도 = 111,320 × cos(37°) ≈ 88,800m → 1e4 단위 ≈ 8.880m
    //
    //  lat_1e4 → 미터: × LAT_M_PER_UNIT / 1000
    //  lon_1e4 → 미터: × LON_M_PER_UNIT / 1000
    //  (×1000 정밀도 보존 후 /1000)
    // =====================================================================
    static constexpr int32_t LAT_MM_PER_UNIT = 11132;  // 1e4 단위당 mm
    static constexpr int32_t LON_MM_PER_UNIT = 8880;   // 1e4 단위당 mm (37°)

    // GPS 압축 (Emergency_Beacon 동일)
    static constexpr int32_t LAT_OFFSET = 330000;
    static constexpr int32_t LON_OFFSET = 1240000;
    static constexpr int32_t GPS_DIV = 10;

    static void ser_u16(uint8_t* dst, uint16_t v) noexcept {
        dst[0] = static_cast<uint8_t>(v & 0xFFu);
        dst[1] = static_cast<uint8_t>((v >> 8u) & 0xFFu);
    }

    static void ser_i16(uint8_t* dst, int16_t v) noexcept {
        ser_u16(dst, static_cast<uint16_t>(v));
    }

    static int16_t compress_coord(int32_t val_1e4, int32_t offset) noexcept {
        const int32_t v = (val_1e4 - offset) / GPS_DIV;
        if (v > 32767) { return 32767; }
        if (v < -32768) { return -32768; }
        return static_cast<int16_t>(v);
    }


    // =====================================================================
    //  삼각측량 (3앵커 Cramer — 순수 32비트, ASIC 호환)
    //
    //  [ASIC 설계 원칙]
    //   · int64_t 전면 금지
    //   · 나눗셈 1회 (역수 곱셈으로 2회→1회 절감)
    //   · HLS 파이프라인 친화
    //
    //  [Q7 정규화]
    //   좌표/거리 >> 7 (÷128) → 모든 중간값 int32_t 보장
    //   K×B max: 1,429,138,000 < int32_t(2.1×10^9)
    //   정밀도: ±12.8m (에폭 평균 후 ±2m)
    // =====================================================================
    static constexpr int32_t TRI_SHIFT = 7;

    struct TriResult {
        int32_t x_dm;
        int32_t y_dm;
        bool    valid;
    };

    static TriResult trilaterate_3(
        int32_t x1, int32_t y1, int32_t d1,
        int32_t x2, int32_t y2, int32_t d2,
        int32_t x3, int32_t y3, int32_t d3) noexcept
    {
        TriResult r = { 0, 0, false };

        const int32_t ax2 = x2 - x1;
        const int32_t ay2 = y2 - y1;
        const int32_t ax3 = x3 - x1;
        const int32_t ay3 = y3 - y1;

        const int32_t qx2 = ax2 >> TRI_SHIFT;
        const int32_t qy2 = ay2 >> TRI_SHIFT;
        const int32_t qx3 = ax3 >> TRI_SHIFT;
        const int32_t qy3 = ay3 >> TRI_SHIFT;
        const int32_t qd1 = d1 >> TRI_SHIFT;
        const int32_t qd2 = d2 >> TRI_SHIFT;
        const int32_t qd3 = d3 >> TRI_SHIFT;

        const int32_t det_half = qx2 * qy3 - qx3 * qy2;
        if (det_half > -2 && det_half < 2) { return r; }

        const int32_t K12 = (qd1 * qd1 - qd2 * qd2) + (qx2 * qx2 + qy2 * qy2);
        const int32_t K13 = (qd1 * qd1 - qd3 * qd3) + (qx3 * qx3 + qy3 * qy3);

        //
        //  위협: K12(~4×10^6) × qy3(~10^3) = ~4×10^9 > INT32_MAX(2.1×10^9)
        //        x_num(~10^9) × inv_det(~10^5) = ~10^14 >> INT32_MAX
        //        → 좌표 쓰레기값 → 구조대상자 위치 완전 붕괴
        //
        //  K12*qy3, x_num*inv_det 모두 int64_t 중간값 사용
        //        Cortex-M4 SMULL: 32×32→64 곱셈 단일 사이클 (성능 영향 0)
        const int64_t x_num = static_cast<int64_t>(K12) * qy3
            - static_cast<int64_t>(K13) * qy2;
        const int64_t y_num = static_cast<int64_t>(qx2) * K13
            - static_cast<int64_t>(qx3) * K12;

        const int32_t det_full = det_half * 2;
        if (det_full == 0) { return r; }

        //  inv_det = (1 << 20) / det_full   (Q20 역수, SDIV 1회)
        //  x = (x_num × inv_det) >> 20      (SMULL 1회 + 시프트)
        //  y = (y_num × inv_det) >> 20      (SMULL 1회 + 시프트)
        //  ASIC: 나눗셈기 1개, 곱셈기 재사용 → 면적 50% 절감
        static constexpr int32_t RECIP_SHIFT = 20;
        const int32_t inv_det =
            (static_cast<int32_t>(1) << RECIP_SHIFT) / det_full;

        //  Cortex-M4: SMULL+SMLAL 조합 (~2cyc), int32-only 경로 대비 +1cyc
        const int32_t x_q7 = static_cast<int32_t>(
            (x_num * static_cast<int64_t>(inv_det)) >> RECIP_SHIFT);
        const int32_t y_q7 = static_cast<int32_t>(
            (y_num * static_cast<int64_t>(inv_det)) >> RECIP_SHIFT);

        r.x_dm = (x_q7 << TRI_SHIFT) + x1;
        r.y_dm = (y_q7 << TRI_SHIFT) + y1;
        r.valid = true;
        return r;
    }

    // =====================================================================
    //  Pimpl 구현 구조체
    //
    //  ③ 다중 에폭 위치 링버퍼 (8포인트)
    //  ④ TDOA: 기준 앵커 오프셋 차분 (evaluate 내 적용)
    // =====================================================================

    // ③ 위치 에폭 항목 (8바이트)
    struct PosEpoch {
        int32_t lat_1e4;
        int32_t lon_1e4;
    };

    static constexpr size_t EPOCH_RING_SIZE = 8u;

    struct HTS_Location_Engine::Impl {
        AnchorEntry anchors[MAX_ANCHORS] = {};

        uint16_t    my_id = 0u;
        LocationMode mode = LocationMode::MOBILE;
        DeviceClass  dev_class = DeviceClass::HUMAN_ADULT;
        PositionResult position = {};
        int32_t     my_lat_1e4 = 0;
        int32_t     my_lon_1e4 = 0;
        uint32_t    last_report_ms = 0u;
        bool        first_tick = true;

        // ③ 다중 에폭 링버퍼
        PosEpoch  epoch_ring[EPOCH_RING_SIZE] = {};
        uint8_t   epoch_head = 0u;
        uint8_t   epoch_count = 0u;

        // ── Privacy Gate 상태 ──
        // PET/LIVESTOCK/ASSET → ALWAYS_TRACKABLE (Privacy Gate 우회)
        TrackingMode tracking_mode = TrackingMode::TRACKING_OFF;
        AuthToken    auth_token = {};
        bool         auth_valid = false;
        uint32_t     owner_pin_hash = 0u;
        bool         owner_pin_set = false;
        uint16_t     family_ids[4] = {};
        uint8_t      family_count = 0u;
        uint8_t      battery_pct = 100u;
        bool         is_moving = false;
        //  last_gasp_sent=true → Tick 빈 블록 → 전송 0회
        //  remain=3→2→1→DONE 카운터 + DONE 센티넬(재발동 영구 차단)
        //
        //  상태: IDLE(0) → 배터리<5% → ACTIVE(3→2→1) → DONE(0xFF) → 영구 종료
        //  DONE 이후 Set_Battery_Percent 재호출 시 remain≠0(IDLE) → 재발동 차단
        //  → 무한 버스트 지옥 원천 방지
        static constexpr uint8_t LAST_GASP_IDLE = 0u;
        static constexpr uint8_t LAST_GASP_DONE = 0xFFu;
        uint8_t      last_gasp_remain = LAST_GASP_IDLE;
        uint32_t     prev_interval = 0xFFFFFFFFu;

        // 감사 로그 (8건 링버퍼)
        AuditEntry   audit_log[8] = {};
        uint8_t      audit_head = 0u;
        uint8_t      audit_count = 0u;

        /// 인스턴스별 위치 보고 패킷 슬롯 (전역 풀 제거 — 다중 인스턴스/레이스 방지)
        static constexpr uint8_t LOC_PKT_SLOTS = 4u;
        static constexpr uint8_t LOC_PKT_SLOT_MASK = 3u;
        alignas(uint32_t) uint8_t loc_pkt_pool[LOC_PKT_SLOTS][HTS_Location_Engine::POS_REPORT_SIZE]{};
        std::atomic<uint8_t> loc_pkt_slot{ 0u };

        uint8_t* acquire_loc_pkt_buffer() noexcept {
            const uint8_t idx = static_cast<uint8_t>(
                loc_pkt_slot.fetch_add(1u, std::memory_order_relaxed)
                & LOC_PKT_SLOT_MASK);
            return &loc_pkt_pool[static_cast<size_t>(idx)][0];
        }

        explicit Impl(uint16_t id, LocationMode m, DeviceClass dc) noexcept
            : my_id(id), mode(m), dev_class(dc)
        {
            // PET/LIVESTOCK/ASSET → ALWAYS_TRACKABLE (Privacy Gate 우회)
            const uint8_t cls = static_cast<uint8_t>(dc);
            if (cls >= 0x10u) {  // 0x10 이상 = 비인간
                tracking_mode = TrackingMode::ALWAYS_TRACKABLE;
            }
        }
        ~Impl() noexcept = default;

        // 감사 로그 기록
        void log_audit(uint32_t ts, uint16_t actor,
            uint8_t action) noexcept
        {
            AuditEntry& e = audit_log[audit_head];
            e.timestamp = ts;
            e.actor_id = actor;
            e.action = action;
            e.mode = static_cast<uint8_t>(tracking_mode);
            audit_head = static_cast<uint8_t>(
                (audit_head + 1u) & 7u);
            if (audit_count < 8u) { ++audit_count; }
        }

        // 배터리 적응형 보고 주기 (ms)
        uint32_t get_report_interval_ms() const noexcept {
            if (tracking_mode == TrackingMode::TRACKING_OFF) {
                return 0xFFFFFFFFu;  // 전송 안 함
            }

            // PET/LIVESTOCK/ASSET: 배터리 충전 기반 적응형
            //  태양광 충전 중(>80%): 5초, 보통: 15초, 부족: 60초, 위험: 5분
            if (tracking_mode == TrackingMode::ALWAYS_TRACKABLE) {
                if (battery_pct > 80u) { return 5000u; }    // 5초 (최대 추적)
                if (battery_pct > 50u) { return 15000u; }   // 15초
                if (battery_pct > 20u) { return 60000u; }   // 60초
                return 300000u;                              // 5분 (생존)
            }

            if (tracking_mode == TrackingMode::EMERGENCY_AUTH) {
                if (battery_pct > 50u) { return 10000u; }
                if (battery_pct > 20u) { return 30000u; }
                if (battery_pct > 10u) { return 60000u; }
                return 300000u;
            }
            // FAMILY_CONSENT
            if (battery_pct <= 20u) { return 1800000u; }
            if (!is_moving) { return 300000u; }
            return 30000u;
        }

        // ③ 에폭 추가 + 평균 계산
        void push_epoch(int32_t lat, int32_t lon) noexcept {
            epoch_ring[epoch_head].lat_1e4 = lat;
            epoch_ring[epoch_head].lon_1e4 = lon;
            epoch_head = static_cast<uint8_t>(
                (epoch_head + 1u) & 7u);
            if (epoch_count < EPOCH_RING_SIZE) { ++epoch_count; }
        }

        void avg_epoch(int32_t& out_lat, int32_t& out_lon) const noexcept {
            if (epoch_count == 0u) { out_lat = 0; out_lon = 0; return; }
            int32_t sum_lat = 0;
            int32_t sum_lon = 0;
            for (size_t i = 0u; i < epoch_count; ++i) {
                sum_lat += epoch_ring[i].lat_1e4;
                sum_lon += epoch_ring[i].lon_1e4;
            }
            // 32비트 SDIV (epoch_count ≤ 8)
            out_lat = sum_lat / static_cast<int32_t>(epoch_count);
            out_lon = sum_lon / static_cast<int32_t>(epoch_count);
        }

        int32_t find_anchor(uint16_t nid) const noexcept {
            for (size_t i = 0u; i < MAX_ANCHORS; ++i) {
                if (anchors[i].valid != 0u && anchors[i].node_id == nid) {
                    return static_cast<int32_t>(i);
                }
            }
            return -1;
        }

        int32_t find_free_anchor() const noexcept {
            for (size_t i = 0u; i < MAX_ANCHORS; ++i) {
                if (anchors[i].valid == 0u) {
                    return static_cast<int32_t>(i);
                }
            }
            return -1;
        }
    };

    // =====================================================================
    //  get_impl
    // =====================================================================
    HTS_Location_Engine::Impl*
        HTS_Location_Engine::get_impl() noexcept
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE(512B)를 초과합니다");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 요구가 alignas를 초과합니다");
        return impl_valid_.load(std::memory_order_acquire)
            ? std::launder(reinterpret_cast<Impl*>(impl_buf_)) : nullptr;
    }

    const HTS_Location_Engine::Impl*
        HTS_Location_Engine::get_impl() const noexcept
    {
        return impl_valid_.load(std::memory_order_acquire)
            ? std::launder(reinterpret_cast<const Impl*>(impl_buf_)) : nullptr;
    }

    // =====================================================================
    //  생성자 / 소멸자
    // =====================================================================
    HTS_Location_Engine::HTS_Location_Engine(
        uint16_t my_id, LocationMode mode, DeviceClass dev_class) noexcept
        : impl_valid_(false)
    {
        Loc_Secure_Wipe(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl(my_id, mode, dev_class);
        impl_valid_.store(true, std::memory_order_release);
    }

    HTS_Location_Engine::~HTS_Location_Engine() noexcept {
        const bool was_valid =
            impl_valid_.exchange(false, std::memory_order_acq_rel);
        if (was_valid) {
            Impl* const p = std::launder(reinterpret_cast<Impl*>(impl_buf_));
            p->~Impl();
            Loc_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
        }
    }

    // =====================================================================
    //  Register_Anchor — 앵커 좌표 등록
    // =====================================================================
    bool HTS_Location_Engine::Register_Anchor(
        uint16_t node_id, int32_t lat_1e4, int32_t lon_1e4) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return false; }

        Armv7m_Irq_Mask_Guard irq;

        // 앵커 갱신
        int32_t slot = p->find_anchor(node_id);
        if (slot >= 0) {
            p->anchors[static_cast<size_t>(slot)].lat_1e4 = lat_1e4;
            p->anchors[static_cast<size_t>(slot)].lon_1e4 = lon_1e4;
            irq.release();
            return true;
        }

        // 신규 등록
        slot = p->find_free_anchor();
        if (slot < 0) {
            irq.release();
            return false;
        }

        AnchorEntry& a = p->anchors[static_cast<size_t>(slot)];
        a.node_id = node_id;
        a.lat_1e4 = lat_1e4;
        a.lon_1e4 = lon_1e4;
        a.valid = 1u;

        irq.release();
        return true;
    }

    void HTS_Location_Engine::Set_My_Position(
        int32_t lat_1e4, int32_t lon_1e4) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        p->my_lat_1e4 = lat_1e4;
        p->my_lon_1e4 = lon_1e4;
    }

    // =====================================================================
    //  Update_Position — 삼각측량 실행
    //
    //  [H-ISR] PRIMASK 분할: 앵커 스냅샷·결과 커밋만 짧게 잠그고,
    //    ranging 매칭·Cramer/WLS·품질 루프는 IRQ 허용 구간에서 수행
    //    (UART/DMA 오버런·지터 완화 — Device_Status_Reporter 패턴과 동일 계열)
    // =====================================================================
    void HTS_Location_Engine::Update_Position(
        const HTS_Mesh_Sync& sync) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        if (p->mode != LocationMode::MOBILE) { return; }

        PeerRanging ranging[16] = {};
        const size_t peer_count = sync.Get_All_Ranging(ranging, 16u);

        AnchorEntry anchors_snap[MAX_ANCHORS];
        {
            Armv7m_Irq_Mask_Guard irq_snap;
            for (size_t a = 0u; a < MAX_ANCHORS; ++a) {
                anchors_snap[a] = p->anchors[static_cast<size_t>(a)];
            }
        }

        // 앵커-거리 매칭 (데시미터 단위 — 10cm 정밀도)
        struct AnchorDist {
            int32_t x_dm;
            int32_t y_dm;
            int32_t dist_dm;
        };

        AnchorDist matched[MAX_ANCHORS] = {};
        size_t match_count = 0u;

        int32_t ref_lat = 0;
        int32_t ref_lon = 0;
        bool ref_set = false;

        for (size_t a = 0u; a < MAX_ANCHORS; ++a) {
            if (anchors_snap[a].valid == 0u) { continue; }
            if (!ref_set) {
                ref_lat = anchors_snap[a].lat_1e4;
                ref_lon = anchors_snap[a].lon_1e4;
                ref_set = true;
            }

            for (size_t r = 0u; r < peer_count; ++r) {
                if (ranging[r].peer_id == anchors_snap[a].node_id &&
                    ranging[r].distance_cm > 0u)
                {
                    const int32_t dlat = anchors_snap[a].lat_1e4 - ref_lat;
                    const int32_t dlon = anchors_snap[a].lon_1e4 - ref_lon;
                    // 1e4 → 데시미터: × MM_PER_UNIT / 100
                    // ⑨ /100 → Q19 역수 곱
                    //  정밀도: |x|≤2B 범위에서 오차 < 0.002%
                    //  int64_t 중간값: |1.6B × 5243| = 8.4T → int64_t 안전
                    static constexpr int32_t Q19_RECIP_100 = 5243;
                    const int32_t x_dm = static_cast<int32_t>(
                        (static_cast<int64_t>(dlon)
                            * static_cast<int64_t>(LON_MM_PER_UNIT)
                            * static_cast<int64_t>(Q19_RECIP_100)) >> 19);
                    const int32_t y_dm = static_cast<int32_t>(
                        (static_cast<int64_t>(dlat)
                            * static_cast<int64_t>(LAT_MM_PER_UNIT)
                            * static_cast<int64_t>(Q19_RECIP_100)) >> 19);
                    // cm → dm
                    // ⑨ /10u → Q16 역수 곱
                    static constexpr uint32_t Q16_RECIP_10 = 6554u;
                    const int32_t d_dm =
                        static_cast<int32_t>(
                            (static_cast<uint64_t>(ranging[r].distance_cm)
                                * Q16_RECIP_10) >> 16u);

                    if (match_count < MAX_ANCHORS) {
                        matched[match_count].x_dm = x_dm;
                        matched[match_count].y_dm = y_dm;
                        matched[match_count].dist_dm = d_dm;
                        ++match_count;
                    }
                    break;
                }
            }
        }

        // 최소 3앵커
        if (match_count < 3u || !ref_set) {
            Armv7m_Irq_Mask_Guard irq;
            p->position.valid = 0u;
            p->position.map_10m_cert = 0u;
            p->position.anchor_count = static_cast<uint8_t>(match_count);
            return;
        }

        // ④ TDOA: 기준 앵커(0번) 거리를 차분하여 클럭 오프셋 상쇄
        //  d_tdoa[i] = d[i] - d[0]
        //  이렇게 하면 공통 클럭 오프셋이 상쇄됨
        //  삼각측량은 d²차이를 사용하므로 TDOA 차분이 자연스럽게 반영
        const int32_t d_ref = matched[0].dist_dm;
        for (size_t i = 1u; i < match_count; ++i) {
            // 차분 거리로 교체하지 않음 — Cramer K항에서 d1²-di²가
            // 이미 차분 구조이므로 TDOA 효과는 앵커0 원점 이동으로 달성
            // 대신: 거리 품질 가중치로 사용 (기준과 차이 큰 쪽이 정밀)
            (void)d_ref;
        }

        // ② WLS: 앵커 4+개 시 다중 3-조합 평균 (가중 최소제곱 근사)
        //  C(4,3)=4조합, C(5,3)=10조합, C(6,3)=20조합
        //  최대 8조합까지 (ISR 지터 제한)
        int32_t sum_x = 0;
        int32_t sum_y = 0;
        uint8_t valid_count = 0u;

        // ② WLS: 정적 조합 테이블 (3중 루프 제거 — ASIC FSM 방지)
        //  HLS: 단일 for 루프 → 파이프라인 전개 가능
        struct Combo { uint8_t i; uint8_t j; uint8_t k; };
        static constexpr Combo combo_table[8] = {
            {0,1,2}, {0,1,3}, {0,2,3}, {1,2,3},
            {0,1,4}, {0,2,4}, {0,3,4}, {1,2,4},
        };
        // 앵커 수별 유효 조합 수 (3→1, 4→4, 5+→8)
        static constexpr uint8_t combo_count_by_n[9] = {
            0,0,0, 1, 4, 8, 8, 8, 8
        };
        const uint8_t n_combos = (match_count <= 8u)
            ? combo_count_by_n[match_count] : 8u;

        // 단일 for 루프: ASIC에서 파이프라인 전개 가능
        for (uint8_t c = 0u; c < n_combos; ++c) {
            const uint8_t ci = combo_table[c].i;
            const uint8_t cj = combo_table[c].j;
            const uint8_t ck = combo_table[c].k;
            // 인덱스 범위 검증 (match_count 미만)
            if (ck >= match_count) { continue; }

            const TriResult t = trilaterate_3(
                matched[ci].x_dm, matched[ci].y_dm, matched[ci].dist_dm,
                matched[cj].x_dm, matched[cj].y_dm, matched[cj].dist_dm,
                matched[ck].x_dm, matched[ck].y_dm, matched[ck].dist_dm);
            if (t.valid) {
                sum_x += t.x_dm;
                sum_y += t.y_dm;
                ++valid_count;
            }
        }

        if (valid_count == 0u) {
            Armv7m_Irq_Mask_Guard irq;
            p->position.valid = 0u;
            p->position.map_10m_cert = 0u;
            return;
        }

        // ② 가중 평균 (32비트 SDIV — valid_count는 런타임 변수, 하드웨어 SDIV 허용)
        const int32_t avg_x_dm = sum_x / static_cast<int32_t>(valid_count);
        const int32_t avg_y_dm = sum_y / static_cast<int32_t>(valid_count);

        // 로컬 데시미터 → GPS 좌표(1e4)
        // [⑨ 주석] constexpr 상수 나눗셈 — GCC -O2 자동 역수 곱셈 변환
        //  /LAT_MM_PER_UNIT(11132), /LON_MM_PER_UNIT(8880): 비2의제곱
        //  Cortex-M4: 컴파일러가 (x * magic) >> shift 시퀀스로 자동 변환
        //  Q 수동 역수 적용 시 정밀도 손실(GPS ±1dm) vs 자동 변환 정밀도 우위
        //  → 컴파일러 자동 역수 유지 (32비트 SDIV 폴백도 하드웨어 지원)
        const int32_t dlat_1e4 = (avg_y_dm * 100) / LAT_MM_PER_UNIT;
        const int32_t dlon_1e4 = (avg_x_dm * 100) / LON_MM_PER_UNIT;

        const int32_t new_lat = ref_lat + dlat_1e4;
        const int32_t new_lon = ref_lon + dlon_1e4;

        // 정확도 후보·품질: 스냅샷 기준 peer 루프 — IRQ 허용
        uint8_t acc_m = 50u;
        if (valid_count >= 2u) { acc_m = 25u; }   // ② 다중 조합
        if (valid_count >= 4u) { acc_m = 12u; }   // 4+ 조합 시 상한 축소 (10m 지도 인증 후보)

        uint8_t quality = 0u;
        for (size_t r = 0u; r < peer_count; ++r) {
            if (ranging[r].sync_quality > quality) {
                quality = ranging[r].sync_quality;
            }
        }
        if (quality >= 80u) { acc_m = static_cast<uint8_t>(acc_m >> 1u); }

        {
            Armv7m_Irq_Mask_Guard irq;
            // ③ 다중 에폭 링버퍼에 추가 + 평균 산출 (Impl 일관성)
            p->push_epoch(new_lat, new_lon);

            int32_t avg_lat = 0;
            int32_t avg_lon = 0;
            p->avg_epoch(avg_lat, avg_lon);

            if (p->epoch_count >= 4u) { acc_m = static_cast<uint8_t>(acc_m >> 1u); }  // ③ 에폭

            // 상황실 지도 「10m 이내」 표시: 앵커 4+ · 동기 품질 · 에폭 안정 · 오차 상한 10m 이하
            uint8_t map_10m_cert = 0u;
            if (match_count >= 4u && quality >= 80u && p->epoch_count >= 4u
                && acc_m <= 10u) {
                map_10m_cert = 1u;
            }

            p->position.lat_1e4 = avg_lat;
            p->position.lon_1e4 = avg_lon;
            p->position.accuracy_m = acc_m;
            p->position.anchor_count = static_cast<uint8_t>(match_count);
            p->position.quality = quality;
            p->position.map_10m_cert = map_10m_cert;
            p->position.valid = 1u;
        }
    }

    PositionResult HTS_Location_Engine::Get_Position() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) {
            PositionResult empty = {};
            return empty;
        }
        PositionResult result = {};
        {
            Armv7m_Irq_Mask_Guard irq;
            result = p->position;
        }
        return result;
    }

    // =====================================================================
    //  Privacy Gate — Zero-Knowledge 위치 추적 인가
    // =====================================================================
    TrackingMode HTS_Location_Engine::Get_Tracking_Mode() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? p->tracking_mode : TrackingMode::TRACKING_OFF;
    }

    // =====================================================================
    //  HMAC 간이 검증 (양산 시 LSH256_Bridge::Hash_256 연동)
    //
    //  토큰 필드로 해시 계산 → 서명과 constant-time 비교
    //  양산: LSH256_Bridge::Hash_256(token_data, len, expected)
    // =====================================================================
    static bool verify_token_signature(const AuthToken& token) noexcept {
        // 서명 대상: agency_id~zone_radius_m (pad·signature 제외) — 구조체 패딩 미포함
        static constexpr size_t kSignedPayloadBytes =
            sizeof(token.agency_id) + sizeof(token.target_device_id) +
            sizeof(token.issue_time) + sizeof(token.last_heartbeat) +
            sizeof(token.zone_lat_1e4) + sizeof(token.zone_lon_1e4) +
            sizeof(token.zone_radius_m);
        static_assert(kSignedPayloadBytes == 22u, "AuthToken signed span");
        uint8_t data[kSignedPayloadBytes];
        size_t o = 0u;
        std::memcpy(data + o, &token.agency_id, sizeof(token.agency_id));
        o += sizeof(token.agency_id);
        std::memcpy(data + o, &token.target_device_id,
            sizeof(token.target_device_id));
        o += sizeof(token.target_device_id);
        std::memcpy(data + o, &token.issue_time, sizeof(token.issue_time));
        o += sizeof(token.issue_time);
        std::memcpy(data + o, &token.last_heartbeat,
            sizeof(token.last_heartbeat));
        o += sizeof(token.last_heartbeat);
        std::memcpy(data + o, &token.zone_lat_1e4,
            sizeof(token.zone_lat_1e4));
        o += sizeof(token.zone_lat_1e4);
        std::memcpy(data + o, &token.zone_lon_1e4,
            sizeof(token.zone_lon_1e4));
        o += sizeof(token.zone_lon_1e4);
        std::memcpy(data + o, &token.zone_radius_m,
            sizeof(token.zone_radius_m));
        o += sizeof(token.zone_radius_m);
        const size_t data_len = o;

        // 간이 해시: XOR 폴드 (양산 시 LSH256_Bridge 교체)
        // 토큰 필드 전체를 4바이트씩 XOR → 서명 첫 4바이트와 비교
        uint32_t hash = 0x5A5A5A5Au;  // 초기 시드 (CA 공개키 대용)
        for (size_t i = 0u; i < data_len; ++i) {
            hash ^= static_cast<uint32_t>(data[i]) << ((i & 3u) << 3u);
            hash = (hash << 7u) | (hash >> 25u);  // 비트 회전
        }

        // Constant-Time 비교 (서명 첫 4바이트)
        const uint32_t sig_val =
            (static_cast<uint32_t>(token.signature[0]) << 24u) |
            (static_cast<uint32_t>(token.signature[1]) << 16u) |
            (static_cast<uint32_t>(token.signature[2]) << 8u) |
            static_cast<uint32_t>(token.signature[3]);

        // CT 비교: XOR → 0이면 일치
        const uint32_t diff = hash ^ sig_val;
        return (diff == 0u);
    }

    // =====================================================================
    //  Zone 범위 확인 (내 위치가 수색 영역 안인지)
    // =====================================================================
    static bool is_within_zone(
        int32_t my_lat, int32_t my_lon,
        const AuthToken& token) noexcept
    {
        if (token.zone_radius_m == 0u) { return true; }  // 무제한

        const int32_t dlat = my_lat - token.zone_lat_1e4;
        const int32_t dlon = my_lon - token.zone_lon_1e4;

        // 거리²(m²) ≈ (dlat×11)² + (dlon×9)² — int32 제곱은 원거리에서 UB → int64
        const int64_t dy = static_cast<int64_t>(dlat) * 11;
        const int64_t dx = static_cast<int64_t>(dlon) * 9;
        const int64_t dist_sq = dy * dy + dx * dx;

        const int64_t radius =
            static_cast<int64_t>(token.zone_radius_m) * 10;
        const int64_t radius_sq = radius * radius;

        return (dist_sq <= radius_sq);
    }

    bool HTS_Location_Engine::Authorize_Emergency(
        const AuthToken& token, uint32_t current_sec) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return false; }

        Armv7m_Irq_Mask_Guard irq;

        // 대상 확인: 내 ID 또는 와일드카드(0xFFFF)
        const bool is_wildcard =
            (token.target_device_id == DEVICE_ID_WILDCARD);
        if (!is_wildcard && token.target_device_id != p->my_id) {
            p->log_audit(current_sec, token.agency_id, 3u);
            irq.release();
            return false;
        }

        // 와일드카드는 경찰/소방 기관 ID만 허용
        if (is_wildcard) {
            const bool valid_agency =
                (token.agency_id == 0x0110u) ||  // 경찰청
                (token.agency_id == 0x0119u);    // 소방청
            if (!valid_agency) {
                p->log_audit(current_sec, token.agency_id, 3u);
                irq.release();
                return false;
            }
        }

        // 시간 유효성 (발급 시각 이후여야)
        if (current_sec < token.issue_time) {
            p->log_audit(current_sec, token.agency_id, 3u);
            irq.release();
            return false;
        }

        // Heartbeat_Renew로 갱신, 48h 미수신 시 만료

        // Zone 확인 (내 위치가 수색 영역 안인지)
        if (!is_within_zone(p->position.lat_1e4,
            p->position.lon_1e4, token))
        {
            p->log_audit(current_sec, token.agency_id, 3u);
            irq.release();
            return false;
        }

        if (!verify_token_signature(token)) {
            p->log_audit(current_sec, token.agency_id, 3u);
            irq.release();
            return false;
        }

        // 인가 성공 — 하트비트 시각을 현재로 초기화
        p->auth_token = token;
        p->auth_token.last_heartbeat = current_sec;
        p->auth_valid = true;
        p->last_gasp_remain = Impl::LAST_GASP_IDLE;
        p->tracking_mode = TrackingMode::EMERGENCY_AUTH;
        p->log_audit(current_sec, token.agency_id, 0u);
        irq.release();
        return true;
    }

    bool HTS_Location_Engine::Enable_Family_Tracking(
        uint32_t owner_pin, uint16_t family_id) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return false; }
        if (!p->owner_pin_set) { return false; }
        if (p->owner_pin_hash != owner_pin) { return false; }

        Armv7m_Irq_Mask_Guard irq;

        // 중복 확인
        for (size_t i = 0u; i < p->family_count; ++i) {
            if (p->family_ids[i] == family_id) {
                irq.release();
                return true;  // 이미 등록
            }
        }

        if (p->family_count >= MAX_FAMILY_DEVS) {
            irq.release();
            return false;
        }

        p->family_ids[p->family_count] = family_id;
        p->family_count++;
        p->tracking_mode = TrackingMode::FAMILY_CONSENT;
        p->log_audit(0u, family_id, 0u);
        irq.release();
        return true;
    }

    bool HTS_Location_Engine::Owner_Kill_Switch(uint32_t owner_pin) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return false; }

        // PET/LIVESTOCK/ASSET: 추적 해제 불가 (유기/도난 방지)
        const uint8_t cls = static_cast<uint8_t>(p->dev_class);
        if (cls >= 0x10u) { return false; }

        if (!p->owner_pin_set) { return false; }
        if (p->owner_pin_hash != owner_pin) { return false; }

        Armv7m_Irq_Mask_Guard irq;
        p->tracking_mode = TrackingMode::TRACKING_OFF;
        p->auth_valid = false;
        p->family_count = 0u;
        Loc_Secure_Wipe(p->family_ids, sizeof(p->family_ids));
        Loc_Secure_Wipe(&p->auth_token, sizeof(p->auth_token));
        p->log_audit(0u, p->my_id, 2u);  // 소유자 해제
        irq.release();
        return true;
    }

    void HTS_Location_Engine::Set_Battery_Percent(uint8_t pct) noexcept {
        Impl* p = get_impl();
        if (p != nullptr) { p->battery_pct = pct; }

        //  remain==IDLE(0)일 때만 발동 → DONE(0xFF)이면 조건 불일치 → 재발동 불가
        //  → 배터리 5% 유지 구간에서 무한 버스트 지옥 원천 차단
        if (p != nullptr && pct < 5u &&
            p->last_gasp_remain == Impl::LAST_GASP_IDLE &&
            p->tracking_mode == TrackingMode::EMERGENCY_AUTH)
        {
            p->last_gasp_remain = 3u;  // Tick에서 3회 연속 즉시 전송
        }
    }

    // =====================================================================
    //  Heartbeat_Renew — 수색 하트비트 갱신 (48시간 연장)
    // =====================================================================
    bool HTS_Location_Engine::Heartbeat_Renew(
        uint16_t agency_id, uint32_t current_sec) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return false; }
        if (p->tracking_mode != TrackingMode::EMERGENCY_AUTH) { return false; }
        if (!p->auth_valid) { return false; }

        // 기관 ID 일치 확인 (다른 기관이 갱신 시도 차단)
        if (p->auth_token.agency_id != agency_id) { return false; }

        Armv7m_Irq_Mask_Guard irq;
        p->auth_token.last_heartbeat = current_sec;
        p->log_audit(current_sec, agency_id, 4u);  // 4=갱신
        irq.release();
        return true;
    }

    void HTS_Location_Engine::Set_Moving(bool moving) noexcept {
        Impl* p = get_impl();
        if (p != nullptr) { p->is_moving = moving; }
    }

    void HTS_Location_Engine::Set_Owner_PIN(uint32_t pin_hash) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        if (p->owner_pin_set) { return; }  // 이중 설정 차단
        p->owner_pin_hash = pin_hash;
        p->owner_pin_set = true;
    }

    size_t HTS_Location_Engine::Get_Audit_Log(
        AuditEntry* out, size_t cap) const noexcept
    {
        const Impl* p = get_impl();
        if (p == nullptr || out == nullptr || cap == 0u) { return 0u; }
        size_t n = 0u;
        {
            Armv7m_Irq_Mask_Guard irq;
            n = (p->audit_count < cap) ? p->audit_count : cap;
            for (size_t i = 0u; i < n; ++i) {
                out[i] = p->audit_log[i];
            }
        }
        return n;
    }

    // =====================================================================
    //  Tick — 주기적 위치 보고 패킷 전송
    //
    //  패킷 (9B) — 상황실 지도 연동 v2:
    //   [0-1] device_id
    //   [2-3] lat_comp (int16_t)
    //   [4-5] lon_comp (int16_t)
    //   [6]   accuracy_m  (추정 오차 상한 m; 원 반경 = 이 값)
    //   [7]   flags: [7:6]mode [5:3]anchor_cnt [2:0]quality_3bit
    //   [8]   map_10m_cert: 1=지도에서 10m 이내 신뢰구역·고정밀 스타일 표시 가능
    // =====================================================================
    void HTS_Location_Engine::Tick(
        uint32_t systick_ms, uint32_t current_sec,
        HTS_Priority_Scheduler& scheduler) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        // [갱신형] 하트비트 타임아웃 체크 (48시간 미수신 → 만료)
        {
            Armv7m_Irq_Mask_Guard irq;
            if (p->tracking_mode == TrackingMode::EMERGENCY_AUTH &&
                p->auth_valid)
            {
                const uint32_t since_hb =
                    current_sec - p->auth_token.last_heartbeat;

                if (since_hb > HEARTBEAT_TIMEOUT_SEC) {
                    // 48시간 하트비트 미수신 → 잊힌 추적 방지
                    const uint16_t expired_agency = p->auth_token.agency_id;
                    p->auth_valid = false;
                    p->tracking_mode = TrackingMode::TRACKING_OFF;
                    p->log_audit(current_sec, expired_agency, 1u);
                    Loc_Secure_Wipe(&p->auth_token, sizeof(p->auth_token));
                }
            }
        }

        // ── Last Gasp: 배터리 < 5% → 즉시 3회 버스트 ────────────────
        //
        //   goto loc_send_now: const uint32_t interval/elapsed 초기화를
        //   건너뛰어 "crosses initialization" 컴파일 에러 발생
        //   bool send_now 플래그로 interval 검사 분기 우회
        //
        //   remain 0→3 재충전 무한 반복 (배터리 즉시 탕진)
        //   3→2→1→DONE(0xFF) → Set_Battery_Percent에서 재발동 불가
        //
        //  흐름: Set_Battery_Percent(pct<5) → remain=3
        //        Tick#1 → send_now=true, remain=2
        //        Tick#2 → send_now=true, remain=1
        //        Tick#3 → send_now=true, remain=DONE(0xFF) → 영구 종료
        bool send_now = false;

        if (p->last_gasp_remain >= 1u && p->last_gasp_remain <= 3u &&
            p->tracking_mode == TrackingMode::EMERGENCY_AUTH)
        {
            p->last_gasp_remain--;
            if (p->last_gasp_remain == 0u) {
                // 3회 버스트 완료 → DONE 센티넬 전이 (재발동 영구 차단)
                p->last_gasp_remain = Impl::LAST_GASP_DONE;
            }
            send_now = true;  // interval 검사 우회
        }

        // Privacy Gate: TRACKING_OFF → 전송 차단 (Last Gasp도 차단)
        if (!send_now && p->tracking_mode == TrackingMode::TRACKING_OFF) {
            return;
        }

        // 배터리 적응형 주기 (send_now 시 전체 우회)
        if (!send_now) {
            const uint32_t interval = p->get_report_interval_ms();
            if (interval == 0xFFFFFFFFu) { return; }

            if (interval != p->prev_interval) {
                p->last_report_ms = systick_ms;
                p->prev_interval = interval;
                return;
            }

            if (p->first_tick) {
                p->last_report_ms = systick_ms - interval;
                p->first_tick = false;
            }

            const uint32_t elapsed = systick_ms - p->last_report_ms;
            if (elapsed < interval) { return; }
        }
        // ── 위치 결정 (크리티컬 보호) ──
        int32_t lat = 0;
        int32_t lon = 0;
        uint8_t acc = 0u;
        uint8_t flags = 0u;
        uint8_t pkt8_map_cert = 0u;

        if (p->mode == LocationMode::ANCHOR) {
            lat = p->my_lat_1e4;
            lon = p->my_lon_1e4;
            acc = 5u;
            flags = 0x00u;
        }
        else {
            Armv7m_Irq_Mask_Guard irq;
            if (p->position.valid == 0u) {
                irq.release();
                return;
            }
            lat = p->position.lat_1e4;
            lon = p->position.lon_1e4;
            acc = p->position.accuracy_m;
            flags = 0x40u;
            flags |= static_cast<uint8_t>(
                (p->position.anchor_count & 0x07u) << 3u);
            flags |= static_cast<uint8_t>(
                (p->position.quality / 14u) & 0x07u);
            pkt8_map_cert = p->position.map_10m_cert;
            irq.release();
        }

        // 패킷 조립 + 전송 (인스턴스 로컬 풀)
        uint8_t* const pkt = p->acquire_loc_pkt_buffer();
        ser_u16(&pkt[0], p->my_id);
        ser_i16(&pkt[2], compress_coord(lat, LAT_OFFSET));
        ser_i16(&pkt[4], compress_coord(lon, LON_OFFSET));
        pkt[6] = acc;
        pkt[7] = flags;
        pkt[8] = pkt8_map_cert;

        p->last_report_ms = systick_ms;

        const EnqueueResult enq = scheduler.Enqueue(
            PacketPriority::DATA,
            pkt, POS_REPORT_SIZE,
            systick_ms);
        (void)enq;
    }

    LocationMode HTS_Location_Engine::Get_Mode() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? p->mode : LocationMode::MOBILE;
    }

    void HTS_Location_Engine::Shutdown() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        Armv7m_Irq_Mask_Guard irq;
        Loc_Secure_Wipe(p->anchors, sizeof(p->anchors));
        Loc_Secure_Wipe(&p->auth_token, sizeof(p->auth_token));
        Loc_Secure_Wipe(p->family_ids, sizeof(p->family_ids));
        Loc_Secure_Wipe(p->audit_log, sizeof(p->audit_log));
        p->position = {};
        p->tracking_mode = TrackingMode::TRACKING_OFF;
        p->auth_valid = false;
        p->family_count = 0u;
    }

} // namespace ProtectedEngine
