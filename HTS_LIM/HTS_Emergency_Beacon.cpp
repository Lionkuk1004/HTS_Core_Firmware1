// =========================================================================
// HTS_Emergency_Beacon.cpp
// 긴급 비콘 자동 송출기 구현부 (Pimpl 은닉)
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// [설계]
//  · GPIO/센서 트리거 → 자동 비콘 발동 (ISR 안전)
//  · 500ms 주기 × 최소 30초 연속 = 60회 이상
//  · 8바이트 패킷: device_id + alert_flags + GPS 압축
//  · Priority_Scheduler P0(SOS) 큐 삽입
//  · 3중 보안 소거
//
#include "HTS_Emergency_Beacon.h"
#include "HTS_Arm_Irq_Mask_Guard.h"
#include "HTS_Priority_Scheduler.h"
#include "HTS_Secure_Memory.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

static_assert(sizeof(uint16_t) == 2, "uint16_t must be 2 bytes");
static_assert(sizeof(int16_t) == 2, "int16_t must be 2 bytes");
static_assert(sizeof(uint32_t) == 4, "uint32_t must be 4 bytes");

namespace ProtectedEngine {

    // =====================================================================
    //  보안 소거 — SecureMemory::secureWipe (D-2 / X-5-1)
    // =====================================================================
    static void Beacon_Secure_Wipe(void* p, size_t n) noexcept {
        SecureMemory::secureWipe(p, n);
    }

    // =====================================================================
    //  GPS 압축
    //
    //  한국 범위: 위도 33~39°, 경도 124~132°
    //  입력: lat_1e4 = 위도 × 10000 (예: 375665 = 37.5665°)
    //  압축: int16_t = (lat_1e4 - OFFSET) / 10
    //  → 위도: (0~60000)/10 = 0~6000 → int16_t 안전 ✅
    //  → 경도: (0~80000)/10 = 0~8000 → int16_t 안전 ✅
    //  → 정밀도: 0.001° ≈ 111m (SOS 용도 충분)
    //
    //  해외 확장: 오프셋 조정으로 전 세계 커버 가능
    //  int16_t ±32767 → ±32.767° 범위 → 오프셋 중심 ±32° 커버
    //
    //  diff / 10             (SDIV ~12cyc, 비2의제곱 금지)
    //  (diff * 6554) >> 16   (MUL+ASR ~3cyc)
    //  검증: 6554/65536 = 0.09999... vs 1/10 = 0.1 → 오차 -0.009%
    //        최대 diff = 80000: 80000 × 6554 = 524,320,000 < INT32_MAX ✓
    //        음수: int64_t 확장 후 산술 우시프트로 부호 보존
    // =====================================================================
    static constexpr int32_t LAT_OFFSET = 330000;   // 33.0000°
    static constexpr int32_t LON_OFFSET = 1240000;  // 124.0000°
    static constexpr int32_t GPS_RECIP_Q16 = 6554;

    static int16_t compress_lat(int32_t lat_1e4) noexcept {
        const int32_t v = static_cast<int32_t>(
            (static_cast<int64_t>(lat_1e4 - LAT_OFFSET) * GPS_RECIP_Q16) >> 16);
        if (v > 32767) { return  32767; }
        if (v < -32768) { return -32768; }
        return static_cast<int16_t>(v);
    }

    static int16_t compress_lon(int32_t lon_1e4) noexcept {
        const int32_t v = static_cast<int32_t>(
            (static_cast<int64_t>(lon_1e4 - LON_OFFSET) * GPS_RECIP_Q16) >> 16);
        if (v > 32767) { return  32767; }
        if (v < -32768) { return -32768; }
        return static_cast<int16_t>(v);
    }

    // =====================================================================
    //  엔디안 독립 직렬화
    // =====================================================================
    static void ser_u16(uint8_t* dst, uint16_t v) noexcept {
        dst[0] = static_cast<uint8_t>(v & 0xFFu);
        dst[1] = static_cast<uint8_t>((v >> 8u) & 0xFFu);
    }

    static void ser_i16(uint8_t* dst, int16_t v) noexcept {
        ser_u16(dst, static_cast<uint16_t>(v));
    }

    // 스택 임시 패킷 제거: 수명 보장 정적 슬롯 풀
    // SOS 큐 깊이(4)에 맞춰 슬롯 4개를 순환 사용
    static constexpr size_t BEACON_PKT_SLOT_COUNT = 4u;
    static constexpr uint8_t BEACON_PKT_SLOT_MASK = 3u; // 4 - 1
    alignas(uint32_t) static uint8_t g_beacon_pkt_pool[BEACON_PKT_SLOT_COUNT]
                                                     [HTS_Emergency_Beacon::BEACON_SIZE] = {};
    static uint8_t g_beacon_pkt_slot = 0u;

    static uint8_t* acquire_beacon_pkt_slot() noexcept {
        Armv7m_Irq_Mask_Guard irq;
        uint8_t* const pkt = g_beacon_pkt_pool[g_beacon_pkt_slot];
        g_beacon_pkt_slot = static_cast<uint8_t>(
            (g_beacon_pkt_slot + 1u) & BEACON_PKT_SLOT_MASK);
        return pkt;
    }

    // =====================================================================
    //  Pimpl 구현 구조체
    // =====================================================================
    struct HTS_Emergency_Beacon::Impl {
        uint16_t device_id = 0u;
        uint16_t alert_flags = 0u;
        int32_t  lat_1e4 = 0;       // 위도 × 10000
        int32_t  lon_1e4 = 0;       // 경도 × 10000
        bool     active = false;   // 비콘 활성 상태
        uint32_t start_ms = 0u;      // 비콘 시작 시각
        uint32_t last_tx_ms = 0u;      // 마지막 송출 시각
        uint32_t tx_count = 0u;      // 송출 횟수

        explicit Impl(uint16_t id) noexcept
            : device_id(id) {
        }

        ~Impl() noexcept = default;

        // 비콘 패킷 조립 (8바이트 정확)
        void build_packet(uint8_t* out) const noexcept {
            ser_u16(&out[0], device_id);
            ser_u16(&out[2], alert_flags);
            ser_i16(&out[4], compress_lat(lat_1e4));
            ser_i16(&out[6], compress_lon(lon_1e4));
        }
    };

    // =====================================================================
    //  get_impl
    // =====================================================================
    HTS_Emergency_Beacon::Impl*
        HTS_Emergency_Beacon::get_impl() noexcept
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE(256B)를 초과합니다");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 요구가 alignas를 초과합니다");
        return impl_valid_.load(std::memory_order_acquire)
            ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }

    const HTS_Emergency_Beacon::Impl*
        HTS_Emergency_Beacon::get_impl() const noexcept
    {
        return impl_valid_.load(std::memory_order_acquire)
            ? reinterpret_cast<const Impl*>(impl_buf_) : nullptr;
    }

    // =====================================================================
    //  생성자 / 소멸자
    // =====================================================================
    HTS_Emergency_Beacon::HTS_Emergency_Beacon(uint16_t device_id) noexcept
        : impl_valid_(false)
    {
        Beacon_Secure_Wipe(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl(device_id);
        impl_valid_.store(true, std::memory_order_release);
    }

    HTS_Emergency_Beacon::~HTS_Emergency_Beacon() noexcept {
        impl_valid_.store(false, std::memory_order_release);
        Armv7m_Irq_Mask_Guard irq;
        Impl* p = reinterpret_cast<Impl*>(impl_buf_);
        if (p != nullptr) { p->~Impl(); }
        Beacon_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
    }

    // =====================================================================
    //  Set_GPS — 좌표 설정
    // =====================================================================
    void HTS_Emergency_Beacon::Set_GPS(
        int32_t lat_1e4, int32_t lon_1e4) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        Armv7m_Irq_Mask_Guard irq;
        p->lat_1e4 = lat_1e4;
        p->lon_1e4 = lon_1e4;
    }

    // =====================================================================
    //  Trigger — 알림 플래그 설정 + 비콘 자동 발동 (ISR 안전)
    // =====================================================================
    void HTS_Emergency_Beacon::Trigger(uint16_t flag) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        Armv7m_Irq_Mask_Guard irq;
        p->alert_flags |= flag;

        // 이미 활성이면 플래그만 갱신 → exit
        // 비활성이면 자동 발동 조건 확인
        if (!p->active) {
            static constexpr uint16_t AUTO_TRIGGER_MASK =
                AlertFlag::SOS_ALARM |
                AlertFlag::POWER_LOSS |
                AlertFlag::TILT_FALL |
                AlertFlag::COVER_OPEN |
                AlertFlag::WATER_LEAK |
                AlertFlag::TEMP_HIGH;

            if ((flag & AUTO_TRIGGER_MASK) != 0u) {
                p->active = true;
                p->start_ms = 0u;  // Tick 첫 호출 시 초기화
                p->last_tx_ms = 0u;
                p->tx_count = 0u;
            }
        }
    }

    void HTS_Emergency_Beacon::Set_Flags(uint16_t flags) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        Armv7m_Irq_Mask_Guard irq;
        p->alert_flags = flags;
    }

    uint16_t HTS_Emergency_Beacon::Get_Flags() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) { return 0u; }
        Armv7m_Irq_Mask_Guard irq;
        const uint16_t v = p->alert_flags;
        return v;
    }

    uint32_t HTS_Emergency_Beacon::Is_Active() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) { return SECURE_FALSE; }
        Armv7m_Irq_Mask_Guard irq;
        const bool v = p->active;
        return v ? SECURE_TRUE : SECURE_FALSE;
    }

    // =====================================================================
    //  Tick — 500ms 주기 비콘 송출
    //
    //  [설계]
    //   active == true 동안:
    //   1. start_ms 초기화 (첫 Tick)
    //   2. 500ms 간격 확인
    //   3. 비콘 패킷 조립 (8바이트)
    //   4. Priority_Scheduler P0(SOS) 큐 삽입
    //   5. 최소 30초 경과 + 플래그 해소 시 자동 종료
    // =====================================================================
    void HTS_Emergency_Beacon::Tick(
        uint32_t systick_ms,
        HTS_Priority_Scheduler& scheduler) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        bool should_tx = false;
        uint16_t snap_device_id = 0u;
        uint16_t snap_alert_flags = 0u;
        int32_t  snap_lat_1e4 = 0;
        int32_t  snap_lon_1e4 = 0;

        Armv7m_Irq_Mask_Guard irq;

        if (!p->active) {
            irq.release();
            return;
        }

        //  last_tx_ms = systick_ms - INTERVAL → 첫 송출 즉시 허용
        //  last_tx_ms=0 → elapsed=systick_ms → 폭주 가능
        if (p->start_ms == 0u && p->tx_count == 0u) {
            p->start_ms = systick_ms;
            p->last_tx_ms = systick_ms - BEACON_INTERVAL_MS;
        }

        // 500ms 간격 확인
        const uint32_t elapsed_since_tx = systick_ms - p->last_tx_ms;
        if (elapsed_since_tx < BEACON_INTERVAL_MS) {
            irq.release();
            return;
        }

        // 패킷 조립용 스냅샷만 보관 (실제 직렬화는 PRIMASK 밖에서 수행)
        should_tx = true;
        snap_device_id = p->device_id;
        snap_alert_flags = p->alert_flags;
        snap_lat_1e4 = p->lat_1e4;
        snap_lon_1e4 = p->lon_1e4;

        //  p->last_tx_ms = systick_ms
        //    → Tick 호출 지연(인터럽트, 스케줄 지연)이 그대로 누적
        //    → 비콘 주기가 뒤로 밀림 → B-CDMA P0 타임슬롯 충돌
        //  p->last_tx_ms += BEACON_INTERVAL_MS
        //    → 이전 송출 시각 기준 정확히 +500ms 갱신
        //    → 누적 오차 0, 타임슬롯 위상 고정
        //  예: t=0 송출→ last=500, t=503 Tick→ last=1000 (systick 대입 시 1003)
        //      1000회 후 오차: 주기 기반=0ms, systick 대입=최대수백ms
        p->last_tx_ms += BEACON_INTERVAL_MS;
        p->tx_count++;

        //  30초 미만: 무조건 계속 송출
        //  30초 이상 + alert_flags == 0: 자동 종료 (위험 해소)
        //  30초 이상 + alert_flags != 0: 계속 송출 (위험 지속)
        const uint32_t elapsed_total = systick_ms - p->start_ms;
        const bool min_duration_met = (elapsed_total >= MIN_DURATION_MS);
        const bool flags_cleared = (p->alert_flags == 0u);

        if (min_duration_met && flags_cleared) {
            p->active = false;
            p->tx_count = 0u;
        }

        irq.release();

        if (!should_tx) { return; }

        uint8_t* const pkt = acquire_beacon_pkt_slot();
        ser_u16(&pkt[0], snap_device_id);
        ser_u16(&pkt[2], snap_alert_flags);
        ser_i16(&pkt[4], compress_lat(snap_lat_1e4));
        ser_i16(&pkt[6], compress_lon(snap_lon_1e4));

        // 크리티컬 밖에서 인큐 (scheduler 내부에 자체 PRIMASK)
        const EnqueueResult enq = scheduler.Enqueue(
            PacketPriority::SOS,
            pkt, BEACON_SIZE,
            systick_ms);
        (void)enq;  // P0 큐 풀 시 드롭 허용 (다음 500ms에 재시도)
    }

    // =====================================================================
    //  Cancel — 비콘 해제
    //  POWER_LOSS는 복전 전 수동 취소 불가. 그 외: alert_flags=0 즉시 반영,
    //  active 해제는 MIN_TX_COUNT(30초) 충족 시 또는 Tick이 flags_cleared로 종료.
    // =====================================================================
    void HTS_Emergency_Beacon::Cancel() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        Armv7m_Irq_Mask_Guard irq;

        // POWER_LOSS는 수동 취소 불가 (물리적 복전 필요)
        if ((p->alert_flags & AlertFlag::POWER_LOSS) != 0u) {
            irq.release();
            return;
        }

        //  Tick()이 다음 500ms 주기에 flags_cleared=true를 확인하여
        //  min_duration_met 충족 시 active=false로 자동 전환
        p->alert_flags = 0u;

        // active = false 즉시 전환은 최소 30초(60회) 경과 후에만 허용
        static constexpr uint32_t MIN_TX_COUNT = 60u;
        if (p->tx_count >= MIN_TX_COUNT) {
            p->active = false;
            p->tx_count = 0u;
        }
        // tx_count < MIN_TX_COUNT: alert_flags=0 설정 완료 → Tick에 위임
        // Tick은 min_duration_met && flags_cleared 조건으로 정시 종료 보장
    }

    // =====================================================================
    //  Shutdown — 안전 종료
    // =====================================================================
    void HTS_Emergency_Beacon::Shutdown() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        Armv7m_Irq_Mask_Guard irq;
        p->active = false;
        p->alert_flags = 0u;
    }

} // namespace ProtectedEngine
