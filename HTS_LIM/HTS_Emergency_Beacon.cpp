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
// =========================================================================
#include "HTS_Emergency_Beacon.h"
#include "HTS_Priority_Scheduler.h"

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
    //  3중 보안 소거
    // =====================================================================
    static void Beacon_Secure_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) { q[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  PRIMASK 크리티컬 섹션 (Trigger는 ISR에서 호출 가능)
    // =====================================================================
#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
    static inline uint32_t bcn_critical_enter() noexcept {
        uint32_t primask;
        __asm volatile ("MRS %0, PRIMASK\n CPSID I"
        : "=r"(primask) :: "memory");
        return primask;
    }
    static inline void bcn_critical_exit(uint32_t pm) noexcept {
        __asm volatile ("MSR PRIMASK, %0" :: "r"(pm) : "memory");
    }
#else
    static inline uint32_t bcn_critical_enter() noexcept { return 0u; }
    static inline void bcn_critical_exit(uint32_t) noexcept {}
#endif

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
    // =====================================================================
    static constexpr int32_t LAT_OFFSET = 330000;  // 33.0000°
    static constexpr int32_t LON_OFFSET = 1240000; // 124.0000°
    static constexpr int32_t GPS_DIV = 10;      // 1e4→1e3 스케일

    static int16_t compress_lat(int32_t lat_1e4) noexcept {
        const int32_t v = (lat_1e4 - LAT_OFFSET) / GPS_DIV;
        if (v > 32767) { return 32767; }
        if (v < -32768) { return -32768; }
        return static_cast<int16_t>(v);
    }

    static int16_t compress_lon(int32_t lon_1e4) noexcept {
        const int32_t v = (lon_1e4 - LON_OFFSET) / GPS_DIV;
        if (v > 32767) { return 32767; }
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
        return impl_valid_
            ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }

    const HTS_Emergency_Beacon::Impl*
        HTS_Emergency_Beacon::get_impl() const noexcept
    {
        return impl_valid_
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
        impl_valid_ = true;
    }

    HTS_Emergency_Beacon::~HTS_Emergency_Beacon() noexcept {
        Impl* p = get_impl();
        if (p != nullptr) { p->~Impl(); }
        Beacon_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
        impl_valid_ = false;
    }

    // =====================================================================
    //  Set_GPS — 좌표 설정
    // =====================================================================
    void HTS_Emergency_Beacon::Set_GPS(
        int32_t lat_1e4, int32_t lon_1e4) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        const uint32_t pm = bcn_critical_enter();
        p->lat_1e4 = lat_1e4;
        p->lon_1e4 = lon_1e4;
        bcn_critical_exit(pm);
    }

    // =====================================================================
    //  Trigger — 알림 플래그 설정 + 비콘 자동 발동 (ISR 안전)
    // =====================================================================
    void HTS_Emergency_Beacon::Trigger(uint16_t flag) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        const uint32_t pm = bcn_critical_enter();
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

        // [FIX-DEADLOCK] 모든 경로에서 반드시 실행
        bcn_critical_exit(pm);
    }

    void HTS_Emergency_Beacon::Set_Flags(uint16_t flags) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        const uint32_t pm = bcn_critical_enter();
        p->alert_flags = flags;
        bcn_critical_exit(pm);
    }

    uint16_t HTS_Emergency_Beacon::Get_Flags() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? p->alert_flags : 0u;
    }

    bool HTS_Emergency_Beacon::Is_Active() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) && p->active;
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

        const uint32_t pm = bcn_critical_enter();

        if (!p->active) {
            bcn_critical_exit(pm);
            return;
        }

        // [FIX-FLOOD] 첫 Tick 초기화
        //  last_tx_ms = systick_ms - INTERVAL → 첫 송출 즉시 허용
        //  기존: last_tx_ms=0 → elapsed=systick_ms → 폭주 가능
        if (p->start_ms == 0u && p->tx_count == 0u) {
            p->start_ms = systick_ms;
            p->last_tx_ms = systick_ms - BEACON_INTERVAL_MS;
        }

        // 500ms 간격 확인
        const uint32_t elapsed_since_tx = systick_ms - p->last_tx_ms;
        if (elapsed_since_tx < BEACON_INTERVAL_MS) {
            bcn_critical_exit(pm);
            return;
        }

        // 비콘 패킷 조립 (크리티컬 내부 — 플래그/좌표 일관성)
        uint8_t pkt[BEACON_SIZE] = {};
        p->build_packet(pkt);
        p->last_tx_ms = systick_ms;
        p->tx_count++;

        // [FIX-DURATION] 최소 30초 경과 + 플래그 해소 시 자동 종료
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

        bcn_critical_exit(pm);

        // 크리티컬 밖에서 인큐 (scheduler 내부에 자체 PRIMASK)
        // [FIX-C6031] [[nodiscard]] 반환값 검사
        const EnqueueResult enq = scheduler.Enqueue(
            PacketPriority::SOS,
            pkt, BEACON_SIZE,
            systick_ms);
        (void)enq;  // P0 큐 풀 시 드롭 허용 (다음 500ms에 재시도)

        // 패킷 소거 (크리티컬 밖)
        Beacon_Secure_Wipe(pkt, sizeof(pkt));
    }

    // =====================================================================
    //  Cancel — 비콘 해제
    // =====================================================================
    void HTS_Emergency_Beacon::Cancel() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        const uint32_t pm = bcn_critical_enter();

        // POWER_LOSS는 수동 취소 불가 (물리적 복전 필요)
        if ((p->alert_flags & AlertFlag::POWER_LOSS) != 0u) {
            bcn_critical_exit(pm);
            return;
        }

        // [FIX-DURATION] 최소 30초(60회) 미경과 시 취소 거부
        //  500ms × 60회 = 30초
        static constexpr uint32_t MIN_TX_COUNT = 60u;
        if (p->tx_count < MIN_TX_COUNT) {
            bcn_critical_exit(pm);
            return;
        }

        p->active = false;
        p->alert_flags = 0u;
        p->tx_count = 0u;

        bcn_critical_exit(pm);
    }

    // =====================================================================
    //  Shutdown — 안전 종료
    // =====================================================================
    void HTS_Emergency_Beacon::Shutdown() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        const uint32_t pm = bcn_critical_enter();
        p->active = false;
        p->alert_flags = 0u;
        bcn_critical_exit(pm);
    }

} // namespace ProtectedEngine