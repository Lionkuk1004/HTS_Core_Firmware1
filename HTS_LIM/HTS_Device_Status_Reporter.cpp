// =========================================================================
// HTS_Device_Status_Reporter.cpp
// 장비 상태 보고 + Wake-on-Signal 응답 구현부
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// [설계]
//  · ACTIVE: 60초(정상)/10초(경고) 주기 보고
//  · WOR_ONLY: Tick 스킵, WoR ISR에서만 응답 (파렛트)
//  · 8바이트 상태 패킷: P2 DATA 전송
//  · 자동 장애 감지: 배터리<10%, 온도>70°C → 경고 모드
// =========================================================================
#include "HTS_Device_Status_Reporter.h"
#include "HTS_Priority_Scheduler.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

namespace ProtectedEngine {

    // =====================================================================
    //  보안 소거 / PRIMASK
    // =====================================================================
    static void Rpt_Secure_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) { q[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
    static inline uint32_t rpt_critical_enter() noexcept {
        uint32_t primask;
        __asm volatile ("MRS %0, PRIMASK\n CPSID I"
        : "=r"(primask) :: "memory");
        return primask;
    }
    static inline void rpt_critical_exit(uint32_t pm) noexcept {
        __asm volatile ("MSR PRIMASK, %0" :: "r"(pm) : "memory");
    }
#else
    static inline uint32_t rpt_critical_enter() noexcept { return 0u; }
    static inline void rpt_critical_exit(uint32_t) noexcept {}
#endif

    // 엔디안 독립 직렬화
    static void ser_u16(uint8_t* dst, uint16_t v) noexcept {
        dst[0] = static_cast<uint8_t>(v & 0xFFu);
        dst[1] = static_cast<uint8_t>((v >> 8u) & 0xFFu);
    }

    // =====================================================================
    //  Pimpl 구현 구조체
    // =====================================================================
    struct HTS_Device_Status_Reporter::Impl {
        uint16_t   my_id = 0u;
        uint8_t    dev_class = 0u;
        ReportMode rpt_mode = ReportMode::ACTIVE;

        uint8_t    battery_pct = 100u;
        int8_t     temperature = 25;
        uint8_t    fault_flags = 0u;
        uint8_t    module_flags = 0u;

        // [FIX-UPTIME] 누적 시간 카운터 (래핑 면역)
        //  get_uptime_hours(now-boot) 방식: 49.7일 래핑 시 0으로 리셋
        //  수정: last_hour_ms에서 1시간 경과할 때마다 uptime_hours++
        //  → 255시간(10.6일) 후 255 고정, 래핑과 무관
        uint32_t   last_hour_ms = 0u;
        uint8_t    uptime_hours = 0u;
        uint32_t   last_rpt_ms = 0u;
        bool       first_tick = true;
        uint32_t   scan_count = 0u;

        explicit Impl(uint16_t id, uint8_t dc, ReportMode rm) noexcept
            : my_id(id), dev_class(dc), rpt_mode(rm) {
        }
        ~Impl() noexcept = default;

        bool is_alert() const noexcept {
            return (fault_flags != FaultFlag::NONE);
        }

        uint32_t get_interval() const noexcept {
            return is_alert() ? ALERT_INTERVAL : NORMAL_INTERVAL;
        }

        // [FIX-UPTIME] Tick에서 호출 — 1시간 경과 시 누적
        void tick_uptime(uint32_t now_ms) noexcept {
            static constexpr uint32_t ONE_HOUR_MS = 3600000u;
            const uint32_t since = now_ms - last_hour_ms;
            if (since >= ONE_HOUR_MS) {
                if (uptime_hours < 255u) { uptime_hours++; }
                last_hour_ms = now_ms;
            }
        }

        // 자동 장애 감지 (배터리/온도)
        void auto_detect_faults() noexcept {
            // 배터리
            if (battery_pct < 10u) {
                fault_flags |= FaultFlag::LOW_BATTERY;
            }
            else {
                fault_flags &= static_cast<uint8_t>(~FaultFlag::LOW_BATTERY);
            }
            // 온도
            if (temperature > 70) {
                fault_flags |= FaultFlag::OVER_TEMP;
            }
            else {
                fault_flags &= static_cast<uint8_t>(~FaultFlag::OVER_TEMP);
            }
            // 복합 위험
            if ((fault_flags & FaultFlag::LOW_BATTERY) != 0u &&
                (fault_flags & FaultFlag::OVER_TEMP) != 0u)
            {
                fault_flags |= FaultFlag::CRITICAL;
            }
            else {
                fault_flags &= static_cast<uint8_t>(~FaultFlag::CRITICAL);
            }
        }

        // 상태 패킷 조립 (8바이트)
        void build_packet(uint8_t* pkt) const noexcept {
            ser_u16(&pkt[0], my_id);
            pkt[2] = battery_pct;
            pkt[3] = static_cast<uint8_t>(temperature);
            pkt[4] = fault_flags;
            pkt[5] = module_flags;
            pkt[6] = uptime_hours;  // 누적 카운터 (래핑 면역)
            pkt[7] = dev_class;
        }
    };

    // =====================================================================
    //  get_impl
    // =====================================================================
    HTS_Device_Status_Reporter::Impl*
        HTS_Device_Status_Reporter::get_impl() noexcept
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE(256B)를 초과합니다");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 요구가 alignas를 초과합니다");
        return impl_valid_
            ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }

    const HTS_Device_Status_Reporter::Impl*
        HTS_Device_Status_Reporter::get_impl() const noexcept
    {
        return impl_valid_
            ? reinterpret_cast<const Impl*>(impl_buf_) : nullptr;
    }

    // =====================================================================
    //  생성자 / 소멸자
    // =====================================================================
    HTS_Device_Status_Reporter::HTS_Device_Status_Reporter(
        uint16_t my_id, uint8_t dev_class, ReportMode rpt_mode) noexcept
        : impl_valid_(false)
    {
        Rpt_Secure_Wipe(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl(my_id, dev_class, rpt_mode);
        impl_valid_ = true;
    }

    HTS_Device_Status_Reporter::~HTS_Device_Status_Reporter() noexcept {
        Impl* p = get_impl();
        if (p != nullptr) { p->~Impl(); }
        Rpt_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
        impl_valid_ = false;
    }

    // =====================================================================
    //  상태 입력
    // =====================================================================
    void HTS_Device_Status_Reporter::Set_Battery(uint8_t pct) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        const uint32_t pm = rpt_critical_enter();
        p->battery_pct = pct;
        p->auto_detect_faults();
        rpt_critical_exit(pm);
    }

    void HTS_Device_Status_Reporter::Set_Temperature(int8_t celsius) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        const uint32_t pm = rpt_critical_enter();
        p->temperature = celsius;
        p->auto_detect_faults();
        rpt_critical_exit(pm);
    }

    void HTS_Device_Status_Reporter::Set_Fault(uint8_t flag) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        const uint32_t pm = rpt_critical_enter();
        p->fault_flags |= flag;
        rpt_critical_exit(pm);
    }

    void HTS_Device_Status_Reporter::Clear_Fault(uint8_t flag) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        const uint32_t pm = rpt_critical_enter();
        p->fault_flags &= static_cast<uint8_t>(~flag);
        rpt_critical_exit(pm);
    }

    void HTS_Device_Status_Reporter::Set_Module_Active(uint8_t flag) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        p->module_flags |= flag;
    }

    void HTS_Device_Status_Reporter::Clear_Module_Active(uint8_t flag) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        p->module_flags &= static_cast<uint8_t>(~flag);
    }

    // =====================================================================
    //  상태 조회
    // =====================================================================
    uint8_t HTS_Device_Status_Reporter::Get_Battery() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? p->battery_pct : 0u;
    }

    int8_t HTS_Device_Status_Reporter::Get_Temperature() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? p->temperature : 0;
    }

    uint8_t HTS_Device_Status_Reporter::Get_Faults() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? p->fault_flags : 0u;
    }

    uint8_t HTS_Device_Status_Reporter::Get_Modules() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? p->module_flags : 0u;
    }

    bool HTS_Device_Status_Reporter::Has_Any_Fault() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) && (p->fault_flags != FaultFlag::NONE);
    }

    // =====================================================================
    //  On_WoR_Scan — Wake-on-Signal 즉시 응답 (ISR 안전)
    //
    //  파렛트/물류: 게이트웨이 스캔 수신 → 즉시 상태 패킷 전송
    //  ACTIVE 모드에서도 호출 가능 (수동 스캔)
    // =====================================================================
    void HTS_Device_Status_Reporter::On_WoR_Scan(
        uint32_t systick_ms,
        HTS_Priority_Scheduler& scheduler) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        const uint32_t pm = rpt_critical_enter();

        uint8_t pkt[STATUS_PKT_SIZE] = {};
        p->build_packet(pkt);
        p->scan_count++;

        rpt_critical_exit(pm);

        // P2 DATA 인큐
        const EnqueueResult enq = scheduler.Enqueue(
            PacketPriority::DATA,
            pkt, STATUS_PKT_SIZE,
            systick_ms);
        (void)enq;

        Rpt_Secure_Wipe(pkt, sizeof(pkt));
    }

    // =====================================================================
    //  Tick — 주기적 상태 보고
    //
    //  ACTIVE:   60초(정상) / 10초(경고) 주기
    //  WOR_ONLY: 즉시 return (전력 절약)
    // =====================================================================
    void HTS_Device_Status_Reporter::Tick(
        uint32_t systick_ms,
        HTS_Priority_Scheduler& scheduler) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        // WOR_ONLY: Tick 스킵 (On_WoR_Scan에서만 응답)
        if (p->rpt_mode == ReportMode::WOR_ONLY) { return; }

        // [FIX-RACE] 초기화 + 주기 확인 + 패킷 조립 전체 크리티컬 보호
        //  On_WoR_Scan ISR이 build_packet 호출 시 boot_ms/last_rpt_ms
        //  미초기화 값 읽기 방지
        const uint32_t pm = rpt_critical_enter();

        // 첫 Tick 초기화
        if (p->first_tick) {
            p->last_hour_ms = systick_ms;
            // [FIX-JITTER] 즉시 보고: 현재 - interval → elapsed=interval → 즉시 통과
            p->last_rpt_ms = systick_ms - p->get_interval();
            p->first_tick = false;
        }

        // [FIX-UPTIME] 누적 가동 시간 갱신 (래핑 면역)
        p->tick_uptime(systick_ms);

        // 주기 확인
        const uint32_t interval = p->get_interval();
        const uint32_t elapsed = systick_ms - p->last_rpt_ms;
        if (elapsed < interval) {
            rpt_critical_exit(pm);
            return;
        }

        // 패킷 조립
        uint8_t pkt[STATUS_PKT_SIZE] = {};
        p->build_packet(pkt);
        p->last_rpt_ms = systick_ms;

        rpt_critical_exit(pm);

        // 크리티컬 밖: 인큐 (scheduler 내부 자체 PRIMASK)
        const EnqueueResult enq = scheduler.Enqueue(
            PacketPriority::DATA,
            pkt, STATUS_PKT_SIZE,
            systick_ms);
        (void)enq;

        Rpt_Secure_Wipe(pkt, sizeof(pkt));
    }

    // =====================================================================
    //  Shutdown
    // =====================================================================
    void HTS_Device_Status_Reporter::Shutdown() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        const uint32_t pm = rpt_critical_enter();
        p->fault_flags = FaultFlag::NONE;
        p->module_flags = 0u;
        rpt_critical_exit(pm);
    }

} // namespace ProtectedEngine