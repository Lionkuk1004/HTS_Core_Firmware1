// =========================================================================
// HTS_Meter_Data_Manager.cpp
// AMI 계량 데이터 관리 구현부
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
// =========================================================================
#include "HTS_Meter_Data_Manager.h"
#include "HTS_Crc32Util.h"
#include "HTS_Priority_Scheduler.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <new>

namespace ProtectedEngine {

    static void Mtr_Secure_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) { q[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
    static inline uint32_t mtr_critical_enter() noexcept {
        uint32_t primask;
        __asm volatile ("MRS %0, PRIMASK\n CPSID I"
        : "=r"(primask) :: "memory");
        return primask;
    }
    static inline void mtr_critical_exit(uint32_t pm) noexcept {
        __asm volatile ("MSR PRIMASK, %0" :: "r"(pm) : "memory");
    }
#else
    static inline uint32_t mtr_critical_enter() noexcept { return 0u; }
    static inline void mtr_critical_exit(uint32_t) noexcept {}
#endif

    static void ser_u16(uint8_t* dst, uint16_t v) noexcept {
        dst[0] = static_cast<uint8_t>(v & 0xFFu);
        dst[1] = static_cast<uint8_t>((v >> 8u) & 0xFFu);
    }
    static void ser_u32(uint8_t* dst, uint32_t v) noexcept {
        dst[0] = static_cast<uint8_t>(v & 0xFFu);
        dst[1] = static_cast<uint8_t>((v >> 8u) & 0xFFu);
        dst[2] = static_cast<uint8_t>((v >> 16u) & 0xFFu);
        dst[3] = static_cast<uint8_t>((v >> 24u) & 0xFFu);
    }

    /// A-4: 엔디안 독립 14B 캐논(패딩 제외) — IEEE 802.3 CRC32
    static void meter_serialize_canonical(
        const MeterReading& r, uint8_t out[14]) noexcept
    {
        out[0] = static_cast<uint8_t>(r.watt_hour >> 24u);
        out[1] = static_cast<uint8_t>((r.watt_hour >> 16u) & 0xFFu);
        out[2] = static_cast<uint8_t>((r.watt_hour >> 8u) & 0xFFu);
        out[3] = static_cast<uint8_t>(r.watt_hour & 0xFFu);
        out[4] = static_cast<uint8_t>(r.cumul_kwh_x100 >> 24u);
        out[5] = static_cast<uint8_t>((r.cumul_kwh_x100 >> 16u) & 0xFFu);
        out[6] = static_cast<uint8_t>((r.cumul_kwh_x100 >> 8u) & 0xFFu);
        out[7] = static_cast<uint8_t>(r.cumul_kwh_x100 & 0xFFu);
        out[8] = static_cast<uint8_t>(r.voltage_x10 >> 8u);
        out[9] = static_cast<uint8_t>(r.voltage_x10 & 0xFFu);
        out[10] = static_cast<uint8_t>(r.current_x100 >> 8u);
        out[11] = static_cast<uint8_t>(r.current_x100 & 0xFFu);
        out[12] = r.power_factor;
        out[13] = r.valid;
    }

    static uint32_t meter_reading_crc(const MeterReading& r) noexcept
    {
        uint8_t buf[14];
        meter_serialize_canonical(r, buf);
        return Crc32Util::calculate(buf, 14u);
    }

    // =====================================================================
    //  Pimpl
    // =====================================================================
    struct HTS_Meter_Data_Manager::Impl {
        uint16_t     my_id = 0u;
        MeterReading latest = {};
        uint32_t     latest_crc = 0u;
        MeterReading_VerifyFn verify_fn = nullptr;
        void*        verify_user = nullptr;
        mutable bool crc_fault_latched = false;

        // 부하 프로파일: 15분 × 96 = 24시간
        uint32_t profile[PROFILE_SLOTS] = {};
        uint8_t  profile_head = 0u;

        // 이벤트 로그
        MeterLogEntry event_log[EVENT_LOG_SIZE] = {};
        uint8_t  event_head = 0u;
        uint8_t  event_count = 0u;

        uint32_t last_profile_ms = 0u;
        uint32_t last_report_ms = 0u;
        bool     first_tick = true;

        explicit Impl(uint16_t id) noexcept : my_id(id) {
            latest_crc = meter_reading_crc(latest);
        }
        ~Impl() noexcept = default;
    };

    HTS_Meter_Data_Manager::Impl*
        HTS_Meter_Data_Manager::get_impl() noexcept
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE, "Impl 초과");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN, "Impl 정렬 초과");
        return impl_valid_
            ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }

    const HTS_Meter_Data_Manager::Impl*
        HTS_Meter_Data_Manager::get_impl() const noexcept
    {
        return impl_valid_
            ? reinterpret_cast<const Impl*>(impl_buf_) : nullptr;
    }

    HTS_Meter_Data_Manager::HTS_Meter_Data_Manager(uint16_t my_id) noexcept
        : impl_valid_(false)
    {
        Mtr_Secure_Wipe(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl(my_id);
        impl_valid_ = true;
    }

    HTS_Meter_Data_Manager::~HTS_Meter_Data_Manager() noexcept {
        Impl* p = get_impl();
        if (p != nullptr) { p->~Impl(); }
        Mtr_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
        impl_valid_ = false;
    }

    // =====================================================================
    //  데이터 입력
    // =====================================================================
    void HTS_Meter_Data_Manager::Update_Reading(
        const MeterReading& reading) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        if (p->verify_fn != nullptr &&
            !p->verify_fn(reading, p->verify_user)) {
            return;
        }
        MeterReading norm = reading;
        norm.pad[0] = 0u;
        norm.pad[1] = 0u;
        const uint32_t crc = meter_reading_crc(norm);
        const uint32_t pm = mtr_critical_enter();
        p->latest = norm;
        p->latest_crc = crc;
        p->crc_fault_latched = false;
        mtr_critical_exit(pm);
    }

    void HTS_Meter_Data_Manager::Register_Meter_Reading_Verify(
        MeterReading_VerifyFn fn, void* user) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        const uint32_t pm = mtr_critical_enter();
        p->verify_fn = fn;
        p->verify_user = user;
        mtr_critical_exit(pm);
    }

    void HTS_Meter_Data_Manager::Log_Event(
        MeterEvent event, uint32_t timestamp) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        const uint32_t pm = mtr_critical_enter();
        MeterLogEntry& e = p->event_log[p->event_head];
        e.timestamp = timestamp;
        e.event = event;
        p->event_head = static_cast<uint8_t>(
            (p->event_head + 1u) % EVENT_LOG_SIZE);
        if (p->event_count < EVENT_LOG_SIZE) { p->event_count++; }
        mtr_critical_exit(pm);
    }

    // =====================================================================
    //  데이터 조회
    // =====================================================================
    MeterReading HTS_Meter_Data_Manager::Get_Latest() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) { MeterReading r = {}; return r; }
        const uint32_t pm = mtr_critical_enter();
        const MeterReading r = p->latest;
        const uint32_t expect = p->latest_crc;
        if (meter_reading_crc(r) != expect) {
            p->crc_fault_latched = true;
            mtr_critical_exit(pm);
            MeterReading z = {};
            return z;
        }
        mtr_critical_exit(pm);
        return r;
    }

    bool HTS_Meter_Data_Manager::Is_Meter_Integrity_Fault() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) { return false; }
        const uint32_t pm = mtr_critical_enter();
        const bool f = p->crc_fault_latched;
        mtr_critical_exit(pm);
        return f;
    }

    uint32_t HTS_Meter_Data_Manager::Get_Profile_Value(
        size_t slot) const noexcept
    {
        const Impl* p = get_impl();
        if (p == nullptr || slot >= PROFILE_SLOTS) { return 0u; }
        return p->profile[slot];
    }

    size_t HTS_Meter_Data_Manager::Get_Event_Log(
        MeterLogEntry* out, size_t cap) const noexcept
    {
        const Impl* p = get_impl();
        if (p == nullptr || out == nullptr || cap == 0u) { return 0u; }
        const uint32_t pm = mtr_critical_enter();
        const size_t n = (p->event_count < cap) ? p->event_count : cap;
        for (size_t i = 0u; i < n; ++i) {
            out[i] = p->event_log[i];
        }
        mtr_critical_exit(pm);
        return n;
    }

    // =====================================================================
    //  Tick — 프로파일 기록 + 주기 보고
    // =====================================================================
    void HTS_Meter_Data_Manager::Tick(
        uint32_t systick_ms,
        HTS_Priority_Scheduler& scheduler) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        if (p->first_tick) {
            p->last_profile_ms = systick_ms;
            p->last_report_ms = systick_ms - REPORT_INTERVAL_MS;
            p->first_tick = false;
        }

        // 15분 프로파일 기록
        const uint32_t prof_elapsed = systick_ms - p->last_profile_ms;
        if (prof_elapsed >= PROFILE_INTERVAL_MS) {
            p->last_profile_ms += PROFILE_INTERVAL_MS;
            const uint32_t pm = mtr_critical_enter();
            const MeterReading lr = p->latest;
            const uint32_t expect = p->latest_crc;
            if (meter_reading_crc(lr) == expect) {
                p->profile[p->profile_head] = lr.watt_hour;
                p->profile_head = static_cast<uint8_t>(
                    (p->profile_head + 1u) % PROFILE_SLOTS);
            }
            else {
                p->crc_fault_latched = true;
            }
            mtr_critical_exit(pm);
        }

        // 1시간 보고
        const uint32_t rpt_elapsed = systick_ms - p->last_report_ms;
        if (rpt_elapsed < REPORT_INTERVAL_MS) { return; }
        p->last_report_ms += REPORT_INTERVAL_MS;

        // 보고 패킷 (8바이트 요약) — CRC 무결성 통과 시에만 유효 계량값 전송
        uint8_t pkt[8] = {};
        const uint32_t pm = mtr_critical_enter();
        const MeterReading lr = p->latest;
        const uint32_t expect = p->latest_crc;
        const bool ok = (meter_reading_crc(lr) == expect);
        if (ok) {
            ser_u16(&pkt[0], p->my_id);
            ser_u32(&pkt[2], lr.cumul_kwh_x100);
            pkt[6] = lr.power_factor;
            pkt[7] = p->event_count;
        }
        else {
            p->crc_fault_latched = true;
        }
        mtr_critical_exit(pm);
        if (!ok) { return; }

        const EnqueueResult enq = scheduler.Enqueue(
            PacketPriority::DATA,
            pkt, 8u, systick_ms);
        (void)enq;

        Mtr_Secure_Wipe(pkt, sizeof(pkt));
    }

    void HTS_Meter_Data_Manager::Shutdown() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        const uint32_t pm = mtr_critical_enter();
        p->verify_fn = nullptr;
        p->verify_user = nullptr;
        mtr_critical_exit(pm);
        Mtr_Secure_Wipe(p->profile, sizeof(p->profile));
        Mtr_Secure_Wipe(p->event_log, sizeof(p->event_log));
    }

} // namespace ProtectedEngine