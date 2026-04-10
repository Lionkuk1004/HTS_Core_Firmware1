// =========================================================================
// HTS_Meter_Data_Manager.cpp
// AMI 계량 데이터 관리 구현부
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
// =========================================================================
#include "HTS_Meter_Data_Manager.h"
#include "HTS_Arm_Irq_Mask_Guard.h"
#include "HTS_Crc32Util.h"
#include "HTS_Priority_Scheduler.h"

#if defined(_MSC_VER)
#include <intrin.h>
#endif
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <new>

namespace ProtectedEngine {

    // EVENT_LOG_SIZE=8 → 링 인덱스는 & (SIZE-1) 로 UDIV 회피 (⑨)
    static_assert((HTS_Meter_Data_Manager::EVENT_LOG_SIZE &
        (HTS_Meter_Data_Manager::EVENT_LOG_SIZE - 1u)) == 0u,
        "EVENT_LOG_SIZE must be 2^N for bitmask ring");
    static constexpr uint32_t EVENT_LOG_MASK =
        static_cast<uint32_t>(HTS_Meter_Data_Manager::EVENT_LOG_SIZE - 1u);

    static void Mtr_Secure_Wipe(void* p, size_t n) noexcept {
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
        mutable bool report_enqueue_fault_latched = false;

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
        return impl_valid_.load(std::memory_order_acquire)
            ? std::launder(reinterpret_cast<Impl*>(impl_buf_)) : nullptr;
    }

    const HTS_Meter_Data_Manager::Impl*
        HTS_Meter_Data_Manager::get_impl() const noexcept
    {
        return impl_valid_.load(std::memory_order_acquire)
            ? std::launder(reinterpret_cast<const Impl*>(impl_buf_)) : nullptr;
    }

    HTS_Meter_Data_Manager::HTS_Meter_Data_Manager(uint16_t my_id) noexcept
        : impl_valid_(false)
    {
        Mtr_Secure_Wipe(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl(my_id);
        impl_valid_.store(true, std::memory_order_release);
    }

    HTS_Meter_Data_Manager::~HTS_Meter_Data_Manager() noexcept {
        const bool was_valid =
            impl_valid_.exchange(false, std::memory_order_acq_rel);
        if (was_valid) {
            Impl* const p = std::launder(reinterpret_cast<Impl*>(impl_buf_));
            p->~Impl();
            Mtr_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
        }
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
        Armv7m_Irq_Mask_Guard irq;
        p->latest = norm;
        p->latest_crc = crc;
        p->crc_fault_latched = false;
    }

    void HTS_Meter_Data_Manager::Register_Meter_Reading_Verify(
        MeterReading_VerifyFn fn, void* user) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        Armv7m_Irq_Mask_Guard irq;
        p->verify_fn = fn;
        p->verify_user = user;
    }

    void HTS_Meter_Data_Manager::Log_Event(
        MeterEvent event, uint32_t timestamp) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        Armv7m_Irq_Mask_Guard irq;
        const size_t hi = static_cast<size_t>(p->event_head);
        MeterLogEntry& e = p->event_log[hi];
        e.timestamp = timestamp;
        e.event = event;
        const uint32_t nh =
            (static_cast<uint32_t>(p->event_head) + 1u) & EVENT_LOG_MASK;
        p->event_head = static_cast<uint8_t>(nh);
        if (p->event_count < EVENT_LOG_SIZE) { p->event_count++; }
    }

    // =====================================================================
    //  데이터 조회
    // =====================================================================
    MeterReading HTS_Meter_Data_Manager::Get_Latest() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) { MeterReading r = {}; return r; }
        // CRC32(LUT)는 PRIMASK 밖에서 — N-10 ISR 기아 완화
        MeterReading r;
        uint32_t expect;
        {
            Armv7m_Irq_Mask_Guard irq;
            r = p->latest;
            expect = p->latest_crc;
        }
        if (meter_reading_crc(r) != expect) {
            Armv7m_Irq_Mask_Guard irq;
            p->crc_fault_latched = true;
            MeterReading z = {};
            return z;
        }
        return r;
    }

    bool HTS_Meter_Data_Manager::Is_Meter_Integrity_Fault() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) { return false; }
        bool f = false;
        {
            Armv7m_Irq_Mask_Guard irq;
            f = p->crc_fault_latched;
        }
        return f;
    }

    bool HTS_Meter_Data_Manager::Is_Scheduler_Report_Fault() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) { return false; }
        bool f = false;
        {
            Armv7m_Irq_Mask_Guard irq;
            f = p->report_enqueue_fault_latched;
        }
        return f;
    }

    uint32_t HTS_Meter_Data_Manager::Get_Profile_Value(
        size_t slot) const noexcept
    {
        const Impl* p = get_impl();
        if (p == nullptr || slot >= PROFILE_SLOTS) { return 0u; }
        uint32_t v = 0u;
        {
            Armv7m_Irq_Mask_Guard irq;
            v = p->profile[static_cast<size_t>(slot)];
        }
        return v;
    }

    size_t HTS_Meter_Data_Manager::Get_Event_Log(
        MeterLogEntry* out, size_t cap) const noexcept
    {
        const Impl* p = get_impl();
        if (p == nullptr || out == nullptr || cap == 0u) { return 0u; }
        size_t n = 0u;
        {
            Armv7m_Irq_Mask_Guard irq;
            n = (p->event_count < cap) ? p->event_count : cap;
            const uint8_t ec = p->event_count;
            const uint8_t eh = p->event_head;
            for (size_t i = 0u; i < n; ++i) {
                const uint32_t sum =
                    static_cast<uint32_t>(eh) + EVENT_LOG_SIZE
                    - static_cast<uint32_t>(ec) + static_cast<uint32_t>(i);
                const size_t idx =
                    static_cast<size_t>(sum & EVENT_LOG_MASK);
                out[i] = p->event_log[idx];
            }
        }
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
            MeterReading lr;
            uint32_t expect;
            {
                Armv7m_Irq_Mask_Guard irq;
                lr = p->latest;
                expect = p->latest_crc;
            }
            if (meter_reading_crc(lr) == expect) {
                Armv7m_Irq_Mask_Guard irq;
                const size_t ph = static_cast<size_t>(p->profile_head);
                p->profile[ph] = lr.watt_hour;
                // PROFILE_SLOTS=96 → 2의 거듭제곱 아님 — 비교·래핑으로 UDIV 회피
                uint32_t phn = static_cast<uint32_t>(p->profile_head) + 1u;
                if (phn >= static_cast<uint32_t>(PROFILE_SLOTS)) { phn = 0u; }
                p->profile_head = static_cast<uint8_t>(phn);
                p->last_profile_ms += PROFILE_INTERVAL_MS;
            }
            else {
                Armv7m_Irq_Mask_Guard irq;
                p->crc_fault_latched = true;
            }
        }

        // 1시간 보고
        const uint32_t rpt_elapsed = systick_ms - p->last_report_ms;
        if (rpt_elapsed < REPORT_INTERVAL_MS) { return; }

        // 보고 패킷 (8바이트 요약) — CRC는 잠금 밖에서 (LUT 순회 N-10)
        uint8_t pkt[8] = {};
        MeterReading lr;
        uint32_t expect;
        uint8_t evc = 0u;
        uint16_t my_id_snap = 0u;
        {
            Armv7m_Irq_Mask_Guard irq;
            lr = p->latest;
            expect = p->latest_crc;
            evc = p->event_count;
            my_id_snap = p->my_id;
        }
        const bool ok = (meter_reading_crc(lr) == expect);
        if (!ok) {
            Armv7m_Irq_Mask_Guard irq;
            p->crc_fault_latched = true;
            return;
        }
        ser_u16(&pkt[0], my_id_snap);
        ser_u32(&pkt[2], lr.cumul_kwh_x100);
        pkt[6] = lr.power_factor;
        pkt[7] = evc;

        const EnqueueResult enq = scheduler.Enqueue(
            PacketPriority::DATA,
            pkt, 8u, systick_ms);
        if (enq != EnqueueResult::OK) {
            Armv7m_Irq_Mask_Guard irq;
            p->report_enqueue_fault_latched = true;
            Mtr_Secure_Wipe(pkt, sizeof(pkt));
            return;
        }
        {
            Armv7m_Irq_Mask_Guard irq;
            p->report_enqueue_fault_latched = false;
            p->last_report_ms += REPORT_INTERVAL_MS;
        }

        Mtr_Secure_Wipe(pkt, sizeof(pkt));
    }

    void HTS_Meter_Data_Manager::Shutdown() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        {
            Armv7m_Irq_Mask_Guard irq;
            p->verify_fn = nullptr;
            p->verify_user = nullptr;
        }
        Mtr_Secure_Wipe(p->profile, sizeof(p->profile));
        Mtr_Secure_Wipe(p->event_log, sizeof(p->event_log));
    }

} // namespace ProtectedEngine