// =========================================================================
// HTS_Sensor_Fusion.cpp
// 다중 센서 융합 + 경보 등급 산출 구현부
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// [설계]
//  · IIR α=1/4: diff/4 단일식(GCC/Clang -O3 → ASR 분기 없이), 데드밴드·경보는 산술 마스킹
//  · 경보: 센서별 2단계 임계 + 복합 판정
//  · 화재 확정: 온도 ALERT + 연기 ALERT 동시
//  · Feed_*: ISR 가능 — raw_* 는 std::atomic (relaxed). PRIMASK 미사용.
//  · Tick / Get_*: 동일 논리 스레드(메인 루프)에서만 filt_* 일관 읽기 가정.
//  · Tick 상단: ARM Release 시 DHCSR·OPTCR(RDP) 폴링
// =========================================================================
#include "HTS_Sensor_Fusion.h"
#include "HTS_Secure_Memory.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <new>

#if defined(_MSC_VER)
#include <intrin.h>
#endif
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#include "HTS_Anti_Debug.h"
#include "HTS_Hardware_Init.h"
#endif

namespace ProtectedEngine {

#if !defined(HTS_SENSOR_FUSION_SKIP_PHYS_TRUST)
#if defined(HTS_ALLOW_OPEN_DEBUG) || !defined(NDEBUG)
#define HTS_SENSOR_FUSION_SKIP_PHYS_TRUST 1
#else
#define HTS_SENSOR_FUSION_SKIP_PHYS_TRUST 0
#endif
#endif

#if HTS_SENSOR_FUSION_SKIP_PHYS_TRUST == 0 && \
    (defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH))
    [[noreturn]] static void SensorFusion_PhysicalTrust_Fault() noexcept {
        Hardware_Init_Manager::Terminal_Fault_Action();
    }

    static void SensorFusion_AssertPhysicalTrustOrFault() noexcept {
        volatile const uint32_t* const dhcsr =
            reinterpret_cast<volatile const uint32_t*>(ADDR_DHCSR);
        const uint32_t d0 = *dhcsr;
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("dsb sy" ::: "memory");
#endif
        const uint32_t d1 = *dhcsr;
        if (d0 != d1) {
            SensorFusion_PhysicalTrust_Fault();
        }
        if ((d0 & DHCSR_DEBUG_MASK) != 0u) {
            SensorFusion_PhysicalTrust_Fault();
        }
        volatile const uint32_t* const optcr =
            reinterpret_cast<volatile const uint32_t*>(HTS_FLASH_OPTCR_ADDR);
        const uint32_t o0 = *optcr;
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("dsb sy" ::: "memory");
#endif
        const uint32_t o1 = *optcr;
        if (o0 != o1) {
            SensorFusion_PhysicalTrust_Fault();
        }
        const uint32_t rdp = (o0 & HTS_RDP_OPTCR_MASK) >> 8u;
        if (rdp != HTS_RDP_EXPECTED_BYTE_VAL) {
            SensorFusion_PhysicalTrust_Fault();
        }
    }
#else
    static void SensorFusion_AssertPhysicalTrustOrFault() noexcept {}
#endif

    static constexpr int32_t IIR_SHIFT = 2;

    static int16_t iir_i16(int16_t old_val, int16_t raw) noexcept {
        const int32_t diff = static_cast<int32_t>(raw) -
            static_cast<int32_t>(old_val);
        const int32_t threshold = static_cast<int32_t>(1) << IIR_SHIFT;
        const uint32_t c_lo = static_cast<uint32_t>(diff > -threshold);
        const uint32_t c_hi = static_cast<uint32_t>(diff < threshold);
        const uint32_t is_inside = c_lo & c_hi;
        const uint32_t use_iir = 1u - is_inside;
        const int32_t adj = diff / 4;
        const int32_t filt_v = static_cast<int32_t>(old_val) + adj;
        return static_cast<int16_t>(
            static_cast<int32_t>(raw) * static_cast<int32_t>(is_inside)
            + filt_v * static_cast<int32_t>(use_iir));
    }

    static uint16_t iir_u16(uint16_t old_val, uint16_t raw) noexcept {
        const int32_t diff = static_cast<int32_t>(raw) -
            static_cast<int32_t>(old_val);
        const int32_t threshold = static_cast<int32_t>(1) << IIR_SHIFT;
        const uint32_t c_lo = static_cast<uint32_t>(diff > -threshold);
        const uint32_t c_hi = static_cast<uint32_t>(diff < threshold);
        const uint32_t is_inside = c_lo & c_hi;
        const uint32_t use_iir = 1u - is_inside;
        const int32_t adj = diff / 4;
        const int32_t fv = static_cast<int32_t>(old_val) + adj;
        const uint32_t okn = static_cast<uint32_t>(fv >= 0);
        const uint16_t filt_u = static_cast<uint16_t>(
            fv * static_cast<int32_t>(okn));
        return static_cast<uint16_t>(
            static_cast<uint32_t>(raw) * is_inside
            + static_cast<uint32_t>(filt_u) * use_iir);
    }

    struct HTS_Sensor_Fusion::Impl {
        std::atomic<int16_t>  raw_temp{ 250 };
        std::atomic<uint16_t> raw_smoke{ 0u };
        std::atomic<uint8_t>  raw_humid{ 50u };
        std::atomic<uint16_t> raw_wind{ 0u };
        std::atomic<uint16_t> raw_accel{ 0u };

        int16_t  filt_temp = 250;
        uint16_t filt_smoke = 0u;
        uint8_t  filt_humid = 50u;
        uint16_t filt_wind = 0u;
        uint16_t filt_accel = 0u;

        AlertLevel level = AlertLevel::NORMAL;
        uint8_t trigger_flags = 0u;
        bool    is_moving = false;
        bool    initialized = false;

        explicit Impl() noexcept = default;
        ~Impl() noexcept = default;

        void evaluate() noexcept {
            const uint32_t ta =
                static_cast<uint32_t>(filt_temp >= HTS_Sensor_Fusion::TEMP_ALERT);
            const uint32_t tw =
                static_cast<uint32_t>(filt_temp >= HTS_Sensor_Fusion::TEMP_WATCH);
            const uint32_t sa =
                static_cast<uint32_t>(filt_smoke >= HTS_Sensor_Fusion::SMOKE_ALERT);
            const uint32_t sw =
                static_cast<uint32_t>(filt_smoke >= HTS_Sensor_Fusion::SMOKE_WATCH);
            const uint32_t wind_a =
                static_cast<uint32_t>(filt_wind >= HTS_Sensor_Fusion::WIND_ALERT);
            const uint32_t humid_low =
                static_cast<uint32_t>(filt_humid < 20u);
            const uint32_t mv =
                static_cast<uint32_t>(filt_accel >= HTS_Sensor_Fusion::ACCEL_MOVING);

            const uint32_t alert_sum = ta + sa + wind_a;
            const uint32_t watch_sum =
                tw * (1u - ta) + sw * (1u - sa) + humid_low;

            trigger_flags = static_cast<uint8_t>(
                SensorID::TEMPERATURE * tw
                | SensorID::SMOKE * sw
                | SensorID::WIND * wind_a
                | SensorID::HUMIDITY * humid_low
                | SensorID::ACCEL * mv);

            is_moving = (mv != 0u);

            const uint32_t emerg = ta & sa;
            const uint32_t any_alert_tier =
                static_cast<uint32_t>(alert_sum > 0u)
                | static_cast<uint32_t>(watch_sum >= 2u);
            const uint32_t inner =
                any_alert_tier * 2u
                + (1u - any_alert_tier) * static_cast<uint32_t>(watch_sum > 0u);
            const uint32_t code = emerg * 3u + (1u - emerg) * inner;
            level = static_cast<AlertLevel>(static_cast<uint8_t>(code));
        }
    };

    HTS_Sensor_Fusion::Impl*
        HTS_Sensor_Fusion::get_impl() noexcept
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE를 초과합니다");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 초과");
        if (!impl_valid_.load(std::memory_order_acquire)) {
            return nullptr;
        }
        return std::launder(reinterpret_cast<Impl*>(impl_buf_));
    }

    const HTS_Sensor_Fusion::Impl*
        HTS_Sensor_Fusion::get_impl() const noexcept
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE를 초과합니다");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 초과");
        if (!impl_valid_.load(std::memory_order_acquire)) {
            return nullptr;
        }
        return std::launder(reinterpret_cast<const Impl*>(impl_buf_));
    }

    HTS_Sensor_Fusion::HTS_Sensor_Fusion() noexcept
        : impl_valid_(false)
    {
        SecureMemory::secureWipe(impl_buf_, sizeof(impl_buf_));
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(impl_buf_) : "memory");
#elif defined(_MSC_VER)
        _ReadWriteBarrier();
#endif
        ::new (static_cast<void*>(impl_buf_)) Impl();
        impl_valid_.store(true, std::memory_order_release);
    }

    HTS_Sensor_Fusion::~HTS_Sensor_Fusion() noexcept {
        Impl* const p = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        const bool was_valid = impl_valid_.exchange(false, std::memory_order_acq_rel);
        if (was_valid) { p->~Impl(); }
        SecureMemory::secureWipe(impl_buf_, sizeof(impl_buf_));
    }

    void HTS_Sensor_Fusion::Feed_Temperature(int16_t raw_x10) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        p->raw_temp.store(raw_x10, std::memory_order_relaxed);
    }

    void HTS_Sensor_Fusion::Feed_Smoke(uint16_t raw_adc) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        p->raw_smoke.store(raw_adc, std::memory_order_relaxed);
    }

    void HTS_Sensor_Fusion::Feed_Humidity(uint8_t raw_pct) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        p->raw_humid.store(raw_pct, std::memory_order_relaxed);
    }

    void HTS_Sensor_Fusion::Feed_Wind(uint16_t raw_x10) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        p->raw_wind.store(raw_x10, std::memory_order_relaxed);
    }

    void HTS_Sensor_Fusion::Feed_Accel(uint16_t raw_mg) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        p->raw_accel.store(raw_mg, std::memory_order_relaxed);
    }

    FusionResult HTS_Sensor_Fusion::Get_Result() const noexcept {
        SensorFusion_AssertPhysicalTrustOrFault();
        const Impl* p = get_impl();
        FusionResult r = {};
        if (p == nullptr) { return r; }

        r.temperature_x10 = p->filt_temp;
        r.smoke_raw = p->filt_smoke;
        r.humidity_pct = p->filt_humid;
        r.wind_x10 = p->filt_wind;
        r.accel_mg = p->filt_accel;
        r.level = p->level;
        r.trigger_sensors = p->trigger_flags;
        r.is_moving = p->is_moving;
        return r;
    }

    AlertLevel HTS_Sensor_Fusion::Get_Level() const noexcept {
        SensorFusion_AssertPhysicalTrustOrFault();
        const Impl* p = get_impl();
        if (p == nullptr) { return AlertLevel::NORMAL; }
        return p->level;
    }

    bool HTS_Sensor_Fusion::Is_Moving() const noexcept {
        SensorFusion_AssertPhysicalTrustOrFault();
        const Impl* p = get_impl();
        if (p == nullptr) { return false; }
        return p->is_moving;
    }

    void HTS_Sensor_Fusion::Tick() noexcept {
        SensorFusion_AssertPhysicalTrustOrFault();

        Impl* p = get_impl();
        if (p == nullptr) { return; }

        const int16_t  r_temp = p->raw_temp.load(std::memory_order_relaxed);
        const uint16_t r_smoke = p->raw_smoke.load(std::memory_order_relaxed);
        const uint8_t  r_humid = p->raw_humid.load(std::memory_order_relaxed);
        const uint16_t r_wind = p->raw_wind.load(std::memory_order_relaxed);
        const uint16_t r_accel = p->raw_accel.load(std::memory_order_relaxed);

        const uint32_t is_init = static_cast<uint32_t>(p->initialized);
        const uint32_t not_init = 1u - is_init;

        const int16_t  old_temp = p->filt_temp;
        const uint16_t old_smoke = p->filt_smoke;
        const uint8_t  old_humid = p->filt_humid;
        const uint16_t old_wind = p->filt_wind;
        const uint16_t old_accel = p->filt_accel;

        const int16_t iir_t = iir_i16(old_temp, r_temp);
        const int16_t new_temp = static_cast<int16_t>(
            static_cast<int32_t>(iir_t) * static_cast<int32_t>(is_init)
            + static_cast<int32_t>(r_temp) * static_cast<int32_t>(not_init));

        const uint16_t iir_s = iir_u16(old_smoke, r_smoke);
        const uint16_t new_smoke = static_cast<uint16_t>(
            static_cast<uint32_t>(iir_s) * is_init
            + static_cast<uint32_t>(r_smoke) * not_init);

        const uint16_t h16_raw = iir_u16(
            static_cast<uint16_t>(old_humid),
            static_cast<uint16_t>(r_humid));
        const uint16_t h16_pass = static_cast<uint16_t>(
            static_cast<uint32_t>(h16_raw) * is_init
            + static_cast<uint32_t>(static_cast<uint16_t>(r_humid)) * not_init);
        const uint32_t o = static_cast<uint32_t>(h16_pass > 100u);
        const uint8_t new_humid = static_cast<uint8_t>(
            (h16_pass & static_cast<uint16_t>((1u - o) * 65535u))
            | static_cast<uint16_t>(100u * o));

        const uint16_t iir_w = iir_u16(old_wind, r_wind);
        const uint16_t new_wind = static_cast<uint16_t>(
            static_cast<uint32_t>(iir_w) * is_init
            + static_cast<uint32_t>(r_wind) * not_init);

        const uint16_t iir_ac = iir_u16(old_accel, r_accel);
        const uint16_t new_accel = static_cast<uint16_t>(
            static_cast<uint32_t>(iir_ac) * is_init
            + static_cast<uint32_t>(r_accel) * not_init);

        p->filt_temp = new_temp;
        p->filt_smoke = new_smoke;
        p->filt_humid = new_humid;
        p->filt_wind = new_wind;
        p->filt_accel = new_accel;
        p->initialized = true;
        p->evaluate();
    }

    void HTS_Sensor_Fusion::Shutdown() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        p->raw_temp.store(250, std::memory_order_relaxed);
        p->raw_smoke.store(0u, std::memory_order_relaxed);
        p->raw_humid.store(50u, std::memory_order_relaxed);
        p->raw_wind.store(0u, std::memory_order_relaxed);
        p->raw_accel.store(0u, std::memory_order_relaxed);
        p->filt_temp = 250;
        p->filt_smoke = 0u;
        p->filt_humid = 50u;
        p->filt_wind = 0u;
        p->filt_accel = 0u;
        p->level = AlertLevel::NORMAL;
        p->trigger_flags = 0u;
        p->is_moving = false;
        p->initialized = false;
    }

} // namespace ProtectedEngine
