// =========================================================================
// HTS_Sensor_Fusion.cpp
// 다중 센서 융합 + 경보 등급 산출 구현부
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// [설계]
//  · IIR α=1/4 (시프트 기반, 나눗셈 0)
//  · 경보: 센서별 2단계 임계 + 복합 판정
//  · 화재 확정: 온도 ALERT + 연기 ALERT 동시
//  · PRIMASK ISR 보호 (ADC/I2C ISR에서 Feed 호출)
// =========================================================================
#include "HTS_Sensor_Fusion.h"
#include "HTS_Secure_Memory.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <new>

namespace ProtectedEngine {

#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
    static inline uint32_t fus_critical_enter() noexcept {
        uint32_t primask;
        __asm volatile ("MRS %0, PRIMASK\n CPSID I"
        : "=r"(primask) :: "memory");
        return primask;
    }
    static inline void fus_critical_exit(uint32_t pm) noexcept {
        __asm volatile ("MSR PRIMASK, %0" :: "r"(pm) : "memory");
    }
#else
    static inline uint32_t fus_critical_enter() noexcept { return 0u; }
    static inline void fus_critical_exit(uint32_t) noexcept {}
#endif

    // =====================================================================
    //  IIR 필터 (α=1/4, 시프트 기반)
    //   new = old + (raw - old) >> 2
    // =====================================================================
    static constexpr int32_t IIR_SHIFT = 2;

    //  -1 >> 2 = -1 (2의 보수) → old + (-1) → 영원히 1 오차 표류
    //  |diff| < 4 → output = raw (데드존 스냅)
    static int16_t iir_i16(int16_t old_val, int16_t raw) noexcept {
        const int32_t diff = static_cast<int32_t>(raw) -
            static_cast<int32_t>(old_val);
        // 수렴 스냅: 차이가 시프트 단위 미만이면 즉시 수렴
        const int32_t threshold = static_cast<int32_t>(1) << IIR_SHIFT;
        if (diff > -threshold && diff < threshold) {
            return raw;
        }
        return static_cast<int16_t>(
            old_val + static_cast<int16_t>(diff >> IIR_SHIFT));
    }

    static uint16_t iir_u16(uint16_t old_val, uint16_t raw) noexcept {
        const int32_t diff = static_cast<int32_t>(raw) -
            static_cast<int32_t>(old_val);
        const int32_t threshold = static_cast<int32_t>(1) << IIR_SHIFT;
        if (diff > -threshold && diff < threshold) {
            return raw;
        }
        const int32_t result = static_cast<int32_t>(old_val) +
            (diff >> IIR_SHIFT);
        return (result < 0) ? 0u : static_cast<uint16_t>(result);
    }

    // =====================================================================
    //  Pimpl 구현 구조체
    // =====================================================================
    struct HTS_Sensor_Fusion::Impl {
        // 원시 입력 (ISR에서 기록)
        int16_t  raw_temp = 250;    // 25.0°C 기본
        uint16_t raw_smoke = 0u;
        uint8_t  raw_humid = 50u;
        uint16_t raw_wind = 0u;
        uint16_t raw_accel = 0u;

        // IIR 필터 출력
        int16_t  filt_temp = 250;
        uint16_t filt_smoke = 0u;
        uint8_t  filt_humid = 50u;
        uint16_t filt_wind = 0u;
        uint16_t filt_accel = 0u;

        // 경보 상태
        AlertLevel level = AlertLevel::NORMAL;
        uint8_t trigger_flags = 0u;
        bool    is_moving = false;
        bool    initialized = false;

        explicit Impl() noexcept = default;
        ~Impl() noexcept = default;

        // 경보 등급 재평가
        void evaluate() noexcept {
            uint8_t watch_cnt = 0u;
            uint8_t alert_cnt = 0u;
            trigger_flags = 0u;

            // 온도
            if (filt_temp >= HTS_Sensor_Fusion::TEMP_ALERT) {
                trigger_flags |= SensorID::TEMPERATURE;
                ++alert_cnt;
            }
            else if (filt_temp >= HTS_Sensor_Fusion::TEMP_WATCH) {
                trigger_flags |= SensorID::TEMPERATURE;
                ++watch_cnt;
            }

            // 연기
            if (filt_smoke >= HTS_Sensor_Fusion::SMOKE_ALERT) {
                trigger_flags |= SensorID::SMOKE;
                ++alert_cnt;
            }
            else if (filt_smoke >= HTS_Sensor_Fusion::SMOKE_WATCH) {
                trigger_flags |= SensorID::SMOKE;
                ++watch_cnt;
            }

            // 풍속
            if (filt_wind >= HTS_Sensor_Fusion::WIND_ALERT) {
                trigger_flags |= SensorID::WIND;
                ++alert_cnt;
            }

            // 이동 감지
            is_moving = (filt_accel >= HTS_Sensor_Fusion::ACCEL_MOVING);
            if (is_moving) {
                trigger_flags |= SensorID::ACCEL;
            }

            // 습도 역전: 극저습 = 화재 위험 증가
            if (filt_humid < 20u) {
                ++watch_cnt;
                trigger_flags |= SensorID::HUMIDITY;
            }

            // 경보 등급 결정
            // EMERGENCY: 온도 ALERT + 연기 ALERT (화재 확정)
            const bool temp_alert =
                (filt_temp >= HTS_Sensor_Fusion::TEMP_ALERT);
            const bool smoke_alert =
                (filt_smoke >= HTS_Sensor_Fusion::SMOKE_ALERT);

            if (temp_alert && smoke_alert) {
                level = AlertLevel::EMERGENCY;
            }
            else if (alert_cnt > 0u) {
                level = AlertLevel::ALERT;
            }
            else if (watch_cnt >= 2u) {
                level = AlertLevel::ALERT;
            }
            else if (watch_cnt > 0u) {
                level = AlertLevel::WATCH;
            }
            else {
                level = AlertLevel::NORMAL;
            }
        }
    };

    // =====================================================================
    //  get_impl
    // =====================================================================
    HTS_Sensor_Fusion::Impl*
        HTS_Sensor_Fusion::get_impl() noexcept
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE를 초과합니다");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 초과");
        return impl_valid_.load(std::memory_order_acquire)
            ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }

    const HTS_Sensor_Fusion::Impl*
        HTS_Sensor_Fusion::get_impl() const noexcept
    {
        return impl_valid_.load(std::memory_order_acquire)
            ? reinterpret_cast<const Impl*>(impl_buf_) : nullptr;
    }

    // =====================================================================
    //  생성자 / 소멸자
    // =====================================================================
    HTS_Sensor_Fusion::HTS_Sensor_Fusion() noexcept
        : impl_valid_(false)
    {
        SecureMemory::secureWipe(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl();
        impl_valid_.store(true, std::memory_order_release);
    }

    HTS_Sensor_Fusion::~HTS_Sensor_Fusion() noexcept {
        Impl* const p = reinterpret_cast<Impl*>(impl_buf_);
        const bool was_valid = impl_valid_.exchange(false, std::memory_order_acq_rel);
        if (was_valid) { p->~Impl(); }
        SecureMemory::secureWipe(impl_buf_, sizeof(impl_buf_));
    }

    // =====================================================================
    //  센서 입력 (ISR 안전 — PRIMASK 보호)
    // =====================================================================
    void HTS_Sensor_Fusion::Feed_Temperature(int16_t raw_x10) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        // ISR 경로에서도 호출될 수 있으므로 PRIMASK 재조작 금지
        p->raw_temp = raw_x10;
    }

    void HTS_Sensor_Fusion::Feed_Smoke(uint16_t raw_adc) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        // ISR 경로에서도 호출될 수 있으므로 PRIMASK 재조작 금지
        p->raw_smoke = raw_adc;
    }

    void HTS_Sensor_Fusion::Feed_Humidity(uint8_t raw_pct) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        // ISR 경로에서도 호출될 수 있으므로 PRIMASK 재조작 금지
        p->raw_humid = (raw_pct > 100u) ? 100u : raw_pct;
    }

    void HTS_Sensor_Fusion::Feed_Wind(uint16_t raw_x10) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        // ISR 경로에서도 호출될 수 있으므로 PRIMASK 재조작 금지
        p->raw_wind = raw_x10;
    }

    void HTS_Sensor_Fusion::Feed_Accel(uint16_t raw_mg) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        // ISR 경로에서도 호출될 수 있으므로 PRIMASK 재조작 금지
        p->raw_accel = raw_mg;
    }

    // =====================================================================
    //  융합 결과 조회
    // =====================================================================
    FusionResult HTS_Sensor_Fusion::Get_Result() const noexcept {
        const Impl* p = get_impl();
        FusionResult r = {};
        if (p == nullptr) { return r; }

        const uint32_t pm = fus_critical_enter();
        r.temperature_x10 = p->filt_temp;
        r.smoke_raw = p->filt_smoke;
        r.humidity_pct = p->filt_humid;
        r.wind_x10 = p->filt_wind;
        r.accel_mg = p->filt_accel;
        r.level = p->level;
        r.trigger_sensors = p->trigger_flags;
        r.is_moving = p->is_moving;
        fus_critical_exit(pm);
        return r;
    }

    AlertLevel HTS_Sensor_Fusion::Get_Level() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) { return AlertLevel::NORMAL; }
        const uint32_t pm = fus_critical_enter();
        const AlertLevel level = p->level;
        fus_critical_exit(pm);
        return level;
    }

    bool HTS_Sensor_Fusion::Is_Moving() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) { return false; }
        const uint32_t pm = fus_critical_enter();
        const bool moving = p->is_moving;
        fus_critical_exit(pm);
        return moving;
    }

    // =====================================================================
    //  Tick — IIR 갱신 + 경보 재평가
    //
    //  호출 주기: 100~500ms (메인 루프)
    //  ISR에서 직접 호출하지 말 것 (evaluate 연산 비용)
    // =====================================================================
    void HTS_Sensor_Fusion::Tick() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        // ── 1단계: 원시값 스냅샷 (짧은 크리티컬) ──
        int16_t  r_temp = 0;
        uint16_t r_smoke = 0u;
        uint8_t  r_humid = 0u;
        uint16_t r_wind = 0u;
        uint16_t r_accel = 0u;

        {
            const uint32_t pm = fus_critical_enter();
            r_temp = p->raw_temp;
            r_smoke = p->raw_smoke;
            r_humid = p->raw_humid;
            r_wind = p->raw_wind;
            r_accel = p->raw_accel;
            fus_critical_exit(pm);
        }

        // ── 2단계: IIR 필터 연산 (로컬 변수, 크리티컬 밖) ──
        int16_t  new_temp = r_temp;
        uint16_t new_smoke = r_smoke;
        uint8_t  new_humid = r_humid;
        uint16_t new_wind = r_wind;
        uint16_t new_accel = r_accel;

        if (p->initialized) {
            const uint32_t pm2 = fus_critical_enter();
            const int16_t  old_temp = p->filt_temp;
            const uint16_t old_smoke = p->filt_smoke;
            const uint8_t  old_humid = p->filt_humid;
            const uint16_t old_wind = p->filt_wind;
            const uint16_t old_accel = p->filt_accel;
            fus_critical_exit(pm2);

            new_temp = iir_i16(old_temp, r_temp);
            new_smoke = iir_u16(old_smoke, r_smoke);
            const uint16_t h16 = iir_u16(
                static_cast<uint16_t>(old_humid),
                static_cast<uint16_t>(r_humid));
            new_humid = (h16 > 100u) ? 100u : static_cast<uint8_t>(h16);
            new_wind = iir_u16(old_wind, r_wind);
            new_accel = iir_u16(old_accel, r_accel);
        }

        // ── 3단계: 필터 출력 + 경보 원자적 갱신 ──
        //  모든 filt_* + evaluate를 단일 크리티컬에서 수행
        {
            const uint32_t pm3 = fus_critical_enter();
            p->filt_temp = new_temp;
            p->filt_smoke = new_smoke;
            p->filt_humid = new_humid;
            p->filt_wind = new_wind;
            p->filt_accel = new_accel;
            p->initialized = true;
            p->evaluate();
            fus_critical_exit(pm3);
        }
    }

    // =====================================================================
    //  Shutdown
    // =====================================================================
    void HTS_Sensor_Fusion::Shutdown() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        const uint32_t pm = fus_critical_enter();
        // 재가동 시 stale 데이터 기반 IIR 재개를 방지하기 위해
        // 입력/필터/상태를 생성자 기본값으로 원자적 리셋한다.
        p->raw_temp = 250;
        p->raw_smoke = 0u;
        p->raw_humid = 50u;
        p->raw_wind = 0u;
        p->raw_accel = 0u;
        p->filt_temp = 250;
        p->filt_smoke = 0u;
        p->filt_humid = 50u;
        p->filt_wind = 0u;
        p->filt_accel = 0u;
        p->level = AlertLevel::NORMAL;
        p->trigger_flags = 0u;
        p->is_moving = false;
        p->initialized = false;
        fus_critical_exit(pm);
    }

} // namespace ProtectedEngine
