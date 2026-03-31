// =========================================================================
// HTS_Sensor_Fusion.h
// 다중 센서 융합 + 경보 등급 산출 엔진
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  [센서 → IIR 필터 → 경보 등급 → 모듈 연동]
//
//   온도(ADC) ──┐
//   연기(ADC) ──┤   IIR α=1/4   ┌──────────┐   → Neighbor_Discovery
//   습도(ADC) ──┼──→ 필터링 ──→│경보 판정  │──→ Emergency_Beacon
//   풍속(ADC) ──┤               │          │   → Location_Engine
//   가속도(I2C)─┘               └──────────┘   → Device_Status_Reporter
//
//  [경보 등급]
//   NORMAL:    전 센서 정상
//   WATCH:     1+ 센서 주의 임계 돌파
//   ALERT:     1+ 센서 경고 임계 돌파 or 2+ WATCH
//   EMERGENCY: 화재 확정 (온도+연기 동시) or SOS
//
//  @warning sizeof ≈ 260B — 전역/정적 배치 권장
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    enum class AlertLevel : uint8_t {
        NORMAL = 0u,
        WATCH = 1u,
        ALERT = 2u,
        EMERGENCY = 3u,
    };

    namespace SensorID {
        static constexpr uint8_t TEMPERATURE = 0x01u;
        static constexpr uint8_t SMOKE = 0x02u;
        static constexpr uint8_t HUMIDITY = 0x04u;
        static constexpr uint8_t WIND = 0x08u;
        static constexpr uint8_t ACCEL = 0x10u;
    }

    struct FusionResult {
        int16_t    temperature_x10;
        uint16_t   smoke_raw;
        uint8_t    humidity_pct;
        uint16_t   wind_x10;
        uint16_t   accel_mg;
        AlertLevel level;
        uint8_t    trigger_sensors;
        bool       is_moving;
    };

    class HTS_Sensor_Fusion {
    public:
        static constexpr int16_t  TEMP_WATCH = 450;
        static constexpr int16_t  TEMP_ALERT = 600;
        static constexpr uint16_t SMOKE_WATCH = 1000u;
        static constexpr uint16_t SMOKE_ALERT = 2500u;
        static constexpr uint16_t WIND_ALERT = 150u;
        static constexpr uint16_t ACCEL_MOVING = 200u;

        explicit HTS_Sensor_Fusion() noexcept;
        ~HTS_Sensor_Fusion() noexcept;

        HTS_Sensor_Fusion(const HTS_Sensor_Fusion&) = delete;
        HTS_Sensor_Fusion& operator=(const HTS_Sensor_Fusion&) = delete;
        HTS_Sensor_Fusion(HTS_Sensor_Fusion&&) = delete;
        HTS_Sensor_Fusion& operator=(HTS_Sensor_Fusion&&) = delete;

        void Feed_Temperature(int16_t raw_x10) noexcept;
        void Feed_Smoke(uint16_t raw_adc) noexcept;
        void Feed_Humidity(uint8_t raw_pct) noexcept;
        void Feed_Wind(uint16_t raw_x10) noexcept;
        void Feed_Accel(uint16_t raw_mg) noexcept;

        [[nodiscard]] FusionResult Get_Result() const noexcept;
        [[nodiscard]] AlertLevel   Get_Level() const noexcept;
        [[nodiscard]] bool         Is_Moving() const noexcept;

        void Tick() noexcept;
        void Shutdown() noexcept;

    private:
        static constexpr size_t IMPL_BUF_SIZE = 256u;
        static constexpr size_t IMPL_BUF_ALIGN = 8u;
        struct Impl;
        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        bool impl_valid_ = false;
        Impl* get_impl() noexcept;
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine