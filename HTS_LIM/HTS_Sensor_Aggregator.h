// =========================================================================
// HTS_Sensor_Aggregator.h
// 센서 HAL + 샘플링 스케줄러
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  [목적]
//  ADC/I2C 센서 하드웨어를 추상화하고, 주기적 샘플링 후
//  Sensor_Fusion에 원시 데이터를 전달합니다.
//
//  [센서 채널]
//   CH0: 온도     (ADC1_CH0, NTC 서미스터)
//   CH1: 연기     (ADC1_CH1, MQ-2 가스센서)
//   CH2: 습도     (ADC1_CH2, 저항형)
//   CH3: 풍속     (ADC1_CH3, 열선 풍속계)
//   CH4: 가속도   (I2C1, LIS2DH12 or 유사)
//
//  [샘플링 주기]
//   NORMAL:  1초 (전력 절약)
//   FAST:    100ms (경보 상태)
//
//  [센서 건강 감시]
//   ADC 값이 0 또는 4095 고착 → SENSOR_FAIL 장애
//   I2C NACK → SENSOR_FAIL 장애
//
//  @warning sizeof ≈ 132B — 전역/정적 배치 권장
// ─────────────────────────────────────────────────────────────────────────
#pragma once
// ─────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────
//  [사용법] 기본 사용 예시를 여기에 기재하세요.
//  [메모리] sizeof(클래스명) 확인 후 전역/정적 배치 필수.
//  [보안]   복사/이동 연산자 = delete (키 소재 복제 차단).
//
//  ⚠ [파트너사 필수 확인]
//    HW 레지스터 주소(UART/WDT 등)는 보드 설계에 맞게 교체.
//    IRQ 번호는 STM32F407 RM0090 벡터 테이블 기준으로 교체.
// ─────────────────────────────────────────────────────────

#include <cstdint>
#include <cstddef>
#include <atomic>

namespace ProtectedEngine {

    class HTS_Sensor_Fusion;

    /// @brief 센서 채널 상태
    enum class SensorHealth : uint8_t {
        OK = 0u,
        STALE = 1u,   ///< 장시간 미갱신
        STUCK = 2u,   ///< 값 고착 (0 or 4095)
        FAIL = 3u,   ///< 통신 실패 (I2C NACK)
    };

    class HTS_Sensor_Aggregator {
    public:
        static constexpr size_t  NUM_ADC_CH = 4u;
        static constexpr uint32_t NORMAL_PERIOD_MS = 1000u;
        static constexpr uint32_t FAST_PERIOD_MS = 100u;

        /// @brief 생성자
        explicit HTS_Sensor_Aggregator() noexcept;
        ~HTS_Sensor_Aggregator() noexcept;

        HTS_Sensor_Aggregator(const HTS_Sensor_Aggregator&) = delete;
        HTS_Sensor_Aggregator& operator=(const HTS_Sensor_Aggregator&) = delete;
        HTS_Sensor_Aggregator(HTS_Sensor_Aggregator&&) = delete;
        HTS_Sensor_Aggregator& operator=(HTS_Sensor_Aggregator&&) = delete;

        // ─── ADC DMA 완료 콜백 (ISR에서 호출) ────────────

        /// @brief ADC DMA 전송 완료 → 4채널 원시값 수집
        /// @param adc_buf  ADC DMA 버퍼 (4개 채널, 12비트)
        void On_ADC_DMA_Complete(const uint16_t* adc_buf) noexcept;

        /// @brief I2C 가속도 읽기 완료
        /// @param accel_mg  가속도 크기 (mg)
        /// @param success   I2C 통신 성공 여부
        void On_Accel_Read(uint16_t accel_mg, bool success) noexcept;

        // ─── 샘플링 제어 ─────────────────────────────────

        /// @brief 빠른 샘플링 전환 (경보 시)
        void Set_Fast_Mode(bool fast) noexcept;

        // ─── 센서 건강 ──────────────────────────────────

        /// @brief 개별 센서 건강 상태
        [[nodiscard]]
        SensorHealth Get_Health(uint8_t channel) const noexcept;

        /// @brief 전체 센서 정상 여부
        [[nodiscard]] bool All_Healthy() const noexcept;

        // ─── 주기 처리 ──────────────────────────────────

        /// @brief ADC 트리거 + Fusion 전달 + 건강 감시
        void Tick(uint32_t systick_ms,
            HTS_Sensor_Fusion& fusion) noexcept;

        void Shutdown() noexcept;

    private:
        static constexpr size_t IMPL_BUF_SIZE = 128u;
        static constexpr size_t IMPL_BUF_ALIGN = 8u;
        struct Impl;
        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        std::atomic<bool> impl_valid_{ false };
        Impl* get_impl() noexcept;
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine