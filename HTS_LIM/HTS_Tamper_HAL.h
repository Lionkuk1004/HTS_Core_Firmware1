// =========================================================================
// HTS_Tamper_HAL.h
// 물리적 변조 감지 HAL (Hardware Abstraction Layer)
// Target: STM32F407 (Cortex-M4)
//
// [FIPS 140-3 Level 2 — 물리적 보안]
//  - 탬퍼 증거 씰 (Tamper-evident seals)
//  - 덮개 개방 감지 (Case-open switch)
//  - 전압 이상 감지 (PVD)
//
// [하드웨어 연결 — 보드 설계 시 적용]
//
//  1. 케이스 오픈 스위치 (GPIO)
//     STM32 PA0 (EXTI0) ← 케이스 덮개 개방 시 LOW→HIGH
//     HAL: Register_Case_Open_GPIO(GPIOA, 0)
//
//  2. 전압 탬퍼 (PVD)
//     STM32 내장 PVD ← VDD < 2.5V 시 PVD IRQ
//     HAL: 이미 HTS_Power_Manager에서 처리
//
//  3. 온도 이상 (ADC)
//     STM32 내장 온도 센서 ← -20℃ 미만 또는 +85℃ 초과 시
//     HAL: Register_Temperature_ADC(channel)
//
// [동작]
//  탬퍼 감지 → 키 소재 즉시 소거 → 감사 로그 → Self-Healing
//  ※ 키 소거가 리셋보다 우선 (FIPS 요구)
//
// [제약] try-catch 0, float/double 0, heap 0
// =========================================================================
#pragma once

#include <cstdint>

namespace ProtectedEngine {

    /// @brief 탬퍼 이벤트 종류
    enum class TamperEvent : uint8_t {
        CASE_OPEN = 0u,   ///< 덮개 개방
        VOLTAGE_LOW = 1u,   ///< 저전압 (PVD)
        TEMPERATURE_HIGH = 2u,  ///< 고온 초과
        TEMPERATURE_LOW = 3u,  ///< 저온 초과
        GLITCH_DETECT = 4u,   ///< 클럭/전압 글리치
        DEBUG_ATTACH = 5u,   ///< JTAG/SWD 감지
    };

    /// @brief 탬퍼 응답 콜백 타입
    ///  키 소거 + 로깅을 수행하는 함수 포인터
    using TamperResponseFunc = void(*)(TamperEvent event);

    class Tamper_HAL {
    public:
        /// @brief 케이스 오픈 GPIO 등록
        /// @param gpio_port  GPIO 포트 베이스 주소 (예: 0x40020000 = GPIOA)
        /// @param pin_number 핀 번호 (0~15)
        /// @param response   탬퍼 응답 콜백
        static void Register_Case_Open(
            uint32_t gpio_port, uint8_t pin_number,
            TamperResponseFunc response) noexcept;

        /// @brief 온도 감시 ADC 등록
        /// @param adc_channel  ADC 채널 (STM32 내부 온도 = 16)
        /// @param high_limit   고온 임계 (ADC raw 값)
        /// @param low_limit    저온 임계 (ADC raw 값)
        /// @param response     탬퍼 응답 콜백
        static void Register_Temperature_Monitor(
            uint8_t adc_channel,
            uint16_t high_limit, uint16_t low_limit,
            TamperResponseFunc response) noexcept;

        /// @brief 탬퍼 상태 주기적 폴링 (메인 루프에서 호출)
        /// @note  GPIO/ADC 인터럽트 방식 권장, 폴링은 보조 수단
        static void Poll_Tamper_Status() noexcept;

        /// @brief 탬퍼 ISR — EXTI 인터럽트 핸들러에서 호출
        static void Case_Open_ISR() noexcept;

        Tamper_HAL() = delete;
    };

} // namespace ProtectedEngine