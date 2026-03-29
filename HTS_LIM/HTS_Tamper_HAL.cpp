// =========================================================================
// HTS_Tamper_HAL.cpp
// 물리적 변조 감지 HAL 구현부
// Target: STM32F407 (Cortex-M4)
//
// [제약] try-catch 0, float/double 0, heap 0
// =========================================================================
#include "HTS_Tamper_HAL.h"
#include "HTS_Secure_Logger.h"

#include <atomic>

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#define HTS_TAMPER_ARM
#endif

namespace ProtectedEngine {

    // ── 정적 상태 ─────────────────────────────────────────────────
    static TamperResponseFunc s_case_response = nullptr;
    static TamperResponseFunc s_temp_response = nullptr;
    static uint32_t s_case_gpio_port = 0u;
    static uint8_t  s_case_pin = 0u;
    static uint8_t  s_temp_adc_ch = 0u;
    static uint16_t s_temp_high = 0xFFFFu;
    static uint16_t s_temp_low = 0u;

    // =====================================================================
    //  Register_Case_Open
    // =====================================================================
    void Tamper_HAL::Register_Case_Open(
        uint32_t gpio_port, uint8_t pin_number,
        TamperResponseFunc response) noexcept {

        s_case_gpio_port = gpio_port;
        s_case_pin = pin_number;
        s_case_response = response;

#if defined(HTS_TAMPER_ARM)
        // GPIO 입력 모드 설정 (MODER = 00 = Input)
        volatile uint32_t* moder = reinterpret_cast<volatile uint32_t*>(
            gpio_port + 0x00u);  // GPIOx_MODER
        const uint32_t shift = static_cast<uint32_t>(pin_number) * 2u;
        *moder &= ~(3u << shift);  // Input mode

        // EXTI 인터럽트 설정은 NVIC 초기화에서 수행 (외부 설정)
#endif

        SecureLogger::logSecurityEvent(
            "TAMPER_REG", "Case-open switch registered.");
    }

    // =====================================================================
    //  Register_Temperature_Monitor
    // =====================================================================
    void Tamper_HAL::Register_Temperature_Monitor(
        uint8_t adc_channel,
        uint16_t high_limit, uint16_t low_limit,
        TamperResponseFunc response) noexcept {

        s_temp_adc_ch = adc_channel;
        s_temp_high = high_limit;
        s_temp_low = low_limit;
        s_temp_response = response;

        SecureLogger::logSecurityEvent(
            "TAMPER_REG", "Temperature monitor registered.");
    }

    // =====================================================================
    //  Poll_Tamper_Status — 메인 루프 보조 폴링
    // =====================================================================
    void Tamper_HAL::Poll_Tamper_Status() noexcept {

#if defined(HTS_TAMPER_ARM)
        // 1. 케이스 오픈 GPIO 확인
        if (s_case_response != nullptr && s_case_gpio_port != 0u) {
            volatile uint32_t* idr = reinterpret_cast<volatile uint32_t*>(
                s_case_gpio_port + 0x10u);  // GPIOx_IDR
            if (*idr & (1u << s_case_pin)) {
                // 핀 HIGH = 케이스 개방 감지
                s_case_response(TamperEvent::CASE_OPEN);
            }
        }

        // 2. 온도 ADC 확인 (ADC1 단일 변환)
        if (s_temp_response != nullptr) {
            // ADC1 채널 선택 + 단일 변환은 외부 ADC 드라이버에 위임
            // 여기서는 간단한 레지스터 폴링
            static constexpr uint32_t ADC1_BASE = 0x40012000u;
            volatile uint32_t* adc_dr = reinterpret_cast<volatile uint32_t*>(
                ADC1_BASE + 0x4Cu);  // ADC_DR
            const uint16_t raw = static_cast<uint16_t>(*adc_dr & 0xFFFu);

            if (raw > s_temp_high) {
                s_temp_response(TamperEvent::TEMPERATURE_HIGH);
            }
            if (raw < s_temp_low) {
                s_temp_response(TamperEvent::TEMPERATURE_LOW);
            }
        }
#endif
    }

    // =====================================================================
    //  Case_Open_ISR — EXTI 인터럽트 핸들러에서 호출
    // =====================================================================
    void Tamper_HAL::Case_Open_ISR() noexcept {
        if (s_case_response != nullptr) {
            s_case_response(TamperEvent::CASE_OPEN);
        }
    }

} // namespace ProtectedEngine