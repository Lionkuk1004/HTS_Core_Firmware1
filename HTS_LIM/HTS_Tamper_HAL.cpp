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
#include <cstddef>
#include <cstdint>

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#define HTS_TAMPER_ARM
#endif

namespace {

    /// STM32F407 ADC1 유효 채널 상한 (외부 0~15 + 내부 16~18) — PC 빌드에서도 등록 검증에 사용
    static constexpr uint8_t ADC1_CH_MAX = 18u;

#if defined(HTS_TAMPER_ARM)
    /// STM32F407 ADC1 — RM0090 레지스터 맵 (X-1-1)
    static constexpr uint32_t ADC1_BASE = 0x40012000u;
    static constexpr uint32_t ADC1_SR_OFF = 0x00u;
    static constexpr uint32_t ADC1_CR2_OFF = 0x08u;
    static constexpr uint32_t ADC1_SQR1_OFF = 0x2Cu;
    static constexpr uint32_t ADC1_SQR3_OFF = 0x34u;
    static constexpr uint32_t ADC1_DR_OFF = 0x4Cu;

    static constexpr uint32_t ADC_SR_EOC = (1u << 1u);
    static constexpr uint32_t ADC_CR2_ADON = (1u << 0u);
    static constexpr uint32_t ADC_CR2_DMA = (1u << 8u);
    static constexpr uint32_t ADC_CR2_SWSTART = (1u << 30u);
    /// STM32F407 ADC1 — 정규 시퀀스 길이 L (SQR1[23:20]) = 변환 개수-1
    static constexpr uint32_t ADC_SQR1_L_MASK = (0xFu << 20u);
    /// SQ1[4:0] — 첫 번째 변환 채널 (SQR3)
    static constexpr uint32_t ADC_SQR3_SQ1_MASK = 0x1Fu;

    static constexpr uint32_t ADC_EOC_SPIN_MAX = 10000u;

    static inline uint32_t tamper_crit_enter() noexcept {
        uint32_t primask;
        __asm volatile ("MRS %0, PRIMASK\n CPSID I"
            : "=r"(primask) :: "memory");
        return primask;
    }
    static inline void tamper_crit_exit(uint32_t pm) noexcept {
        __asm volatile ("MSR PRIMASK, %0" :: "r"(pm) : "memory");
    }
#endif

} // namespace

namespace ProtectedEngine {

    static std::atomic<TamperResponseFunc> s_case_response{ nullptr };
    static std::atomic<TamperResponseFunc> s_temp_response{ nullptr };
    static std::atomic<uint32_t> s_case_gpio_port{ 0u };
    static std::atomic<uint8_t> s_case_pin{ 0u };
    static std::atomic<uint8_t> s_temp_adc_ch{ 0u };
    static std::atomic<uint16_t> s_temp_high{ 0xFFFFu };
    static std::atomic<uint16_t> s_temp_low{ 0u };

    /// DMA 구동 시 SWSTART 경로 대신 — 외부(DMA 완료 콜백 등)에서 주입
    static std::atomic<uint16_t> s_temp_dma_sample{ 0u };
    static std::atomic<bool> s_temp_dma_sample_ready{ false };

    // =====================================================================
    //  Register_Case_Open
    // =====================================================================
    void Tamper_HAL::Register_Case_Open(
        uint32_t gpio_port, uint8_t pin_number,
        TamperResponseFunc response) noexcept {

        if (response == nullptr) {
            return;
        }
        if (gpio_port == 0u) {
            return;
        }
        if (pin_number > 15u) {
            return;
        }

        s_case_gpio_port.store(gpio_port, std::memory_order_relaxed);
        s_case_pin.store(pin_number, std::memory_order_relaxed);

#if defined(HTS_TAMPER_ARM)
        // X-1-2 / N-1: MODER RMW 원자적 (PRIMASK — 다른 GPIO 갱신과 tearing 방지)
        {
            const uint32_t pm = tamper_crit_enter();
            volatile uint32_t* const moder = reinterpret_cast<volatile uint32_t*>(
                static_cast<uintptr_t>(gpio_port) + 0x00u);
            const uint32_t shift = static_cast<uint32_t>(pin_number) * 2u;
            *moder &= ~(3u << shift);
            tamper_crit_exit(pm);
        }
#endif

        s_case_response.store(response, std::memory_order_release);

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

        if (response == nullptr) {
            return;
        }
        if (high_limit < low_limit) {
            return;
        }
        if (adc_channel > ADC1_CH_MAX) {
            return;
        }

        s_temp_adc_ch.store(adc_channel, std::memory_order_relaxed);
        s_temp_high.store(high_limit, std::memory_order_relaxed);
        s_temp_low.store(low_limit, std::memory_order_relaxed);
        s_temp_response.store(response, std::memory_order_release);

        SecureLogger::logSecurityEvent(
            "TAMPER_REG", "Temperature monitor registered.");
    }

    // =====================================================================
    //  Submit_Temperature_ADC_Sample — DMA/연동기에서 호출
    // =====================================================================
    void Tamper_HAL::Submit_Temperature_ADC_Sample(uint16_t raw12) noexcept {
#if defined(HTS_TAMPER_ARM)
        s_temp_dma_sample.store(raw12 & 0xFFFu, std::memory_order_relaxed);
        s_temp_dma_sample_ready.store(true, std::memory_order_release);
#else
        (void)raw12;
#endif
    }

    // =====================================================================
    //  Poll_Tamper_Status — 메인 루프 보조 폴링
    // =====================================================================
    void Tamper_HAL::Poll_Tamper_Status() noexcept {

#if defined(HTS_TAMPER_ARM)
        TamperResponseFunc const case_cb =
            s_case_response.load(std::memory_order_acquire);
        const uint32_t gpio_port =
            s_case_gpio_port.load(std::memory_order_relaxed);
        const uint8_t pin = s_case_pin.load(std::memory_order_relaxed);

        if (case_cb != nullptr && gpio_port != 0u) {
            volatile uint32_t* const idr = reinterpret_cast<volatile uint32_t*>(
                static_cast<uintptr_t>(gpio_port) + 0x10u);
            const uint32_t pin_mask = 1u << static_cast<uint32_t>(pin);
            if ((*idr) & pin_mask) {
                case_cb(TamperEvent::CASE_OPEN);
            }
        }

        TamperResponseFunc const temp_cb =
            s_temp_response.load(std::memory_order_acquire);
        if (temp_cb == nullptr) {
            return;
        }

        const uint16_t th = s_temp_high.load(std::memory_order_relaxed);
        const uint16_t tl = s_temp_low.load(std::memory_order_relaxed);
        const uint8_t ch = s_temp_adc_ch.load(std::memory_order_relaxed);

        volatile uint32_t* const adc_sr =
            reinterpret_cast<volatile uint32_t*>(
                static_cast<uintptr_t>(ADC1_BASE) + ADC1_SR_OFF);
        volatile uint32_t* const adc_cr2 =
            reinterpret_cast<volatile uint32_t*>(
                static_cast<uintptr_t>(ADC1_BASE) + ADC1_CR2_OFF);

        uint16_t raw = 0u;

        if (((*adc_cr2) & ADC_CR2_DMA) != 0u) {
            // DMA가 ADC1을 사용 중 → 레지스터 직접 폴링/SWSTART 금지 (스트림 충돌 방지)
            const bool had_sample = s_temp_dma_sample_ready.exchange(
                false, std::memory_order_acq_rel);
            if (!had_sample) {
                return;
            }
            raw = s_temp_dma_sample.load(std::memory_order_relaxed);
        }
        else {
            if (((*adc_cr2) & ADC_CR2_ADON) == 0u) {
                return;
            }

            volatile uint32_t* const adc_sqr1 =
                reinterpret_cast<volatile uint32_t*>(
                    static_cast<uintptr_t>(ADC1_BASE) + ADC1_SQR1_OFF);
            volatile uint32_t* const adc_sqr3 =
                reinterpret_cast<volatile uint32_t*>(
                    static_cast<uintptr_t>(ADC1_BASE) + ADC1_SQR3_OFF);
            volatile uint32_t* const adc_dr =
                reinterpret_cast<volatile uint32_t*>(
                    static_cast<uintptr_t>(ADC1_BASE) + ADC1_DR_OFF);

            const uint32_t pm = tamper_crit_enter();

            if ((*adc_sr & ADC_SR_EOC) != 0u) {
                (void)static_cast<uint32_t>(*adc_dr);
            }

            uint32_t r_sqr1 = *adc_sqr1;
            r_sqr1 &= ~ADC_SQR1_L_MASK;
            r_sqr1 |= (0u << 20u);
            *adc_sqr1 = r_sqr1;

            uint32_t r_sqr3 = *adc_sqr3;
            r_sqr3 &= ~ADC_SQR3_SQ1_MASK;
            r_sqr3 |= static_cast<uint32_t>(ch) & ADC_SQR3_SQ1_MASK;
            *adc_sqr3 = r_sqr3;

            *adc_cr2 |= ADC_CR2_SWSTART;

            uint32_t spins = 0u;
            while (((*adc_sr) & ADC_SR_EOC) == 0u
                && spins < ADC_EOC_SPIN_MAX) {
                ++spins;
            }
            if (spins >= ADC_EOC_SPIN_MAX) {
                tamper_crit_exit(pm);
                return;
            }

            raw = static_cast<uint16_t>(*adc_dr & 0xFFFu);
            tamper_crit_exit(pm);
        }

        if (raw > th) {
            temp_cb(TamperEvent::TEMPERATURE_HIGH);
        }
        if (raw < tl) {
            temp_cb(TamperEvent::TEMPERATURE_LOW);
        }
#endif
    }

    // =====================================================================
    //  Case_Open_ISR
    // =====================================================================
    void Tamper_HAL::Case_Open_ISR() noexcept {
        TamperResponseFunc const cb =
            s_case_response.load(std::memory_order_acquire);
        if (cb != nullptr) {
            cb(TamperEvent::CASE_OPEN);
        }
    }

} // namespace ProtectedEngine


