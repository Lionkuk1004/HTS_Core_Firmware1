#pragma once
/// @file  HTS_Power_Manager_Defs.h
/// @brief HTS 전력 관리자 공통 정의부
/// @details
///   STM32F407 저전력 모드 관리. IoT 배터리/태양전지 시나리오에서
///   주변장치 클럭 게이팅, 슬립 모드 전환, PVD 전압 감시를 수행한다.
///
///   전력 모드:
///   - RUN:     풀 속도 168MHz (모든 주변장치 활성)
///   - LOW_RUN: 저속 클럭 (HSI 16MHz, 최소 주변장치)
///   - SLEEP:   CPU 정지, 주변장치 유지 (WFI, ~1mA)
///   - STOP:    1.2V 레귤레이터 저전력, SRAM 유지 (~20uA)
///   - STANDBY: 전원 차단, RTC+백업 레지스터만 유지 (~2uA)
///
///   설계 기준:
///   - Cortex-M4F STM32F407VGT6
///   - 힙 0, float/double 0, 나눗셈 0
///   - 슬립 전/후 상태 보존 콜백 (외부 모듈 연동)
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    // ============================================================
    //  전력 모드
    // ============================================================

    /// @brief 전력 모드
    enum class PowerMode : uint8_t {
        RUN = 0x00u,    ///< 풀 속도 168MHz
        LOW_RUN = 0x01u,    ///< 저속 HSI 16MHz
        SLEEP = 0x02u,    ///< CPU WFI, 주변장치 유지
        STOP = 0x03u,    ///< 레귤레이터 저전력, SRAM 유지
        STANDBY = 0x04u,    ///< 전원 차단, RTC만 유지
        MODE_COUNT = 0x05u     ///< 모드 총 개수 (검증용)
    };

    // ============================================================
    //  웨이크업 소스
    // ============================================================

    /// @brief 웨이크업 소스 비트맵
    namespace WakeSource {
        static constexpr uint16_t RTC_ALARM = (1u << 0u);   ///< RTC 알람
        static constexpr uint16_t RTC_WAKEUP = (1u << 1u);   ///< RTC 주기 웨이크업
        static constexpr uint16_t EXTI_PIN = (1u << 2u);   ///< 외부 GPIO 인터럽트
        static constexpr uint16_t UART_RX = (1u << 3u);   ///< UART 수신 (STOP 모드)
        static constexpr uint16_t SPI_CS = (1u << 4u);   ///< SPI CS 하강 에지
        static constexpr uint16_t PVD_EVENT = (1u << 5u);   ///< PVD 전압 하락
        static constexpr uint16_t WATCHDOG = (1u << 6u);   ///< IWDG 타임아웃
        static constexpr uint16_t BLE_CONNECT = (1u << 7u);   ///< BLE 연결 이벤트
    }  // namespace WakeSource

    // ============================================================
    //  주변장치 클럭 게이팅 비트맵
    // ============================================================

    /// @brief 주변장치 클럭 활성화 비트맵 (RCC 레지스터 매핑)
    namespace ClockGate {
        static constexpr uint32_t SPI1 = (1u << 0u);
        static constexpr uint32_t SPI2 = (1u << 1u);
        static constexpr uint32_t SPI3 = (1u << 2u);
        static constexpr uint32_t USART1 = (1u << 3u);
        static constexpr uint32_t USART2 = (1u << 4u);
        static constexpr uint32_t USART3 = (1u << 5u);
        static constexpr uint32_t I2C1 = (1u << 6u);
        static constexpr uint32_t I2C2 = (1u << 7u);
        static constexpr uint32_t TIM2 = (1u << 8u);
        static constexpr uint32_t TIM3 = (1u << 9u);
        static constexpr uint32_t ADC1 = (1u << 10u);
        static constexpr uint32_t DAC = (1u << 11u);
        static constexpr uint32_t DMA1 = (1u << 12u);
        static constexpr uint32_t DMA2 = (1u << 13u);
        static constexpr uint32_t ETH_MAC = (1u << 14u);
        static constexpr uint32_t CRC_UNIT = (1u << 15u);
        static constexpr uint32_t RNG = (1u << 16u);
        static constexpr uint32_t ALL = 0x0001FFFFu;  ///< 전체 마스크 (17비트)
    }  // namespace ClockGate

    // ============================================================
    //  전력 모드별 프리셋 (constexpr ROM)
    // ============================================================

    /// @brief 단일 전력 모드 프리셋
    struct PowerPreset {
        PowerMode mode;                 ///< 전력 모드
        uint8_t   cpu_freq_mhz;        ///< CPU 클럭 (MHz)
        uint16_t  wake_source_mask;    ///< 허용 웨이크업 소스
        uint32_t  clock_gate_mask;     ///< 활성화 주변장치 클럭
    };
    static_assert(sizeof(PowerPreset) == 8u, "PowerPreset must be 8 bytes");

    /// @brief 5종 전력 프리셋 테이블 (constexpr ROM)
    static constexpr PowerPreset k_power_presets[5] = {
        { PowerMode::RUN,     168u, 0x00FFu, ClockGate::ALL },
        { PowerMode::LOW_RUN,  16u, 0x00FFu,
            ClockGate::SPI1 | ClockGate::USART1 | ClockGate::DMA1 | ClockGate::CRC_UNIT },
        { PowerMode::SLEEP,   168u,
            WakeSource::RTC_ALARM | WakeSource::EXTI_PIN | WakeSource::UART_RX | WakeSource::SPI_CS,
            ClockGate::SPI1 | ClockGate::USART1 | ClockGate::DMA1 },
        { PowerMode::STOP,      0u,
            WakeSource::RTC_ALARM | WakeSource::RTC_WAKEUP | WakeSource::EXTI_PIN,
            0u },  // All clocks stopped
        { PowerMode::STANDBY,   0u,
            WakeSource::RTC_ALARM | WakeSource::EXTI_PIN,
            0u }   // Full power-off
    };
    static_assert(sizeof(k_power_presets) == 40u, "Power preset table must be 40 bytes");

    // ============================================================
    //  PVD 임계값
    // ============================================================

    /// @brief PVD 전압 레벨 (STM32F407 PLS 필드)
    enum class PVD_Level : uint8_t {
        V_2_0 = 0u,  ///< 2.0V
        V_2_1 = 1u,  ///< 2.1V
        V_2_3 = 2u,  ///< 2.3V
        V_2_5 = 3u,  ///< 2.5V
        V_2_6 = 4u,  ///< 2.6V
        V_2_7 = 5u,  ///< 2.7V
        V_2_8 = 6u,  ///< 2.8V
        V_2_9 = 7u   ///< 2.9V
    };

    // ============================================================
    //  전력 관리 HAL 콜백
    // ============================================================

    /// @brief 전력 HAL 콜백 (저수준 하드웨어 제어)
    struct Power_HAL_Callbacks {
        void (*set_cpu_clock)(uint8_t mhz);             ///< CPU 클럭 변경
        void (*set_clock_gates)(uint32_t mask);          ///< 주변장치 클럭 게이팅
        void (*enter_sleep_wfi)(void);                   ///< WFI 실행 (SLEEP)
        void (*enter_stop_mode)(void);                   ///< STOP 모드 진입
        void (*enter_standby_mode)(void);                ///< STANDBY 진입 [[noreturn]]
        void (*restore_clocks_from_stop)(void);          ///< STOP 복귀 후 클럭 재설정
        void (*configure_pvd)(uint8_t level);            ///< PVD 임계값 설정
        void (*configure_rtc_wakeup)(uint32_t sec);      ///< RTC 웨이크업 주기 설정
        uint16_t(*get_battery_mv)(void);                ///< 배터리 전압 (mV)
        uint16_t(*get_wake_source)(void);               ///< 마지막 웨이크업 소스
        void (*disable_irq)(void);                       ///< __disable_irq() (PRIMASK=1)
        void (*enable_irq)(void);                        ///< __enable_irq() (PRIMASK=0)
        bool (*is_interrupt_pending)(void);              ///< NVIC ISPR 또는 SCB->ICSR ISRPENDING 확인
    };

    /// @brief 슬립 전/후 통지 콜백 (외부 모듈 상태 보존/복원)
    struct Power_Notify_Callbacks {
        void (*on_pre_sleep)(PowerMode target);          ///< 슬립 진입 전 호출
        void (*on_post_wake)(PowerMode from, uint16_t wake_src); ///< 웨이크업 후 호출
        void (*on_pvd_warning)(uint16_t battery_mv);     ///< PVD 전압 경고
    };

    // ============================================================
    //  전력 관리 CFI 상태
    // ============================================================

    /// @brief 전력 관리 상태 (비트마스크, CFI 검증)
    enum class PowerState : uint8_t {
        UNINITIALIZED = 0x00u,
        ACTIVE = 0x01u,    ///< 정상 운용 (RUN/LOW_RUN)
        SLEEPING = 0x02u,    ///< 슬립 진입 처리 중
        WAKING = 0x04u,    ///< 웨이크업 복원 처리 중
        ERROR = 0x08u
    };

    static constexpr uint8_t POWER_VALID_STATE_MASK =
        static_cast<uint8_t>(PowerState::ACTIVE)
        | static_cast<uint8_t>(PowerState::SLEEPING)
        | static_cast<uint8_t>(PowerState::WAKING)
        | static_cast<uint8_t>(PowerState::ERROR);

    inline bool Power_Is_Valid_State(PowerState s) noexcept
    {
        const uint8_t v = static_cast<uint8_t>(s);
        if (v == 0u) { return true; }
        if ((v & ~POWER_VALID_STATE_MASK) != 0u) { return false; }
        return ((v & (v - 1u)) == 0u);
    }

    inline bool Power_Is_Legal_Transition(PowerState from, PowerState to) noexcept
    {
        if (!Power_Is_Valid_State(to)) { return false; }

        static constexpr uint8_t k_legal[5] = {
            /* UNINITIALIZED -> */ static_cast<uint8_t>(PowerState::ACTIVE),
            /* ACTIVE        -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(PowerState::SLEEPING)
              | static_cast<uint8_t>(PowerState::UNINITIALIZED)),
            /* SLEEPING      -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(PowerState::WAKING)
              | static_cast<uint8_t>(PowerState::ERROR)),
            /* WAKING        -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(PowerState::ACTIVE)
              | static_cast<uint8_t>(PowerState::ERROR)),
            /* ERROR         -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(PowerState::ACTIVE)
              | static_cast<uint8_t>(PowerState::UNINITIALIZED))
        };

        uint8_t idx;
        switch (from) {
        case PowerState::UNINITIALIZED: idx = 0u; break;
        case PowerState::ACTIVE:        idx = 1u; break;
        case PowerState::SLEEPING:      idx = 2u; break;
        case PowerState::WAKING:        idx = 3u; break;
        case PowerState::ERROR:         idx = 4u; break;
        default:                        return false;
        }

        if (static_cast<uint8_t>(to) == 0u) {
            static constexpr uint8_t k_uninit_src = static_cast<uint8_t>(
                static_cast<uint8_t>(PowerState::ACTIVE)
                | static_cast<uint8_t>(PowerState::ERROR));
            return (static_cast<uint8_t>(from) & k_uninit_src) != 0u;
        }

        return (k_legal[idx] & static_cast<uint8_t>(to)) != 0u;
    }

} // namespace ProtectedEngine