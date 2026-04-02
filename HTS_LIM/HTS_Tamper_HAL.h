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
//  S-5: 콜백 종료 후 즉시 정지가 필요하면 AntiDebugManager::trustedHalt 호출 권장 (cpp 연동)
//
// [제약] try-catch 0, float/double 0, heap 0
// =========================================================================
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
        /// @note H-1: `response==nullptr` 또는 `gpio_port==0` 또는 `pin_number>15` 이면 등록 무시
        /// @note X-1-2: MODER RMW는 PRIMASK 크리티컬 섹션에서 수행
        static void Register_Case_Open(
            uint32_t gpio_port, uint8_t pin_number,
            TamperResponseFunc response) noexcept;

        /// @brief 온도 감시 ADC 등록
        /// @param adc_channel  ADC1 채널 0~18 (내부 온도 = 16)
        /// @param high_limit   고온 임계 (ADC raw 값)
        /// @param low_limit    저온 임계 (ADC raw 값)
        /// @param response     탬퍼 응답 콜백
        /// @note H-1: `response==nullptr` 이면 무시. `high_limit < low_limit` 이면 무시. `adc_channel>18` 이면 무시
        static void Register_Temperature_Monitor(
            uint8_t adc_channel,
            uint16_t high_limit, uint16_t low_limit,
            TamperResponseFunc response) noexcept;

        /// @brief ADC1이 DMA로 구동될 때 변환 완료 raw(12비트) 주입 — SWSTART 경로와 배타적
        /// @note CR2.DMA=1 이면 Poll은 레지스터를 건드리지 않음; DMA/ISR에서 본 API 호출 필요
        static void Submit_Temperature_ADC_Sample(uint16_t raw12) noexcept;

        /// @brief 탬퍼 상태 주기적 폴링 (메인 루프에서 호출)
        /// @note GPIO/ADC 인터럽트 방식 권장, 폴링은 보조 수단
        /// @note DMA 미사용: SQR1(L=0)+SQR3(SQ1=ch)+SWSTART 후 EOC 상한 대기 → DR
        /// @note ⑮/X-4-4: EOC 미수신 시 상한 스핀 후 해당 폴링 주기만 중단(케이스 GPIO는 이미 처리됨)
        static void Poll_Tamper_Status() noexcept;

        /// @brief 탬퍼 ISR — EXTI 인터럽트 핸들러에서 호출
        /// @note W-4: 콜백은 짧게(디바운스/무거운 작업은 메인으로 위임)
        static void Case_Open_ISR() noexcept;

        Tamper_HAL() = delete;
    };

} // namespace ProtectedEngine