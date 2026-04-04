// =========================================================================
// HTS_Hardware_Init.h
// 하드웨어 초기화 매니저 (WDT, DWT, DMA 배리어, UART 리타겟팅)
// Target: STM32F407 (Cortex-M4)
//
// [하드웨어 레지스터 주소]
//  UART/WDT 레지스터: 0x80002000 / 0x80003000 대역
//  → STM32F407 표준 USART(0x40011000) / IWDG(0x40003000)가 아닌
//    AMI 보드 커스텀 메모리 맵입니다.
//  → 파트너사 보드 설계에 따라 레지스터 주소를 교체하십시오.
//  → DWT CYCCNT(0xE0001004) / DEMCR(0xE000EDFC)는 Cortex-M4 표준
//
// [Secure Provisioning / 부트 FSM 연계]
//  · 공정(Unprovisioned): SWD/JTAG·루트키 주입이 필요한 단계는 RDP/옵션·빌드 스위치
//    (예: HTS_ALLOW_OPEN_DEBUG)로 “봉인 전”과 구분. Sealed 양산에서는
//    HTS_BOOT_ENFORCE_RDP_LEVEL2·HTS_RDP_EXPECTED_BYTE 등으로 봉인 조건 강제.
//  · 런타임 JTAG 핫플러깅 자폭(Anti_Debug 등)은 Sealed 전제에서 적용하고 공정 모드와
//    상태 전이를 분리할 것.
//
// [독립 클럭 Watchdog]
//  · WDT_CTRL/FEED(0x80003000대)는 AMI placeholder. HSE/HSI 정지 시에도 리셋을 보장하려면
//    STM32 IWDG(LSI, RM0090 0x40003000) 등 메인 PLL과 독립 클럭의 HW WDT를 병행하거나
//    본 레지스터를 IWDG 리로드 경로에 매핑해 Kick_Watchdog()이 실제 독립 WDT를 갱신하도록
//    양산 보드에서 확정할 것.
//
// [Cache 함수 명칭 참고]
//  STM32F407 (Cortex-M4)에는 I/D 캐시가 없습니다.
//  Cache_Clean_Tx / Cache_Invalidate_Rx / Cache_Invalidate_Tx는
//  실제로 DMA 전송 전후 메모리 배리어(DMB/ISB)를 수행합니다.
//  → DMA 컨트롤러와 CPU 간 메모리 일관성 보장 목적
//  → Cortex-M7(STM32F7/H7) 마이그레이션 시 실제 캐시 관리 코드 추가 필요
//
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
#include <cstdio>
#include <cstddef>

namespace ProtectedEngine {

    // =====================================================================
    //  AMI 보드 커스텀 레지스터 주소 (ARM 전용)
    //
    //  [파트너사 주의] 보드 설계에 따라 아래 주소를 교체하십시오.
    //  STM32F407 표준 주소가 아닌 AMI 보드 메모리 맵 주소입니다.
    //  DWT/DEMCR 주소(0xE000xxxx)는 Cortex-M4 표준이므로 변경 불필요
    // =====================================================================
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
    static const uint32_t UART0_TX_REG = 0x80002000u;
    static const uint32_t UART0_FR_REG = 0x80002018u;
    static const uint32_t UART_TXFF = (1u << 5);

    static const uint32_t WDT_CTRL_REG = 0x80003000u;
    static const uint32_t WDT_FEED_REG = 0x80003004u;

    //  검증용 명세 — .cpp Initialize_MPU()와 동일 값 필수
    //    MPU_TYPE  = 0xE000ED90  (offset +0xD90, TYPE.DREGION[15:8] = 지원 리전 수)
    //    MPU_CTRL  = 0xE000ED94  (PRIVDEFENA|HFNMIENA|ENABLE)
    //    MPU_RNR   = 0xE000ED98  (리전 번호 선택 0~7)
    //    MPU_RBAR  = 0xE000ED9C  (리전 베이스 + VALID/REGION)
    //    MPU_RASR  = 0xE000EDA0  (속성·SIZE·ENABLE)
    //    MPU_CTRL_FULL = 0x07u = bit0 ENABLE | bit1 HFNMIENA | bit2 PRIVDEFENA
    static constexpr uintptr_t MPU_TYPE_ADDR = 0xE000ED90u;
    static constexpr uintptr_t MPU_CTRL_ADDR = 0xE000ED94u;
    static constexpr uintptr_t MPU_RNR_ADDR = 0xE000ED98u;
    static constexpr uintptr_t MPU_RBAR_ADDR = 0xE000ED9Cu;
    static constexpr uintptr_t MPU_RASR_ADDR = 0xE000EDA0u;
    static constexpr uint32_t  MPU_CTRL_FULL = 0x07u;

    // [H-1] SCS 레이아웃·MPU_CTRL 비트 — 컴파일 타임 정합 (K-1/R-11)
    static_assert(
        MPU_RBAR_ADDR + static_cast<uintptr_t>(4) == MPU_RASR_ADDR,
        "MPU RASR must immediately follow RBAR (+4) in ARMv7-M SCS");
    static_assert(
        MPU_CTRL_FULL == (1u | 2u | 4u),
        "MPU_CTRL FULL: ENABLE|HFNMIENA|PRIVDEFENA");

    // ── 부트 RDP 검사 (STM32F407 Flash OPTCR, RM0090) ─────────────────
    //  기본값: OPTCR 읽기 주소·RDP 바이트 마스크·양산 기대값(0xCC = Level2 프로비저닝 가정).
    //  빌드: HTS_BOOT_ENFORCE_RDP_LEVEL2 (미정의 시 Release+ARM에서 1, Debug 또는 HTS_ALLOW_OPEN_DEBUG 시 0)
    //        HTS_RDP_EXPECTED_BYTE 재정의로 칩·라인별 옵션 바이트에 맞출 수 있음.
#ifndef HTS_RDP_EXPECTED_BYTE
#define HTS_RDP_EXPECTED_BYTE 0xCCu
#endif
    inline constexpr uintptr_t HTS_FLASH_OPTCR_ADDR = 0x40023C14u;
    inline constexpr uint32_t  HTS_RDP_OPTCR_MASK = 0x0000FF00u;
    inline constexpr uint32_t  HTS_RDP_EXPECTED_BYTE_VAL =
        static_cast<uint32_t>(HTS_RDP_EXPECTED_BYTE) & 0xFFu;
#endif

    class Hardware_Init_Manager {
    public:
        /// RDP/보안 검증 실패·강제 정지: ARM은 AIRCR 리셋 경로, PC 시뮬은 abort
        [[noreturn]] static void Terminal_Fault_Action() noexcept;

        // 시스템 초기화 (ARM: WDT + MPU + DWT CYCCNT 활성화 / PC: no-op)
        static void Initialize_System() noexcept;

        // 워치독 타이머 킥 (ARM: WDT 피드 / PC: no-op)
        static void Kick_Watchdog() noexcept;

#if defined(HTS_ALLOW_HOST_BUILD)
        /// 호스트 TU 전용: `Kick_Watchdog()` 호출 누적(실칩 IWDG 미연동)
        static uint64_t Debug_Host_WdtKick_Count() noexcept;
#endif

    private:
        // @param stack_bottom_addr  스택 가드 리전 베이스 (링커 __stack_bottom__ 또는 폴백)
        // @note ARM 전용 — PC 빌드에서 no-op
        static void Initialize_MPU(uint32_t stack_bottom_addr) noexcept;

    public:
        // DMA TX 전: CPU→RAM 메모리 배리어 (DMB)
        static void Cache_Clean_Tx(uint32_t* buffer, size_t length) noexcept;

        // DMA RX 후: RAM→CPU 메모리 배리어 (DMB + ISB)
        static void Cache_Invalidate_Rx(volatile int16_t* buffer, size_t length) noexcept;

        // DMA TX ISR: FIFO 읽기 전 메모리 배리어 (DMB + ISB)
        static void Cache_Invalidate_Tx(volatile int16_t* buffer, size_t length) noexcept;
    };

} // namespace ProtectedEngine
