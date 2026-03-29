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
// [Cache 함수 명칭 참고]
//  STM32F407 (Cortex-M4)에는 I/D 캐시가 없습니다.
//  Cache_Clean_Tx / Cache_Invalidate_Rx / Cache_Invalidate_Tx는
//  실제로 DMA 전송 전후 메모리 배리어(DMB/ISB)를 수행합니다.
//  → DMA 컨트롤러와 CPU 간 메모리 일관성 보장 목적
//  → Cortex-M7(STM32F7/H7) 마이그레이션 시 실제 캐시 관리 코드 추가 필요
//
// [양산 수정]
//  1. UART 레지스터 주소: namespace 상수로 공개 (fputc 접근용)
//  2. 문서화: AMI 커스텀 레지스터 vs STM32 표준 구분 명시
//  3. 문서화: Cache 함수 = DMA 배리어 역할 명시
//  4. fputc: EMCON 모드 문서화
// =========================================================================
#pragma once

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
#endif

    class Hardware_Init_Manager {
    public:
        // 시스템 초기화 (ARM: WDT + DWT CYCCNT 활성화 / PC: no-op)
        static void Initialize_System() noexcept;

        // 워치독 타이머 킥 (ARM: WDT 피드 / PC: no-op)
        static void Kick_Watchdog() noexcept;

        // DMA TX 전: CPU→RAM 메모리 배리어 (DMB)
        static void Cache_Clean_Tx(uint32_t* buffer, size_t length) noexcept;

        // DMA RX 후: RAM→CPU 메모리 배리어 (DMB + ISB)
        static void Cache_Invalidate_Rx(volatile int16_t* buffer, size_t length) noexcept;

        // DMA TX ISR: FIFO 읽기 전 메모리 배리어 (DMB + ISB)
        static void Cache_Invalidate_Tx(volatile int16_t* buffer, size_t length) noexcept;
    };

} // namespace ProtectedEngine