// =========================================================================
// HTS_Hardware_Init.cpp
// 하드웨어 초기화 매니저 구현부
// Target: STM32F407 (Cortex-M4)
//
#include "HTS_Hardware_Init.h"
#include <cstdio>
#include <cstdlib>

// =========================================================================
//  플랫폼 감지
// =========================================================================
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#define HTS_TARGET_ARM_BAREMETAL
#endif

#ifdef HTS_TARGET_ARM_BAREMETAL
extern uint32_t __stack_bottom__ __attribute__((weak));

// Fault / RDP 실패 공통: AIRCR SYSRESETREQ → 하드웨어 리셋 (wfi만으로 정지 금지)
[[noreturn]] static inline void HTS_Fault_Reset_Wait() noexcept {
    static constexpr uintptr_t ADDR_AIRCR = 0xE000ED0Cu;
    static constexpr uint32_t  AIRCR_RESET =
        (0x05FAu << 16) | (1u << 2);
    volatile uint32_t* const aircr =
        reinterpret_cast<volatile uint32_t*>(ADDR_AIRCR);
    *aircr = AIRCR_RESET;
#if defined(__GNUC__) || defined(__clang__)
    static constexpr uintptr_t ADDR_DBGMCU_FZ = 0xE0042008u;
    static constexpr uint32_t DBGMCU_WWDG_STOP = (1u << 11);
    static constexpr uint32_t DBGMCU_IWDG_STOP = (1u << 12);
    volatile uint32_t* const dbgmcu_fz =
        reinterpret_cast<volatile uint32_t*>(ADDR_DBGMCU_FZ);
    *dbgmcu_fz &= ~(DBGMCU_WWDG_STOP | DBGMCU_IWDG_STOP);
    __asm__ __volatile__("dsb sy\n\t" "isb\n\t" ::: "memory");
#endif
    for (;;) {
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("wfi");
#else
        __asm__ __volatile__("nop");
#endif
    }
}
#endif

// 양산: RDP Level2(OPTCR[15:8]==0xCC) 미만이면 Terminal_Fault → 리셋
//  HTS_ALLOW_OPEN_DEBUG 정의 시 개발 보드용으로 강제 비활성화
#ifndef HTS_BOOT_ENFORCE_RDP_LEVEL2
#if defined(HTS_TARGET_ARM_BAREMETAL) && defined(NDEBUG) && \
    !defined(HTS_ALLOW_OPEN_DEBUG)
#define HTS_BOOT_ENFORCE_RDP_LEVEL2 1
#else
#define HTS_BOOT_ENFORCE_RDP_LEVEL2 0
#endif
#endif

namespace ProtectedEngine {

#if defined(HTS_TARGET_ARM_BAREMETAL)
[[noreturn]] void Hardware_Init_Manager::Terminal_Fault_Action() noexcept {
    HTS_Fault_Reset_Wait();
}
#else
[[noreturn]] void Hardware_Init_Manager::Terminal_Fault_Action() noexcept {
    std::abort();
}
#endif

} // namespace ProtectedEngine

#if HTS_BOOT_ENFORCE_RDP_LEVEL2 && defined(HTS_TARGET_ARM_BAREMETAL)
namespace {
void HTS_Boot_Assert_Rdp_Level2_Or_Halt() noexcept {
    using ProtectedEngine::HTS_FLASH_OPTCR_ADDR;
    using ProtectedEngine::HTS_RDP_EXPECTED_BYTE_VAL;
    using ProtectedEngine::HTS_RDP_OPTCR_MASK;
    using ProtectedEngine::Hardware_Init_Manager;
    // 이중 읽기 + dsb: 글리치/재배치에 대한 OPTCR 일관성 확인 (양산 부트 검증)
    const uint32_t optcr_a =
        *reinterpret_cast<volatile uint32_t*>(HTS_FLASH_OPTCR_ADDR);
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("dsb sy" ::: "memory");
#endif
    const uint32_t optcr_b =
        *reinterpret_cast<volatile uint32_t*>(HTS_FLASH_OPTCR_ADDR);
    if (optcr_a != optcr_b) {
        Hardware_Init_Manager::Terminal_Fault_Action();
    }
    const uint32_t rdp = (optcr_a & HTS_RDP_OPTCR_MASK) >> 8u;
    if (rdp != HTS_RDP_EXPECTED_BYTE_VAL) {
        Hardware_Init_Manager::Terminal_Fault_Action();
    }
}
} // namespace
#endif

namespace ProtectedEngine {

    // =====================================================================
    //  ARM 하드웨어 배리어 매크로
    //
    //  DMB SY (Data Memory Barrier — System):
    //    이 명령어 이전의 모든 메모리 접근이 완료된 후에만
    //    이후의 메모리 접근이 시작됨을 보장
    //    → DMA 전송 전: CPU 쓰기가 RAM에 반영된 후 DMA 시작
    //    → DMA 전송 후: DMA 쓰기가 RAM에 반영된 후 CPU 읽기
    //
    //  ISB (Instruction Synchronization Barrier):
    //    파이프라인 플러시 → 이후 명령어가 새로운 메모리 상태에서 실행
    //    → DWT CYCCNT 활성화 직후 필요 (설정 즉시 반영 보장)
    // =====================================================================
#ifdef HTS_TARGET_ARM_BAREMETAL
#define HW_BARRIER() __asm__ __volatile__("dmb sy" ::: "memory")
#define HW_ISB()     __asm__ __volatile__("isb" ::: "memory")
#else
#define HW_BARRIER() ((void)0)
#define HW_ISB()     ((void)0)
#endif

    // =====================================================================
    //  Initialize_System — WDT → (옵션) RDP 검사 → NVIC → MPU → DWT CYCCNT
    //
    //  [호출 시점] main() 진입 직후, POST 이전
    //  [ARM 동작 순서 — H-2]
    //    1. WDT 활성화: WDT_CTRL_REG에 0x01 쓰기 (RDP 검사보다 선행)
    //       → 이후 주기적으로 Kick_Watchdog() 미호출 시 하드웨어 리셋
    //    2. HTS_BOOT_ENFORCE_RDP_LEVEL2 시: Flash OPTCR RDP Level2 미만이면 AIRCR 리셋
    //    3. NVIC: Tx 스케줄러 IRQ 우선순위 플레이스홀더 (파트너사 IRQ 번호 교체)
    //    4. MPU: Initialize_MPU() 8리전 (K-1/R-11)
    //    5. DWT CYCCNT: DEMCR TRCENA → DWT_CTRL CYCCNTENA → 카운터 리셋
    //       → Hardware_Bridge::Get_Physical_CPU_Tick() 사용 가능
    //  [PC 동작] no-op (시뮬레이션 환경)
    // =====================================================================
    void Hardware_Init_Manager::Initialize_System() noexcept {
#ifdef HTS_TARGET_ARM_BAREMETAL
        // ── WDT 활성화 (RDP 검사 전) ─────────────────────────────────
        //  RDP 실패 시 Terminal_Fault_Action → AIRCR 리셋 외에도 WDT가 동작하도록 선행
        volatile uint32_t* wdt_ctrl = reinterpret_cast<volatile uint32_t*>(
            static_cast<uintptr_t>(WDT_CTRL_REG));
        HW_BARRIER();
        *wdt_ctrl = 0x01u;
        HW_ISB();
#if HTS_BOOT_ENFORCE_RDP_LEVEL2
        HTS_Boot_Assert_Rdp_Level2_Or_Halt();
#endif

        // Tx_Scheduler 타임슬롯 마감 보장 — NVIC 우선순위 일괄 설정
        // 파트너사: TIM_IRQn / DMA_IRQn 번호를 보드 설계에 맞게 교체
        {
            typedef int32_t IRQn_Type;
            static constexpr IRQn_Type TIM_IRQn = static_cast<IRQn_Type>(28);  // 예: STM32 TIM2 — 교체
            static constexpr IRQn_Type DMA_IRQn = static_cast<IRQn_Type>(56);  // 예: DMA2_Stream1 — 교체
            auto NVIC_SetPriority = [](IRQn_Type irq, uint32_t prio) noexcept {
                if (static_cast<int32_t>(irq) < 0) { return; }
                volatile uint8_t* ipr = reinterpret_cast<volatile uint8_t*>(
                    0xE000E400u + static_cast<uintptr_t>(static_cast<uint32_t>(irq)));
                *ipr = static_cast<uint8_t>((prio << 4u) & 0xFFu);
            };
            auto NVIC_EnableIRQ = [](IRQn_Type irq) noexcept {
                if (static_cast<int32_t>(irq) < 0) { return; }
                const uint32_t u = static_cast<uint32_t>(irq);
                volatile uint32_t* iser = reinterpret_cast<volatile uint32_t*>(
                    0xE000E100u + (u >> 5u) * 4u);
                *iser = 1u << (u & 31u);
            };
// ⚠════════════════════════════════════════════════════════
// [외부업체 필수 확인] IRQ 번호 교체 필요 — 양산 사용 금지
//
// STM32F407 RM0090 벡터 테이블:
//   TIM2=28, TIM3=29, TIM4=30, TIM5=50
//   DMA1_Stream0=11 ~ DMA1_Stream7=47
//   DMA2_Stream0=56 ~ DMA2_Stream7=70
//   SPI1=35, SPI2=36, SPI3=51
//   USART1=37, USART2=38, USART3=39
//
// ※ IPC_Protocol이 DMA2_Stream0(56번)을 SPI1 RX로 사용 중.
//   Tx 스케줄러 DMA는 반드시 다른 Stream 번호로 설정하세요.
// ⚠════════════════════════════════════════════════════════
            NVIC_SetPriority(TIM_IRQn, 2u);   // Tx 심볼 타이머 — 높은 우선순위
// ⚠════════════════════════════════════════════════════════
// [외부업체 필수 확인] IRQ 번호 교체 필요 — 양산 사용 금지
//
// STM32F407 RM0090 벡터 테이블:
//   TIM2=28, TIM3=29, TIM4=30, TIM5=50
//   DMA1_Stream0=11 ~ DMA1_Stream7=47
//   DMA2_Stream0=56 ~ DMA2_Stream7=70
//   SPI1=35, SPI2=36, SPI3=51
//   USART1=37, USART2=38, USART3=39
//
// ※ IPC_Protocol이 DMA2_Stream0(56번)을 SPI1 RX로 사용 중.
//   Tx 스케줄러 DMA는 반드시 다른 Stream 번호로 설정하세요.
// ⚠════════════════════════════════════════════════════════
            NVIC_SetPriority(DMA_IRQn, 3u);   // Tx DMA 완료 — Tx 타이머 다음
            NVIC_EnableIRQ(TIM_IRQn);
            NVIC_EnableIRQ(DMA_IRQn);
        }

        const uintptr_t sb_raw = reinterpret_cast<uintptr_t>(&__stack_bottom__);
        const uint32_t stack_bot = (sb_raw != 0u)
            ? static_cast<uint32_t>(sb_raw)
            : 0x2001C000u;
        Hardware_Init_Manager::Initialize_MPU(stack_bot);

        // ── DWT CYCCNT 활성화 (Cortex-M3/M4/M7 공통) ────────────────
        //  레지스터 주소: ARM CoreSight 아키텍처 표준
        //  DEMCR   : 0xE000EDFC (bit24 = TRCENA)
        //  DWT_CTRL: 0xE0001000 (bit0 = CYCCNTENA)
        //  DWT_CYCCNT: 0xE0001004 (32-bit cycle counter)
        //
        // J-3: HW 레지스터 주소·비트 constexpr 상수화
        static constexpr uintptr_t ADDR_DEMCR = 0xE000EDFCu;  ///< Debug Exception & Monitor Control
        static constexpr uintptr_t ADDR_DWT_CTRL = 0xE0001000u;  ///< DWT Control Register
        static constexpr uintptr_t ADDR_DWT_CYCCNT = 0xE0001004u;  ///< DWT Cycle Count Register
        static constexpr uint32_t  DEMCR_TRCENA = (1u << 24);   ///< Trace Enable bit
        static constexpr uint32_t  DWT_CYCCNTENA = (1u << 0);    ///< Cycle Counter Enable bit

        volatile uint32_t* DEMCR = reinterpret_cast<volatile uint32_t*>(ADDR_DEMCR);
        volatile uint32_t* DWT_CTRL = reinterpret_cast<volatile uint32_t*>(ADDR_DWT_CTRL);
        volatile uint32_t* DWT_CYCCNT = reinterpret_cast<volatile uint32_t*>(ADDR_DWT_CYCCNT);

        *DEMCR |= DEMCR_TRCENA;    // TRCENA 활성화
        *DWT_CYCCNT = 0u;           // 카운터 리셋
        *DWT_CTRL |= DWT_CYCCNTENA; // CYCCNTENA 활성화
        HW_ISB();                    // 설정 즉시 반영 보장
#endif
        // PC (Windows/Linux/Mac): no-op
    }

    // =====================================================================
    //  Initialize_MPU — STM32F407 MPU 8개 리전 (K-1, R-11)
    //
    //  Region 5·1 중복(0x20000000): 번호 큰 리전 우선 → 하위 4KB는 Region 5
    //    Region 5: Strongly-ordered 분리(TEX=0,S=1,C=0,B=0) — Region 1 Normal WB와 구분
    //  Region 4: 스택 가드 SIZE=7(256B) — 예외 8워드 push(32B) 한 번에 가드 우회 방지
    //  Region 7: 원안 512MB는 Flash(0x08000000)와 중첩 위험 → SIZE=26(128MB)로
    //            [0, 0x08000000)만 No Access (저주소/널 가드, Flash 제외)
    // =====================================================================
    void Hardware_Init_Manager::Initialize_MPU(uint32_t stack_bottom_addr) noexcept {
#ifdef HTS_TARGET_ARM_BAREMETAL
        volatile uint32_t* const MPU_CTRL = reinterpret_cast<volatile uint32_t*>(
            static_cast<uintptr_t>(MPU_CTRL_ADDR));
        volatile uint32_t* const MPU_RNR = reinterpret_cast<volatile uint32_t*>(
            static_cast<uintptr_t>(MPU_RNR_ADDR));
        volatile uint32_t* const MPU_RBAR = reinterpret_cast<volatile uint32_t*>(
            static_cast<uintptr_t>(MPU_RBAR_ADDR));
        volatile uint32_t* const MPU_RASR = reinterpret_cast<volatile uint32_t*>(
            static_cast<uintptr_t>(MPU_RASR_ADDR));

        *MPU_CTRL = 0u;
        HW_BARRIER();

        // Region 0: Flash — RO Both, XN=0, 1MB
        *MPU_RNR = 0u;
        *MPU_RBAR = 0x08000000u;
        *MPU_RASR = static_cast<uint32_t>(
            (0u << 28) | (6u << 24) | (0u << 19) | (1u << 17) | (1u << 16)
            | (19u << 1) | (1u));

        // Region 1: SRAM1+2 — RW Both, XN=1, 128KB
        *MPU_RNR = 1u;
        *MPU_RBAR = 0x20000000u;
        *MPU_RASR = static_cast<uint32_t>(
            (1u << 28) | (3u << 24) | (0u << 19) | (1u << 17) | (1u << 16)
            | (16u << 1) | (1u));

        // Region 2: CCM — RW Both, XN=1, 64KB
        *MPU_RNR = 2u;
        *MPU_RBAR = 0x10000000u;
        *MPU_RASR = static_cast<uint32_t>(
            (1u << 28) | (3u << 24) | (0u << 19) | (1u << 17) | (1u << 16)
            | (15u << 1) | (1u));

        // Region 3: APB/AHB — RW Priv only, XN=1, 512MB, device (C=0,B=0)
        *MPU_RNR = 3u;
        *MPU_RBAR = 0x40000000u;
        *MPU_RASR = static_cast<uint32_t>(
            (1u << 28) | (1u << 24) | (0u << 19) | (0u << 18) | (0u << 17)
            | (0u << 16) | (28u << 1) | (1u));

        // Region 4: 스택 가드 256B — No Access, XN=1, SIZE=7 (예외 진입 32B push 대비)
        const uint32_t guard_base =
            (stack_bottom_addr + 255u) & ~static_cast<uint32_t>(255u);
        *MPU_RNR = 4u;
        *MPU_RBAR = guard_base;
        *MPU_RASR = static_cast<uint32_t>(
            (1u << 28) | (0u << 24) | (7u << 1) | (1u));

        // Region 5: DMA 버퍼 4KB @ SRAM 선두 — RW Both, XN=1
        //   TEX=0,S=1,C=0,B=0 → Shareable Device (Region 1 Normal WBWA와 속성 분리)
        *MPU_RNR = 5u;
        *MPU_RBAR = 0x20000000u;
        *MPU_RASR = static_cast<uint32_t>(
            (1u << 28) | (3u << 24) | (0u << 19) | (1u << 18) | (0u << 17)
            | (0u << 16) | (11u << 1) | (1u));

        // Region 6: CoreSight/시스템 — RO Priv, XN=1, 256MB
        *MPU_RNR = 6u;
        *MPU_RBAR = 0xE0000000u;
        *MPU_RASR = static_cast<uint32_t>(
            (1u << 28) | (5u << 24) | (0u << 19) | (0u << 17) | (0u << 16)
            | (27u << 1) | (1u));

        // Region 7: 저주소 No Access — SIZE=26(128MB): Flash 시작 미포함
        *MPU_RNR = 7u;
        *MPU_RBAR = 0x00000000u;
        *MPU_RASR = static_cast<uint32_t>(
            (1u << 28) | (0u << 24) | (26u << 1) | (1u));

        HW_BARRIER();
        *MPU_CTRL = MPU_CTRL_FULL;
        HW_ISB();
#else
        (void)stack_bottom_addr;
#endif
    }

    // =====================================================================
    //  Kick_Watchdog — WDT 타이머 피드
    //
    //  [호출 주기] 메인 루프 1사이클당 1회 (WDT 타임아웃 이내)
    //  [ARM] WDT_FEED_REG에 매직 값(0xAA55) 쓰기
    //        → WDT 카운터 리셋 → 타임아웃 방지
    //  [주의] ISR 내부에서는 호출하지 않음 (ISR hang → WDT 리셋 = 의도된 동작)
    // =====================================================================
    void Hardware_Init_Manager::Kick_Watchdog() noexcept {
#ifdef HTS_TARGET_ARM_BAREMETAL
        //
        //  위협: 공격적 최적화(-O3/LTO)가 volatile 쓰기를 LICM로 루프 외부 이동
        //        또는 연속 호출 시 중간 쓰기를 DSE로 제거할 가능성
        //        → WDT 타임아웃 → 무한 리셋 루프 → 시스템 영구 불능
        //
        //  방어 1: volatile 포인터 → C++ 표준 관찰가능 부수효과 (DSE 금지)
        //  방어 2: HW_BARRIER (dmb sy + "memory" 클로버) → LICM 차단
        //  방어 3: asm 직접 STR → 컴파일러 코드 생성 완전 우회
        //
        //  [J-3] 매직넘버 constexpr 상수화
        static constexpr uint32_t WDT_FEED_VALUE = 0xAA55u;

        HW_BARRIER();
        // [방어 3] asm 직접 STR: 컴파일러 최적화 경로 완전 우회
        //  volatile 쓰기를 compiler에 위임하지 않고, 기계어 직접 발행
        //  → -O3, LTO, PGO 어떤 조합에서도 이 STR 명령어 제거 불가
        __asm__ __volatile__(
            "str %1, [%0]"
            :
        : "r"(static_cast<uintptr_t>(WDT_FEED_REG)),
            "r"(WDT_FEED_VALUE)
            : "memory"
            );
        HW_BARRIER();
#endif
    }

    // =====================================================================
    //  Cache_Clean_Tx — DMA TX 전 CPU→RAM 메모리 배리어
    //
    //  [Cortex-M4] I/D 캐시 없음 → DMB만으로 DMA 일관성 보장
    //  [Cortex-M7 마이그레이션 시]
    //    SCB_CleanDCache_by_Addr(buffer, length * sizeof(uint32_t)) 추가 필요
    // =====================================================================
    void Hardware_Init_Manager::Cache_Clean_Tx(
        uint32_t* buffer, size_t length) noexcept {
        (void)buffer; (void)length;
#ifdef HTS_TARGET_ARM_BAREMETAL
        HW_BARRIER();
#endif
    }

    // =====================================================================
    //  Cache_Invalidate_Rx — DMA RX 후 RAM→CPU 메모리 배리어
    //
    //  [Cortex-M4] DMB + ISB: DMA 쓰기 완료 후 CPU가 새 데이터를 읽도록 보장
    //  [Cortex-M7 마이그레이션 시]
    //    SCB_InvalidateDCache_by_Addr(buffer, length * sizeof(int16_t)) 추가 필요
    // =====================================================================
    void Hardware_Init_Manager::Cache_Invalidate_Rx(
        volatile int16_t* buffer, size_t length) noexcept {
        (void)buffer; (void)length;
#ifdef HTS_TARGET_ARM_BAREMETAL
        HW_BARRIER();
        HW_ISB();
#endif
    }

    // =====================================================================
    //  Cache_Invalidate_Tx — TX ISR에서 FIFO 읽기 전 메모리 배리어
    // =====================================================================
    void Hardware_Init_Manager::Cache_Invalidate_Tx(
        volatile int16_t* buffer, size_t length) noexcept {
        (void)buffer; (void)length;
#ifdef HTS_TARGET_ARM_BAREMETAL
        HW_BARRIER();
        HW_ISB();
#endif
    }

} // namespace ProtectedEngine

// =====================================================================
//  UART Retargeting — ARM 베어메탈 전용
//
//  newlib/newlib-nano의 printf → fputc 리타겟팅
//  PC(Windows/Linux/Mac)에서는 이 함수가 컴파일되지 않음
//  → printf/std::cout이 정상적으로 콘솔에 출력
//
//  [EMCON 모드] HTS_MILITARY_GRADE_EW 정의 시
//    모든 UART 출력을 물리적으로 묵살 (Zero-Emission)
//    → 적군의 전파 방향 탐지(DF) 차단
//    → SecureLogger ARM 출력도 이 경로로 묵살됨
//
//  [타임아웃] UART TX FIFO Full 시 100000회 폴링 후 포기
//    → UART 컨트롤러 고장 시 메인 코어 무한 대기 방지
// =====================================================================
#ifdef HTS_TARGET_ARM_BAREMETAL
extern "C" int fputc(int ch, FILE* f) {
    (void)f;

#ifdef HTS_MILITARY_GRADE_EW
    // EMCON 스텔스: 모든 I/O 출력 물리적 묵살 (Zero-Emission)
    return ch;
#else
    volatile uint32_t* uart_tx = reinterpret_cast<volatile uint32_t*>(
        static_cast<uintptr_t>(ProtectedEngine::UART0_TX_REG));
    volatile uint32_t* uart_fr = reinterpret_cast<volatile uint32_t*>(
        static_cast<uintptr_t>(ProtectedEngine::UART0_FR_REG));

    // TX FIFO Full 폴링 + 타임아웃
    static constexpr uint32_t UART_TX_TIMEOUT = 100000u;
    uint32_t timeout = UART_TX_TIMEOUT;
    while (((*uart_fr) & ProtectedEngine::UART_TXFF) != 0u) {
        if (--timeout == 0u) return ch;
        __asm__ __volatile__("nop");
    }

    *uart_tx = static_cast<uint32_t>(ch);
    return ch;
#endif
}
#endif

#ifdef HTS_TARGET_ARM_BAREMETAL
#if defined(__GNUC__) || defined(__clang__)
extern "C" __attribute__((weak)) void MemManage_Handler(void)
#else
extern "C" void MemManage_Handler(void)
#endif
{
    HTS_Fault_Reset_Wait();
}

#if defined(__GNUC__) || defined(__clang__)
extern "C" __attribute__((weak)) void HardFault_Handler(void)
#else
extern "C" void HardFault_Handler(void)
#endif
{
    HTS_Fault_Reset_Wait();
}

#if defined(__GNUC__) || defined(__clang__)
extern "C" __attribute__((weak)) void BusFault_Handler(void)
#else
extern "C" void BusFault_Handler(void)
#endif
{
    HTS_Fault_Reset_Wait();
}

#if defined(__GNUC__) || defined(__clang__)
extern "C" __attribute__((weak)) void UsageFault_Handler(void)
#else
extern "C" void UsageFault_Handler(void)
#endif
{
    HTS_Fault_Reset_Wait();
}
#endif

// =====================================================================
//  매크로 클린업 (다른 번역 단위로 누출 방지)
// =====================================================================
#undef HW_BARRIER
#undef HW_ISB
