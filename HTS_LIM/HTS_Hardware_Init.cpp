// =========================================================================
// HTS_Hardware_Init.cpp
// 하드웨어 초기화 매니저 구현부
// Target: STM32F407 (Cortex-M4)
//
// [양산 수정 — 4건 결함 교정]
//
//  BUG-01 [MEDIUM] 레지스터 주소 선언 이중화
//    기존: .cpp 내부 constexpr + fputc에서 ProtectedEngine:: 접근
//          → 헤더에 선언이 없어 다른 모듈에서 접근 불가
//          → fputc (extern "C")가 namespace 상수에 의존하는 불투명 구조
//    수정: 레지스터 주소를 헤더로 이동 (ARM 가드 내부)
//          → fputc에서 ProtectedEngine:: 접근 투명
//          → 다른 모듈(SecureLogger UART 직접 출력 등)에서도 사용 가능
//
//  BUG-02 [LOW] Cache 함수가 DMA 배리어만 수행하나 명칭이 "Cache"
//    STM32F407 (Cortex-M4)에는 I/D 캐시 없음
//    수정: 함수명 변경 없이 (API 호환) 주석 보강
//
//  BUG-03 [LOW] AMI 커스텀 레지스터 vs STM32 표준 구분 미문서화
//    수정: 헤더 + .cpp에 파트너사 교체 가이드 추가
//
//  BUG-04 [LOW] fputc EMCON 모드 의도 미문서화
//    수정: HTS_MILITARY_GRADE_EW 정의 시 모든 UART 출력 묵살 = Zero-Emission
//
// [기존 설계 100% 보존]
//  - 3단 플랫폼 분기 (ARM/Windows/Linux)
//  - WDT 활성화 + DWT CYCCNT 활성화
//  - DMB/ISB DMA 배리어
//  - UART fputc 리타겟팅 + 타임아웃
//  - EMCON 스텔스 모드
//  - 매크로 클린업
// =========================================================================
#include "HTS_Hardware_Init.h"
#include <cstdio>

// =========================================================================
//  플랫폼 감지
// =========================================================================
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#define HTS_TARGET_ARM_BAREMETAL
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
    //  Initialize_System — WDT + DWT CYCCNT 활성화
    //
    //  [호출 시점] main() 진입 직후, POST 이전
    //  [ARM 동작]
    //    1. WDT 활성화: WDT_CTRL_REG에 0x01 쓰기
    //       → 이후 주기적으로 Kick_Watchdog() 미호출 시 하드웨어 리셋
    //    2. DWT CYCCNT 활성화:
    //       DEMCR TRCENA(bit24) → DWT_CTRL CYCCNTENA(bit0) → 카운터 리셋
    //       → Hardware_Bridge::Get_Physical_CPU_Tick() 사용 가능
    //  [PC 동작] no-op (시뮬레이션 환경)
    // =====================================================================
    void Hardware_Init_Manager::Initialize_System() noexcept {
#ifdef HTS_TARGET_ARM_BAREMETAL
        // ── WDT 활성화 ──────────────────────────────────────────────
        volatile uint32_t* wdt_ctrl = reinterpret_cast<volatile uint32_t*>(
            static_cast<uintptr_t>(WDT_CTRL_REG));
        HW_BARRIER();
        *wdt_ctrl = 0x01u;
        HW_ISB();

        // ── DWT CYCCNT 활성화 (Cortex-M3/M4/M7 공통) ────────────────
        //  레지스터 주소: ARM CoreSight 아키텍처 표준
        //  DEMCR   : 0xE000EDFC (bit24 = TRCENA)
        //  DWT_CTRL: 0xE0001000 (bit0 = CYCCNTENA)
        //  DWT_CYCCNT: 0xE0001004 (32-bit cycle counter)
        volatile uint32_t* DEMCR = reinterpret_cast<volatile uint32_t*>(0xE000EDFCu);
        volatile uint32_t* DWT_CTRL = reinterpret_cast<volatile uint32_t*>(0xE0001000u);
        volatile uint32_t* DWT_CYCCNT = reinterpret_cast<volatile uint32_t*>(0xE0001004u);

        *DEMCR |= (1u << 24);   // TRCENA 활성화
        *DWT_CYCCNT = 0;        // 카운터 리셋
        *DWT_CTRL |= (1u << 0); // CYCCNTENA 활성화
        HW_ISB();                // 설정 즉시 반영 보장
#endif
        // PC (Windows/Linux/Mac): no-op
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
        volatile uint32_t* wdt_feed = reinterpret_cast<volatile uint32_t*>(
            static_cast<uintptr_t>(WDT_FEED_REG));
        HW_BARRIER();
        *wdt_feed = 0xAA55u;
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
    // [BUG-06] 매직넘버 → constexpr 상수
    static constexpr uint32_t UART_TX_TIMEOUT = 100000u;
    uint32_t timeout = UART_TX_TIMEOUT;
    while (((*uart_fr) & ProtectedEngine::UART_TXFF) != 0) {
        if (--timeout == 0) return ch;
        __asm__ __volatile__("nop");
    }

    *uart_tx = static_cast<uint32_t>(ch);
    return ch;
#endif
}
#endif

// =====================================================================
//  매크로 클린업 (다른 번역 단위로 누출 방지)
// =====================================================================
#undef HW_BARRIER
#undef HW_ISB