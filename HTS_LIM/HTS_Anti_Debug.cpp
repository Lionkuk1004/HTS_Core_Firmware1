// =========================================================================
// HTS_Anti_Debug.cpp
// 디버거/JTAG 연결 탐지 및 강제 시스템 정지 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// [양산 수정 — 26건]
//
//  ── 기존 (2건) ──
//  - 3단 플랫폼 분기, ARM DHCSR 탐지
//
//  ── 세션 5 (BUG-01 ~ BUG-12) ──
//  BUG-01 [CRIT] forceHalt abort → 자가 치유 + 무한 루프
//  BUG-02 [HIGH] 인스턴스화 차단
//  BUG-03 [MED]  SecureLogger 호출
//  BUG-04 [LOW]  Doxygen
//  BUG-05 [LOW]  DHCSR const
//  BUG-06 [CRIT] cpsid i 인터럽트 차단
//  BUG-07 [CRIT] DHCSR 다중 비트 교차 검증
//  BUG-08 [HIGH] Linux TracerPid 직접 파싱
//  BUG-09 [CRIT] DBGMCU WDT 프리즈 방지 + 레지스터 분쇄 + AIRCR 리셋
//  BUG-10 [CRIT] #if 전처리 스코프 정밀 교정
//  BUG-11 [CRIT] ldr pseudo-instruction → C++ 입력 파라미터 전달
//  BUG-12 [CRIT] 레지스터 분쇄 vs AIRCR 입력 파라미터 충돌
//
//  ── 세션 8 전수검사 (BUG-13 ~ BUG-21) ──
//  BUG-13 [CRIT] Linux std::ifstream/std::string 힙 할당 → POSIX read
//  BUG-14 [HIGH] 스택 버퍼 크기 미제한 → char[256] 고정
//  BUG-15 [CRIT] try-catch → 조건문 (-fno-exceptions 준수)
//  BUG-16 [MED]  DHCSR 비트 매직 넘버 → constexpr 상수화
//  BUG-17 [MED]  MMIO 주소 매직 넘버 → constexpr 상수화
//  BUG-18 [LOW]  TracerPid 파싱 오버플로 방어
//  BUG-19 [MED]  static_assert 빌드타임 검증 추가
//  BUG-20 [LOW]  주석 건수 불일치 (14→21)
//  BUG-21 [CRIT] cpsid i ↔ SecureLogger 데드락 (Phase 순서 재배치)
//
//  ── 세션 10+ (BUG-22 ~ BUG-24) ──
//  BUG-22 [HIGH] ⑭ HTS_PLATFORM_ARM_BAREMETAL → HTS_PLATFORM_ARM 통일
//                PC 전용 헤더(<iostream>/<cstdlib>) #ifndef 가드
//  BUG-23 [MED]  D-2: Linux buf[256] SecWipe 누락 → 전 반환경로 소거
//  BUG-24 [LOW]  J-3: 0xDEAD0DBGu → k_HEAL_CODE_DEBUG constexpr
//
// [제약] float 0, double 0, try-catch 0, 힙 0 (ARM 경로)
// =========================================================================
#include "HTS_Anti_Debug.h"
#include "HTS_Auto_Rollback_Manager.hpp"
#include "HTS_Secure_Logger.h"

// ── 플랫폼: ARM 전용 (MSVC 개발 빌드 예외 허용) ──────────────────────
#if !defined(__arm__) && !defined(__TARGET_ARCH_ARM) && \
    !defined(__TARGET_ARCH_THUMB) && !defined(__ARM_ARCH) && !defined(_MSC_VER)
#error "[HTS_FATAL] HTS_Anti_Debug.cpp는 ARM 전용입니다."
#endif

namespace ProtectedEngine {

    // [BUG-24] 자가 치유 트리거 코드 (J-3)
    // 원래 의도: 0xDEAD_DEBUG → 'G'는 16진수 아님
    // 수정: 0xDEAD0DB6u (DEAD + 0xDB6 = 3510)
    static constexpr uint32_t k_HEAL_CODE_DEBUG = 0xDEAD0DB6u;

    // =====================================================================
    //  forceHalt — 궁극의 안티포렌식 자가 파괴
    //
    //  [BUG-21 수정] Phase 실행 순서 재배치!
    //
    //  [기존 순서 — 데드락!]
    //    Phase 1: cpsid i (인터럽트 차단)
    //    Phase 2: DBGMCU WDT
    //    Phase 3: SecureLogger + Self_Healing ← 인터럽트 필요! → 데드락!
    //    Phase 4: AIRCR 리셋 ← 영원히 도달 불가!
    //
    //  [수정 순서 — 데드락 해소]
    //    Phase 1: SecureLogger + Self_Healing (인터럽트 살아있는 상태)
    //    Phase 2: cpsid i (로깅 완료 후 인터럽트 전면 차단)
    //    Phase 3: DBGMCU WDT 프리즈 해제
    //    Phase 4: AIRCR 리셋 → 레지스터 분쇄 → MSP/PSP 파괴
    //
    //  [보안 분석]
    //    Phase 1에서 로깅하는 수 ms 동안 해커가 SRAM을 덤프할 수 있으나,
    //    이 시점에는 아직 forceHalt 진입 직전이므로 정상 실행 중과 동일.
    //    로깅 완료 즉시 cpsid i → AIRCR까지 수 사이클 이내 도달 보장.
    //    기존 설계는 Phase 4에 영원히 도달 못해 SRAM이 무한 노출되므로
    //    수정 후가 보안상 압도적으로 우수함.
    // =====================================================================
    [[noreturn]] void AntiDebugManager::forceHalt(
        const char* message) noexcept {

        // ── Phase 1: 감사 로그 + 키/플래시 소거 ─────────────────────
        SecureLogger::logSecurityEvent(
            "ANTI_DEBUG_HALT",
            message ? message : "UNKNOWN");

        Auto_Rollback_Manager::Execute_Self_Healing(
            k_HEAL_CODE_DEBUG);

        // ── Phase 2: 글로벌 인터럽트 즉시 차단 ──────────────────────
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("cpsid i" : : : "memory");
#endif

        // ── Phase 3: DBGMCU WDT 프리즈 강제 해제 ────────────────────
#if defined(__GNUC__) || defined(__clang__)
        {
            volatile uint32_t* const dbgmcu =
                reinterpret_cast<volatile uint32_t*>(ADDR_DBGMCU_FZ);
            *dbgmcu &= ~(DBGMCU_IWDG_STOP | DBGMCU_WWDG_STOP);
        }
#endif

        // ── Phase 4: 궁극의 자가 파괴 (순수 어셈블리) ────────────────
#if defined(__GNUC__) || defined(__clang__)
        register uint32_t aircr_addr __asm__("r0") = ADDR_AIRCR;
        register uint32_t aircr_val  __asm__("r1") = AIRCR_RESET_CMD;

        __asm__ __volatile__(
            // 4-1. AIRCR SYSRESETREQ 직접 타격
            "str r1, [r0]        \n\t"

            // 4-2. 메모리 배리어
            "dsb                 \n\t"
            "isb                 \n\t"

            // 4-3. 레지스터 분쇄 (리셋 진행 중 보호)
            "mov r0, #0          \n\t"
            "mov r1, #0          \n\t"
            "mov r2, #0          \n\t"
            "mov r3, #0          \n\t"
            "mov r4, #0          \n\t"
            "mov r5, #0          \n\t"
            "mov r6, #0          \n\t"
            "mov r7, #0          \n\t"
            "mov r8, #0          \n\t"
            "mov r9, #0          \n\t"
            "mov r10, #0         \n\t"
            "mov r11, #0         \n\t"
            "mov r12, #0         \n\t"
            "mov lr, #0          \n\t"

            // 4-4. MSP/PSP 파괴
            "msr msp, r0         \n\t"
            "msr psp, r0         \n\t"

            // 4-5. 무한 루프
            "1: b 1b             \n\t"
            : "+r"(aircr_addr), "+r"(aircr_val)
            :
            : "r2", "r3", "r4", "r5", "r6", "r7",
            "r8", "r9", "r10", "r11", "r12", "lr", "memory"
        );
#endif

        // 도달 불가 — [[noreturn]] 경고 방지
        while (true) {}
    }

    // =====================================================================
    //  checkDebuggerPresence — 플랫폼별 디버거 탐지
    // =====================================================================
    void AntiDebugManager::checkDebuggerPresence() noexcept {

#if defined(__GNUC__) || defined(__clang__)
        // ARM: DHCSR 레지스터 직접 검사
        volatile const uint32_t* const dhcsr =
            reinterpret_cast<volatile const uint32_t*>(ADDR_DHCSR);
        const uint32_t val = *dhcsr;

        if (val & DHCSR_DEBUG_MASK) {
            forceHalt(
                "SECURITY ALERT: JTAG/SWD Debugger"
                " (Halt or Attach) detected!");
        }
#endif
    }

} // namespace ProtectedEngine