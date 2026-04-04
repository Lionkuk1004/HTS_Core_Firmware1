// =========================================================================
// HTS_Anti_Debug.cpp
// 디버거/JTAG 연결 탐지 및 강제 시스템 정지 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
//
#include "HTS_Anti_Debug.h"
#include "HTS_Auto_Rollback_Manager.hpp"
#include "HTS_Secure_Logger.h"

// ── 플랫폼: ARM 전용 (MSVC 개발 빌드 예외 허용) ──────────────────────
#if !defined(__arm__) && !defined(__TARGET_ARCH_ARM) && \
    !defined(__TARGET_ARCH_THUMB) && !defined(__ARM_ARCH) && !defined(_MSC_VER)
#error "[HTS_FATAL] HTS_Anti_Debug.cpp는 ARM 전용입니다."
#endif

namespace ProtectedEngine {

    // 힐 코드: 0xDEAD0DB6u (16진수 유효 문자만)
    static constexpr uint32_t k_HEAL_CODE_DEBUG = 0xDEAD0DB6u;

    // =====================================================================
    //  forceHalt — 궁극의 안티포렌식 자가 파괴
    //
    //
    //  순서: 로깅·Self_Healing(인터럽트 허용) → cpsid i → DBGMCU → AIRCR
    //  (먼저 인터럽트를 끄면 로깅/힐링 경로가 막히지 않도록)
    //
    //  로깅 구간은 짧고, 이후 cpsid i로 전환·리셋까지 고정 지연.
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
            *dbgmcu &= ~(DBGMCU_WWDG_STOP | DBGMCU_IWDG_STOP);
            __asm__ __volatile__("dsb sy\n\t" "isb\n\t" ::: "memory");
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
            //  GCC/Clang: lr(r14)는 프롤로그/에필로그 관리 레지스터
            //  클로버 선언 시 Register Allocator 충돌 → 빌드 에러/기형 코드
            : "r2", "r3", "r4", "r5", "r6", "r7",
            "r8", "r9", "r10", "r11", "r12", "memory"
        );
#endif

        // 도달 불가 — [[noreturn]] 경고 방지
        while (true) {}
    }

    [[noreturn]] void AntiDebugManager::trustedHalt(const char* message) noexcept {
        forceHalt(message ? message : "TRUSTED_HALT");
    }

    // =====================================================================
    //  pollHardwareOrFault — SysTick/스케줄러 등 주기 경로 (DHCSR + DBGMCU_CR)
    // =====================================================================
    void AntiDebugManager::pollHardwareOrFault() noexcept {

#if defined(HTS_ALLOW_OPEN_DEBUG)
        return;
#endif

#if (defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)) && \
    (defined(__GNUC__) || defined(__clang__))
        volatile const uint32_t* const dhcsr =
            reinterpret_cast<volatile const uint32_t*>(ADDR_DHCSR);
        volatile const uint32_t* const dbgcr =
            reinterpret_cast<volatile const uint32_t*>(ADDR_DBGMCU_CR);
        const uint32_t v = *dhcsr;
        const uint32_t cr = *dbgcr;
        if ((v & DHCSR_DEBUG_MASK) != 0u) {
            SecureLogger_WipeRingAndFault();
        }
        if ((cr & DBGMCU_CR_DEBUG_MASK) != 0u) {
            SecureLogger_WipeRingAndFault();
        }
#endif
    }

    // =====================================================================
    //  checkDebuggerPresence — 플랫폼별 디버거 탐지
    // =====================================================================
    void AntiDebugManager::checkDebuggerPresence() noexcept {

#if defined(HTS_ALLOW_OPEN_DEBUG)
        return;
#endif

#if defined(__GNUC__) || defined(__clang__)
        // ARM: DHCSR 레지스터 직접 검사
        volatile const uint32_t* const dhcsr =
            reinterpret_cast<volatile const uint32_t*>(ADDR_DHCSR);
        const uint32_t val = *dhcsr;

        // [교차검수 패치] "Attach 탐지"와 구현 정합
        //  구현은 Halt 동반시에만 탐지되어 Attach(실행중 디버그) 우회 가능.
        //  오탐 방어를 위해 2회 샘플 모두 C_DEBUGEN=1일 때만 Attach로 판정.
        const bool c_debugen_1 = (val & DHCSR_C_DEBUGEN) != 0u;
        const bool halted_1 = (val & (DHCSR_C_HALT | DHCSR_S_HALT)) != 0u;
        const uint32_t val2 = *dhcsr;
        const bool c_debugen_2 = (val2 & DHCSR_C_DEBUGEN) != 0u;
        const bool halted_2 = (val2 & (DHCSR_C_HALT | DHCSR_S_HALT)) != 0u;
        const bool attached_confirmed = c_debugen_1 && c_debugen_2;
        const bool halted_confirmed = (halted_1 && c_debugen_1) || (halted_2 && c_debugen_2);

        if (attached_confirmed || halted_confirmed) {
            forceHalt(
                "SECURITY ALERT: JTAG/SWD Debugger"
                " (Halt or Attach) detected!");
        }
#endif
    }

} // namespace ProtectedEngine
