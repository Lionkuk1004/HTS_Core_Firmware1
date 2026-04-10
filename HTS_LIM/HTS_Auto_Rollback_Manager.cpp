// =========================================================================
// HTS_Auto_Rollback_Manager.cpp
// 치명적 변조 감지 시 자가 치유(Self-Healing) 트리거 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
//
#include "HTS_Auto_Rollback_Manager.hpp"
#include "HTS_Secure_Logger.h"
// [NOTE] HTS_Secure_Memory.h — 직접 호출 없음 (호출자 소거 책임 원칙)
//  각 보안 모듈이 Execute_Self_Healing 호출 전에 자체 secureWipe 수행
#include <atomic>
#include <cstdint>

namespace ProtectedEngine {

    // =====================================================================
    //  Execute_Self_Healing — 최후의 중앙 집중식 사형 집행인
    //
    //
    //  [아키텍처 원칙] 제로 트러스트 (Zero-Trust)
    //   이 함수는 로그 + 소거 + 하드웨어 리셋을 모두 책임지는 단일 집행점.
    //   모든 보안 모듈(Anti_Glitch, AntiAnalysis, FEC 등)은
    //   이 함수를 호출하면 시스템이 반드시 죽는다고 신뢰(Trust).
    //
    //  [Anti_Debug 호출 순서 가이드]
    //   Anti_Debug는 DBGMCU 프리즈 해제 + 레지스터 파쇄 + MSP/PSP 파괴를
    //   Execute_Self_Healing 호출 "전에" 완료해야 함.
    //   (본 함수 호출 후에는 어떤 코드도 실행되지 않음)
    // =====================================================================
    [[noreturn]] void Auto_Rollback_Manager::Execute_Self_Healing(
        uint32_t session_id) noexcept {

        // ── Phase 1: 감사 로그 기록 ──
        char msg_buf[80] = {};
        static_assert(sizeof(msg_buf) >= (10u + 8u + 1u),
            "msg_buf too small for HALT id log");
        {
            const char* prefix = "HALT id=0x";
            int pos = 0;
            while (prefix[pos]
                && pos < static_cast<int>(sizeof(msg_buf) - 1u)) {
                msg_buf[pos] = prefix[pos];
                ++pos;
            }
            for (int d = 7; d >= 0; --d) {
                if (pos >= static_cast<int>(sizeof(msg_buf) - 1u)) { break; }
                const uint32_t nibble = (session_id >> (d * 4u)) & 0xFu;
                msg_buf[pos++] = static_cast<char>(
                    nibble < 10u ? ('0' + nibble) : ('A' + nibble - 10u));
            }
            msg_buf[pos] = '\0';
        }
        SecureLogger::logSecurityEvent(
            "SELF_HEALING", msg_buf);

        // 로그 I/O 완료 후 하드웨어 리셋 경로로만 진행 (LTO 재배치 억제)
        std::atomic_thread_fence(std::memory_order_release);
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" ::: "memory");
#endif

        // ── Phase 2: 보안 메모리 소거 지침 ──
        //
        //  SecureMemory API: secureWipe(void* ptr, size_t size) — 특정 버퍼 소거
        //  전역 Wipe_All() 은 존재하지 않음 (버퍼별 개별 소거 설계)
        //
        //  [아키텍처] 호출자 소거 책임 원칙:
        //   각 보안 모듈은 자신이 관리하는 키/세션 버퍼를
        //   Execute_Self_Healing 호출 "전에" secureWipe로 소거해야 함.
        //   예: Anti_Debug   → 세션 키 wipe → 레지스터 파쇄 → 이 함수 호출
        //       Key_Rotator  → 마스터 키 wipe → 이 함수 호출
        //       Entropy_Arrow → PRNG 상태 wipe → 이 함수 호출
        //
        //  이 함수 내부에서는 개별 버퍼 주소를 알 수 없으므로
        //  직접 소거하지 않음. (의존성 역전 위반 방지)

        // ── Phase 3: 시스템 즉사 — 플랫폼별 최적 경로 ──
        //
        //  Cortex-M4: cpsid i → AIRCR SYSRESETREQ (하드웨어 리셋)
        //  A55 Linux: __builtin_trap() → SIGILL → OS 프로세스 즉시 회수
        //   ※ while(true) 금지: watchdog 대기 수 초 → /proc/mem 덤프 취약
        //  PC 빌드:  무한 루프 (디버거 부착 상태 유지)

#if (defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
     defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)) \
    && !defined(__aarch64__)
        // STM32/Cortex-M4: 인터럽트 비활성 → SCB->AIRCR(SYSRESETREQ) 선기입 →
        //  이후 DBGMCU_APB1_FZ(워치독 프리즈 해제). ARM 코어 응용 노트 순서 준수.
        //  ※ SWD/JTAG 영구 차단은 옵션 바이트 RDP(부팅/키 프로비저닝) 영역.
        //     DBGMCU 해제는 리셋 진행과 병행 가능한 보조 경로(사양 순서 고정).
        static constexpr uintptr_t AIRCR_ADDR = 0xE000ED0Cu;
        static constexpr uintptr_t DBGMCU_APB1_FZ_ADDR = 0xE0042008u;
        static constexpr uint32_t  DBGMCU_WWDG_STOP = (1u << 11);
        static constexpr uint32_t  DBGMCU_IWDG_STOP = (1u << 12);
        static constexpr uint32_t  AIRCR_VECTKEY = 0x05FA0000u;
        static constexpr uint32_t  AIRCR_SYSRST = 0x04u;

        __asm__ __volatile__("cpsid i" : : : "memory");

#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" ::: "memory");
#endif
        {
            volatile uint32_t* const aircr =
                reinterpret_cast<volatile uint32_t*>(AIRCR_ADDR);
            const uint32_t aircr_val = AIRCR_VECTKEY | AIRCR_SYSRST;
            *aircr = aircr_val;
        }
        __asm__ __volatile__("dsb sy\n\tisb" ::: "memory");

        {
            volatile uint32_t* const dbg_fz =
                reinterpret_cast<volatile uint32_t*>(DBGMCU_APB1_FZ_ADDR);
            const uint32_t fz = *dbg_fz;
            *dbg_fz = fz & ~(DBGMCU_WWDG_STOP | DBGMCU_IWDG_STOP);
        }

        __asm__ __volatile__("dsb sy\n\tisb" ::: "memory");

#elif defined(__aarch64__)
        //  A55: __builtin_trap() → 즉시 SIGILL (무한 대기·덤프 창 최소화)  
        __builtin_trap();

#else
        // PC 개발빌드: 무한 정지 (디버거 상태 유지)
        (void)0;
#endif

        // 모든 플랫폼 공통: AIRCR 리셋 대기 / trap 후 안전망
        while (true) {
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("" ::: "memory");
#endif
        }
    }

} // namespace ProtectedEngine
