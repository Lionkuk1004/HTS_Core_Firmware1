// =========================================================================
// HTS_Auto_Rollback_Manager.cpp
// 치명적 변조 감지 시 자가 치유(Self-Healing) 트리거 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// [양산 수정 — 11건]
//
//  ── 기존 (1건) ──
//  01: <iostream> / std::cerr ARM 가드 적용
//
//  ── 세션 8 전수검사 (BUG-02 ~ BUG-11) ──
//  BUG-02 [CRIT] bool 반환 → void (FI Boolean Coercion 차단)
//  BUG-03 [HIGH] integrity_fail 분기 FI 취약 → 비트 방어
//  BUG-04 [HIGH] ARM session_id 무시 → SecureLogger 전달
//  BUG-05 [MED]  키/플래시 소거 기능 추가 (SecureMemory)
//  BUG-06 [MED]  static_assert 추가
//  BUG-07 [LOW]  인스턴스화 차단 6종 완비
//  BUG-08 [MED]  Doxygen/외주 가이드 추가
//  BUG-09 [LOW]  session_id uint64_t → uint32_t (ARM 레지스터 최적화)
//  BUG-10 [CRIT] void → [[noreturn]] + 내부 AIRCR 리셋/무한 루프
//  BUG-11 [CRIT] integrity_fail 매개변수 삭제 (진입=사형선고)
//
// [제약] ARM: try-catch 0, float/double 0, 힙 0
// =========================================================================
#include "HTS_Auto_Rollback_Manager.hpp"
#include "HTS_Secure_Logger.h"
// [NOTE] HTS_Secure_Memory.h — 직접 호출 없음 (호출자 소거 책임 원칙)
//  각 보안 모듈이 Execute_Self_Healing 호출 전에 자체 secureWipe 수행
#include <cstdint>

namespace ProtectedEngine {

    // =====================================================================
    //  Execute_Self_Healing — 최후의 중앙 집중식 사형 집행인
    //
    //  [BUG-10] [[noreturn]] — 이 함수에 진입하면 영원히 탈출 불가
    //  [BUG-11] integrity_fail 매개변수 완전 삭제 (진입 = 사형 확정)
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
        {
            const char* prefix = "HALT id=0x";
            int pos = 0;
            while (prefix[pos] && pos < 60) { msg_buf[pos] = prefix[pos]; ++pos; }
            for (int d = 7; d >= 0; --d) {
                const uint32_t nibble = (session_id >> (d * 4u)) & 0xFu;
                msg_buf[pos++] = static_cast<char>(
                    nibble < 10u ? ('0' + nibble) : ('A' + nibble - 10u));
            }
            msg_buf[pos] = '\0';
        }
        SecureLogger::logSecurityEvent(
            "SELF_HEALING", msg_buf);

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
        // STM32: 인터럽트 비활성 + AIRCR 시스템 리셋 직접 타격
        static constexpr uintptr_t AIRCR_ADDR = 0xE000ED0Cu;
        static constexpr uint32_t  AIRCR_VECTKEY = 0x05FA0000u;
        static constexpr uint32_t  AIRCR_SYSRST = 0x04u;

        __asm__ __volatile__("cpsid i" : : : "memory");

        volatile uint32_t* const aircr =
            reinterpret_cast<volatile uint32_t*>(AIRCR_ADDR);
        *aircr = AIRCR_VECTKEY | AIRCR_SYSRST;

        __asm__ __volatile__("dsb" : : : "memory");
        __asm__ __volatile__("isb" : : : "memory");

#elif defined(__aarch64__)
        // [BUG-FIX CRIT] A55 Linux: 프로세스 즉사 (메모리 덤프 차단)
        //  기존: while(true) → watchdog SIGKILL 대기 수 초 → 덤프 가능
        //  수정: __builtin_trap() → SIGILL 즉시 발생 → OS가 프로세스 메모리 회수  
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