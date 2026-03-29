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
#include "HTS_Secure_Memory.h"

namespace ProtectedEngine {

    // =====================================================================
    //  Execute_Self_Healing — 최후의 사형 집행인
    //
    //  [BUG-10] [[noreturn]] — 이 함수에 진입하면 영원히 탈출 불가
    //    기존: void 반환 → "호출자가 while(true) 해줄 것" 가정
    //    → 공격자가 LR 변조 / while(true) NOP화 → 롤백 우회!
    //    수정: 함수 내부에 무한 루프 + ARM AIRCR 리셋 직접 포함
    //
    //  [BUG-11] integrity_fail 매개변수 완전 삭제
    //    기존: if (fail_flag == 0u) return; → FI로 Zero 플래그 세트 시 우회!
    //    → 모든 호출처가 항상 true 전달 → 재검증 자체가 공격 표면
    //    수정: 매개변수 없음 → 진입 = 사형 선고 확정 → 즉시 집행
    // =====================================================================
    [[noreturn]] void Auto_Rollback_Manager::Execute_Self_Healing(
        uint32_t session_id) noexcept {

        // ── Phase 1: 감사 로그 기록 ──
        // session_id를 16진수 문자열로 변환하여 메시지에 포함
        char msg_buf[80] = {};
        {
            const char* prefix = "HALT id=0x";
            int pos = 0;
            while (prefix[pos] && pos < 60) { msg_buf[pos] = prefix[pos]; ++pos; }
            // uint32_t → 8자리 hex (수동 변환, snprintf 없이)
            for (int d = 7; d >= 0; --d) {
                const uint32_t nibble = (session_id >> (d * 4u)) & 0xFu;
                msg_buf[pos++] = static_cast<char>(
                    nibble < 10u ? ('0' + nibble) : ('A' + nibble - 10u));
            }
            msg_buf[pos] = '\0';
        }
        SecureLogger::logSecurityEvent(
            "SELF_HEALING", msg_buf);

        // ── Phase 2: 시스템 정지 — 플랫폼별 최적 경로 ──
        //
        // [BUG-13] 3단 분기:
        //   ARM (Cortex-M): AIRCR 레지스터 직접 타격 → 하드웨어 리셋
        //   A55 (aarch64):  무한 정지 → systemd watchdog 재시작
        //     → AIRCR/cpsid는 Cortex-M 전용, A55 EL0에서 Illegal Instruction
        //   PC 개발빌드:    무한 정지 (디버거 부착 상태 유지)

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
        // STM32: 인터럽트 비활성 + AIRCR 시스템 리셋 직접 타격
        // [C-SEC-3] 매직넘버 → constexpr 상수화
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
        // 통합콘솔 (A55 Linux): AIRCR 접근 불가 (EL0 유저스페이스)
        // 무한 정지 후 상위 watchdog(systemd)이 프로세스 재시작
        // cpsid/AIRCR 사용 시 Illegal Instruction 발생
        (void)0;
#else
        // PC 개발빌드: 무한 정지 (디버거 상태 유지)
        (void)0;
#endif

        // 모든 플랫폼 공통: 무한 루프 (ARM AIRCR 리셋 대기 포함)
        while (true) {
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("" ::: "memory");
#endif
        }
    }

} // namespace ProtectedEngine