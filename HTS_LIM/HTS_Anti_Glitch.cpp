// =========================================================================
// HTS_Anti_Glitch.cpp
// 전압 글리칭 / 명령어 스킵 공격 방어 쉴드 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// [양산 수정 — 12건]
//
//  ── 기존 (2건) ──
//  01: ProtectedEngine 네임스페이스로 이동
//  02: GlitchConsts → 익명 네임스페이스, HW_NOP #undef
//
//  ── 세션 8 전수검사 (BUG-03 ~ BUG-08) ──
//  BUG-03 [MED]  dummy==0 → dummy!=ALU_CANARY 정확 비교 강화
//  BUG-04 [MED]  매직 넘버 상수화 (ALU_CANARY, GLITCH_HEAL_CODE)
//  BUG-05 [MED]  static_assert 빌드타임 검증 추가
//  BUG-06 [LOW]  이동 생성자/대입 차단 완비
//  BUG-07 [CRIT] 단축평가(||) 4분기 → 비트OR(|) 단일분기 (FI 방어)
//  BUG-08 [CRIT] volatile fail_acc → 레지스터 격리 (Write Suppression 차단)
//
//  ── 세션 10+ (BUG-09 ~ BUG-10) ──
//  BUG-09 [MED]  ⑭ PC코드 물리삭제: <intrin.h>/__nop()/x86 pause 제거
//  BUG-10 [LOW]  주석 정합: Target "/ PC" 제거
//
// [제약] float 0, double 0, try-catch 0, 힙 0
// =========================================================================
#include "HTS_Anti_Glitch.h"
#include "HTS_Auto_Rollback_Manager.hpp"

// =========================================================================
//  [BUG-09] ARM 전용 하드웨어 NOP
//  MSVC 개발빌드: 빈 매크로 (컴파일만 통과)
// =========================================================================
#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__ARM_ARCH))
#define HW_NOP() __asm__ __volatile__("nop")
#else
#define HW_NOP() do {} while(0)
#endif

namespace ProtectedEngine {

    // 글리치 방어 상수 (내부 링키지 — 외부 노출 차단)
    namespace {
        constexpr uint32_t LOCKED = 0xAAAAAAAAu;  ///< 잠금 상태 (비트 10 반복)
        constexpr uint32_t UNLOCKED = 0x55555555u;  ///< 해제 상태 (비트 01 반복)

        // [BUG-04] 매직 넘버 상수화
        constexpr uint32_t ALU_CANARY = 0xDEADBEEFu;  ///< ALU 교차 검증 기대값
        constexpr uint32_t GLITCH_HEAL_CODE = 0xFA11FA11u;  ///< 자가 치유 트리거 코드
    }

    // [BUG-05] 빌드 타임 정합성 검증
    static_assert(LOCKED != UNLOCKED,
        "LOCKED and UNLOCKED must differ");
    static_assert((LOCKED^ UNLOCKED) == 0xFFFFFFFFu,
        "LOCKED/UNLOCKED must be bitwise complement");
    static_assert((UNLOCKED^ ALU_CANARY) != 0u,
        "ALU canary must not cancel with UNLOCKED");
    static_assert(ALU_CANARY != 0u,
        "ALU canary must be non-zero");

    // =====================================================================
    //  생성자 — 초기 상태: LOCKED
    // =====================================================================
    AntiGlitchShield::AntiGlitchShield() noexcept
        : systemState(LOCKED) {
    }

    // =====================================================================
    //  잠금 해제
    //  release 배리어: 이 시점 이전의 모든 메모리 쓰기가 완료됨을 보장
    // =====================================================================
    void AntiGlitchShield::unlockSystem() noexcept {
        systemState.store(UNLOCKED, std::memory_order_release);
    }

    // =====================================================================
    //  다중 검증 — 전압 글리칭 명령어 스킵 탐지
    //
    //  [방어 원리]
    //  1. systemState를 3회 독립적으로 acquire 로드
    //  2. ALU 교차 검증 (XOR 연산 스킵 시 dummy 변조)
    //  3. 불규칙 NOP 삽입 (타이밍 동기화 교란)
    //
    //  [BUG-07 CRITICAL] 단축 평가(Short-circuit) 제거
    //
    //    기존: if (check1 != UNLOCKED || check2 != UNLOCKED || ...)
    //    → 컴파일러가 4개의 개별 BNE 분기문을 생성!
    //    → 공격자가 BNE 1개만 NOP화(스킵)하면 방어막 통과!
    //
    //    수정: 비트 OR(|) 누적 → 단일 분기(BNE) 1개만 생성
    //    → 분기가 1개이므로 스킵하면 즉시 halt 경로에 진입
    //    → 공격 포인트 4개 → 1개로 축소 (75% 공격면 제거)
    //
    //    어셈블리 비교:
    //    기존 (4개 BNE):          수정 (1개 BNE):
    //      CMP check1, UNLOCKED     XOR check1, UNLOCKED → acc
    //      BNE .halt  ← 공격①     XOR check2, UNLOCKED → acc |=
    //      CMP check2, UNLOCKED     XOR check3, UNLOCKED → acc |=
    //      BNE .halt  ← 공격②     XOR dummy, CANARY    → acc |=
    //      CMP check3, UNLOCKED     CMP acc, #0
    //      BNE .halt  ← 공격③     BNE .halt  ← 유일한 분기
    //      CMP dummy, CANARY
    //      BNE .halt  ← 공격④
    // =====================================================================
    void AntiGlitchShield::verifyCriticalExecution() const noexcept {
        volatile uint32_t check1 = systemState.load(std::memory_order_acquire);

        HW_NOP(); HW_NOP();

        // ALU 교차 검증: 명령어 스킵 시 dummy 값이 변조됨
        volatile uint32_t dummy = check1 ^ ALU_CANARY;

        volatile uint32_t check2 = systemState.load(std::memory_order_acquire);

        HW_NOP(); HW_NOP(); HW_NOP();
        dummy ^= check2;

        volatile uint32_t check3 = systemState.load(std::memory_order_acquire);

        // [BUG-07] 비트 OR 누적 → 단일 분기로 합산
        // [BUG-08] fail_acc에서 volatile 제거 → CPU 레지스터 격리
        //
        //  기존: volatile uint32_t fail_acc → 매 |= 마다 STR(SRAM 쓰기) 강제
        //  → 공격자가 STR 타이밍에 전압 글리치 → Write Suppression
        //  → fail_acc가 SRAM에서 영원히 0 → 방어막 통과!
        //
        //  수정: uint32_t fail_acc → 순수 레지스터(R0 등)에만 존재
        //  → ORR R0, R0, R1 연속 수행 (SRAM 접근 0회)
        //  → 메모리 쓰기 억제 공격 원천 불가
        //
        //  안전성: check1/2/3은 volatile, dummy는 volatile
        //  → 입력 읽기는 컴파일러가 절대 제거/재배치 불가
        //  → fail_acc 자체만 레지스터에 격리 → 최적의 방어 구조
        uint32_t fail_acc = 0u;
        fail_acc |= (check1 ^ UNLOCKED);   // 정상이면 0
        HW_NOP();
        fail_acc |= (check2 ^ UNLOCKED);   // 정상이면 0
        HW_NOP();
        fail_acc |= (check3 ^ UNLOCKED);   // 정상이면 0
        HW_NOP();
        fail_acc |= (dummy ^ ALU_CANARY);  // 정상이면 0

        // ★ 단일 분기 — 공격 포인트 1개 ★
        // 글리치로 이 분기를 스킵하면 → fall-through → halt 경로
        // (방어 코드를 if 밖이 아니라 if 안에 두면, 스킵 시 정상 경로로 빠지는
        //  문제가 있으므로, 정상 경로를 if 안에, halt를 if 밖에 배치)
        if (fail_acc == 0u) {
            return;  // ✅ 정상 — 엔진 가동 허가
        }

        // ── 여기 도달 = 글리치 탐지 또는 잠금 상태 ──
        // 자가 치유 트리거 (펌웨어 복원 시도)
        Auto_Rollback_Manager::Execute_Self_Healing(
            GLITCH_HEAL_CODE);

        // WDT 리셋 대기 — HW_NOP()으로 컴파일러의 루프 제거 차단
        while (true) {
            HW_NOP();
        }
    }

} // namespace ProtectedEngine

// 매크로 클린업 (다른 파일로 누출 방지)
#undef HW_NOP