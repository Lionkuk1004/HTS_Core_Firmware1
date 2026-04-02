// =========================================================================
// HTS_Anti_Glitch.cpp
// 전압 글리칭 / 명령어 스킵 공격 방어 쉴드 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
//
#include "HTS_Anti_Glitch.h"
#include "HTS_Anti_Debug.h"
#include "HTS_Auto_Rollback_Manager.hpp"

// =========================================================================
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

        constexpr uint32_t ALU_CANARY = 0xDEADBEEFu;  ///< ALU 교차 검증 기대값
        constexpr uint32_t GLITCH_HEAL_CODE = 0xFA11FA11u;  ///< 자가 치유 트리거 코드
    }

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

        // ★ [BUG-FIX FATAL] 3중 방어 + VRP 차단 Permission Gate ★
        //
        //  1차 수정: 3중 분기 (permission + fail_acc 재검증)
        //  문제: 컴파일러 VRP(Value Range Propagation)가 Path A에서
        //        fail_acc==0 확정 → Gate 3(fail_acc!=0) 데드코드 삭제
        //        → 단일 BNE 글리치로 3중 방어 전부 무력화
        //
        //  최종 수정:
        //   (a) Gate 3 앞에 asm volatile "+r" (레지스터 세탁)
        //       → 컴파일러가 fail_acc 값을 추적 불가 → Gate 3 삭제 불가
        //   (b) permission은 volatile → VRP가 UNLOCKED 전파 불가
        //   (c) HW_NOP 분산 → 글리치 타이밍 윈도우 분리
        //
        //  [분기 1] fail_acc → permission 게이트 설정
        volatile uint32_t permission = LOCKED;  // 기본: 차단 (Fall-through=HALT)
        if (fail_acc == 0u) {
            permission = UNLOCKED;  // 통과 시에만 해제
        }
        HW_NOP(); HW_NOP();  // 글리치 타이밍 윈도우 분산

        //  [분기 2] permission 재검증 (volatile → VRP 차단)
        //   분기1 글리치 시: permission은 LOCKED 유지 → 여기서 HALT
        if (permission != UNLOCKED) {
            Auto_Rollback_Manager::Execute_Self_Healing(GLITCH_HEAL_CODE);
            AntiDebugManager::trustedHalt("AntiGlitch: permission gate");
        }
        HW_NOP();

        //  [분기 3] fail_acc 원본 재검증 (VRP 차단: asm volatile 레지스터 세탁)
        //
        //  핵심: "+r"(fail_acc) → 컴파일러에게 "fail_acc 레지스터가
        //        이 asm 블록에서 읽히고 쓰였다"고 거짓 통보
        //        → Path A에서 fail_acc==0 확정이었어도, asm 이후에는
        //          "값이 변경되었을 수 있다"로 추적 리셋
        //        → Gate 3의 (fail_acc != 0u) 비교가 삭제 불가능
        //
        //  GCC/Clang -O2/-O3 + VRP + Jump Threading 모두 무력화
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : "+r"(fail_acc));  // VRP 차단: 값 추적 리셋
#endif
        if (fail_acc != 0u) {
            Auto_Rollback_Manager::Execute_Self_Healing(GLITCH_HEAL_CODE);
            AntiDebugManager::trustedHalt("AntiGlitch: fail_acc reverify");
        }

        // ✅ 3중 분기 모두 통과 → 정상 리턴
        return;
    }

} // namespace ProtectedEngine

// 매크로 클린업 (다른 파일로 누출 방지)
#undef HW_NOP
