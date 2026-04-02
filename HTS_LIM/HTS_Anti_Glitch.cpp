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
    //    XOR/OR 누적 후 단일 분기 — 다중 BNE 스킵 면 축소
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

        //  fail_acc는 레지스터 누적(입력만 volatile) — STR write-suppression 면 축소
        uint32_t fail_acc = 0u;
        fail_acc |= (check1 ^ UNLOCKED);   // 정상이면 0
        HW_NOP();
        fail_acc |= (check2 ^ UNLOCKED);   // 정상이면 0
        HW_NOP();
        fail_acc |= (check3 ^ UNLOCKED);   // 정상이면 0
        HW_NOP();
        fail_acc |= (dummy ^ ALU_CANARY);  // 정상이면 0

        // permission 게이트 + asm 레지스터 세탁(VRP·데드코드 제거 방지)
        //
        //  [분기 1] fail_acc → permission
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
