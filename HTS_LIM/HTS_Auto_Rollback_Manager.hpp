// =========================================================================
// HTS_Auto_Rollback_Manager.hpp
// 치명적 변조 감지 시 자가 치유(Self-Healing) 트리거
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [설계 목적]
//  프로젝트 전반의 최후 방어선 — Anti_Glitch, Anti_Debug,
//  Session_Gateway, Security_Pipeline, PAC_Manager 등 5곳 이상에서 호출
//  치명적 변조 감지 시 감사 로그 기록 + 민감 데이터 소거 수행
//
//  [사용법]
//   Auto_Rollback_Manager::Execute_Self_Healing( 0xDEAD0000u);
//   while (true) { HW_NOP(); }  // WDT 리셋 대기
//
//  [보안 설계]
//   1. integrity_fail 검사에 FI 방어 적용 (비트 OR 누적)
//   2. void 반환 — bool 반환 시 FI Boolean Coercion 취약
//   3. ARM: SecureLogger + 키 소거, PC: cerr 진단 출력
//
//  [양산 수정 이력 — 11건 + 세션 14 (2건) = 총 13건]
//   기존 01: iostream ARM 가드
//   세션8 02~11: void→[[noreturn]], FI 안전 분기→매개변수 삭제,
//     SecureLogger, 키 소거, session_id 활용, static_assert,
//     인스턴스화 차단, Doxygen, [[noreturn]]+내부 트랩,
//     integrity_fail 삭제(진입=사형선고)
//   세션14:
//     BUG-12 [LOW]  Target / PC 제거
//     BUG-13 [CRIT] AIRCR/cpsid — A55 aarch64 분기 추가
//            (Cortex-M 전용 명령어 → A55 EL0 Illegal Instruction 방지)
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>

namespace ProtectedEngine {

    /// @brief 치명적 변조 감지 시 자가 치유 트리거 (정적 유틸리티)
    class Auto_Rollback_Manager {
    public:
        /// @brief 자가 치유 시퀀스 가동 — 호출 시 시스템 영구 정지
        /// @param session_id  변조 발생 세션/모듈 식별 코드
        ///
        /// [BUG-10] [[noreturn]] — 제어권을 절대 반환하지 않음
        ///   기존: void 반환 → 호출자가 while(true) 수행 → 호출자 의존!
        ///   → 공격자가 LR 변조 또는 while(true) NOP화로 롤백 우회
        ///   수정: 내부에 무한 루프 + AIRCR 리셋 직접 포함
        ///   → 이 함수에 진입하면 어떤 공격으로도 탈출 불가
        ///
        /// [BUG-11] integrity_fail 매개변수 삭제
        ///   기존: if (fail_flag == 0u) return; → FI로 Zero 플래그 세트 시 우회!
        ///   → 모든 호출처가 Execute_Self_Healing( ...) → 항상 true
        ///   → 호출 자체가 "시스템 붕괴" 선언 → 내부 재검증 불필요
        ///   수정: 매개변수 제거 → 진입 즉시 소각 + 정지
        [[noreturn]]
        static void Execute_Self_Healing(uint32_t session_id) noexcept;

        // [BUG-07] 정적 전용 클래스 — 인스턴스화 차단 (6종)
        Auto_Rollback_Manager() = delete;
        ~Auto_Rollback_Manager() = delete;
        Auto_Rollback_Manager(const Auto_Rollback_Manager&) = delete;
        Auto_Rollback_Manager& operator=(const Auto_Rollback_Manager&) = delete;
        Auto_Rollback_Manager(Auto_Rollback_Manager&&) = delete;
        Auto_Rollback_Manager& operator=(Auto_Rollback_Manager&&) = delete;
    };

    // [BUG-06] 빌드 타임 검증
    static_assert(sizeof(uint32_t) == 4, "uint32_t must be 4 bytes");

} // namespace ProtectedEngine