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
//  [M-2] session_id는 호출 모듈별 구분 코드(HEAL_*, k_HEAL_CODE_*, GLITCH_* 등).
//   동일 수치가 모듈 간 재사용될 수 있으나 의미는 호출 스택으로 식별.
//   HTS_Secure_Boot_Verify는 해시 실패 시 안전 모드(g_safe_mode) 유지가 설계상
//   우선 — Execute_Self_Healing 미호출. 최종 AIRCR는 본 클래스가 단일 보장.
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
        /// [[noreturn]] — 제어권 미반환, AIRCR 리셋 경로 내장
        [[noreturn]]
        static void Execute_Self_Healing(uint32_t session_id) noexcept;

        Auto_Rollback_Manager() = delete;
        ~Auto_Rollback_Manager() = delete;
        Auto_Rollback_Manager(const Auto_Rollback_Manager&) = delete;
        Auto_Rollback_Manager& operator=(const Auto_Rollback_Manager&) = delete;
        Auto_Rollback_Manager(Auto_Rollback_Manager&&) = delete;
        Auto_Rollback_Manager& operator=(Auto_Rollback_Manager&&) = delete;
    };

    static_assert(sizeof(uint32_t) == 4, "uint32_t must be 4 bytes");

} // namespace ProtectedEngine
