// =========================================================================
// HTS_Secure_Logger.h
// 보안 감사 로거 — 이벤트 로깅 + CRC32 로그 무결성
// Target: STM32F407 (Cortex-M4)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [설계 목적]
//  보안 감사 이벤트를 CRC32 무결성 지문 포함 포맷으로 기록
//
//  [사용법]
//   SecureLogger::logSecurityEvent("SESSION_OPEN", "PUF seed injected");
//
//  [출력 포맷]
//   [AUDIT@0xTICK] TYPE | DETAIL | CRC:0xHEX
//
//  [호출 제약]
//   ✓ 메인 루프 (POST, 세션 관리)
//   ✗ ISR 내부: 호출 가능하지만 UART 출력 지연 주의
//
//  [M-3] HTS_MILITARY_GRADE_EW 정의 시 logSecurityEvent 묵살
//       (HTS_Hardware_Init fputc EMCON과 동일 Zero-Emission 정책)
//
//  [양산 수정 이력 — 12건]
//   FIX-01~03, BUG-01~08: (이전 이력 참조)
//   BUG-09 [CRIT] D-2: 스택 버퍼 잔상 소거 3중 방어
//   BUG-10 [LOW]  Target "/ Windows / Linux" 제거
//   BUG-11 [CRIT] std::string/std::vector 파라미터 → const char* (힙 0)
//   BUG-12 [CRIT] PC 코드 물리삭제: iostream/Log_PC/플랫폼분기 전량 제거
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    /// @brief 보안 감사 로거 (정적 유틸리티, 힙 할당 0회)
    class SecureLogger {
    public:
        /// @brief 보안 감사 이벤트 기록
        /// @param eventType  이벤트 분류 ("SESSION_OPEN", "POST_START" 등)
        /// @param details    상세 설명 (const char* — 힙 할당 금지)
        /// @note  ARM: stdout/semihosting 비의존 고정 버퍼 경로 + CRC32 지문
        static void logSecurityEvent(
            const char* eventType,
            const char* details) noexcept;

        // 정적 전용 — 인스턴스화 차단 (6종)
        SecureLogger() = delete;
        ~SecureLogger() = delete;
        SecureLogger(const SecureLogger&) = delete;
        SecureLogger& operator=(const SecureLogger&) = delete;
        SecureLogger(SecureLogger&&) = delete;
        SecureLogger& operator=(SecureLogger&&) = delete;
    };

} // namespace ProtectedEngine