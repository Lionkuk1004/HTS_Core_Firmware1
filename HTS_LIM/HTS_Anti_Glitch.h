// =========================================================================
// HTS_Anti_Glitch.h
// 전압 글리칭 / 명령어 스킵 공격 방어 쉴드
// Target: STM32F407 (Cortex-M4)
//
#pragma once
// ─────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────
//  [사용법] 기본 사용 예시를 여기에 기재하세요.
//  [메모리] sizeof(클래스명) 확인 후 전역/정적 배치 필수.
//  [보안]   복사/이동 연산자 = delete (키 소재 복제 차단).
//
//  ⚠ [파트너사 필수 확인]
//    HW 레지스터 주소(UART/WDT 등)는 보드 설계에 맞게 교체.
//    IRQ 번호는 STM32F407 RM0090 벡터 테이블 기준으로 교체.
// ─────────────────────────────────────────────────────────

#include <cstdint>
#include <atomic>

namespace ProtectedEngine {

    class AntiGlitchShield {
    private:
        std::atomic<uint32_t> systemState;

    public:
        AntiGlitchShield() noexcept;

        AntiGlitchShield(const AntiGlitchShield&) = delete;
        AntiGlitchShield& operator=(const AntiGlitchShield&) = delete;

        // 보안 검증 통과 후 시스템 잠금 해제
        void unlockSystem() noexcept;

        // 핵심 엔진 가동 전 다중 검증 (3중 읽기 + ALU 교차 검증)
        void verifyCriticalExecution() const noexcept;
    };

} // namespace ProtectedEngine
