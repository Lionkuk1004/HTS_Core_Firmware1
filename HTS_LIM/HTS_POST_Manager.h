// =========================================================================
// HTS_POST_Manager.h
// FIPS 140-3 Power-On Self-Test (POST) - KAT Validation Manager
// Target: STM32F407 (Cortex-M4)
//
// [Revision - 10 fixes]
//  01~05: iostream removal, namespace, while barrier, noexcept
//  06~10: Self_Healing sig, dead code, vector->fixed array,
//         try-catch removal, magic numbers, Doxygen, delete 6
// =========================================================================
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

namespace ProtectedEngine {

    class POST_Manager {
    private:
        // (헤더에서 제거 — ISR/스레드 가시성을 위해 atomic 사용)

        static bool KAT_Parity_Recovery_Engine() noexcept;
        static bool KAT_Gravity_Interpolation_Engine() noexcept;

    public:
        static void executePowerOnSelfTest() noexcept;
        static void verifyOperationalState() noexcept;

        POST_Manager() = delete;
        ~POST_Manager() = delete;
        POST_Manager(const POST_Manager&) = delete;
        POST_Manager& operator=(const POST_Manager&) = delete;
        POST_Manager(POST_Manager&&) = delete;
        POST_Manager& operator=(POST_Manager&&) = delete;
    };

} // namespace ProtectedEngine
