// =========================================================================
// HTS_Remote_Attestation.hpp
// Remote Attestation — FNV-1a firmware/memory integrity quote
// Target: STM32F407 (Cortex-M4, 168MHz)
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
#include <cstddef>

namespace ProtectedEngine {

    static_assert(sizeof(uint64_t) == 8, "uint64_t must be 8 bytes");

    class Remote_Attestation {
    private:

    public:
        /// @brief Generate device-bound integrity quote for memory region
        /// @return 64-bit quote (0 = invalid input)
        static uint64_t Generate_Enclave_Quote(
            const void* memory_region, size_t size) noexcept;

        /// @brief Constant-time quote comparison (FI-hardened)
        /// @return 0 = match, non-zero = mismatch
        /// @warning Do NOT cast to bool — use (result != 0u) pattern
        [[nodiscard]]
        static uint32_t Verify_Quote(
            uint64_t computed_quote,
            uint64_t expected_quote) noexcept;

        /// @brief Legacy server verification API (stub)
        /// @note  0 = accepted, non-zero = rejected (FI/글리치 주입 방어)
        [[nodiscard]]
        static uint32_t Verify_Quote_With_Server(uint64_t quote) noexcept;

        Remote_Attestation() = delete;
        ~Remote_Attestation() = delete;
        Remote_Attestation(const Remote_Attestation&) = delete;
        Remote_Attestation& operator=(const Remote_Attestation&) = delete;
        Remote_Attestation(Remote_Attestation&&) = delete;
        Remote_Attestation& operator=(Remote_Attestation&&) = delete;
    };

} // namespace ProtectedEngine
