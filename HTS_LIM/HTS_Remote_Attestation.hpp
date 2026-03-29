// =========================================================================
// HTS_Remote_Attestation.hpp
// Remote Attestation — FNV-1a firmware/memory integrity quote
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// [양산 수정 — 22건]
//  01~08: 100% coverage, FNV-1a+Murmur3, Verify_Quote, UID binding,
//         DWT nonce, noexcept, nullptr guard, pragma
//  09~18: volatile removal (Write Suppression), bool->uint32_t (FI),
//         nullptr standardization, Murmur3 constants, golden ratio,
//         test key constant, static_assert, delete 6, Doxygen
//
// [Usage]
//  uint64_t q = Remote_Attestation::Generate_Enclave_Quote(flash, size);
//  uint32_t r = Remote_Attestation::Verify_Quote(q, expected);
//  if (r != 0u) { /* tamper detected */ }
//
//  WARNING: Verify_Quote returns uint32_t (0=match, non-zero=mismatch)
//           Do NOT use: if (Verify_Quote(...)) — Boolean Coercion FI!
//           MUST use:   if (result != 0u) — safe pattern
// =========================================================================
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    // [BUG-08] Build-time validation
    static_assert(sizeof(uint64_t) == 8, "uint64_t must be 8 bytes");

    class Remote_Attestation {
    private:
        // [BUG-11] 내부 구현 → cpp static 함수로 이동 (헤더 미노출)

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
        /// @note  Currently returns basic validity check only
        [[nodiscard]]
        static bool Verify_Quote_With_Server(uint64_t quote) noexcept;

        // [BUG-09] Static-only — instantiation blocked
        Remote_Attestation() = delete;
        ~Remote_Attestation() = delete;
        Remote_Attestation(const Remote_Attestation&) = delete;
        Remote_Attestation& operator=(const Remote_Attestation&) = delete;
        Remote_Attestation(Remote_Attestation&&) = delete;
        Remote_Attestation& operator=(Remote_Attestation&&) = delete;
    };

} // namespace ProtectedEngine