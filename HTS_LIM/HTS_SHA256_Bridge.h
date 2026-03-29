// =========================================================================
// HTS_SHA256_Bridge.h
// FIPS 180-4 SHA-256 해시 래퍼
// Target: STM32F407 (Cortex-M4) / Cortex-A55 / PC
//
// [규격] FIPS 180-4: Secure Hash Standard (SHA-256)
// [구현] KISA SHA-256 C 라이브러리 래퍼 (KISA_SHA256.h)
//
// [HMAC_Bridge와의 관계]
//  HMAC_Bridge: SHA-256 기반 HMAC (내부적으로 KISA SHA256 사용)
//  SHA256_Bridge: 순수 해시 전용 (FIPS KAT 및 무결성 검증용)
//
// [제약] try-catch 0, float/double 0, heap 0, iostream 0
// =========================================================================
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    class SHA256_Bridge {
    public:
        static constexpr size_t DIGEST_LEN = 32u;

        /// @brief SHA-256 해시 (원샷)
        /// @param data       입력 데이터 (nullptr 시 data_len=0 필수)
        /// @param data_len   바이트 단위
        /// @param output_32  출력 버퍼 (32바이트 이상)
        /// @return true=성공
        [[nodiscard]] static bool Hash(
            const uint8_t* data, size_t data_len,
            uint8_t* output_32) noexcept;

        SHA256_Bridge() = delete;
        ~SHA256_Bridge() = delete;
        SHA256_Bridge(const SHA256_Bridge&) = delete;
        SHA256_Bridge& operator=(const SHA256_Bridge&) = delete;
    };

} // namespace ProtectedEngine