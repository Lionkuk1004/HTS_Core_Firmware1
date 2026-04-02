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

    class SHA256_Bridge {
    public:
        static constexpr size_t DIGEST_LEN = 32u;

        /// @brief SHA-256 해시 (원샷)
        /// @param data       입력 데이터 (nullptr 시 data_len=0 필수)
        /// @param data_len   바이트 단위 (KISA UINT 상한 초과 시 실패)
        /// @param output_32  출력 버퍼 (32바이트 이상)
        /// @return true=성공
        /// @note  실패 경로에서는 output_32 가 SecureMemory::secureWipe 로 소거될 수 있음
        /// @see   KISA_SHA256.h (SHA256_Init / SHA256_Process / SHA256_Close)
        [[nodiscard]] static bool Hash(
            const uint8_t* data, size_t data_len,
            uint8_t* output_32) noexcept;

        SHA256_Bridge() = delete;
        ~SHA256_Bridge() = delete;
        SHA256_Bridge(const SHA256_Bridge&) = delete;
        SHA256_Bridge& operator=(const SHA256_Bridge&) = delete;
    };

} // namespace ProtectedEngine