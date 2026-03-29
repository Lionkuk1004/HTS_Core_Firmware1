// =========================================================================
// HTS_Conditional_SelfTest.h
// KCMVP/FIPS 140-3 조건부 자가진단 + 소프트웨어 무결성 검증
// Target: STM32F407 (Cortex-M4) / Cortex-A55 / PC
//
// [KCMVP 검증기준 v3.0 — 7.4.2 조건부 자체시험]
//  - 키 생성/주입 시 쌍대 일관성 테스트 (Pairwise Consistency)
//    암호화(PT→CT) → 복호화(CT→PT) → 원본 일치 확인
//
// [FIPS 140-3 / ISO 19790]
//  - AS09.13: 조건부 자가진단 (키 생성 시)
//  - AS09.40: 소프트웨어/펌웨어 무결성 테스트
//    부팅 시 Flash 영역 HMAC-SHA256 검증
//
// [제약] try-catch 0, float/double 0, heap 0, iostream 0
// =========================================================================
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    class Conditional_SelfTest {
    public:
        // ══════════════════════════════════════════════════════════
        //  키 쌍대 일관성 테스트 (Pairwise Consistency)
        //  키 생성/로테이션 시 호출 → 암호화+복호화 라운드트립 검증
        //  실패 시 해당 키 폐기 + false 반환
        // ══════════════════════════════════════════════════════════

        /// @brief ARIA 키 쌍대 일관성 (KCMVP)
        [[nodiscard]] static bool Verify_ARIA_Key(
            const uint8_t* key, int key_bits) noexcept;

        /// @brief LEA 키 쌍대 일관성 (KCMVP)
        [[nodiscard]] static bool Verify_LEA_Key(
            const uint8_t* key, uint32_t key_len_bytes,
            const uint8_t* iv_16) noexcept;

#if defined(HTS_CRYPTO_FIPS) || defined(HTS_CRYPTO_DUAL)
        /// @brief AES 키 쌍대 일관성 (FIPS)
        [[nodiscard]] static bool Verify_AES_Key(
            const uint8_t* key, int key_bits) noexcept;
#endif

        // ══════════════════════════════════════════════════════════
        //  Boot Verify — Flash HMAC-SHA256 무결성 검증
        //
        //  부팅 시 POST 체인에서 호출.
        //  STM32F407 Flash Bank A (0x0800_0000, 512KB) 전체 해시.
        //  OTP/보호 섹터에 저장된 참조 HMAC과 비교.
        //
        //  PC/A55: 콜백 기반 (flash_read 함수 포인터 주입)
        // ══════════════════════════════════════════════════════════

        /// @brief Flash 메모리 읽기 콜백 타입
        ///  addr: Flash 시작 주소 오프셋
        ///  buf:  읽기 버퍼
        ///  len:  읽기 바이트 수
        ///  반환: 실제 읽은 바이트 수 (0=실패)
        using FlashReadFunc = size_t(*)(uint32_t addr,
            uint8_t* buf, size_t len);

        /// @brief Flash HMAC-SHA256 무결성 검증
        /// @param flash_read     Flash 읽기 콜백
        /// @param flash_base     Flash 시작 주소 (예: 0x08000000)
        /// @param flash_size     Flash 크기 (예: 512*1024)
        /// @param hmac_key       HMAC 키 (32바이트)
        /// @param expected_hmac  기대 HMAC 값 (32바이트)
        /// @return true=무결성 통과
        [[nodiscard]] static bool Verify_Flash_Integrity(
            FlashReadFunc flash_read,
            uint32_t flash_base,
            uint32_t flash_size,
            const uint8_t* hmac_key,
            const uint8_t* expected_hmac) noexcept;

        Conditional_SelfTest() = delete;
        ~Conditional_SelfTest() = delete;
        Conditional_SelfTest(const Conditional_SelfTest&) = delete;
        Conditional_SelfTest& operator=(const Conditional_SelfTest&) = delete;
    };

} // namespace ProtectedEngine