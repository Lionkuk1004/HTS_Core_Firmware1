// =========================================================================
// HTS_CTR_DRBG.h
// NIST SP 800-90A CTR_DRBG — 결정론적 난수 생성기
// Target: STM32F407 (Cortex-M4) / Cortex-A55 / PC
//
// [규격]
//  NIST SP 800-90A Rev.1: CTR_DRBG (Block Cipher Based)
//  KCMVP: ARIA-256 기반 CTR_DRBG
//  FIPS:  AES-256 기반 CTR_DRBG
//
// [보안 강도]
//  256-bit security strength
//  Key: 32바이트, V(counter): 16바이트
//  Seed: 48바이트 (Key + V)
//  Reseed interval: 2^20 (임베디드 보수적 설정)
//
// [빌드 프리셋]
//  HTS_CRYPTO_KCMVP: ARIA-256 기반 CTR_DRBG
//  HTS_CRYPTO_FIPS:  AES-256 기반 CTR_DRBG
//  HTS_CRYPTO_DUAL:  ARIA 우선 (KCMVP 인증 기본)
//
// [제약] try-catch 0, float/double 0, heap 0, iostream 0
//
// [양산 수정 이력 — 1건]
//  BUG-01 [신규] 초기 구현
// =========================================================================
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    /// @brief CTR_DRBG 상태 코드
    enum class DRBG_Status : uint8_t {
        OK = 0u,
        ERROR_UNINSTANTIATED = 1u,
        ERROR_RESEED_REQUIRED = 2u,
        ERROR_INPUT_TOO_LONG = 3u,
        ERROR_ENTROPY_FAIL = 4u,
        ERROR_CIPHER_FAIL = 5u,
    };

    class HTS_CTR_DRBG {
    public:
        // ── 상수 ─────────────────────────────────────────────────
        static constexpr size_t KEY_LEN = 32u;   ///< 256-bit key
        static constexpr size_t BLOCK_LEN = 16u;   ///< 128-bit block
        static constexpr size_t SEED_LEN = KEY_LEN + BLOCK_LEN;  ///< 48B
        static constexpr size_t MAX_OUTPUT = 512u;  ///< 1회 최대 출력
        static constexpr uint32_t RESEED_INTERVAL = (1u << 20);  ///< 2^20

        HTS_CTR_DRBG() noexcept;
        ~HTS_CTR_DRBG() noexcept;

        HTS_CTR_DRBG(const HTS_CTR_DRBG&) = delete;
        HTS_CTR_DRBG& operator=(const HTS_CTR_DRBG&) = delete;
        HTS_CTR_DRBG(HTS_CTR_DRBG&&) = delete;
        HTS_CTR_DRBG& operator=(HTS_CTR_DRBG&&) = delete;

        /// @brief DRBG 인스턴스화 (전원 투입 후 1회)
        /// @param entropy      엔트로피 입력 (≥ SEED_LEN 바이트)
        /// @param entropy_len  엔트로피 길이
        /// @param nonce        논스 (nullptr 허용)
        /// @param nonce_len    논스 길이
        /// @param pers         개인화 문자열 (nullptr 허용)
        /// @param pers_len     개인화 문자열 길이
        [[nodiscard]] DRBG_Status Instantiate(
            const uint8_t* entropy, size_t entropy_len,
            const uint8_t* nonce, size_t nonce_len,
            const uint8_t* pers, size_t pers_len) noexcept;

        /// @brief 자동 엔트로피 수집 인스턴스화 (Physical_Entropy_Engine 사용)
        [[nodiscard]] DRBG_Status Instantiate_Auto() noexcept;

        /// @brief 난수 생성
        /// @param output       출력 버퍼
        /// @param output_len   요청 바이트 수 (≤ MAX_OUTPUT)
        [[nodiscard]] DRBG_Status Generate(
            uint8_t* output, size_t output_len) noexcept;

        /// @brief 리시드 (엔트로피 재주입)
        [[nodiscard]] DRBG_Status Reseed(
            const uint8_t* entropy, size_t entropy_len,
            const uint8_t* additional, size_t add_len) noexcept;

        /// @brief 자동 엔트로피 리시드
        [[nodiscard]] DRBG_Status Reseed_Auto() noexcept;

        /// @brief 상태 소거 (키 제로화 포함)
        void Uninstantiate() noexcept;

        /// @brief 인스턴스화 여부
        [[nodiscard]] bool Is_Instantiated() const noexcept { return instantiated; }

    private:
        // ── SP 800-90A 내부 상태 ─────────────────────────────────
        uint8_t  key[KEY_LEN] = {};   ///< 현재 키 (256-bit)
        uint8_t  V[BLOCK_LEN] = {};   ///< 카운터 (128-bit)
        uint32_t reseed_counter = 0u;
        bool     instantiated = false;

        // ── CRNG 연속 테스트 (FIPS 140-3 AS09.35) ────────────────
        //  연속 2개 출력 블록이 동일하면 DRBG 고장 판정
        uint8_t  prev_block[BLOCK_LEN] = {};
        bool     prev_block_valid = false;

        // ── 내부 연산 ────────────────────────────────────────────

        /// @brief SP 800-90A §10.2.1.2 CTR_DRBG_Update
        void Update(const uint8_t* provided_data) noexcept;

        /// @brief V 카운터 1 증가 (Big-Endian, 16바이트)
        static void Increment_V(uint8_t* v) noexcept;

        /// @brief 블록 암호 호출 (빌드 프리셋에 따라 ARIA 또는 AES)
        /// @return true=성공
        bool Block_Encrypt(const uint8_t* key_32,
            const uint8_t* in_16, uint8_t* out_16) noexcept;

        /// @brief seed_material 구성 (entropy || nonce || pers, SEED_LEN 패딩)
        static void Build_Seed_Material(
            uint8_t* seed_out,
            const uint8_t* entropy, size_t e_len,
            const uint8_t* nonce, size_t n_len,
            const uint8_t* pers, size_t p_len) noexcept;
    };

} // namespace ProtectedEngine