// =========================================================================
// HTS_Role_Auth.h
// FIPS 140-3 Level 2 역할 기반 접근 제어
// Target: STM32F407 (Cortex-M4) / Cortex-A55 / PC
//
// [FIPS 140-3 AS05 — 역할, 서비스, 인증]
//  Level 2: 역할 기반 인증 필수
//  - Crypto Officer: 키 주입, 설정 변경, 자가진단 실행, DRBG 리시드
//  - User: 암호화/복호화, 상태 조회
//  - 미인증: 자가진단 상태 조회만 허용
//
// [인증 메커니즘]
//  HMAC-SHA256 기반 비밀번호 검증 (상수 시간)
//  비밀번호는 평문 저장 금지 — HMAC(salt, password) 해시만 저장
//
// [KCMVP 검증기준 v3.0 — 7.3]
//  운용자(Crypto Officer)와 사용자(User) 역할 구분
//  운용자: 암호 모듈 초기화, 키 관리, 자체시험 실행
//  사용자: 암호 서비스 이용
//
// [제약] try-catch 0, float/double 0, heap 0, iostream 0
// =========================================================================
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    /// @brief 모듈 역할
    enum class Role : uint8_t {
        UNAUTHENTICATED = 0u,   ///< 미인증 (상태 조회만)
        USER = 1u,   ///< 사용자 (암호화/복호화)
        CRYPTO_OFFICER = 2u,   ///< 운용자 (키 관리, 설정, 자가진단)
    };

    /// @brief 서비스 종류
    enum class Service : uint8_t {
        // 미인증 허용
        STATUS_QUERY = 0u,   ///< 자가진단 상태 조회
        MODULE_VERSION = 1u,   ///< 모듈 버전 조회

        // User 이상
        ENCRYPT = 10u,  ///< 데이터 암호화
        DECRYPT = 11u,  ///< 데이터 복호화
        HASH = 12u,  ///< 해시 연산
        HMAC_GENERATE = 13u,  ///< HMAC 생성
        HMAC_VERIFY = 14u,  ///< HMAC 검증
        DRBG_GENERATE = 15u,  ///< 난수 생성

        // Crypto Officer 전용
        KEY_INJECT = 20u,  ///< 키 주입/교체
        KEY_ZEROIZE = 21u,  ///< 키 제로화
        SELF_TEST = 22u,  ///< 자가진단 실행
        DRBG_RESEED = 23u,  ///< DRBG 리시드
        CONFIG_CHANGE = 24u,  ///< 설정 변경
        FIRMWARE_UPDATE = 25u,  ///< 펌웨어 업데이트 시작
        AUDIT_LOG_READ = 26u,  ///< 감사 로그 조회
    };

    class Role_Auth {
    public:
        /// @brief 역할 인증 (HMAC-SHA256 비밀번호 검증)
        /// @param password      비밀번호 (평문)
        /// @param password_len  비밀번호 길이
        /// @param target_role   요청 역할 (USER 또는 CRYPTO_OFFICER)
        /// @return true=인증 성공 → 현재 역할 변경
        [[nodiscard]] static bool Authenticate(
            const uint8_t* password, size_t password_len,
            Role target_role) noexcept;

        /// @brief 현재 역할에서 서비스 접근 가능 여부
        [[nodiscard]] static bool Is_Authorized(Service svc) noexcept;

        /// @brief 현재 인증 역할 조회
        [[nodiscard]] static Role Get_Current_Role() noexcept;

        /// @brief 로그아웃 (UNAUTHENTICATED로 복귀)
        static void Logout() noexcept;

        /// @brief Crypto Officer 비밀번호 해시 설정 (초기 프로비저닝)
        /// @note  OTP/보호 Flash에 저장 — 1회만 호출
        static bool Set_Officer_Password_Hash(
            const uint8_t* hash_32) noexcept;

        /// @brief User 비밀번호 해시 설정
        static bool Set_User_Password_Hash(
            const uint8_t* hash_32) noexcept;

        Role_Auth() = delete;
        ~Role_Auth() = delete;
        Role_Auth(const Role_Auth&) = delete;
        Role_Auth& operator=(const Role_Auth&) = delete;

    private:
        static constexpr size_t HASH_LEN = 32u;
        static constexpr size_t SALT_LEN = 16u;

        /// @brief 비밀번호 → HMAC-SHA256 해시
        static void Compute_Password_Hash(
            const uint8_t* password, size_t len,
            const uint8_t* salt, uint8_t* out_32) noexcept;
    };

} // namespace ProtectedEngine