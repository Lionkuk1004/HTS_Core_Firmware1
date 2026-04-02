// =========================================================================
// HTS_Role_Auth.cpp
// FIPS 140-3 Level 2 역할 기반 접근 제어 구현부
// Target: STM32F407 (Cortex-M4) / Cortex-A55 / PC
//
// [인증 흐름]
//  1. 초기: UNAUTHENTICATED
//  2. Authenticate(password, role) → HMAC(salt, pw) == stored_hash?
//  3. 성공 → 역할 전환 (User 또는 Crypto Officer)
//  4. Logout() → UNAUTHENTICATED 복귀
//
// [제약] try-catch 0, float/double 0, heap 0
// =========================================================================
#include "HTS_Role_Auth.h"
#include "HTS_HMAC_Bridge.hpp"
#include "HTS_Secure_Logger.h"

#include <atomic>
#include <cstring>

namespace ProtectedEngine {

    // =====================================================================
    //  보안 소거
    // =====================================================================
    static void RA_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) return;
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) q[i] = 0u;
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(q));
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  정적 상태 (파일 스코프)
    // =====================================================================
    static std::atomic<uint8_t> s_current_role{
        static_cast<uint8_t>(Role::UNAUTHENTICATED) };

    // 비밀번호 해시 저장소 (프로비저닝 시 1회 설정)
    // 양산: OTP 또는 보호 Flash 섹터에 저장
    static uint8_t s_officer_hash[32] = {};
    static uint8_t s_user_hash[32] = {};
    static std::atomic<bool> s_officer_hash_set{ false };
    static std::atomic<bool> s_user_hash_set{ false };

    // 고정 Salt (양산 시 디바이스별 고유값으로 교체 권장)
    static constexpr uint8_t FIXED_SALT[16] = {
        0x48,0x54,0x53,0x5F, 0x52,0x4F,0x4C,0x45,  // "HTS_ROLE"
        0x5F,0x41,0x55,0x54, 0x48,0x5F,0x56,0x31   // "_AUTH_V1"
    };

    // 인증 실패 카운터 (연속 5회 실패 → 잠금)
    static std::atomic<uint8_t> s_fail_count{ 0u };
    static constexpr uint8_t MAX_FAIL_COUNT = 5u;

    // =====================================================================
    //  Compute_Password_Hash — HMAC-SHA256(salt || password)
    // =====================================================================
    void Role_Auth::Compute_Password_Hash(
        const uint8_t* password, size_t len,
        const uint8_t* salt, uint8_t* out_32) noexcept {

        // HMAC(key=salt, message=password) → 32바이트 해시
        // [FIX-C6031] [[nodiscard]] 반환값 검사 — 실패 시 출력 제로화
        if (HMAC_Bridge::Generate(password, len, salt, Role_Auth::SALT_LEN, out_32)
            != HMAC_Bridge::SECURE_TRUE) {
            RA_Wipe(out_32, 32u);  // 실패 시 부분 기록 방지
        }
    }

    // =====================================================================
    //  Authenticate — 역할 인증
    // =====================================================================
    bool Role_Auth::Authenticate(
        const uint8_t* password, size_t password_len,
        Role target_role) noexcept {

        if (password == nullptr || password_len == 0u) return false;

        // 잠금 상태 확인
        if (s_fail_count.load(std::memory_order_acquire) >= MAX_FAIL_COUNT) {
            SecureLogger::logSecurityEvent(
                "AUTH_LOCKED",
                "Authentication locked. Max failures exceeded.");
            return false;
        }

        // 대상 해시 선택
        const uint8_t* stored_hash = nullptr;
        bool hash_set = false;

        if (target_role == Role::CRYPTO_OFFICER) {
            stored_hash = s_officer_hash;
            hash_set = s_officer_hash_set.load(std::memory_order_acquire);
        }
        else if (target_role == Role::USER) {
            stored_hash = s_user_hash;
            hash_set = s_user_hash_set.load(std::memory_order_acquire);
        }
        else {
            return false;  // UNAUTHENTICATED는 인증 불필요
        }

        if (!hash_set || stored_hash == nullptr) {
            return false;  // 비밀번호 미설정
        }

        // 입력 비밀번호 해시 계산
        uint8_t computed[32] = {};
        Compute_Password_Hash(password, password_len, FIXED_SALT, computed);

        // 상수 시간 비교
        volatile uint8_t diff = 0u;
        for (size_t i = 0u; i < Role_Auth::HASH_LEN; ++i) {
            diff |= computed[i] ^ stored_hash[i];
        }

        RA_Wipe(computed, sizeof(computed));

        if (diff != 0u) {
            const uint8_t cur = s_fail_count.load(std::memory_order_relaxed);
            if (cur < MAX_FAIL_COUNT) {
                s_fail_count.store(static_cast<uint8_t>(cur + 1u), std::memory_order_release);
            }
            SecureLogger::logSecurityEvent(
                "AUTH_FAIL", "Authentication failed.");
            return false;
        }

        // 인증 성공
        s_current_role.store(
            static_cast<uint8_t>(target_role),
            std::memory_order_release);
        s_fail_count.store(0u, std::memory_order_release);

        SecureLogger::logSecurityEvent(
            "AUTH_OK",
            (target_role == Role::CRYPTO_OFFICER)
            ? "Crypto Officer authenticated."
            : "User authenticated.");
        return true;
    }

    // =====================================================================
    //  Is_Authorized — 서비스 접근 제어 (ACL)
    // =====================================================================
    bool Role_Auth::Is_Authorized(Service svc) noexcept {

        const auto role = static_cast<Role>(
            s_current_role.load(std::memory_order_acquire));
        const auto sv = static_cast<uint8_t>(svc);

        // 미인증: 상태 조회만
        if (sv <= 1u) return true;  // STATUS_QUERY, MODULE_VERSION

        // User 이상: 암호 서비스
        if (sv >= 10u && sv <= 15u) {
            return (role == Role::USER || role == Role::CRYPTO_OFFICER);
        }

        // Crypto Officer 전용: 키 관리, 설정, 자가진단
        if (sv >= 20u) {
            return (role == Role::CRYPTO_OFFICER);
        }

        return false;
    }

    // =====================================================================
    //  Get_Current_Role / Logout
    // =====================================================================
    Role Role_Auth::Get_Current_Role() noexcept {
        return static_cast<Role>(
            s_current_role.load(std::memory_order_acquire));
    }

    void Role_Auth::Logout() noexcept {
        s_current_role.store(
            static_cast<uint8_t>(Role::UNAUTHENTICATED),
            std::memory_order_release);
        SecureLogger::logSecurityEvent("AUTH_LOGOUT", "Session ended.");
    }

    // =====================================================================
    //  비밀번호 해시 설정 (프로비저닝)
    // =====================================================================
    bool Role_Auth::Set_Officer_Password_Hash(
        const uint8_t* hash_32) noexcept {
        if (hash_32 == nullptr) return false;
        if (s_officer_hash_set.load(std::memory_order_acquire)) { return false; }  // 이미 설정됨 → 재설정 금지
        std::memcpy(s_officer_hash, hash_32, 32);
        s_officer_hash_set.store(true, std::memory_order_release);
        return true;
    }

    bool Role_Auth::Set_User_Password_Hash(
        const uint8_t* hash_32) noexcept {
        if (hash_32 == nullptr) return false;
        if (s_user_hash_set.load(std::memory_order_acquire)) { return false; }
        std::memcpy(s_user_hash, hash_32, 32);
        s_user_hash_set.store(true, std::memory_order_release);
        return true;
    }

} // namespace ProtectedEngine