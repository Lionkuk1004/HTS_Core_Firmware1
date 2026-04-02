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
#include "HTS_Secure_Memory.h"

#include <atomic>
#include <cstring>

namespace ProtectedEngine {

    namespace {
        /// 프로비저닝 해시 슬롯 상태 (TOCTOU 방지 — [C] compare_exchange 단일 작성자)
        constexpr uint32_t kProvUninit = 0u;
        constexpr uint32_t kProvWriting = 1u;
        constexpr uint32_t kProvDone = 2u;
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
    static std::atomic<uint32_t> s_officer_hash_state{ kProvUninit };
    static std::atomic<uint32_t> s_user_hash_state{ kProvUninit };

    // 고정 Salt (양산 시 디바이스별 고유값으로 교체 권장)
    static constexpr uint8_t FIXED_SALT[16] = {
        0x48,0x54,0x53,0x5F, 0x52,0x4F,0x4C,0x45,  // "HTS_ROLE"
        0x5F,0x41,0x55,0x54, 0x48,0x5F,0x56,0x31   // "_AUTH_V1"
    };

    // 역할별 인증 실패 카운터 (연속 실패 → 잠금; 역할 간 분리 — 브루트포스 우회 차단)
    static std::atomic<uint32_t> s_officer_fail_count{ 0u };
    static std::atomic<uint32_t> s_user_fail_count{ 0u };
    static constexpr uint32_t MAX_FAIL_COUNT = 5u;

    // =====================================================================
    //  Compute_Password_Hash — HMAC-SHA256(salt || password)
    // =====================================================================
    bool Role_Auth::Compute_Password_Hash(
        const uint8_t* password, size_t len,
        const uint8_t* salt, uint8_t* out_32) noexcept {

        if (HMAC_Bridge::Generate(password, len, salt, Role_Auth::SALT_LEN, out_32)
            != HMAC_Bridge::SECURE_TRUE) {
            SecureMemory::secureWipe(out_32, 32u);
            return false;
        }
        return true;
    }

    // =====================================================================
    //  Authenticate — 역할 인증
    // =====================================================================
    bool Role_Auth::Authenticate(
        const uint8_t* password, size_t password_len,
        Role target_role) noexcept {

        if (password == nullptr || password_len == 0u) return false;

        const uint8_t* stored_hash = nullptr;
        std::atomic<uint32_t>* fail_counter = nullptr;

        if (target_role == Role::CRYPTO_OFFICER) {
            stored_hash = s_officer_hash;
            fail_counter = &s_officer_fail_count;
        }
        else if (target_role == Role::USER) {
            stored_hash = s_user_hash;
            fail_counter = &s_user_fail_count;
        }
        else {
            return false;
        }

        if (fail_counter->load(std::memory_order_acquire) >= MAX_FAIL_COUNT) {
            SecureLogger::logSecurityEvent(
                "AUTH_LOCKED",
                "Authentication locked. Max failures exceeded.");
            return false;
        }

        const std::atomic<uint32_t>& hash_state =
            (target_role == Role::CRYPTO_OFFICER)
            ? s_officer_hash_state
            : s_user_hash_state;

        if (hash_state.load(std::memory_order_acquire) != kProvDone
            || stored_hash == nullptr) {
            return false;
        }

        uint8_t computed[32] = {};
        if (!Compute_Password_Hash(password, password_len, FIXED_SALT, computed)) {
            SecureLogger::logSecurityEvent(
                "AUTH_HMAC_FAIL",
                "Password hash computation failed.");
            (void)fail_counter->fetch_add(1u, std::memory_order_acq_rel);
            return false;
        }

        volatile uint8_t diff = 0u;
        for (size_t i = 0u; i < Role_Auth::HASH_LEN; ++i) {
            // C++20: volatile에 대한 |= 복합 대입 deprecate — 명시 대입 + uint8_t 캐스팅 (-Wconversion)
            diff = static_cast<uint8_t>(
                diff | static_cast<uint8_t>(
                    computed[static_cast<size_t>(i)]
                    ^ stored_hash[static_cast<size_t>(i)]));
        }

        SecureMemory::secureWipe(computed, sizeof(computed));

        if (diff != 0u) {
            (void)fail_counter->fetch_add(1u, std::memory_order_acq_rel);
            SecureLogger::logSecurityEvent(
                "AUTH_FAIL", "Authentication failed.");
            return false;
        }

        s_current_role.store(
            static_cast<uint8_t>(target_role),
            std::memory_order_release);
        fail_counter->store(0u, std::memory_order_release);

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

        if (sv <= 1u) return true;

        if (sv >= 10u && sv <= 15u) {
            return (role == Role::USER || role == Role::CRYPTO_OFFICER);
        }

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
    //  비밀번호 해시 설정 (프로비저닝) — 3상태 CAS (UNINIT→WRITING→DONE)
    // =====================================================================
    bool Role_Auth::Set_Officer_Password_Hash(
        const uint8_t* hash_32) noexcept {
        if (hash_32 == nullptr) return false;

        uint32_t expected = kProvUninit;
        if (!s_officer_hash_state.compare_exchange_strong(
            expected,
            kProvWriting,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
            return false;
        }

        std::memcpy(s_officer_hash, hash_32, 32u);
        s_officer_hash_state.store(kProvDone, std::memory_order_release);
        return true;
    }

    bool Role_Auth::Set_User_Password_Hash(
        const uint8_t* hash_32) noexcept {
        if (hash_32 == nullptr) return false;

        uint32_t expected = kProvUninit;
        if (!s_user_hash_state.compare_exchange_strong(
            expected,
            kProvWriting,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
            return false;
        }

        std::memcpy(s_user_hash, hash_32, 32u);
        s_user_hash_state.store(kProvDone, std::memory_order_release);
        return true;
    }

} // namespace ProtectedEngine
