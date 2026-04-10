// =========================================================================
// HTS_Session_Gateway.cpp
// 최상위 보안 세션 컨트롤러 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
//
#include "HTS_Session_Gateway.hpp"
#include "HTS_Secure_Memory.h"
#include "HTS_Secure_Logger.h"
#include "HTS_SHA256_Bridge.h"
#include "HTS_Auto_Rollback_Manager.hpp"
#include "HTS_Physical_Entropy_Engine.h"
#include "HTS_Anti_Debug.h"
#include "HTS_Anti_Glitch.h"
#include "HTS_POST_Manager.h"

#include <atomic>
#include <cstring>

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#include "HTS_Hardware_Init.h"
#endif
#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace ProtectedEngine {

#if !defined(HTS_SESSION_GATEWAY_SKIP_PHYS_TRUST)
#if defined(HTS_ALLOW_OPEN_DEBUG) || !defined(NDEBUG)
#define HTS_SESSION_GATEWAY_SKIP_PHYS_TRUST 1
#else
#define HTS_SESSION_GATEWAY_SKIP_PHYS_TRUST 0
#endif
#endif

#if HTS_SESSION_GATEWAY_SKIP_PHYS_TRUST == 0 && \
    (defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH))
    [[noreturn]] static void SessionGateway_PhysicalTrust_Fault() noexcept {
        Hardware_Init_Manager::Terminal_Fault_Action();
    }

    static void SessionGateway_AssertPhysicalTrustOrFault() noexcept {
        volatile const uint32_t* const dhcsr =
            reinterpret_cast<volatile const uint32_t*>(ADDR_DHCSR);
        const uint32_t d0 = *dhcsr;
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("dsb sy" ::: "memory");
#endif
        const uint32_t d1 = *dhcsr;
        if (d0 != d1) {
            SessionGateway_PhysicalTrust_Fault();
        }
        if ((d0 & DHCSR_DEBUG_MASK) != 0u) {
            SessionGateway_PhysicalTrust_Fault();
        }
        volatile const uint32_t* const optcr =
            reinterpret_cast<volatile const uint32_t*>(HTS_FLASH_OPTCR_ADDR);
        const uint32_t o0 = *optcr;
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("dsb sy" ::: "memory");
#endif
        const uint32_t o1 = *optcr;
        if (o0 != o1) {
            SessionGateway_PhysicalTrust_Fault();
        }
        const uint32_t rdp = (o0 & HTS_RDP_OPTCR_MASK) >> 8u;
        if (rdp != HTS_RDP_EXPECTED_BYTE_VAL) {
            SessionGateway_PhysicalTrust_Fault();
        }
    }
#else
    static void SessionGateway_AssertPhysicalTrustOrFault() noexcept {}
#endif

    namespace {
        constexpr uint32_t HEAL_ALLOC_FAIL = 0xDEAD0001u;  ///< 세션 초기화 실패
        constexpr uint32_t HEAL_TRAP_CODE = 0xFA11FA11u;  ///< 하드웨어 탬퍼 코드
        constexpr uint32_t SESSION_LOCK_MAX_ATTEMPTS = 128u; ///< bounded spin
        constexpr size_t kDomainCap = 79u;
        constexpr size_t kIkmMax = 1u + MAX_SEED_SIZE + kDomainCap;

        static inline void compiler_memory_fence() noexcept {
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
            _ReadWriteBarrier();
#else
            std::atomic_thread_fence(std::memory_order_acq_rel);
#endif
        }
    }

    static std::atomic<bool> g_Session_Active{ false };
    static std::atomic_flag g_Session_Busy = ATOMIC_FLAG_INIT;

    struct Secure_Session_Context {
        alignas(4) uint8_t master_seed[MAX_SEED_SIZE] = {};
        size_t seed_len = 0;
        bool is_valid = false;

        static_assert(sizeof(master_seed) == MAX_SEED_SIZE,
            "master_seed size mismatch");

        void Init() noexcept {
            AntiDebugManager::checkDebuggerPresence();
            POST_Manager::verifyOperationalState();
            AntiGlitchShield glitchShield;
            glitchShield.unlockSystem();
            glitchShield.verifyCriticalExecution();

            constexpr size_t kHwSeedBytes = 32u;
            static_assert(kHwSeedBytes <= MAX_SEED_SIZE, "master seed capacity");
            static_assert((kHwSeedBytes % 4u) == 0u, "word fill");
            constexpr size_t kHwSeedWords = kHwSeedBytes / 4u;
            uint32_t seed_words[kHwSeedWords];
            for (size_t wi = 0u; wi < kHwSeedWords; ++wi) {
                seed_words[wi] = Physical_Entropy_Engine::Extract_Quantum_Seed();
            }

            uint32_t orv = 0u;
            uint32_t andv = 0xFFFFFFFFu;
            for (size_t wi = 0u; wi < kHwSeedWords; ++wi) {
                orv |= seed_words[wi];
                andv &= seed_words[wi];
            }
            const uint32_t bad_or =
                static_cast<uint32_t>(orv == 0u);
            const uint32_t bad_and =
                static_cast<uint32_t>(andv == 0xFFFFFFFFu);
            if ((bad_or | bad_and) != 0u) {
                SecureMemory::secureWipe(seed_words, sizeof(seed_words));
                SecureMemory::secureWipe(master_seed, sizeof(master_seed));
                seed_len = 0u;
                is_valid = false;
                return;
            }

            std::memcpy(master_seed, seed_words, kHwSeedBytes);
            SecureMemory::secureWipe(seed_words, sizeof(seed_words));
            seed_len = kHwSeedBytes;

            SecureMemory::lockMemory(master_seed, seed_len);
            is_valid = true;
            SecureLogger::logSecurityEvent(
                "SESSION_OPEN",
                "Control Plane: Security Gateway Opened");
        }

        void Clean() noexcept {
            SecureMemory::secureWipe(master_seed, sizeof(master_seed));
            seed_len = 0;
            is_valid = false;
            SecureLogger::logSecurityEvent(
                "SESSION_CLOSE",
                "Control Plane: Security Gateway Closed");
        }
    };

    static Secure_Session_Context g_Session_Ctx;

    class Session_Busy_Guard final {
    private:
        bool locked_;

    public:
        Session_Busy_Guard() noexcept
            : locked_(false)
        {
            for (uint32_t i = 0u; i < SESSION_LOCK_MAX_ATTEMPTS; ++i) {
                if (!g_Session_Busy.test_and_set(std::memory_order_acquire)) {
                    locked_ = true;
                    compiler_memory_fence();
                    break;
                }
            }
        }

        ~Session_Busy_Guard() noexcept {
            if (locked_) {
                compiler_memory_fence();
                g_Session_Busy.clear(std::memory_order_release);
            }
        }

        Session_Busy_Guard(const Session_Busy_Guard&) = delete;
        Session_Busy_Guard& operator=(const Session_Busy_Guard&) = delete;

        [[nodiscard]] bool locked() const noexcept { return locked_; }
    };

    void Session_Gateway::Open_Session() noexcept {
        bool expected = false;
        if (!g_Session_Active.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
            return;
        }

        bool init_ok = false;
        {
            Session_Busy_Guard guard;
            if (static_cast<uint32_t>(guard.locked()) == 0u) {
                g_Session_Active.store(false, std::memory_order_release);
                return;
            }
            g_Session_Ctx.Init();
            init_ok = g_Session_Ctx.is_valid;
        }

        if (static_cast<uint32_t>(init_ok) == 0u) {
            g_Session_Active.store(false, std::memory_order_release);
            Auto_Rollback_Manager::Execute_Self_Healing(HEAL_ALLOC_FAIL);
        }
    }

    void Session_Gateway::Close_Session() noexcept {
        Session_Busy_Guard guard;
        if (static_cast<uint32_t>(guard.locked()) == 0u) { return; }
        g_Session_Ctx.Clean();
        g_Session_Active.store(false, std::memory_order_release);
    }

    bool Session_Gateway::Is_Session_Active() noexcept {
        Session_Busy_Guard guard;
        if (static_cast<uint32_t>(guard.locked()) == 0u) { return false; }
        const uint32_t a = static_cast<uint32_t>(
            g_Session_Active.load(std::memory_order_acquire));
        const uint32_t v = static_cast<uint32_t>(g_Session_Ctx.is_valid);
        const uint32_t z = static_cast<uint32_t>(g_Session_Ctx.seed_len > 0u);
        return (a & v & z) != 0u;
    }

    size_t Session_Gateway::Derive_Session_Material(
        const char* domain_label,
        uint8_t* out_buf,
        size_t out_len) noexcept {

        const uint32_t ok_ptr = static_cast<uint32_t>(out_buf != nullptr);
        const uint32_t ok_len = static_cast<uint32_t>(out_len != 0u);
        if ((ok_ptr & ok_len) == 0u) {
            return 0u;
        }

        const char* dom = domain_label ? domain_label : "";
        size_t dlen = 0u;
        while (dom[dlen] != '\0' && dlen < kDomainCap) {
            ++dlen;
        }

        Session_Busy_Guard guard;
        if (static_cast<uint32_t>(guard.locked()) == 0u) {
            return 0u;
        }

        const uint32_t sa = static_cast<uint32_t>(
            g_Session_Active.load(std::memory_order_acquire));
        const uint32_t sv = static_cast<uint32_t>(g_Session_Ctx.is_valid);
        const uint32_t sz = static_cast<uint32_t>(g_Session_Ctx.seed_len > 0u);
        if ((sa & sv & sz) == 0u) {
            return 0u;
        }

        SessionGateway_AssertPhysicalTrustOrFault();

        const size_t slen = g_Session_Ctx.seed_len;
        if ((1u + slen + dlen) > kIkmMax) {
            return 0u;
        }

        size_t written = 0u;
        for (uint32_t ctr = 0u; written < out_len; ++ctr) {
            uint8_t ikm[kIkmMax];
            size_t bl = 0u;
            ikm[bl++] = static_cast<uint8_t>(ctr & 0xFFu);
            std::memcpy(ikm + bl, g_Session_Ctx.master_seed, slen);
            bl += slen;
            std::memcpy(ikm + bl, dom, dlen);
            bl += dlen;

            uint8_t dig[SHA256_Bridge::DIGEST_LEN];
            if (static_cast<uint32_t>(SHA256_Bridge::Hash(ikm, bl, dig)) == 0u) {
                SecureMemory::secureWipe(out_buf, written);
                SecureMemory::secureWipe(ikm, sizeof(ikm));
                SecureMemory::secureWipe(dig, sizeof(dig));
                return 0u;
            }
            const size_t chunk = (out_len - written < SHA256_Bridge::DIGEST_LEN)
                ? (out_len - written)
                : SHA256_Bridge::DIGEST_LEN;
            std::memcpy(out_buf + written, dig, chunk);
            written += chunk;
            SecureMemory::secureWipe(dig, sizeof(dig));
            SecureMemory::secureWipe(ikm, sizeof(ikm));
            if (ctr >= 255u) {
                break;
            }
        }

        return written;
    }

    void Session_Gateway::Trigger_Hardware_Trap(
        const char* reason) noexcept {

        SessionGateway_AssertPhysicalTrustOrFault();

        {
            Session_Busy_Guard guard;
            if (guard.locked()) {
                g_Session_Ctx.Clean();
            }
            else {
                SecureMemory::secureWipe(
                    g_Session_Ctx.master_seed,
                    sizeof(g_Session_Ctx.master_seed));
                g_Session_Ctx.seed_len = 0u;
                g_Session_Ctx.is_valid = false;
            }
            g_Session_Active.store(false, std::memory_order_release);
        }

        SecureLogger::logSecurityEvent(
            "HARDWARE_TRAP",
            reason ? reason : "UNKNOWN");

        SecureLogger::flushAuditRingForTrap();

        SessionGateway_AssertPhysicalTrustOrFault();

        Auto_Rollback_Manager::Execute_Self_Healing(HEAL_TRAP_CODE);
    }

} // namespace ProtectedEngine
