// =========================================================================
// HTS_Session_Gateway.cpp
// 최상위 보안 세션 컨트롤러 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
//
#include "HTS_Session_Gateway.hpp"
#include "HTS_Secure_Memory.h"
#include "HTS_Secure_Logger.h"
#include "HTS_Auto_Rollback_Manager.hpp"
#include "HTS_PUF_Adapter.h"
#include "HTS_Anti_Debug.h"
#include "HTS_Anti_Glitch.h"
#include "HTS_POST_Manager.h"

#include <atomic>
#include <cstring>

namespace ProtectedEngine {

    // ── [BUG-24] 매직 넘버 상수화 ──
    namespace {
        constexpr uint32_t HEAL_PUF_FAIL = 0xDEAD0000u;  ///< PUF 시드 추출 실패
        constexpr uint32_t HEAL_ALLOC_FAIL = 0xDEAD0001u;  ///< 세션 초기화 실패
        constexpr uint32_t HEAL_TRAP_CODE = 0xFA11FA11u;  ///< 하드웨어 탬퍼 코드
        constexpr uint32_t SESSION_LOCK_MAX_ATTEMPTS = 128u; ///< bounded spin

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
        /// 락 미획득 시 secureWipe — ISR/스레드와의 seed 경쟁 방지 (X-5-1, N-1)
        static inline uint32_t trap_wipe_crit_enter() noexcept {
            uint32_t primask;
            __asm volatile ("MRS %0, PRIMASK\n CPSID I"
                : "=r"(primask) :: "memory");
            return primask;
        }
        static inline void trap_wipe_crit_exit(uint32_t pm) noexcept {
            __asm volatile ("MSR PRIMASK, %0" :: "r"(pm) : "memory");
        }
#else
        static inline uint32_t trap_wipe_crit_enter() noexcept { return 0u; }
        static inline void trap_wipe_crit_exit(uint32_t) noexcept {}
#endif
    }

    static std::atomic<bool> g_Session_Active{ false };
    static std::atomic_flag g_Session_Busy = ATOMIC_FLAG_INIT;

    /// Execute_Self_Healing 진입 직전: g_Session_Busy + g_Session_Active 원자적 해제
    /// @note Open_Session 이 Session_Busy_Guard 를 잡은 채 Init() 실패 시
    ///       noreturn/호스트 대기 경로에서 락이 영구 잠길 수 있어 선행 해제.
    static void session_release_locks_before_fatal() noexcept {
        g_Session_Busy.clear(std::memory_order_release);
        g_Session_Active.store(false, std::memory_order_release);
    }

    // =====================================================================
    //  세션 컨텍스트 — 힙 할당 0 (static 로컬 + 고정 배열)
    // =====================================================================
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

            // PUF 챌린지: 고정 4바이트 (힙 할당 0)
            uint8_t hwChallenge[4] = { 0x01, 0x02, 0x03, 0x04 };

            seed_len = 0;
            if (!PUF_Adapter::getHardwareSeed_Fixed(
                hwChallenge, sizeof(hwChallenge),
                master_seed, MAX_SEED_SIZE, &seed_len)) {
                seed_len = 0;
            }

            if (seed_len == 0) {
                session_release_locks_before_fatal();
                Auto_Rollback_Manager::Execute_Self_Healing(HEAL_PUF_FAIL);
            }

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

    // =====================================================================
    //  세션 싱글톤 — static 객체 (BSS 영초기화)
    // =====================================================================
    static Secure_Session_Context g_Session_Ctx;

    /// 세션 컨텍스트 접근 직렬화 (bounded spin, 힙 0)
    /// @note std::atomic_flag::test_and_set 은 이전 값을 반환한다.
    ///       이전이 clear(false)이면 획득 성공 → 반환 false → !false 로 진입.
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
                    break;
                }
            }
        }

        ~Session_Busy_Guard() noexcept {
            if (locked_) {
                g_Session_Busy.clear(std::memory_order_release);
            }
        }

        Session_Busy_Guard(const Session_Busy_Guard&) = delete;
        Session_Busy_Guard& operator=(const Session_Busy_Guard&) = delete;

        [[nodiscard]] bool locked() const noexcept { return locked_; }
    };

    void Session_Gateway::Open_Session() noexcept {
        // load→Init 사이 ISR 재진입 시 이중 Init 방지
        bool expected = false;
        if (!g_Session_Active.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
            return;  // 이미 활성 또는 다른 컨텍스트가 Init 중
        }

        Session_Busy_Guard guard;
        if (!guard.locked()) {
            g_Session_Active.store(false, std::memory_order_release);
            return;
        }

        g_Session_Ctx.Init();
        if (!g_Session_Ctx.is_valid) {
            // Init 실패: 락 해제 후 self-healing (AIRCR 리셋은 Execute_Self_Healing 내부)
            session_release_locks_before_fatal();
            Auto_Rollback_Manager::Execute_Self_Healing(HEAL_ALLOC_FAIL);
        }
        // CAS에서 이미 true 설정 완료 — 추가 store 불필요
    }

    void Session_Gateway::Close_Session() noexcept {
        Session_Busy_Guard guard;
        if (!guard.locked()) { return; }
        g_Session_Active.store(false, std::memory_order_release);
        g_Session_Ctx.Clean();
    }

    bool Session_Gateway::Is_Session_Active() noexcept {
        Session_Busy_Guard guard;
        if (!guard.locked()) { return false; }
        return g_Session_Active.load(std::memory_order_acquire)
            && g_Session_Ctx.is_valid
            && g_Session_Ctx.seed_len > 0;
    }

    size_t Session_Gateway::Get_Master_Seed_Raw(
        uint8_t* out_buf, size_t buf_size) noexcept {

        if ((out_buf == nullptr) || (buf_size == 0u)) { return 0u; }

        Session_Busy_Guard guard;
        if (!guard.locked()) { return 0u; }

        if (!g_Session_Active.load(std::memory_order_acquire)
            || !g_Session_Ctx.is_valid
            || g_Session_Ctx.seed_len == 0) {
            return 0u;
        }

        const size_t copy_len = (g_Session_Ctx.seed_len < buf_size)
            ? g_Session_Ctx.seed_len : buf_size;
        std::memcpy(out_buf, g_Session_Ctx.master_seed, copy_len);
        return copy_len;
    }

    void Session_Gateway::Trigger_Hardware_Trap(
        const char* reason) noexcept {

        {
            Session_Busy_Guard guard;
            g_Session_Active.store(false, std::memory_order_release);
            if (guard.locked()) {
                g_Session_Ctx.Clean();
            }
            else {
                const uint32_t pm = trap_wipe_crit_enter();
                SecureMemory::secureWipe(
                    g_Session_Ctx.master_seed,
                    sizeof(g_Session_Ctx.master_seed));
                g_Session_Ctx.seed_len = 0u;
                g_Session_Ctx.is_valid = false;
                trap_wipe_crit_exit(pm);
            }
        }

        SecureLogger::logSecurityEvent(
            "HARDWARE_TRAP",
            reason ? reason : "UNKNOWN");

        Auto_Rollback_Manager::Execute_Self_Healing(HEAL_TRAP_CODE);
    }

} // namespace ProtectedEngine
