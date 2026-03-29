// =========================================================================
// HTS_Session_Gateway.cpp
// 최상위 보안 세션 컨트롤러 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// [양산 수정 — 33건]
//
//  ── 기존~세션8 (BUG-01~29) ── (이전 이력 참조)
//  BUG-30 [HIGH] #define HTS_PLATFORM_ARM 하드코딩 → 제거 (ARM 전용 파일)
//  BUG-31 [CRIT] ⑭ PC 코드 물리삭제: mutex/vector/string/cerr/try-catch/
//                socket/Winsock/1:N라우팅/Get_Master_Seed(vector) 전량 제거
//  BUG-32 [LOW]  주석 정합: "/ PC / Server" 제거
//
// [제약] try-catch 0, float/double 0, 힙 0
// =========================================================================
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
                Auto_Rollback_Manager::Execute_Self_Healing(HEAL_PUF_FAIL);
                while (true) {
#if defined(__GNUC__) || defined(__clang__)
                    __asm__ __volatile__("wfi");
#endif
                }
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
    static std::atomic<bool> g_Session_Active{ false };

    void Session_Gateway::Open_Session() noexcept {
        // [BUG-33] TOCTOU 방어: CAS로 원자적 진입 보호
        // load→Init 사이 ISR 재진입 시 이중 Init 방지
        bool expected = false;
        if (!g_Session_Active.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
            return;  // 이미 활성 또는 다른 컨텍스트가 Init 중
        }

        g_Session_Ctx.Init();
        if (!g_Session_Ctx.is_valid) {
            // Init 실패: 플래그 원복 후 self-healing
            g_Session_Active.store(false, std::memory_order_release);
            Auto_Rollback_Manager::Execute_Self_Healing(HEAL_ALLOC_FAIL);
            while (true) {
#if defined(__GNUC__) || defined(__clang__)
                __asm__ __volatile__("wfi");
#endif
            }
        }
        // CAS에서 이미 true 설정 완료 — 추가 store 불필요
    }

    void Session_Gateway::Close_Session() noexcept {
        g_Session_Active.store(false, std::memory_order_release);
        g_Session_Ctx.Clean();
    }

    bool Session_Gateway::Is_Session_Active() noexcept {
        return g_Session_Active.load(std::memory_order_acquire)
            && g_Session_Ctx.is_valid
            && g_Session_Ctx.seed_len > 0;
    }

    size_t Session_Gateway::Get_Master_Seed_Raw(
        uint8_t* out_buf, size_t buf_size) noexcept {

        if (!out_buf || buf_size == 0) return 0;

        if (!g_Session_Active.load(std::memory_order_acquire)
            || !g_Session_Ctx.is_valid
            || g_Session_Ctx.seed_len == 0) {
            return 0;
        }

        const size_t copy_len = (g_Session_Ctx.seed_len < buf_size)
            ? g_Session_Ctx.seed_len : buf_size;
        std::memcpy(out_buf, g_Session_Ctx.master_seed, copy_len);
        return copy_len;
    }

    void Session_Gateway::Trigger_Hardware_Trap(
        const char* reason) noexcept {

        g_Session_Active.store(false, std::memory_order_release);
        g_Session_Ctx.Clean();

        SecureLogger::logSecurityEvent(
            "HARDWARE_TRAP",
            reason ? reason : "UNKNOWN");

        Auto_Rollback_Manager::Execute_Self_Healing(HEAL_TRAP_CODE);
        while (true) {
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("wfi");
#endif
        }
    }

} // namespace ProtectedEngine