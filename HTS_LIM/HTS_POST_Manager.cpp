// =========================================================================
// HTS_POST_Manager.cpp
// FIPS 140-3 / KCMVP Power-On Self-Test (POST) - KAT Validation Manager
// Target: STM32F407 (Cortex-M4)
//
// [Revision - 12 fixes]
//  01~05: iostream removal, namespace, while barrier, noexcept, namespace
//
//  06~10 (Session 8):
//  BUG-06 [CRIT] Execute_Self_Healing( uint64_t) -> (uint32_t)
//  BUG-07 [HIGH] while(true) after [[noreturn]] = dead code -> removed
//  BUG-08 [HIGH] vector<uint32_t> -> fixed array (heap 0, ARM safe)
//  BUG-09 [HIGH] try-catch removed (ARM -fno-exceptions)
//  BUG-10 [MED]  magic numbers -> constexpr
//
//  11~12 (Session 14 — KCMVP/FIPS 이중 인증):
//  BUG-11 [CRIT] 암호 알고리즘 KAT POST 체인 통합
//         · 기존: Parity/Gravity KAT만 실행 → 암호 KAT 0개
//         · 수정: Crypto_KAT::Run_All_Crypto_KAT() 호출 추가
//         · KCMVP: ARIA + LEA + HMAC + LSH KAT
//         · FIPS:  AES + SHA-256 KAT (빌드 프리셋 조건부)
//  BUG-12 [MED]  g_isOperational atomic 이동 (헤더 → cpp 스코프)
//
// [Constraints] try-catch 0, float/double 0, heap 0 (KAT functions)
// =========================================================================
#include "HTS_POST_Manager.h"
#include "HTS_Crypto_KAT.h"     // [BUG-11] 암호 KAT POST 체인 통합
#include "HTS_Sparse_Recovery.h"
#include "HTS_Secure_Logger.h"
#include "HTS_Secure_Memory.h"
#include "HTS_Auto_Rollback_Manager.hpp"
#include <atomic>

namespace ProtectedEngine {

    // [BUG-10] Magic number constants
    namespace {
        constexpr uint32_t HEAL_ALU_FAIL = 0x0000A111u;
        constexpr uint32_t HEAL_KAT1_FAIL = 0x0000A112u;
        constexpr uint32_t HEAL_KAT2_FAIL = 0x0000A113u;
        constexpr uint32_t HEAL_POST_BLOCK = 0x0000A1E0u;
        // [BUG-11] 암호 KAT 실패 코드
        constexpr uint32_t HEAL_CRYPTO_KAT = 0x0000A114u;
        constexpr size_t   KAT_PACKET_SIZE = 40u;
    }

    // [BUG-12] atomic<bool> — ISR/스레드 간 가시성 보장
    static std::atomic<bool> g_isOperational{ false };

    // =====================================================================
    //  KAT #1: Parity Recovery Engine
    //  [BUG-08] vector -> fixed array, [BUG-09] try-catch removed
    // =====================================================================
    bool POST_Manager::KAT_Parity_Recovery_Engine() noexcept {
        uint32_t test_data[KAT_PACKET_SIZE];
        for (size_t i = 0; i < KAT_PACKET_SIZE; ++i) {
            test_data[i] = 100 + static_cast<uint32_t>(i);
        }

        uint64_t dummy_session = 0x1122334455667788ULL;
        uint32_t anchor_interval = 20;

        Sparse_Recovery_Engine::Generate_Interference_Pattern(
            test_data, KAT_PACKET_SIZE, dummy_session, anchor_interval, true);

        // 1 element corrupted
        test_data[5] = 0xFFFFFFFFu;

        RecoveryStats stats;
        bool result = Sparse_Recovery_Engine::Execute_L1_Reconstruction(
            test_data, KAT_PACKET_SIZE, dummy_session,
            anchor_interval, true, false, stats);

        if (result && stats.recovered_by_parity == 1 &&
            stats.recovered_by_gravity == 0 && stats.destroyed_count == 1) {
            // [BUG-11] 스택 잔존 데이터 소거
            SecureMemory::secureWipe(test_data, sizeof(test_data));
            return true;
        }
        // [BUG-11] 실패 경로도 소거
        SecureMemory::secureWipe(test_data, sizeof(test_data));
        return false;
    }

    // =====================================================================
    //  KAT #2: Gravity Interpolation Engine
    //  [BUG-08] vector -> fixed array, [BUG-09] try-catch removed
    // =====================================================================
    bool POST_Manager::KAT_Gravity_Interpolation_Engine() noexcept {
        uint32_t test_data[KAT_PACKET_SIZE];
        for (size_t i = 0; i < KAT_PACKET_SIZE; ++i) {
            test_data[i] = 200 + static_cast<uint32_t>(i);
        }

        uint64_t dummy_session = 0xAABBCCDDEEFF1122ULL;
        uint32_t anchor_interval = 20;

        Sparse_Recovery_Engine::Generate_Interference_Pattern(
            test_data, KAT_PACKET_SIZE, dummy_session, anchor_interval, true);

        // 3 consecutive corrupted
        test_data[25] = 0xFFFFFFFFu;
        test_data[26] = 0xFFFFFFFFu;
        test_data[27] = 0xFFFFFFFFu;

        RecoveryStats stats;
        bool result = Sparse_Recovery_Engine::Execute_L1_Reconstruction(
            test_data, KAT_PACKET_SIZE, dummy_session,
            anchor_interval, true, false, stats);

        if (result && stats.recovered_by_gravity == 3 &&
            stats.recovered_by_parity == 0) {
            SecureMemory::secureWipe(test_data, sizeof(test_data));
            return true;
        }
        SecureMemory::secureWipe(test_data, sizeof(test_data));
        return false;
    }

    // =====================================================================
    //  executePowerOnSelfTest
    //  [BUG-06] Self_Healing(uint32_t) - true removed
    //  [BUG-07] while(true) after [[noreturn]] removed (dead code)
    // =====================================================================
    void POST_Manager::executePowerOnSelfTest() noexcept {
        SecureLogger::logSecurityEvent(
            "POST_START",
            "FIPS 140-3 Power-On Self-Test (KAT) initiated.");

        // ALU basic sanity
        volatile uint32_t aluTest = 0u;
        aluTest += 1u;
        if (aluTest != 1u) {
            g_isOperational.store(false, std::memory_order_release);
            Auto_Rollback_Manager::Execute_Self_Healing(HEAL_ALU_FAIL);
            // [[noreturn]] - never reaches here
        }

        // KAT #1: Parity Recovery
        if (!KAT_Parity_Recovery_Engine()) {
            g_isOperational.store(false, std::memory_order_release);
            Auto_Rollback_Manager::Execute_Self_Healing(HEAL_KAT1_FAIL);
        }

        // KAT #2: Gravity Interpolation
        if (!KAT_Gravity_Interpolation_Engine()) {
            g_isOperational.store(false, std::memory_order_release);
            Auto_Rollback_Manager::Execute_Self_Healing(HEAL_KAT2_FAIL);
        }

        // [BUG-11] KAT #3: 암호 알고리즘 KAT (KCMVP + FIPS)
        //  KCMVP: ARIA-128 ECB + LEA-128 CTR + HMAC-SHA256 + LSH-256
        //  FIPS:  AES-256 + SHA-256 (HTS_CRYPTO_FIPS/DUAL 빌드 시)
        //  실패 시 → Execute_Self_Healing (암호 기능 전면 차단)
        if (!Crypto_KAT::Run_All_Crypto_KAT()) {
            g_isOperational.store(false, std::memory_order_release);
            Auto_Rollback_Manager::Execute_Self_Healing(HEAL_CRYPTO_KAT);
        }

        g_isOperational.store(true, std::memory_order_release);
        SecureLogger::logSecurityEvent(
            "POST_PASS",
            "All Known Answer Tests passed. Module is OPERATIONAL.");
    }

    // =====================================================================
    //  verifyOperationalState
    // =====================================================================
    void POST_Manager::verifyOperationalState() noexcept {
        if (!g_isOperational.load(std::memory_order_acquire)) {
            SecureLogger::logSecurityEvent(
                "POST_BLOCK",
                "I/O blocked. Module is in ERROR STATE.");
            Auto_Rollback_Manager::Execute_Self_Healing(HEAL_POST_BLOCK);
            // [[noreturn]] - never reaches here
        }
    }

} // namespace ProtectedEngine