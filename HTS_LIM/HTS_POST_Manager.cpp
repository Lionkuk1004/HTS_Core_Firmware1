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

    namespace {
        constexpr uint32_t HEAL_ALU_FAIL = 0x0000A111u;
        constexpr uint32_t HEAL_KAT1_FAIL = 0x0000A112u;
        constexpr uint32_t HEAL_KAT2_FAIL = 0x0000A113u;
        constexpr uint32_t HEAL_POST_BLOCK = 0x0000A1E0u;
        constexpr uint32_t HEAL_CRYPTO_KAT = 0x0000A114u;
        constexpr size_t   KAT_PACKET_SIZE = 40u;
    }

    static std::atomic<bool> g_isOperational{ false };

    // =====================================================================
    //  KAT #1: Parity Recovery Engine
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
            SecureMemory::secureWipe(test_data, sizeof(test_data));
            return true;
        }
        SecureMemory::secureWipe(test_data, sizeof(test_data));
        return false;
    }

    // =====================================================================
    //  KAT #2: Gravity Interpolation Engine
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
    // =====================================================================
    void POST_Manager::executePowerOnSelfTest() noexcept {
        // [H-3] 순차 진단: ALU(SRAM 경로)·Sparse(KAT)·Crypto_KAT(Flash 내 상수/코드 검증)
        //   센서 하드웨어 전용 루프는 별도 모듈 — 여기서는 알고리즘 KAT 중심
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
            return; // 방어: 비정상 복귀 시 POST 진행 차단
        }

        // KAT #1: Parity Recovery
        if (!KAT_Parity_Recovery_Engine()) {
            g_isOperational.store(false, std::memory_order_release);
            Auto_Rollback_Manager::Execute_Self_Healing(HEAL_KAT1_FAIL);
            return; // 방어: 실패 후 정상 상태 복귀 금지
        }

        // KAT #2: Gravity Interpolation
        if (!KAT_Gravity_Interpolation_Engine()) {
            g_isOperational.store(false, std::memory_order_release);
            Auto_Rollback_Manager::Execute_Self_Healing(HEAL_KAT2_FAIL);
            return; // 방어: 실패 후 정상 상태 복귀 금지
        }

        //  KCMVP: ARIA-128 ECB + LEA-128 CTR + HMAC-SHA256 + LSH-256
        //  FIPS:  AES-256 + SHA-256 (HTS_CRYPTO_FIPS/DUAL 빌드 시)
        //  실패 시 → Execute_Self_Healing (암호 기능 전면 차단)
        if (!Crypto_KAT::Run_All_Crypto_KAT()) {
            g_isOperational.store(false, std::memory_order_release);
            Auto_Rollback_Manager::Execute_Self_Healing(HEAL_CRYPTO_KAT);
            return; // 방어: 실패 후 정상 상태 복귀 금지
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
            return; // 방어: 비정상 복귀 시 이후 경로 차단
        }
    }

} // namespace ProtectedEngine
