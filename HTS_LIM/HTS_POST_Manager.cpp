// =========================================================================
// HTS_POST_Manager.cpp
// FIPS 140-3 / KCMVP Power-On Self-Test (POST) - KAT Validation Manager
// Target: STM32F407 (Cortex-M4)
//
// [Constraints] try-catch 0, float/double 0, heap 0 (KAT functions)
//  POST → Crypto_KAT::Run_All_Crypto_KAT (KCMVP/FIPS 프리셋)
//
//  B-CDMA 검수 요약 (본 TU)
//   ① LTO/TBAA: TBAA 위반형 reinterpret 없음. 키 버퍼 소거는 SecureMemory::secureWipe
//      (Force_Secure_Wipe: noinline + volatile 소거 + fence, HTS_Secure_Memory.cpp D-2).
//   ② ISR: PRIMASK/cpsid 없음. POST는 부팅 직후·메인 컨텍스트 가정; 장시간 KAT는
//      통합 측에서 IRQ 우선순위·WDT·UART 오버런과 함께 설계 [요검토: 스케줄].
//   ③ Flash/BOR: 본 파일은 Flash 프로그램 없음. 실패 시 Auto_Rollback_Manager::
//      Execute_Self_Healing → AIRCR 리셋(플래시 섹터 쓰기 없음). BOR·RDP는 HW_Init.
//   ④ 퓨즈/RDP: RDP Level·JTAG 차단 검증은 HTS_Hardware_Init 등 부팅 계층 책임 [요검토].
// =========================================================================
#include "HTS_POST_Manager.h"
#include "HTS_Crypto_KAT.h"     // 암호 KAT POST 체인
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
        constexpr size_t KAT_TEST_DATA_BYTES = KAT_PACKET_SIZE * sizeof(uint32_t);
        // B-CDMA 통합 기준서 ⑥: 스택 로컬 배열 512B 초과 금지 (KAT 버퍼 사전 검증)
        static_assert(
            KAT_TEST_DATA_BYTES <= 512u,
            "POST KAT buffer must stay <= 512B per B-CDMA ⑥");
    }

    static std::atomic<bool> g_isOperational{ false };

    // =====================================================================
    //  KAT #1: Parity Recovery Engine
    // =====================================================================
    bool POST_Manager::KAT_Parity_Recovery_Engine() noexcept {
        uint32_t test_data[KAT_PACKET_SIZE];
        for (size_t i = 0u; i < KAT_PACKET_SIZE; ++i) {
            test_data[i] = 100u + static_cast<uint32_t>(i);
        }

        constexpr uint64_t DUMMY_SESSION = 0x1122334455667788ULL;
        constexpr uint32_t ANCHOR_INTERVAL = 20u;

        Sparse_Recovery_Engine::Generate_Interference_Pattern(
            test_data, KAT_PACKET_SIZE, DUMMY_SESSION, ANCHOR_INTERVAL, true);

        // 1 element corrupted
        test_data[static_cast<size_t>(5)] = 0xFFFFFFFFu;

        RecoveryStats stats;
        bool result = Sparse_Recovery_Engine::Execute_L1_Reconstruction(
            test_data, KAT_PACKET_SIZE, DUMMY_SESSION,
            ANCHOR_INTERVAL, true, false, stats);

        if (result && stats.recovered_by_parity == size_t{1} &&
            stats.recovered_by_gravity == size_t{0} && stats.destroyed_count == size_t{1}) {
            SecureMemory::secureWipe(test_data, KAT_TEST_DATA_BYTES);
            return true;
        }
        SecureMemory::secureWipe(test_data, KAT_TEST_DATA_BYTES);
        return false;
    }

    // =====================================================================
    //  KAT #2: Gravity Interpolation Engine
    // =====================================================================
    bool POST_Manager::KAT_Gravity_Interpolation_Engine() noexcept {
        uint32_t test_data[KAT_PACKET_SIZE];
        for (size_t i = 0u; i < KAT_PACKET_SIZE; ++i) {
            test_data[i] = 200u + static_cast<uint32_t>(i);
        }

        constexpr uint64_t DUMMY_SESSION = 0xAABBCCDDEEFF1122ULL;
        constexpr uint32_t ANCHOR_INTERVAL = 20u;

        Sparse_Recovery_Engine::Generate_Interference_Pattern(
            test_data, KAT_PACKET_SIZE, DUMMY_SESSION, ANCHOR_INTERVAL, true);

        // 3 consecutive corrupted
        test_data[static_cast<size_t>(25)] = 0xFFFFFFFFu;
        test_data[static_cast<size_t>(26)] = 0xFFFFFFFFu;
        test_data[static_cast<size_t>(27)] = 0xFFFFFFFFu;

        RecoveryStats stats;
        bool result = Sparse_Recovery_Engine::Execute_L1_Reconstruction(
            test_data, KAT_PACKET_SIZE, DUMMY_SESSION,
            ANCHOR_INTERVAL, true, false, stats);

        if (result && stats.recovered_by_gravity == size_t{3} &&
            stats.recovered_by_parity == size_t{0}) {
            SecureMemory::secureWipe(test_data, KAT_TEST_DATA_BYTES);
            return true;
        }
        SecureMemory::secureWipe(test_data, KAT_TEST_DATA_BYTES);
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
