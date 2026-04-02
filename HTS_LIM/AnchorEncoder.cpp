// =========================================================================
// AnchorEncoder.cpp
// GF(2^8) Cauchy Reed-Solomon 인코더 구현부
// Target: Cortex-A55 (CORE-X Pro 메인CPU) / Server
//

#include "AnchorManager.h"

// ARM(STM32) 빌드 차단 — A55/서버 전용 모듈
#if (defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
     defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)) && \
    !defined(__aarch64__)
#error "[HTS_FATAL] AnchorEncoder는 A55/서버 전용. STM32 빌드에서 제외하십시오."
#endif

#include "AnchorEncoder.h"

// 실제 사용되는 내부 모듈만 include
#include "HTS_Session_Gateway.hpp"

// HTS_Entropy_Monitor, HTS_Anti_Glitch, HTS_PUF_Adapter,
// HTS_Key_Rotator, HTS_Secure_Memory, HTS_Anti_Debug,
// HTS_Secure_Logger, HTS_POST_Manager — 사용처 0건


// ── Self-Contained [BUG-08] ─────────────────────────────────────────
#include <cstddef>
#include <cstdint>
#include <vector>
#include <atomic>
#include <mutex>   // [BUG-18] std::call_once (A55 멀티스레드 안전)

namespace ProtectedEngine {
    // =====================================================================
    //  masterSeed 보안 소거 RAII
    // =====================================================================
    struct RAII_Seed_Wiper_ENC {
        volatile uint8_t* ptr;
        size_t size;

        RAII_Seed_Wiper_ENC(uint8_t* p, size_t s) noexcept
            : ptr(reinterpret_cast<volatile uint8_t*>(p)), size(s) {
        }

        ~RAII_Seed_Wiper_ENC() noexcept {
            for (size_t i = 0u; i < size; ++i) { ptr[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
            std::atomic_thread_fence(std::memory_order_release);
        }

        RAII_Seed_Wiper_ENC(const RAII_Seed_Wiper_ENC&) = delete;
        RAII_Seed_Wiper_ENC& operator=(const RAII_Seed_Wiper_ENC&) = delete;
        RAII_Seed_Wiper_ENC(RAII_Seed_Wiper_ENC&&) = delete;
        RAII_Seed_Wiper_ENC& operator=(RAII_Seed_Wiper_ENC&&) = delete;
    };

    // =====================================================================
    //  GF(2^8) 고속 연산 엔진
    // =====================================================================
    namespace GF8Bit_ENC {
        static uint8_t exp_table[512];
        static uint8_t log_table[256];
        static std::once_flag tables_init_flag;

        static void initTablesImpl() noexcept {
            uint16_t x = 1;
            for (int i = 0; i < 255; ++i) {
                exp_table[i] = static_cast<uint8_t>(x);
                exp_table[i + 255] = static_cast<uint8_t>(x);
                log_table[static_cast<uint8_t>(x)] = static_cast<uint8_t>(i);
                x = static_cast<uint16_t>(
                    (x << 1) ^ ((x & 0x80u) ? 0x11Bu : 0u));
            }
            exp_table[510] = 1;
            log_table[0] = 0;
        }

        void initTables() noexcept {
            std::call_once(tables_init_flag, initTablesImpl);
        }

        inline uint8_t multiply(uint8_t a, uint8_t b) noexcept {
            if (a == 0 || b == 0) return 0;
            uint16_t idx = static_cast<uint16_t>(log_table[a]) +
                static_cast<uint16_t>(log_table[b]);
            return exp_table[idx];
        }

        // 현재 row∈[0,127] col∈[0,127] → bit7 항상 다름 → xor_val≥128
        // 하지만 호출자 변경 시 UB 방지를 위한 방어적 프로그래밍
        inline uint8_t getCauchyCoefficient(
            uint8_t row, uint8_t col) noexcept {
            uint8_t xor_val = row ^ (col | 0x80u);
            if (xor_val == 0) return 0;  // 1/0 = 정의 불가 → 0 반환
            uint16_t idx = static_cast<uint16_t>(
                255u - log_table[xor_val]);
            return exp_table[idx];
        }
    } // namespace GF8Bit_ENC

    // =====================================================================
    //  AnchorEncoder 구현
    // =====================================================================

    AnchorEncoder::AnchorEncoder(AnchorManager& anchorManager) noexcept
        : manager(anchorManager) {
        GF8Bit_ENC::initTables();
    }

    // =====================================================================
    //  encode — RS 패리티 + CRC-32 생성
    //
    //  빈 입력/세션 미초기화/OOM 시 빈 벡터 반환
    //  상위 파이프라인(TensorCodec)이 빈 앵커를 감지하여 재전송 요청
    // =====================================================================
    std::vector<uint16_t> AnchorEncoder::encode(
        const std::vector<uint16_t>& originalData) const noexcept {

        if (originalData.empty()) return {};
        if (!manager.shouldGenerateAnchor()) return {};

        static constexpr size_t MAX_SEED = 64u;
        uint8_t masterSeed[MAX_SEED] = {};
        RAII_Seed_Wiper_ENC seed_wiper(masterSeed, MAX_SEED);
        const size_t mseed_len =
            Session_Gateway::Get_Master_Seed_Raw(masterSeed, MAX_SEED);
        if (mseed_len == 0u) {
            Session_Gateway::Trigger_Hardware_Trap(
                "Unauthorized Data Plane Access (Encoder)");
            return {};
        }

        const size_t originalSize = originalData.size();
        uint64_t chunkAnchorSize =
            manager.calculateAnchorSize(originalSize);
        if (chunkAnchorSize == 0 && manager.shouldGenerateAnchor())
            chunkAnchorSize = 1;
        if (chunkAnchorSize > 127) chunkAnchorSize = 127;

        std::vector<uint16_t> anchorData = generateParityBlock(
            originalData, static_cast<size_t>(chunkAnchorSize));

        if (anchorData.empty()) return {};

        // CRC-32 엔디안 독립: 비트 시프트 바이트 추출
        {
            uint32_t crc = 0xFFFFFFFFu;
            for (size_t i = 0; i < originalSize; ++i) {
                const uint16_t word = originalData[i];
                const uint8_t hi = static_cast<uint8_t>(word >> 8u);
                const uint8_t lo = static_cast<uint8_t>(word & 0xFFu);

                crc ^= hi;
                for (int b = 0; b < 8; ++b)
                    crc = (crc >> 1u) ^ (0xEDB88320u & (~(crc & 1u) + 1u));
                crc ^= lo;
                for (int b = 0; b < 8; ++b)
                    crc = (crc >> 1u) ^ (0xEDB88320u & (~(crc & 1u) + 1u));
            }
            crc ^= 0xFFFFFFFFu;

            anchorData.push_back(
                static_cast<uint16_t>((crc >> 16u) & 0xFFFFu));
            anchorData.push_back(
                static_cast<uint16_t>(crc & 0xFFFFu));
        }

        return anchorData;
    }

    // =====================================================================
    //  generateParityBlock — Cauchy RS 패리티 생성
    //
    //  row/col: &0x7F → GF(2^8) Cauchy 행렬 인덱스 제한 (0~127)
    //  데이터 128+ 시 col 래핑 → 동일 Cauchy 계수 재사용 (약간의 코드 약화)
    //  → 실용적으로 TensorCodec의 최대 라인 = 64 → 127 이내 안전
    // =====================================================================
    std::vector<uint16_t> AnchorEncoder::generateParityBlock(
        const std::vector<uint16_t>& dataChunk,
        size_t anchorSize) const noexcept {

        std::vector<uint16_t> parity(anchorSize, 0);
        const size_t dataSize = dataChunk.size();

        for (size_t i = 0; i < anchorSize; ++i) {
            uint8_t p_hi = 0;
            uint8_t p_lo = 0;
            const uint8_t row = static_cast<uint8_t>(i & 0x7Fu);

            for (size_t j = 0; j < dataSize; ++j) {
                const uint16_t word = dataChunk[j];
                if (word == 0) continue;

                const uint8_t d_hi =
                    static_cast<uint8_t>(word >> 8u);
                const uint8_t d_lo =
                    static_cast<uint8_t>(word & 0xFFu);
                const uint8_t col =
                    static_cast<uint8_t>(j & 0x7Fu);
                const uint8_t coef =
                    GF8Bit_ENC::getCauchyCoefficient(row, col);

                if (d_hi != 0)
                    p_hi ^= GF8Bit_ENC::multiply(coef, d_hi);
                if (d_lo != 0)
                    p_lo ^= GF8Bit_ENC::multiply(coef, d_lo);
            }

            parity[i] = static_cast<uint16_t>(
                (static_cast<uint16_t>(p_hi) << 8u) | p_lo);
        }
        return parity;
    }

} // namespace ProtectedEngine
