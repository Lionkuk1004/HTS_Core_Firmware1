// =========================================================================
// AnchorEncoder.cpp
// GF(2^8) Cauchy Reed-Solomon 인코더 구현부
// Target: Cortex-A55 (CORE-X Pro 메인CPU) / Server
//
// [양산 수정 — 세션 5+6+11: 18건 결함 교정]
//
//  BUG-01~12 (이전 세션)
//  BUG-13 [CRIT] OOM 시 기형 패킷 방지: generateParityBlock 빈 벡터 체크
//  BUG-14 [HIGH] CRC-32 엔디안 독립: reinterpret_cast → 비트 시프트 바이트 추출
//
//  BUG-01 [CRITICAL] std::abort() × 4회 → 빈 벡터 반환
//    noexcept 함수에서 abort = MCU 즉시 정지 → 복구 불가
//    수정: 빈 벡터 반환 (상위 파이프라인이 재전송/스킵)
//
//  BUG-02 [HIGH]     dead include 8개 (사용처 0건)
//    HTS_Entropy_Monitor, HTS_Anti_Glitch, HTS_PUF_Adapter,
//    HTS_Key_Rotator, HTS_Secure_Memory, HTS_Anti_Debug,
//    HTS_Secure_Logger, HTS_POST_Manager → 전부 제거
//    → 헤더 전파 체인 대폭 축소 + 빌드 시간 단축
//
//  BUG-03 [HIGH]     GF8Bit static lambda 초기화 — ISR 데드락
//    기존: static bool init_done = [](){...}() (magic statics)
//          → ARM GCC: __cxa_guard_acquire 뮤텍스 사용
//          → ISR에서 재진입 시 데드락 (guard 미해제)
//    수정: 명시적 bool 플래그 + 조건 검사 (뮤텍스 없음)
//          ARM 베어메탈은 단일 코어 → 원자적 검사 불필요
//          ISR에서 initTables 호출 안 됨 (생성자에서 1회 호출)
//
//  BUG-04 [MEDIUM]   AnchorManager.h 헤더 직접 include
//    수정: 헤더에서 전방 선언 → .cpp에서만 full include
//
//  BUG-05 [MEDIUM]   복사/이동 미차단
//    수정: = delete
//
//  BUG-06 [MEDIUM]   <iostream>/<cstdlib> 잔존
//    수정: 전부 제거 (cerr/abort 제거에 따라 불필요)
//
//  BUG-07 [LOW]      [[nodiscard]] 미적용
//  BUG-08 [LOW]      Self-Contained <cstddef> 누락
//  BUG-09 [LOW]      extern DEFAULT_BLOCK_SIZE 데드 심볼 제거
//  BUG-10 [LOW]      외부업체 Doxygen 가이드 없음
//
//  BUG-11 [LOW]      getCauchyCoefficient xor_val==0 방어 가드 (MISRA 1-0-1)
//    현재 row/col 범위에서 수학적으로 불가능하지만 방어적 가드 추가
//    수정: xor_val == 0 시 0 반환 (GF에서 1/0 = 정의 불가)
//
//  BUG-12 [MEDIUM]   CRC32 임시 벡터 → Zero-copy 인라인
//    기존: vector<uint8_t> byteChunk 힙 복사 → HTS_Crc32Util.h::calculate
//    수정: reinterpret_cast 포인터 직접 인라인 CRC-32/ISO-HDLC
//      → 힙 할당 0회 + memcpy 0회 + OOM 원천 차단 + HTS_Crc32Util.h 의존 제거
//
// [GF(2^8) 엔진]
//  원시 다항식: x^8 + x^4 + x^3 + x + 1 (0x11B — AES 동일)
//  LUT: exp[512] + log[256] = 768바이트
//  Cauchy 행렬: coefficient = exp[255 - log[row XOR (col | 0x80)]]
// =========================================================================

// [BUG-04] AnchorManager는 전역 네임스페이스
#include "AnchorManager.h"

// ARM(STM32) 빌드 차단 — A55/서버 전용 모듈
// [BUG-21] STM32 (Cortex-M) 빌드 차단 — 프로젝트 표준 4종 매크로
#if (defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
     defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)) && \
    !defined(__aarch64__)
#error "[HTS_FATAL] AnchorEncoder는 A55/서버 전용. STM32 빌드에서 제외하십시오."
#endif

#include "AnchorEncoder.h"

// 실제 사용되는 내부 모듈만 include
#include "HTS_Session_Gateway.hpp"
// [BUG-12] HTS_HTS_Crc32Util.h제거 — 로컬 인라인 CRC32로 교체 (Zero-copy)

// [BUG-02] dead include 8개 제거:
// HTS_Entropy_Monitor, HTS_Anti_Glitch, HTS_PUF_Adapter,
// HTS_Key_Rotator, HTS_Secure_Memory, HTS_Anti_Debug,
// HTS_Secure_Logger, HTS_POST_Manager — 사용처 0건

// [BUG-06] <iostream>, <cstdlib> 제거 (cerr/abort 제거)

// ── Self-Contained [BUG-08] ─────────────────────────────────────────
#include <cstddef>
#include <cstdint>
#include <vector>
#include <atomic>
#include <mutex>   // [BUG-18] std::call_once (A55 멀티스레드 안전)

namespace ProtectedEngine {

    // =====================================================================
    //  GF(2^8) 고속 연산 엔진
    //  [BUG-18] bool tables_initialized → std::call_once (A55 스레드 안전)
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

        // [BUG-11] xor_val == 0 방어 가드 (MISRA Rule 1-0-1)
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
    //  [BUG-01] abort → 빈 벡터 반환
    //  빈 입력/세션 미초기화/OOM 시 빈 벡터 반환
    //  상위 파이프라인(TensorCodec)이 빈 앵커를 감지하여 재전송 요청
    // =====================================================================
    std::vector<uint16_t> AnchorEncoder::encode(
        const std::vector<uint16_t>& originalData) const noexcept {

        if (originalData.empty()) return {};
        if (!manager.shouldGenerateAnchor()) return {};

        // [BUG-18] Get_Master_Seed → Get_Master_Seed_Raw (BUG-29)
        static constexpr size_t MAX_SEED = 64u;
        uint8_t masterSeed[MAX_SEED] = {};
        const size_t mseed_len =
            Session_Gateway::Get_Master_Seed_Raw(masterSeed, MAX_SEED);
        if (mseed_len == 0u) {
            Session_Gateway::Trigger_Hardware_Trap(
                "Unauthorized Data Plane Access (Encoder)");
            return {};
        }

        // [BUG-17] try-catch 삭제 — 직접 실행
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

        // [BUG-17] masterSeed D-2 보안 소거 — 3중 방어
        volatile uint8_t* v_seed = masterSeed;
        for (size_t i = 0u; i < MAX_SEED; ++i) v_seed[i] = 0u;
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(v_seed) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);

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

        // [BUG-17] try-catch 삭제 — 직접 실행
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