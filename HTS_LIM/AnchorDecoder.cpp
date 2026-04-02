// =========================================================================
// AnchorDecoder.cpp
// GF(2^8) Cauchy Reed-Solomon 이레이저 복구 디코더 구현부
// Target: Cortex-A55 (CORE-X Pro 메인CPU) / Server
//

#include "AnchorManager.h"

// ARM(STM32) 빌드 차단 — A55/서버 전용 모듈
// __arm__ 단독 → ARMCC(Keil)/IAR/GCC Thumb-only 누락
// A55 (aarch64): 정상 통과
#if (defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
     defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)) && \
    !defined(__aarch64__)
#error "[HTS_FATAL] AnchorDecoder는 A55/서버 전용. STM32 빌드에서 제외하십시오."
#endif

#include "AnchorDecoder.h"

// 실제 사용되는 내부 모듈만 include
#include "HTS_Session_Gateway.hpp"

// HTS_Anti_Glitch, HTS_PUF_Adapter, HTS_Key_Rotator,
// HTS_Secure_Memory, HTS_Anti_Debug, HTS_Secure_Logger,
// HTS_ConstantTimeUtil, HTS_POST_Manager


// ── Self-Contained 표준 헤더 ────────────────────────────────────────
#include <cstddef>
#include <cstdint>
#include <vector>
#include <atomic>
#include <mutex>   // std::call_once (A55 멀티스레드 안전)

namespace ProtectedEngine {

    // =====================================================================
    //  decode_inplace 내 4개 exit 경로에서 동일 소거 블록 4회 복사 제거
    //  소멸자에서 volatile + asm clobber + release fence 1회 자동 실행
    // =====================================================================
    struct RAII_Seed_Wiper {
        volatile uint8_t* ptr;
        size_t size;

        RAII_Seed_Wiper(uint8_t* p, size_t s) noexcept
            : ptr(reinterpret_cast<volatile uint8_t*>(p)), size(s) {
        }

        ~RAII_Seed_Wiper() noexcept {
            for (size_t i = 0u; i < size; ++i) { ptr[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
            std::atomic_thread_fence(std::memory_order_release);
        }

        RAII_Seed_Wiper(const RAII_Seed_Wiper&) = delete;
        RAII_Seed_Wiper& operator=(const RAII_Seed_Wiper&) = delete;
        RAII_Seed_Wiper(RAII_Seed_Wiper&&) = delete;
        RAII_Seed_Wiper& operator=(RAII_Seed_Wiper&&) = delete;
    };

    // =====================================================================
    //  GF(2^8) 고속 연산 엔진 (Decoder 전용)
    //
    //  문제 (A55 멀티스레드):
    //    스레드A: tables_initialized=false 확인 → 테이블 생성 시작
    //    스레드B: tables_initialized=false 확인 → 동시 생성 시작
    //    → 반만 초기화된 테이블로 GF 연산 → 데이터 훼손
    //
    //  std::call_once — C++11 표준 스레드 안전 1회 초기화
    //    A55 Linux: pthread_once 기반, ISR 미사용 → 데드락 위험 없음
    // =====================================================================
    namespace GF8Bit_DEC {
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

        inline uint8_t divide(uint8_t a, uint8_t b) noexcept {
            if (b == 0) return 0;
            if (a == 0) return 0;
            int16_t diff = static_cast<int16_t>(log_table[a]) -
                static_cast<int16_t>(log_table[b]);
            if (diff < 0) diff = static_cast<int16_t>(diff + 255);
            return exp_table[static_cast<uint16_t>(diff)];
        }

        inline uint8_t getCauchyCoefficient(
            uint8_t row, uint8_t col) noexcept {
            uint8_t xor_val = row ^ (col | 0x80u);
            if (xor_val == 0) return 0;
            uint16_t idx = static_cast<uint16_t>(
                255u - log_table[xor_val]);
            return exp_table[idx];
        }

        bool invertMatrix(std::vector<uint8_t>& matrix, size_t n) noexcept {
            if (n == 0) return false;

            std::vector<uint8_t> aug(n * n * 2, 0);

            const size_t stride = n * 2;

            for (size_t i = 0; i < n; ++i) {
                for (size_t j = 0; j < n; ++j)
                    aug[i * stride + j] = matrix[i * n + j];
                aug[i * stride + n + i] = 1;
            }

            for (size_t i = 0; i < n; ++i) {
                if (aug[i * stride + i] == 0) {
                    bool swapped = false;
                    for (size_t k = i + 1; k < n; ++k) {
                        if (aug[k * stride + i] != 0) {
                            for (size_t j = 0; j < stride; ++j) {
                                const uint8_t tmp = aug[i * stride + j];
                                aug[i * stride + j] = aug[k * stride + j];
                                aug[k * stride + j] = tmp;
                            }
                            swapped = true;
                            break;
                        }
                    }
                    if (!swapped) return false;
                }

                const uint8_t pivot = aug[i * stride + i];
                const uint8_t inv_pivot = divide(1, pivot);
                for (size_t j = 0; j < stride; ++j) {
                    if (aug[i * stride + j] != 0)
                        aug[i * stride + j] =
                        multiply(aug[i * stride + j], inv_pivot);
                }

                for (size_t k = 0; k < n; ++k) {
                    if (k != i && aug[k * stride + i] != 0) {
                        const uint8_t factor = aug[k * stride + i];
                        for (size_t j = 0; j < stride; ++j) {
                            if (aug[i * stride + j] != 0)
                                aug[k * stride + j] ^=
                                multiply(factor, aug[i * stride + j]);
                        }
                    }
                }
            }

            for (size_t i = 0; i < n; ++i) {
                for (size_t j = 0; j < n; ++j)
                    matrix[i * n + j] = aug[i * stride + n + j];
            }
            return true;
        }
    } // namespace GF8Bit_DEC

    // =====================================================================
    //  AnchorDecoder 구현
    // =====================================================================

    AnchorDecoder::AnchorDecoder(AnchorManager& anchorManager) noexcept
        : manager(anchorManager) {
        GF8Bit_DEC::initTables();
    }

    // =====================================================================
    //  엔디안 독립: 비트 시프트 바이트 추출 (HI→LO 고정 순서)
    // =====================================================================
    static uint32_t compute_crc32_(
        const std::vector<uint16_t>& data) noexcept {
        uint32_t crc = 0xFFFFFFFFu;
        for (size_t i = 0; i < data.size(); ++i) {
            const uint16_t word = data[i];
            const uint8_t hi = static_cast<uint8_t>(word >> 8u);
            const uint8_t lo = static_cast<uint8_t>(word & 0xFFu);
            crc ^= hi;
            for (int b = 0; b < 8; ++b)
                crc = (crc >> 1u) ^ (0xEDB88320u & (~(crc & 1u) + 1u));
            crc ^= lo;
            for (int b = 0; b < 8; ++b)
                crc = (crc >> 1u) ^ (0xEDB88320u & (~(crc & 1u) + 1u));
        }
        return crc ^ 0xFFFFFFFFu;
    }

    // =====================================================================
    //  decode — decode_inplace 래퍼 (기존 API 호환)
    //
    //  독립 구현 (중복 코드)
    //  decode_inplace 호출 → 결과 반환 (DRY 원칙)
    // =====================================================================
    std::vector<uint16_t> AnchorDecoder::decode(
        const std::vector<uint16_t>& brokenData,
        const std::vector<uint16_t>& anchorData) const noexcept {

        std::vector<uint16_t> result;
        if (decode_inplace(brokenData, anchorData, result) == SECURE_TRUE) {
            return result;
        }
        return {};
    }

    //  decode()가 decode_inplace 래퍼로 리팩토링 완료 → 호출자 0
    //  ~60줄 데드코드 제거, 헤더 선언도 동시 삭제

    // =====================================================================
    //
    //  restoreBlock: restored = brokenChunk (힙 복사) + 수정 + 반환
    //  data가 이미 brokenData의 assign 복사본 → 직접 수정
    //  내부 임시 벡터(erasureIndices, healthy 등)는 E에 비례 (E < 16)
    //  → 메모리 할당 무시 가능
    // =====================================================================
    uint32_t AnchorDecoder::restoreBlock_inplace(
        std::vector<uint16_t>& data,
        const std::vector<uint16_t>& parityChunk) const noexcept {

        const size_t chunkSize = data.size();

        // 1. erasure 위치 검출
        std::vector<size_t> erasureIndices;
        erasureIndices.reserve(chunkSize / 4);
        for (size_t i = 0; i < chunkSize; ++i) {
            if (data[i] == 0xFFFFu) erasureIndices.push_back(i);
        }
        const size_t E = erasureIndices.size();

        if (E == 0) return SECURE_TRUE;  // 이레이저 없음 → 이미 정상
        if (E > parityChunk.size()) return SECURE_FALSE;

        // 2. 건강한 패리티 행 선택
        std::vector<size_t> healthy;
        healthy.reserve(E);
        for (size_t p = 0; p < parityChunk.size(); ++p) {
            if (parityChunk[p] != 0xFFFFu) healthy.push_back(p);
            if (healthy.size() == E) break;
        }
        if (healthy.size() != E) return SECURE_FALSE;

        // 3. 신드롬 계산
        std::vector<uint8_t> syn_hi(E, 0);
        std::vector<uint8_t> syn_lo(E, 0);

        for (size_t k = 0; k < E; ++k) {
            const size_t p = healthy[k];
            uint8_t s_hi = static_cast<uint8_t>(parityChunk[p] >> 8u);
            uint8_t s_lo = static_cast<uint8_t>(
                parityChunk[p] & 0xFFu);
            const uint8_t row = static_cast<uint8_t>(p & 0x7Fu);

            for (size_t i = 0; i < chunkSize; ++i) {
                const uint16_t val = data[i];
                if (val == 0xFFFFu || val == 0) continue;

                const uint8_t col = static_cast<uint8_t>(i & 0x7Fu);
                const uint8_t coef =
                    GF8Bit_DEC::getCauchyCoefficient(row, col);
                const uint8_t v_hi = static_cast<uint8_t>(val >> 8u);
                const uint8_t v_lo = static_cast<uint8_t>(val & 0xFFu);

                if (v_hi != 0)
                    s_hi ^= GF8Bit_DEC::multiply(coef, v_hi);
                if (v_lo != 0)
                    s_lo ^= GF8Bit_DEC::multiply(coef, v_lo);
            }
            syn_hi[k] = s_hi;
            syn_lo[k] = s_lo;
        }

        // 4. Cauchy 복원 행렬 + 역행렬
        std::vector<uint8_t> M(E * E, 0);
        for (size_t r = 0; r < E; ++r) {
            const uint8_t row =
                static_cast<uint8_t>(healthy[r] & 0x7Fu);
            for (size_t c = 0; c < E; ++c) {
                const uint8_t col =
                    static_cast<uint8_t>(erasureIndices[c] & 0x7Fu);
                M[r * E + c] =
                    GF8Bit_DEC::getCauchyCoefficient(row, col);
            }
        }

        if (!GF8Bit_DEC::invertMatrix(M, E)) return SECURE_FALSE;

        // 5. 역행렬 × 신드롬 → 복원 (data 직접 수정)
        for (size_t k = 0; k < E; ++k) {
            uint8_t val_hi = 0;
            uint8_t val_lo = 0;
            for (size_t r = 0; r < E; ++r) {
                const uint8_t m_kr = M[k * E + r];
                if (m_kr != 0) {
                    if (syn_hi[r] != 0)
                        val_hi ^= GF8Bit_DEC::multiply(m_kr, syn_hi[r]);
                    if (syn_lo[r] != 0)
                        val_lo ^= GF8Bit_DEC::multiply(m_kr, syn_lo[r]);
                }
            }
            data[erasureIndices[k]] = static_cast<uint16_t>(
                (static_cast<uint16_t>(val_hi) << 8u) | val_lo);
        }

        return SECURE_TRUE;
    }

    // =====================================================================
    //
    //  4개 exit 경로마다 동일한 volatile+asm+fence 소거 블록 복사
    //  RAII_Seed_Wiper 소멸자에서 1회 자동 소거
    //        경로 추가 시 소거 누락 위험 원천 차단
    // =====================================================================
    uint32_t AnchorDecoder::decode_inplace(
        const std::vector<uint16_t>& brokenData,
        const std::vector<uint16_t>& anchorData,
        std::vector<uint16_t>& out) const noexcept {

        out.clear();
        if (brokenData.empty() || anchorData.empty()) return SECURE_FALSE;

        static constexpr size_t MAX_SEED = 64u;
        uint8_t masterSeed[MAX_SEED] = {};

        RAII_Seed_Wiper seed_wiper(masterSeed, MAX_SEED);

        const size_t mseed_len =
            Session_Gateway::Get_Master_Seed_Raw(masterSeed, MAX_SEED);
        if (mseed_len == 0u) {
            Session_Gateway::Trigger_Hardware_Trap(
                "Unauthorized Data Plane Access (Decoder)");
            return SECURE_FALSE;
        }

        const size_t brokenSize = brokenData.size();
        uint64_t chunkAnchorSize =
            manager.calculateAnchorSize(brokenSize);
        if (chunkAnchorSize == 0 && manager.shouldGenerateAnchor())
            chunkAnchorSize = 1;
        if (chunkAnchorSize > 127) chunkAnchorSize = 127;

        if (static_cast<size_t>(chunkAnchorSize) + 2 > anchorData.size()) {
            return SECURE_FALSE;
        }

        // out = brokenData (capacity 재사용 → malloc 0회)
        out.assign(brokenData.begin(), brokenData.end());

        // parityChunk 추출 (E 비례 — 소형)
        std::vector<uint16_t> parityChunk(
            anchorData.begin(),
            anchorData.begin() +
            static_cast<ptrdiff_t>(chunkAnchorSize));

        const uint32_t storedCrc =
            (static_cast<uint32_t>(
                anchorData[static_cast<size_t>(chunkAnchorSize)]) << 16u)
            | anchorData[static_cast<size_t>(chunkAnchorSize) + 1];

        // [1차 검증] Pre-check: 이미 정상
        if (compute_crc32_(out) == storedCrc) {
            return SECURE_TRUE;  // seed_wiper 소멸자: masterSeed 자동 소거
        }

        // RS 복원 — out 직접 수정
        if (restoreBlock_inplace(out, parityChunk) != SECURE_TRUE) {
            out.clear();
            return SECURE_FALSE;  // seed_wiper 소멸자: masterSeed 자동 소거
        }

        // [2차 검증] Post-check: 복원 결과 무결성
        if (compute_crc32_(out) != storedCrc) {
            out.clear();
            return SECURE_FALSE;  // seed_wiper 소멸자: masterSeed 자동 소거
        }

        return SECURE_TRUE;  // seed_wiper 소멸자: masterSeed 자동 소거
    }

} // namespace ProtectedEngine
