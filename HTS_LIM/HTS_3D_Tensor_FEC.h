#pragma once
// =========================================================================
// HTS_3D_Tensor_FEC.h
// B-CDMA DIOC 항재밍 코어 + LTE HARQ 시뮬레이션 — 공개 인터페이스
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB) / PC
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  이 파일은 2개 계층으로 구성됩니다:
//
//  [Layer 1] ProtectedEngine::HTS16_DIOC_Core
//   — Dual Independent Optimal Code + OS-CFAR 물리 계층 항재밍 코어
//   — PSL=4 최적 균형 코드북 64개 + ARX128 CSPRNG
//   — I/Q 독립 코드 배정 → 가짜 피크 확률 제곱 감소
//   — ⚠ 현재 .cpp는 PC 시뮬레이션 전용 (ARM 빌드 제외)
//   — ARM 실장: HTS64_Native_ECCM_Core 참조
//
//  [Layer 2] HTS_Engine (PC 시뮬레이션 전용)
//   — LTE HARQ 시뮬레이션, Text Codec, CRC16, Tensor FEC
//   — ARM 빌드에서는 이 네임스페이스를 사용하지 마십시오
//   — #if !defined(HTS_3D_ARM_EXCLUDE) 가드로 ARM 노출 차단
//
//  [사용법 — HTS16_DIOC_Core]       
//   1. 생성: HTS16_DIOC_Core(seed) — seed=0 시 0xDEADBEEF 대체
//   2. 송신: Transmit_4Bit(data_4bit) → SparseChip[16] I/Q 독립 극성
//   3. 수신: Decode_4Bit(rx_I, rx_Q) → 복호된 4비트 (실패 시 -1)
//   4. TX/RX 간 PRNG 동기: 동일 seed + 동일 호출 순서 필수
//
//  [메모리 요구량]
//   sizeof(HTS16_DIOC_Core) ≈ 264B (impl_buf_[256] + impl_valid_ + padding)
//   Impl(SRAM In-Place): arx_state[4] = 16B — placement new, 힙 할당 0회
//       
//  [보안 설계]
//   arx_state: Impl 소멸자에서 보안 소거 (128비트 PRNG 키 잔존 방지)
//   impl_buf_: 소멸자에서 SecWipe — Impl 전체 이중 소거
//   복사/이동: = delete (PRNG 상태 복제 원천 차단)
//
//  [양산 수정 이력 — 세션 5: 10건 + BUG-15]
//   BUG-01~09 (arx_state 소거, Pimpl, 헤더 분리, copy/move,
//             noexcept, rotl32 가드, Self-Contained, nodiscard, 이중 가드)
//   BUG-10 (Cognitive CFAR 이중 모드 — 광대역 재밍 통신 생존)
//   BUG-11~14 (나눗셈 제거, SecWipe, idx_Q, Soft_Tensor_FEC 방어)
//   BUG-15 [CRIT] unique_ptr + make_unique + try-catch → placement new
//          · impl_buf_[256] alignas(8) — uint32_t[4] 정렬 수용
//          · make_unique 예외 경로 및 try-catch 완전 제거
//          · 힙 OOM 위험 원천 제거 / 결정론적 SRAM 배치 보장
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>
#include <array>

// =========================================================================
//  [Layer 2] HTS_Engine — PC 시뮬레이션 전용
//  [BUG-03] ARM 빌드에서 <random>, <string> 등 STL 헤더 전파 차단
// =========================================================================
#if !defined(__arm__) && !defined(__TARGET_ARCH_ARM) && \
    !defined(__TARGET_ARCH_THUMB) && !defined(__ARM_ARCH)

#include <vector>
#include <string>
#include <random>

namespace HTS_Engine {

    class Text_Codec {
    public:
        static std::vector<double> String_To_Bits(const std::string& text);
        static std::string Bits_To_String(const std::vector<double>& bits);
    };

    class CRC16 {
    public:
        static std::vector<double> Append(const std::vector<double>& data);
        static bool Check(const std::vector<double>& data_with_crc);
    private:
        static uint16_t compute(const std::vector<double>& data);
    };

    class Tensor_Interleaver {
    public:
        explicit Tensor_Interleaver(size_t dim = 64);
        size_t Get_Size() const;
        std::vector<double> Interleave(
            const std::vector<double>& input) const;
        std::vector<double> Deinterleave(
            const std::vector<double>& input) const;

        // ── [OPT-3] Buffer-reuse API (HARQ 루프 힙 할당 제거) ──
        void Interleave_To(const std::vector<double>& in,
            std::vector<double>& out) const;
        void Deinterleave_To(const std::vector<double>& in,
            std::vector<double>& out) const;

        // ── [BUG-21] ARM Raw API (int8_t, zero-heap) ──
        //  순수 인덱스 치환 → int8_t(±1) 안전
        //  in/out 크기 = min(input_len, dim³)
        size_t Interleave_Raw(const int8_t* in, size_t in_len,
            int8_t* out, size_t out_max) const noexcept;
        size_t Deinterleave_Raw(const int8_t* in, size_t in_len,
            int8_t* out, size_t out_max) const noexcept;
    private:
        size_t dim;
        size_t total_size;
    };

    class Soft_Tensor_FEC {
    public:
        std::vector<double> Encode(
            const std::vector<double>& bits,
            unsigned int frame_seed) const;
        std::vector<double> Decode_Soft(
            const std::vector<double>& tensor,
            size_t num_bits,
            unsigned int frame_seed) const;

        // ── [BUG-21] ARM Raw API (int8_t ±1, zero-heap) ──
        //  Tag()는 ±1만 반환 → bits[i] * Tag() = ±1 × ±1 = ±1
        //  int8_t 안전. out_max가 TENSOR_SIZE를 대체 (ARM 축소용)
        //  npb = min(out_max / n_bits, TENSOR_SIZE / n_bits)
        //  반환값 = 실제 출력 크기
        size_t Encode_Raw(const int8_t* bits, size_t n_bits,
            int8_t* out, size_t out_max,
            unsigned int frame_seed) const noexcept;

        // ── [OPT-3] Buffer-reuse API ──
        void Encode_To(const std::vector<double>& bits,
            unsigned int frame_seed,
            std::vector<double>& out) const;
        void Decode_Soft_To(const std::vector<double>& tensor,
            size_t num_bits, unsigned int frame_seed,
            std::vector<double>& out) const;

    private:
        static constexpr size_t TENSOR_SIZE = 262144;
        static double Tag(unsigned int seed, size_t index);
        // [BUG-21] int8_t 버전 (±1 반환)
        static int8_t Tag_i8(unsigned int seed, size_t index) noexcept;
    };

    class LTE_Channel {
    public:
        static constexpr double JS_DB = 50.0;
        static constexpr int    NUM_CHIPS = 128;
        static constexpr double EMP_RATE = 0.03;
        static constexpr double EMP_AMP = 99999.0;
        static std::vector<double> Transmit(
            const std::vector<double>& tensor, std::mt19937& rng);
        // [OPT-3] Buffer-reuse
        static void Transmit_To(const std::vector<double>& tensor,
            std::mt19937& rng, std::vector<double>& out);
    };

    class LTE_HARQ_Controller {
    public:
        static constexpr int    MTU = 512;
        static constexpr int    CRC_BITS = 16;
        static constexpr int    REP_FACTOR = 5;
        static constexpr int    MAX_HARQ = 12;
        static constexpr double HARQ_RTT_MS = 8.0;
        static constexpr int    PROTECTED_BITS = MTU / REP_FACTOR;
        static constexpr int    INFO_PER_BLOCK = PROTECTED_BITS - CRC_BITS;

        struct BlockResult {
            std::vector<double> info_bits;
            int    harq_rounds = 0;
            bool   success = false;
            double latency_ms = 0.0;
        };

        static BlockResult TransmitBlock(
            const std::vector<double>& info_bits,
            unsigned int block_seed,
            Soft_Tensor_FEC& fec,
            Tensor_Interleaver& interleaver,
            std::mt19937& rng,
            int block_id);
    };

    void Print_LTE_Analysis();

} // namespace HTS_Engine

#endif // !ARM — Layer 2 PC 전용 끝

// =========================================================================
//  [Layer 1] ProtectedEngine::HTS16_DIOC_Core
//  Dual Independent Optimal Code + OS-CFAR 물리 계층 항재밍 코어
// =========================================================================
namespace ProtectedEngine {

    class HTS16_DIOC_Core {
    public:
        /// @brief DIOC 코어 생성 (128비트 ARX PRNG 초기화)
        /// @param seed  32비트 시드 (0 시 0xDEADBEEF 대체)
        /// @note  TX/RX 동일 seed 필수 (PRNG 동기)
        explicit HTS16_DIOC_Core(uint32_t seed) noexcept;

        /// @brief 소멸자 — arx_state 보안 소거 후 impl_buf_ SecWipe
        ~HTS16_DIOC_Core() noexcept;

        /// PRNG 상태 복제 원천 차단
        HTS16_DIOC_Core(const HTS16_DIOC_Core&) = delete;
        HTS16_DIOC_Core& operator=(const HTS16_DIOC_Core&) = delete;
        HTS16_DIOC_Core(HTS16_DIOC_Core&&) = delete;
        HTS16_DIOC_Core& operator=(HTS16_DIOC_Core&&) = delete;

        struct SparseChip {
            uint16_t slot_index;
            int8_t   polarity_I;  ///< I채널 극성 (+1/-1)
            int8_t   polarity_Q;  ///< Q채널 극성 (+1/-1, I와 독립)
        };

        /// @brief DIOC 4비트 송신 (I/Q 독립 최적 코드 배정)
        /// @param data_4bit  4비트 데이터 (0~15)
        /// @return 16칩 SparseChip 배열 (슬롯 인덱스 + I/Q 극성)
        [[nodiscard]]
        std::array<SparseChip, 16> Transmit_4Bit(
            uint8_t data_4bit) noexcept;

        /// @brief DIOC 4비트 수신 (OS-CFAR + 16-회전 상관기)
        /// @param rx_universe_I  I채널 1024슬롯 수신 배열 (nullptr 불가)
        /// @param rx_universe_Q  Q채널 1024슬롯 수신 배열 (nullptr 불가)
        /// @return 0~15: 복호 성공, -1: 유효 칩 부족 (재밍 과다)
        [[nodiscard]]
        int16_t Decode_4Bit(
            const int16_t* rx_universe_I,
            const int16_t* rx_universe_Q) noexcept;

    private:
        // ── [BUG-15] Pimpl In-Place Storage (zero-heap) ──────────────
        // Impl = arx_state[4](16B) + static methods (데이터 없음)
        // alignof(Impl) = 4 (uint32_t) → alignas(8) 안전 초과 정렬
        static constexpr size_t IMPL_BUF_SIZE = 256u;
        static constexpr size_t IMPL_BUF_ALIGN = 8u;

        struct Impl;  ///< ARX PRNG + 코드북 인덱스 은닉 (ABI 안정성 보장)

        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        bool impl_valid_ = false;  ///< placement new 성공 여부

        /// @brief impl_buf_에서 Impl 포인터 반환 (컴파일 타임 크기·정렬 검증 포함)
        Impl* get_impl() noexcept;
        /// @overload
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine