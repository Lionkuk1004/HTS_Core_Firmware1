// =========================================================================
// HTS_3D_Tensor_FEC.cpp
// B-CDMA DIOC 항재밍 코어 + LTE HARQ 시뮬레이션 구현부
// Target: PC 시뮬레이션 전용 (ARM 빌드 제외)
//
// [양산 수정 — 세션 5+6: 15건 결함 교정]
//
//  BUG-01~10 (이전 세션)
//  BUG-11 [MED]  나눗셈 → 비트마스크 (% 1024 → & 0x3FF, % 64 → & 0x3F)
//  BUG-12 [CRIT] Secure_Wipe_DIOC pragma O0 삭제 → asm clobber + volatile
//  BUG-13 [CRIT] idx_Q % 63 → 비트마스크 + step≥1 보장 (나눗셈 완전 제거)
//  BUG-14 [HIGH] Soft_Tensor_FEC npb=0 방어 (bits > TENSOR_SIZE 시 빈 텐서)
//  BUG-15 [CRIT] unique_ptr + make_unique + try-catch → placement new
//         · impl_buf_[256] alignas(8) 정적 배치
//         · make_unique 예외 경로 및 try-catch 완전 제거
//         · 생성자: ::new(impl_buf_) Impl() 후 arx_state 초기화
//         · 소멸자: = default 제거 → 명시적 p->~Impl() + SecWipe_DIOC
//  BUG-FIX ① Secure_Wipe_DIOC 배리어 seq_cst → release
//         · 소거 완료 가시화 목적 → release fence로 충분
//         · 프로젝트 보안 소거 배리어 정책 통일
//
// =========================================================================
#include "HTS_3D_Tensor_FEC.h"

// [양산 방어] LTE HARQ 시뮬레이션 — PC 전용, ARM 빌드 제외
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#error "[HTS_FATAL] HTS_3D_Tensor_FEC.cpp는 PC 시뮬레이션 전용입니다. ARM 빌드에서 제외하십시오."
#endif

#include "HTS_Channel_Physics.h"

// ── Self-Contained 표준 헤더 [BUG-07] ───────────────────────────────
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <vector>
#include <array>

// PC 전용 헤더
#include <cmath>
#include <bitset>
#include <algorithm>

// [FIX-MEDIUM] iostream/iomanip — PC 시뮬레이션 전용
//  ARM 링크 시 C++ I/O 라이브러리 ~50KB Flash 낭비 방지
#if !defined(__arm__) && !defined(__TARGET_ARCH_ARM)
#include <iomanip>
#include <iostream>
#endif

#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
#include <bit>
#endif

#if defined(_MSC_VER)
#include <intrin.h>  // MSVC: __popcnt
#endif

namespace {

/// @brief 분기 없는 HARQ 라운드 클램핑(가변 /·% 없음)
inline uint32_t FractalHarq_Clamp_U32(uint32_t n, uint32_t cap) noexcept
{
    const uint32_t over = 0u - static_cast<uint32_t>(n > cap);
    return (n & ~over) | (cap & over);
}

} // namespace

// =========================================================================
//  [Layer 2] HTS_Engine — PC 시뮬레이션 (변경 없음)
// =========================================================================

namespace HTS_Engine {

    std::vector<double> Text_Codec::String_To_Bits(const std::string& text) {
        std::vector<double> bits;
        bits.reserve(text.size() * 8);
        for (char c : text) {
            std::bitset<8> b(c);
            for (int i = 7; i >= 0; --i)
                bits.push_back(b[i] ? 1.0 : -1.0);
        }
        return bits;
    }

    std::string Text_Codec::Bits_To_String(
        const std::vector<double>& bits) {
        std::string text;
        for (size_t i = 0u; i + 8u <= bits.size(); i += 8u) {
            std::bitset<8> b;
            for (int j = 0; j < 8; ++j)
                if (bits[i + j] > 0.0) { b.set(7 - j); }
            text += static_cast<char>(b.to_ulong());
        }
        return text;
    }

    uint16_t CRC16::compute(const std::vector<double>& data) {
        uint16_t crc = 0xFFFF;
        for (auto bv : data) {
            uint8_t bit = (bv > 0) ? 1u : 0u;
            if (((crc >> 15) & 1u) ^ bit)
                crc = static_cast<uint16_t>(((crc << 1) ^ 0x1021) & 0xFFFF);
            else
                crc = static_cast<uint16_t>((crc << 1) & 0xFFFF);
        }
        return crc;
    }

    std::vector<double> CRC16::Append(const std::vector<double>& data) {
        uint16_t crc = compute(data);
        std::vector<double> result = data;
        for (int i = 15; i >= 0; --i)
            result.push_back(((crc >> i) & 1u) ? 1.0 : -1.0);
        return result;
    }

    bool CRC16::Check(const std::vector<double>& data_with_crc) {
        if (data_with_crc.size() < 17u) { return false; }
        size_t data_len = data_with_crc.size() - 16u;
        std::vector<double> data_part(
            data_with_crc.begin(),
            data_with_crc.begin() + static_cast<ptrdiff_t>(data_len));
        uint16_t expected_crc = compute(data_part);
        uint16_t received_crc = 0u;
        for (int i = 0; i < 16; ++i) {
            uint8_t bit = (data_with_crc[data_len + i] > 0) ? 1u : 0u;
            received_crc |= static_cast<uint16_t>(bit << (15 - i));
        }
        return expected_crc == received_crc;
    }

    Tensor_Interleaver::Tensor_Interleaver(size_t d)
        : dim(d)
        , total_size(d * d * d)
        // Dynamic_Fractal_Mapper 도메인 4096 — dim^3 == 4096 일 때만 (16^3)
        , fractal_layer_active_(d == 16u)
        , fractal_mapper_() {
        if (fractal_layer_active_) {
            fractal_mapper_.Update_Frame(0u, 0u);
        }
    }

    size_t Tensor_Interleaver::Get_Size() const { return total_size; }

    void Tensor_Interleaver::Sync_Fractal_Key(
        uint64_t session_id, uint32_t logical_frame_counter,
        uint32_t harq_round) noexcept {
        if (!fractal_layer_active_) { return; }

        const uint32_t hr_slot = FractalHarq_Clamp_U32(
            harq_round, Tensor_Interleaver::kFractalHarqSlotStride - 1u);

        const uint32_t mapper_fc =
            logical_frame_counter * Tensor_Interleaver::kFractalHarqSlotStride
            + hr_slot;

        fractal_mapper_.Update_Frame(session_id, mapper_fc);
    }

    std::vector<double> Tensor_Interleaver::Interleave(
        const std::vector<double>& in) const {
        std::vector<double> out(total_size, 0.0);
        for (size_t z = 0u; z < dim; ++z)
            for (size_t y = 0u; y < dim; ++y)
                for (size_t x = 0u; x < dim; ++x) {
                    const size_t w = z * dim * dim + y * dim + x;
                    const size_t r = y * dim * dim + x * dim + z;
                    const size_t w_write = fractal_layer_active_
                        ? static_cast<size_t>(fractal_mapper_.Forward(
                            static_cast<uint32_t>(w)))
                        : w;
                    if (r < in.size() && w_write < out.size()) {
                        out[w_write] = in[r];
                    }
                }
        return out;
    }

    std::vector<double> Tensor_Interleaver::Deinterleave(
        const std::vector<double>& in) const {
        std::vector<double> out(total_size, 0.0);
        for (size_t z = 0u; z < dim; ++z)
            for (size_t y = 0u; y < dim; ++y)
                for (size_t x = 0u; x < dim; ++x) {
                    const size_t r = z * dim * dim + y * dim + x;
                    const size_t w = y * dim * dim + x * dim + z;
                    const size_t r_read = fractal_layer_active_
                        ? static_cast<size_t>(fractal_mapper_.Forward(
                            static_cast<uint32_t>(r)))
                        : r;
                    if (r_read < in.size() && w < out.size()) {
                        out[w] = in[r_read];
                    }
                }
        return out;
    }

    // ── [BUG-21] Interleave_Raw — int8_t ARM zero-heap ──
    size_t Tensor_Interleaver::Interleave_Raw(const int8_t* in, size_t in_len,
        int8_t* out, size_t out_max) const noexcept {
        if (!in || !out || in_len == 0u || out_max == 0u) return 0u;
        const size_t n = (in_len < total_size) ? in_len : total_size;
        const size_t m = (n < out_max) ? n : out_max;
        std::memset(out, 0, m);
        for (size_t z = 0u; z < dim; ++z)
            for (size_t y = 0u; y < dim; ++y)
                for (size_t x = 0u; x < dim; ++x) {
                    const size_t w = z * dim * dim + y * dim + x;
                    const size_t r = y * dim * dim + x * dim + z;
                    const size_t w_write = fractal_layer_active_
                        ? static_cast<size_t>(fractal_mapper_.Forward(
                            static_cast<uint32_t>(w)))
                        : w;
                    if (r < in_len && w_write < m) { out[w_write] = in[r]; }
                }
        return m;
    }

    size_t Tensor_Interleaver::Deinterleave_Raw(const int8_t* in, size_t in_len,
        int8_t* out, size_t out_max) const noexcept {
        if (!in || !out || in_len == 0u || out_max == 0u) return 0u;
        const size_t n = (in_len < total_size) ? in_len : total_size;
        const size_t m = (n < out_max) ? n : out_max;
        std::memset(out, 0, m);
        for (size_t z = 0u; z < dim; ++z)
            for (size_t y = 0u; y < dim; ++y)
                for (size_t x = 0u; x < dim; ++x) {
                    const size_t r = z * dim * dim + y * dim + x;
                    const size_t w = y * dim * dim + x * dim + z;
                    const size_t r_read = fractal_layer_active_
                        ? static_cast<size_t>(fractal_mapper_.Forward(
                            static_cast<uint32_t>(r)))
                        : r;
                    if (r_read < in_len && w < m) { out[w] = in[r_read]; }
                }
        return m;
    }

    // ── [OPT-3] Interleave_To / Deinterleave_To (버퍼 재사용) ──
    //  HARQ 루프에서 매 라운드 vector 생성/파괴 방지
    //  out.resize(): capacity ≥ size이면 재할당 0회
    void Tensor_Interleaver::Interleave_To(const std::vector<double>& in,
        std::vector<double>& out) const {
        out.assign(total_size, 0.0);
        for (size_t z = 0u; z < dim; ++z)
            for (size_t y = 0u; y < dim; ++y)
                for (size_t x = 0u; x < dim; ++x) {
                    const size_t w = z * dim * dim + y * dim + x;
                    const size_t r = y * dim * dim + x * dim + z;
                    const size_t w_write = fractal_layer_active_
                        ? static_cast<size_t>(fractal_mapper_.Forward(
                            static_cast<uint32_t>(w)))
                        : w;
                    if (r < in.size() && w_write < out.size()) {
                        out[w_write] = in[r];
                    }
                }
    }

    void Tensor_Interleaver::Deinterleave_To(const std::vector<double>& in,
        std::vector<double>& out) const {
        out.assign(total_size, 0.0);
        for (size_t z = 0u; z < dim; ++z)
            for (size_t y = 0u; y < dim; ++y)
                for (size_t x = 0u; x < dim; ++x) {
                    const size_t r = z * dim * dim + y * dim + x;
                    const size_t w = y * dim * dim + x * dim + z;
                    const size_t r_read = fractal_layer_active_
                        ? static_cast<size_t>(fractal_mapper_.Forward(
                            static_cast<uint32_t>(r)))
                        : r;
                    if (r_read < in.size() && w < out.size()) {
                        out[w] = in[r_read];
                    }
                }
    }

    double Soft_Tensor_FEC::Tag(unsigned int seed, size_t index) {
        uint64_t z =
            static_cast<uint64_t>(seed) * 2654435761ULL + index;
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        z = z ^ (z >> 31);
        return (z & 1u) ? 1.0 : -1.0;
    }

    std::vector<double> Soft_Tensor_FEC::Encode(
        const std::vector<double>& bits,
        unsigned int frame_seed) const {
        std::vector<double> tensor(TENSOR_SIZE, 0.0);
        if (bits.empty()) { return tensor; }
        if (bits.size() > TENSOR_SIZE) { return tensor; }  // [BUG-14]
        size_t npb = TENSOR_SIZE / bits.size();
        for (size_t i = 0u; i < bits.size(); ++i)
            for (size_t j = 0u; j < npb; ++j) {
                size_t idx = i * npb + j;
                if (idx < TENSOR_SIZE)
                    tensor[idx] = bits[i] * Tag(frame_seed, idx);
            }
        return tensor;
    }

    // ── [OPT-3] Encode_To (버퍼 재사용) ──
    void Soft_Tensor_FEC::Encode_To(const std::vector<double>& bits,
        unsigned int frame_seed,
        std::vector<double>& out) const {
        out.assign(TENSOR_SIZE, 0.0);
        if (bits.empty() || bits.size() > TENSOR_SIZE) { return; }
        const size_t npb = TENSOR_SIZE / bits.size();
        for (size_t i = 0u; i < bits.size(); ++i)
            for (size_t j = 0u; j < npb; ++j) {
                const size_t idx = i * npb + j;
                if (idx < TENSOR_SIZE)
                    out[idx] = bits[i] * Tag(frame_seed, idx);
            }
    }

    // ── [BUG-21] Tag_i8 — int8_t 버전 (±1 반환, double 0회) ──
    int8_t Soft_Tensor_FEC::Tag_i8(unsigned int seed, size_t index) noexcept {
        uint64_t z =
            static_cast<uint64_t>(seed) * 2654435761ULL + index;
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        z = z ^ (z >> 31);
        return (z & 1u) ? static_cast<int8_t>(1) : static_cast<int8_t>(-1);
    }

    // ── [BUG-21] Encode_Raw — int8_t ARM zero-heap ──
    //  bits[i] ∈ {+1, -1}, Tag_i8() ∈ {+1, -1}
    //  곱셈: (+1)×(+1)=+1, (+1)×(-1)=-1, (-1)×(+1)=-1, (-1)×(-1)=+1
    //  → 결과 ∈ {+1, -1} → int8_t 안전
    //  npb = out_max / n_bits (ARM에서 축소된 텐서 크기 적용)
    size_t Soft_Tensor_FEC::Encode_Raw(const int8_t* bits, size_t n_bits,
        int8_t* out, size_t out_max,
        unsigned int frame_seed) const noexcept {
        if (!bits || !out || n_bits == 0u || out_max == 0u) return 0u;
        if (n_bits > out_max) return 0u;
        std::memset(out, 0, out_max);
        const size_t npb = out_max / n_bits;
        if (npb == 0u) return 0u;
        for (size_t i = 0u; i < n_bits; ++i)
            for (size_t j = 0u; j < npb; ++j) {
                const size_t idx = i * npb + j;
                if (idx < out_max)
                    out[idx] = static_cast<int8_t>(
                        bits[i] * Tag_i8(frame_seed, idx));
            }
        return (npb * n_bits < out_max) ? npb * n_bits : out_max;
    }

    std::vector<double> Soft_Tensor_FEC::Decode_Soft(
        const std::vector<double>& tensor, size_t num_bits,
        unsigned int frame_seed) const {
        std::vector<double> soft(num_bits, 0.0);
        if (num_bits == 0u || num_bits > TENSOR_SIZE) { return soft; } // [BUG-14]
        const size_t npb = TENSOR_SIZE / num_bits;

        // [OPT-4] samp vector 힙 할당 제거 — 고정 256 서브샘플링
        //  기존: vector<double> samp(65536) = 512KB 힙/회, HARQ 12회 = 6MB
        //  수정: double samp[256] = 2KB 스택, 통계적 오차 <5%
        //  MAD 중위수: EMP 버스트(99999) 이상치에 강건 (mean 불가)
        static constexpr size_t NOISE_SAMP_COUNT = 256u;
        double samp[NOISE_SAMP_COUNT];
        const size_t t_size = tensor.size();
        const size_t stride = (t_size > NOISE_SAMP_COUNT * 4u)
            ? (t_size / NOISE_SAMP_COUNT) : 4u;
        size_t samp_n = 0u;
        for (size_t i = 0u; i < t_size && samp_n < NOISE_SAMP_COUNT; i += stride)
            samp[samp_n++] = std::abs(tensor[i]);

        double sigma_est = 1e30;
        if (samp_n > 1u) {
            auto mid_it = samp + (samp_n >> 1u);
            std::nth_element(samp, mid_it, samp + samp_n);
            const double med = *mid_it;
            sigma_est = (med > 1e-12) ? med / 0.6745 : 1e30;
        }
        const double erasure_thresh =
            (sigma_est < 1e30) ? sigma_est * 5.0 : 1e30;
        for (size_t i = 0u; i < num_bits; ++i) {
            double s = 0.0;
            for (size_t j = 0u; j < npb; ++j) {
                size_t idx = i * npb + j;
                if (idx >= TENSOR_SIZE) { break; }
                double rx = tensor[idx];
                if (std::abs(rx) > erasure_thresh) { continue; }
                s += rx * Tag(frame_seed, idx);
            }
            soft[i] = s;
        }
        return soft;
    }

    // ── [OPT-3] Decode_Soft_To (버퍼 재사용) ──
    void Soft_Tensor_FEC::Decode_Soft_To(
        const std::vector<double>& tensor, size_t num_bits,
        unsigned int frame_seed,
        std::vector<double>& out) const {
        out.assign(num_bits, 0.0);
        if (num_bits == 0u || num_bits > TENSOR_SIZE) { return; }
        const size_t npb = TENSOR_SIZE / num_bits;

        static constexpr size_t NOISE_SAMP_COUNT = 256u;
        double samp[NOISE_SAMP_COUNT];
        const size_t t_size = tensor.size();
        const size_t stride = (t_size > NOISE_SAMP_COUNT * 4u)
            ? (t_size / NOISE_SAMP_COUNT) : 4u;
        size_t samp_n = 0u;
        for (size_t i = 0u; i < t_size && samp_n < NOISE_SAMP_COUNT; i += stride)
            samp[samp_n++] = std::abs(tensor[i]);

        double sigma_est = 1e30;
        if (samp_n > 1u) {
            auto mid_it = samp + (samp_n >> 1u);
            std::nth_element(samp, mid_it, samp + samp_n);
            const double med = *mid_it;
            sigma_est = (med > 1e-12) ? med / 0.6745 : 1e30;
        }
        const double erasure_thresh =
            (sigma_est < 1e30) ? sigma_est * 5.0 : 1e30;
        for (size_t i = 0u; i < num_bits; ++i) {
            double s = 0.0;
            for (size_t j = 0u; j < npb; ++j) {
                size_t idx = i * npb + j;
                if (idx >= TENSOR_SIZE) { break; }
                double rx = tensor[idx];
                if (std::abs(rx) > erasure_thresh) { continue; }
                s += rx * Tag(frame_seed, idx);
            }
            out[i] = s;
        }
    }

    std::vector<double> LTE_Channel::Transmit(
        const std::vector<double>& tensor, std::mt19937& rng) {
        std::vector<double> rx(tensor.size());
        HTS_Core::Physics::Apply_Lte_Channel_To(
            tensor, rng, rx, JS_DB, NUM_CHIPS, EMP_RATE, EMP_AMP);
        return rx;
    }

    // ── [OPT-3] Transmit_To (버퍼 재사용) ──
    void LTE_Channel::Transmit_To(const std::vector<double>& tensor,
        std::mt19937& rng, std::vector<double>& out) {
        HTS_Core::Physics::Apply_Lte_Channel_To(
            tensor, rng, out, JS_DB, NUM_CHIPS, EMP_RATE, EMP_AMP);
    }

    LTE_HARQ_Controller::BlockResult LTE_HARQ_Controller::TransmitBlock(
        const std::vector<double>& info_bits, unsigned int block_seed,
        Soft_Tensor_FEC& fec, Tensor_Interleaver& interleaver,
        std::mt19937& rng, int block_id) {

        BlockResult result;
        result.success = false; result.harq_rounds = 0;
        result.latency_ms = 0.0;

        std::vector<double> protected_bits = CRC16::Append(info_bits);
        std::vector<double> coded(MTU, 1.0);
        for (int r = 0; r < REP_FACTOR; ++r)
            for (size_t i = 0u; i < protected_bits.size(); ++i) {
                size_t pos =
                    static_cast<size_t>(r) * protected_bits.size() + i;
                if (pos < static_cast<size_t>(MTU))
                    coded[pos] = protected_bits[i];
            }

        std::vector<double> harq_accum(MTU, 0.0);
        std::vector<double> last_hard(PROTECTED_BITS);

        // [OPT-3] 루프 진입 전 1회 할당 (Zero-Allocation Pipeline)
        //  기존: 매 라운드 tensor(2MB)+tx(2MB)+rx(2MB)+rx_dint(2MB)+soft(2MB) = 10MB/회
        //  수정: 5개 버퍼 사전 확보, _To API로 덮어쓰기 → 힙 할당 0회/회
        std::vector<double> tensor_buf(interleaver.Get_Size(), 0.0);
        std::vector<double> tx_buf(interleaver.Get_Size(), 0.0);
        std::vector<double> rx_buf(tx_buf.size(), 0.0);
        std::vector<double> rx_dint_buf(tx_buf.size(), 0.0);
        std::vector<double> soft_buf(MTU, 0.0);
        std::vector<double> combined(PROTECTED_BITS, 0.0);

        for (int k = 1; k <= MAX_HARQ; ++k) {
            result.harq_rounds = k;
            result.latency_ms =
                static_cast<double>(k) * HARQ_RTT_MS;
            unsigned int frame_seed =
                block_seed + static_cast<unsigned int>(k) * 7919u;

            // HARQ 시간 다양성: 논리 프레임(block_seed) + 슬롯(k-1) — V2 Dispatcher 와 stride=16 정합
            interleaver.Sync_Fractal_Key(
                static_cast<uint64_t>(block_seed) ^
                    (static_cast<uint64_t>(static_cast<uint32_t>(block_id)) << 32u),
                static_cast<uint32_t>(block_seed),
                static_cast<uint32_t>(k - 1));

            // [OPT-3] _To API: capacity 재사용, 루프 내 힙 할당 0회
            fec.Encode_To(coded, frame_seed, tensor_buf);
            interleaver.Interleave_To(tensor_buf, tx_buf);
            LTE_Channel::Transmit_To(tx_buf, rng, rx_buf);
            interleaver.Deinterleave_To(rx_buf, rx_dint_buf);
            fec.Decode_Soft_To(rx_dint_buf, MTU, frame_seed, soft_buf);
            for (int i = 0; i < MTU; ++i)
                harq_accum[i] += soft_buf[i];

            std::fill(combined.begin(), combined.end(), 0.0);
            for (int r = 0; r < REP_FACTOR; ++r)
                for (int i = 0; i < PROTECTED_BITS; ++i) {
                    size_t pos =
                        static_cast<size_t>(r) * PROTECTED_BITS + i;
                    if (pos < static_cast<size_t>(MTU))
                        combined[i] += harq_accum[pos];
                }
            for (int i = 0; i < PROTECTED_BITS; ++i)
                last_hard[i] = (combined[i] > 0.0) ? 1.0 : -1.0;

            if (CRC16::Check(last_hard)) {
                result.info_bits.assign(
                    last_hard.begin(),
                    last_hard.begin() + INFO_PER_BLOCK);
                result.success = true;
#if !defined(__arm__) && !defined(__TARGET_ARCH_ARM)
                std::cout << "  [Block " << block_id << "] HARQ "
                    << k << "/" << MAX_HARQ
                    << " -> CRC PASS (ACK)\n";
#endif
                return result;
            }
            else {
#if !defined(__arm__) && !defined(__TARGET_ARCH_ARM)
                std::cout << "  [Block " << block_id << "] HARQ "
                    << k << "/" << MAX_HARQ
                    << " -> CRC FAIL (NACK)\n";
#endif
            }
        }
        result.info_bits.assign(
            last_hard.begin(),
            last_hard.begin() + INFO_PER_BLOCK);
        return result;
    }

    void Print_LTE_Analysis() {
#if !defined(__arm__) && !defined(__TARGET_ARCH_ARM)
        const double js = LTE_Channel::JS_DB;
        const int chips = LTE_Channel::NUM_CHIPS;
        const int mtu = LTE_HARQ_Controller::MTU;
        const int rep = LTE_HARQ_Controller::REP_FACTOR;
        const int max_harq = LTE_HARQ_Controller::MAX_HARQ;
        const int prot = LTE_HARQ_Controller::PROTECTED_BITS;
        const int info = LTE_HARQ_Controller::INFO_PER_BLOCK;
        const double sigma = std::sqrt(std::pow(10.0, js / 10.0));
        const int npb = 262144 / mtu;
        const double sig_tot = sigma * std::sqrt(static_cast<double>(chips));
        double signal = static_cast<double>(npb) * chips;
        double noise_std =
            std::sqrt(static_cast<double>(npb)) * sig_tot;
        (void)signal; (void)noise_std;

        std::cout << std::fixed << std::setprecision(1);
        std::cout
            << "+================================================================+\n"
            << "|        LTE Anti-Jam System Analysis (J/S +50 dB)               |\n"
            << "+================================================================+\n"
            << "| Chips = " << chips << " | MTU = " << mtu
            << " | Rate 1/" << rep
            << " | HARQ = " << max_harq
            << " | Info = " << info << " bits  |\n"
            << "+----------------------------------------------------------------+\n"
            << "| After HARQ + Repetition combining (info bit SNR):              |\n";

        for (int K : {1, 2, 3, 4, 8, 12}) {
            if (K > max_harq) { continue; }
            double total_obs =
                static_cast<double>(npb) * chips * K * rep;
            double snr = std::sqrt(total_obs) / sigma;
            double ber = 0.5 * std::erfc(snr / std::sqrt(2.0));
            double exp_e = static_cast<double>(prot) * ber;
            std::cout << std::setprecision(2);
            std::cout << "|   K=" << std::setw(2) << K
                << ": SNR=" << snr
                << "σ BER=" << std::scientific
                << std::setprecision(1) << ber;
            if (exp_e < 0.1) { std::cout << " -> CRC PASS"; }
            std::cout << std::fixed
                << "                        |\n";
        }
        std::cout
            << "+================================================================+\n\n";
#endif
    }

} // namespace HTS_Engine


// =========================================================================
//  [Layer 1] ProtectedEngine::HTS16_DIOC_Core — Pimpl 구현
// =========================================================================

namespace ProtectedEngine {

    // =====================================================================
    //  보안 메모리 소거 (volatile + asm clobber + release fence 3중 보호)
    //  [BUG-12] pragma O0 삭제 완료 버전 — Strict Aliasing 규칙 준수
    //  [BUG-FIX ①] seq_cst → release: 소거 완료를 후속 읽기에 가시화하는 것이
    //               목적이므로 release fence로 충분. seq_cst의 전역 순서화 오버헤드
    //               불필요 (프로젝트 배리어 정책 통일).
    // =====================================================================
    static void Secure_Wipe_DIOC(void* ptr, size_t size) noexcept {
        if (ptr == nullptr || size == 0u) { return; }
        volatile unsigned char* p =
            static_cast<volatile unsigned char*>(ptr);
        for (size_t i = 0u; i < size; ++i) { p[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // ── PSL=4 최적 균형 코드북 (전수탐색 2^16, weight=8) ──
    // [OPT-2] static const → static constexpr (.rodata 배치, 런타임 초기화 0회)
    static constexpr uint16_t OPTIMAL_CODEBOOK[64] = {
        0x035F, 0x036F, 0x03AF, 0x03D7, 0x03DB, 0x03EB, 0x053F, 0x056F,
        0x05B7, 0x05CF, 0x05E7, 0x066F, 0x0677, 0x06AF, 0x06B7, 0x06BE,
        0x06D7, 0x06DE, 0x06E7, 0x073B, 0x073D, 0x075B, 0x075E, 0x076B,
        0x076D, 0x0773, 0x079D, 0x07AB, 0x07AE, 0x07B3, 0x07B5, 0x07B6,
        0x07D6, 0x07E5, 0x093F, 0x095F, 0x099F, 0x09AF, 0x09BB, 0x09CF,
        0x09DB, 0x0A3F, 0x0A6F, 0x0A7E, 0x0A9F, 0x0ABB, 0x0ACF, 0x0ADB,
        0x0ADE, 0x0B37, 0x0B3D, 0x0B57, 0x0B5D, 0x0B67, 0x0B6E, 0x0B73,
        0x0B9E, 0x0BA7, 0x0BAD, 0x0BB3, 0x0BCD, 0x0BCE, 0x0BD3, 0x0BE3,
    };

    // =====================================================================
    //  [BUG-02] Pimpl 구현 구조체
    //
    //  [은닉 대상]
    //  arx_state[4]: 128비트 ARX CSPRNG 상태 (보안 핵심 자산)
    //  SlotBitset, 내부 유틸리티 함수
    // =====================================================================

    static constexpr int UNIVERSE_SLOTS = 1024;
    static constexpr int CHIP_COUNT = 16;
    static constexpr int DATA_BITS = 4;
    static constexpr int MIN_VALID_CHIPS = 4;
    static constexpr int CODEBOOK_SIZE = 64;
    static constexpr int CFAR_BASELINE_MIN = 5;
    static constexpr int CFAR_THRESHOLD_SHIFT = 3;

    struct HTS16_DIOC_Core::Impl {
        uint32_t arx_state[4] = {};

        struct SlotBitset {
            uint32_t words[32] = {};
            void clear() noexcept {
                std::memset(words, 0, sizeof(words));
            }
            bool test(uint32_t idx) const noexcept {
                return (words[idx >> 5u] >> (idx & 31u)) & 1u;
            }
            void set(uint32_t idx) noexcept {
                words[idx >> 5u] |= (1u << (idx & 31u));
            }
        };

        // [BUG-06] rotl32 시프트 가드 (n &= 31, n==0 조기 반환)
        static uint32_t rotl32(uint32_t x, uint32_t n) noexcept {
            n &= 31u;
            if (n == 0u) { return x; }
            return (x << n) | (x >> (32u - n));
        }

        uint32_t NextChaos() noexcept {
            uint32_t a = arx_state[0], b = arx_state[1];
            uint32_t c = arx_state[2], d = arx_state[3];

            a += b; d ^= a; d = rotl32(d, 16u);
            c += d; b ^= c; b = rotl32(b, 12u);
            a += b; d ^= a; d = rotl32(d, 8u);
            c += d; b ^= c; b = rotl32(b, 7u);
            d++;

            arx_state[0] = a; arx_state[1] = b;
            arx_state[2] = c; arx_state[3] = d;
            return a;
        }

        static int popcount16(uint16_t x) noexcept {
#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
            return std::popcount(static_cast<uint32_t>(x));
#elif defined(_MSC_VER)
            return static_cast<int>(
                __popcnt(static_cast<unsigned int>(x)));
#elif defined(__GNUC__) || defined(__clang__)
            return __builtin_popcount(static_cast<uint32_t>(x));
#else
            uint32_t v = x;
            int c = 0;
            while (v) { v &= v - 1u; ++c; }
            return c;
#endif
        }

        static int32_t fast_abs(int32_t x) noexcept {
            const int32_t mask = x >> 31;
            return (x ^ mask) - mask;
        }

        static uint16_t Cyclic_Shift_16(
            uint16_t val, int shift) noexcept {
            shift &= 15;
            if (shift == 0) { return val; }
            return static_cast<uint16_t>(
                (val << shift) | (val >> (16 - shift)));
        }

        void AllocateSlots(
            uint16_t* slots, SlotBitset& used) noexcept {
            used.clear();
            for (int i = 0; i < CHIP_COUNT; ++i) {
                uint32_t slot = NextChaos() & 0x3FFu;
                while (used.test(slot))
                    slot = (slot + 1u) & 0x3FFu;
                used.set(slot);
                slots[i] = static_cast<uint16_t>(slot);
            }
        }

        // [BUG-01] 소멸자 — arx_state 보안 소거
        ~Impl() noexcept {
            Secure_Wipe_DIOC(arx_state, sizeof(arx_state));
        }
    };

    // =====================================================================
    //  [BUG-15] 컴파일 타임 크기·정렬 검증 + get_impl()
    // =====================================================================
    HTS16_DIOC_Core::Impl* HTS16_DIOC_Core::get_impl() noexcept {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE(256B)를 초과합니다 — 버퍼 크기를 늘려주세요");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 요구가 impl_buf_ alignas(8)을 초과합니다");
        return impl_valid_
            ? std::launder(reinterpret_cast<Impl*>(impl_buf_)) : nullptr;
    }

    const HTS16_DIOC_Core::Impl* HTS16_DIOC_Core::get_impl() const noexcept {
        return impl_valid_
            ? std::launder(reinterpret_cast<const Impl*>(impl_buf_))
            : nullptr;
    }

    // =====================================================================
    //  [BUG-15] 생성자 — placement new (zero-heap)
    //
    //  기존: std::make_unique<Impl>() + try-catch
    //        → 힙 할당 + 예외 경로 2중 위반
    //  수정: impl_buf_ SecWipe → ::new Impl() → arx_state 초기화
    //        try-catch 완전 제거 (-fno-exceptions 양산 원칙 준수)
    //        [BUG-05] noexcept 유지
    // =====================================================================
    HTS16_DIOC_Core::HTS16_DIOC_Core(uint32_t seed) noexcept
        : impl_valid_(false)
    {
        Secure_Wipe_DIOC(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl();
        impl_valid_ = true;

        Impl* p = get_impl();
        if (p == nullptr) { return; }  // static_assert에 걸리지 않는 한 도달 불가

        if (seed == 0u) { seed = 0xDEADBEEFu; }
        p->arx_state[0] = seed;
        p->arx_state[1] = seed ^ 0x9E3779B9u;
        p->arx_state[2] = seed ^ 0x6A09E667u;
        p->arx_state[3] = seed ^ 0xBB67AE85u;

        // ARX 워밍업 8라운드 — 초기 상태 편향 제거
        for (int i = 0; i < 8; ++i) { p->NextChaos(); }
    }

    // =====================================================================
    //  [BUG-15] 소멸자 — 명시적 (= default 제거)
    //  Impl 소멸자(arx_state 소거) 호출 → impl_buf_ 전체 SecWipe → 플래그 무효화
    // =====================================================================
    HTS16_DIOC_Core::~HTS16_DIOC_Core() noexcept {
        Impl* p = get_impl();
        if (p != nullptr) { p->~Impl(); }
        Secure_Wipe_DIOC(impl_buf_, sizeof(impl_buf_));
        impl_valid_ = false;
    }

    // =====================================================================
    //  DIOC 송신: I/Q에 독립 최적 코드 배정
    // =====================================================================
    std::array<HTS16_DIOC_Core::SparseChip, 16>
        HTS16_DIOC_Core::Transmit_4Bit(uint8_t data_4bit) noexcept {

        std::array<SparseChip, 16> tx_frame = {};
        Impl* p = get_impl();
        if (p == nullptr) { return tx_frame; }
        auto& impl = *p;

        uint32_t idx_I = impl.NextChaos() & 0x3Fu;
        // [BUG-13] 나눗셈 제거: & 0x3F + 0 방어
        uint32_t step = impl.NextChaos() & 0x3Fu;
        if (step == 0u) { step = 1u; }
        uint32_t idx_Q = (idx_I + step) & 0x3Fu;

        uint16_t code_I = Impl::Cyclic_Shift_16(
            OPTIMAL_CODEBOOK[idx_I], data_4bit & 0x0F);
        uint16_t code_Q = Impl::Cyclic_Shift_16(
            OPTIMAL_CODEBOOK[idx_Q], data_4bit & 0x0F);

        Impl::SlotBitset used;
        uint16_t slots[CHIP_COUNT];
        impl.AllocateSlots(slots, used);

        for (int i = 0; i < CHIP_COUNT; ++i) {
            int8_t pol_I = ((code_I >> (15 - i)) & 1u) ? 1 : -1;
            int8_t pol_Q = ((code_Q >> (15 - i)) & 1u) ? 1 : -1;
            tx_frame[i] = { slots[i], pol_I, pol_Q };
        }

        return tx_frame;
    }

    // =====================================================================
    //  DIOC 수신: OS-CFAR + 16-회전 상관기
    // =====================================================================
    int16_t HTS16_DIOC_Core::Decode_4Bit(
        const int16_t* rx_universe_I,
        const int16_t* rx_universe_Q) noexcept {

        Impl* p = get_impl();
        if (p == nullptr || rx_universe_I == nullptr
            || rx_universe_Q == nullptr) {
            return -1;
        }
        auto& impl = *p;

        // Phase 1: PRNG 동기 복원
        uint32_t idx_I = impl.NextChaos() & 0x3Fu;
        // [BUG-13] 나눗셈 제거 (Transmit_4Bit과 동일 PRNG 시퀀스 보장)
        uint32_t step_d = impl.NextChaos() & 0x3Fu;
        if (step_d == 0u) { step_d = 1u; }
        uint32_t idx_Q = (idx_I + step_d) & 0x3Fu;

        uint16_t base_I = OPTIMAL_CODEBOOK[idx_I];
        uint16_t base_Q = OPTIMAL_CODEBOOK[idx_Q];

        Impl::SlotBitset used;
        uint16_t slots[CHIP_COUNT];
        impl.AllocateSlots(slots, used);

        // Phase 2: 16칩 에너지 추출
        uint32_t chip_mags[CHIP_COUNT];
        for (int i = 0; i < CHIP_COUNT; ++i) {
            int s = slots[i];
            chip_mags[i] = static_cast<uint32_t>(
                Impl::fast_abs(
                    static_cast<int32_t>(rx_universe_I[s])) +
                Impl::fast_abs(
                    static_cast<int32_t>(rx_universe_Q[s])));
        }

        // Phase 3: 자기참조 OS-CFAR (1-Pass 4-Min Tracking)
        // [OPT-1] 삽입정렬 O(N²) + 64B sorted_mags → O(N) 4개 최솟값 추적
        //  baseline = (m0+m1+m2+m3)/4 이므로 최소 4개만 필요
        //  CHIP_COUNT=16: 기존 ~120비교 → 16비교 (87% 절감)
        uint32_t m0 = UINT32_MAX, m1 = UINT32_MAX;
        uint32_t m2 = UINT32_MAX, m3 = UINT32_MAX;
        for (int i = 0; i < CHIP_COUNT; ++i) {
            const uint32_t v = chip_mags[i];
            if (v < m0) { m3 = m2; m2 = m1; m1 = m0; m0 = v; }
            else if (v < m1) { m3 = m2; m2 = m1; m1 = v; }
            else if (v < m2) { m3 = m2; m2 = v; }
            else if (v < m3) { m3 = v; }
        }

        uint32_t baseline = (m0 + m1 + m2 + m3) >> 2u;
        if (baseline < static_cast<uint32_t>(CFAR_BASELINE_MIN))
            baseline = static_cast<uint32_t>(CFAR_BASELINE_MIN);

        // ── [BUG-10] Cognitive CFAR: 이중 모드 자동 전환 ─────────────
        static constexpr uint32_t BARRAGE_BASELINE_THRESHOLD = 2000u;
        const bool is_barrage = (baseline > BARRAGE_BASELINE_THRESHOLD);
        const uint32_t jamming_threshold =
            baseline << static_cast<uint32_t>(CFAR_THRESHOLD_SHIFT);

        // Phase 4: Cognitive CFAR 필터링 + 1-bit 하드 리미팅
        uint16_t data_I = 0u, data_Q = 0u, valid_mask = 0u;

        for (int i = 0; i < CHIP_COUNT; ++i) {
            if (!is_barrage && chip_mags[i] > jamming_threshold) {
                continue; // EMP 모드: 재밍 칩 블랙홀 펀칭
            }
            int s = slots[i];
            uint16_t bit_pos = static_cast<uint16_t>(1u << (15 - i));
            valid_mask |= bit_pos;
            if (rx_universe_I[s] > 0) { data_I |= bit_pos; }
            if (rx_universe_Q[s] > 0) { data_Q |= bit_pos; }
        }

        const int valid_count = Impl::popcount16(valid_mask);
        if (valid_count < MIN_VALID_CHIPS) { return -1; }

        // Phase 5: DIOC 16-회전 상관기
        int best_energy = -1;
        uint8_t decoded_data = 0u;

        for (uint8_t m = 0u; m < 16u; ++m) {
            uint16_t test_I = Impl::Cyclic_Shift_16(base_I, m);
            uint16_t test_Q = Impl::Cyclic_Shift_16(base_Q, m);

            uint16_t match_I = static_cast<uint16_t>(
                ~(test_I ^ data_I) & valid_mask);
            uint16_t match_Q = static_cast<uint16_t>(
                ~(test_Q ^ data_Q) & valid_mask);

            int score_I =
                (Impl::popcount16(match_I) << 1) - valid_count;
            int score_Q =
                (Impl::popcount16(match_Q) << 1) - valid_count;

            int total_energy =
                (score_I * score_I) + (score_Q * score_Q);

            if (total_energy > best_energy) {
                best_energy = total_energy;
                decoded_data = m;
            }
        }

        return static_cast<int16_t>(decoded_data);
    }

} // namespace ProtectedEngine