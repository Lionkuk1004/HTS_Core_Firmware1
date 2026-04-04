// HTS 3단계 실전 검증 — Layer 8~11 (DSP/PHY, 텐서, FEC/HARQ, 디스패처)
// NULL·극단 길이·용량 부족·비정상 모드 조합 — 크래시 없이 거부/0 반환 검증

#include "HTS_FEC_HARQ.hpp"
#include "HTS_Gaussian_Pulse.h"
#include "HTS_Holo_Dispatcher.h"
#include "HTS_Holo_Tensor_4D.h"
#include "HTS_V400_Dispatcher.hpp"

#include <climits>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace {

int g_failures = 0;

void strike_check(const char* /*tag*/, bool ok) noexcept {
    if (!ok) {
        ++g_failures;
    }
}

} // namespace

int main() {
    using namespace ProtectedEngine;

    // ── Layer 8: Gaussian 펄스 ─────────────────────────────────────────
    {
        Gaussian_Pulse_Shaper shaper(31u, 19661u);
        alignas(8) int32_t out_buf[512] = {};
        alignas(8) uint32_t tensor[4] = {0x12345678u, 0u, 0u, 0u};
        strike_check("gauss_null_tensor",
                     shaper.Apply_Pulse_Shaping_Tensor_Raw(
                         nullptr, 1u, out_buf, sizeof(out_buf) / sizeof(out_buf[0]))
                         == 0u);
        strike_check("gauss_null_out",
                     shaper.Apply_Pulse_Shaping_Tensor_Raw(
                         tensor, 1u, nullptr, 100u) == 0u);
        strike_check("gauss_tlen_overflow",
                     shaper.Apply_Pulse_Shaping_Tensor_Raw(
                         tensor,
                         (std::numeric_limits<size_t>::max() / 8u) + 1u,
                         out_buf,
                         sizeof(out_buf) / sizeof(out_buf[0]))
                         == 0u);
        strike_check("gauss_out_cap_small",
                     shaper.Apply_Pulse_Shaping_Tensor_Raw(
                         tensor, 64u, out_buf, 1u) == 0u);
    }

    // ── Layer 9: Holo 텐서 엔진 ───────────────────────────────────────
    {
        HTS_Holo_Tensor_4D eng;
        strike_check("holo4d_init_null_seed",
                     eng.Initialize(nullptr, nullptr) == HTS_Holo_Tensor_4D::SECURE_FALSE);
        uint32_t seed[4] = {1u, 2u, 3u, 4u};
        strike_check("holo4d_init_ok",
                     eng.Initialize(seed, nullptr) == HTS_Holo_Tensor_4D::SECURE_TRUE);
        alignas(8) int8_t chips[128] = {};
        alignas(8) int8_t bits[128] = {};
        strike_check("holo4d_encode_null_data",
                     eng.Encode_Block(nullptr, 16u, chips, 16u)
                         == HTS_Holo_Tensor_4D::SECURE_FALSE);
        strike_check("holo4d_encode_null_out",
                     eng.Encode_Block(bits, 16u, nullptr, 16u)
                         == HTS_Holo_Tensor_4D::SECURE_FALSE);
        alignas(8) int16_t rx[128] = {};
        strike_check("holo4d_decode_null_rx",
                     eng.Decode_Block(nullptr, 16u, ~0ull, bits, 16u)
                         == HTS_Holo_Tensor_4D::SECURE_FALSE);
        strike_check("holo4d_decode_null_out_bits",
                     eng.Decode_Block(rx, 16u, ~0ull, nullptr, 16u)
                         == HTS_Holo_Tensor_4D::SECURE_FALSE);
        eng.Shutdown();
    }

    // ── Layer 10: FEC/HARQ ────────────────────────────────────────────
    {
        alignas(8) uint8_t syms[256] = {};
        alignas(8) uint8_t inf[FEC_HARQ::MAX_INFO] = {};
        strike_check("fec_encode1_null",
                     FEC_HARQ::Encode1(nullptr, 1, syms) == 0);
        strike_check("fec_encode1_null_syms",
                     FEC_HARQ::Encode1(inf, 1, nullptr) == 0);
        strike_check("fec_encode1_len0",
                     FEC_HARQ::Encode1(inf, 0, syms) == 0);
        strike_check("fec_encode1_len_huge",
                     FEC_HARQ::Encode1(inf, INT_MAX, syms) == 0);
        alignas(8) int16_t rx_i[FEC_HARQ::INFO_BITS] = {};
        alignas(8) uint8_t dec_out[FEC_HARQ::MAX_INFO] = {};
        int dec_len = 0;
        strike_check("fec_decode1_null_rx",
                     !FEC_HARQ::Decode1(nullptr, dec_out, &dec_len));
        strike_check("fec_decode1_null_out",
                     !FEC_HARQ::Decode1(rx_i, nullptr, &dec_len));
        int* null_len = nullptr;
        strike_check("fec_decode1_null_len",
                     !FEC_HARQ::Decode1(rx_i, dec_out, null_len));
        strike_check("fec_crc16_null",
                     FEC_HARQ::CRC16(nullptr, 10) == 0u);
        strike_check("fec_crc16_bad_len",
                     FEC_HARQ::CRC16(inf, INT_MIN) == 0u);
    }

    // ── Layer 11: Holo 디스패처 + V400 디스패처 ───────────────────────
    {
        HTS_Holo_Dispatcher holo;
        strike_check("holo_disp_init_null",
                     holo.Initialize(nullptr) == HTS_Holo_Dispatcher::SECURE_FALSE);
        uint32_t hseed[4] = {0xA5A5A5A5u, 0u, 0u, 0u};
        strike_check("holo_disp_init_ok",
                     holo.Initialize(hseed) == HTS_Holo_Dispatcher::SECURE_TRUE);

        alignas(8) int16_t oI[4096] = {};
        alignas(8) int16_t oQ[4096] = {};
        alignas(8) uint8_t payload[16] = {0x55u};

        strike_check("holo_build_null_info",
                     holo.Build_Holo_Packet(
                         HoloPayload::DATA_HOLO, nullptr, 1u,
                         100, oI, oQ, sizeof(oI) / sizeof(oI[0]))
                         == 0u);
        strike_check("holo_build_len_size_max",
                     holo.Build_Holo_Packet(
                         HoloPayload::DATA_HOLO, payload, static_cast<size_t>(-1),
                         100, oI, oQ, sizeof(oI) / sizeof(oI[0]))
                         == 0u);
        strike_check("holo_build_len_overflow_17",
                     holo.Build_Holo_Packet(
                         HoloPayload::VOICE_HOLO, payload, 17u,
                         100, oI, oQ, sizeof(oI) / sizeof(oI[0]))
                         == 0u);
        strike_check("holo_build_bad_mode",
                     holo.Build_Holo_Packet(
                         0xFFu, payload, 4u, 100, oI, oQ, sizeof(oI) / sizeof(oI[0]))
                         == 0u);
        strike_check("holo_build_max_chips0",
                     holo.Build_Holo_Packet(
                         HoloPayload::VOICE_HOLO, payload, 4u,
                         100, oI, oQ, 0u)
                         == 0u);

        holo.Set_Current_Mode(HoloPayload::DATA_HOLO);
        alignas(8) int16_t rxI[512] = {};
        alignas(8) int16_t rxQ[512] = {};
        alignas(8) uint8_t out_data[16] = {};
        size_t out_len = 0u;
        strike_check("holo_decode_null_I",
                     holo.Decode_Holo_Block(
                         nullptr, rxQ, 128u, ~0ull, out_data, &out_len)
                         == HTS_Holo_Dispatcher::SECURE_FALSE);
        strike_check("holo_decode_null_out",
                     holo.Decode_Holo_Block(
                         rxI, rxQ, 128u, ~0ull, nullptr, &out_len)
                         == HTS_Holo_Dispatcher::SECURE_FALSE);
        size_t* null_olen = nullptr;
        strike_check("holo_decode_null_olen",
                     holo.Decode_Holo_Block(
                         rxI, rxQ, 128u, ~0ull, out_data, null_olen)
                         == HTS_Holo_Dispatcher::SECURE_FALSE);
        strike_check("holo_decode_chip0",
                     holo.Decode_Holo_Block(
                         rxI, rxQ, 0u, ~0ull, out_data, &out_len)
                         == HTS_Holo_Dispatcher::SECURE_FALSE);

        (void)holo.Shutdown();
    }

    {
        HTS_V400_Dispatcher v400;
        v400.Set_Seed(0xC0DEF00Du);
        alignas(8) uint8_t inf[16] = {};
        alignas(8) int16_t oI[20000] = {};
        alignas(8) int16_t oQ[20000] = {};
        const int max_c = static_cast<int>(sizeof(oI) / sizeof(oI[0]));

        strike_check("v400_build_null_info",
                     v400.Build_Packet(
                         PayloadMode::VIDEO_1, nullptr, 8, 200, oI, oQ, max_c)
                         == 0);
        strike_check("v400_build_neg_ilen",
                     v400.Build_Packet(
                         PayloadMode::VIDEO_1, inf, -1, 200, oI, oQ, max_c)
                         == 0);
        strike_check("v400_build_ilen_int_max",
                     v400.Build_Packet(
                         PayloadMode::VIDEO_1, inf, INT_MAX, 200, oI, oQ, max_c)
                         == 0);
        strike_check("v400_build_null_oI",
                     v400.Build_Packet(
                         PayloadMode::VIDEO_1, inf, 8, 200, nullptr, oQ, max_c)
                         == 0);
        strike_check("v400_build_max_c_tiny",
                     v400.Build_Packet(
                         PayloadMode::VIDEO_1, inf, 8, 200, oI, oQ, 1)
                         == 0);

        v400.Reset();
        for (int i = 0; i < 128; ++i) {
            v400.Feed_Chip(0, 0);
        }
        v400.Reset();
    }

    return (g_failures == 0) ? 0 : 1;
}
