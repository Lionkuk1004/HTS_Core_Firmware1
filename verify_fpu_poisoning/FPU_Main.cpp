// Verify_FPU_Poisoning — 호스트 TU: NaN/Inf/서브노멀 오염 → 정수 경로 주입 스트레스
// 타겟: HTS_Sensor_ADC_Guard → HTS_Holo_Tensor_4D::Decode_Block, HTS_V400_Dispatcher::Feed_Chip

#include "HTS_Holo_Tensor_4D.h"
#include "HTS_Sensor_ADC_Guard.h"
#include "HTS_V400_Dispatcher.hpp"

#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <limits>

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#include <pmmintrin.h>
#include <xmmintrin.h>
#endif

namespace {

using namespace ProtectedEngine;

[[nodiscard]] float poison_sample(uint32_t i) noexcept
{
    switch (i % 9u) {
    case 0u:
        return std::numeric_limits<float>::quiet_NaN();
    case 1u:
        return std::numeric_limits<float>::infinity();
    case 2u:
        return -std::numeric_limits<float>::infinity();
    case 3u:
        return std::numeric_limits<float>::denorm_min();
    case 4u:
        return -std::numeric_limits<float>::denorm_min();
    case 5u:
        return 1.0e38f;
    case 6u:
        return -1.0e38f;
    case 7u:
        return 1.0e-40f;
    default:
        return -1.0e-40f;
    }
}

void set_sse_flush_modes(bool flush_denorm) noexcept
{
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
    if (flush_denorm) {
        _MM_SET_FLUSH_ZERO_MODE(_MM_FLUSH_ZERO_ON);
        _MM_SET_DENORMALS_ZERO_MODE(_MM_DENORMALS_ZERO_ON);
    }
    else {
        _MM_SET_FLUSH_ZERO_MODE(_MM_FLUSH_ZERO_OFF);
        _MM_SET_DENORMALS_ZERO_MODE(_MM_DENORMALS_ZERO_OFF);
    }
#else
    (void)flush_denorm;
#endif
}

[[nodiscard]] double subnormal_soak_ms() noexcept
{
    using clock = std::chrono::steady_clock;
    const auto t0 = clock::now();
    volatile float x = 1.0f;
    const float d = std::numeric_limits<float>::denorm_min();
    for (int i = 0; i < 400000; ++i) {
        x = x * d + d;
    }
    const auto t1 = clock::now();
    std::printf("FPU: subnormal soak volatile scratch x=%g\n", static_cast<double>(x));
    return std::chrono::duration<double, std::milli>(t1 - t0).count();
}

[[nodiscard]] bool run_holo_tensor_poison() noexcept
{
    HTS_Holo_Tensor_4D eng;
    uint32_t seed[4] = { 0xDEADBEEFu, 0x00BAB10Cu, 0xCAFEF00Du, 0x12345678u };
    if (eng.Initialize(seed, nullptr) != HTS_Holo_Tensor_4D::SECURE_TRUE) {
        std::puts("FPU: Holo Initialize FAIL");
        return false;
    }

    constexpr uint16_t K = 16u;
    constexpr uint16_t N = 64u;
    alignas(8) int8_t bits[K];
    alignas(8) int8_t chips[N];
    alignas(8) int8_t out_bits[K];
    for (uint16_t i = 0u; i < K; ++i) {
        bits[i] = static_cast<int8_t>((i & 1u) != 0u ? 1 : -1);
    }

    if (eng.Encode_Block(bits, K, chips, N) != HTS_Holo_Tensor_4D::SECURE_TRUE) {
        std::puts("FPU: Holo Encode_Block FAIL");
        eng.Shutdown();
        return false;
    }

    alignas(8) int16_t rx[N];
    constexpr uint32_t kIters = 5000u;
    for (uint32_t round = 0u; round < kIters; ++round) {
        for (uint16_t i = 0u; i < N; ++i) {
            const float p = poison_sample(round + static_cast<uint32_t>(i) * 131u);
            const int16_t pq = Float_Sensor_To_Soft_Symbol(p);
            const int16_t bc =
                static_cast<int16_t>(static_cast<int16_t>(chips[i]) * 96);
            const int32_t mix = static_cast<int32_t>(pq) + static_cast<int32_t>(bc);
            int16_t v = 0;
            if (mix > 32767) {
                v = 32767;
            }
            else if (mix < -32768) {
                v = -32768;
            }
            else {
                v = static_cast<int16_t>(mix);
            }
            rx[i] = v;
        }
        const uint64_t valid_mask = ~0ull;
        const uint32_t dec = eng.Decode_Block(rx, N, valid_mask, out_bits, K);
        if (dec != HTS_Holo_Tensor_4D::SECURE_TRUE) {
            std::printf("FPU: Holo Decode_Block FAIL round %" PRIu32 "\n", round);
            eng.Shutdown();
            return false;
        }
        if ((round & 0x3FFu) == 0u) {
            (void)eng.Advance_Time_Slot();
        }
    }

    eng.Shutdown();
    std::printf("FPU: Holo Tensor 4D poison decode x%" PRIu32 " — PASS\n", kIters);
    return true;
}

[[nodiscard]] bool run_v400_feed_poison() noexcept
{
    HTS_V400_Dispatcher disp;
    disp.Set_Seed(0xF00DF00Du);
    constexpr uint32_t kFeeds = 30000u;
    for (uint32_t i = 0u; i < kFeeds; ++i) {
        const float p = poison_sample(i * 17u);
        const int16_t ii = Float_Sensor_To_Soft_Symbol(p);
        const int16_t qq = Float_Sensor_To_Soft_Symbol(poison_sample(i * 19u + 3u));
        disp.Feed_Chip(ii, qq);
    }
    std::printf("FPU: V400 Feed_Chip x%" PRIu32 " — PASS\n", kFeeds);
    return true;
}

} // namespace

int main()
{
    std::puts("FPU: Verify_FPU_Poisoning (host TU) — Flush/DAZ on for timing A");
    set_sse_flush_modes(true);
    const double ms_ftz = subnormal_soak_ms();

    std::puts("FPU: Flush/DAZ off for timing B");
    set_sse_flush_modes(false);
    const double ms_noftz = subnormal_soak_ms();

    std::printf(
        "FPU: subnormal soak 400k iter — FTZ/DAZ on: %.2f ms, off: %.2f ms\n",
        ms_ftz, ms_noftz);

    set_sse_flush_modes(true);

    if (!run_holo_tensor_poison()) {
        return 1;
    }
    if (!run_v400_feed_poison()) {
        return 2;
    }

    std::puts("Verify_FPU_Poisoning: ALL checks PASSED");
    return 0;
}
