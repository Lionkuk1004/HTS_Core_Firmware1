// =============================================================================
/// @file HTS_AJ_Stats.cpp
/// @brief Wilson 95% — 정수 스케일 (내부 1e6 고정도)
// =============================================================================
#include "HTS_AJ_Stats.h"

static uint64_t aj_isqrt_u64(uint64_t x) noexcept {
    uint64_t r = 0;
    uint64_t b = 1ull << 62;
    while (b > x) {
        b >>= 2u;
    }
    while (b != 0ull) {
        if (x >= r + b) {
            x -= r + b;
            r = (r >> 1u) + b;
        } else {
            r >>= 1u;
        }
        b >>= 2u;
    }
    return r;
}

void AJ_Wilson95_Q8(uint32_t n, uint32_t k, uint16_t* lo_q8,
                    uint16_t* hi_q8) noexcept {
    if (lo_q8 == nullptr || hi_q8 == nullptr) {
        return;
    }
    if (n == 0u) {
        *lo_q8 = 0u;
        *hi_q8 = 0u;
        return;
    }
    if (k > n) {
        k = n;
    }
    const uint64_t N = static_cast<uint64_t>(n);
    const uint64_t K = static_cast<uint64_t>(k);
    const uint64_t z = 196ull; // 1.96 * 100
    const uint64_t z2 = z * z; // 38416

    const uint64_t denom = N * 10000ull + z2;
    if (denom == 0ull) {
        *lo_q8 = 0u;
        *hi_q8 = 256u;
        return;
    }

    const uint64_t rad =
        4ull * K * (N - K) * 10000ull * 10000ull + z2 * N * 10000ull;
    const uint64_t s = aj_isqrt_u64(rad);

    const int64_t center = static_cast<int64_t>(2ull * K * 10000ull * 10000ull +
                                                z2 * 10000ull);
    const int64_t margin = static_cast<int64_t>(z * s);

    int64_t low_num = center - margin;
    int64_t high_num = center + margin;
    if (low_num < 0) {
        low_num = 0;
    }
    const uint64_t denom2 = 2ull * denom * 10000ull;
    const uint64_t lo = static_cast<uint64_t>(low_num) / denom2;
    const uint64_t hi = static_cast<uint64_t>(high_num) / denom2;
    const uint64_t lo_clamped = (lo > 100ull) ? 100ull : lo;
    const uint64_t hi_clamped = (hi > 100ull) ? 100ull : hi;
    *lo_q8 = static_cast<uint16_t>(lo_clamped * 256ull / 100ull);
    *hi_q8 = static_cast<uint16_t>(hi_clamped * 256ull / 100ull);
    if (*hi_q8 > 256u) {
        *hi_q8 = 256u;
    }
}
