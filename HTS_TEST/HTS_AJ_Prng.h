// =============================================================================
/// @file HTS_AJ_Prng.h
/// @brief xoshiro128** — 고정 시드 재현성 (항재밍 시험 하네스)
// =============================================================================
#ifndef HTS_AJ_PRNG_H
#define HTS_AJ_PRNG_H

#include <cstdint>

struct Xoshiro128 {
    uint32_t s[4];
};

inline void xoshiro128_seed(Xoshiro128* st, uint32_t seed) noexcept {
    uint32_t x = seed ? seed : 0x9E3779B9u;
    for (int i = 0; i < 4; ++i) {
        x ^= x << 13u;
        x ^= x >> 17u;
        x ^= x << 5u;
        st->s[static_cast<unsigned>(i)] = x + static_cast<uint32_t>(i * 0x9E3779B9u);
    }
}

inline uint32_t xoshiro128_next(Xoshiro128* st) noexcept {
    const uint32_t r = st->s[1u] * 5u;
    const uint32_t t = st->s[1u] << 9u;
    uint32_t z = st->s[0u];
    st->s[2u] ^= st->s[0u];
    st->s[3u] ^= st->s[1u];
    st->s[1u] ^= st->s[2u];
    st->s[0u] ^= st->s[3u];
    st->s[2u] ^= t;
    st->s[3u] = (st->s[3u] << 11u) | (st->s[3u] >> 21u);
    return (r << 7u) | (r >> 25u);
}

/// @return [-32767, 32767] 근사 가우시안 (12 균등 합 근사)
inline int32_t xoshiro_gauss_i16(Xoshiro128* st) noexcept {
    int32_t s = 0;
    for (int i = 0; i < 12; ++i) {
        s += static_cast<int32_t>(xoshiro128_next(st) & 0x7FFF) - 16384;
    }
    if (s > 32767) {
        s = 32767;
    }
    if (s < -32767) {
        s = -32767;
    }
    return s;
}

#endif
