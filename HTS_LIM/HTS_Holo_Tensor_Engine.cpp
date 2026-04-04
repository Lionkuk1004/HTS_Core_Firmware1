// =========================================================================
// HTS_Holo_Tensor_Engine.cpp — 4D 홀로그래픽 텐서 변조/암호화 코어
// Target: STM32F407 (Cortex-M4) — 순수 정수 연산
//
#include "HTS_Holo_Tensor_Engine.h"
#include "HTS_Secure_Memory.h"
#include <atomic>
#include <cstring>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace ProtectedEngine {
    namespace {
        // 분기 없는 조건부 부호 반전 (bit=1 -> negate, bit=0 -> keep)
        static inline int32_t holo_cond_sat_neg_ct(int32_t x, uint32_t bit) noexcept {
            const uint32_t ux = static_cast<uint32_t>(x);
            const uint32_t b = bit & 1u;
            const uint32_t mask = 0u - b;
            uint32_t flipped = (ux ^ mask) - mask;
            const uint32_t is_min = (flipped == 0x80000000u) ? 1u : 0u;
            flipped -= (is_min & mask);
            return static_cast<int32_t>(flipped);
        }

        // 상한/하한 클램프 — 삼항·비교 분기 없음 (마스크 + 산술, O(1))
        // v>hi → mask_hi=-1 … (hi&mask)|(v&~mask) = min(v,hi)
        static inline int32_t holo_clamp_i32_ct(
            int32_t v, int32_t lo, int32_t hi) noexcept {
            const int32_t diff_hi = hi - v;
            const int32_t mask_hi = diff_hi >> 31;
            int32_t x = (hi & mask_hi) | (v & ~mask_hi);
            const int32_t diff_lo = x - lo;
            const int32_t mask_lo = diff_lo >> 31;
            x = (lo & mask_lo) | (x & ~mask_lo);
            return x;
        }
    }

    // ── Xoshiro128ss — 128비트 상태 PRNG ───────────────────────
    //  128비트 상태 공간 — 단일 출력으로의 상태 복원 비현실적
    struct Holo_Xoshiro128 {
        uint32_t s[4];

        static uint32_t rotl(uint32_t x, int k) noexcept {
            const uint32_t kk = static_cast<uint32_t>(k) & 31u;
            const uint32_t sh = (32u - kk) & 31u;
            return (x << kk) | (x >> sh);
        }
        uint32_t next() noexcept {
            const uint32_t result = rotl(s[1] * 5u, 7u) * 9u;
            const uint32_t t = s[1] << 9u;
            s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3];
            s[2] ^= t; s[3] = rotl(s[3], 11u);
            return result;
        }
    };

    // ── 128비트 시드 → Xoshiro128ss 상태 초기화 ─────────────────
    //  SplitMix32 화이트닝: 입력 상관 제거 + 비가역 확산
    static Holo_Xoshiro128 expand_seed(const uint32_t seed[4]) noexcept {
        Holo_Xoshiro128 rng;
        auto mix32 = [](uint32_t z) noexcept -> uint32_t {
            z = (z ^ (z >> 16u)) * 0x45D9F3Bu;
            z = (z ^ (z >> 16u)) * 0x45D9F3Bu;
            return z ^ (z >> 16u);
            };
        rng.s[0] = mix32(seed[0]);
        rng.s[1] = mix32(seed[1]);
        rng.s[2] = mix32(seed[2]);
        rng.s[3] = mix32(seed[3]);
        // 워밍업: 초기 상태 상관 제거
        for (int i = 0; i < 4; ++i) { (void)rng.next(); }
        return rng;
    }

    static uint32_t log2_pow2(uint32_t n) noexcept {
        if (n <= 1u) { return 0u; }
#if defined(__GNUC__) || defined(__clang__)
        return 31u - static_cast<uint32_t>(__builtin_clz(n));
#elif defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
        unsigned long idx = 0u;
        if (_BitScanReverse(&idx, static_cast<unsigned long>(n)) == 0) { return 0u; }
        return static_cast<uint32_t>(idx);
#elif defined(_MSC_VER) && defined(_M_ARM64)
        unsigned long idx = 0u;
        if (_BitScanReverse64(&idx, static_cast<unsigned __int64>(n)) == 0) { return 0u; }
        return static_cast<uint32_t>(idx);
#else
        uint32_t r = 0u;
        while (n > 1u) { n >>= 1u; ++r; }
        return r;
#endif
    }

    // ── FWHT 나비 (FEC_HARQ와 동일 순서 — in-place, 수학 동치) ─────────
#define HOLO_FWHT_BF_S(d_, i_, j_)                          \
        do {                                                  \
            int32_t _u = (d_)[(i_)];                          \
            int32_t _v = (d_)[(j_)];                          \
            (d_)[(i_)] = static_cast<int32_t>(_u + _v);      \
            (d_)[(j_)] = static_cast<int32_t>(_u - _v);       \
        } while (0)

#define HOLO_FWHT_BF_U(d_, i_, j_)                                      \
        do {                                                              \
            uint32_t _u = static_cast<uint32_t>((d_)[(i_)]);            \
            uint32_t _v = static_cast<uint32_t>((d_)[(j_)]);            \
            (d_)[(i_)] = static_cast<int32_t>(_u + _v);                   \
            (d_)[(j_)] = static_cast<int32_t>(_u - _v);                   \
        } while (0)

    static void fwht_signed_unroll16(int32_t* d) noexcept {
        HOLO_FWHT_BF_S(d, 0, 1);
        HOLO_FWHT_BF_S(d, 2, 3);
        HOLO_FWHT_BF_S(d, 4, 5);
        HOLO_FWHT_BF_S(d, 6, 7);
        HOLO_FWHT_BF_S(d, 8, 9);
        HOLO_FWHT_BF_S(d, 10, 11);
        HOLO_FWHT_BF_S(d, 12, 13);
        HOLO_FWHT_BF_S(d, 14, 15);
        HOLO_FWHT_BF_S(d, 0, 2);
        HOLO_FWHT_BF_S(d, 1, 3);
        HOLO_FWHT_BF_S(d, 4, 6);
        HOLO_FWHT_BF_S(d, 5, 7);
        HOLO_FWHT_BF_S(d, 8, 10);
        HOLO_FWHT_BF_S(d, 9, 11);
        HOLO_FWHT_BF_S(d, 12, 14);
        HOLO_FWHT_BF_S(d, 13, 15);
        HOLO_FWHT_BF_S(d, 0, 4);
        HOLO_FWHT_BF_S(d, 1, 5);
        HOLO_FWHT_BF_S(d, 2, 6);
        HOLO_FWHT_BF_S(d, 3, 7);
        HOLO_FWHT_BF_S(d, 8, 12);
        HOLO_FWHT_BF_S(d, 9, 13);
        HOLO_FWHT_BF_S(d, 10, 14);
        HOLO_FWHT_BF_S(d, 11, 15);
        HOLO_FWHT_BF_S(d, 0, 8);
        HOLO_FWHT_BF_S(d, 1, 9);
        HOLO_FWHT_BF_S(d, 2, 10);
        HOLO_FWHT_BF_S(d, 3, 11);
        HOLO_FWHT_BF_S(d, 4, 12);
        HOLO_FWHT_BF_S(d, 5, 13);
        HOLO_FWHT_BF_S(d, 6, 14);
        HOLO_FWHT_BF_S(d, 7, 15);
    }

#define HOLO_FWHT_WHT4_COL_S(d_, c_)               \
        do {                                       \
            HOLO_FWHT_BF_S(d_, c_, (c_) + 16);     \
            HOLO_FWHT_BF_S(d_, (c_) + 32, (c_) + 48); \
            HOLO_FWHT_BF_S(d_, c_, (c_) + 32);     \
            HOLO_FWHT_BF_S(d_, (c_) + 16, (c_) + 48); \
        } while (0)

    static void fwht_signed_unroll64(int32_t* d) noexcept {
        fwht_signed_unroll16(d + 0);
        fwht_signed_unroll16(d + 16);
        fwht_signed_unroll16(d + 32);
        fwht_signed_unroll16(d + 48);
        HOLO_FWHT_WHT4_COL_S(d, 0);
        HOLO_FWHT_WHT4_COL_S(d, 1);
        HOLO_FWHT_WHT4_COL_S(d, 2);
        HOLO_FWHT_WHT4_COL_S(d, 3);
        HOLO_FWHT_WHT4_COL_S(d, 4);
        HOLO_FWHT_WHT4_COL_S(d, 5);
        HOLO_FWHT_WHT4_COL_S(d, 6);
        HOLO_FWHT_WHT4_COL_S(d, 7);
        HOLO_FWHT_WHT4_COL_S(d, 8);
        HOLO_FWHT_WHT4_COL_S(d, 9);
        HOLO_FWHT_WHT4_COL_S(d, 10);
        HOLO_FWHT_WHT4_COL_S(d, 11);
        HOLO_FWHT_WHT4_COL_S(d, 12);
        HOLO_FWHT_WHT4_COL_S(d, 13);
        HOLO_FWHT_WHT4_COL_S(d, 14);
        HOLO_FWHT_WHT4_COL_S(d, 15);
    }

#undef HOLO_FWHT_WHT4_COL_S

    static void fwht_signed_n4(int32_t* t) noexcept {
        HOLO_FWHT_BF_S(t, 0, 1);
        HOLO_FWHT_BF_S(t, 2, 3);
        HOLO_FWHT_BF_S(t, 0, 2);
        HOLO_FWHT_BF_S(t, 1, 3);
    }

    static void fwht_signed_n8(int32_t* t) noexcept {
        HOLO_FWHT_BF_S(t, 0, 1);
        HOLO_FWHT_BF_S(t, 2, 3);
        HOLO_FWHT_BF_S(t, 4, 5);
        HOLO_FWHT_BF_S(t, 6, 7);
        HOLO_FWHT_BF_S(t, 0, 2);
        HOLO_FWHT_BF_S(t, 1, 3);
        HOLO_FWHT_BF_S(t, 4, 6);
        HOLO_FWHT_BF_S(t, 5, 7);
        HOLO_FWHT_BF_S(t, 0, 4);
        HOLO_FWHT_BF_S(t, 1, 5);
        HOLO_FWHT_BF_S(t, 2, 6);
        HOLO_FWHT_BF_S(t, 3, 7);
    }

    static void fwht_signed_n32(int32_t* t) noexcept {
        for (uint32_t len = 1u; len < 32u; len <<= 1u) {
            for (uint32_t i = 0u; i < 32u; i += 2u * len) {
                for (uint32_t j = 0u; j < len; ++j) {
                    const uint32_t ia = i + j;
                    const uint32_t ib = i + len + j;
                    int32_t u = t[ia];
                    int32_t v = t[ib];
                    t[ia] = u + v;
                    t[ib] = u - v;
                }
            }
        }
    }

    static void fwht_signed_n128(int32_t* t) noexcept {
        for (uint32_t len = 1u; len < 128u; len <<= 1u) {
            for (uint32_t i = 0u; i < 128u; i += 2u * len) {
                for (uint32_t j = 0u; j < len; ++j) {
                    const uint32_t ia = i + j;
                    const uint32_t ib = i + len + j;
                    int32_t u = t[ia];
                    int32_t v = t[ib];
                    t[ia] = u + v;
                    t[ib] = u - v;
                }
            }
        }
    }

    static void fwht_signed_n256(int32_t* t) noexcept {
        for (uint32_t len = 1u; len < 256u; len <<= 1u) {
            for (uint32_t i = 0u; i < 256u; i += 2u * len) {
                for (uint32_t j = 0u; j < len; ++j) {
                    const uint32_t ia = i + j;
                    const uint32_t ib = i + len + j;
                    int32_t u = t[ia];
                    int32_t v = t[ib];
                    t[ia] = u + v;
                    t[ib] = u - v;
                }
            }
        }
    }

    static void fwht_signed_n512(int32_t* t) noexcept {
        for (uint32_t len = 1u; len < 512u; len <<= 1u) {
            for (uint32_t i = 0u; i < 512u; i += 2u * len) {
                for (uint32_t j = 0u; j < len; ++j) {
                    const uint32_t ia = i + j;
                    const uint32_t ib = i + len + j;
                    int32_t u = t[ia];
                    int32_t v = t[ib];
                    t[ia] = u + v;
                    t[ib] = u - v;
                }
            }
        }
    }

    static void fwht_safe_unroll16(int32_t* d) noexcept {
        HOLO_FWHT_BF_U(d, 0, 1);
        HOLO_FWHT_BF_U(d, 2, 3);
        HOLO_FWHT_BF_U(d, 4, 5);
        HOLO_FWHT_BF_U(d, 6, 7);
        HOLO_FWHT_BF_U(d, 8, 9);
        HOLO_FWHT_BF_U(d, 10, 11);
        HOLO_FWHT_BF_U(d, 12, 13);
        HOLO_FWHT_BF_U(d, 14, 15);
        HOLO_FWHT_BF_U(d, 0, 2);
        HOLO_FWHT_BF_U(d, 1, 3);
        HOLO_FWHT_BF_U(d, 4, 6);
        HOLO_FWHT_BF_U(d, 5, 7);
        HOLO_FWHT_BF_U(d, 8, 10);
        HOLO_FWHT_BF_U(d, 9, 11);
        HOLO_FWHT_BF_U(d, 12, 14);
        HOLO_FWHT_BF_U(d, 13, 15);
        HOLO_FWHT_BF_U(d, 0, 4);
        HOLO_FWHT_BF_U(d, 1, 5);
        HOLO_FWHT_BF_U(d, 2, 6);
        HOLO_FWHT_BF_U(d, 3, 7);
        HOLO_FWHT_BF_U(d, 8, 12);
        HOLO_FWHT_BF_U(d, 9, 13);
        HOLO_FWHT_BF_U(d, 10, 14);
        HOLO_FWHT_BF_U(d, 11, 15);
        HOLO_FWHT_BF_U(d, 0, 8);
        HOLO_FWHT_BF_U(d, 1, 9);
        HOLO_FWHT_BF_U(d, 2, 10);
        HOLO_FWHT_BF_U(d, 3, 11);
        HOLO_FWHT_BF_U(d, 4, 12);
        HOLO_FWHT_BF_U(d, 5, 13);
        HOLO_FWHT_BF_U(d, 6, 14);
        HOLO_FWHT_BF_U(d, 7, 15);
    }

#define HOLO_FWHT_WHT4_COL_U(d_, c_)               \
        do {                                       \
            HOLO_FWHT_BF_U(d_, c_, (c_) + 16);     \
            HOLO_FWHT_BF_U(d_, (c_) + 32, (c_) + 48); \
            HOLO_FWHT_BF_U(d_, c_, (c_) + 32);     \
            HOLO_FWHT_BF_U(d_, (c_) + 16, (c_) + 48); \
        } while (0)

    static void fwht_safe_unroll64(int32_t* d) noexcept {
        fwht_safe_unroll16(d + 0);
        fwht_safe_unroll16(d + 16);
        fwht_safe_unroll16(d + 32);
        fwht_safe_unroll16(d + 48);
        HOLO_FWHT_WHT4_COL_U(d, 0);
        HOLO_FWHT_WHT4_COL_U(d, 1);
        HOLO_FWHT_WHT4_COL_U(d, 2);
        HOLO_FWHT_WHT4_COL_U(d, 3);
        HOLO_FWHT_WHT4_COL_U(d, 4);
        HOLO_FWHT_WHT4_COL_U(d, 5);
        HOLO_FWHT_WHT4_COL_U(d, 6);
        HOLO_FWHT_WHT4_COL_U(d, 7);
        HOLO_FWHT_WHT4_COL_U(d, 8);
        HOLO_FWHT_WHT4_COL_U(d, 9);
        HOLO_FWHT_WHT4_COL_U(d, 10);
        HOLO_FWHT_WHT4_COL_U(d, 11);
        HOLO_FWHT_WHT4_COL_U(d, 12);
        HOLO_FWHT_WHT4_COL_U(d, 13);
        HOLO_FWHT_WHT4_COL_U(d, 14);
        HOLO_FWHT_WHT4_COL_U(d, 15);
    }

#undef HOLO_FWHT_WHT4_COL_U

    static void fwht_safe_n4(int32_t* t) noexcept {
        HOLO_FWHT_BF_U(t, 0, 1);
        HOLO_FWHT_BF_U(t, 2, 3);
        HOLO_FWHT_BF_U(t, 0, 2);
        HOLO_FWHT_BF_U(t, 1, 3);
    }

    static void fwht_safe_n8(int32_t* t) noexcept {
        HOLO_FWHT_BF_U(t, 0, 1);
        HOLO_FWHT_BF_U(t, 2, 3);
        HOLO_FWHT_BF_U(t, 4, 5);
        HOLO_FWHT_BF_U(t, 6, 7);
        HOLO_FWHT_BF_U(t, 0, 2);
        HOLO_FWHT_BF_U(t, 1, 3);
        HOLO_FWHT_BF_U(t, 4, 6);
        HOLO_FWHT_BF_U(t, 5, 7);
        HOLO_FWHT_BF_U(t, 0, 4);
        HOLO_FWHT_BF_U(t, 1, 5);
        HOLO_FWHT_BF_U(t, 2, 6);
        HOLO_FWHT_BF_U(t, 3, 7);
    }

    static void fwht_safe_n32(int32_t* t) noexcept {
        for (uint32_t len = 1u; len < 32u; len <<= 1u) {
            for (uint32_t i = 0u; i < 32u; i += 2u * len) {
                for (uint32_t j = 0u; j < len; ++j) {
                    const uint32_t ia = i + j;
                    const uint32_t ib = i + len + j;
                    uint32_t u = static_cast<uint32_t>(t[ia]);
                    uint32_t v = static_cast<uint32_t>(t[ib]);
                    t[ia] = static_cast<int32_t>(u + v);
                    t[ib] = static_cast<int32_t>(u - v);
                }
            }
        }
    }

    static void fwht_safe_n128(int32_t* t) noexcept {
        for (uint32_t len = 1u; len < 128u; len <<= 1u) {
            for (uint32_t i = 0u; i < 128u; i += 2u * len) {
                for (uint32_t j = 0u; j < len; ++j) {
                    const uint32_t ia = i + j;
                    const uint32_t ib = i + len + j;
                    uint32_t u = static_cast<uint32_t>(t[ia]);
                    uint32_t v = static_cast<uint32_t>(t[ib]);
                    t[ia] = static_cast<int32_t>(u + v);
                    t[ib] = static_cast<int32_t>(u - v);
                }
            }
        }
    }

    static void fwht_safe_n256(int32_t* t) noexcept {
        for (uint32_t len = 1u; len < 256u; len <<= 1u) {
            for (uint32_t i = 0u; i < 256u; i += 2u * len) {
                for (uint32_t j = 0u; j < len; ++j) {
                    const uint32_t ia = i + j;
                    const uint32_t ib = i + len + j;
                    uint32_t u = static_cast<uint32_t>(t[ia]);
                    uint32_t v = static_cast<uint32_t>(t[ib]);
                    t[ia] = static_cast<int32_t>(u + v);
                    t[ib] = static_cast<int32_t>(u - v);
                }
            }
        }
    }

    static void fwht_safe_n512(int32_t* t) noexcept {
        for (uint32_t len = 1u; len < 512u; len <<= 1u) {
            for (uint32_t i = 0u; i < 512u; i += 2u * len) {
                for (uint32_t j = 0u; j < len; ++j) {
                    const uint32_t ia = i + j;
                    const uint32_t ib = i + len + j;
                    uint32_t u = static_cast<uint32_t>(t[ia]);
                    uint32_t v = static_cast<uint32_t>(t[ib]);
                    t[ia] = static_cast<int32_t>(u + v);
                    t[ib] = static_cast<int32_t>(u - v);
                }
            }
        }
    }

#undef HOLO_FWHT_BF_S
#undef HOLO_FWHT_BF_U

    // =====================================================================
    //  Max_Safe_Amplitude — N에 따른 안전 입력 한계
    //  M_max = floor((2^31 - 1) / (4 × N²))
    // =====================================================================
    int32_t Holo_Tensor_Engine::Max_Safe_Amplitude(
        uint32_t chip_count) noexcept {
        if (chip_count < 2) return 0;
        // chip_count는 2의제곱 보장 (호출자 가드)
        // scale = 4 × N² = 1 << (2 + 2×log2(N))
        const uint32_t shift = 2u + 2u * log2_pow2(chip_count);
        if (shift >= 31u) return 0;
        return static_cast<int32_t>(0x7FFFFFFFu >> shift);
    }

    // =====================================================================
    //  FWHT — 이중 모드
    //           safe=true:  uint32_t 모듈로 (Decode — 악성 패킷 방어)
    // =====================================================================
    static void fwht_signed(int32_t* tensor, uint32_t n) noexcept {
        switch (n) {
        case 4u:  fwht_signed_n4(tensor); return;
        case 8u:  fwht_signed_n8(tensor); return;
        case 16u: fwht_signed_unroll16(tensor); return;
        case 32u: fwht_signed_n32(tensor); return;
        case 64u: fwht_signed_unroll64(tensor); return;
        case 128u: fwht_signed_n128(tensor); return;
        case 256u: fwht_signed_n256(tensor); return;
        case 512u: fwht_signed_n512(tensor); return;
        default: break;
        }
        const size_t n_sz = static_cast<size_t>(n);
        for (size_t len = 1u; len < n_sz; len <<= 1u) {
            for (size_t i = 0u; i < n_sz; i += 2u * len) {
                for (size_t j = 0u; j < len; ++j) {
                    const size_t ia = i + j;
                    const size_t ib = i + len + j;
                    int32_t u = tensor[ia];
                    int32_t v = tensor[ib];
                    tensor[ia] = u + v;
                    tensor[ib] = u - v;
                }
            }
        }
    }

    static void fwht_safe(int32_t* tensor, uint32_t n) noexcept {
        switch (n) {
        case 4u:  fwht_safe_n4(tensor); return;
        case 8u:  fwht_safe_n8(tensor); return;
        case 16u: fwht_safe_unroll16(tensor); return;
        case 32u: fwht_safe_n32(tensor); return;
        case 64u: fwht_safe_unroll64(tensor); return;
        case 128u: fwht_safe_n128(tensor); return;
        case 256u: fwht_safe_n256(tensor); return;
        case 512u: fwht_safe_n512(tensor); return;
        default: break;
        }
        const size_t n_sz = static_cast<size_t>(n);
        for (size_t len = 1u; len < n_sz; len <<= 1u) {
            for (size_t i = 0u; i < n_sz; i += 2u * len) {
                for (size_t j = 0u; j < len; ++j) {
                    const size_t ia = i + j;
                    const size_t ib = i + len + j;
                    uint32_t u = static_cast<uint32_t>(tensor[ia]);
                    uint32_t v = static_cast<uint32_t>(tensor[ib]);
                    tensor[ia] = static_cast<int32_t>(u + v);
                    tensor[ib] = static_cast<int32_t>(u - v);
                }
            }
        }
    }

    // ── 24가지 전체 순열 테이블 ─────────────────────────────────
    static constexpr uint8_t PERM_TABLE[24][4] = {
        {0,1,2,3}, {0,1,3,2}, {0,2,1,3}, {0,2,3,1}, {0,3,1,2}, {0,3,2,1},
        {1,0,2,3}, {1,0,3,2}, {1,2,0,3}, {1,2,3,0}, {1,3,0,2}, {1,3,2,0},
        {2,0,1,3}, {2,0,3,1}, {2,1,0,3}, {2,1,3,0}, {2,3,0,1}, {2,3,1,0},
        {3,0,1,2}, {3,0,2,1}, {3,1,0,2}, {3,1,2,0}, {3,2,0,1}, {3,2,1,0}
    };
    static constexpr uint8_t INV_PERM_TABLE[24][4] = {
        {0,1,2,3}, {0,1,3,2}, {0,2,1,3}, {0,3,1,2}, {0,2,3,1}, {0,3,2,1},
        {1,0,2,3}, {1,0,3,2}, {2,0,1,3}, {3,0,1,2}, {2,0,3,1}, {3,0,2,1},
        {1,2,0,3}, {1,3,0,2}, {2,1,0,3}, {3,1,0,2}, {2,3,0,1}, {3,2,0,1},
        {1,2,3,0}, {1,3,2,0}, {2,1,3,0}, {3,1,2,0}, {2,3,1,0}, {3,2,1,0}
    };

    // (gyro_seed>>4)&31 → PERM 인덱스 0..23 (기존 if(pi>=24) pi-=24 와 동일)
    static constexpr uint8_t PERM_IDX_FROM_5BIT[32] = {
        0u,  1u,  2u,  3u,  4u,  5u,  6u,  7u,
        8u,  9u, 10u, 11u, 12u, 13u, 14u, 15u,
        16u, 17u, 18u, 19u, 20u, 21u, 22u, 23u,
        0u,  1u,  2u,  3u,  4u,  5u,  6u,  7u
    };

    // ── 정방향 4D 회전 (Encode 전용 — signed, 클램핑 보장) ──
    static void rotate_4d_signed(
        int32_t* block4, uint32_t gyro_seed) noexcept {
        int32_t v[4] = { block4[0], block4[1], block4[2], block4[3] };

        v[0] = holo_cond_sat_neg_ct(v[0], (gyro_seed >> 0u) & 1u);
        v[1] = holo_cond_sat_neg_ct(v[1], (gyro_seed >> 1u) & 1u);
        v[2] = holo_cond_sat_neg_ct(v[2], (gyro_seed >> 2u) & 1u);
        v[3] = holo_cond_sat_neg_ct(v[3], (gyro_seed >> 3u) & 1u);

        const uint8_t pi = PERM_IDX_FROM_5BIT[
            static_cast<size_t>((gyro_seed >> 4u) & 0x1Fu)];
        const uint8_t* const p = PERM_TABLE[static_cast<size_t>(pi)];
        int32_t pv[4] = {
            v[static_cast<size_t>(p[static_cast<size_t>(0)])],
            v[static_cast<size_t>(p[static_cast<size_t>(1)])],
            v[static_cast<size_t>(p[static_cast<size_t>(2)])],
            v[static_cast<size_t>(p[static_cast<size_t>(3)])]
        };

        block4[0] = pv[0] + pv[1] + pv[2] + pv[3];
        block4[1] = pv[0] - pv[1] + pv[2] - pv[3];
        block4[2] = pv[0] + pv[1] - pv[2] - pv[3];
        block4[3] = pv[0] - pv[1] - pv[2] + pv[3];
    }

    // ── 역방향 4D 회전 (Decode 전용 — uint32_t 안전 산술) ────────
    static void inverse_rotate_4d_safe(
        int32_t* block4, uint32_t gyro_seed) noexcept {
        uint32_t uw = static_cast<uint32_t>(block4[0]);
        uint32_t ux = static_cast<uint32_t>(block4[1]);
        uint32_t uy = static_cast<uint32_t>(block4[2]);
        uint32_t uz = static_cast<uint32_t>(block4[3]);

        int32_t iv[4] = {
            static_cast<int32_t>(uw + ux + uy + uz),
            static_cast<int32_t>(uw - ux + uy - uz),
            static_cast<int32_t>(uw + ux - uy - uz),
            static_cast<int32_t>(uw - ux - uy + uz)
        };

        const uint8_t pi = PERM_IDX_FROM_5BIT[
            static_cast<size_t>((gyro_seed >> 4u) & 0x1Fu)];
        const uint8_t* const ip = INV_PERM_TABLE[static_cast<size_t>(pi)];
        int32_t rv[4] = {
            iv[static_cast<size_t>(ip[static_cast<size_t>(0)])],
            iv[static_cast<size_t>(ip[static_cast<size_t>(1)])],
            iv[static_cast<size_t>(ip[static_cast<size_t>(2)])],
            iv[static_cast<size_t>(ip[static_cast<size_t>(3)])]
        };

        rv[0] = holo_cond_sat_neg_ct(rv[0], (gyro_seed >> 0u) & 1u);
        rv[1] = holo_cond_sat_neg_ct(rv[1], (gyro_seed >> 1u) & 1u);
        rv[2] = holo_cond_sat_neg_ct(rv[2], (gyro_seed >> 2u) & 1u);
        rv[3] = holo_cond_sat_neg_ct(rv[3], (gyro_seed >> 3u) & 1u);

        block4[0] = rv[0]; block4[1] = rv[1];
        block4[2] = rv[2]; block4[3] = rv[3];
    }

    // =====================================================================
    //  Encode_Hologram — 송신부
    // =====================================================================
    void Holo_Tensor_Engine::Encode_Hologram(
        int32_t* tensor,
        uint32_t chip_count,
        const uint32_t seed[4]) noexcept {
        if (!tensor || !seed || chip_count < 4 ||
            (chip_count & 3u) != 0 ||
            (chip_count & (chip_count - 1)) != 0)
            return;

        const int32_t clamp_max = Max_Safe_Amplitude(chip_count);
        const int32_t clamp_min = static_cast<int32_t>(0) - clamp_max;
        for (uint32_t i = 0u; i < chip_count; ++i) {
            tensor[static_cast<size_t>(i)] = holo_clamp_i32_ct(
                tensor[static_cast<size_t>(i)], clamp_min, clamp_max);
        }

        fwht_signed(tensor, chip_count);

        Holo_Xoshiro128 rng = expand_seed(seed);
        for (uint32_t i = 0u; i < chip_count; i += 4u) {
            const uint32_t blk_seed = rng.next();
            rotate_4d_signed(&tensor[static_cast<size_t>(i)], blk_seed);
        }

        fwht_signed(tensor, chip_count);
        SecureMemory::secureWipe(static_cast<void*>(&rng), sizeof(rng));
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" ::: "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  Decode_Hologram — 수신부
    // =====================================================================
    uint32_t Holo_Tensor_Engine::Decode_Hologram(
        int32_t* tensor,
        uint32_t chip_count,
        const uint32_t seed[4]) noexcept {
        if (!tensor || !seed || chip_count < 4 ||
            (chip_count & 3u) != 0 ||
            (chip_count & (chip_count - 1)) != 0) {
            return SECURE_FALSE;
        }

        fwht_safe(tensor, chip_count);

        Holo_Xoshiro128 rng = expand_seed(seed);
        for (uint32_t i = 0u; i < chip_count; i += 4u) {
            const uint32_t blk_seed = rng.next();
            inverse_rotate_4d_safe(&tensor[static_cast<size_t>(i)], blk_seed);
        }

        fwht_safe(tensor, chip_count);

        // chip_count = 2의 거듭제곱 (가드 통과)
        // shift = 2 + 2×log2(N); 32비트 시프트 UB 방지 → shift_amt 산술 상한 30
        uint32_t shift_amt = 2u * log2_pow2(chip_count) + 2u;
        const uint32_t over_30 = 0u - static_cast<uint32_t>(shift_amt > 30u);
        shift_amt = (30u & over_30) | (shift_amt & ~over_30);
        const int32_t scale = static_cast<int32_t>(1u << shift_amt);

        {
            // 클램프 + 정규화 단일 패스 (tensor 1회 스캔 — 동일 수식)
            const int32_t decode_clamp = Max_Safe_Amplitude(chip_count) *
                static_cast<int32_t>(static_cast<uint32_t>(scale));
            const int32_t round_bias = scale - 1;
            for (uint32_t i = 0u; i < chip_count; ++i) {
                const int32_t x = holo_clamp_i32_ct(
                    tensor[static_cast<size_t>(i)],
                    static_cast<int32_t>(0) - decode_clamp,
                    decode_clamp);
                const uint32_t is_neg_x = static_cast<uint32_t>(x) >> 31u;
                const int32_t adj = static_cast<int32_t>(
                    static_cast<uint32_t>(is_neg_x) *
                    static_cast<uint32_t>(round_bias));
                const int32_t val = x + adj;
                const uint32_t mask_neg =
                    static_cast<uint32_t>(static_cast<int32_t>(val >> 31));
                const uint32_t abs_u =
                    (static_cast<uint32_t>(val) ^ mask_neg) - mask_neg;
                const int32_t q_mag =
                    static_cast<int32_t>(abs_u >> shift_amt);
                const uint32_t sign_v =
                    static_cast<uint32_t>(val) >> 31u;
                tensor[static_cast<size_t>(i)] = static_cast<int32_t>(
                    q_mag * (static_cast<int32_t>(1) -
                        static_cast<int32_t>(2 * static_cast<int32_t>(sign_v))));
            }
        }
        SecureMemory::secureWipe(static_cast<void*>(&rng), sizeof(rng));
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" ::: "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
        return SECURE_TRUE;
    }

} // namespace ProtectedEngine
