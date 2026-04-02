// =========================================================================
// HTS_Holo_Tensor_Engine.cpp — 4D 홀로그래픽 텐서 변조/암호화 코어
// Target: STM32F407 (Cortex-M4) — 순수 정수 연산
//
#include "HTS_Holo_Tensor_Engine.h"
#include <cstring>
#include <atomic>

namespace ProtectedEngine {
    namespace {
        static inline int32_t holo_sat_neg_i32(int32_t x) noexcept {
            if (x == static_cast<int32_t>(0x80000000u)) {
                return static_cast<int32_t>(0x7FFFFFFFu);
            }
            return static_cast<int32_t>(-x);
        }

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

        static inline int32_t holo_clamp_i32_ct(
            int32_t v, int32_t lo, int32_t hi) noexcept {
            int32_t x = (v > hi) ? hi : v;
            x = (x < lo) ? lo : x;
            return x;
        }
    }

    // ── Xoshiro128ss — 128비트 상태 PRNG ───────────────────────
    //  128비트 상태 공간 — 단일 출력으로의 상태 복원 비현실적
    struct Holo_Xoshiro128 {
        uint32_t s[4];

        static uint32_t rotl(uint32_t x, int k) noexcept {
            return (x << k) | (x >> (32 - k));
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
        uint32_t r = 0;
        while (n > 1) { n >>= 1; ++r; }
        return r;
    }

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
        for (uint32_t len = 1; len < n; len <<= 1) {
            for (uint32_t i = 0; i < n; i += 2 * len) {
                for (uint32_t j = 0; j < len; ++j) {
                    int32_t u = tensor[i + j];
                    int32_t v = tensor[i + len + j];
                    tensor[i + j] = u + v;
                    tensor[i + len + j] = u - v;
                }
            }
        }
    }

    static void fwht_safe(int32_t* tensor, uint32_t n) noexcept {
        for (uint32_t len = 1; len < n; len <<= 1) {
            for (uint32_t i = 0; i < n; i += 2 * len) {
                for (uint32_t j = 0; j < len; ++j) {
                    uint32_t u = static_cast<uint32_t>(tensor[i + j]);
                    uint32_t v = static_cast<uint32_t>(tensor[i + len + j]);
                    tensor[i + j] = static_cast<int32_t>(u + v);
                    tensor[i + len + j] = static_cast<int32_t>(u - v);
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

    // ── 정방향 4D 회전 (Encode 전용 — signed, 클램핑 보장) ──
    static void rotate_4d_signed(
        int32_t* block4, uint32_t gyro_seed) noexcept {
        int32_t v[4] = { block4[0], block4[1], block4[2], block4[3] };

        v[0] = holo_cond_sat_neg_ct(v[0], (gyro_seed >> 0u) & 1u);
        v[1] = holo_cond_sat_neg_ct(v[1], (gyro_seed >> 1u) & 1u);
        v[2] = holo_cond_sat_neg_ct(v[2], (gyro_seed >> 2u) & 1u);
        v[3] = holo_cond_sat_neg_ct(v[3], (gyro_seed >> 3u) & 1u);

        uint8_t pi = static_cast<uint8_t>((gyro_seed >> 4u) & 0x1Fu);
        if (pi >= 24u) pi -= 24u;
        const uint8_t* p = PERM_TABLE[pi];
        int32_t pv[4] = { v[p[0]], v[p[1]], v[p[2]], v[p[3]] };

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

        uint8_t pi = static_cast<uint8_t>((gyro_seed >> 4u) & 0x1Fu);
        if (pi >= 24u) pi -= 24u;
        const uint8_t* ip = INV_PERM_TABLE[pi];
        int32_t rv[4] = { iv[ip[0]], iv[ip[1]], iv[ip[2]], iv[ip[3]] };

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
        const int32_t clamp_min = -clamp_max;
        for (uint32_t i = 0; i < chip_count; ++i) {
            tensor[i] = holo_clamp_i32_ct(tensor[i], clamp_min, clamp_max);
        }

        fwht_signed(tensor, chip_count);

        Holo_Xoshiro128 rng = expand_seed(seed);
        for (uint32_t i = 0; i < chip_count; i += 4) {
            const uint32_t blk_seed = rng.next();
            rotate_4d_signed(&tensor[i], blk_seed);
        }

        fwht_signed(tensor, chip_count);
    }

    // =====================================================================
    //  Decode_Hologram — 수신부
    // =====================================================================
    void Holo_Tensor_Engine::Decode_Hologram(
        int32_t* tensor,
        uint32_t chip_count,
        const uint32_t seed[4]) noexcept {
        if (!tensor || !seed || chip_count < 4 ||
            (chip_count & 3u) != 0 ||
            (chip_count & (chip_count - 1)) != 0)
            return;

        fwht_safe(tensor, chip_count);

        Holo_Xoshiro128 rng = expand_seed(seed);
        for (uint32_t i = 0; i < chip_count; i += 4) {
            const uint32_t blk_seed = rng.next();
            inverse_rotate_4d_safe(&tensor[i], blk_seed);
        }

        fwht_safe(tensor, chip_count);

        //  ARM Cortex-M4: 즉치(Immediate) ASR = 1사이클 확정
        //  chip_count = 2의 거듭제곱 (가드 통과)
        //  shift = 2 + 2×log2(N): N=4→4, N=8→8, N=16→10,
        //                          N=32→12, N=64→14, N=128→16
        uint32_t shift_amt;
        int32_t scale;
        switch (chip_count) {
        case 4:   shift_amt = 4u;  scale = (1 << 4);  break;
        case 8:   shift_amt = 8u;  scale = (1 << 8);  break;
        case 16:  shift_amt = 10u; scale = (1 << 10); break;
        case 32:  shift_amt = 12u; scale = (1 << 12); break;
        case 64:  shift_amt = 14u; scale = (1 << 14); break;
        case 128: shift_amt = 16u; scale = (1 << 16); break;
        case 256: shift_amt = 18u; scale = (1 << 18); break;
        default: {
            const uint32_t log2_n = log2_pow2(chip_count);
            shift_amt = 2u * log2_n + 2u;
            if (shift_amt >= 31u) { return; }  // UB 방지: 1u << shift_amt
            scale = static_cast<int32_t>(1u << shift_amt);
            break;
        }
        }

        // 정규화 전 클램핑 복원 (악성 패킷 안전)
        const int32_t decode_clamp = Max_Safe_Amplitude(chip_count) *
            static_cast<int32_t>(static_cast<uint32_t>(scale));
        for (uint32_t i = 0; i < chip_count; ++i) {
            tensor[i] = holo_clamp_i32_ct(tensor[i], -decode_clamp, decode_clamp);
        }

        // 산술 시프트 (음수 0방향 반올림 보존, branchless)
        const int32_t round_bias = scale - 1;
        for (uint32_t i = 0; i < chip_count; ++i) {
            const int32_t x = tensor[i];
            tensor[i] = (x + ((x >> 31) & round_bias))
                >> static_cast<int>(shift_amt);
        }
    }

} // namespace ProtectedEngine
