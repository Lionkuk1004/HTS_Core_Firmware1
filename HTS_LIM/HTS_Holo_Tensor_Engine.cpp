// =========================================================================
// HTS_Holo_Tensor_Engine.cpp — 4D 홀로그래픽 텐서 변조/암호화 코어
// Target: STM32F407 (Cortex-M4) — 순수 정수 연산
//
// [양산 수정 — 13건]
//  BUG-01 [HIGH] XorShift32 → SplitMix64 출력 화이트닝
//  BUG-02 [HIGH] 4D 순열 4→24가지 (4! 전체)
//  BUG-03 [LOW]  sec_wipe dead code 제거
//  BUG-04 [LOW]  int → uint32_t 파라미터
//  BUG-05 [CRIT] signed overflow → uint32_t 모듈로 산술 (Decode 방어)
//  BUG-06 [HIGH] >>14 음수 편향 → /= scale 대칭 절사
//  BUG-07 [HIGH] 64 하드코딩 → chip_count 파라미터화
//  BUG-08 [HIGH] >>14 고정 → 동적 정규화 log2(N²×4)
//  BUG-09 [CRIT] 모듈로 랩어라운드 + 나눗셈 충돌 → Encode 클램핑
//  BUG-10 [CRIT] Encode/Decode 이중 방어 융합
//    Encode: 입력 클램핑 → signed 연산 안전 (수학적 정합성 완벽)
//    Decode: 외부 패킷 제어 불가 → uint32_t 안전 산술 (UB 방지)
//           + 정규화 전 클램핑 복원 (모듈로 랩어라운드 → 나눗셈 충돌 차단)
// =========================================================================
#include "HTS_Holo_Tensor_Engine.h"
#include <cstring>
#include <atomic>

namespace ProtectedEngine {

    // ── [BUG-13] 32비트 XorShift PRNG (64비트 곱셈 제거) ──
    // 기존 SplitMix64: uint64_t 곱셈 3회 → __aeabi_lmul ~90cyc/호출
    // 수정: XorShift32 → 3명령어, 전부 단일사이클
    static uint32_t prng32_next(uint32_t& state) noexcept {
        state ^= state << 13u;
        state ^= state >> 17u;
        state ^= state << 5u;
        return state;
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
        // [BUG-13] 64비트 나눗셈 → 32비트 시프트
        const uint32_t shift = 2u + 2u * log2_pow2(chip_count);
        if (shift >= 31u) return 0;
        return static_cast<int32_t>(0x7FFFFFFFu >> shift);
    }

    // =====================================================================
    //  FWHT — 이중 모드
    //  [BUG-10] safe=false: signed 연산 (Encode — 클램핑 보장)
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

    // [BUG-05/10] uint32_t 모듈로 산술 — signed overflow UB 완전 차단
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

    // ── 24가지 전체 순열 테이블 [BUG-02] ──
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

        if (gyro_seed & 0x01u) v[0] = -v[0];
        if (gyro_seed & 0x02u) v[1] = -v[1];
        if (gyro_seed & 0x04u) v[2] = -v[2];
        if (gyro_seed & 0x08u) v[3] = -v[3];

        // [BUG-11] % 24u → 마스크+조건빼기 (UDIV 제거)
        uint8_t pi = static_cast<uint8_t>((gyro_seed >> 4u) & 0x1Fu);
        if (pi >= 24u) pi -= 24u;
        const uint8_t* p = PERM_TABLE[pi];
        int32_t pv[4] = { v[p[0]], v[p[1]], v[p[2]], v[p[3]] };

        block4[0] = pv[0] + pv[1] + pv[2] + pv[3];
        block4[1] = pv[0] - pv[1] + pv[2] - pv[3];
        block4[2] = pv[0] + pv[1] - pv[2] - pv[3];
        block4[3] = pv[0] - pv[1] - pv[2] + pv[3];
    }

    // ── 역방향 4D 회전 (Decode 전용 — uint32_t 안전 산술) [BUG-05/10] ──
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

        // [BUG-11] % 24u → 마스크+조건빼기 (UDIV 제거)
        uint8_t pi = static_cast<uint8_t>((gyro_seed >> 4u) & 0x1Fu);
        if (pi >= 24u) pi -= 24u;
        const uint8_t* ip = INV_PERM_TABLE[pi];
        int32_t rv[4] = { iv[ip[0]], iv[ip[1]], iv[ip[2]], iv[ip[3]] };

        if (gyro_seed & 0x01u) rv[0] = -rv[0];
        if (gyro_seed & 0x02u) rv[1] = -rv[1];
        if (gyro_seed & 0x04u) rv[2] = -rv[2];
        if (gyro_seed & 0x08u) rv[3] = -rv[3];

        block4[0] = rv[0]; block4[1] = rv[1];
        block4[2] = rv[2]; block4[3] = rv[3];
    }

    // =====================================================================
    //  Encode_Hologram — 송신부
    //  [BUG-09] 입력 클램핑 → signed 연산 안전 (수학적 정합성 완벽)
    // =====================================================================
    void Holo_Tensor_Engine::Encode_Hologram(
        int32_t* tensor,
        uint32_t chip_count,
        uint32_t gyro_phase) noexcept {
        if (!tensor || chip_count < 4 ||
            (chip_count & (chip_count - 1)) != 0)
            return;

        // [BUG-09] 입력 클램핑 → 중간 연산 int32_t 이내 보장
        const int32_t clamp_max = Max_Safe_Amplitude(chip_count);
        const int32_t clamp_min = -clamp_max;
        for (uint32_t i = 0; i < chip_count; ++i) {
            if (tensor[i] > clamp_max) tensor[i] = clamp_max;
            else if (tensor[i] < clamp_min) tensor[i] = clamp_min;
        }

        // 클램핑 보장 → signed FWHT (수학적 정합성)
        fwht_signed(tensor, chip_count);

        // [BUG-13] 32비트 PRNG (64비트 곱셈 제거)
        uint32_t prng_state = gyro_phase;
        if (prng_state == 0u) prng_state = 0x9E3779B9u;
        for (uint32_t i = 0; i < chip_count; i += 4) {
            uint32_t seed = prng32_next(prng_state);
            rotate_4d_signed(&tensor[i], seed);
        }

        fwht_signed(tensor, chip_count);
    }

    // =====================================================================
    //  Decode_Hologram — 수신부
    //  [BUG-05/10] 외부 패킷 → uint32_t 안전 산술 (UB 완전 차단)
    //  [BUG-10] 정규화 전 클램핑: 모듈로 랩어라운드 상태에서 나눗셈 방지
    //  [BUG-08] 동적 정규화 + [BUG-06] /= 대칭 절사
    // =====================================================================
    void Holo_Tensor_Engine::Decode_Hologram(
        int32_t* tensor,
        uint32_t chip_count,
        uint32_t gyro_phase) noexcept {
        if (!tensor || chip_count < 4 ||
            (chip_count & (chip_count - 1)) != 0)
            return;

        // [BUG-05/10] uint32_t 안전 FWHT (악성 패킷 UB 방지)
        fwht_safe(tensor, chip_count);

        // [BUG-05/10] uint32_t 안전 역4D 회전
        // [BUG-13] 32비트 PRNG
        uint32_t prng_state = gyro_phase;
        if (prng_state == 0u) prng_state = 0x9E3779B9u;
        for (uint32_t i = 0; i < chip_count; i += 4) {
            uint32_t seed = prng32_next(prng_state);
            inverse_rotate_4d_safe(&tensor[i], seed);
        }

        // [BUG-05/10] uint32_t 안전 FWHT
        fwht_safe(tensor, chip_count);

        // [BUG-08] 동적 정규화 시프트 (나눗셈 → 시프트 최적화)
        // scale = 1 << shift_amt → 항상 2의 거듭제곱
        // SDIV: 2~12 사이클 vs ASR: 1 사이클
        const uint32_t log2_n = log2_pow2(chip_count);
        const uint32_t shift_amt = 2u * log2_n + 2u;
        const int32_t scale = static_cast<int32_t>(1u << shift_amt);

        // [BUG-10] 정규화 전 클램핑 복원
        // 모듈로 래핑이 발생했더라도 나눗셈 전에 유효 범위로 복원
        // 정상 패킷: 래핑 없음 → 클램핑 무영향
        // 악성 패킷: 래핑 발생 → 쓰레기값이지만 나눗셈 UB 없이 안전 절사
        const int32_t decode_clamp = Max_Safe_Amplitude(chip_count) *
            static_cast<int32_t>(static_cast<uint32_t>(scale));
        for (uint32_t i = 0; i < chip_count; ++i) {
            if (tensor[i] > decode_clamp) tensor[i] = decode_clamp;
            else if (tensor[i] < -decode_clamp) tensor[i] = -decode_clamp;
        }

        // [BUG-06→11] 나눗셈 → 산술 시프트 (음수 0방향 반올림 보존)
        //
        // 문제: >> 는 -∞ 방향 (음수 편향), / 는 0 방향 (대칭)
        //   -7 >> 2 = -2 (floor)  vs  -7 / 4 = -1 (truncate)
        //
        // 해결: 음수일 때 (scale-1)을 더한 후 시프트
        //   x / scale = (x + ((x >> 31) & (scale - 1))) >> shift_amt
        //   음수: x + (scale-1) → -∞ 방향 시프트가 0 방향이 됨
        //   양수: x + 0 → 그대로 (>> 31 = 0)
        //
        // ARM: ASR + AND + ADD + ASR = 4사이클 고정 (SDIV 2~12 vs 4 고정)
        //   chip_count=64, 칩당 4사이클 × 64 = 256사이클 절감
        const int32_t round_bias = scale - 1;  // 2^shift - 1
        for (uint32_t i = 0; i < chip_count; ++i) {
            const int32_t x = tensor[i];
            // branchless: 음수면 (scale-1) 보정, 양수면 0
            tensor[i] = (x + ((x >> 31) & round_bias)) >> static_cast<int>(shift_amt);
        }
    }

} // namespace ProtectedEngine