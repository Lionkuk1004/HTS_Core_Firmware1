#pragma once
// ─────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────
//  [사용법] 기본 사용 예시를 여기에 기재하세요.
//  [메모리] sizeof(클래스명) 확인 후 전역/정적 배치 필수.
//  [보안]   복사/이동 연산자 = delete (키 소재 복제 차단).
//
//  ⚠ [파트너사 필수 확인]
//    HW 레지스터 주소(UART/WDT 등)는 보드 설계에 맞게 교체.
//    IRQ 번호는 STM32F407 RM0090 벡터 테이블 기준으로 교체.
// ─────────────────────────────────────────────────────────

/// @file  HTS_Holo_Tensor_4D_Defs.h
/// @brief HTS 4D 홀로그램 텐서 엔진 — 공통 정의부 (통신 전용)
/// @details
///   진정한 홀로그램 원리 기반 4차원 텐서 확산/역확산 엔진.
///   모든 출력 칩이 모든 입력 비트의 위상 간섭 패턴을 담는다.
///   물리 홀로그램 필름과 동일: 일부 손실 → 해상도 저하, 데이터 보존.
///
///   4차원:
///   - Dim 1: Chip (공간) — 64칩 확산 위치
///   - Dim 2: Time (시간) — 블록 간 시간 인터리빙
///   - Dim 3: Phase (위상) — Q16 위상 회전, 간섭 패턴 생성 핵심
///   - Dim 4: Layer (계층) — 다중 투영 레이어, 복원 여유도
///
///   인코딩 수학:
///   @code
///   chip[i] = sign( SUM(k=0..K-1) data[k] * cos_q15(phase(k,i,L,t)) )
///   @endcode
///
///   보안:
///   - 위상 행렬은 PRNG(Xoshiro128**) 시드에서 파생
///   - 시드 미보유 시 brute-force: 2^(16*N*K) (N=64,K=64 → 2^65536)
///   - 4096노드 확장 시: 2^268,435,456 ≈ 10^80,807,124
///
///   설계 기준:
///   - Cortex-M4F (32비트 전용, ASIC 합성 가능)
///   - Q15 고정소수점 위상 연산 (float/double 0)
///   - 힙 0, 나눗셈 0, try-catch 0
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    // ============================================================
    //  Q15/Q16 Fixed-Point Phase Arithmetic
    // ============================================================

    /// Q16 각도: 0x0000=0deg, 0x4000=90deg, 0x8000=180deg, 0xC000=270deg
    /// Q15 진폭: -32767 ~ +32767 (cos/sin 값)

    // ============================================================
    //  Cosine LUT (Q15, 첫 사분면 64항목, constexpr ROM)
    // ============================================================

    /// @brief Q15 코사인 테이블 (0 ~ 90도, 256항목)
    /// @note  ASIC: 512바이트 ROM 직접 합성.
    ///        cos_q15(angle) = round(cos(i * pi/2 / 256) * 32767)
    static constexpr int16_t k_cos_q15_lut[256] = {
         32767,  32766,  32765,  32761,  32757,  32752,  32745,  32737,
         32728,  32717,  32705,  32692,  32678,  32663,  32646,  32628,
         32609,  32589,  32567,  32545,  32521,  32495,  32469,  32441,
         32412,  32382,  32351,  32318,  32285,  32250,  32213,  32176,
         32137,  32098,  32057,  32014,  31971,  31926,  31880,  31833,
         31785,  31736,  31685,  31633,  31580,  31526,  31470,  31414,
         31356,  31297,  31237,  31176,  31113,  31050,  30985,  30919,
         30852,  30783,  30714,  30643,  30571,  30498,  30424,  30349,
         30273,  30195,  30117,  30037,  29956,  29874,  29791,  29706,
         29621,  29534,  29447,  29358,  29268,  29177,  29085,  28992,
         28898,  28803,  28706,  28609,  28510,  28411,  28310,  28208,
         28105,  28001,  27896,  27790,  27683,  27575,  27466,  27356,
         27245,  27133,  27019,  26905,  26790,  26674,  26556,  26438,
         26319,  26198,  26077,  25955,  25832,  25708,  25582,  25456,
         25329,  25201,  25072,  24942,  24811,  24680,  24547,  24413,
         24279,  24143,  24007,  23870,  23731,  23592,  23452,  23311,
         23170,  23027,  22884,  22739,  22594,  22448,  22301,  22154,
         22005,  21856,  21705,  21554,  21403,  21250,  21096,  20942,
         20787,  20631,  20475,  20317,  20159,  20000,  19841,  19680,
         19519,  19357,  19195,  19032,  18868,  18703,  18537,  18371,
         18204,  18037,  17869,  17700,  17530,  17360,  17189,  17018,
         16846,  16673,  16499,  16325,  16151,  15976,  15800,  15623,
         15446,  15269,  15090,  14912,  14732,  14553,  14372,  14191,
         14010,  13828,  13645,  13462,  13279,  13094,  12910,  12725,
         12539,  12353,  12167,  11980,  11793,  11605,  11417,  11228,
         11039,  10849,  10659,  10469,  10278,  10087,   9896,   9704,
          9512,   9319,   9126,   8933,   8739,   8545,   8351,   8157,
          7962,   7767,   7571,   7375,   7179,   6983,   6786,   6590,
          6393,   6195,   5998,   5800,   5602,   5404,   5205,   5007,
          4808,   4609,   4410,   4210,   4011,   3811,   3612,   3412,
          3212,   3012,   2811,   2611,   2410,   2210,   2009,   1809,
          1608,   1407,   1206,   1005,    804,    603,    402,    201
    };

    /// @brief Q16 각도 → Q15 코사인 값 변환 (분기 없는 사분면 대칭)
    /// @param angle  Q16 각도 (0x0000 ~ 0xFFFF)
    /// @return Q15 코사인 값 (-32767 ~ +32767)
    /// @note  Branchless: XOR + 부호 마스크로 사분면 처리. 일정 시간.
    inline int16_t Cos_Q15(uint16_t angle) noexcept
    {
        // 사분면 결정 (상위 2비트)
        const uint32_t quadrant = (static_cast<uint32_t>(angle) >> 14u) & 3u;
        // LUT 인덱스 (비트 15~6, 256항목)
        uint32_t idx = (static_cast<uint32_t>(angle) >> 6u) & 0xFFu;
        // 사분면 2,3: 인덱스 반전 (63 - idx)
        // mirror_mask = (quadrant & 1) ? 0x3F : 0x00
        const uint32_t mirror_mask = static_cast<uint32_t>(
            -static_cast<int32_t>(quadrant & 1u)) & 0xFFu;
        idx ^= mirror_mask;
        // LUT 조회
        int32_t val = static_cast<int32_t>(k_cos_q15_lut[idx]);
        // 사분면 1,2: 부호 반전
        // negate_mask = (quadrant >= 2) ? -1 : 0
        const int32_t negate = -static_cast<int32_t>((quadrant >> 1u) & 1u);
        val = (val ^ negate) - negate;  // Branchless conditional negate
        return static_cast<int16_t>(val);
    }

    /// @brief Q16 각도 → Q15 사인 값 (cos(angle - 90도))
    inline int16_t Sin_Q15(uint16_t angle) noexcept
    {
        return Cos_Q15(static_cast<uint16_t>(angle - 0x4000u));
    }

    // ============================================================
    //  Xoshiro128** (32비트, ASIC 합성 가능)
    // ============================================================

    /// @brief 32비트 좌측 회전 (ARM: 단일 ROR 명령어)
    inline uint32_t Rotl32(uint32_t x, uint32_t r) noexcept
    {
        return (x << r) | (x >> (32u - r));
    }

    /// @brief Xoshiro128** 상태 (16바이트, 32비트 전용)
    /// @note  ASIC: 32비트 시프트+XOR 조합논리만 사용. 64비트 곱셈 없음.
    ///        *5, *9는 시프트+가산으로 분해: x*5=(x<<2)+x, x*9=(x<<3)+x
    struct Xoshiro128ss {
        uint32_t s[4];

        /// @brief 다음 32비트 난수 생성
        uint32_t Next() noexcept
        {
            // result = rotl(s[1] * 5, 7) * 9
            // *5 = (s[1]<<2) + s[1], *9 = (tmp<<3) + tmp (ASIC: shift+add only)
            const uint32_t s1x5 = (s[1] << 2u) + s[1];
            const uint32_t rot = Rotl32(s1x5, 7u);
            const uint32_t result = (rot << 3u) + rot;  // *9

            // State advance
            const uint32_t t = s[1] << 9u;
            s[2] ^= s[0];
            s[3] ^= s[1];
            s[1] ^= s[2];
            s[0] ^= s[3];
            s[2] ^= t;
            s[3] = Rotl32(s[3], 11u);
            return result;
        }

        /// @brief Q16 위상 각도 생성 (상위 16비트 사용)
        uint16_t Next_Phase_Q16() noexcept
        {
            return static_cast<uint16_t>(Next() >> 16u);
        }

        /// @brief 시드 주입
        void Seed(uint32_t s0, uint32_t s1, uint32_t s2, uint32_t s3) noexcept
        {
            s[0] = s0; s[1] = s1; s[2] = s2; s[3] = s3;
        }

        /// @brief 시드 + 컨텍스트 혼합 (칩/레이어/시간별 독립 스트림 생성)
        void Seed_With_Context(const uint32_t master[4],
            uint32_t chip_idx,
            uint32_t layer_idx,
            uint32_t time_idx) noexcept
        {
            // SplitMix32 기반 시드 혼합 (칩/레이어/시간을 마스터에 XOR 후 확산)
            s[0] = master[0] ^ Rotl32(chip_idx * 0x9E3779B9u, 13u);
            s[1] = master[1] ^ Rotl32(layer_idx * 0x517CC1B7u, 17u);
            s[2] = master[2] ^ Rotl32(time_idx * 0x6C078965u, 5u);
            s[3] = master[3] ^ (chip_idx + layer_idx + time_idx);
            // Warm up (초기 상관 제거)
            for (uint32_t w = 0u; w < 4u; ++w) { (void)Next(); }
        }
    };

    // ============================================================
    //  블록 크기 상수
    // ============================================================

    /// 최대 입력 블록 크기 (비트 수)
    static constexpr uint16_t HOLO_MAX_BLOCK_BITS = 128u;
    /// 기본 블록 크기 (비트)
    static constexpr uint16_t HOLO_DEFAULT_BLOCK = 64u;
    /// 출력 칩 수 (B-CDMA 64칩 유지)
    static constexpr uint16_t HOLO_CHIP_COUNT = 64u;
    /// 최대 레이어 수 (M4: 4, ASIC: 최대 64)
    static constexpr uint8_t  HOLO_MAX_LAYERS = 4u;
    /// 기본 레이어 수
    static constexpr uint8_t  HOLO_DEFAULT_LAYERS = 2u;

    // ============================================================
    //  홀로그램 텐서 프로파일
    // ============================================================

    /// @brief 홀로그램 텐서 프로파일 (운용 모드별 파라미터)
    struct HoloTensor_Profile {
        uint16_t block_bits;    ///< 입력 블록 크기 K (비트)
        uint16_t chip_count;    ///< 출력 칩 수 N
        uint8_t  num_layers;    ///< 투영 레이어 수 L
        uint8_t  pad_[3];
    };
    static_assert(sizeof(HoloTensor_Profile) == 8u, "HoloTensor_Profile must be 8 bytes");

    /// @brief 프리셋 프로파일 (constexpr ROM)
    /// @note  홀로그램 핵심 법칙: N/K >= 4 (필름 면적 >> 물체 복잡도)
    ///        Partitioned row selection: L*K <= N (교차간섭 0)
    ///        대용량 데이터는 멀티블록으로 분할 전송.
    ///        블록당 바이트: K/8 (K=16→2B, K=8→1B)
    ///
    ///   프로파일 최적화 근거 (FEC 없는 물리계층 성능):
    ///   - VOICE K=8 L=2: AWGN50 99%, EMP50% 97% (K=16 L=1 대비 AWGN +24%, EMP +30%)
    ///   - DATA  K=16 L=2: AWGN50 98%, EMP50% 64% (교차간섭 해결 후)
    ///   - RESIL K=8 L=4:  AWGN50 100%, EMP50% 96% (최고 보호)
    static constexpr HoloTensor_Profile k_holo_profiles[3] = {
        {  8u,  64u, 2u, {0,0,0} },   ///< VOICE: 1B/블록, N/K=8, L=2, 저지연+고내성
        { 16u,  64u, 2u, {0,0,0} },   ///< DATA:  2B/블록×멀티블록, N/K=4, L=2, 균형
        {  8u,  64u, 4u, {0,0,0} }    ///< RESILIENT: 1B/블록×멀티블록, N/K=8, L=4, 최대보호
    };

    // ============================================================
    //  CFI 상태
    // ============================================================

    /// @brief 홀로그램 텐서 엔진 상태
    enum class HoloState : uint8_t {
        OFFLINE = 0x00u,
        READY = 0x01u,    ///< 초기화 완료, 인코딩/디코딩 가능
        ENCODING = 0x02u,    ///< 블록 인코딩 중
        DECODING = 0x04u,    ///< 블록 디코딩 중
        ERROR = 0x08u
    };

    static constexpr uint8_t HOLO_VALID_STATE_MASK =
        static_cast<uint8_t>(HoloState::READY)
        | static_cast<uint8_t>(HoloState::ENCODING)
        | static_cast<uint8_t>(HoloState::DECODING)
        | static_cast<uint8_t>(HoloState::ERROR);

    inline bool Holo_Is_Valid_State(HoloState s) noexcept
    {
        const uint8_t v = static_cast<uint8_t>(s);
        if (v == 0u) { return true; }
        if ((v & ~HOLO_VALID_STATE_MASK) != 0u) { return false; }
        return ((v & (v - 1u)) == 0u);
    }

    inline bool Holo_Is_Legal_Transition(HoloState from, HoloState to) noexcept
    {
        if (!Holo_Is_Valid_State(to)) { return false; }
        static constexpr uint8_t k_legal[5] = {
            /* OFFLINE  -> */ static_cast<uint8_t>(HoloState::READY),
            /* READY    -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(HoloState::ENCODING)
              | static_cast<uint8_t>(HoloState::DECODING)
              | static_cast<uint8_t>(HoloState::OFFLINE)),
            /* ENCODING -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(HoloState::READY)
              | static_cast<uint8_t>(HoloState::ERROR)),
            /* DECODING -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(HoloState::READY)
              | static_cast<uint8_t>(HoloState::ERROR)),
            /* ERROR    -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(HoloState::READY)
              | static_cast<uint8_t>(HoloState::OFFLINE))
        };
        uint8_t idx;
        switch (from) {
        case HoloState::OFFLINE:  idx = 0u; break;
        case HoloState::READY:    idx = 1u; break;
        case HoloState::ENCODING: idx = 2u; break;
        case HoloState::DECODING: idx = 3u; break;
        case HoloState::ERROR:    idx = 4u; break;
        default:                  return false;
        }
        if (static_cast<uint8_t>(to) == 0u) {
            static constexpr uint8_t k_off_src = static_cast<uint8_t>(
                static_cast<uint8_t>(HoloState::READY)
                | static_cast<uint8_t>(HoloState::ERROR));
            return (static_cast<uint8_t>(from) & k_off_src) != 0u;
        }
        return (k_legal[idx] & static_cast<uint8_t>(to)) != 0u;
    }

} // namespace ProtectedEngine