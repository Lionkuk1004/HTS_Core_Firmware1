// =============================================================================
/// @file  HTS_Polar_Codec.h
/// @brief Polar 코덱 — SC/SCL 인코더·디코더 (N=512, K=80)
/// @target STM32F407 (Cortex-M4F, 168MHz, SRAM 192KB) / PC
///
///  [파라미터]
///   N = 512   코드 길이 (2^9)
///   K = 80    정보 비트 (64 데이터 + 16 CRC)
///   R = 0.156 코드율
///
///  [디코더 계층]
///   SC:    연속 취소 (Successive Cancellation) — 1.5KB, 83µs
///   SCL-4: 리스트 SC, CRC-Aided — 6KB, 327µs
///
///  [제약] float 0, double 0, 나눗셈 0, try-catch 0, 힙 0
// =============================================================================
#pragma once
#include <cstddef>
#include <cstdint>
namespace ProtectedEngine {
class HTS_Polar_Codec {
  public:
    // ── 코드 파라미터 ──────────────────────────────────────────
    static constexpr int N = 1024;       ///< 코드 길이 (2^10)
    static constexpr int LOG_N = 10;     ///< log2(N)
    static constexpr int K = 80;         ///< 정보 비트 (64데이터 + 16CRC)
    static constexpr int FROZEN = N - K; ///< 944 frozen 비트
    static constexpr int DATA_BYTES = 8; ///< 데이터 바이트 수
    static constexpr int CRC_BITS = 16;  ///< CRC-16 비트
    // ── SCL 파라미터 ──────────────────────────────────────────
    static constexpr int SCL_L = 4; ///< 리스트 크기 (N=1024에서 메모리 제약)
    // ── 인코딩 ────────────────────────────────────────────────
    /// @brief Polar 인코딩: 80비트 정보 → 512비트 코드워드
    /// @param info    8바이트 데이터 (64비트)
    /// @param info_len 바이트 수 (≤8)
    /// @param coded   출력: 512비트 (64바이트, MSB first)
    /// @return 성공 시 N(512), 실패 시 0
    [[nodiscard]] static int Encode(const uint8_t *info, int info_len,
                                    uint8_t *coded) noexcept;
    // ── SC 디코딩 ─────────────────────────────────────────────
    /// @brief SC 디코더: LLR 512개 → 80비트 정보 복원
    /// @param llr     입력 LLR (int16_t[512], 양수=0 쪽, 음수=1 쪽)
    /// @param out     복원된 8바이트 데이터
    /// @param out_len 유효 바이트 수
    /// @return CRC 통과 시 true
    [[nodiscard]] static bool Decode_SC(const int16_t *llr, uint8_t *out,
                                        int *out_len) noexcept;
    // ── SCL-8 디코딩 ─────────────────────────────────────────
    /// @brief SCL-8 CRC-Aided 디코더
    /// @param llr     입력 LLR (int16_t[512])
    /// @param out     복원된 8바이트 데이터
    /// @param out_len 유효 바이트 수
    /// @return CRC 통과 경로 존재 시 true
    [[nodiscard]] static bool Decode_SCL(const int16_t *llr, uint8_t *out,
                                         int *out_len) noexcept;
    // ── Frozen 비트 마스크 ────────────────────────────────────
    /// @brief 비트 i가 정보 비트이면 1, frozen이면 0
    /// @param i 비트 인덱스 (0 ≤ i < N)
    [[nodiscard]] static bool Is_Info_Bit(int i) noexcept;
    // ── CRC-16/CCITT ──────────────────────────────────────────
    [[nodiscard]] static uint16_t CRC16(const uint8_t *data, int len) noexcept;
    HTS_Polar_Codec() = delete;
    ~HTS_Polar_Codec() = delete;
    HTS_Polar_Codec(const HTS_Polar_Codec &) = delete;
    HTS_Polar_Codec &operator=(const HTS_Polar_Codec &) = delete;

  private:
    // ── 내부 연산 ─────────────────────────────────────────────
    /// @brief f-node: f(a,b) ≈ sign(a)×sign(b)×min(|a|,|b|)
    static int16_t f_node_(int16_t a, int16_t b) noexcept;
    /// @brief g-node: g(a,b,u) = b + (1-2u)×a
    static int16_t g_node_(int16_t a, int16_t b, uint8_t u) noexcept;
    /// @brief Polar 인코딩 나비 연산 (GF(2) XOR, in-place)
    static void encode_butterfly_(uint8_t *u, int n) noexcept;
    /// @brief 비트 반전 순열 (bit-reversal permutation)
    static int bit_reverse_(int val, int bits) noexcept;
};
// ── 메모리 예산 정적 검증 ────────────────────────────────────
static_assert(HTS_Polar_Codec::N == 1024, "Polar N must be 1024");
static_assert(HTS_Polar_Codec::K == 80, "Polar K must be 80");
static_assert(HTS_Polar_Codec::FROZEN == 944, "Frozen count mismatch");
static_assert(HTS_Polar_Codec::LOG_N == 10, "LOG_N mismatch");
} // namespace ProtectedEngine
