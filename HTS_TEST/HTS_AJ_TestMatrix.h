// =============================================================================
/// @file HTS_AJ_TestMatrix.h
/// @brief 144개 시험 케이스 constexpr 매트릭스 (4×9×2×2)
/// @details 채널 4종 × J/S 9단 × 칩 16/64 × IR-HARQ on/off
// =============================================================================
#ifndef HTS_AJ_TESTMATRIX_H
#define HTS_AJ_TESTMATRIX_H

#include <cstdint>

/// 채널·재밍 유형 (스펙 동일 인덱스)
enum AJ_ChannelType : uint8_t {
    AJ_CH_AWGN = 0u,
    AJ_CH_BARRAGE = 1u,
    AJ_CH_CW = 2u,
    AJ_CH_EMP = 3u
};

struct AJ_TestCase {
    uint16_t test_id;     ///< T-001 … T-144
    uint8_t channel_type; ///< AJ_ChannelType
    uint8_t jam_type;     ///< 동일 분류 (CSV용)
    uint8_t js_dB;        ///< 0,10,…,50
    uint8_t chip_mode;    ///< 16 또는 64
    uint8_t bps;          ///< 3~6 (M4 시뮬 시 클램프는 런너에서 반영)
    uint8_t harq_on;      ///< 0=OFF 1=ON
    uint16_t frame_count; ///< 프레임 반복
    uint8_t pass_threshold_pct; ///< 합격 기준 (시험 전 고정, 케이스별 산출)
};

constexpr uint8_t AJ_JS_TABLE[9u] = {0u, 10u, 20u, 25u, 30u,
                                     35u, 40u, 45u, 50u};

constexpr uint16_t AJ_MATRIX_COUNT = 144u;

/// @brief 인덱스 0..143 → 케이스 (런타임 생성 금지 대신 컴파일 타임 함수)
constexpr AJ_TestCase AJ_MakeCase(uint16_t idx) noexcept {
    AJ_TestCase t{};
    if (idx >= AJ_MATRIX_COUNT) {
        t.test_id = 0;
        return t;
    }
    const uint8_t ch = static_cast<uint8_t>(idx % 4u);
    const uint8_t r1 = static_cast<uint8_t>(idx / 4u);
    const uint8_t js_idx = static_cast<uint8_t>(r1 % 9u);
    const uint8_t r2 = static_cast<uint8_t>(r1 / 9u);
    const uint8_t chip64 = static_cast<uint8_t>(r2 % 2u);
    const uint8_t harq = static_cast<uint8_t>(r2 / 2u);
    t.test_id = static_cast<uint16_t>(idx + 1u);
    t.channel_type = ch;
    t.jam_type = ch;
    t.js_dB = AJ_JS_TABLE[js_idx];
    t.chip_mode = static_cast<uint8_t>(chip64 != 0u ? 64u : 16u);
    t.bps = 4u;
    t.harq_on = harq;
    t.frame_count = 1000u;
    t.pass_threshold_pct = 0u;
    return t;
}

/// @brief 시험 전 고정 합격 기준 (%)
constexpr uint8_t AJ_PassThresholdPct(const AJ_TestCase& c) noexcept {
    const uint8_t js = c.js_dB;
    const bool is64 = (c.chip_mode == 64u);
    if (js == 0u) {
        return 99u;
    }
    if (js <= 25u) {
        return 95u;
    }
    if (!is64 && js >= 30u && js <= 40u) {
        return 90u;
    }
    if (is64 && js >= 30u && js <= 50u) {
        return 90u;
    }
    return 90u;
}

/// @brief 전 매트릭스 채우기 (TU 초기화 시 1회)
inline void AJ_FillMatrix(AJ_TestCase* out, uint16_t count) noexcept {
    for (uint16_t i = 0u; i < count && i < AJ_MATRIX_COUNT; ++i) {
        out[i] = AJ_MakeCase(i);
        out[i].pass_threshold_pct = AJ_PassThresholdPct(out[i]);
    }
}

#endif
