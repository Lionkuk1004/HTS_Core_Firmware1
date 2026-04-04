#pragma once
// =========================================================================
// HTS_Sensor_ADC_Guard.h
// 엣지 ADC / 부동소수점 센서 → 홀로/디스패처 int16 소프트 심볼 경로 직전 방어
// Target: STM32F407F (단, 본 헤더의 float API는 FPU 있는 경로 전용)
//
// @note Cortex-M4F 양산: FPSCR의 FZ(DAZ) 비트로 서브노멀 페널티 완화 가능.
//       펌웨어 부팅 시 HW 초기화 계층에서 설정 — 본 함수는 소프트웨어 2차 방어.
// =========================================================================
#include <cmath>
#include <cstdint>

namespace ProtectedEngine {

/// @brief NaN/±Inf/서브노멀을 제거한 유한 float (실패 시 0)
[[nodiscard]] inline float Sanitize_Float_Sensor_For_Q15(float x) noexcept
{
    if (!std::isfinite(x)) {
        return 0.f;
    }
    if (std::fpclassify(x) == FP_SUBNORMAL) {
        return 0.f;
    }
    return x;
}

/// @brief [-1,1] 클램프 후 대략 Q13 스케일 int16 (홀로 Decode_Block 소프트 입력용)
[[nodiscard]] inline int16_t Float_Sensor_To_Soft_Symbol(float x) noexcept
{
    const float c = Sanitize_Float_Sensor_For_Q15(x);
    const float t = (c < -1.f) ? -1.f : ((c > 1.f) ? 1.f : c);
    const float s = t * 8192.f;
    if (s >= 32767.f) {
        return 32767;
    }
    if (s <= -32768.f) {
        return -32768;
    }
    return static_cast<int16_t>(s);
}

} // namespace ProtectedEngine
