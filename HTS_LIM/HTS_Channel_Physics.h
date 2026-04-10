#pragma once
// =========================================================================
// HTS_Channel_Physics.h
// PC 시뮬레이션 전용 — 파라메트릭 채널(AWGN/바라지/CW/EMP) + LTE 고정 J/S 경로
//
// 단일 진실 공급원(SSoT): 구현은 HTS_Channel_Physics.cpp 단일 TU.
// HTS_3D_Tensor_FEC(LTE_Channel), HTS_TEST(종합재밍·캘리브레이션)은 본 API만 호출.
//
// ARM 펌웨어: HTS_Channel_Physics.cpp 는 CMake/vcxproj 에서 M4 타깃 제외.
// =========================================================================

#include <cstdint>
#if !defined(__arm__)
#include <random>
#include <vector>
#endif

namespace HTS_Core::Physics {

/// 종합재밍 ChannelType / 캘리브레이션 HTS_CalChannelType 과 동일 순서(0..3).
enum class ParametricChannel : std::uint8_t {
    AWGN = 0,
    BARRAGE = 1,
    CW = 2,
    EMP = 3
};

/// 파라메트릭 채널 (NUM_CHIPS=128, base_noise σ=0.01; EMP: 파괴 시 rd∈[3000,100000] 균일,
/// 비파괴 시 σ_env=200+intensity×5 스프레드 도메인)
/// @pre `rx.size() == tx.size()` — 내부에서 resize/힙 재할당 없음
void Apply_Parametric_Channel(
    const std::vector<double>& tx,
    std::mt19937& rng,
    std::vector<double>& rx,
    ParametricChannel type,
    double intensity_db);

/// CW 간섭을 텐서 전 인덱스에 주입 (캘리브레이션 확장 경로)
/// @pre `rx.size() == tx.size()`
void Apply_Cw_Full_Tensor(
    const std::vector<double>& tx,
    std::mt19937& rng,
    std::vector<double>& rx,
    double intensity_db);

/// LTE_Channel::Transmit_To 와 동일 수학 (J/S dB, 칩 수, EMP 비율).
/// EMP 펄스 진폭은 Parametric EMP 와 동일 균일 [3000,100000]; `emp_amp` 인자는 호환용(미사용).
/// @pre `out.size() == tensor.size()`
void Apply_Lte_Channel_To(
    const std::vector<double>& tensor,
    std::mt19937& rng,
    std::vector<double>& out,
    double js_db,
    int num_chips,
    double emp_rate,
    double emp_amp);

} // namespace HTS_Core::Physics
