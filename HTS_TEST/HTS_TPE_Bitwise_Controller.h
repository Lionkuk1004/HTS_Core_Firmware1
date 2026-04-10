// =========================================================================
// HTS_TPE_Bitwise_Controller.h
// 테라 코어-X48 Pro — TPE(Tensor Processing Element) 범용 비트 논리 데이터 플레인
// Target: ARM Cortex-M4(F) — 상수 시간·무분기(소스 레벨 if/switch/?: 금지)
//
// [계약]
//  - 동적 할당·예외·나눗셈(/)·모듈로(%)·<cmath> 금지
//  - 제어: if / else / switch / ?: 미사용; 판별은 &, |, ^, ~, >> 만 사용
//  - 비교 연산자(>, <, ==) 소스 미사용 — 대소는 u32_gt_mask_u64 등 산술·시프트로만
//  - 정수 승격·암시적 변환 최소화; 필요 시 static_cast 명시
//
// [ADC Flat-Top / 클리핑 방어]
//  - 국소 피크(기울기)만으로는 32767,32767,32767 연속 레일이 누락될 수 있음.
//  - |curr| 가 정규화 int16 레일(32767) 이상이면 clipping_mask 로 bomb_mask 에 강제 OR.
//
// [증명 요지 — Cortex-M4 / Thumb-2]
//  - 분기 명령(Bcc)이 없으면 BTB/분기 예측 미스 페널티가 발생하지 않음.
//  - 본 헤더의 핵심 경로는 AND/OR/EOR/SUB/LSR/NEG 등 데이터 처리 명령으로만 구성되며,
//    컴파일러가 IT 블록으로 조건부 실행을 넣더라도 **예측 실패에 따른 파이프라인
//    플러시**는 전형적인 조건부 분기보다 훨씬 저비용이다.
//  - 단일 사이클(1c): 레지스터 피연산자에 대한 AND/OR/EOR/LSL/LSR 등은 1사이클.
//    uint64_t 연산·다중 SUB는 여러 사이클이나 **데이터에 따른 가변 사이클(조기 종료)
//    를 만들지 않는다**(상수 시간).
// =========================================================================
#pragma once

#include <cstdint>

namespace ProtectedEngine {
namespace TPE_Bitwise {

    /// int16 ADC 정규화 레일: |x| ≥ 32767 (32767·32768 포함) → 클리핑 의심
    /// u32_gt_mask_u64(abs, k_adc_sat_abs_gt_ref) = ~0u 는 abs > 32766 ≡ abs ≥ 32767
    static constexpr uint32_t k_adc_sat_abs_gt_ref = 32766u;

    // -----------------------------------------------------------------
    // 내부: unsigned a > b 를 전비트 마스크로 (~0u / 0u). 비교 연산자 미사용.
    // 수식: t = (uint64)a + 2^32 - (uint64)b - 1  →  a>b 이면 t >= 2^32.
    // -----------------------------------------------------------------
    [[nodiscard]] inline uint32_t u32_gt_mask_u64(uint32_t a, uint32_t b) noexcept
    {
        const uint64_t t =
            static_cast<uint64_t>(a)
            + (UINT64_C(1) << 32)
            - static_cast<uint64_t>(b)
            - UINT64_C(1);
        const uint32_t bit = static_cast<uint32_t>(t >> 32);
        return static_cast<uint32_t>(0u - bit);
    }

    // int32 전역 순서 보존: XOR 0x80000000 으로 unsigned 공간에 올려 비교
    [[nodiscard]] inline uint32_t i32_gt_mask(int32_t a, int32_t b) noexcept
    {
        const uint32_t ua =
            static_cast<uint32_t>(a) ^ UINT32_C(0x80000000);
        const uint32_t ub =
            static_cast<uint32_t>(b) ^ UINT32_C(0x80000000);
        return u32_gt_mask_u64(ua, ub);
    }

    /// @brief int32 절대값을 uint32 로 (분기 없음). (ux ^ sm) - sm, sm = 부호 비트 확장
    /// @note  Cortex-M4: ASR → XOR → SUB 고정 경로.
    [[nodiscard]] inline uint32_t i32_abs_as_u32(int32_t v) noexcept
    {
        const uint32_t ux = static_cast<uint32_t>(v);
        const uint32_t sm = static_cast<uint32_t>(static_cast<int32_t>(v >> 31));
        return static_cast<uint32_t>((ux ^ sm) - sm);
    }

    /// @brief |curr| 레일 포화 마스크: abs ≥ 32767 이면 ~0u (비교 연산자 미사용)
    [[nodiscard]] inline uint32_t adc_clipping_mask_from_i32(int32_t curr) noexcept
    {
        const uint32_t abs_curr = i32_abs_as_u32(curr);
        return u32_gt_mask_u64(abs_curr, k_adc_sat_abs_gt_ref);
    }

    /// @brief 입력의 부호 상태를 {-1, 0, +1} 로 압축 (분기·삼항·비교 연산자 없음)
    /// @note  s = 산술 시프트 부호, nz = (x!=0) 를 (x|(-x))의 MSB로 얻음.
    ///        Cortex-M4: ASR / ORR / LSR / ORR 가 각 1c 근처, 데이터 의존 경로만 고정.
    [[nodiscard]] inline int32_t Extract_State(int32_t x) noexcept
    {
        const int32_t s = x >> 31;
        const uint32_t ux = static_cast<uint32_t>(x);
        const uint32_t nz = (ux | (0u - ux)) >> 31u;
        return static_cast<int32_t>(
            s | static_cast<int32_t>(nz));
    }

    /// @brief cond_mask 가 ~0u 이면 a, 0u 이면 b 선택 (멀티플렉서)
    /// @note  단일 AND/OR 쌍 — M4에서 전형적으로 2×1c + 1c OR.
    [[nodiscard]] inline uint32_t Bitwise_Select(
        uint32_t cond_mask,
        uint32_t a,
        uint32_t b) noexcept
    {
        return static_cast<uint32_t>(
            (a & cond_mask) | (b & static_cast<uint32_t>(~cond_mask)));
    }

    /// @brief 국소 피크 또는 ADC 클리핑(Flat-Top) 시 출력 0, 아니면 curr
    /// @note  bomb_mask = peak_mask | clipping_mask. clipping 은 |curr|≥32767.
    /// @note  curr 는 부호 확장된 ADC 샘플로 가정(하위 16비트·int32 캐스팅).
    [[nodiscard]] inline uint32_t TPE_Core_Process(
        uint32_t prev,
        uint32_t curr,
        uint32_t next,
        uint32_t threshold) noexcept
    {
        const uint32_t m_prev = u32_gt_mask_u64(curr, prev);
        const uint32_t m_next = u32_gt_mask_u64(curr, next);
        const uint32_t m_thr = u32_gt_mask_u64(curr, threshold);
        const uint32_t peak_mask =
            static_cast<uint32_t>(m_prev & m_next & m_thr);
        const int32_t curr_s = static_cast<int32_t>(curr);
        const uint32_t clipping_mask = adc_clipping_mask_from_i32(curr_s);
        const uint32_t bomb_mask =
            static_cast<uint32_t>(peak_mask | clipping_mask);
        return Bitwise_Select(bomb_mask, UINT32_C(0), curr);
    }

    /// @brief 부호 있는 샘플: 피크(XOR biject) | ADC 클리핑 마스크
    [[nodiscard]] inline int32_t TPE_Core_Process_I32(
        int32_t prev,
        int32_t curr,
        int32_t next,
        int32_t threshold) noexcept
    {
        const uint32_t m_prev = i32_gt_mask(curr, prev);
        const uint32_t m_next = i32_gt_mask(curr, next);
        const uint32_t m_thr = i32_gt_mask(curr, threshold);
        const uint32_t peak_mask =
            static_cast<uint32_t>(m_prev & m_next & m_thr);
        const uint32_t clipping_mask = adc_clipping_mask_from_i32(curr);
        const uint32_t bomb_mask =
            static_cast<uint32_t>(peak_mask | clipping_mask);
        const uint32_t ucurr = static_cast<uint32_t>(curr);
        const uint32_t out_u = Bitwise_Select(bomb_mask, UINT32_C(0), ucurr);
        return static_cast<int32_t>(out_u);
    }

} // namespace TPE_Bitwise
} // namespace ProtectedEngine
