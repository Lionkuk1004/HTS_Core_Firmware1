// =========================================================================
/// @file  HTS_BitOps.h
/// @brief 프로젝트 공통 비트 연산 헬퍼 (popcount32)
/// @target STM32F407VGT6 (Cortex-M4F) / PC
///
// =========================================================================
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

#include <cstdint>

// C++20 <bit> — PC/x86 빌드에서만 사용 (ARM은 SWAR 고정)
#if !defined(__arm__) && !defined(__TARGET_ARCH_ARM) && \
    !defined(__TARGET_ARCH_THUMB) && !defined(__ARM_ARCH) && \
    !defined(__aarch64__) && \
    (__cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L))
#include <bit>
#endif

namespace ProtectedEngine {

    /// @brief 32비트 정수의 세트 비트(1) 개수 반환
    /// @param x 입력 값
    /// @return 0~32 범위의 세트 비트 수
    [[nodiscard]]
    constexpr uint32_t popcount32(uint32_t x) noexcept {
        // ARM·Thumb: SWAR 고정 (M4에 HW popcount 없음). PC/x86만 std::popcount.

#if !defined(__arm__) && !defined(__TARGET_ARCH_ARM) && \
    !defined(__TARGET_ARCH_THUMB) && !defined(__ARM_ARCH) && \
    !defined(__aarch64__) && \
    (__cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L))
        // PC/x86 빌드 전용: HW POPCNT 활용 (단일 사이클)
        return static_cast<uint32_t>(
            std::popcount(static_cast<unsigned int>(x)));
#else
        // ARM (Cortex-M4/A55) + C++17 이하 PC: SWAR 알고리즘
        x = x - ((x >> 1u) & 0x55555555u);
        x = (x & 0x33333333u) + ((x >> 2u) & 0x33333333u);
        return (((x + (x >> 4u)) & 0x0F0F0F0Fu) * 0x01010101u) >> 24u;
#endif
    }

} // namespace ProtectedEngine
