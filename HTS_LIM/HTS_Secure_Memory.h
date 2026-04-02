// =========================================================================
// HTS_Secure_Memory.h
// 보안 메모리 잠금 + 안티포렌식 소거 (코어 인터페이스)
// Target: STM32F407 (Cortex-M4)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [설계 목적]
//  민감 데이터(키, PRNG 상태, 평문)의 물리 RAM 고정 + 안티포렌식 소거
//  프로젝트 전반의 모든 보안 모듈이 이 API에 의존
//
//  [플랫폼 동작]
//   ARM: lockMemory = no-op (SRAM = 항상 물리)
//        secureWipe = volatile 0x00 + asm barrier + release fence
//
//  [사용법]
//   SecureMemory::lockMemory(key_ptr, 32);    // 스왑 방지
//   // ... 키 사용 ...
//   SecureMemory::secureWipe(key_ptr, 32);    // 소거 + 잠금 해제
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    static_assert(sizeof(unsigned char) == 1, "byte must be 1 byte");

    // SecureVector typedef 미사용 — ARM에서 <vector> 힙 인프라 유입 방지

    /// @brief 보안 메모리 잠금 + 안티포렌식 소거 (정적 유틸리티)
    class SecureMemory {
    public:
        /// @brief 물리 RAM 고정 (스왑 방지)
        /// @param ptr   대상 메모리
        /// @param size  바이트 수
        /// @note  ARM: no-op (SRAM 항상 물리)
        static void lockMemory(void* ptr, size_t size) noexcept;

        /// @brief 안티포렌식 데이터 파쇄 + 잠금 해제
        /// @param ptr   대상 메모리
        /// @param size  바이트 수
        /// @note  volatile 0x00 + 컴파일러 전체 배리어 + release fence (D-2/X-5-1)
        /// @note  [M-1] 모듈 전역 로컬 소거 루프는 MSVC에서 배리어 누락 위험이 있으므로
        ///        Key_Rotator·Secure_Boot·Conditional_SelfTest 등은 본 API 위임으로 통일.
        static void secureWipe(void* ptr, size_t size) noexcept;

        SecureMemory() = delete;
        ~SecureMemory() = delete;
        SecureMemory(const SecureMemory&) = delete;
        SecureMemory& operator=(const SecureMemory&) = delete;
        SecureMemory(SecureMemory&&) = delete;
        SecureMemory& operator=(SecureMemory&&) = delete;
    };

} // namespace ProtectedEngine
