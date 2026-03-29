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
//  [양산 수정 이력 — 10건]
//   기존 01~05: 3단 플랫폼 분기, ARM no-op, GCC pragma,
//               iostream 가드, mutex 가드
//   세션8 06~10: vector 제거(ARM 힙 방지), static_assert,
//                Doxygen, 인스턴스화 차단, SecureVector 폐기
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    // [BUG-05] 빌드 타임 검증
    static_assert(sizeof(unsigned char) == 1, "byte must be 1 byte");

    // [BUG-02] SecureVector typedef 제거
    // 기존: using SecureVector = std::vector<uint8_t>;
    // → <vector> include가 ARM에서 힙 할당 인프라 강제 링크
    // → Session_Gateway에서 고정 배열로 교체 완료 → typedef 불필요

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
        /// @note  volatile 0x00 + asm clobber + release fence → DCE 차단
        static void secureWipe(void* ptr, size_t size) noexcept;

        // [BUG-07] 정적 전용 — 인스턴스화 차단 (6종)
        SecureMemory() = delete;
        ~SecureMemory() = delete;
        SecureMemory(const SecureMemory&) = delete;
        SecureMemory& operator=(const SecureMemory&) = delete;
        SecureMemory(SecureMemory&&) = delete;
        SecureMemory& operator=(SecureMemory&&) = delete;
    };

} // namespace ProtectedEngine