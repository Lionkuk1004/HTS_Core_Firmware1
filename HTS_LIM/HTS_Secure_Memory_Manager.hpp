// =========================================================================
// HTS_Secure_Memory_Manager.hpp
// SecureMemory 인라인 래퍼 (헤더 전용, 제로코스트 추상화)
// Target: STM32F407 (Cortex-M4)
//
// [제로코스트 추상화]
//  인라인 구현으로 BL 호출 + 스택 프레임 오버헤드 제거
//  컴파일러가 호출 지점에서 SecureMemory::lockMemory를 직접 치환
//  래퍼 함수는 바이너리에서 완전 소멸
//
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

#include "HTS_Secure_Memory.h"
#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    /// @brief SecureMemory 인라인 래퍼 (정적 유틸리티)
    class Secure_Memory_Manager {
    public:
        /// @brief 물리 RAM 고정 (ARM: no-op)
        static inline void Lock_Memory_Region(
            void* ptr, size_t size) noexcept {
            SecureMemory::lockMemory(ptr, size);
        }

        /// @brief 안티포렌식 소거 + 잠금 해제
        static inline void Unlock_And_Erase_Memory(
            void* ptr, size_t size) noexcept {
            SecureMemory::secureWipe(ptr, size);
        }

        // 정적 전용 — 인스턴스화 차단 (6종)
        Secure_Memory_Manager() = delete;
        ~Secure_Memory_Manager() = delete;
        Secure_Memory_Manager(const Secure_Memory_Manager&) = delete;
        Secure_Memory_Manager& operator=(const Secure_Memory_Manager&) = delete;
        Secure_Memory_Manager(Secure_Memory_Manager&&) = delete;
        Secure_Memory_Manager& operator=(Secure_Memory_Manager&&) = delete;
    };

} // namespace ProtectedEngine
