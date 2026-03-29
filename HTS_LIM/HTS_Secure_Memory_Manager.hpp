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
// [양산 수정 — 5건]
//  Doxygen, 인스턴스화 차단 6종, Lock void 반환, 인라인 헤더전용, cpp 제거
// =========================================================================
#pragma once

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