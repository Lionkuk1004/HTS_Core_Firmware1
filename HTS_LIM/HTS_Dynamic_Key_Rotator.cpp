// =========================================================================
// HTS_Dynamic_Key_Rotator.cpp
// 동적 키 로테이터 구현부 — LCG + Murmur3 비선형 키 파생
// Target: STM32F407 (Cortex-M4, 168MHz)
//
#include "HTS_Dynamic_Key_Rotator.hpp"
#include "HTS_Secure_Memory.h"
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace ProtectedEngine {

#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
    static inline uint32_t keyrot_critical_enter() noexcept {
        uint32_t primask;
        __asm volatile ("MRS %0, PRIMASK\n CPSID I"
            : "=r"(primask) :: "memory");
        return primask;
    }
    static inline void keyrot_critical_exit(uint32_t pm) noexcept {
        __asm volatile ("MSR PRIMASK, %0" :: "r"(pm) : "memory");
    }
#else
    static inline uint32_t keyrot_critical_enter() noexcept { return 0u; }
    static inline void keyrot_critical_exit(uint32_t) noexcept {}
#endif

    // =====================================================================
    //  Murmur3 64-bit Finalizer — 키 파생 비선형 혼합
    // =====================================================================
    static uint64_t Murmur3_Fmix64(uint64_t k) noexcept {
        k ^= k >> 33;
        k *= 0xFF51AFD7ED558CCDULL;
        k ^= k >> 33;
        k *= 0xC4CEB9FE1A85EC53ULL;
        k ^= k >> 33;
        return k;
    }

    // =====================================================================
    //  생성자
    // =====================================================================
    Dynamic_Key_Rotator::Dynamic_Key_Rotator(
        uint64_t initial_key, uint64_t interval) noexcept
        : rotation_interval((interval == 0) ? 1024ULL : interval)
        , operation_count(0) {

        internal_state = (initial_key == 0)
            ? 0x9E3779B97F4A7C15ULL : initial_key;

        // 첫 세션 키도 단방향 파생 (마스터 시드 미노출)
        current_key = Murmur3_Fmix64(internal_state) ^ internal_state;
    }

    // =====================================================================
    // =====================================================================
    Dynamic_Key_Rotator::~Dynamic_Key_Rotator() noexcept {
        const uint32_t pm = keyrot_critical_enter();
        SecureMemory::secureWipe(
            static_cast<void*>(&internal_state), sizeof(internal_state));
        SecureMemory::secureWipe(
            static_cast<void*>(&current_key), sizeof(current_key));
        SecureMemory::secureWipe(
            static_cast<void*>(&operation_count), sizeof(operation_count));
        SecureMemory::secureWipe(
            static_cast<void*>(&rotation_interval), sizeof(rotation_interval));
        keyrot_critical_exit(pm);
    }

    // =====================================================================
    //  Get_Current_Key_And_Rotate
    // =====================================================================

    uint64_t Dynamic_Key_Rotator::Get_Current_Key_And_Rotate() noexcept {
        const uint32_t pm = keyrot_critical_enter();
        //  기존: count++ 선행 → 첫 키 K0가 (interval-1)회만 사용 → TX/RX 키 엇갈림
        //  수정: 회전 검사 먼저, 카운트 증가 후행 → 모든 키 정확히 interval회 사용
        //
        //  흐름 (interval=1024):
        //   Call 1:    count=0 → 0<1024 → count++=1 → return K0
        //   Call 1024: count=1023 → 1023<1024 → count++=1024 → return K0
        //   Call 1025: count=1024 → 1024≥1024 → 회전→K1, count=0 → count++=1 → return K1
        //   → K0: 1024회, K1: 1024회 (대칭 ✓)
        if (operation_count >= rotation_interval) {
            // ── LCG 상태 전이 (은닉된 internal_state만 전진) ─────────
            uint64_t lcg_state = internal_state;
            lcg_state = (lcg_state * 0x5851F42D4C957F2DULL)
                + 0x14057B7EF767814FULL;
            lcg_state = (lcg_state << 21) | (lcg_state >> 43);

            internal_state = lcg_state;

            // ── [BUG-12] 단방향 키 파생 (Forward/Backward Secrecy) ───
            uint64_t new_key = Murmur3_Fmix64(lcg_state) ^ lcg_state;

            current_key = new_key;
            operation_count = 0;
        }

        operation_count++;
        const uint64_t out = current_key;
        keyrot_critical_exit(pm);
        return out;
    }


} // namespace ProtectedEngine
