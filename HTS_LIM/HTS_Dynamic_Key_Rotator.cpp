// =========================================================================
// HTS_Dynamic_Key_Rotator.cpp
// 동적 키 로테이터 구현부 — LCG + Murmur3 비선형 키 파생
// Target: STM32F407 (Cortex-M4, 168MHz)
//
#include "HTS_Dynamic_Key_Rotator.hpp"
#include "HTS_Arm_Irq_Mask_Guard.h"
#include "HTS_Secure_Memory.h"
#include <cstddef>
#include <cstdint>
#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
#include <bit>
#endif

namespace ProtectedEngine {

    static inline uint64_t RotL64(uint64_t x, uint32_t k) noexcept {
        k &= 63u;
        if (k == 0u) { return x; }
#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
        return std::rotl(x, static_cast<int>(k));
#else
        return (x << k) | (x >> (64u - k));
#endif
    }

    static constexpr uint32_t k_LCG_ROT = 21u;

    // =====================================================================
    //  Murmur3 64-bit Finalizer — 키 파생 비선형 혼합
    // =====================================================================
    static uint64_t Murmur3_Fmix64(uint64_t k) noexcept {
        k ^= k >> 33ULL;
        k *= 0xFF51AFD7ED558CCDULL;
        k ^= k >> 33ULL;
        k *= 0xC4CEB9FE1A85EC53ULL;
        k ^= k >> 33ULL;
        return k;
    }

    // =====================================================================
    //  생성자
    // =====================================================================
    Dynamic_Key_Rotator::Dynamic_Key_Rotator(
        uint64_t initial_key, uint64_t interval) noexcept
        : rotation_interval((interval == 0ULL) ? 1024ULL : interval)
        , operation_count(0ULL) {

        internal_state = (initial_key == 0ULL)
            ? 0x9E3779B97F4A7C15ULL : initial_key;

        // 첫 세션 키도 단방향 파생 (마스터 시드 미노출)
        current_key = Murmur3_Fmix64(internal_state) ^ internal_state;
    }

    // =====================================================================
    // =====================================================================
    Dynamic_Key_Rotator::~Dynamic_Key_Rotator() noexcept {
        Armv7m_Irq_Mask_Guard irq;
        SecureMemory::secureWipe(
            static_cast<void*>(&internal_state), sizeof(internal_state));
        SecureMemory::secureWipe(
            static_cast<void*>(&current_key), sizeof(current_key));
        SecureMemory::secureWipe(
            static_cast<void*>(&operation_count), sizeof(operation_count));
        SecureMemory::secureWipe(
            static_cast<void*>(&rotation_interval), sizeof(rotation_interval));
    }

    // =====================================================================
    //  Get_Current_Key_And_Rotate
    // =====================================================================

    uint64_t Dynamic_Key_Rotator::Get_Current_Key_And_Rotate() noexcept {
        //  회전 임계 도달 시에만 LCG 전이 — 카운트는 회전 후 증가(키당 interval회 대칭)
        //
        //  흐름 (interval=1024):
        //   Call 1:    count=0 → 0<1024 → count++=1 → return K0
        //   Call 1024: count=1023 → 1023<1024 → count++=1024 → return K0
        //   Call 1025: count=1024 → 1024≥1024 → 회전→K1, count=0 → count++=1 → return K1
        //   → K0: 1024회, K1: 1024회 (대칭 ✓)
        //
        //  검사·LCG·Murmur·상태·카운트를 한 PRIMASK 구역에서 원자화 — 이중 검사/스핀 분할 금지.
        //  PRIMASK 밖 스핀 대기는 ISR이 메인의 커밋을 기다리며 교착(우선순위 역전) 가능.
        //  회전 시점만 IRQ 짧게 지연(interval 크면 드묾); ISR에서 본 API 호출 금지(헤더 참고).
        uint64_t out = 0ULL;
        {
            Armv7m_Irq_Mask_Guard irq;
            if (operation_count >= rotation_interval) {
                uint64_t lcg_state = internal_state;
                lcg_state = (lcg_state * 0x5851F42D4C957F2DULL) + 0x14057B7EF767814FULL;
                lcg_state = RotL64(lcg_state, k_LCG_ROT);
                const uint64_t new_key = Murmur3_Fmix64(lcg_state) ^ lcg_state;
                internal_state = lcg_state;
                current_key = new_key;
                operation_count = 0ULL;
            }
            operation_count++;
            out = current_key;
        }
        return out;
    }


} // namespace ProtectedEngine
