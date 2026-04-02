// =========================================================================
// HTS_Quantum_Decoy_VDF.cpp
// 양자 디코이 VDF — 순차 시간 잠금 퍼즐 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
//
#include "HTS_Quantum_Decoy_VDF.h"
#include "HTS_Hardware_Init.h"

#include <atomic>
#include <cstdint>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace {

    // Murmur3 64-bit finalizer — GF(2) 선형 단독 Xorshift와 달리 곱·혼합으로 숏컷 난이도 상승
    // (Dynamic_Key_Rotator.cpp 와 동일 상수 — J-3)
    constexpr uint64_t kMurmur64_C1 = 0xFF51AFD7ED558CCDULL;
    constexpr uint64_t kMurmur64_C2 = 0xC4CEB9FE1A85EC53ULL;
    constexpr uint64_t kVdfArxOddMul = 0xD6E8FEB8666FDFFFULL; ///< 홀수 모듈러 곱 (ARX)

    inline uint64_t RotL64(uint64_t x, uint32_t k) noexcept {
        k &= 63u;
        if (k == 0u) { return x; }
        return (x << k) | (x >> (64u - k));
    }

    inline uint64_t Murmur3_Fmix64(uint64_t k) noexcept {
        k ^= k >> 33u;
        k *= kMurmur64_C1;
        k ^= k >> 33u;
        k *= kMurmur64_C2;
        k ^= k >> 33u;
        return k;
    }

    /// ARX 한 스텝: fmix(비선형) + 회전/XOR + 모듈러 곱(홀수) + 덧셈
    inline uint64_t Vdf_Arx_Step(uint64_t x, uint32_t round_idx) noexcept {
        x = Murmur3_Fmix64(x);
        x ^= RotL64(x, 13u);
        x += static_cast<uint64_t>(round_idx) * 0x9E3779B97F4A7C15ULL;
        x *= kVdfArxOddMul;
        x ^= RotL64(x, 31u);
        return x;
    }

} // namespace

namespace ProtectedEngine {

    // =====================================================================
    //  Execute_Time_Lock_Puzzle — 순차 VDF 코어
    //
    //  · 상태는 uint64_t 레지스터 체인( volatile 미사용 → SRAM 스래싱 완화 ).
    //  · DCE 방지: GNU/Clang 은 "+r"만 사용( "memory" 클로버 금지 — 매 반복 전역 spill/fill 유발 ).
    //    MSVC 는 _ReadWriteBarrier (인라인 asm 미지원 경로).
    //  · 장시간 루프: 4096 주기 WDT 킥 (나눗셈 없이 비트 마스크).
    // =====================================================================
    uint64_t Quantum_Decoy_VDF::Execute_Time_Lock_Puzzle(
        uint64_t session_id,
        uint32_t iterations) noexcept {

        uint64_t x = session_id
            ^ (static_cast<uint64_t>(QUANTUM_NOISE_SEED) << 32u);

        for (uint32_t j = 0u; j < iterations; ++j) {
            if ((j & 0xFFFu) == 0u) {
                Hardware_Init_Manager::Kick_Watchdog();
            }

            x = Vdf_Arx_Step(x, j);

#if defined(__GNUC__) || defined(__clang__)
#if defined(__arm__) && !defined(__aarch64__)
            {
                uint32_t x_lo = static_cast<uint32_t>(x);
                uint32_t x_hi = static_cast<uint32_t>(x >> 32u);
                __asm__ __volatile__("" : "+r"(x_lo), "+r"(x_hi));
                x = (static_cast<uint64_t>(x_hi) << 32u) | static_cast<uint64_t>(x_lo);
            }
#else
            __asm__ __volatile__("" : "+r"(x));
#endif
#elif defined(_MSC_VER)
            _ReadWriteBarrier();
#endif
        }

        std::atomic_thread_fence(std::memory_order_release);
        return x;
    }

} // namespace ProtectedEngine
