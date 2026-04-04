// =========================================================================
// HTS_Universal_API.cpp
// ProtectedEngine 내부 보안 게이트 / 세션 검증 / 물리적 파쇄
// Target: STM32F407VGT6 (Cortex-M4F, 168MHz)
//
#include "HTS_Universal_API.h"
#include "HTS_BitOps.h"
#include "HTS_Secure_Memory.h"

#include <atomic>
#include <cstdint>
#include <cstring>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace ProtectedEngine {

    namespace {

        static constexpr uint64_t HOLOGRAPHIC_INTERFACE_KEY = 0x3D504F574E533332ULL;

#if defined(__GNUC__) || defined(__clang__)
        typedef uint32_t __attribute__((__may_alias__)) uapi_u32_alias_t;
#else
        typedef uint32_t uapi_u32_alias_t;
#endif

        // LCG 대신 회전·XOR만 사용 (ALU 곱셈/덧셈 글리치 우회 시에도 상태 전파)
        static uint32_t uapi_scramble_advance(uint32_t s, size_t widx) noexcept {
            const uint32_t k_lo = static_cast<uint32_t>(HOLOGRAPHIC_INTERFACE_KEY);
            const uint32_t k_hi =
                static_cast<uint32_t>(HOLOGRAPHIC_INTERFACE_KEY >> 32);
            s ^= k_lo ^ k_hi ^ static_cast<uint32_t>(widx);
            s = (s >> 19) | (s << 13);
            s ^= k_hi;
            s = (s >> 7) | (s << 25);
            s ^= k_lo;
            return s;
        }

    } // namespace

    // =====================================================================
    //  Secure_Gate: uint64_t 동등성 — 분기 최소화, 반환은 풀비트 마스크
    // =====================================================================
    uint32_t Universal_API::Secure_Gate_Open(uint64_t session_id) noexcept {
        const uint64_t diff = session_id ^ HOLOGRAPHIC_INTERFACE_KEY;
        const uint32_t hi = static_cast<uint32_t>(diff >> 32);
        const uint32_t lo = static_cast<uint32_t>(diff & 0xFFFFFFFFu);
        const uint32_t combined = hi | lo;
        const uint32_t neg = ~combined + 1u;
        const uint32_t nz = (combined | neg) >> 31;
        const uint32_t open_lsb = nz ^ 1u;
        return 0u - open_lsb;
    }

    uint32_t Universal_API::Continuous_Session_Verification(
        uint64_t session_id) noexcept {
        return Secure_Gate_Open(session_id);
    }

    // =====================================================================
    //  Absolute_Trace_Erasure: 32비트 XOR(체크섬 유출) → 배리어 → secureWipe
    // =====================================================================
    void Universal_API::Absolute_Trace_Erasure(
        void* target, size_t size) noexcept {

        const uint32_t bad =
            static_cast<uint32_t>(target == nullptr)
            | static_cast<uint32_t>(size == 0u);
        if (bad != 0u) {
            return;
        }

        uint32_t scrambler = static_cast<uint32_t>(
            reinterpret_cast<uintptr_t>(target) & 0xFFFFFFFFu);
        scrambler ^= static_cast<uint32_t>(size);
        scrambler ^= static_cast<uint32_t>(HOLOGRAPHIC_INTERFACE_KEY);
        scrambler ^= static_cast<uint32_t>(HOLOGRAPHIC_INTERFACE_KEY >> 32);
        scrambler = (scrambler >> 11) | (scrambler << 21);

        auto* const w = reinterpret_cast<uapi_u32_alias_t*>(target);
        const size_t word_count = size >> 2;
        const size_t rem = size & 3u;

        uint32_t checksum = 0u;

        for (size_t i = 0; i < word_count; ++i) {
            scrambler = uapi_scramble_advance(scrambler, i);
            uint32_t v = w[i];
            v ^= scrambler;
            w[i] = v;
            checksum ^= v;
        }

        uint8_t* const tail =
            static_cast<uint8_t*>(target) + (word_count * 4u);
        uint32_t u = 0u;
        std::memcpy(&u, tail, rem);
        scrambler = uapi_scramble_advance(scrambler, word_count);
        const uint32_t tail_active =
            align_up_pow2_mask_u32(static_cast<uint32_t>(rem), 3u) >> 2;
        const uint32_t tail_mask = static_cast<uint32_t>(0u - tail_active);
        u ^= scrambler & tail_mask;
        checksum ^= u & tail_mask;
        std::memcpy(tail, &u, rem);

#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(checksum) : "memory");
#elif defined(_MSC_VER)
        volatile uint32_t uapi_xor_checksum_sink = checksum;
        (void)uapi_xor_checksum_sink;
        _ReadWriteBarrier();
#endif
        std::atomic_thread_fence(std::memory_order_release);

        SecureMemory::secureWipe(static_cast<void*>(target), size);
    }

} // namespace ProtectedEngine
