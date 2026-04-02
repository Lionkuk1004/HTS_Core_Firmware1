// =========================================================================
// HTS_Universal_API.cpp
// ProtectedEngine 내부 보안 게이트 / 세션 검증 / 물리적 파쇄
// Target: STM32F407VGT6 (Cortex-M4F, 168MHz)
//
#include "HTS_Universal_API.h"
#include "HTS_Secure_Memory.h"

#include <atomic>
#include <cstdint>
#include <cstring>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace ProtectedEngine {

    // ── 마스터 키 (바이너리 내부 은닉) ──────────────────────────
    static constexpr uint64_t HOLOGRAPHIC_INTERFACE_KEY = 0x3D504F574E533332ULL;

    // =====================================================================
    //  Secure_Gate: uint64_t 동등성 — 분기 최소화(브랜치리스 zero 검출)
    // =====================================================================
    bool Universal_API::Secure_Gate_Open(uint64_t session_id) noexcept {
        const uint64_t diff = session_id ^ HOLOGRAPHIC_INTERFACE_KEY;
        // 64비트 XOR 결과를 32비트로 접기 (OR 누산)
        const uint32_t hi = static_cast<uint32_t>(diff >> 32);
        const uint32_t lo = static_cast<uint32_t>(diff & 0xFFFFFFFFu);
        const uint32_t combined = hi | lo;
        // combined=0 → (0|0)>>31 = 0 → 0^1 = 1 (true)
        // combined≠0 → (v|(-v))>>31 = 1 → 1^1 = 0 (false)
        const uint32_t neg = ~combined + 1u;  // 2의 보수 부정
        const uint32_t nz = (combined | neg) >> 31;  // nonzero flag
        return static_cast<bool>(nz ^ 1u);  // 반전: zero→true
    }

    bool Universal_API::Continuous_Session_Verification(
        uint64_t session_id) noexcept {
        return Secure_Gate_Open(session_id);
    }

    // =====================================================================
    //  Absolute_Trace_Erasure: XOR 스크램블 → 배리어 → SecureMemory::secureWipe
    // =====================================================================
    void Universal_API::Absolute_Trace_Erasure(
        void* target, size_t size) noexcept {
        if (target == nullptr || size == 0u) {
            return;
        }

        // 64비트 포인터: uintptr 하위 32비트만 shredder 시드에 사용
        uint32_t shredder = static_cast<uint32_t>(
            (reinterpret_cast<uintptr_t>(target) & 0xFFFFFFFFu)
            ^ static_cast<uint32_t>(size) ^ 0xDEADBEEFu);

        // ── 1단계: 엔트로피 셔레더 XOR (Unaligned 안전 처리) ────
        uint8_t* b_ptr = static_cast<uint8_t*>(target);
        size_t bytes_left = size;

        // 프롤로그: 4바이트 정렬 맞추기
        while (bytes_left > 0u &&
            (reinterpret_cast<uintptr_t>(b_ptr) & 3u) != 0u) {
            shredder = shredder * 1103515245u + 12345u;
            *b_ptr ^= static_cast<uint8_t>(shredder >> 16);
            ++b_ptr;
            --bytes_left;
        }

        // 메인 바디: 정렬된 32비트 워드 고속 타격
        // Strict Aliasing 준수: memcpy 4B → 컴파일러가 LDR/STR 인라인 치환
        if (bytes_left >= 4u) {
            // 워드 개수: bytes_left >> 2 (항목⑨ 시프트)
            const size_t words = bytes_left >> 2u;
            for (size_t i = 0; i < words; ++i) {
                shredder = shredder * 1103515245u + 12345u;
                uint32_t temp;
                std::memcpy(&temp, b_ptr, sizeof(uint32_t));
                temp ^= shredder; // 32비트 전 영역 스크램블링 보장
                std::memcpy(b_ptr, &temp, sizeof(uint32_t));
                b_ptr += 4u;
            }
            bytes_left &= 3u; // 잔여 바이트만 남김 (Dead Store 제거)
        }

        // 에필로그: 잔여 바이트 처리 (최대 3)
        while (bytes_left-- > 0u) {
            shredder = shredder * 1103515245u + 12345u;
            *b_ptr ^= static_cast<uint8_t>(shredder >> 16);
            ++b_ptr;
        }

        // ── 1단계/2단계 경계: DSE(Dead Store Elimination) 방어
        //  LTO/-O2에서 XOR 쓰기 전체가 "곧바로 secureWipe로 덮임"으로 dead store 판정되는 것을 차단.
        //  (기능: XOR 스크램블은 그대로 수행된 뒤에만 최종 소거가 이어짐 — 동작 의미 동일, 최적화만 억제)
#if (defined(__GNUC__) || defined(__clang__))
        __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
        _ReadWriteBarrier();
#endif
        std::atomic_thread_fence(std::memory_order_release);

        // ── 2단계: 0 오버라이트 — 프로젝트 표준 SecureMemory (바이트 순회, 비정렬 안전, D-2)
        SecureMemory::secureWipe(static_cast<void*>(target), size);
    }

} // namespace ProtectedEngine
