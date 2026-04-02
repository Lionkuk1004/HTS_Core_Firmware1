// =========================================================================
// HTS_ConstantTimeUtil.cpp
// 사이드채널 공격 방어용 상수시간 비교 구현부
// Target: STM32F407 (Cortex-M4)
//
#include "HTS_ConstantTimeUtil.h"

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace ProtectedEngine {

    // =====================================================================
    //  compare — 고정 길이 상수시간 비교 (Primary API)
    //
    //  [ARM Cortex-M4 어셈블리 예상]
    //  루프 1회당: LDRB×2 + EOR + ORR + asm = ~6사이클/바이트
    //  32바이트(HMAC): ~192사이클 ≈ 1.1µs @168MHz
    // =====================================================================
    bool ConstantTimeUtil::compare(
        const uint8_t* a,
        const uint8_t* b,
        size_t len) noexcept {

        if (!a || !b) {
            return (!a && !b && len == 0);
        }

        uint8_t result = 0;  // [BUG-12] volatile 제거 — asm "+r" 레지스터 격리

        for (size_t i = 0; i < len; ++i) {
            result = static_cast<uint8_t>(result | (a[i] ^ b[i]));

            // → 컴파일러가 result 값을 추론하여 조기 종료 삽입 차단
            // → 루프 벡터화/언롤링 패턴 변형 차단
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("" : "+r"(result) : : "memory");
#elif defined(_MSC_VER)
            _ReadWriteBarrier();
#endif
        }

        return (result == 0);
    }

    // =====================================================================
    //  compare_variable — 가변 길이 상수시간 비교
    //
    //  max(len_a, len_b) 바이트를 무조건 순회 → 길이 정보 미누출
    //  비트마스크 AND: 범위 밖 = 0x00 (분기 없음)
    // =====================================================================
    bool ConstantTimeUtil::compare_variable(
        const uint8_t* a, size_t len_a,
        const uint8_t* b, size_t len_b) noexcept {

        uint8_t length_mismatch =  // [BUG-12] volatile 제거
            static_cast<uint8_t>(len_a != len_b);

        size_t max_len = (len_a > len_b) ? len_a : len_b;

        const uint8_t dummy = 0;
        const uint8_t* ptr_a = (a && len_a > 0) ? a : &dummy;
        const uint8_t* ptr_b = (b && len_b > 0) ? b : &dummy;

        size_t safe_len_a = (len_a > 0) ? len_a : 1;
        size_t safe_len_b = (len_b > 0) ? len_b : 1;

        uint8_t result = 0;  // [BUG-12] volatile 제거 — asm "+r" 레지스터 격리

        for (size_t i = 0; i < max_len; ++i) {
            // (i < len_a)=1 → 0u-1u = 0xFF, =0 → 0u-0u = 0x00
            uint8_t mask_a = static_cast<uint8_t>(
                0u - static_cast<uint32_t>(i < len_a));
            uint8_t mask_b = static_cast<uint8_t>(
                0u - static_cast<uint32_t>(i < len_b));

            // cond=1이면 i, cond=0이면 (safe_len-1)
            uint32_t cond_a = static_cast<uint32_t>(i < len_a);
            uint32_t cond_b = static_cast<uint32_t>(i < len_b);
            size_t idx_a = (i * cond_a) + ((safe_len_a - 1) * (1u - cond_a));
            size_t idx_b = (i * cond_b) + ((safe_len_b - 1) * (1u - cond_b));

            uint8_t val_a = ptr_a[idx_a] & mask_a;
            uint8_t val_b = ptr_b[idx_b] & mask_b;

            result = static_cast<uint8_t>(result | (val_a ^ val_b));

#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("" : "+r"(result) : : "memory");
#elif defined(_MSC_VER)
            _ReadWriteBarrier();
#endif
        }

        return (static_cast<uint8_t>(result | length_mismatch) == 0);
    }

} // namespace ProtectedEngine
