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

    namespace {
        // 값 혹은 포인터가 0이면 1, 아니면 0 (branchless)
        static constexpr size_t is_zero_sz(size_t v) noexcept {
            return static_cast<size_t>(
                (v | (~v + static_cast<size_t>(1u))) >> ((sizeof(size_t) * 8u) - 1u)
            ) ^ static_cast<size_t>(1u);
        }

        static inline size_t is_null_ptr(const void* p) noexcept {
            const uintptr_t v = reinterpret_cast<uintptr_t>(p);
            return static_cast<size_t>(
                (v | (~v + static_cast<uintptr_t>(1u))) >> ((sizeof(uintptr_t) * 8u) - 1u)
            ) ^ static_cast<size_t>(1u);
        }

        // branchless max(a, b)
        static constexpr size_t ct_max(size_t a, size_t b) noexcept {
            const size_t diff = a - b;
            const size_t mask_bit = diff >> ((sizeof(size_t) * 8u) - 1u); // a < b 이면 1
            const size_t mask = (~mask_bit + static_cast<size_t>(1u));     // 1 -> all ones, 0 -> 0
            return a - (diff & mask);
        }
    } // namespace

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
        const size_t a_null = is_null_ptr(a);
        const size_t b_null = is_null_ptr(b);
        const size_t any_null = a_null | b_null;

        static const uint8_t dummy = 0u;
        const uintptr_t p_dummy = reinterpret_cast<uintptr_t>(&dummy);
        const uintptr_t p_a = reinterpret_cast<uintptr_t>(a);
        const uintptr_t p_b = reinterpret_cast<uintptr_t>(b);

        // 포인터가 null이면 dummy 주소로 안전 매핑
        const uint8_t* safe_a = reinterpret_cast<const uint8_t*>(
            p_a | (p_dummy * static_cast<uintptr_t>(a_null)));
        const uint8_t* safe_b = reinterpret_cast<const uint8_t*>(
            p_b | (p_dummy * static_cast<uintptr_t>(b_null)));

        uint8_t result = 0;  // volatile 제거 — asm "+r" 레지스터 격리

        for (size_t i = 0; i < len; ++i) {
            // null 포인터 경로에서는 idx를 0으로 강제해 OOB 방어
            const size_t idx_a = i * (a_null ^ static_cast<size_t>(1u));
            const size_t idx_b = i * (b_null ^ static_cast<size_t>(1u));
            result = static_cast<uint8_t>(result | (safe_a[idx_a] ^ safe_b[idx_b]));

            // → 컴파일러가 result 값을 추론하여 조기 종료 삽입 차단
            // → 루프 벡터화/언롤링 패턴 변형 차단
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("" : "+r"(result) : : "memory");
#elif defined(_MSC_VER)
            _ReadWriteBarrier();
#endif
        }
        const size_t len_is_zero = is_zero_sz(len);
        const size_t null_fail = any_null & (len_is_zero ^ static_cast<size_t>(1u));
        return (result == 0u) && (null_fail == 0u);
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
        const size_t len_diff = len_a - len_b;
        const size_t len_mismatch = is_zero_sz(len_diff) ^ static_cast<size_t>(1u);
        const size_t max_len = ct_max(len_a, len_b);

        const size_t a_null = is_null_ptr(a);
        const size_t b_null = is_null_ptr(b);
        const size_t a_empty = a_null | is_zero_sz(len_a);
        const size_t b_empty = b_null | is_zero_sz(len_b);

        static const uint8_t dummy = 0u;
        const uintptr_t p_dummy = reinterpret_cast<uintptr_t>(&dummy);
        const uintptr_t p_a = reinterpret_cast<uintptr_t>(a);
        const uintptr_t p_b = reinterpret_cast<uintptr_t>(b);

        const uint8_t* safe_a = reinterpret_cast<const uint8_t*>(
            p_a | (p_dummy * static_cast<uintptr_t>(a_empty)));
        const uint8_t* safe_b = reinterpret_cast<const uint8_t*>(
            p_b | (p_dummy * static_cast<uintptr_t>(b_empty)));

        const size_t safe_len_a = len_a + a_empty;
        const size_t safe_len_b = len_b + b_empty;

        uint8_t result = 0;  // volatile 제거 — asm "+r" 레지스터 격리

        for (size_t i = 0; i < max_len; ++i) {
            // i < len 조건을 언더플로우 MSB로 획득
            const size_t diff_a = i - len_a;
            const size_t cond_a = diff_a >> ((sizeof(size_t) * 8u) - 1u);
            const uint8_t mask_a = static_cast<uint8_t>(
                0u - static_cast<uint32_t>(cond_a));

            const size_t diff_b = i - len_b;
            const size_t cond_b = diff_b >> ((sizeof(size_t) * 8u) - 1u);
            const uint8_t mask_b = static_cast<uint8_t>(
                0u - static_cast<uint32_t>(cond_b));

            const size_t idx_a =
                (i * cond_a) + ((safe_len_a - 1u) * (cond_a ^ static_cast<size_t>(1u)));
            const size_t idx_b =
                (i * cond_b) + ((safe_len_b - 1u) * (cond_b ^ static_cast<size_t>(1u)));

            const uint8_t val_a = safe_a[idx_a] & mask_a;
            const uint8_t val_b = safe_b[idx_b] & mask_b;

            result = static_cast<uint8_t>(result | (val_a ^ val_b));

#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("" : "+r"(result) : : "memory");
#elif defined(_MSC_VER)
            _ReadWriteBarrier();
#endif
        }
        return (result == 0u) && (len_mismatch == 0u);
    }

} // namespace ProtectedEngine
