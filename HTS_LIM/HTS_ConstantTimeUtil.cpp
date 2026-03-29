// =========================================================================
// HTS_ConstantTimeUtil.cpp
// 사이드채널 공격 방어용 상수시간 비교 구현부
// Target: STM32F407 (Cortex-M4)
//
// [양산 수정 — 9건]
//  BUG-01~06 (이전)
//  BUG-07 [CRIT] pragma O0 삭제 → 루프 내부 asm clobber
//  BUG-08 [CRIT] 삼항 연산자 분기 → 브랜치리스 산술 (타이밍 유출 차단)
//  BUG-09 [HIGH] signed 음수화 마스크 → unsigned 모듈로 마스크 (UB 제거)
//    이 모듈은 타이밍 사이드채널 방어가 목적이므로
//    매 이터레이션 asm clobber로 상수시간 보장:
//      ① "+r"(result): result 레지스터 격리 + DCE/조기 종료 차단
//      ② asm("memory"): 루프 내부 재배치/벡터화 차단
//      ③ SRAM Store 0회: Write Suppression 공격 표면 제거
//
// [상수시간 보장 원리]
//  모든 바이트를 무조건 순회 → 결과와 무관하게 동일 사이클
//  XOR + OR 누적 → 불일치가 하나라도 있으면 result ≠ 0
//  asm clobber → 컴파일러 분기 최적화/조기 종료 차단
//  [BUG-12] volatile 제거: asm "+r"가 이미 완전 방어
//           volatile은 불필요한 SRAM Store 강제 → Write Suppression 공격 표면
// =========================================================================
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

            // [BUG-07] 매 이터레이션 asm clobber
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
            // [BUG-09] unsigned 모듈로 마스크 (signed 음수화 UB 제거)
            // (i < len_a)=1 → 0u-1u = 0xFF, =0 → 0u-0u = 0x00
            uint8_t mask_a = static_cast<uint8_t>(
                0u - static_cast<uint32_t>(i < len_a));
            uint8_t mask_b = static_cast<uint8_t>(
                0u - static_cast<uint32_t>(i < len_b));

            // [BUG-08] 삼항 연산자 분기 제거 → 브랜치리스 산술
            // cond=1이면 i, cond=0이면 (safe_len-1)
            uint32_t cond_a = static_cast<uint32_t>(i < len_a);
            uint32_t cond_b = static_cast<uint32_t>(i < len_b);
            size_t idx_a = (i * cond_a) + ((safe_len_a - 1) * (1u - cond_a));
            size_t idx_b = (i * cond_b) + ((safe_len_b - 1) * (1u - cond_b));

            uint8_t val_a = ptr_a[idx_a] & mask_a;
            uint8_t val_b = ptr_b[idx_b] & mask_b;

            result = static_cast<uint8_t>(result | (val_a ^ val_b));

            // [BUG-07] 매 이터레이션 asm clobber (상수시간 보장)
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("" : "+r"(result) : : "memory");
#elif defined(_MSC_VER)
            _ReadWriteBarrier();
#endif
        }

        // [BUG-10] 단축 평가(&&) 분기 제거 → 비트 OR 병합 후 단일 비교
        return (static_cast<uint8_t>(result | length_mismatch) == 0);
    }

    // =====================================================================
    //  compare (vector) — 레거시 래퍼
    // =====================================================================
    bool ConstantTimeUtil::compare(
        const std::vector<uint8_t>& a,
        const std::vector<uint8_t>& b) noexcept {

        return compare_variable(
            a.empty() ? nullptr : a.data(), a.size(),
            b.empty() ? nullptr : b.data(), b.size());
    }

} // namespace ProtectedEngine