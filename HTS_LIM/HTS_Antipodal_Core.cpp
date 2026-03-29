// =========================================================================
// HTS_Antipodal_Core.cpp — 안티포달 텐서 변환 유틸리티
// Target: STM32F407 (Cortex-M4, 168MHz) / PC
//
// [양산 수정 이력 — 18건]
//  BUG-01~11 (이전 세션 완료)
//  BUG-12 [CRIT] 32비트 워드 단위 Dual-MAC 내적 (버스 효율 400%)
//  BUG-13 [HIGH] 함수 속성(pure, leaf) 추가 — 컴파일러 최적화 가이드
//  BUG-14 [MED]  루프 잔여분(Tail) 처리 최적화
//  BUG-15 [CRIT] Parallel Subtraction 수학 오류 발견 → 바이트 루프 유지
//                (32비트 감산은 바이트 간 borrow 전파 → 혼합 입력 시 오염)
//  BUG-16 [HIGH] Dual-MAC 구조 — SMLAD DSP 명령어 최적화 가이드
//  BUG-17 [CRIT] Strict Aliasing 위반(reinterpret_cast int8→int32) UB 제거
//                → memcpy 4B 로드 (컴파일러 LDR 단일 명령어 치환)
//  BUG-18 [LOW]  MSVC C6297 경고 해소: w << 2u → size_t 승격 후 곱셈
//                · uint32_t << 2 결과가 64비트 포인터 산술 전에 오버플로우 가능
//                · static_cast<size_t>(w) * sizeof(int32_t) 로 안전 확장
// =========================================================================
#include "HTS_Antipodal_Core.h"
#include <cstddef>
#include <cstdint>
#include <cstring>  // [BUG-17] memcpy (Strict Aliasing 준수 워드 로드)

// [BUG-11+13] GCC/Clang: 함수 레벨 속성 매크로
#if defined(__GNUC__) || defined(__clang__)
#define HTS_UNROLL __attribute__((optimize("unroll-loops")))
#define HTS_PURE   __attribute__((pure, leaf))
#define HTS_ALIGNED(p) __builtin_assume_aligned(p, 4)
#else
#define HTS_UNROLL
#define HTS_PURE
#define HTS_ALIGNED(p) p
#endif

namespace ProtectedEngine {

    // =====================================================================
    //  convertToAntipodal — 바이너리(0/1) → 안티포달(±1)
    //
    //  [BUG-15] Parallel Subtraction 불가 증명:
    //   (word << 1) - 0x01010101 → 바이트 간 borrow 전파
    //   입력 [0,1,1,0]: byte[1] = 0x02-0x01-borrow(1) = 0x00 ≠ +1
    //   → 바이트 루프가 유일한 정확 해법
    //
    //  [BUG-10] (LSL #1) → (SUB #1) 브랜치리스 산술
    // =====================================================================
    HTS_UNROLL
        void AntipodalTensor::convertToAntipodal(
            const uint8_t* __restrict in,
            int8_t* __restrict out, size_t len) noexcept {
        if (!in || !out || len == 0u) return;

#if defined(__GNUC__) || defined(__clang__)
        const uint8_t* __restrict p_in = static_cast<const uint8_t*>(
            HTS_ALIGNED(in));
        int8_t* __restrict p_out = static_cast<int8_t*>(
            HTS_ALIGNED(out));
#else
        const uint8_t* __restrict p_in = in;
        int8_t* __restrict p_out = out;
#endif

        const uint32_t u_len = static_cast<uint32_t>(len);

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC ivdep
#endif
        for (uint32_t i = 0u; i < u_len; ++i) {
            // 순수 산술: (0&1)*2-1 = -1, (1&1)*2-1 = +1
            // Cortex-M4: AND + LSL + SUB = 3사이클
            p_out[i] = static_cast<int8_t>(
                (static_cast<int32_t>(p_in[i] & 1u) << 1u) - 1);
        }
    }

    // =====================================================================
    //  calculateOrthogonality — 안티포달 텐서 내적
    //
    //  [BUG-12+16] 32비트 워드 단위 Dual-MAC:
    //   4바이트를 한 워드로 로드 → 8비트 개별 곱셈+누적
    //   → 개별 곱셈이므로 바이트 간 간섭 없음 (수학적 정확)
    //   → Cortex-M4 SMLAD 활용 유도
    // =====================================================================
    HTS_UNROLL HTS_PURE
        int32_t AntipodalTensor::calculateOrthogonality(
            const int8_t* __restrict a,
            const int8_t* __restrict b, size_t len) noexcept {
        if (!a || !b || len == 0u) return 0;

        int32_t dot = 0;
        uint32_t i = 0u;
        const uint32_t u_len = static_cast<uint32_t>(len);

        // [BUG-12+17] 정렬 시 워드 단위 고속 경로
        // [BUG-17] reinterpret_cast<int32_t*>(int8_t*) = Strict Aliasing UB
        //  → memcpy 4B 로드: 컴파일러가 LDR 단일 명령어로 치환 (성능 동일)
        if ((reinterpret_cast<uintptr_t>(a) & 3u) == 0u &&
            (reinterpret_cast<uintptr_t>(b) & 3u) == 0u) {

            const uint32_t word_count = u_len >> 2u;

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC ivdep
#endif
            for (uint32_t w = 0u; w < word_count; ++w) {
                // [BUG-17] memcpy 4B → int32_t (Strict Aliasing 준수)
                // GCC -O2: memcpy 4B → LDR Rn, [Rm, #off] 단일 명령어
                // [BUG-18] w << 2u → size_t 승격 (MSVC C6297 오버플로우 경고 해소)
                //  uint32_t << 2 결과가 64비트 size_t 확장 전에 오버플로우 가능
                //  static_cast<size_t>(w) * sizeof(int32_t) 로 안전 확장
                const size_t byte_off = static_cast<size_t>(w) * sizeof(int32_t);
                int32_t va, vb;
                std::memcpy(&va, a + byte_off, sizeof(int32_t));
                std::memcpy(&vb, b + byte_off, sizeof(int32_t));

                // [BUG-16] 8비트 페어링 → SMLAD 유도
                // 개별 곱셈이므로 바이트 간 간섭 없음 (수학적 정확)
                int32_t sum_low =
                    static_cast<int8_t>(va) * static_cast<int8_t>(vb) +
                    static_cast<int8_t>(va >> 8) * static_cast<int8_t>(vb >> 8);

                int32_t sum_high =
                    static_cast<int8_t>(va >> 16) * static_cast<int8_t>(vb >> 16) +
                    static_cast<int8_t>(va >> 24) * static_cast<int8_t>(vb >> 24);

                dot += (sum_low + sum_high);
            }
            i = word_count << 2u;
        }

        // [BUG-14] 잔여분 처리
        for (; i < u_len; ++i) {
            dot += static_cast<int32_t>(a[i]) * static_cast<int32_t>(b[i]);
        }
        return dot;
    }

} // namespace ProtectedEngine