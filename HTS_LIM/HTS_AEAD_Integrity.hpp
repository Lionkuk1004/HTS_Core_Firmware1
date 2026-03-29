// =========================================================================
// HTS_AEAD_Integrity.hpp
// AEAD 태그 상수 시간 무결성 검증 (헤더 전용)
// Target: STM32F407 (Cortex-M4)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [설계 목적]
//  AEAD MAC 태그의 상수 시간(Constant-Time) 비교
//  타이밍 사이드 채널로 바이트 단위 태그 유추 원천 차단
//
//  [사용법]
//   uint32_t result = AEAD_Integrity_Vault::Constant_Time_Compare(expected, computed);
//   if (result != 0u) { /* 변조 탐지 — 세션 종료 */ }
//
//   ⚠ 금지 패턴: if (Constant_Time_Compare(...))
//     → bool 강제 변환으로 Boolean Coercion FI 취약점 재발
//     → 반드시 == 0u 또는 != 0u로 비교할 것
//
//  [양산 수정 이력 — 8건]
//   기존 01~03: noexcept, [[nodiscard]], 비트 축소 강화
//   세션8 04~08: volatile 제거(Write Suppression 차단),
//                static_assert, 인스턴스화 차단,
//                bool→uint32_t 반환(Boolean Coercion FI 차단)
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once
#include <cstdint>

namespace ProtectedEngine {

    // [BUG-04] 빌드 타임 검증
    static_assert(sizeof(uint64_t) == 8, "uint64_t must be 8 bytes");
    static_assert(sizeof(uint32_t) == 4, "uint32_t must be 4 bytes");

    class AEAD_Integrity_Vault {
    public:
        // =================================================================
        //  상수 시간 태그 비교 (Constant-Time Compare)
        //
        //  [설계 근거]
        //  일반적인 if (a == b) 비교는 첫 번째 불일치 바이트에서
        //  조기 반환(early-return)하여 실행 시간이 데이터에 의존함
        //  → 타이밍 사이드 채널로 해커가 바이트 단위로 태그를 유추 가능
        //
        //  XOR + 비트 축소 방식:
        //    diff = expected ^ computed  → 불일치 비트만 1
        //    diff를 32비트로 OR 축소   → 불일치가 하나라도 있으면 ≠ 0
        //    reduced를 그대로 반환      → 호출자가 == 0 비교
        //
        //  ARM Cortex-M4 (3 사이클 고정):
        //    EOR R0, R0, R2    // 하위 32비트 XOR
        //    EOR R1, R1, R3    // 상위 32비트 XOR
        //    ORRS R0, R0, R1   // 합산 → R0에 직접 반환
        //
        //  [BUG-01/02] volatile 제거 — 레지스터 격리
        //    SRAM Store 0회 → Write Suppression 공격 불가
        //
        //  [BUG-06] bool 반환 → uint32_t 반환 (Boolean Coercion 차단)
        //
        //    문제: bool 반환 시 컴파일러가 CMP + MOVEQ/MOVNE 생성
        //      → 글리치로 MOVNE(R0=0) 스킵 → R0에 쓰레기값 잔류
        //      → C++ "0이 아닌 값 = true" → 위조 패킷이 true로 통과!
        //
        //    수정: uint32_t 반환 — 0이면 일치, 0이 아니면 불일치
        //      → R0에 reduced 값이 그대로 반환 (CMP/MOV 없음!)
        //      → 글리치로 R0를 조작해도 0을 만들어야 함
        //        (32비트 전체를 0으로 만드는 글리치 = 사실상 불가능)
        //
        //    호출자 사용법:
        //      uint32_t result = Constant_Time_Compare(expected, computed);
        //      if (result != 0u) { /* 변조 탐지 — 세션 종료 */ }
        //
        //    ⚠ 주의: if (Constant_Time_Compare(...)) 패턴 금지!
        //      → bool 강제 변환으로 동일 취약점 재발
        //      → 반드시 == 0u 또는 != 0u로 비교할 것
        // =================================================================
        [[nodiscard]]
        static uint32_t Constant_Time_Compare(
            const uint64_t expected_tag,
            const uint64_t computed_tag) noexcept {

            // 레지스터 격리: diff/reduced는 CPU 레지스터에만 존재
            uint64_t diff = expected_tag ^ computed_tag;

            // 64비트 → 32비트 OR 축소
            // 결과: 0 = 일치, non-zero = 불일치
            uint32_t reduced =
                static_cast<uint32_t>(diff) |
                static_cast<uint32_t>(diff >> 32);

            // [BUG-06] reduced를 그대로 반환 — CMP/MOV 없음
            // ARM: MOV R0, reduced → BX LR (조건 분기 0개)
            return reduced;
        }

        // [BUG-05] 정적 전용 클래스 — 인스턴스화 차단 (6종)
        AEAD_Integrity_Vault() = delete;
        ~AEAD_Integrity_Vault() = delete;
        AEAD_Integrity_Vault(const AEAD_Integrity_Vault&) = delete;
        AEAD_Integrity_Vault& operator=(const AEAD_Integrity_Vault&) = delete;
        AEAD_Integrity_Vault(AEAD_Integrity_Vault&&) = delete;
        AEAD_Integrity_Vault& operator=(AEAD_Integrity_Vault&&) = delete;
    };

} // namespace ProtectedEngine