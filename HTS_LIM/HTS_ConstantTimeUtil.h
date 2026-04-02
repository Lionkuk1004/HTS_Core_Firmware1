// =========================================================================
// HTS_ConstantTimeUtil.h
// 사이드채널 공격 방어용 상수시간 비교 유틸리티
// Target: STM32F407 (Cortex-M4)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [설계 목적]
//  타이밍 사이드채널 공격 방어용 상수시간(Constant-Time) 바이트 비교.
//  HMAC/AEAD 태그, 키, 서명 등 보안 민감 데이터의 동등성 검증에 사용.
//  결과와 무관하게 모든 바이트를 무조건 순회하여 실행 시간이
//  데이터에 의존하지 않습니다.
//
//  [사용법]
//   // 고정 길이 (Primary — HMAC 32B, AEAD 8B 등)
//   bool ok = ConstantTimeUtil::compare(computed, received, 32);
//
//   // 가변 길이 (길이 정보도 미누출)
//   bool ok = ConstantTimeUtil::compare_variable(a, a_len, b, b_len);
//
//  [상수시간 보장]
//   XOR + OR 비트 누적 + asm clobber("+r") → 조기 종료/벡터화 차단
//   레지스터 격리: result는 CPU 레지스터에만 존재 (SRAM Store 0회)
//
//  [성능 — STM32F407 @168MHz]
//   ~6사이클/바이트 (LDRB×2 + EOR + ORR + asm)
//   32바이트(HMAC): ~192사이클 ≈ 1.1us
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    class ConstantTimeUtil {
    public:
        // =================================================================
        //  [Primary] 고정 길이 상수시간 비교
        //
        //  HMAC/AEAD 태그, 키 검증 등 보안 컨텍스트 전용
        //  두 버퍼가 동일 길이임을 호출자가 보장
        //
        //  반환: true = 전 바이트 일치
        // =================================================================
        [[nodiscard]]
        static bool compare(
            const uint8_t* a,
            const uint8_t* b,
            size_t len) noexcept;

        // =================================================================
        //  [가변 길이] 길이가 다를 수 있는 두 버퍼 상수시간 비교
        //
        //  max(len_a, len_b) 바이트를 무조건 순회 → 길이 정보 미누출
        //  반환: true = 길이 동일 + 전 바이트 일치
        // =================================================================
        [[nodiscard]]
        static bool compare_variable(
            const uint8_t* a, size_t len_a,
            const uint8_t* b, size_t len_b) noexcept;

    };

} // namespace ProtectedEngine
