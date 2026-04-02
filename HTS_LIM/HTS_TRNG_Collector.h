// =========================================================================
// HTS_TRNG_Collector.h
// TRNG Raw 데이터 수집기 — NIST SP 800-90B 통계 테스트용
// Target: STM32F407 (Cortex-M4)
//
// [목적]
//  FIPS 140-3 / KCMVP 인증 시 TRNG의 엔트로피 품질 증명 필요.
//  NIST SP 800-90B Statistical Test Suite 실행을 위해
//  최소 100만 바이트의 Raw TRNG 데이터를 수집하여 UART로 출력.
//
// [사용법]
//  1. STM32 보드에서 HTS_TRNG_Collector::Collect_And_Output() 호출
//  2. UART로 Raw 바이트 스트림 출력 (바이너리 또는 hex)
//  3. PC에서 직렬 포트 캡처 → .bin 파일 저장
//  4. NIST ea_non_iid / ea_iid 도구 실행
//
// [NIST SP 800-90B 요구]
//  - 최소 1,000,000 샘플 (8비트/샘플)
//  - 연속 수집 (중간 리셋 없음)
//  - Raw 출력 (조건화 전 데이터)
//
// [제약] ARM 전용 (STM32 TRNG 레지스터 직접 접근)
//
// [RNG 오류 복구]
//  CECS/SECS 감지 시 RM0090 절차로 SR 클리어·재가동(구현부 RNG_Clear_Error_Flags)
// =========================================================================
#pragma once
// ─────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────
//  [사용법] 기본 사용 예시를 여기에 기재하세요.
//  [메모리] sizeof(클래스명) 확인 후 전역/정적 배치 필수.
//  [보안]   복사/이동 연산자 = delete (키 소재 복제 차단).
//
//  ⚠ [파트너사 필수 확인]
//    HW 레지스터 주소(UART/WDT 등)는 보드 설계에 맞게 교체.
//    IRQ 번호는 STM32F407 RM0090 벡터 테이블 기준으로 교체.
// ─────────────────────────────────────────────────────────

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    class TRNG_Collector {
    public:
        /// @brief TRNG Raw 데이터 수집 + UART 출력
        /// @param sample_count  수집할 바이트 수 (최소 1,000,000)
        /// @param uart_putchar  UART 1바이트 출력 콜백
        /// @return 실제 수집된 바이트 수
        /// @note H-1: `uart_putchar==nullptr` 이면 0. 재진입 시 0 (ISR/RTOS 데드락 방지)
        static uint32_t Collect_And_Output(
            uint32_t sample_count,
            void (*uart_putchar)(uint8_t)) noexcept;

        /// @brief TRNG Raw 데이터 수집 → 버퍼 저장
        /// @param buffer       출력 버퍼
        /// @param buffer_size  버퍼 크기
        /// @return 실제 수집된 바이트 수
        /// @note H-1: `buffer==nullptr` 또는 `buffer_size==0` 이면 0. 재진입 시 0
        static uint32_t Collect_To_Buffer(
            uint8_t* buffer, uint32_t buffer_size) noexcept;

        TRNG_Collector() = delete;
    };

} // namespace ProtectedEngine