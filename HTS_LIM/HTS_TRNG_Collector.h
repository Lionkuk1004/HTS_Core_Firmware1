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
// =========================================================================
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    class TRNG_Collector {
    public:
        /// @brief TRNG Raw 데이터 수집 + UART 출력
        /// @param sample_count  수집할 바이트 수 (최소 1,000,000)
        /// @param uart_putchar  UART 1바이트 출력 콜백
        /// @return 실제 수집된 바이트 수
        static uint32_t Collect_And_Output(
            uint32_t sample_count,
            void (*uart_putchar)(uint8_t)) noexcept;

        /// @brief TRNG Raw 데이터 수집 → 버퍼 저장
        /// @param buffer       출력 버퍼
        /// @param buffer_size  버퍼 크기
        /// @return 실제 수집된 바이트 수
        static uint32_t Collect_To_Buffer(
            uint8_t* buffer, uint32_t buffer_size) noexcept;

        TRNG_Collector() = delete;
    };

} // namespace ProtectedEngine