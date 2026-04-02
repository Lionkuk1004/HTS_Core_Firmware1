// =========================================================================
// HTS_PUF_Adapter.h
// PUF (Physical Unclonable Function) 하드웨어 시드 추출 어댑터
// Target: STM32F407 (Cortex-M4)
//
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

namespace ProtectedEngine {

    class PUF_Adapter {
    public:
        /// @brief PUF 시드 추출 — 고정 배열 API (ARM Zero-Heap)
        /// @param challenge     챌린지 배열 (nullptr 불가)
        /// @param challenge_len 챌린지 길이
        /// @param out_buf       출력 버퍼 (호출자 제공)
        /// @param buf_size      출력 버퍼 크기 (최소 32 권장)
        /// @param out_len       실제 출력 바이트 수
        /// @return true=성공, false=실패
        [[nodiscard]]
        static bool getHardwareSeed_Fixed(
            const uint8_t* challenge, size_t challenge_len,
            uint8_t* out_buf, size_t buf_size,
            size_t* out_len) noexcept;
    };

} // namespace ProtectedEngine
