// =========================================================================
// HTS_Holo_Tensor_Engine.h
// 4D 홀로그래픽 텐서 변조/암호화 코어 — 공개 인터페이스
// Target: STM32F407 (Cortex-M4) — 순수 정수 연산
//
// [오버플로 안전 설계]
//  중간 최대 진폭 = 4 × N² × M_input
//  int32_t 한계:   2^31 - 1 = 2,147,483,647
//
//  N=64:   M_max = 131,071 (17비트) → 16비트 입력 안전
//  N=256:  M_max = 8,191   (13비트) → 자동 클램핑 적용
//  N=4096: M_max = 31      ( 5비트) → 자동 클램핑 적용
//
//  Encode: 입력을 M_max 범위로 클램핑 (정보 손실 최소화)
//  Decode: 정규화 후 클램핑 범위 내 복원
//
//  호출자는 chip_count에 따른 해상도 제약을 인지해야 합니다.
//  N이 클수록 분산 강도↑ / 입력 해상도↓ (트레이드오프)
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

    class Holo_Tensor_Engine {
    public:
        /// @brief 주어진 칩 수에서 안전한 최대 입력 절대값
        /// @return floor((2^31 - 1) / (4 * N²))
        [[nodiscard]]
        static int32_t Max_Safe_Amplitude(uint32_t chip_count) noexcept;

        /// @brief 송신부: 클램핑 → FWHT → 4D회전 → FWHT
        /// @param seed 128비트 시드 (4 × uint32_t, 블록별 독립)
        static void Encode_Hologram(
            int32_t* tensor,
            uint32_t chip_count,
            const uint32_t seed[4]) noexcept;

        /// @brief 수신부: 역FWHT → 역4D회전 → 역FWHT → 정규화
        static void Decode_Hologram(
            int32_t* tensor,
            uint32_t chip_count,
            const uint32_t seed[4]) noexcept;

        // 정적 전용 — 인스턴스화 차단 (6종)
        Holo_Tensor_Engine() = delete;
        ~Holo_Tensor_Engine() = delete;
        Holo_Tensor_Engine(const Holo_Tensor_Engine&) = delete;
        Holo_Tensor_Engine& operator=(const Holo_Tensor_Engine&) = delete;
        Holo_Tensor_Engine(Holo_Tensor_Engine&&) = delete;
        Holo_Tensor_Engine& operator=(Holo_Tensor_Engine&&) = delete;
    };

} // namespace ProtectedEngine