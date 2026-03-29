// =========================================================================
// HTS_Entropy_Monitor.h
// TRNG 건강성 감시 — NIST SP 800-90B RCT + APT
// Target: STM32F407 (Cortex-M4)
//
// [NIST SP 800-90B 필수 건강 테스트 2종]
//
//  1. RCT (Repetition Count Test) — §4.4.1
//     동일 바이트 연속 출력 감지 → Stuck-at Fault
//     Cutoff = 16 (H=8 기준, 오탐 2^(-128))
//
//  2. APT (Adaptive Proportion Test) — §4.4.2 [🆕]
//     윈도우(W=512) 내 특정 값의 과잉 출현 감지 → Bias Fault
//     Cutoff = 41 (H=4 기준, 오탐 2^(-30) 이하)
//     W=512, 기대 빈도=512/256=2 → 41회 초과 시 TRNG 편향 확정
//
// [양산 수정 — 8건]
//  BUG-01~06 (이전 세션)
//  BUG-07 [CRIT] NIST RCT Off-By-One: count 0 기반 → 1 기반
//  BUG-08 [HIGH] PC WDT 부재: while(true) → std::abort()
//  BUG-09 [CRIT] APT 추가 (NIST SP 800-90B 필수 2/2)
// =========================================================================
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    class EntropyMonitor {
    private:
        // ── RCT 상수 ─────────────────────────────────────────────
        static constexpr size_t NIST_RCT_CUTOFF = 16u;

        // ── APT 상수 (NIST SP 800-90B §4.4.2) ───────────────────
        //  W = 512: 윈도우 크기 (바이트 TRNG 출력 기준)
        //  C = 41:  임계치 (H≥4 가정, α=2^-30)
        //    기대값 = W × 2^(-H) = 512 × 2^(-4) = 32
        //    Cutoff = 32 + margin = 41 (NIST 표 기준)
        static constexpr size_t APT_WINDOW_SIZE = 512u;
        static constexpr size_t APT_CUTOFF = 41u;

        // ── RCT 상태 ─────────────────────────────────────────────
        uint8_t last_byte = 0u;
        size_t  repeat_count = 1u;
        bool    is_initialized = false;

        // ── APT 상태 ─────────────────────────────────────────────
        uint8_t apt_sample = 0u;   ///< 윈도우 첫 번째 샘플 값
        size_t  apt_count = 0u;   ///< 해당 값 출현 횟수
        size_t  apt_window_pos = 0u;   ///< 현재 윈도우 내 위치

    public:
        EntropyMonitor() noexcept;

        /// @brief TRNG 출력 1바이트 건강성 검사 (RCT + APT)
        ///  임계치 초과 시 Self-Healing (반환 안 함)
        void healthCheck(uint8_t generatedByte) noexcept;
    };

} // namespace ProtectedEngine