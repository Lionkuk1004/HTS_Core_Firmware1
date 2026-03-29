// =========================================================================
// HTS_Anti_Glitch.h
// 전압 글리칭 / 명령어 스킵 공격 방어 쉴드
// Target: STM32F407 (Cortex-M4)
//
// [양산 수정]
//  1. ProtectedEngine 네임스페이스로 이동 (프로젝트 일관성)
//  2. GlitchConsts → ProtectedEngine 내부 익명 네임스페이스로 이관 (.cpp)
// =========================================================================
#pragma once

#include <cstdint>
#include <atomic>

namespace ProtectedEngine {

    class AntiGlitchShield {
    private:
        std::atomic<uint32_t> systemState;

    public:
        AntiGlitchShield() noexcept;

        AntiGlitchShield(const AntiGlitchShield&) = delete;
        AntiGlitchShield& operator=(const AntiGlitchShield&) = delete;

        // 보안 검증 통과 후 시스템 잠금 해제
        void unlockSystem() noexcept;

        // 핵심 엔진 가동 전 다중 검증 (3중 읽기 + ALU 교차 검증)
        void verifyCriticalExecution() const noexcept;
    };

} // namespace ProtectedEngine