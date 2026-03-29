// =========================================================================
// HTS_Anti_Debug.h
// 디버거/JTAG 연결 탐지 및 강제 시스템 정지
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [설계 목적]
//  디버거/JTAG/SWD 연결 탐지 시 즉각 시스템 정지
//  키/평문/PRNG 상태가 메모리에서 덤프되기 전에 자가 치유(소거) 실행
//
//  [탐지 방식]
//   ARM: CoreDebug→DHCSR.C_DEBUGEN 직접 읽기 (HW 레벨, 우회 불가)
//
//  [사용법]
//   AntiDebugManager::checkDebuggerPresence();
//   → 탐지 시 forceHalt() 호출 — 반환하지 않음 ([[noreturn]])
//   → 모든 함수 static — 인스턴스 생성 불필요/불가
//
//  [양산 수정 이력 — 25건]
//   기존~세션8 BUG-01~21: (cpp 참조)
//   세션10+ BUG-22~24: PC코드 물리삭제, SecWipe, constexpr
//   BUG-25 [LOW] 주석 정합: PC/Server/Windows/Linux 탐지 설명 제거 (ARM 전용)
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>

namespace ProtectedEngine {

    // ── [BUG-17] ARM Cortex-M4 MMIO 주소 상수 (매직 넘버 근절) ──
    // ARM DDI 0403E (ARMv7-M Architecture Reference Manual) 기준
    static constexpr uint32_t ADDR_DHCSR = 0xE000EDF0u;  ///< Debug Halting Control/Status
    static constexpr uint32_t ADDR_AIRCR = 0xE000ED0Cu;  ///< App Interrupt/Reset Control
    static constexpr uint32_t ADDR_DBGMCU_FZ = 0xE0042008u;  ///< DBGMCU APB1 Freeze (STM32F4)

    // ── [BUG-16] DHCSR 비트 필드 상수 ──
    static constexpr uint32_t DHCSR_C_DEBUGEN = 0x00000001u;  ///< bit 0:  디버거 활성화
    static constexpr uint32_t DHCSR_C_HALT = 0x00000002u;  ///< bit 1:  코어 정지
    static constexpr uint32_t DHCSR_S_HALT = 0x00020000u;  ///< bit 17: 정지 상태
    static constexpr uint32_t DHCSR_S_SLEEP = 0x00040000u;  ///< bit 18: 슬립 상태
    static constexpr uint32_t DHCSR_DEBUG_MASK =
        DHCSR_C_DEBUGEN | DHCSR_C_HALT | DHCSR_S_HALT | DHCSR_S_SLEEP;

    // ── AIRCR 상수 ──
    static constexpr uint32_t AIRCR_VECTKEY = 0x05FA0000u;
    static constexpr uint32_t AIRCR_SYSRESETREQ = 0x00000004u;
    static constexpr uint32_t AIRCR_RESET_CMD = AIRCR_VECTKEY | AIRCR_SYSRESETREQ;

    // ── DBGMCU WDT 프리즈 비트 ──
    static constexpr uint32_t DBGMCU_IWDG_STOP = (1u << 11);
    static constexpr uint32_t DBGMCU_WWDG_STOP = (1u << 12);

    // ── [BUG-19] 빌드 타임 정합성 검증 ──
    static_assert(sizeof(uint32_t) == 4, "uint32_t must be 4 bytes");
    static_assert(ADDR_DHCSR >= 0xE0000000u && ADDR_DHCSR < 0xF0000000u,
        "DHCSR address out of Cortex-M PPB range");
    static_assert(ADDR_AIRCR >= 0xE0000000u && ADDR_AIRCR < 0xF0000000u,
        "AIRCR address out of Cortex-M PPB range");
    static_assert((AIRCR_RESET_CMD & 0xFFFF0000u) == AIRCR_VECTKEY,
        "AIRCR VECTKEY mismatch");
    static_assert((DHCSR_DEBUG_MASK& DHCSR_C_DEBUGEN) != 0u,
        "DHCSR mask must include C_DEBUGEN");

    /// @brief 디버거/JTAG 탐지 및 강제 시스템 정지 (정적 유틸리티)
    class AntiDebugManager {
    public:
        /// @brief 디버거 연결 여부 확인 — 탐지 시 forceHalt 호출
        /// @note  ARM: DHCSR.C_DEBUGEN 직접 검사
        static void checkDebuggerPresence() noexcept;

        // 정적 전용 클래스 — 인스턴스화 차단
        AntiDebugManager() = delete;
        ~AntiDebugManager() = delete;
        AntiDebugManager(const AntiDebugManager&) = delete;
        AntiDebugManager& operator=(const AntiDebugManager&) = delete;
        AntiDebugManager(AntiDebugManager&&) = delete;
        AntiDebugManager& operator=(AntiDebugManager&&) = delete;

    private:
        /// @brief 탐지 시 즉각 시스템 정지 — 반환 안 함
        /// @param message  정지 사유 (SecureLogger 기록)
        [[noreturn]] static void forceHalt(const char* message) noexcept;
    };

} // namespace ProtectedEngine