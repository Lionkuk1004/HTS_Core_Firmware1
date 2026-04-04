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
//  [RDP/퓨즈] 옵션 바이트 RDP Level 검사는 부팅 경로(예: HTS_Hardware_Init,
//   HTS_BOOT_ENFORCE_RDP_LEVEL2)에서 수행 — 본 모듈은 런타임 DHCSR 보완 탐지
//
//  [프로비저닝 FSM] Unprovisioned(공정·SWD/JTAG 허용) 단계와 Sealed 양산 단계를 부트·
//   빌드 스위치(예: HTS_ALLOW_OPEN_DEBUG)로 분리. HTS_ALLOW_OPEN_DEBUG 정의 시
//   pollHardwareOrFault / checkDebuggerPresence 는 즉시 반환(공정 디버그 허용).
//   양산 Release에서는 반드시 미정의 — Sealed 후 런타임 핫플러깅 자폭과 HTS_Key_Provisioning
//   정책을 정합할 것.
//
//  [사용법]
//   AntiDebugManager::checkDebuggerPresence();
//   → 탐지 시 forceHalt() 호출 — 반환하지 않음 ([[noreturn]])
//   → 모든 함수 static — 인스턴스 생성 불필요/불가
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>

namespace ProtectedEngine {

    // ── ARM Cortex-M4 MMIO 주소 상수 (J-3) ─────────────────────
    // ARM DDI 0403E (ARMv7-M Architecture Reference Manual) 기준
    static constexpr uint32_t ADDR_DHCSR = 0xE000EDF0u;  ///< Debug Halting Control/Status
    static constexpr uint32_t ADDR_AIRCR = 0xE000ED0Cu;  ///< App Interrupt/Reset Control
    static constexpr uint32_t ADDR_DBGMCU_CR = 0xE0042004u;  ///< DBGMCU Control (STM32F4 RM0090)
    static constexpr uint32_t ADDR_DBGMCU_FZ = 0xE0042008u;  ///< DBGMCU APB1 Freeze (STM32F4)

    /// DBGMCU_CR 비트 0..2: DBG_SLEEP / DBG_STOP / DBG_STANDBY (디버거 세션에서 호스트가 설정 가능)
    static constexpr uint32_t DBGMCU_CR_DEBUG_MASK =
        (1u << 0) | (1u << 1) | (1u << 2);

    // ── DHCSR 비트 필드 상수 ───────────────────────────────────
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

    // ── DBGMCU_APB1_FZ WDT 프리즈 (RM0090 STM32F4, 0xE0042008) ──
    static constexpr uint32_t DBGMCU_WWDG_STOP = (1u << 11);  ///< DBG_WWDG_STOP
    static constexpr uint32_t DBGMCU_IWDG_STOP = (1u << 12); ///< DBG_IWDG_STOP

    // ── 빌드 타임 정합성 검증 ───────────────────────────────────
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
        /// @brief SysTick·스케줄러 Tick·부트 등 주기 경로에서 호출 — DHCSR+DBGMCU_CR 교차 검증, 탐지 시 감사링 소거 후 자폭
        /// @note 로거 전용 수동 API에만 두지 말 것 — ISR/비마스크 가능 경로에서 상시 호출
        static void pollHardwareOrFault() noexcept;

        /// @brief 디버거 연결 여부 확인 — 탐지 시 forceHalt 호출
        /// @note  ARM: DHCSR 2회 샘플 기반 C_DEBUGEN Attach 탐지 +
        ///        (C_HALT|S_HALT) Halt 교차 검증
        static void checkDebuggerPresence() noexcept;

        /// @brief 글리치/탬퍼 등 신뢰 모듈 전용 — forceHalt와 동일 AIRCR·DBGMCU 파이프라인 (S-1)
        [[noreturn]] static void trustedHalt(const char* message) noexcept;

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
