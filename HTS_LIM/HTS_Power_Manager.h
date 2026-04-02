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

/// @file  HTS_Power_Manager.h
/// @brief HTS 전력 관리자 -- IoT 저전력 슬립 관리
/// @details
///   STM32F407 저전력 모드를 관리하여 배터리/태양전지 IoT 시나리오에서
///   전력 소비를 최소화한다. 주변장치 클럭 게이팅, 슬립/스톱 모드 전환,
///   PVD 전압 감시, RTC 주기 웨이크업을 통합 관리.
///
///   사용 예시:
///   @code
///   static ProtectedEngine::HTS_Power_Manager g_power;
///   g_power.Initialize();
///   g_power.Register_HAL_Callbacks(hal_cbs);
///   g_power.Register_Notify_Callbacks(notify_cbs);
///   g_power.Set_PVD_Level(PVD_Level::V_2_5);
///
///   // IoT 센서 보고 완료 후 60초 슬립:
///   g_power.Request_Sleep(PowerMode::STOP, 60);
///
///   // 웨이크업 후 자동 복원 -> on_post_wake 콜백 호출
///   @endcode
///
/// @warning sizeof(HTS_Power_Manager) ~ 256B. 전역/정적 배치 권장.
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_Power_Manager_Defs.h"
#include <cstdint>
#include <atomic>

namespace ProtectedEngine {

    /// @brief HTS 전력 관리자
    ///
    /// @warning sizeof ~ 256B. 전역/정적 배치 권장.
    class HTS_Power_Manager final {
    public:
        HTS_Power_Manager() noexcept;
        ~HTS_Power_Manager() noexcept;

        /// @brief 초기화
        /// @return 성공 시 true
        bool Initialize() noexcept;

        /// @brief 종료
        void Shutdown() noexcept;

        /// @brief HAL 콜백 등록
        void Register_HAL_Callbacks(const Power_HAL_Callbacks& cb) noexcept;

        /// @brief 슬립 통지 콜백 등록
        void Register_Notify_Callbacks(const Power_Notify_Callbacks& cb) noexcept;

        /// @brief 슬립 모드 진입 요청
        /// @param mode       목표 전력 모드 (SLEEP/STOP/STANDBY)
        /// @param wakeup_sec RTC 웨이크업 주기 (초, 0=RTC 미사용)
        /// @return 성공 시 true (SLEEP/STOP: 웨이크업 후 반환, STANDBY: 반환 안 함)
        bool Request_Sleep(PowerMode mode, uint32_t wakeup_sec) noexcept;

        /// @brief 클럭 모드 변경 (RUN <-> LOW_RUN)
        /// @param mode  RUN 또는 LOW_RUN
        /// @return 성공 시 true
        bool Set_Clock_Mode(PowerMode mode) noexcept;

        /// @brief PVD 임계값 설정
        /// @param level  PVD 전압 레벨
        void Set_PVD_Level(PVD_Level level) noexcept;

        /// @brief PVD 이벤트 처리 (PVD ISR에서 호출)
        /// @note  ISR 안전. 최소 처리만 수행.
        void Handle_PVD_Event() noexcept;

        /// @brief 주변장치 클럭 수동 제어
        /// @param enable_mask  활성화할 주변장치 비트맵
        void Set_Peripheral_Clocks(uint32_t enable_mask) noexcept;

        /// @name 상태
        /// @{
        PowerState Get_State() const noexcept;
        PowerMode Get_Current_Mode() const noexcept;
        uint16_t Get_Battery_MV() const noexcept;
        uint16_t Get_Last_Wake_Source() const noexcept;
        uint32_t Get_Sleep_Count() const noexcept;
        /// @}

        // -- 복사/이동 금지 --
        HTS_Power_Manager(const HTS_Power_Manager&) = delete;
        HTS_Power_Manager& operator=(const HTS_Power_Manager&) = delete;
        HTS_Power_Manager(HTS_Power_Manager&&) = delete;
        HTS_Power_Manager& operator=(HTS_Power_Manager&&) = delete;

        static constexpr uint32_t IMPL_BUF_SIZE = 256u;

    private:
        struct Impl;
        alignas(4) uint8_t impl_buf_[IMPL_BUF_SIZE];
        std::atomic<bool>  initialized_{ false };
    };

    static_assert(sizeof(HTS_Power_Manager) <= 512u,
        "HTS_Power_Manager exceeds 512B SRAM budget");

} // namespace ProtectedEngine