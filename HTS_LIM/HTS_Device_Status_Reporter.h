// =========================================================================
// HTS_Device_Status_Reporter.h
// 장비 상태 보고 + Wake-on-Signal 응답 모듈
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  [목적]
//  배터리/온도/장애/모듈 상태를 주기적으로 보고하고,
//  Wake-on-Signal(WoR) 스캔 요청에 즉시 응답합니다.
//
//  [보고 패킷] (8바이트)
//   [0-1] device_id
//   [2]   battery_pct       (0-100%)
//   [3]   temperature_c     (int8_t, -40~+85°C)
//   [4]   fault_flags       (8비트 장애)
//   [5]   module_flags      (8비트 모듈 활성)
//   [6]   uptime_hours      (0-255, 255=255+)
//   [7]   device_class      (DeviceClass 값)
//
//  [전력 모드]
//   ACTIVE:   60초/10초 주기 보고 (감시탑/핸드폰)
//   WOR_ONLY: 스캔 시에만 응답 (파렛트/물류)
//
//  @warning sizeof ≈ 260B — 전역/정적 배치 권장
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    class HTS_Priority_Scheduler;

    /// @brief 장애 플래그 (비트필드)
    namespace FaultFlag {
        static constexpr uint8_t NONE = 0x00u;
        static constexpr uint8_t LOW_BATTERY = 0x01u;
        static constexpr uint8_t OVER_TEMP = 0x02u;
        static constexpr uint8_t WATCHDOG_TRIP = 0x04u;
        static constexpr uint8_t FLASH_ERROR = 0x08u;
        static constexpr uint8_t SYNC_LOST = 0x10u;
        static constexpr uint8_t SENSOR_FAIL = 0x20u;
        static constexpr uint8_t TAMPER_DETECT = 0x40u;
        static constexpr uint8_t CRITICAL = 0x80u;
    }

    /// @brief 모듈 활성 플래그 (비트필드)
    namespace ModuleFlag {
        static constexpr uint8_t BEACON = 0x01u;
        static constexpr uint8_t NEIGHBOR = 0x02u;
        static constexpr uint8_t MESH_SYNC = 0x04u;
        static constexpr uint8_t LOCATION = 0x08u;
        static constexpr uint8_t SCHEDULER = 0x10u;
        static constexpr uint8_t CRYPTO = 0x20u;
        static constexpr uint8_t STATUS_RPT = 0x40u;
        static constexpr uint8_t WOR_ACTIVE = 0x80u;
    }

    /// @brief 보고 전력 모드
    enum class ReportMode : uint8_t {
        ACTIVE = 0u,   ///< 주기적 보고 (감시탑/핸드폰/워치)
        WOR_ONLY = 1u,   ///< Wake-on-Signal만 (파렛트/물류)
    };

    class HTS_Device_Status_Reporter {
    public:
        static constexpr size_t   STATUS_PKT_SIZE = 8u;
        static constexpr uint32_t NORMAL_INTERVAL = 60000u;   // 60초
        static constexpr uint32_t ALERT_INTERVAL = 10000u;   // 10초

        /// @brief 생성자
        /// @param my_id        장비 ID
        /// @param dev_class    DeviceClass (0x00~0x31)
        /// @param rpt_mode     ACTIVE 또는 WOR_ONLY
        explicit HTS_Device_Status_Reporter(
            uint16_t my_id,
            uint8_t  dev_class,
            ReportMode rpt_mode = ReportMode::ACTIVE) noexcept;
        ~HTS_Device_Status_Reporter() noexcept;

        HTS_Device_Status_Reporter(const HTS_Device_Status_Reporter&) = delete;
        HTS_Device_Status_Reporter& operator=(const HTS_Device_Status_Reporter&) = delete;
        HTS_Device_Status_Reporter(HTS_Device_Status_Reporter&&) = delete;
        HTS_Device_Status_Reporter& operator=(HTS_Device_Status_Reporter&&) = delete;

        // ─── 상태 입력 ──────────────────────────────────

        void Set_Battery(uint8_t pct) noexcept;
        void Set_Temperature(int8_t celsius) noexcept;
        void Set_Fault(uint8_t flag) noexcept;
        void Clear_Fault(uint8_t flag) noexcept;
        void Set_Module_Active(uint8_t flag) noexcept;
        void Clear_Module_Active(uint8_t flag) noexcept;

        // ─── 상태 조회 ──────────────────────────────────

        [[nodiscard]] uint8_t Get_Battery() const noexcept;
        [[nodiscard]] int8_t  Get_Temperature() const noexcept;
        [[nodiscard]] uint8_t Get_Faults() const noexcept;
        [[nodiscard]] uint8_t Get_Modules() const noexcept;
        [[nodiscard]] bool    Has_Any_Fault() const noexcept;

        // ─── Wake-on-Signal 응답 (WoR ISR에서 호출) ──────

        /// @brief WoR 스캔 수신 → 즉시 상태 패킷 전송
        /// @param systick_ms  현재 시각
        /// @param scheduler   Priority_Scheduler
        /// @note  ISR 안전 (PRIMASK 내부 사용)
        void On_WoR_Scan(
            uint32_t systick_ms,
            HTS_Priority_Scheduler& scheduler) noexcept;

        // ─── 주기 처리 ──────────────────────────────────

        /// @brief ACTIVE 모드: 주기 보고 / WOR_ONLY: 아무 동작 안 함
        void Tick(uint32_t systick_ms,
            HTS_Priority_Scheduler& scheduler) noexcept;

        void Shutdown() noexcept;

    private:
        static constexpr size_t IMPL_BUF_SIZE = 256u;
        static constexpr size_t IMPL_BUF_ALIGN = 8u;
        struct Impl;
        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        bool impl_valid_ = false;
        Impl* get_impl() noexcept;
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine