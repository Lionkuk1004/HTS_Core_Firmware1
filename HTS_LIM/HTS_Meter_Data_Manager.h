// =========================================================================
// HTS_Meter_Data_Manager.h
// AMI 계량 데이터 관리 모듈
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  [목적]
//  전력/가스/수도 계량기 데이터를 수집, 저장, 보고합니다.
//  DLMS/COSEM 프로토콜 호환 데이터 구조를 사용합니다.
//
//  [데이터 구조]
//   순시 전력:   uint32_t (Wh)
//   누적 전력:   uint32_t (kWh × 100)
//   부하 프로파일: 15분 간격 96포인트 (24시간)
//   이벤트 로그:  8건 링버퍼 (정전/복전/과부하)
//
//  @warning sizeof ≈ 512B — 전역/정적 배치 권장
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    class HTS_Priority_Scheduler;

    /// @brief 계량 이벤트 타입
    enum class MeterEvent : uint8_t {
        POWER_OFF = 0u,   ///< 정전
        POWER_ON = 1u,   ///< 복전
        OVERLOAD = 2u,   ///< 과부하
        TAMPER = 3u,   ///< 검침기 조작
        THRESHOLD = 4u,   ///< 임계값 초과
    };

    /// @brief 이벤트 로그 항목
    struct MeterLogEntry {
        uint32_t   timestamp;
        MeterEvent event;
        uint8_t    pad[3];
    };

    /// @brief 순시 계량 데이터
    struct MeterReading {
        uint32_t watt_hour;         ///< 순시 전력 (Wh)
        uint32_t cumul_kwh_x100;    ///< 누적 전력 (kWh × 100)
        uint16_t voltage_x10;       ///< 전압 (V × 10)
        uint16_t current_x100;      ///< 전류 (A × 100)
        uint8_t  power_factor;      ///< 역률 (0-100%)
        uint8_t  valid;
        uint8_t  pad[2];
    };

    class HTS_Meter_Data_Manager {
    public:
        static constexpr size_t  PROFILE_SLOTS = 96u;   // 15분 × 96 = 24시간
        static constexpr size_t  EVENT_LOG_SIZE = 8u;
        static constexpr uint32_t PROFILE_INTERVAL_MS = 900000u;  // 15분
        static constexpr uint32_t REPORT_INTERVAL_MS = 3600000u; // 1시간

        explicit HTS_Meter_Data_Manager(uint16_t my_id) noexcept;
        ~HTS_Meter_Data_Manager() noexcept;

        HTS_Meter_Data_Manager(const HTS_Meter_Data_Manager&) = delete;
        HTS_Meter_Data_Manager& operator=(const HTS_Meter_Data_Manager&) = delete;
        HTS_Meter_Data_Manager(HTS_Meter_Data_Manager&&) = delete;
        HTS_Meter_Data_Manager& operator=(HTS_Meter_Data_Manager&&) = delete;

        // ─── 데이터 입력 ─────────────────────────────────

        void Update_Reading(const MeterReading& reading) noexcept;
        void Log_Event(MeterEvent event, uint32_t timestamp) noexcept;

        // ─── 데이터 조회 ─────────────────────────────────

        [[nodiscard]] MeterReading Get_Latest() const noexcept;
        [[nodiscard]] uint32_t Get_Profile_Value(size_t slot) const noexcept;
        [[nodiscard]] size_t Get_Event_Log(
            MeterLogEntry* out, size_t cap) const noexcept;

        // ─── 주기 처리 ──────────────────────────────────

        void Tick(uint32_t systick_ms,
            HTS_Priority_Scheduler& scheduler) noexcept;

        void Shutdown() noexcept;

    private:
        static constexpr size_t IMPL_BUF_SIZE = 512u;
        static constexpr size_t IMPL_BUF_ALIGN = 8u;
        struct Impl;
        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        bool impl_valid_ = false;
        Impl* get_impl() noexcept;
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine