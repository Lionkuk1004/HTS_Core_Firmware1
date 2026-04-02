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

// ARM Cortex-M (STM32) 전용 모듈: 비대상 플랫폼 빌드 차단
// Visual Studio Windows 정적 라이브러리(HTS_LIM.vcxproj)는 _WIN32 로 호스트 단위검증 빌드 허용.
#if (((!defined(__arm__) && !defined(__TARGET_ARCH_ARM) && \
      !defined(__TARGET_ARCH_THUMB) && !defined(__ARM_ARCH)) || \
     defined(__aarch64__)) && !defined(_WIN32))
#error "[HTS_FATAL] HTS_Meter_Data_Manager는 STM32 전용입니다. A55/서버 빌드에서 제외하십시오."
#endif

#include <cstdint>
#include <cstddef>
#include <atomic>

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

    /// A-4: 외부 무결성(HMAC/서명 등) — 통과 시에만 Update_Reading 저장. nullptr=생략.
    using MeterReading_VerifyFn =
        bool (*)(const MeterReading& r, void* user) noexcept;

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

        /// A-4: HMAC/서명 검증을 훅으로 주입(nullptr이면 IEEE CRC32 저장 무결성만).
        void Register_Meter_Reading_Verify(
            MeterReading_VerifyFn fn, void* user) noexcept;

        // ─── 데이터 조회 ─────────────────────────────────

        [[nodiscard]] MeterReading Get_Latest() const noexcept;
        /// A-4: 저장 CRC 불일치 또는 조회 시 변조 감지 래치
        [[nodiscard]] bool Is_Meter_Integrity_Fault() const noexcept;
        [[nodiscard]] uint32_t Get_Profile_Value(size_t slot) const noexcept;
        [[nodiscard]] size_t Get_Event_Log(
            MeterLogEntry* out, size_t cap) const noexcept;

        // ─── 주기 처리 ──────────────────────────────────

        void Tick(uint32_t systick_ms,
            HTS_Priority_Scheduler& scheduler) noexcept;

        void Shutdown() noexcept;

    private:
        static constexpr size_t IMPL_BUF_SIZE = 544u;
        static constexpr size_t IMPL_BUF_ALIGN = 8u;
        struct Impl;
        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        std::atomic<bool> impl_valid_{ false };
        Impl* get_impl() noexcept;
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine