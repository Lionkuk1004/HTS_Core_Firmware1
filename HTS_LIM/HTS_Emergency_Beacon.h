// =========================================================================
// HTS_Emergency_Beacon.h
// 긴급 비콘 자동 송출기 — 공개 인터페이스
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [목적]
//  하드웨어 트리거(GPIO 비상버튼, 센서 이상)만으로 자동 발동하는
//  최후의 생명선. 운용자 의식불명 시에도 GPS 좌표 + 알림 플래그를
//  500ms 주기로 B-CDMA 무선 송출합니다.
//
//  [비콘 패킷 구조] (8바이트 = 1 FEC_HARQ 패킷)
//   [0-1] device_id     uint16_t  장비 고유 ID
//   [2-3] alert_flags   uint16_t  16비트 알림 플래그
//   [4-5] lat_comp      int16_t   위도 압축 ((lat-33.0)×1000)
//   [6-7] lon_comp      int16_t   경도 압축 ((lon-124.0)×1000)
//   → 정밀도: ~100m (SOS에 충분)
//
//  [알림 플래그 비트 정의]
//   bit0  TEMP_HIGH   과열 감지
//   bit1  BATT_LOW    배터리 부족
//   bit2  POWER_LOSS  정전 (Last Gasp)
//   bit3  WATER_LEAK  침수 감지
//   bit4  TILT_FALL   전도/추락
//   bit5  SOS_ALARM   비상버튼
//   bit6  COVER_OPEN  케이스 개방
//   bit7  MAGNETIC    자기장 이상
//   bit8  SEC_CRYPTO  암호 인증 실패
//   bit9  JAM_DETECT  재밍 감지
//   bit10 AMC_DROP    통신 모드 강등
//   bit11 SYNC_LOSS   메쉬 동기 상실
//   bit12 HARQ_MAX    HARQ 최대 도달
//   bit13 ANT_FAULT   안테나 이상
//   bit14 SENSOR_ERR  센서 통신 단절
//   bit15 MEM_WDT     메모리/WDT 이상
//
//  [사용법]
//   1. 생성: HTS_Emergency_Beacon(device_id)
//   2. Set_GPS(lat, lon): GPS 좌표 설정 (Q24 또는 도 단위)
//   3. Trigger(flag_bit): 긴급 트리거 (ISR에서 호출 가능)
//   4. Tick(systick_ms, scheduler): 주기 처리 → 500ms마다 P0 인큐
//   5. Cancel(): 비콘 해제 (수동 복구 후)
//
//  @warning sizeof ≈ 260B — 전역/정적 배치 권장
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    // 전방 선언 (순환 의존 방지)
    class HTS_Priority_Scheduler;

    /// @brief 알림 플래그 비트 상수
    struct AlertFlag {
        static constexpr uint16_t TEMP_HIGH = (1u << 0u);
        static constexpr uint16_t BATT_LOW = (1u << 1u);
        static constexpr uint16_t POWER_LOSS = (1u << 2u);
        static constexpr uint16_t WATER_LEAK = (1u << 3u);
        static constexpr uint16_t TILT_FALL = (1u << 4u);
        static constexpr uint16_t SOS_ALARM = (1u << 5u);
        static constexpr uint16_t COVER_OPEN = (1u << 6u);
        static constexpr uint16_t MAGNETIC = (1u << 7u);
        static constexpr uint16_t SEC_CRYPTO = (1u << 8u);
        static constexpr uint16_t JAM_DETECT = (1u << 9u);
        static constexpr uint16_t AMC_DROP = (1u << 10u);
        static constexpr uint16_t SYNC_LOSS = (1u << 11u);
        static constexpr uint16_t HARQ_MAX = (1u << 12u);
        static constexpr uint16_t ANT_FAULT = (1u << 13u);
        static constexpr uint16_t SENSOR_ERR = (1u << 14u);
        static constexpr uint16_t MEM_WDT = (1u << 15u);
    };

    class HTS_Emergency_Beacon {
    public:
        /// @brief 비콘 패킷 크기 (FEC_HARQ MAX_INFO와 일치)
        static constexpr size_t BEACON_SIZE = 8u;

        /// @brief 비콘 송출 주기 (ms)
        static constexpr uint32_t BEACON_INTERVAL_MS = 500u;

        /// @brief 최소 연속 송출 시간 (30초 = 60회)
        static constexpr uint32_t MIN_DURATION_MS = 30000u;

        /// @brief 생성자
        /// @param device_id  장비 고유 ID (2바이트)
        explicit HTS_Emergency_Beacon(uint16_t device_id) noexcept;

        /// @brief 소멸자 — Secure_Wipe
        ~HTS_Emergency_Beacon() noexcept;

        /// 복사/이동 차단
        HTS_Emergency_Beacon(const HTS_Emergency_Beacon&) = delete;
        HTS_Emergency_Beacon& operator=(const HTS_Emergency_Beacon&) = delete;
        HTS_Emergency_Beacon(HTS_Emergency_Beacon&&) = delete;
        HTS_Emergency_Beacon& operator=(HTS_Emergency_Beacon&&) = delete;

        // ─── GPS 설정 ───────────────────────────────────────

        /// @brief GPS 좌표 설정 (정수 × 10000 단위)
        /// @param lat_1e4  위도 × 10000 (예: 37.5665 → 375665)
        /// @param lon_1e4  경도 × 10000 (예: 126.9780 → 1269780)
        void Set_GPS(int32_t lat_1e4, int32_t lon_1e4) noexcept;

        // ─── 트리거 API (ISR 안전) ──────────────────────────

        /// @brief 알림 플래그 설정 (비트 OR — ISR에서 호출 가능)
        /// @param flag  AlertFlag 비트 (복수 OR 가능)
        /// @note  SOS_ALARM 비트 포함 시 자동으로 비콘 발동
        void Trigger(uint16_t flag) noexcept;

        /// @brief 알림 플래그 직접 설정 (전체 교체)
        void Set_Flags(uint16_t flags) noexcept;

        /// @brief 현재 알림 플래그 조회
        [[nodiscard]] uint16_t Get_Flags() const noexcept;

        /// @brief 비콘 활성 여부
        [[nodiscard]] bool Is_Active() const noexcept;

        // ─── 주기 처리 ──────────────────────────────────────

        /// @brief 주기 호출 (SysTick 또는 메인 루프)
        /// @param systick_ms  현재 시스템 시각
        /// @param scheduler   Priority_Scheduler 참조 (P0 인큐)
        void Tick(uint32_t systick_ms,
            HTS_Priority_Scheduler& scheduler) noexcept;

        /// @brief 비콘 해제 (수동 복구 후)
        void Cancel() noexcept;

        /// @brief 안전 종료
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