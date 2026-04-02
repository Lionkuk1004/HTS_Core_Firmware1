// =========================================================================
// HTS_Location_Engine.h
// 삼각측량 위치 추적 + Zero-Knowledge 프라이버시 게이트
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  [프라이버시 원칙]
//   1. 위치 계산은 항상 수행 (SOS 대비)
//   2. 위치 전송은 인가된 경우에만 (Privacy Gate)
//   3. 제조사(INNOViD)도 추적 불가 (토큰 키 미보유)
//   4. 모든 접근은 감사 로그 기록 (법적 증거)
//
//  [추적 모드 — 3단계]
//   TRACKING_OFF:    기본값, 위치가 칩을 떠나지 않음
//   EMERGENCY_AUTH:  경찰/소방 인가 토큰 (KCMVP 서명, 최대 72시간)
//   FAMILY_CONSENT:  소유자 PIN + BLE 페어링 (언제든 해제)
//
//  [배터리 적응형 주기]
//   EMERGENCY + 배터리>50%: 10초 | 20-50%: 30초 | <20%: 5분
//   FAMILY + 이동: 30초 | 정지: 5분 | 배터리<20%: 30분
//   TRACKING_OFF: 전송 0회 (전력 0)
//
//  @warning sizeof ≈ 772B — 전역/정적 배치 권장
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

#include <cstdint>
#include <cstddef>
#include <atomic>

namespace ProtectedEngine {

    class HTS_Mesh_Sync;
    class HTS_Priority_Scheduler;

    enum class LocationMode : uint8_t {
        ANCHOR = 0u,
        MOBILE = 1u,
    };

    /// @brief 추적 인가 모드 (Privacy Gate)
    enum class TrackingMode : uint8_t {
        TRACKING_OFF = 0u,   ///< 기본: 위치 전송 차단 (HUMAN)
        EMERGENCY_AUTH = 1u,   ///< 경찰/소방 인가 수색
        FAMILY_CONSENT = 2u,   ///< 소유자 동의 가족 추적
        ALWAYS_TRACKABLE = 3u,   ///< 항시 추적 (PET/LIVESTOCK/ASSET)
    };

    /// @brief 장비 분류 (OTP 기록, 공장 출하 후 변경 불가)
    ///
    /// Privacy Gate 정책:
    ///  HUMAN_*:     TRACKING_OFF 기본, 토큰/PIN 필요
    ///  PET_*:       ALWAYS_TRACKABLE, 주인 항시 추적
    ///  LIVESTOCK:   ALWAYS_TRACKABLE, 농장주 항시 추적
    ///  ASSET:       ALWAYS_TRACKABLE, 소유자 항시 추적
    enum class DeviceClass : uint8_t {
        HUMAN_ADULT = 0x00u,
        HUMAN_MINOR = 0x01u,   ///< 보호자 추적 허용
        HUMAN_SENIOR = 0x02u,   ///< 보호자 추적 허용
        PET_DOG = 0x10u,
        PET_CAT = 0x11u,
        PET_OTHER = 0x12u,
        LIVESTOCK = 0x20u,   ///< 소/돼지/닭 (귀표)
        ASSET = 0x30u,   ///< 차량/장비 (상시 비콘)
        ASSET_PASSIVE = 0x31u,   ///< 파렛트/물류 (Wake-on-Signal)
    };

    /// @brief 와일드카드 ID (재난 지역 전체 검색)
    /// @note  경찰/소방 CA 서명 토큰만 와일드카드 허용
    static constexpr uint16_t DEVICE_ID_WILDCARD = 0xFFFFu;

    /// @brief 인가 토큰 (경찰/소방 수색 명령)
    struct AuthToken {
        uint16_t agency_id;         ///< 기관 ID (경찰청=0x0110, 소방=0x0119)
        uint16_t target_device_id;  ///< 대상 ID (0xFFFF=지역 전체 검색)
        uint32_t issue_time;        ///< 발급 시각 (epoch 초)
        uint32_t last_heartbeat;    ///< 마지막 하트비트 수신 시각
        int32_t  zone_lat_1e4;      ///< 수색 영역 중심 위도 (0=제한 없음)
        int32_t  zone_lon_1e4;      ///< 수색 영역 중심 경도
        uint16_t zone_radius_m;     ///< 수색 반경 (m, 0=무제한)
        uint8_t  pad[2];
        uint8_t  signature[32];     ///< KCMVP HMAC-SHA256 서명
    };

    /// @brief 감사 로그 항목
    struct AuditEntry {
        uint32_t timestamp;     ///< 이벤트 시각
        uint16_t actor_id;      ///< 요청자 ID (기관/가족)
        uint8_t  action;        ///< 0=인가, 1=만료, 2=해제, 3=거부
        uint8_t  mode;          ///< TrackingMode 당시 값
    };

    struct AnchorEntry {
        uint16_t node_id;
        int32_t  lat_1e4;
        int32_t  lon_1e4;
        uint8_t  valid;
        uint8_t  pad[3];
    };

    /// @brief 삼각측량 결과 (상황실 지도·GET API 공통)
    /// @note map_10m_cert==1 일 때만 지도에서 「10m 이내 신뢰」 표시(원·마커) 권장
    struct PositionResult {
        int32_t  lat_1e4;
        int32_t  lon_1e4;
        uint8_t  accuracy_m;       ///< 추정 오차 상한 (m)
        uint8_t  anchor_count;
        uint8_t  quality;
        uint8_t  map_10m_cert;     ///< 1=10m 이내 표시 정책 충족 (앵커·동기·에폭 조건)
        uint8_t  valid;
    };

    class HTS_Location_Engine {
    public:
        static constexpr size_t MAX_ANCHORS = 8u;
        /// 위치 보고 바이너리 (Tick → 스케줄러): v2 = 9바이트 ([8]=map_10m_cert)
        static constexpr size_t POS_REPORT_SIZE = 9u;
        static constexpr size_t MAX_FAMILY_DEVS = 4u;
        static constexpr size_t AUDIT_LOG_SIZE = 8u;

        /// @brief 하트비트 타임아웃 (48시간 = 172,800초)
        ///  수색 본부가 24시간마다 하트비트 전송 → 48시간 미수신 시 만료
        ///  수색 중: 하트비트만 보내면 무제한 갱신
        ///  수색 종료: 본부 철수 → 48시간 후 프라이버시 복원
        static constexpr uint32_t HEARTBEAT_TIMEOUT_SEC = 172800u;

        /// @brief 0xFFFF = 지역 전체 검색 (와일드카드)
        static constexpr uint16_t WILDCARD_ID = 0xFFFFu;

        /// @brief 생성자
        /// @param my_id        장비 ID
        /// @param mode         ANCHOR / MOBILE
        /// @param dev_class    장비 분류 (OTP에서 읽어 전달)
        explicit HTS_Location_Engine(
            uint16_t my_id, LocationMode mode,
            DeviceClass dev_class = DeviceClass::HUMAN_ADULT) noexcept;
        ~HTS_Location_Engine() noexcept;

        HTS_Location_Engine(const HTS_Location_Engine&) = delete;
        HTS_Location_Engine& operator=(const HTS_Location_Engine&) = delete;
        HTS_Location_Engine(HTS_Location_Engine&&) = delete;
        HTS_Location_Engine& operator=(HTS_Location_Engine&&) = delete;

        // ─── 앵커 / 위치 ─────────────────────────────────
        [[nodiscard]] bool Register_Anchor(
            uint16_t node_id, int32_t lat_1e4, int32_t lon_1e4) noexcept;
        void Set_My_Position(int32_t lat_1e4, int32_t lon_1e4) noexcept;
        /// @brief 삼각측량 갱신 (앵커 스냅샷·짧은 커밋 / 무거운 연산은 PRIMASK 밖)
        void Update_Position(const HTS_Mesh_Sync& sync) noexcept;
        [[nodiscard]] PositionResult Get_Position() const noexcept;

        // ─── Privacy Gate (핵심) ─────────────────────────

        /// @brief 현재 추적 모드 조회
        [[nodiscard]] TrackingMode Get_Tracking_Mode() const noexcept;

        /// @brief 긴급 수색 인가 (경찰/소방 토큰)
        /// @param token      인가 토큰 (KCMVP 서명 포함)
        /// @param current_sec 현재 시각 (epoch 초)
        /// @return true = 인가 성공 (서명+시간 유효)
        [[nodiscard]]
        bool Authorize_Emergency(
            const AuthToken& token, uint32_t current_sec) noexcept;

        /// @brief 가족 추적 동의 (소유자 직접 설정)
        /// @param owner_pin   소유자 PIN (4자리 해시)
        /// @param family_id   가족 기기 ID
        /// @return true = 등록 성공
        [[nodiscard]]
        bool Enable_Family_Tracking(
            uint32_t owner_pin, uint16_t family_id) noexcept;

        /// @brief 소유자 킬 스위치 (즉시 추적 해제)
        /// @param owner_pin  소유자 PIN
        /// @return true = 해제 성공
        [[nodiscard]]
        bool Owner_Kill_Switch(uint32_t owner_pin) noexcept;

        /// @brief 수색 하트비트 갱신 (수색 본부 24시간마다 전송)
        /// @param agency_id   기관 ID (인가 토큰과 일치)
        /// @param current_sec 현재 시각
        /// @return true = 갱신 성공
        [[nodiscard]]
        bool Heartbeat_Renew(
            uint16_t agency_id, uint32_t current_sec) noexcept;

        /// @brief 배터리 잔량 갱신 (적응형 주기 계산용)
        void Set_Battery_Percent(uint8_t pct) noexcept;

        /// @brief 이동 상태 갱신 (가속도 센서 기반)
        void Set_Moving(bool moving) noexcept;

        /// @brief 소유자 PIN 설정 (최초 1회, BLE 페어링 시)
        void Set_Owner_PIN(uint32_t pin_hash) noexcept;

        // ─── 감사 로그 ──────────────────────────────────

        /// @brief 감사 로그 조회 (최근 8건)
        [[nodiscard]]
        size_t Get_Audit_Log(
            AuditEntry* out, size_t cap) const noexcept;

        // ─── Tick / 기타 ────────────────────────────────
        void Tick(uint32_t systick_ms, uint32_t current_sec,
            HTS_Priority_Scheduler& scheduler) noexcept;
        [[nodiscard]] LocationMode Get_Mode() const noexcept;
        void Shutdown() noexcept;

    private:
        static constexpr size_t IMPL_BUF_SIZE = 768u;
        static constexpr size_t IMPL_BUF_ALIGN = 8u;
        struct Impl;
        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        std::atomic<bool> impl_valid_{ false };
        Impl* get_impl() noexcept;
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine