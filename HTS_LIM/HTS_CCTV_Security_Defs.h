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

/// @file  HTS_CCTV_Security_Defs.h
/// @brief HTS CCTV 보안 코프로세서 공통 정의부
/// @details
///   CCTV 카메라에 HTS B-CDMA 보안 칩을 내장하여 해킹을 방지하는
///   보안 코프로세서 모듈의 정의부. 영상 전송이 아닌 보안 감시 전담.
///
///   방어 대상 위협:
///   - 영상 스트림 위변조 (MITM replay/injection)
///   - CCTV 펌웨어 변조 (백도어 삽입)
///   - 비인가 네트워크 접속 (RTSP/ONVIF 무단 접근)
///   - 물리적 탬퍼 (케이스 개봉, 렌즈 가림/분사, 케이블 절단)
///   - 설정 변조 (해상도/코덱/네트워크 무단 변경)
///
///   보안 이벤트 프레임 (B-CDMA 페이로드):
///   @code
///   [EVT_TYPE(1)][SEVERITY(1)][TIMESTAMP(4)][CAMERA_ID(4)][DETAIL_LEN(1)][DETAIL(N)][HMAC(4)]
///   @endcode
///
///   설계 기준:
///   - Cortex-M4F 보안 코프로세서 (CCTV 메인 SoC와 SPI/UART 연결)
///   - HMAC-SHA256 (KCMVP) 기반 스트림 인증
///   - 힙 0, float/double 0, 나눗셈 0
///   - 20KB 프레임 버퍼 불필요 (영상 비전송) → SRAM 절약
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    // ============================================================
    //  보안 이벤트 타입
    // ============================================================

    /// @brief CCTV 보안 이벤트 분류
    /// @note  ASIC: 8비트 디코더 ROM. 이벤트 로깅 및 알림용.
    enum class CCTV_EventType : uint8_t {
        // --- 영상 무결성 (0x01~0x0F) ---
        STREAM_HMAC_FAIL = 0x01u,    ///< 영상 스트림 HMAC 검증 실패 (위변조)
        STREAM_REPLAY_DETECT = 0x02u,    ///< 스트림 시퀀스 역전/중복 (replay 공격)
        STREAM_BLACKOUT = 0x03u,    ///< 영상 출력 두절 (케이블 절단/신호 차단)
        STREAM_FROZEN = 0x04u,    ///< 영상 정지 (정지 화면 주입 공격)
        CODEC_MISMATCH = 0x05u,    ///< 코덱/해상도 무단 변경 감지

        // --- 펌웨어 무결성 (0x10~0x1F) ---
        FW_CRC_FAIL = 0x10u,    ///< 펌웨어 CRC 불일치 (변조)
        FW_ROLLBACK_DETECT = 0x11u,    ///< 펌웨어 다운그레이드 시도
        FW_UNSIGNED_BOOT = 0x12u,    ///< 서명되지 않은 펌웨어 부팅 시도
        FW_CONFIG_TAMPER = 0x13u,    ///< 설정 파일 무단 변경

        // --- 네트워크 침입 (0x20~0x2F) ---
        NET_UNAUTHORIZED_ACCESS = 0x20u,    ///< 비인가 IP 접속 시도
        NET_BRUTE_FORCE = 0x21u,    ///< 로그인 무차별 대입 공격
        NET_PORT_SCAN = 0x22u,    ///< 포트 스캔 탐지
        NET_RTSP_HIJACK = 0x23u,    ///< RTSP 세션 하이재킹 시도
        NET_DNS_SPOOF = 0x24u,    ///< DNS 스푸핑 탐지 (NTP/업데이트 서버)

        // --- 물리적 탬퍼 (0x30~0x3F) ---
        TAMPER_CASE_OPEN = 0x30u,    ///< 케이스 개봉 감지 (마이크로 스위치)
        TAMPER_LENS_BLOCKED = 0x31u,    ///< 렌즈 가림/분사 감지 (밝기 급변)
        TAMPER_CABLE_CUT = 0x32u,    ///< PoE/이더넷 케이블 절단 감지
        TAMPER_ORIENTATION = 0x33u,    ///< 카메라 방향 강제 변경 (가속도센서)
        TAMPER_JTAG_PROBE = 0x34u,    ///< 디버그 포트 접속 시도

        // --- 시스템 상태 (0x40~0x4F) ---
        SYSTEM_BOOT_OK = 0x40u,    ///< 보안 부팅 정상 완료
        SYSTEM_HEARTBEAT = 0x41u,    ///< 주기적 정상 보고
        SYSTEM_WATCHDOG_RESET = 0x42u,    ///< 워치독 리셋 발생
        SYSTEM_POWER_ANOMALY = 0x43u     ///< 전원 이상 (PVD)
    };

    // ============================================================
    //  이벤트 심각도
    // ============================================================

    /// @brief 보안 이벤트 심각도
    enum class CCTV_Severity : uint8_t {
        INFO = 0x00u,    ///< 정보 (정상 하트비트 등)
        WARNING = 0x01u,    ///< 경고 (단발 이상)
        CRITICAL = 0x02u,    ///< 위험 (즉시 대응 필요)
        EMERGENCY = 0x03u     ///< 비상 (시스템 무력화 시도)
    };

    // ============================================================
    //  보안 이벤트 프레임 상수
    // ============================================================

    /// 이벤트 헤더: EVT_TYPE(1)+SEVERITY(1)+TIMESTAMP(4)+CAMERA_ID(4)+DETAIL_LEN(1) = 11
    static constexpr uint32_t CCTV_EVT_HEADER_SIZE = 11u;
    /// HMAC 태그 (SHA-256 절단 4바이트 = 32비트 인증)
    static constexpr uint32_t CCTV_EVT_HMAC_SIZE = 4u;
    /// 이벤트 상세 최대 크기
    static constexpr uint32_t CCTV_EVT_MAX_DETAIL = 48u;
    /// 최대 이벤트 프레임 크기
    static constexpr uint32_t CCTV_EVT_MAX_FRAME_SIZE = CCTV_EVT_HEADER_SIZE + CCTV_EVT_MAX_DETAIL + CCTV_EVT_HMAC_SIZE;

    /// 펌웨어 CRC 검증 주기 (ms)
    static constexpr uint32_t CCTV_FW_CHECK_INTERVAL = 60000u;  ///< 1분
    /// 하트비트 주기 (ms)
    static constexpr uint32_t CCTV_HEARTBEAT_INTERVAL = 30000u;  ///< 30초
    /// 스트림 HMAC 검증 주기 (ms)
    static constexpr uint32_t CCTV_STREAM_CHECK_INTERVAL = 5000u;   ///< 5초
    /// 브루트포스 임계값 (실패 횟수 / 분)
    static constexpr uint32_t CCTV_BRUTE_FORCE_THRESHOLD = 5u;
    /// 스트림 정지 판정 시간 (ms)
    static constexpr uint32_t CCTV_STREAM_FROZEN_TIMEOUT = 10000u;  ///< 10초

    /// 이벤트 로그 링 크기 (최근 N개 보관)
    static constexpr uint32_t CCTV_EVENT_LOG_SIZE = 16u;
    static constexpr uint32_t CCTV_EVENT_LOG_MASK = CCTV_EVENT_LOG_SIZE - 1u;
    static_assert((CCTV_EVENT_LOG_SIZE& CCTV_EVENT_LOG_MASK) == 0u,
        "CCTV_EVENT_LOG_SIZE must be power of 2");

    // ============================================================
    //  이벤트 로그 항목
    // ============================================================

    /// @brief 단일 보안 이벤트 로그 항목
    struct CCTV_EventLog {
        CCTV_EventType event_type;      ///< 이벤트 타입
        CCTV_Severity  severity;        ///< 심각도
        uint16_t       count;           ///< 누적 발생 횟수
        uint32_t       first_tick;      ///< 최초 발생 시각
        uint32_t       last_tick;       ///< 최근 발생 시각
    };
    static_assert(sizeof(CCTV_EventLog) == 12u, "CCTV_EventLog must be 12 bytes");

    // ============================================================
    //  카메라 SoC 모니터링 콜백
    // ============================================================

    /// @brief 카메라 SoC 상태 모니터링 콜백 (SPI/UART 인터페이스)
    /// @note  보안 칩이 카메라 SoC의 상태를 주기적으로 감시.
    struct CCTV_Monitor_Callbacks {
        uint32_t(*get_fw_crc)(void);                   ///< 카메라 펌웨어 CRC-32 조회
        uint32_t(*get_fw_version)(void);               ///< 펌웨어 버전 조회
        uint32_t(*get_stream_frame_counter)(void);     ///< 영상 프레임 카운터 (정지 감지)
        uint16_t(*get_stream_resolution)(void);        ///< 현재 스트리밍 해상도
        uint8_t(*get_stream_codec_id)(void);          ///< 현재 코덱 ID
        bool     (*get_tamper_case)(void);              ///< 케이스 개봉 GPIO
        bool     (*get_tamper_cable)(void);             ///< 케이블 연결 GPIO
        uint16_t(*get_lens_brightness)(void);          ///< 렌즈 밝기 (Q8, 가림 감지)
        uint16_t(*get_accel_magnitude)(void);          ///< 가속도 크기 (Q8, 방향 변경)
        uint32_t(*get_login_fail_count)(void);         ///< 로그인 실패 누적 횟수
        uint32_t(*get_active_connections)(void);       ///< 현재 네트워크 접속 수
    };

    // ============================================================
    //  스트림 인증 콜백
    // ============================================================

    /// @brief 영상 스트림 HMAC 인증 콜백
    /// @note  카메라 SoC가 출력하는 영상 프레임에 HMAC 태그를 부착/검증.
    ///        보안 칩이 HMAC 키를 보유하고 검증 수행.
    struct CCTV_Auth_Callbacks {
        /// @brief 스트림 프레임의 HMAC 태그 검증
        /// @param frame_hash  카메라 SoC가 전달한 프레임 해시 (32B)
        /// @param hmac_tag    카메라 SoC가 생성한 HMAC 태그 (4B 절단)
        /// @return HMAC 검증 성공 시 true
        bool (*verify_stream_hmac)(const uint8_t* frame_hash, const uint8_t* hmac_tag);

        /// @brief 스트림 시퀀스 번호 조회 (replay 감지)
        uint32_t(*get_stream_sequence)(void);
    };

    // ============================================================
    //  CCTV 보안 CFI 상태
    // ============================================================

    /// @brief CCTV 보안 상태 (비트마스크, CFI 검증)
    enum class CCTV_SecState : uint8_t {
        OFFLINE = 0x00u,    ///< 미초기화
        MONITORING = 0x01u,    ///< 정상 감시 중
        ALERT = 0x02u,    ///< 경고 발생 (감시 유지)
        LOCKDOWN = 0x04u,    ///< 비상 잠금 (위험 이벤트, 제한 운용)
        ERROR = 0x08u     ///< 자체 오류
    };

    static constexpr uint8_t CCTV_SEC_VALID_STATE_MASK =
        static_cast<uint8_t>(CCTV_SecState::MONITORING)
        | static_cast<uint8_t>(CCTV_SecState::ALERT)
        | static_cast<uint8_t>(CCTV_SecState::LOCKDOWN)
        | static_cast<uint8_t>(CCTV_SecState::ERROR);

    inline bool CCTV_Sec_Is_Valid_State(CCTV_SecState s) noexcept
    {
        const uint8_t v = static_cast<uint8_t>(s);
        if (v == 0u) { return true; }
        if ((v & ~CCTV_SEC_VALID_STATE_MASK) != 0u) { return false; }
        return ((v & (v - 1u)) == 0u);
    }

    /// @note  OFFLINE->MONITORING, MONITORING->ALERT|LOCKDOWN|OFFLINE,
    ///        ALERT->MONITORING|LOCKDOWN|ERROR|OFFLINE,
    ///        LOCKDOWN->MONITORING|ALERT|ERROR|OFFLINE,
    ///        ERROR->MONITORING|OFFLINE
    ///
    /// [BUG-FIX FATAL] CFI 전이 규칙 2건 교정:
    ///  (1) k_legal: | OFFLINE(0x00) 무효 연산 제거 (비트OR 0 = 무의미)
    ///  (2) to==OFFLINE 예외 분기: MONITORING+ERROR만 → 모든 활성 상태(from!=0)
    ///      → ALERT/LOCKDOWN에서 Shutdown() 호출 시 CFI Violation 방지
    inline bool CCTV_Sec_Is_Legal_Transition(CCTV_SecState from, CCTV_SecState to) noexcept
    {
        if (!CCTV_Sec_Is_Valid_State(to)) { return false; }

        static constexpr uint8_t k_legal[5] = {
            /* OFFLINE    -> */ static_cast<uint8_t>(CCTV_SecState::MONITORING),
            /* MONITORING -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(CCTV_SecState::ALERT)
              | static_cast<uint8_t>(CCTV_SecState::LOCKDOWN)),
            /* ALERT      -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(CCTV_SecState::MONITORING)
              | static_cast<uint8_t>(CCTV_SecState::LOCKDOWN)
              | static_cast<uint8_t>(CCTV_SecState::ERROR)),
            /* LOCKDOWN   -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(CCTV_SecState::MONITORING)
              | static_cast<uint8_t>(CCTV_SecState::ALERT)
              | static_cast<uint8_t>(CCTV_SecState::ERROR)),
            /* ERROR      -> */ static_cast<uint8_t>(CCTV_SecState::MONITORING)
        };

        uint8_t idx;
        switch (from) {
        case CCTV_SecState::OFFLINE:    idx = 0u; break;
        case CCTV_SecState::MONITORING: idx = 1u; break;
        case CCTV_SecState::ALERT:      idx = 2u; break;
        case CCTV_SecState::LOCKDOWN:   idx = 3u; break;
        case CCTV_SecState::ERROR:      idx = 4u; break;
        default:                        return false;
        }

        //  기존: k_off_src = MONITORING|ERROR → ALERT/LOCKDOWN에서 Shutdown 불가!
        //  수정: from != OFFLINE (0u) → 켜져있는 모든 상태에서 끄기 허용
        if (static_cast<uint8_t>(to) == 0u) {
            return (static_cast<uint8_t>(from) != 0u);
        }

        return (k_legal[idx] & static_cast<uint8_t>(to)) != 0u;
    }

} // namespace ProtectedEngine
