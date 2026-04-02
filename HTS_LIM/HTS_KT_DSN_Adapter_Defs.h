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

/// @file  HTS_KT_DSN_Adapter_Defs.h
/// @brief HTS KT 재난안전망 어댑터 공통 정의부
/// @details
///   KT 재난안전망(DSN: Disaster Safety Network) CBS/CMAS 메시지를
///   B-CDMA 채널로 중계하기 위한 프로토콜 어댑터 정의부.
///
///   재난 메시지 프레임 (B-CDMA 페이로드):
///   @code
///   [MSG_TYPE(1)][DISASTER_CODE(2)][SEVERITY(1)][AREA_CODE(4)][TIMESTAMP(4)]
///   [PAYLOAD_LEN(1)][PAYLOAD(N)][CRC16(2)]
///   @endcode
///
///   설계 기준:
///   - KT CBS(Cell Broadcast Service) 호환 경량 프로파일
///   - 재난 시 자동 BPS 하향 (1200bps, 64칩 최대 확산)
///   - 힙 0, float/double 0, 나눗셈 0
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {
    static constexpr uint32_t DSN_SECURE_TRUE = 0x5A5A5A5Au;
    static constexpr uint32_t DSN_SECURE_FALSE = 0xA5A5A5A5u;

    // ============================================================
    //  재난 메시지 타입
    // ============================================================

    /// @brief 재난안전망 메시지 타입
    enum class DSN_MsgType : uint8_t {
        CBS_ALERT = 0x01u,    ///< CBS 재난 경보
        CBS_UPDATE = 0x02u,    ///< CBS 경보 갱신
        CBS_CANCEL = 0x03u,    ///< CBS 경보 해제
        CMAS_PRESIDENTIAL = 0x04u,    ///< CMAS 대통령 경보 (최고 우선)
        CMAS_EXTREME = 0x05u,    ///< CMAS 극심 위협
        CMAS_SEVERE = 0x06u,    ///< CMAS 심각 위협
        CMAS_AMBER = 0x07u,    ///< CMAS 아동 유괴 (AMBER)
        CMAS_TEST = 0x08u,    ///< CMAS 테스트
        HEARTBEAT = 0x09u,    ///< DSN 링크 하트비트
        STATUS_REPORT = 0x0Au     ///< 상태 보고 (정상/장애)
    };

    // ============================================================
    //  재난 유형 코드 (행정안전부 재난 분류)
    // ============================================================

    /// @brief 재난 유형 코드 (16비트, 행안부 분류 기반)
    /// @note  ASIC: 16비트 디코더. 상위 8비트=대분류, 하위 8비트=소분류.
    namespace DisasterCode {
        // --- 자연재난 (0x01xx) ---
        static constexpr uint16_t EARTHQUAKE = 0x0101u;  ///< 지진
        static constexpr uint16_t EARTHQUAKE_SEA = 0x0102u;  ///< 해저 지진/지진해일
        static constexpr uint16_t TYPHOON = 0x0103u;  ///< 태풍
        static constexpr uint16_t FLOOD = 0x0104u;  ///< 홍수
        static constexpr uint16_t HEAVY_RAIN = 0x0105u;  ///< 호우
        static constexpr uint16_t HEAVY_SNOW = 0x0106u;  ///< 대설
        static constexpr uint16_t TSUNAMI = 0x0107u;  ///< 쓰나미
        static constexpr uint16_t VOLCANIC = 0x0108u;  ///< 화산
        static constexpr uint16_t HEAT_WAVE = 0x0109u;  ///< 폭염
        static constexpr uint16_t COLD_WAVE = 0x010Au;  ///< 한파
        static constexpr uint16_t DROUGHT = 0x010Bu;  ///< 가뭄
        static constexpr uint16_t YELLOW_DUST = 0x010Cu;  ///< 황사
        static constexpr uint16_t FINE_DUST = 0x010Du;  ///< 미세먼지

        // --- 사회재난 (0x02xx) ---
        static constexpr uint16_t FIRE = 0x0201u;  ///< 화재
        static constexpr uint16_t EXPLOSION = 0x0202u;  ///< 폭발
        static constexpr uint16_t COLLAPSE = 0x0203u;  ///< 붕괴
        static constexpr uint16_t HAZMAT = 0x0204u;  ///< 유해물질 유출
        static constexpr uint16_t NUCLEAR = 0x0205u;  ///< 원자력 사고
        static constexpr uint16_t BLACKOUT = 0x0206u;  ///< 대규모 정전
        static constexpr uint16_t WATER_POLLUTION = 0x0207u;  ///< 수질 오염
        static constexpr uint16_t EPIDEMIC = 0x0208u;  ///< 감염병

        // --- 기타/안보 (0x03xx) ---
        static constexpr uint16_t MISSILE_ALERT = 0x0301u;  ///< 미사일 경보
        static constexpr uint16_t AIR_RAID = 0x0302u;  ///< 공습 경보
        static constexpr uint16_t CIVIL_DEFENSE = 0x0303u;  ///< 민방위 훈련
        static constexpr uint16_t MISSING_CHILD = 0x0304u;  ///< 실종 아동 (AMBER)
    }  // namespace DisasterCode

    // ============================================================
    //  재난 심각도
    // ============================================================

    /// @brief 재난 경보 심각도
    enum class DSN_Severity : uint8_t {
        INFO = 0x00u,    ///< 안내 (테스트, 훈련)
        ADVISORY = 0x01u,    ///< 주의보
        WARNING = 0x02u,    ///< 경보
        CRITICAL = 0x03u,    ///< 위급 (즉시 대피)
        PRESIDENTIAL = 0x04u    ///< 대통령 경보 (최고 우선)
    };

    // ============================================================
    //  재난 프레임 상수
    // ============================================================

    /// 재난 프레임 헤더: MSG(1)+DISASTER(2)+SEV(1)+AREA(4)+TIME(4)+LEN(1) = 13
    static constexpr uint32_t DSN_FRAME_HEADER_SIZE = 13u;
    /// CRC 후미
    static constexpr uint32_t DSN_FRAME_CRC_SIZE = 2u;
    /// 재난 메시지 텍스트 최대 크기
    static constexpr uint32_t DSN_MAX_TEXT_LEN = 96u;
    /// 최대 재난 프레임 크기
    static constexpr uint32_t DSN_MAX_FRAME_SIZE = DSN_FRAME_HEADER_SIZE + DSN_MAX_TEXT_LEN + DSN_FRAME_CRC_SIZE;

    /// 재난 경보 재전송 횟수 (높은 신뢰도)
    static constexpr uint32_t DSN_ALERT_RETRANSMIT = 3u;
    /// 재전송 간격 (ms) -- 무선 채널 플러딩 방지
    /// @note  30초 간격으로 재전송하여 시간대별 음영구역 단말 도달률 극대화.
    ///        3회 x 30초 = 초기 경보 후 90초에 걸쳐 분산 재전송.
    static constexpr uint32_t DSN_RETRANSMIT_INTERVAL = 30000u;  ///< 30초
    /// 하트비트 주기 (ms)
    static constexpr uint32_t DSN_HEARTBEAT_INTERVAL = 60000u;
    /// 재난 경보 유효 시간 (ms, 이후 자동 해제)
    static constexpr uint32_t DSN_ALERT_EXPIRY = 3600000u;  ///< 1시간

    /// 활성 경보 슬롯 수
    static constexpr uint32_t DSN_MAX_ACTIVE_ALERTS = 4u;

    // ============================================================
    //  행정구역 코드 (지역 매칭)
    // ============================================================

    /// @brief 행정구역 코드 (uint32_t, 행안부 표준)
    /// @note  상위 16비트: 시도 코드, 하위 16비트: 시군구 코드.
    ///        0xFFFFFFFF = 전국. 0x0000xxxx = 시도 전체.
    static constexpr uint32_t DSN_AREA_NATIONWIDE = 0xFFFFFFFFu;

    // ============================================================
    //  활성 경보 슬롯
    // ============================================================

    /// @brief 단일 활성 경보 항목
    struct DSN_ActiveAlert {
        uint16_t    disaster_code;          ///< 재난 유형
        DSN_Severity severity;              ///< 심각도
        uint8_t     retransmit_remain;      ///< 남은 재전송 횟수
        uint32_t    area_code;              ///< 대상 행정구역
        uint32_t    timestamp;              ///< 발령 시각 (에포크 초)
        uint32_t    received_tick;          ///< 수신 시스템 틱 (ms)
        uint32_t    last_retransmit_tick;   ///< 마지막 재전송 시각 (ms, 페이싱용)
        uint8_t     active;                 ///< 활성 여부 (0/1)
        uint8_t     pad_[3];               ///< 정렬
    };
    static_assert(sizeof(DSN_ActiveAlert) == 24u, "DSN_ActiveAlert must be 24 bytes");
    static_assert((sizeof(DSN_ActiveAlert) & 3u) == 0u, "DSN_ActiveAlert must be 4-byte aligned");

    // ============================================================
    //  DSN 수신 콜백
    // ============================================================

    /// @brief DSN 경보 수신 콜백 (KT 망 -> 본 모듈 -> 앱/디스플레이)
    struct DSN_Receive_Callbacks {
        /// @brief 재난 경보 수신 시 호출 (디스플레이/사이렌 구동)
        void (*on_alert)(DSN_MsgType type, uint16_t disaster_code,
            DSN_Severity severity, uint32_t area_code,
            const uint8_t* text, uint8_t text_len);
        /// @brief 재난 경보 해제 시 호출
        void (*on_cancel)(uint16_t disaster_code, uint32_t area_code);
    };

    /// @brief BPS/채널 오버라이드 콜백 (재난 시 자동 하향)
    struct DSN_Channel_Callbacks {
        void (*force_bps)(uint16_t bps);            ///< BPS 강제 설정 (재난 모드)
        void (*force_spread_chips)(uint8_t chips);  ///< 확산 칩 강제 (재난 모드)
        void (*restore_normal)(void);               ///< 정상 모드 복원
    };

    // ============================================================
    //  DSN CFI 상태
    // ============================================================

    /// @brief DSN 어댑터 상태 (비트마스크, CFI 검증)
    enum class DSN_State : uint8_t {
        OFFLINE = 0x00u,
        MONITORING = 0x01u,    ///< 정상 대기 (KT 링크 감시)
        ALERT_ACTIVE = 0x02u,    ///< 재난 경보 활성 (중계 중)
        RETRANSMITTING = 0x04u,    ///< 재전송 중
        ERROR = 0x08u
    };

    static constexpr uint8_t DSN_VALID_STATE_MASK =
        static_cast<uint8_t>(DSN_State::MONITORING)
        | static_cast<uint8_t>(DSN_State::ALERT_ACTIVE)
        | static_cast<uint8_t>(DSN_State::RETRANSMITTING)
        | static_cast<uint8_t>(DSN_State::ERROR);

    inline uint32_t DSN_Is_Valid_State(DSN_State s) noexcept
    {
        const uint8_t v = static_cast<uint8_t>(s);
        if (v == 0u) { return DSN_SECURE_TRUE; }
        if ((v & ~DSN_VALID_STATE_MASK) != 0u) { return DSN_SECURE_FALSE; }
        return (((v & (v - 1u)) == 0u) ? DSN_SECURE_TRUE : DSN_SECURE_FALSE);
    }

    inline uint32_t DSN_Is_Legal_Transition(DSN_State from, DSN_State to) noexcept
    {
        if (DSN_Is_Valid_State(to) != DSN_SECURE_TRUE) { return DSN_SECURE_FALSE; }

        static constexpr uint8_t k_legal[5] = {
            /* OFFLINE        -> */ static_cast<uint8_t>(DSN_State::MONITORING),
            /* MONITORING     -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(DSN_State::ALERT_ACTIVE)
              | static_cast<uint8_t>(DSN_State::OFFLINE)),
            /* ALERT_ACTIVE   -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(DSN_State::RETRANSMITTING)
              | static_cast<uint8_t>(DSN_State::MONITORING)
              | static_cast<uint8_t>(DSN_State::ERROR)),
            /* RETRANSMITTING -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(DSN_State::ALERT_ACTIVE)
              | static_cast<uint8_t>(DSN_State::MONITORING)
              | static_cast<uint8_t>(DSN_State::ERROR)),
            /* ERROR          -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(DSN_State::MONITORING)
              | static_cast<uint8_t>(DSN_State::OFFLINE))
        };

        uint8_t idx;
        switch (from) {
        case DSN_State::OFFLINE:        idx = 0u; break;
        case DSN_State::MONITORING:     idx = 1u; break;
        case DSN_State::ALERT_ACTIVE:   idx = 2u; break;
        case DSN_State::RETRANSMITTING: idx = 3u; break;
        case DSN_State::ERROR:          idx = 4u; break;
        default:                        return DSN_SECURE_FALSE;
        }

        if (static_cast<uint8_t>(to) == 0u) {
            static constexpr uint8_t k_off_src = static_cast<uint8_t>(
                static_cast<uint8_t>(DSN_State::MONITORING)
                | static_cast<uint8_t>(DSN_State::ERROR));
            return ((static_cast<uint8_t>(from) & k_off_src) != 0u) ? DSN_SECURE_TRUE : DSN_SECURE_FALSE;
        }

        return ((k_legal[idx] & static_cast<uint8_t>(to)) != 0u) ? DSN_SECURE_TRUE : DSN_SECURE_FALSE;
    }

} // namespace ProtectedEngine