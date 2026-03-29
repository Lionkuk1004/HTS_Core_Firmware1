#pragma once
/// @file  HTS_BLE_NFC_Gateway_Defs.h
/// @brief HTS BLE/NFC 게이트웨이 공통 정의부
/// @details
///   국가지점번호 스마트 안내판용 BLE/NFC 게이트웨이.
///   사용자 스마트폰과 BLE(Bluetooth Low Energy) 또는 NFC(Near Field
///   Communication)로 연결하여 텍스트/음성/위치 데이터를 B-CDMA 망으로 중계.
///
///   메시지 프레임 (B-CDMA 페이로드 내):
///   @code
///   [MSG_TYPE(1)][SESSION_ID(2)][LOCATION_CODE(4)][PAYLOAD_LEN(1)][PAYLOAD(N)][CRC16(2)]
///   @endcode
///
///   설계 기준:
///   - Cortex-M4F 양산 + ASIC ROM 합성
///   - BLE/NFC 모듈: UART AT 명령 (115200bps)
///   - 최대 페이로드 128바이트 (SMART_SIGNAGE 프리셋)
///   - 힙 0, float/double 0, 나눗셈 0
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    // ============================================================
    //  메시지 타입
    // ============================================================

    /// @brief BLE/NFC 게이트웨이 메시지 타입
    enum class BLE_MsgType : uint8_t {
        TEXT_MESSAGE = 0x01u,    ///< 텍스트 메시지 (안내 문구)
        VOICE_TRIGGER = 0x02u,    ///< 음성 안내 트리거 (보코더 인덱스)
        LOCATION_QUERY = 0x03u,    ///< 위치 정보 요청 (국가지점번호)
        LOCATION_RESPONSE = 0x04u,    ///< 위치 정보 응답
        EMERGENCY_CALL = 0x05u,    ///< 긴급 호출 (119/112)
        DEVICE_INFO = 0x06u,    ///< 디바이스 정보 교환
        SESSION_OPEN = 0x07u,    ///< BLE/NFC 세션 개시
        SESSION_CLOSE = 0x08u,    ///< 세션 종료
        HEARTBEAT = 0x09u     ///< 연결 유지 핑
    };

    // ============================================================
    //  BLE/NFC 인터페이스 타입
    // ============================================================

    /// @brief 연결 인터페이스 종류
    enum class LinkType : uint8_t {
        NONE = 0x00u,    ///< 미연결
        BLE = 0x01u,    ///< BLE (Bluetooth Low Energy)
        NFC = 0x02u     ///< NFC (Near Field Communication)
    };

    // ============================================================
    //  국가지점번호 구조체
    // ============================================================

    /// @brief 국가지점번호 위치 코드 (4바이트 압축)
    /// @note  대한민국 국가지점번호: "가나 1234 5678" 형식.
    ///        2글자 한글 인덱스(12비트) + 숫자 8자리(BCD 32비트) 압축.
    ///        여기서는 uint32_t로 일괄 처리 (외부에서 인코딩).
    struct LocationCode {
        uint32_t code;      ///< 압축된 국가지점번호 (또는 GPS 그리드 ID)
    };
    static_assert(sizeof(LocationCode) == 4u, "LocationCode must be 4 bytes");

    // ============================================================
    //  게이트웨이 프레임 상수
    // ============================================================

    /// 프레임 헤더: MSG_TYPE(1) + SESSION_ID(2) + LOCATION_CODE(4) + PAYLOAD_LEN(1) = 8
    static constexpr uint32_t BLE_FRAME_HEADER_SIZE = 8u;
    /// CRC 후미
    static constexpr uint32_t BLE_FRAME_CRC_SIZE = 2u;
    /// 최대 페이로드 (SMART_SIGNAGE 프리셋 128B - 헤더 - CRC)
    static constexpr uint32_t BLE_MAX_PAYLOAD = 118u;
    /// 최대 프레임 크기
    static constexpr uint32_t BLE_MAX_FRAME_SIZE = BLE_FRAME_HEADER_SIZE + BLE_MAX_PAYLOAD + BLE_FRAME_CRC_SIZE;  ///< 128

    /// 세션 ID 마스크 (16비트 순환)
    static constexpr uint16_t BLE_SESSION_MASK = 0xFFFFu;

    /// 동시 접속 세션 수 (BLE 1 + NFC 1)
    static constexpr uint32_t BLE_MAX_SESSIONS = 2u;

    /// BLE/NFC UART 수신 버퍼 크기 (AT 응답 + 데이터)
    static constexpr uint32_t BLE_UART_RX_BUF_SIZE = 256u;

    /// 세션 타임아웃 (ms)
    static constexpr uint32_t BLE_SESSION_TIMEOUT = 30000u;  ///< 30초

    // ============================================================
    //  세션 구조체
    // ============================================================

    /// @brief 단일 BLE/NFC 세션
    struct BLE_Session {
        uint16_t     session_id;        ///< 세션 식별자
        LinkType     link_type;         ///< 연결 타입 (BLE/NFC)
        uint8_t      active;            ///< 활성 여부 (0/1)
        LocationCode location;          ///< 연결된 국가지점번호
        uint32_t     last_activity_tick; ///< 마지막 활동 시각 (ms)
    };
    static_assert(sizeof(BLE_Session) == 12u, "BLE_Session must be 12 bytes");
    static_assert((sizeof(BLE_Session) & 3u) == 0u, "BLE_Session must be 4-byte aligned");

    // ============================================================
    //  게이트웨이 CFI 상태
    // ============================================================

    /// @brief 게이트웨이 상태 (비트마스크, CFI 검증)
    enum class BLE_GW_State : uint8_t {
        OFFLINE = 0x00u,    ///< 미초기화
        IDLE = 0x01u,    ///< 대기 (모듈 활성, 세션 없음)
        CONNECTED = 0x02u,    ///< 세션 활성 (1개 이상 연결)
        TRANSFERRING = 0x04u,    ///< 데이터 전송 중
        ERROR = 0x08u     ///< 오류
    };

    static constexpr uint8_t BLE_GW_VALID_STATE_MASK =
        static_cast<uint8_t>(BLE_GW_State::IDLE)
        | static_cast<uint8_t>(BLE_GW_State::CONNECTED)
        | static_cast<uint8_t>(BLE_GW_State::TRANSFERRING)
        | static_cast<uint8_t>(BLE_GW_State::ERROR);

    inline bool BLE_GW_Is_Valid_State(BLE_GW_State s) noexcept
    {
        const uint8_t v = static_cast<uint8_t>(s);
        if (v == 0u) { return true; }
        if ((v & ~BLE_GW_VALID_STATE_MASK) != 0u) { return false; }
        return ((v & (v - 1u)) == 0u);
    }

    /// @brief CFI 전이 검사
    /// @note  OFFLINE->IDLE, IDLE->CONNECTED|OFFLINE,
    ///        CONNECTED->TRANSFERRING|IDLE|ERROR,
    ///        TRANSFERRING->CONNECTED|ERROR,
    ///        ERROR->IDLE|OFFLINE
    inline bool BLE_GW_Is_Legal_Transition(BLE_GW_State from, BLE_GW_State to) noexcept
    {
        if (!BLE_GW_Is_Valid_State(to)) { return false; }

        static constexpr uint8_t k_legal[5] = {
            /* OFFLINE      -> */ static_cast<uint8_t>(BLE_GW_State::IDLE),
            /* IDLE         -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(BLE_GW_State::CONNECTED)
              | static_cast<uint8_t>(BLE_GW_State::OFFLINE)),
            /* CONNECTED    -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(BLE_GW_State::TRANSFERRING)
              | static_cast<uint8_t>(BLE_GW_State::IDLE)
              | static_cast<uint8_t>(BLE_GW_State::ERROR)),
            /* TRANSFERRING -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(BLE_GW_State::CONNECTED)
              | static_cast<uint8_t>(BLE_GW_State::ERROR)),
            /* ERROR        -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(BLE_GW_State::IDLE)
              | static_cast<uint8_t>(BLE_GW_State::OFFLINE))
        };

        uint8_t idx;
        switch (from) {
        case BLE_GW_State::OFFLINE:      idx = 0u; break;
        case BLE_GW_State::IDLE:         idx = 1u; break;
        case BLE_GW_State::CONNECTED:    idx = 2u; break;
        case BLE_GW_State::TRANSFERRING: idx = 3u; break;
        case BLE_GW_State::ERROR:        idx = 4u; break;
        default:                         return false;
        }

        if (static_cast<uint8_t>(to) == 0u) {
            static constexpr uint8_t k_offline_src = static_cast<uint8_t>(
                static_cast<uint8_t>(BLE_GW_State::IDLE)
                | static_cast<uint8_t>(BLE_GW_State::ERROR));
            return (static_cast<uint8_t>(from) & k_offline_src) != 0u;
        }

        return (k_legal[idx] & static_cast<uint8_t>(to)) != 0u;
    }

} // namespace ProtectedEngine