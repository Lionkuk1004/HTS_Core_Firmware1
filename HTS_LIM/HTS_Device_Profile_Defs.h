#pragma once
/// @file  HTS_Device_Profile_Defs.h
/// @brief HTS 디바이스 프로파일 공통 정의부
/// @details
///   HTS B-CDMA 범용 보안통신 칩의 6종 운용 시나리오별 프리셋 테이블,
///   주변장치 활성화 비트맵, 모드 전환 CFI 상태를 정의한다.
///
///   운용 시나리오 (하나의 펌웨어로 설정만으로 전환):
///   - 재난안전망 센서 게이트웨이: 측정 센서 -> B-CDMA, KT 재난안전망 연동
///   - 국가지점번호 스마트 안내판: 음성(보코더)+텍스트, BLE/NFC 연결
///   - AMI 전력량계: DLMS/COSEM, 전력/전압/전류/역률 보고
///   - CCTV 보안 감시: 저해상도 영상(9600bps), 이벤트 스냅샷
///   - 산업용 IoT: Modbus RTU/TCP 게이트웨이, 공장 센서/액추에이터
///   - 유선-무선 변환 콘솔: Ethernet <-> B-CDMA 브릿지
///
///   설계 기준:
///   - Cortex-M4F (168MHz) 양산 + ASIC ROM 합성 기준
///   - constexpr 프리셋 테이블 6 x 24B = 144B Flash ROM
///   - float/double 금지, 힙 할당 금지, 나눗셈 금지
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_Console_Manager_Defs.h"
#include <cstdint>

namespace ProtectedEngine {

    // ============================================================
    //  주변장치 활성화 비트맵
    // ============================================================

    /// @brief 주변장치 활성화 플래그 (비트마스크)
    /// @note  모드 전환 시 해당 모드에 필요한 주변장치만 활성화.
    ///        ASIC: 8비트 디코더 -> 주변장치 enable 신호 MUX.
    namespace PeriphBit {
        static constexpr uint8_t UART_SENSOR = (1u << 0u);   ///< 센서 UART (RS-485/232)
        static constexpr uint8_t SPI_RF = (1u << 1u);   ///< RF 트랜시버 SPI
        static constexpr uint8_t I2C_SENSOR = (1u << 2u);   ///< I2C 센서 버스
        static constexpr uint8_t BLE_NFC = (1u << 3u);   ///< BLE/NFC 모듈
        static constexpr uint8_t VOCODER = (1u << 4u);   ///< 음성 보코더
        static constexpr uint8_t ETHERNET = (1u << 5u);   ///< Ethernet MAC/PHY
        static constexpr uint8_t MODBUS = (1u << 6u);   ///< Modbus RTU/TCP
        static constexpr uint8_t CCTV_CAM = (1u << 7u);   ///< CCTV 카메라 인터페이스
    }  // namespace PeriphBit

    // ============================================================
    //  모드별 프리셋 구조체
    // ============================================================

    /// @brief 단일 운용 모드의 완전 프리셋 (constexpr ROM 항목)
    /// @note  ChannelConfig(24B) + 주변장치 비트맵(1B) + 패딩(3B) = 28B.
    ///        ASIC: 6 x 28B = 168B ROM 블록.
    struct DevicePreset {
        ChannelConfig  channel;             ///< 채널/RF/보안 설정
        uint8_t        periph_enable_mask;  ///< 주변장치 활성화 비트맵
        uint8_t        max_payload_bytes;   ///< 모드별 최대 페이로드 (바이트)
        uint8_t        max_retx;            ///< 최대 HARQ 재전송 횟수
        uint8_t        reserved;            ///< 정렬 패딩
    };
    static_assert(sizeof(DevicePreset) == 28u, "DevicePreset must be 28 bytes");
    static_assert((sizeof(DevicePreset) & 3u) == 0u, "DevicePreset must be 4-byte aligned");

    // ============================================================
    //  6종 운용 시나리오 프리셋 테이블 (constexpr ROM)
    // ============================================================

    /// @brief 모드별 프리셋 테이블 (DeviceMode 인덱싱)
    /// @note  ASIC: 168B ROM. 모드 전환 시 테이블 참조만으로 전체 설정 로드.
    ///        인덱스 = static_cast<uint8_t>(DeviceMode).
    static constexpr DevicePreset k_device_presets[6] = {

        // [0] SENSOR_GATEWAY: 재난안전망 센서 게이트웨이
        //     100~2400bps 자동, 64칩 확산, HARQ, ARIA, KT 연동
        {
            {   // ChannelConfig
                BpsLevel::AUTO,
                DeviceMode::SENSOR_GATEWAY,
                64u,            // spread_chips
                1u,             // fec_mode = HARQ
                1u,             // ajc_enable
                0u,             // crypto_algo = ARIA
                0u,             // bridge_enable
                0u,             // reserved
                400000u,        // rf_frequency_khz = 400 MHz
                static_cast<uint16_t>(20u << 8u),  // rf_tx_power_q8 = 20.0 dBm
                2000u,          // ajc_threshold
                3600u,          // key_rotation_sec = 1h
                300u            // session_timeout_sec = 5min
            },
            PeriphBit::UART_SENSOR | PeriphBit::SPI_RF | PeriphBit::I2C_SENSOR,  // periph
            64u,    // max_payload_bytes (센서 데이터 소형)
            3u,     // max_retx
            0u      // reserved
        },

        // [1] SMART_SIGNAGE: 국가지점번호 스마트 안내판
        //     2400~4800bps, 음성+텍스트, BLE/NFC, 보코더
        {
            {
                BpsLevel::BPS_2400,
                DeviceMode::SMART_SIGNAGE,
                16u,            // spread_chips (중거리)
                1u,             // fec_mode = HARQ
                1u,             // ajc_enable
                0u,             // crypto_algo = ARIA
                0u,             // bridge_enable
                0u,
                400000u,
                static_cast<uint16_t>(15u << 8u),  // 15.0 dBm
                1500u,
                1800u,          // key_rotation = 30min
                600u            // session_timeout = 10min
            },
            PeriphBit::SPI_RF | PeriphBit::BLE_NFC | PeriphBit::VOCODER,
            128u,   // max_payload (음성 패킷)
            2u,
            0u
        },

        // [2] AMI_METER: AMI 전력량계
        //     1200bps 고정, 64칩, DLMS/COSEM, 저전력
        {
            {
                BpsLevel::BPS_1200,
                DeviceMode::AMI_METER,
                64u,
                1u,             // HARQ
                1u,
                1u,             // crypto_algo = LEA (경량)
                0u,
                0u,
                400000u,
                static_cast<uint16_t>(10u << 8u),  // 10.0 dBm (저전력)
                1000u,
                7200u,          // key_rotation = 2h
                900u            // session_timeout = 15min
            },
            PeriphBit::UART_SENSOR | PeriphBit::SPI_RF,
            48u,    // max_payload (DLMS APDU 소형)
            5u,     // max_retx (높은 신뢰도)
            0u
        },

        // [3] CCTV_SECURITY: CCTV 보안 감시
        //     9600bps 고정, 1칩(최고속), 저해상도 영상/스냅샷
        {
            {
                BpsLevel::BPS_9600,
                DeviceMode::CCTV_SECURITY,
                1u,             // spread_chips = 1 (최고속, 낮은 항재밍)
                2u,             // fec_mode = 3D-Tensor
                0u,             // ajc_enable = off (속도 우선)
                0u,             // ARIA
                0u,
                0u,
                400000u,
                static_cast<uint16_t>(20u << 8u),
                500u,
                1800u,
                120u            // session_timeout = 2min (영상 세션)
            },
            PeriphBit::SPI_RF | PeriphBit::CCTV_CAM | PeriphBit::ETHERNET,
            255u,   // max_payload (영상 프레임 최대)
            1u,     // max_retx (실시간 우선)
            0u
        },

        // [4] INDUSTRIAL_IOT: 산업용 IoT Modbus 게이트웨이
        //     2400bps, 64칩, Modbus RTU/TCP, 공장 센서/액추에이터
        {
            {
                BpsLevel::BPS_2400,
                DeviceMode::INDUSTRIAL_IOT,
                64u,
                1u,             // HARQ
                1u,
                0u,             // ARIA
                0u,
                0u,
                400000u,
                static_cast<uint16_t>(20u << 8u),
                2000u,
                3600u,
                600u
            },
            PeriphBit::UART_SENSOR | PeriphBit::SPI_RF | PeriphBit::MODBUS,
            128u,   // max_payload (Modbus PDU)
            3u,
            0u
        },

        // [5] ETHERNET_BRIDGE: 유선-무선 변환 콘솔
        //     4800~9600bps 자동, 이더넷 브릿지, 최대 처리량
        {
            {
                BpsLevel::AUTO,
                DeviceMode::ETHERNET_BRIDGE,
                16u,            // spread_chips (속도 우선)
                2u,             // 3D-Tensor FEC
                1u,
                0u,             // ARIA
                1u,             // bridge_enable = ON
                0u,
                400000u,
                static_cast<uint16_t>(20u << 8u),
                2000u,
                1800u,
                300u
            },
            PeriphBit::SPI_RF | PeriphBit::ETHERNET,
            255u,   // max_payload (이더넷 프레임 분할)
            2u,
            0u
        }
    };
    static_assert(sizeof(k_device_presets) == 168u, "Preset table must be 168 bytes");

    // ============================================================
    //  프로파일 전환 CFI 상태
    // ============================================================

    /// @brief 프로파일 전환 상태 (비트마스크, CFI 검증용)
    enum class ProfileState : uint8_t {
        UNCONFIGURED = 0x00u,    ///< 미설정
        ACTIVE = 0x01u,    ///< 정상 운용 중
        SWITCHING = 0x02u,    ///< 모드 전환 처리 중
        ERROR = 0x04u     ///< 전환 실패/오류
    };

    /// 유효한 ProfileState 값의 비트 합집합 (단일 비트 전용)
    /// @note  UNCONFIGURED(0x00)은 전이 대상 시 별도 처리(초기화 경로만 허용).
    ///        다중 비트 글리치 값(0x03, 0x07, 0xFF 등) 거부.
    static constexpr uint8_t PROFILE_VALID_STATE_MASK =
        static_cast<uint8_t>(ProfileState::ACTIVE)
        | static_cast<uint8_t>(ProfileState::SWITCHING)
        | static_cast<uint8_t>(ProfileState::ERROR);
    // = 0x01 | 0x02 | 0x04 = 0x07

    /// @brief ProfileState가 정확히 하나의 정의된 값인지 검증
    /// @param s  검증할 상태
    /// @return 유효한 단일 상태이면 true
    /// @note  UNCONFIGURED(0x00)도 유효한 상태로 인정 (초기 상태).
    ///        다중 비트 글리치(0x03, 0x07, 0xFF) 거부.
    ///        Cortex-M4: AND 2회, 분기 0회. ASIC: 조합논리.
    inline bool Profile_Is_Valid_State(ProfileState s) noexcept
    {
        const uint8_t v = static_cast<uint8_t>(s);
        // UNCONFIGURED(0x00) is a valid state (initial)
        if (v == 0u) { return true; }
        // All bits must be within valid mask
        if ((v & ~PROFILE_VALID_STATE_MASK) != 0u) { return false; }
        // Exactly one bit set (power-of-2, non-zero)
        return ((v & (v - 1u)) == 0u);
    }

    /// @brief CFI 검증된 프로파일 상태 전이 검사
    /// @param from 현재 상태
    /// @param to   목표 상태
    /// @return 전이가 합법이면 true
    /// @note  합법 전이 테이블:
    ///        UNCONFIGURED -> SWITCHING (최초 모드 설정)
    ///        ACTIVE       -> SWITCHING (모드 변경)
    ///        SWITCHING    -> ACTIVE    (전환 성공)
    ///        SWITCHING    -> ERROR     (전환 실패)
    ///        ERROR        -> SWITCHING (복구 시도) -- 의도적 허용
    ///        ERROR        -> UNCONFIGURED (완전 리셋)
    ///
    ///        금지 전이 (글리치/공격 차단):
    ///        ERROR -> ACTIVE (검증 우회 금지! 반드시 SWITCHING 거쳐야 함)
    ///        ACTIVE -> ACTIVE (무의미 자기 전이 금지)
    ///        SWITCHING -> UNCONFIGURED (전환 중 리셋 금지)
    ///
    ///        ASIC: 4-entry ROM + 조합논리 검증, 합성 가능.
    inline bool Profile_Is_Legal_Transition(ProfileState from, ProfileState to) noexcept
    {
        // Gate 1: 'to' must be a valid single state
        if (!Profile_Is_Valid_State(to)) { return false; }

        // Gate 2: legal target bitmask per source state
        // Index: UNCONFIGURED=0, ACTIVE=1, SWITCHING=2, ERROR=3
        static constexpr uint8_t k_legal_targets[4] = {
            /* UNCONFIGURED -> */ static_cast<uint8_t>(ProfileState::SWITCHING),
            /* ACTIVE       -> */ static_cast<uint8_t>(ProfileState::SWITCHING),
            /* SWITCHING    -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(ProfileState::ACTIVE)
              | static_cast<uint8_t>(ProfileState::ERROR)),
            /* ERROR        -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(ProfileState::SWITCHING)
              | static_cast<uint8_t>(ProfileState::UNCONFIGURED))
        };

        uint8_t idx;
        switch (from) {
        case ProfileState::UNCONFIGURED: idx = 0u; break;
        case ProfileState::ACTIVE:       idx = 1u; break;
        case ProfileState::SWITCHING:    idx = 2u; break;
        case ProfileState::ERROR:        idx = 3u; break;
        default:                         return false;
        }

        // UNCONFIGURED(0x00) as target: only allowed from ERROR(0x04)
        if (static_cast<uint8_t>(to) == 0u) {
            return (static_cast<uint8_t>(from) & static_cast<uint8_t>(ProfileState::ERROR)) != 0u;
        }

        return (k_legal_targets[idx] & static_cast<uint8_t>(to)) != 0u;
    }
    // ============================================================
    //  주변장치 활성화 콜백 (외부 HAL 연결)
    // ============================================================

    /// @brief 주변장치 제어 콜백 (모드 전환 시 HAL 호출)
    /// @note  ASIC: 함수 포인터 -> 하드와이어 enable 신호 MUX.
    ///        각 콜백은 nullptr이면 해당 주변장치 무시.
    struct PeriphCallbacks {
        void (*enable_uart_sensor)(bool on);    ///< 센서 UART 활성화/비활성화
        void (*enable_spi_rf)(bool on);         ///< RF SPI 활성화/비활성화
        void (*enable_i2c_sensor)(bool on);     ///< I2C 센서 활성화/비활성화
        void (*enable_ble_nfc)(bool on);        ///< BLE/NFC 활성화/비활성화
        void (*enable_vocoder)(bool on);        ///< 보코더 활성화/비활성화
        void (*enable_ethernet)(bool on);       ///< 이더넷 활성화/비활성화
        void (*enable_modbus)(bool on);         ///< Modbus 활성화/비활성화
        void (*enable_cctv_cam)(bool on);       ///< CCTV 카메라 활성화/비활성화
    };

} // namespace ProtectedEngine