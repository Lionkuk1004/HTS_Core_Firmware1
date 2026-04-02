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

/// @file  HTS_IoT_Codec_Defs.h
/// @brief HTS IoT 코덱 공통 정의부
/// @details
///   범용 센서/액추에이터 데이터를 B-CDMA 페이로드에 직렬화/역직렬화하기 위한
///   TLV(Type-Length-Value) 코덱 상수, 센서 타입 레지스트리, 데이터 구조를 정의한다.
///
///   TLV 프레임 구조:
///   @code
///   [MSG_TYPE(1)][DEVICE_ID(4)][TIMESTAMP(4)][TLV_COUNT(1)][TLV_0][TLV_1]...[CRC16(2)]
///   MSG_TYPE: 0x01=센서보고, 0x02=액추에이터명령, 0x03=이벤트알림
///   TLV: [SENSOR_TYPE(1)][LENGTH(1)][VALUE(1~8)]
///   @endcode
///
///   설계 기준:
///   - Cortex-M4F 양산 + ASIC ROM 합성
///   - 최대 페이로드 256바이트 이내 (IPC_MAX_PAYLOAD)
///   - Q16/Q8 고정소수점, float/double 금지, 힙 0, 나눗셈 0
///   - 엔디안 독립 직렬화 (빅엔디안 와이어)
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    // ============================================================
    //  메시지 타입
    // ============================================================

    /// @brief IoT 코덱 메시지 타입
    enum class IoT_MsgType : uint8_t {
        SENSOR_REPORT = 0x01u,    ///< 센서 데이터 보고 (주기적)
        ACTUATOR_CMD = 0x02u,    ///< 액추에이터 제어 명령
        EVENT_NOTIFY = 0x03u,    ///< 이벤트 알림 (임계값 초과 등)
        SENSOR_CONFIG = 0x04u,    ///< 센서 설정 변경
        HEARTBEAT = 0x05u     ///< IoT 디바이스 하트비트
    };

    // ============================================================
    //  센서 타입 레지스트리
    // ============================================================

    /// @brief 센서/액추에이터 타입 식별자
    /// @note  각 센서 타입은 고정 값 크기를 가진다.
    ///        constexpr 크기 테이블로 파싱 시 동적 판단 불필요.
    ///        ASIC: 8비트 디코더 ROM -> 값 크기 조회.
    enum class SensorType : uint8_t {
        // --- 환경 센서 (0x01~0x1F) ---
        TEMPERATURE = 0x01u,    ///< 온도 (Q8 섭씨, int16_t)
        HUMIDITY = 0x02u,    ///< 습도 (Q8 %RH, uint16_t)
        PRESSURE = 0x03u,    ///< 기압 (Q8 hPa, uint32_t)
        WIND_SPEED = 0x04u,    ///< 풍속 (Q8 m/s, uint16_t)
        WIND_DIRECTION = 0x05u,    ///< 풍향 (도, uint16_t, 0~359)
        RAINFALL = 0x06u,    ///< 강수량 (Q8 mm, uint16_t)
        UV_INDEX = 0x07u,    ///< 자외선 지수 (uint8_t)
        AIR_QUALITY = 0x08u,    ///< 대기질 PM2.5 (ug/m3, uint16_t)
        CO2_LEVEL = 0x09u,    ///< CO2 농도 (ppm, uint16_t)
        NOISE_LEVEL = 0x0Au,    ///< 소음 (Q8 dB, uint16_t)

        // --- 전력/에너지 (0x20~0x2F) ---
        VOLTAGE = 0x20u,    ///< 전압 (Q8 V, uint16_t)
        CURRENT = 0x21u,    ///< 전류 (Q8 A, uint16_t)
        POWER = 0x22u,    ///< 전력 (Q8 W, uint32_t)
        ENERGY_WH = 0x23u,    ///< 적산 전력량 (Wh, uint32_t)
        POWER_FACTOR = 0x24u,    ///< 역률 (Q16, uint16_t)
        FREQUENCY = 0x25u,    ///< 주파수 (Q8 Hz, uint16_t)

        // --- 위치/움직임 (0x30~0x3F) ---
        GPS_LATITUDE = 0x30u,    ///< 위도 (Q16 도, int32_t)
        GPS_LONGITUDE = 0x31u,    ///< 경도 (Q16 도, int32_t)
        ACCELERATION_X = 0x32u,    ///< X축 가속도 (Q8 m/s2, int16_t)
        ACCELERATION_Y = 0x33u,    ///< Y축 가속도
        ACCELERATION_Z = 0x34u,    ///< Z축 가속도
        MOTION_DETECT = 0x35u,    ///< 동작 감지 (0/1, uint8_t)

        // --- 산업/제어 (0x40~0x4F) ---
        VALVE_STATE = 0x40u,    ///< 밸브 상태 (0=닫힘/1=열림, uint8_t)
        RELAY_STATE = 0x41u,    ///< 릴레이 상태 (비트맵 8ch, uint8_t)
        ANALOG_INPUT = 0x42u,    ///< 아날로그 입력 (Q16, uint16_t)
        ANALOG_OUTPUT = 0x43u,    ///< 아날로그 출력 (Q16, uint16_t)
        DIGITAL_INPUT = 0x44u,    ///< 디지털 입력 (비트맵, uint8_t)
        DIGITAL_OUTPUT = 0x45u,    ///< 디지털 출력 (비트맵, uint8_t)
        COUNTER_32 = 0x46u,    ///< 32비트 카운터 (uint32_t)

        // --- 상태/진단 (0x60~0x6F) ---
        BATTERY_LEVEL = 0x60u,    ///< 배터리 잔량 (%, uint8_t)
        RSSI = 0x61u,    ///< 수신 신호 강도 (Q8 dBm, int16_t)
        ERROR_CODE = 0x62u,    ///< 에러 코드 (uint16_t)
        UPTIME = 0x63u     ///< 가동 시간 (초, uint32_t)
    };

    // ============================================================
    //  센서 타입별 값 크기 테이블 (constexpr ROM)
    // ============================================================

    /// @brief 센서 타입 -> 값 바이트 크기 조회
    /// @param t  센서 타입
    /// @return 값 크기 (바이트), 알 수 없는 타입이면 0
    /// @note  ASIC: switch -> 조합논리 디코더. 분기가 아닌 병렬 비교.
    ///        Cortex-M4: 컴파일러가 점프 테이블 또는 if-chain으로 최적화.
    inline uint8_t IoT_Sensor_Value_Size(SensorType t) noexcept
    {
        switch (t) {
            // 1-byte
        case SensorType::UV_INDEX:
        case SensorType::MOTION_DETECT:
        case SensorType::VALVE_STATE:
        case SensorType::RELAY_STATE:
        case SensorType::DIGITAL_INPUT:
        case SensorType::DIGITAL_OUTPUT:
        case SensorType::BATTERY_LEVEL:
            return 1u;

            // 2-byte
        case SensorType::TEMPERATURE:
        case SensorType::HUMIDITY:
        case SensorType::WIND_SPEED:
        case SensorType::WIND_DIRECTION:
        case SensorType::RAINFALL:
        case SensorType::AIR_QUALITY:
        case SensorType::CO2_LEVEL:
        case SensorType::NOISE_LEVEL:
        case SensorType::VOLTAGE:
        case SensorType::CURRENT:
        case SensorType::POWER_FACTOR:
        case SensorType::FREQUENCY:
        case SensorType::ACCELERATION_X:
        case SensorType::ACCELERATION_Y:
        case SensorType::ACCELERATION_Z:
        case SensorType::ANALOG_INPUT:
        case SensorType::ANALOG_OUTPUT:
        case SensorType::RSSI:
        case SensorType::ERROR_CODE:
            return 2u;

            // 4-byte
        case SensorType::PRESSURE:
        case SensorType::POWER:
        case SensorType::ENERGY_WH:
        case SensorType::GPS_LATITUDE:
        case SensorType::GPS_LONGITUDE:
        case SensorType::COUNTER_32:
        case SensorType::UPTIME:
            return 4u;

        default:
            return 0u;
        }
    }

    // ============================================================
    //  IoT 프레임 상수
    // ============================================================

    /// IoT 프레임 헤더 크기: MSG_TYPE(1) + DEVICE_ID(4) + TIMESTAMP(4) + TLV_COUNT(1) = 10
    static constexpr uint32_t IOT_FRAME_HEADER_SIZE = 10u;
    /// IoT 프레임 CRC 크기
    static constexpr uint32_t IOT_FRAME_CRC_SIZE = 2u;
    /// TLV 헤더 크기: SENSOR_TYPE(1) + LENGTH(1) = 2
    static constexpr uint32_t IOT_TLV_HEADER_SIZE = 2u;
    /// TLV 최대 값 크기 (GPS int32 = 4, 향후 확장 예비 8)
    static constexpr uint32_t IOT_TLV_MAX_VALUE_SIZE = 8u;
    /// 프레임당 최대 TLV 항목 수 (256B 페이로드 제한)
    static constexpr uint32_t IOT_MAX_TLV_COUNT = 32u;
    /// 최대 IoT 프레임 크기 (IPC 페이로드 이내)
    static constexpr uint32_t IOT_MAX_FRAME_SIZE = 256u;

    // ============================================================
    //  IoT TLV 항목 구조체
    // ============================================================

    /// @brief 단일 센서 TLV 항목 (메모리 내 표현)
    struct IoT_TLV_Item {
        SensorType sensor_type;                         ///< 센서 타입
        uint8_t    value_len;                           ///< 값 길이 (바이트)
        uint8_t    value[IOT_TLV_MAX_VALUE_SIZE];       ///< 값 바이트 (빅엔디안)
        uint8_t    padding[2];                          ///< 4바이트 정렬
    };
    static_assert(sizeof(IoT_TLV_Item) == 12u, "IoT_TLV_Item must be 12 bytes");
    static_assert((sizeof(IoT_TLV_Item) & 3u) == 0u, "IoT_TLV_Item must be 4-byte aligned");

    /// @brief IoT 프레임 헤더 (메모리 내 표현)
    struct IoT_Frame_Header {
        IoT_MsgType msg_type;       ///< 메시지 타입
        uint8_t     reserved;       ///< 정렬 패딩
        uint8_t     tlv_count;      ///< TLV 항목 수
        uint8_t     pad_;           ///< 정렬
        uint32_t    device_id;      ///< 디바이스 고유 ID
        uint32_t    timestamp_sec;  ///< 타임스탬프 (에포크 초 또는 가동 초)
    };
    static_assert(sizeof(IoT_Frame_Header) == 12u, "IoT_Frame_Header must be 12 bytes");

} // namespace ProtectedEngine