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

/// @file  HTS_Modbus_Gateway_Defs.h
/// @brief HTS Modbus 게이트웨이 공통 정의부
/// @details
///   산업용 Modbus 디바이스를 B-CDMA 무선망으로 연결하는 프로토콜 변환
///   게이트웨이. RS-485/RS-232/RS-422/Modbus TCP/4-20mA 전체 지원.
///
///   물리 계층:
///   - RS-485: Modbus RTU 표준, 반이중 멀티드롭 32대, 1200m
///   - RS-232: 레거시 PLC/계측기, 포인트-투-포인트, 15m
///   - RS-422: 전이중 장거리, 1200m, 공장 노이즈 내성
///   - Modbus TCP: 이더넷 TCP/502, 최신 PLC/SCADA
///   - 4-20mA: 아날로그 센서 직결, ADC -> 레지스터 매핑
///
///   Modbus PDU 캡슐화 (B-CDMA 페이로드):
///   @code
///   [GW_CMD(1)][PHY_TYPE(1)][SLAVE_ADDR(1)][FUNC_CODE(1)][DATA_LEN(1)][DATA(N)][CRC16(2)]
///   @endcode
///
///   지원 Modbus 기능 코드:
///   - FC01: 코일 읽기 (Read Coils)
///   - FC02: 이산 입력 읽기 (Read Discrete Inputs)
///   - FC03: 보유 레지스터 읽기 (Read Holding Registers)
///   - FC04: 입력 레지스터 읽기 (Read Input Registers)
///   - FC05: 단일 코일 쓰기 (Write Single Coil)
///   - FC06: 단일 레지스터 쓰기 (Write Single Register)
///   - FC15: 다중 코일 쓰기 (Write Multiple Coils)
///   - FC16: 다중 레지스터 쓰기 (Write Multiple Registers)
///
///   설계 기준:
///   - Cortex-M4F 양산 + ASIC ROM 합성
///   - 힙 0, float/double 0, 나눗셈 0
///   - 물리 계층 추상화 (콜백 기반, 실행 시 교환 가능)
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {
    static constexpr uint32_t MODBUS_SECURE_TRUE = 0x5A5A5A5Au;
    static constexpr uint32_t MODBUS_SECURE_FALSE = 0xA5A5A5A5u;

    // ============================================================
    //  물리 계층 타입
    // ============================================================

    /// @brief Modbus 물리 계층 인터페이스 타입
    /// @note  하나의 게이트웨이에서 복수 포트 동시 운용 가능.
    ///        ASIC: 3비트 디코더 → PHY MUX 선택.
    enum class Modbus_PHY : uint8_t {
        RS485 = 0x01u,    ///< RS-485 반이중 (DE/RE 제어)
        RS232 = 0x02u,    ///< RS-232 전이중
        RS422 = 0x03u,    ///< RS-422 전이중 장거리
        TCP = 0x04u,    ///< Modbus TCP (이더넷 TCP/502)
        ANALOG_4_20 = 0x05u,    ///< 4-20mA 아날로그 (ADC 전용, 읽기만)
        PHY_COUNT = 0x06u     ///< 총 개수 (검증용)
    };

    // ============================================================
    //  게이트웨이 명령
    // ============================================================

    /// @brief 게이트웨이 캡슐화 명령 (B-CDMA <-> Modbus)
    enum class GW_Command : uint8_t {
        MODBUS_REQUEST = 0x01u,    ///< B-CDMA -> Modbus 요청
        MODBUS_RESPONSE = 0x02u,    ///< Modbus -> B-CDMA 응답
        MODBUS_EXCEPTION = 0x03u,    ///< Modbus 예외 응답
        POLL_CONFIG = 0x04u,    ///< 자동 폴링 설정
        POLL_REPORT = 0x05u,    ///< 자동 폴링 결과 보고
        PHY_STATUS = 0x06u,    ///< 물리 포트 상태 조회
        HEARTBEAT = 0x07u     ///< 링크 하트비트
    };

    // ============================================================
    //  Modbus 기능 코드
    // ============================================================

    /// @brief Modbus 표준 기능 코드 (IEC 61158)
    namespace ModbusFC {
        static constexpr uint8_t READ_COILS = 0x01u;
        static constexpr uint8_t READ_DISCRETE_INPUTS = 0x02u;
        static constexpr uint8_t READ_HOLDING_REGS = 0x03u;
        static constexpr uint8_t READ_INPUT_REGS = 0x04u;
        static constexpr uint8_t WRITE_SINGLE_COIL = 0x05u;
        static constexpr uint8_t WRITE_SINGLE_REG = 0x06u;
        static constexpr uint8_t WRITE_MULTIPLE_COILS = 0x0Fu;
        static constexpr uint8_t WRITE_MULTIPLE_REGS = 0x10u;
        static constexpr uint8_t EXCEPTION_FLAG = 0x80u;  ///< 응답 FC에 OR하면 예외
    }  // namespace ModbusFC

    inline uint32_t Modbus_Is_Supported_FC(uint8_t fc) noexcept
    {
        if (fc == ModbusFC::READ_COILS) { return MODBUS_SECURE_TRUE; }
        if (fc == ModbusFC::READ_DISCRETE_INPUTS) { return MODBUS_SECURE_TRUE; }
        if (fc == ModbusFC::READ_HOLDING_REGS) { return MODBUS_SECURE_TRUE; }
        if (fc == ModbusFC::READ_INPUT_REGS) { return MODBUS_SECURE_TRUE; }
        if (fc == ModbusFC::WRITE_SINGLE_COIL) { return MODBUS_SECURE_TRUE; }
        if (fc == ModbusFC::WRITE_SINGLE_REG) { return MODBUS_SECURE_TRUE; }
        if (fc == ModbusFC::WRITE_MULTIPLE_COILS) { return MODBUS_SECURE_TRUE; }
        if (fc == ModbusFC::WRITE_MULTIPLE_REGS) { return MODBUS_SECURE_TRUE; }
        return MODBUS_SECURE_FALSE;
    }

    // ============================================================
    //  Modbus 예외 코드
    // ============================================================

    /// @brief Modbus 예외 코드
    enum class Modbus_Exception : uint8_t {
        ILLEGAL_FUNCTION = 0x01u,
        ILLEGAL_ADDRESS = 0x02u,
        ILLEGAL_VALUE = 0x03u,
        SLAVE_FAILURE = 0x04u,
        ACKNOWLEDGE = 0x05u,
        SLAVE_BUSY = 0x06u,
        GATEWAY_FAIL = 0x0Au,
        GATEWAY_TARGET_FAIL = 0x0Bu
    };

    // ============================================================
    //  UART 설정 (RS-485/232/422 공통)
    // ============================================================

    /// @brief UART 통신 파라미터
    struct Modbus_UART_Config {
        uint32_t baudrate;      ///< 보레이트 (9600/19200/38400/57600/115200)
        uint8_t  data_bits;     ///< 데이터 비트 (7/8)
        uint8_t  parity;        ///< 패리티 (0=없음, 1=홀수, 2=짝수)
        uint8_t  stop_bits;     ///< 정지 비트 (1/2)
        uint8_t  pad_;          ///< 정렬
    };
    static_assert(sizeof(Modbus_UART_Config) == 8u, "Modbus_UART_Config must be 8 bytes");

    // ============================================================
    //  자동 폴링 설정
    // ============================================================

    /// @brief 자동 폴링 항목 (주기적 레지스터 읽기)
    /// @note  최대 8항목 동시 폴링. 각 항목은 독립 주기.
    struct Modbus_PollItem {
        uint8_t  slave_addr;        ///< 슬레이브 주소 (1~247)
        uint8_t  func_code;         ///< 기능 코드 (FC03/FC04)
        uint16_t start_reg;         ///< 시작 레지스터 주소
        uint16_t reg_count;         ///< 레지스터 수 (1~125)
        uint16_t interval_sec;      ///< 폴링 주기 (초, 0=비활성)
        uint32_t last_poll_tick;    ///< 마지막 폴링 시각 (ms)
        uint8_t  active;            ///< 활성 (0/1)
        uint8_t  phy_type;          ///< 물리 계층 (Modbus_PHY)
        uint8_t  pad_[2];           ///< 정렬
    };
    static_assert(sizeof(Modbus_PollItem) == 16u, "Modbus_PollItem must be 16 bytes");

    /// 최대 자동 폴링 항목 수
    static constexpr uint32_t MODBUS_MAX_POLL_ITEMS = 8u;

    // ============================================================
    //  게이트웨이 프레임 상수
    // ============================================================

    /// GW 프레임 헤더: CMD(1)+PHY(1)+ADDR(1)+FC(1)+LEN(1) = 5
    static constexpr uint32_t MODBUS_GW_HEADER_SIZE = 5u;
    /// CRC 후미
    static constexpr uint32_t MODBUS_GW_CRC_SIZE = 2u;
    /// Modbus PDU 최대 데이터 (253 바이트, 표준)
    static constexpr uint32_t MODBUS_MAX_PDU_DATA = 128u;  ///< B-CDMA 페이로드 제한
    /// 최대 GW 프레임
    static constexpr uint32_t MODBUS_GW_MAX_FRAME = MODBUS_GW_HEADER_SIZE + MODBUS_MAX_PDU_DATA + MODBUS_GW_CRC_SIZE;

    /// Modbus RTU CRC-16 다항식 (0xA001, 반전)
    /// @note  Modbus CRC는 IPC CRC(CCITT 0x1021)과 다른 다항식 사용.
    static constexpr uint16_t MODBUS_CRC_POLY = 0xA001u;
    static constexpr uint16_t MODBUS_CRC_INIT = 0xFFFFu;

    /// Modbus 응답 타임아웃 (ms)
    static constexpr uint32_t MODBUS_RESPONSE_TIMEOUT = 1000u;
    /// ISR/타임베이스 정지 상황에서도 무한 대기 차단
    static constexpr uint16_t MODBUS_RX_POLL_MAX_ATTEMPTS = 64u;

    /// 4-20mA ADC 변환 상수 (Q16)
    /// @note  4mA=0, 20mA=65535 (풀 스케일 uint16_t)
    ///        raw_adc -> scaled = (raw_adc - 4mA_offset) * scale_q16 >> 16
    static constexpr uint16_t ANALOG_4MA_ADC_VALUE = 819u;   ///< 12비트 ADC에서 4mA
    static constexpr uint16_t ANALOG_20MA_ADC_VALUE = 4095u;  ///< 12비트 ADC에서 20mA

    // ============================================================
    //  물리 계층 HAL 콜백
    // ============================================================

    /// @brief Modbus 물리 계층 콜백 (포트별 독립)
    struct Modbus_PHY_Callbacks {
        /// @brief UART 데이터 송신 (RS-485/232/422)
        /// @note  RS-485: 송신 전 DE=HIGH, 송신 후 DE=LOW 자동 처리.
        bool (*uart_send)(Modbus_PHY phy, const uint8_t* data, uint16_t len);

        /// @brief UART 데이터 수신 (비동기, 마지막 수신 프레임)
        /// @return 수신 바이트 수, 없으면 0
        uint16_t(*uart_receive)(Modbus_PHY phy, uint8_t* buf, uint16_t buf_size);

        /// @brief UART 설정 변경
        void (*uart_configure)(Modbus_PHY phy, const Modbus_UART_Config* config);

        /// @brief TCP 연결/전송 (Modbus TCP)
        bool (*tcp_send)(uint32_t ip_addr, uint16_t port,
            const uint8_t* data, uint16_t len);
        uint16_t(*tcp_receive)(uint8_t* buf, uint16_t buf_size);

        /// @brief 4-20mA ADC 읽기 (채널별)
        /// @param channel  ADC 채널 번호 (0~7)
        /// @return 12비트 ADC 원시 값
        uint16_t(*adc_read)(uint8_t channel);

        /// @brief RS-485 DE(Driver Enable) 핀 제어
        void (*rs485_set_de)(bool transmit);
    };

    // ============================================================
    //  게이트웨이 CFI 상태
    // ============================================================

    /// @brief Modbus 게이트웨이 상태 (비트마스크, CFI 검증)
    enum class Modbus_State : uint8_t {
        OFFLINE = 0x00u,
        IDLE = 0x01u,    ///< 대기 (요청 없음)
        REQUESTING = 0x02u,    ///< Modbus 요청 전송 중
        AWAITING = 0x04u,    ///< 응답 대기 중
        POLLING = 0x08u,    ///< 자동 폴링 실행 중
        ERROR = 0x10u
    };

    static constexpr uint8_t MODBUS_VALID_STATE_MASK =
        static_cast<uint8_t>(Modbus_State::IDLE)
        | static_cast<uint8_t>(Modbus_State::REQUESTING)
        | static_cast<uint8_t>(Modbus_State::AWAITING)
        | static_cast<uint8_t>(Modbus_State::POLLING)
        | static_cast<uint8_t>(Modbus_State::ERROR);

    inline uint32_t Modbus_Is_Valid_State(Modbus_State s) noexcept
    {
        const uint8_t v = static_cast<uint8_t>(s);
        if (v == 0u) { return MODBUS_SECURE_TRUE; }
        if ((v & ~MODBUS_VALID_STATE_MASK) != 0u) { return MODBUS_SECURE_FALSE; }
        return (((v & (v - 1u)) == 0u) ? MODBUS_SECURE_TRUE : MODBUS_SECURE_FALSE);
    }

    inline uint32_t Modbus_Is_Legal_Transition(Modbus_State from, Modbus_State to) noexcept
    {
        if (Modbus_Is_Valid_State(to) != MODBUS_SECURE_TRUE) { return MODBUS_SECURE_FALSE; }

        static constexpr uint8_t k_legal[6] = {
            /* OFFLINE    -> */ static_cast<uint8_t>(Modbus_State::IDLE),
            /* IDLE       -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(Modbus_State::REQUESTING)
              | static_cast<uint8_t>(Modbus_State::POLLING)
              | static_cast<uint8_t>(Modbus_State::OFFLINE)),
            /* REQUESTING -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(Modbus_State::AWAITING)
              | static_cast<uint8_t>(Modbus_State::IDLE)
              | static_cast<uint8_t>(Modbus_State::ERROR)),
            /* AWAITING   -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(Modbus_State::IDLE)
              | static_cast<uint8_t>(Modbus_State::ERROR)),
            /* POLLING    -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(Modbus_State::REQUESTING)
              | static_cast<uint8_t>(Modbus_State::IDLE)
              | static_cast<uint8_t>(Modbus_State::ERROR)),
            /* ERROR      -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(Modbus_State::IDLE)
              | static_cast<uint8_t>(Modbus_State::OFFLINE))
        };

        uint8_t idx;
        switch (from) {
        case Modbus_State::OFFLINE:    idx = 0u; break;
        case Modbus_State::IDLE:       idx = 1u; break;
        case Modbus_State::REQUESTING: idx = 2u; break;
        case Modbus_State::AWAITING:   idx = 3u; break;
        case Modbus_State::POLLING:    idx = 4u; break;
        case Modbus_State::ERROR:      idx = 5u; break;
        default:                       return MODBUS_SECURE_FALSE;
        }

        if (static_cast<uint8_t>(to) == 0u) {
            static constexpr uint8_t k_off_src = static_cast<uint8_t>(
                static_cast<uint8_t>(Modbus_State::IDLE)
                | static_cast<uint8_t>(Modbus_State::ERROR));
            return ((static_cast<uint8_t>(from) & k_off_src) != 0u) ? MODBUS_SECURE_TRUE : MODBUS_SECURE_FALSE;
        }

        return ((k_legal[idx] & static_cast<uint8_t>(to)) != 0u) ? MODBUS_SECURE_TRUE : MODBUS_SECURE_FALSE;
    }

    /// @brief Modbus RTU CRC-16 계산 (다항식 0xA001)
    /// @note  IPC CRC(CCITT 0x1021)과 다름. Modbus 표준 필수.
    inline uint16_t Modbus_CRC16(const uint8_t* data, uint32_t len) noexcept
    {
        if ((data == NULL) && (len != 0u)) { return 0u; }
        uint16_t crc = MODBUS_CRC_INIT;
        for (uint32_t i = 0u; i < len; ++i) {
            crc ^= static_cast<uint16_t>(data[i]);
            for (uint8_t bit = 0u; bit < 8u; ++bit) {
                if ((crc & 1u) != 0u) {
                    crc = static_cast<uint16_t>((crc >> 1u) ^ MODBUS_CRC_POLY);
                }
                else {
                    crc = static_cast<uint16_t>(crc >> 1u);
                }
            }
        }
        return crc;
    }

} // namespace ProtectedEngine