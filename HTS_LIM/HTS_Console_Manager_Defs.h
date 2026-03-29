#pragma once
/// @file  HTS_Console_Manager_Defs.h
/// @brief HTS 콘솔 매니저 공통 정의부
/// @details
///   INNOVID CORE-X Pro 통합콘솔 스위치에서 A55(Linux) -> STM32(보안 코프로세서)로
///   전달되는 설정/상태/진단 명령의 파라미터 ID, 채널 설정 구조체,
///   디바이스 프로파일, 진단 보고서 구조를 정의한다.
///
///   설계 기준:
///   - Cortex-M4F (168MHz) 양산 + ASIC 이식 기준
///   - constexpr 디스패치 테이블 (ASIC ROM 합성 가능)
///   - float/double 금지, 힙 할당 금지, 나눗셈 금지
///   - 모든 구조체 4바이트 정렬, static_assert 크기 검증
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    // ============================================================
    //  파라미터 ID (CONFIG_SET / CONFIG_GET 명령용)
    // ============================================================

    /// @brief 설정 파라미터 식별자
    /// @note  TLV 프레임 내 param_id 필드. ASIC: 8비트 디코더 ROM.
    ///        0x01~0x1F: 채널/RF, 0x20~0x3F: 보안, 0x40~0x5F: 디바이스,
    ///        0x60~0x7F: 네트워크, 0x80~0x9F: 진단
    enum class ParamId : uint8_t {
        // --- 채널/RF 설정 (0x01~0x1F) ---
        BPS_MODE = 0x01u,    ///< BPS 모드 (0=자동, 1~5=수동 100/1200/2400/4800/9600)
        BPS_CURRENT = 0x02u,    ///< 현재 BPS (읽기 전용)
        RF_FREQUENCY = 0x03u,    ///< RF 주파수 (kHz, uint32_t)
        RF_TX_POWER = 0x04u,    ///< TX 출력 (Q8 dBm)
        SPREAD_CHIPS = 0x05u,    ///< 확산 칩 수 (1/16/64)
        FEC_MODE = 0x06u,    ///< FEC 모드 (0=OFF, 1=HARQ, 2=3D-Tensor)
        AJC_ENABLE = 0x07u,    ///< 항재밍 활성화 (0/1)
        AJC_THRESHOLD = 0x08u,    ///< 항재밍 임계값 (uint16_t)

        // --- 보안 설정 (0x20~0x3F) ---
        CRYPTO_ALGO = 0x20u,    ///< 암호 알고리즘 (0=ARIA, 1=LEA)
        KEY_ROTATION_SEC = 0x21u,    ///< 키 로테이션 주기 (초)
        SESSION_TIMEOUT_SEC = 0x22u,    ///< 세션 타임아웃 (초)
        ANTI_DEBUG_ENABLE = 0x23u,    ///< 안티디버그 활성화 (0/1)
        SECURE_BOOT_STATE = 0x24u,    ///< 보안 부팅 상태 (읽기 전용)

        // --- 디바이스 프로파일 (0x40~0x5F) ---
        DEVICE_MODE = 0x40u,    ///< 운용 모드 (DeviceMode 열거형)
        DEVICE_ID = 0x41u,    ///< 디바이스 고유 ID (uint32_t, 읽기 전용)
        FIRMWARE_VERSION = 0x42u,    ///< 펌웨어 버전 (uint32_t major.minor.patch)
        UPTIME_SEC = 0x43u,    ///< 가동 시간 (초, 읽기 전용)
        CONSOLE_LINK_STATE = 0x44u,    ///< 콘솔 링크 상태 (0=down, 1=up)

        // --- 네트워크 (0x60~0x7F) ---
        BRIDGE_ENABLE = 0x60u,    ///< Ethernet<->B-CDMA 브릿지 활성화
        BRIDGE_MTU = 0x61u,    ///< 브릿지 MTU (바이트)
        MODBUS_ENABLE = 0x62u,    ///< Modbus 게이트웨이 활성화
        AMI_ENABLE = 0x63u,    ///< AMI DLMS/COSEM 활성화
        BLE_NFC_ENABLE = 0x64u,    ///< BLE/NFC 게이트웨이 활성화

        // --- 진단 (0x80~0x9F) ---
        DIAG_SNR_PROXY = 0x80u,    ///< 현재 SNR 프록시 (Q8, 읽기 전용)
        DIAG_JAMMING_LEVEL = 0x81u,    ///< 재밍 레벨 (uint16_t, 읽기 전용)
        DIAG_CRC_ERROR_CNT = 0x82u,    ///< 누적 CRC 에러 수 (읽기 전용)
        DIAG_HARQ_RETX_CNT = 0x83u,    ///< HARQ 재전송 횟수 (읽기 전용)
        DIAG_TEMPERATURE = 0x84u,    ///< 칩 온도 (Q8 섭씨, 읽기 전용)
        DIAG_SRAM_USAGE = 0x85u,    ///< SRAM 사용량 (바이트, 읽기 전용)
        DIAG_FLASH_CRC = 0x86u     ///< 펌웨어 Flash CRC (uint32_t, 읽기 전용)
    };

    // ============================================================
    //  디바이스 운용 모드
    // ============================================================

    /// @brief 디바이스 운용 모드 (설정으로 전환)
    /// @note  하나의 펌웨어로 아래 모든 시나리오를 설정만으로 전환.
    ///        ASIC: 3비트 모드 셀렉터로 합성.
    enum class DeviceMode : uint8_t {
        SENSOR_GATEWAY = 0x00u,    ///< 재난안전망 센서 게이트웨이
        SMART_SIGNAGE = 0x01u,    ///< 국가지점번호 스마트 안내판
        AMI_METER = 0x02u,    ///< AMI 전력량계
        CCTV_SECURITY = 0x03u,    ///< CCTV 보안 감시
        INDUSTRIAL_IOT = 0x04u,    ///< 산업용 IoT Modbus 게이트웨이
        ETHERNET_BRIDGE = 0x05u,    ///< 유선-무선 변환 콘솔
        MODE_COUNT = 0x06u     ///< 모드 총 개수 (검증용)
    };

    // ============================================================
    //  BPS 단계
    // ============================================================

    /// @brief BPS 속도 단계 (자동 적응 또는 수동 오버라이드)
    enum class BpsLevel : uint8_t {
        AUTO = 0x00u,    ///< 자동 적응 (SNR/재밍 기반)
        BPS_100 = 0x01u,    ///< 100 bps (극한 재밍, 50dB 방어)
        BPS_1200 = 0x02u,    ///< 1200 bps (최장거리 생존)
        BPS_2400 = 0x03u,    ///< 2400 bps (전술 표준, 36dB)
        BPS_4800 = 0x04u,    ///< 4800 bps (고음질 음성/중속 데이터)
        BPS_9600 = 0x05u,    ///< 9600 bps (최고속/CCTV 저해상도)
        LEVEL_COUNT = 0x06u     ///< 단계 총 개수 (검증용)
    };

    /// @brief BPS 단계별 실제 bps 값 조회 테이블 (constexpr ROM)
    /// @note  ASIC: 6-entry ROM. 인덱싱 시 나눗셈 없음.
    static constexpr uint32_t BPS_VALUE_TABLE[6] = {
        0u,         // AUTO (실제 값은 Adaptive BPS Controller가 결정)
        100u,
        1200u,
        2400u,
        4800u,
        9600u
    };
    static_assert(sizeof(BPS_VALUE_TABLE) == 24u, "BPS_VALUE_TABLE size check");

    // ============================================================
    //  채널 설정 구조체
    // ============================================================

    /// @brief 채널 설정 (런타임 변경 가능)
    struct ChannelConfig {
        BpsLevel bps_mode;          ///< BPS 모드 (자동/수동)
        DeviceMode device_mode;     ///< 디바이스 운용 모드
        uint8_t  spread_chips;      ///< 확산 칩 수 (1/16/64)
        uint8_t  fec_mode;          ///< FEC 모드 (0=OFF, 1=HARQ, 2=3D)
        uint8_t  ajc_enable;        ///< 항재밍 활성화 (0/1)
        uint8_t  crypto_algo;       ///< 암호 알고리즘 (0=ARIA, 1=LEA)
        uint8_t  bridge_enable;     ///< 이더넷 브릿지 활성화
        uint8_t  reserved;          ///< 정렬 패딩
        uint32_t rf_frequency_khz;  ///< RF 주파수 (kHz)
        uint16_t rf_tx_power_q8;    ///< TX 출력 (Q8 dBm)
        uint16_t ajc_threshold;     ///< 항재밍 임계값
        uint32_t key_rotation_sec;  ///< 키 로테이션 주기 (초)
        uint32_t session_timeout_sec; ///< 세션 타임아웃 (초)
    };
    static_assert(sizeof(ChannelConfig) == 24u, "ChannelConfig must be 24 bytes");
    static_assert((sizeof(ChannelConfig) & 3u) == 0u, "ChannelConfig must be 4-byte aligned");

    // ============================================================
    //  진단 보고서 구조체
    // ============================================================

    /// @brief 진단 상태 보고서 (STATUS_RSP / DIAG_RSP 페이로드)
    struct DiagReport {
        uint32_t uptime_sec;            ///< 가동 시간 (초)
        uint32_t firmware_version;      ///< 펌웨어 버전 (major<<16 | minor<<8 | patch)
        uint32_t device_id;             ///< 디바이스 고유 ID
        uint16_t current_bps;           ///< 현재 BPS 값
        uint16_t snr_proxy_q8;          ///< SNR 프록시 (Q8)
        uint16_t jamming_level;         ///< 재밍 레벨
        uint16_t temperature_q8;        ///< 칩 온도 (Q8 섭씨)
        uint32_t crc_error_count;       ///< 누적 CRC 에러
        uint32_t harq_retx_count;       ///< HARQ 재전송 횟수
        uint32_t sram_usage_bytes;      ///< SRAM 사용량
        uint32_t flash_crc;             ///< 펌웨어 Flash CRC-32
        uint8_t  link_state;            ///< 콘솔 링크 상태 (0=down, 1=up)
        uint8_t  device_mode;           ///< 현재 운용 모드
        uint8_t  bps_mode;              ///< 현재 BPS 모드 설정
        uint8_t  secure_boot_state;     ///< 보안 부팅 상태 (0=미검증, 1=통과)
    };
    static_assert(sizeof(DiagReport) == 40u, "DiagReport must be 40 bytes");
    static_assert((sizeof(DiagReport) & 3u) == 0u, "DiagReport must be 4-byte aligned");

    // ============================================================
    //  TLV 설정 프레임 구조 (IPC 페이로드 내부)
    // ============================================================

    /// @brief 단일 파라미터 TLV (Type-Length-Value)
    /// @note  CONFIG_SET/CONFIG_GET 페이로드: [ParamId(1)][Length(1)][Value(0~4)]
    ///        최대 값 크기 4바이트 (uint32_t). ASIC: 고정 길이 디코더.
    static constexpr uint32_t TLV_HEADER_SIZE = 2u;    ///< ParamId(1) + Length(1)
    static constexpr uint32_t TLV_MAX_VALUE = 4u;    ///< 최대 값 바이트
    static constexpr uint32_t TLV_MAX_SIZE = TLV_HEADER_SIZE + TLV_MAX_VALUE;  ///< 6

    /// @brief TLV 직렬화: 단일 파라미터를 버퍼에 기록
    /// @param[out] buf     출력 버퍼 (최소 TLV_HEADER_SIZE + val_len)
    /// @param      id      파라미터 ID
    /// @param      value   값 바이트 배열
    /// @param      val_len 값 길이 (0~4)
    /// @return 기록된 총 바이트, 에러 시 0
    inline uint32_t TLV_Serialize(uint8_t* buf, ParamId id,
        const uint8_t* value, uint8_t val_len) noexcept
    {
        if (buf == nullptr) { return 0u; }
        if (val_len > TLV_MAX_VALUE) { return 0u; }
        buf[0] = static_cast<uint8_t>(id);
        buf[1] = val_len;
        for (uint8_t i = 0u; i < val_len; ++i) {
            buf[TLV_HEADER_SIZE + i] = (value != nullptr) ? value[i] : 0u;
        }
        return TLV_HEADER_SIZE + static_cast<uint32_t>(val_len);
    }

    /// @brief TLV 파싱: 버퍼에서 단일 파라미터 추출
    /// @param[in]  buf         입력 버퍼
    /// @param      buf_len     버퍼 남은 길이
    /// @param[out] out_id      파라미터 ID
    /// @param[out] out_value   값 바이트 (최대 4바이트)
    /// @param[out] out_val_len 값 길이
    /// @return 소비된 총 바이트, 에러 시 0
    inline uint32_t TLV_Parse(const uint8_t* buf, uint32_t buf_len,
        ParamId& out_id, uint8_t* out_value,
        uint8_t& out_val_len) noexcept
    {
        if (buf == nullptr) { return 0u; }
        if (buf_len < TLV_HEADER_SIZE) { return 0u; }
        out_id = static_cast<ParamId>(buf[0]);
        out_val_len = buf[1];
        if (out_val_len > TLV_MAX_VALUE) { return 0u; }
        if (buf_len < TLV_HEADER_SIZE + static_cast<uint32_t>(out_val_len)) { return 0u; }
        if (out_value != nullptr) {
            for (uint8_t i = 0u; i < out_val_len; ++i) {
                out_value[i] = buf[TLV_HEADER_SIZE + i];
            }
        }
        return TLV_HEADER_SIZE + static_cast<uint32_t>(out_val_len);
    }

    // ============================================================
    //  콘솔 매니저 CFI 상태
    // ============================================================

    /// @brief 콘솔 매니저 내부 상태 (비트마스크, CFI 검증용)
    enum class ConsoleState : uint8_t {
        OFFLINE = 0x00u,    ///< 미초기화 / IPC 미연결
        ONLINE = 0x01u,    ///< IPC 연결, 정상 운용
        CONFIGURING = 0x02u,    ///< 설정 변경 처리 중
        DIAGNOSING = 0x04u,    ///< 진단 보고서 생성 중
        ERROR = 0x08u     ///< 오류 복구 중
    };

} // namespace ProtectedEngine