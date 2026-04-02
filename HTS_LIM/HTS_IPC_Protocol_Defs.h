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

/// @file  HTS_IPC_Protocol_Defs.h
/// @brief HTS IPC 프로토콜 공통 정의부 (STM32 <-> A55 양단 공유)
/// @details
///   HTS B-CDMA 보안통신 칩(STM32F407)과 통합콘솔(Cortex-A55) 간
///   SPI 기반 IPC 통신 프로토콜의 공통 상수, 프레임 구조, CRC-16 LUT,
///   엔디안 독립 직렬화 헬퍼, CFI 상태 전이 테이블을 정의한다.
///
///   와이어 포맷 (Big-Endian):
///   @code
///   [SYNC_H][SYNC_L][SEQ][CMD][LEN_H][LEN_L][PAYLOAD(0..N)][CRC_H][CRC_L]
///   @endcode
///
///   설계 기준:
///   - Cortex-M4F (168MHz, 1MB Flash, 192KB SRAM) 양산 기준
///   - 향후 ASIC 이식을 위한 합성 가능 구조 (constexpr ROM, 조합논리)
///   - float/double 금지, 힙 할당 금지, 나눗셈 금지
///
/// @note  ARM(STM32), AArch64(A55), PC(시뮬레이터) 모두 포함 가능.
///        플랫폼 의존 코드 없음.
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    // ============================================================
    //  프로토콜 상수
    // ============================================================

    /// 동기 워드 (와이어 빅엔디안: 0xAA 먼저, 0x55 뒤)
    static constexpr uint16_t IPC_SYNC_WORD = 0xAA55u;

    /// 프레임 구조 치수
    static constexpr uint32_t IPC_HEADER_SIZE = 6u;    ///< SYNC(2)+SEQ(1)+CMD(1)+LEN(2)
    static constexpr uint32_t IPC_CRC_SIZE = 2u;    ///< CRC-16 후미
    static constexpr uint32_t IPC_MAX_PAYLOAD = 256u;  ///< 최대 페이로드 바이트
    static constexpr uint32_t IPC_MAX_FRAME_SIZE = IPC_HEADER_SIZE + IPC_MAX_PAYLOAD + IPC_CRC_SIZE;  ///< 264

    /// 링 버퍼 깊이 (2의 거듭제곱 -- 비트마스크 인덱싱용)
    static constexpr uint32_t IPC_RING_DEPTH = 8u;
    static constexpr uint32_t IPC_RING_MASK = IPC_RING_DEPTH - 1u;
    static_assert((IPC_RING_DEPTH& IPC_RING_MASK) == 0u,
        "IPC_RING_DEPTH must be power of 2 for & mask indexing");

    /// 타임아웃 기본값 (systick 카운트, 1 tick = 1 ms)
    static constexpr uint32_t IPC_FRAME_TIMEOUT_MS = 100u;  ///< 단일 프레임 수신 타임아웃
    static constexpr uint32_t IPC_RETRY_COUNT = 3u;    ///< 에러 전 최대 재시도
    static constexpr uint32_t IPC_PING_INTERVAL_MS = 1000u; ///< 하트비트 주기

    /// SPI DMA 전송 크기 (슬레이브 사전 적재용 고정 크기)
    static constexpr uint32_t IPC_SPI_DMA_BUF_SIZE = IPC_MAX_FRAME_SIZE;  ///< 264

    // ============================================================
    //  명령 코드
    // ============================================================

    /// @brief IPC 명령 식별자
    /// @details 0x01~0x0F: 핸드셰이크, 0x10~0x1F: ACK/NACK,
    ///          0x20~0x2F: 데이터, 0x30~0x3F: 설정,
    ///          0x40~0x4F: 상태, 0x50~0x5F: 진단,
    ///          0x60~0x6F: 알림, 0xF0~0xFF: 시스템
    enum class IPC_Command : uint8_t {
        PING = 0x01u,    ///< 하트비트 요청
        PONG = 0x02u,    ///< 하트비트 응답
        ACK = 0x10u,    ///< 긍정 확인
        NACK = 0x11u,    ///< 부정 확인
        DATA_TX = 0x20u,    ///< A55->STM32: B-CDMA 송신 데이터
        DATA_RX = 0x21u,    ///< STM32->A55: B-CDMA 수신 데이터
        DATA_TX_BURST = 0x22u,    ///< A55->STM32: 버스트 데이터 (다중 프레임)
        CONFIG_SET = 0x30u,    ///< 설정 파라미터 기록
        CONFIG_GET = 0x31u,    ///< 설정 파라미터 조회
        CONFIG_RSP = 0x32u,    ///< 설정 응답
        STATUS_REQ = 0x40u,    ///< 상태 요청
        STATUS_RSP = 0x41u,    ///< 상태 응답
        DIAG_REQ = 0x50u,    ///< 진단 요청
        DIAG_RSP = 0x51u,    ///< 진단 응답
        BPS_NOTIFY = 0x60u,    ///< BPS 변경 알림 (STM32->A55)
        JAMMING_ALERT = 0x61u,    ///< 재밍 탐지 경보 (STM32->A55)
        RESET_CMD = 0xF0u,    ///< 시스템 리셋 명령
        KILL_SWITCH = 0xFFu     ///< 긴급 킬스위치 (즉시 중단)
    };

    // ============================================================
    //  에러 코드
    // ============================================================

    /// @brief IPC 에러 코드 (프레임 수준 + 프로토콜 수준 결함)
    enum class IPC_Error : uint8_t {
        OK = 0x00u,
        CRC_MISMATCH = 0x01u,    ///< CRC-16 검증 실패
        INVALID_CMD = 0x02u,    ///< 알 수 없는 명령 코드
        INVALID_LEN = 0x03u,    ///< 페이로드 길이 초과
        SEQ_MISMATCH = 0x04u,    ///< 시퀀스 번호 불일치
        TIMEOUT = 0x05u,    ///< 프레임/응답 타임아웃
        QUEUE_FULL = 0x06u,    ///< TX/RX 링 버퍼 오버플로우
        HW_FAULT = 0x07u,    ///< SPI/DMA 하드웨어 오류
        CFI_VIOLATION = 0x08u,    ///< 불법 상태 전이
        BUFFER_OVERFLOW = 0x09u,    ///< 페이로드 버퍼 초과
        NOT_INITIALIZED = 0x0Au,    ///< 모듈 미초기화
        BUSY = 0x0Bu     ///< 전송 진행 중
    };

    // ============================================================
    //  CFI 상태 머신
    // ============================================================

    /// @brief IPC 프로토콜 상태 (CFI용 비트마스크 -- 각 값이 2의 거듭제곱)
    enum class IPC_State : uint8_t {
        UNINITIALIZED = 0x00u,
        IDLE = 0x01u,
        RECEIVING = 0x02u,
        PROCESSING = 0x04u,
        RESPONDING = 0x08u,
        ERROR_RECOVERY = 0x10u
    };

    /// 유효한 IPC_State 값의 비트 합집합 (단일 비트 전용)
    /// @note  UNINITIALIZED(0x00)은 전이 대상으로 허용 불가이므로 제외.
    ///        다중 비트 글리치 값(0x1F, 0xFF 등) 거부에 사용.
    static constexpr uint8_t IPC_VALID_STATE_MASK =
        static_cast<uint8_t>(IPC_State::IDLE)
        | static_cast<uint8_t>(IPC_State::RECEIVING)
        | static_cast<uint8_t>(IPC_State::PROCESSING)
        | static_cast<uint8_t>(IPC_State::RESPONDING)
        | static_cast<uint8_t>(IPC_State::ERROR_RECOVERY);
    // = 0x01 | 0x02 | 0x04 | 0x08 | 0x10 = 0x1F

    /// @brief IPC_State가 정확히 하나의 정의된 단일 비트 값인지 검증
    /// @param s  검증할 상태
    /// @return 알려진 단일 상태이면 true (정확히 1비트, 유효 마스크 내)
    /// @note  일정 시간 실행: 데이터 의존 분기 없음.
    ///        다중 비트 글리치(0x03, 0x1F, 0xFF)와 UNINITIALIZED(0x00) 거부.
    ///        Cortex-M4: AND 2회 + 비교 2회, 분기 0회.
    ///        ASIC: AND 게이트 + 제로 비교기로 합성 가능.
    inline bool IPC_Is_Valid_State(IPC_State s) noexcept
    {
        const uint8_t v = static_cast<uint8_t>(s);
        // 검사 1: 유효 마스크 외부 비트 존재 시 거부
        if ((v & ~IPC_VALID_STATE_MASK) != 0u) { return false; }
        // 검사 2: 정확히 1비트만 설정 (2의 거듭제곱, 비제로)
        //   v & (v - 1) == 0 이면 정확히 1비트. v == 0 이면 실패.
        return (v != 0u) && ((v & (v - 1u)) == 0u);
    }

    /// @brief CFI 검증된 상태 전이 검사
    /// @param from 현재 상태
    /// @param to   목표 상태
    /// @return 전이가 합법이면 true
    /// @note  보안: 비트마스크 조회 전에 to가 단일 유효 상태인지 먼저 검증.
    ///        다중 비트 글리치 우회 차단 (예: to=0xFF는 가드 없으면 모든 검사 통과).
    ///        ASIC: ROM 테이블 + 조합논리 검증, 완전 합성 가능.
    inline bool IPC_Is_Legal_Transition(IPC_State from, IPC_State to) noexcept
    {
        // 게이트 1: 'to'가 단일 유효 상태인지 검증
        if (!IPC_Is_Valid_State(to)) { return false; }

        // 게이트 2: 'from' 상태의 합법 전이 대상 조회
        static constexpr uint8_t k_legal_targets[6] = {
            /* UNINITIALIZED -> */ static_cast<uint8_t>(IPC_State::IDLE),
            /* IDLE          -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(IPC_State::RECEIVING)
              | static_cast<uint8_t>(IPC_State::ERROR_RECOVERY)),
            /* RECEIVING     -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(IPC_State::PROCESSING)
              | static_cast<uint8_t>(IPC_State::IDLE)
              | static_cast<uint8_t>(IPC_State::ERROR_RECOVERY)),
            /* PROCESSING    -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(IPC_State::RESPONDING)
              | static_cast<uint8_t>(IPC_State::IDLE)
              | static_cast<uint8_t>(IPC_State::ERROR_RECOVERY)),
            /* RESPONDING    -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(IPC_State::IDLE)
              | static_cast<uint8_t>(IPC_State::ERROR_RECOVERY)),
            /* ERROR_RECOV   -> */ static_cast<uint8_t>(IPC_State::IDLE)
        };

        uint8_t idx;
        switch (from) {
        case IPC_State::UNINITIALIZED:  idx = 0u; break;
        case IPC_State::IDLE:           idx = 1u; break;
        case IPC_State::RECEIVING:      idx = 2u; break;
        case IPC_State::PROCESSING:     idx = 3u; break;
        case IPC_State::RESPONDING:     idx = 4u; break;
        case IPC_State::ERROR_RECOVERY: idx = 5u; break;
        default:                        return false;
        }

        return (k_legal_targets[idx] & static_cast<uint8_t>(to)) != 0u;
    }

    // ============================================================
    //  엔디안 독립 직렬화 (Big-Endian 와이어)
    // ============================================================

    /// @brief uint16_t를 빅엔디안 와이어 포맷으로 직렬화
    inline void IPC_Serialize_U16(uint8_t* buf, uint16_t val) noexcept
    {
        buf[0] = static_cast<uint8_t>(val >> 8u);
        buf[1] = static_cast<uint8_t>(val & 0xFFu);
    }

    /// @brief 빅엔디안 와이어 포맷에서 uint16_t 역직렬화
    inline uint16_t IPC_Deserialize_U16(const uint8_t* buf) noexcept
    {
        return static_cast<uint16_t>(
            (static_cast<uint16_t>(buf[0]) << 8u) |
            static_cast<uint16_t>(buf[1]));
    }

    /// @brief uint32_t를 빅엔디안 와이어 포맷으로 직렬화
    inline void IPC_Serialize_U32(uint8_t* buf, uint32_t val) noexcept
    {
        buf[0] = static_cast<uint8_t>(val >> 24u);
        buf[1] = static_cast<uint8_t>((val >> 16u) & 0xFFu);
        buf[2] = static_cast<uint8_t>((val >> 8u) & 0xFFu);
        buf[3] = static_cast<uint8_t>(val & 0xFFu);
    }

    /// @brief 빅엔디안 와이어 포맷에서 uint32_t 역직렬화
    inline uint32_t IPC_Deserialize_U32(const uint8_t* buf) noexcept
    {
        return (static_cast<uint32_t>(buf[0]) << 24u) |
            (static_cast<uint32_t>(buf[1]) << 16u) |
            (static_cast<uint32_t>(buf[2]) << 8u) |
            static_cast<uint32_t>(buf[3]);
    }

    // ============================================================
    //  CRC-16 CCITT (0x1021, init=0xFFFF) -- constexpr LUT
    // ============================================================

    /// @brief CRC-16 CCITT 룩업 테이블 (256 항목, 512바이트 Flash ROM)
    /// @note  컴파일 시점 생성. 264바이트 프레임당 2112개 조건 분기를
    ///        264회 XOR+시프트+테이블 참조로 대체 (조건 분기 0회).
    ///        Cortex-M4: ~1.6us/프레임(264B, 168MHz) vs ~6.3us(bit-by-bit).
    ///        ASIC: 512B 조합논리 ROM 합성. 바이트당 1사이클 순수 조합경로.
    static constexpr uint16_t IPC_CRC16_LUT[256] = {
        0x0000u, 0x1021u, 0x2042u, 0x3063u, 0x4084u, 0x50A5u, 0x60C6u, 0x70E7u,
        0x8108u, 0x9129u, 0xA14Au, 0xB16Bu, 0xC18Cu, 0xD1ADu, 0xE1CEu, 0xF1EFu,
        0x1231u, 0x0210u, 0x3273u, 0x2252u, 0x52B5u, 0x4294u, 0x72F7u, 0x62D6u,
        0x9339u, 0x8318u, 0xB37Bu, 0xA35Au, 0xD3BDu, 0xC39Cu, 0xF3FFu, 0xE3DEu,
        0x2462u, 0x3443u, 0x0420u, 0x1401u, 0x64E6u, 0x74C7u, 0x44A4u, 0x5485u,
        0xA56Au, 0xB54Bu, 0x8528u, 0x9509u, 0xE5EEu, 0xF5CFu, 0xC5ACu, 0xD58Du,
        0x3653u, 0x2672u, 0x1611u, 0x0630u, 0x76D7u, 0x66F6u, 0x5695u, 0x46B4u,
        0xB75Bu, 0xA77Au, 0x9719u, 0x8738u, 0xF7DFu, 0xE7FEu, 0xD79Du, 0xC7BCu,
        0x48C4u, 0x58E5u, 0x6886u, 0x78A7u, 0x0840u, 0x1861u, 0x2802u, 0x3823u,
        0xC9CCu, 0xD9EDu, 0xE98Eu, 0xF9AFu, 0x8948u, 0x9969u, 0xA90Au, 0xB92Bu,
        0x5AF5u, 0x4AD4u, 0x7AB7u, 0x6A96u, 0x1A71u, 0x0A50u, 0x3A33u, 0x2A12u,
        0xDBFDu, 0xCBDCu, 0xFBBFu, 0xEB9Eu, 0x9B79u, 0x8B58u, 0xBB3Bu, 0xAB1Au,
        0x6CA6u, 0x7C87u, 0x4CE4u, 0x5CC5u, 0x2C22u, 0x3C03u, 0x0C60u, 0x1C41u,
        0xEDAEu, 0xFD8Fu, 0xCDECu, 0xDDCDu, 0xAD2Au, 0xBD0Bu, 0x8D68u, 0x9D49u,
        0x7E97u, 0x6EB6u, 0x5ED5u, 0x4EF4u, 0x3E13u, 0x2E32u, 0x1E51u, 0x0E70u,
        0xFF9Fu, 0xEFBEu, 0xDFDDu, 0xCFFCu, 0xBF1Bu, 0xAF3Au, 0x9F59u, 0x8F78u,
        0x9188u, 0x81A9u, 0xB1CAu, 0xA1EBu, 0xD10Cu, 0xC12Du, 0xF14Eu, 0xE16Fu,
        0x1080u, 0x00A1u, 0x30C2u, 0x20E3u, 0x5004u, 0x4025u, 0x7046u, 0x6067u,
        0x83B9u, 0x9398u, 0xA3FBu, 0xB3DAu, 0xC33Du, 0xD31Cu, 0xE37Fu, 0xF35Eu,
        0x02B1u, 0x1290u, 0x22F3u, 0x32D2u, 0x4235u, 0x5214u, 0x6277u, 0x7256u,
        0xB5EAu, 0xA5CBu, 0x95A8u, 0x8589u, 0xF56Eu, 0xE54Fu, 0xD52Cu, 0xC50Du,
        0x34E2u, 0x24C3u, 0x14A0u, 0x0481u, 0x7466u, 0x6447u, 0x5424u, 0x4405u,
        0xA7DBu, 0xB7FAu, 0x8799u, 0x97B8u, 0xE75Fu, 0xF77Eu, 0xC71Du, 0xD73Cu,
        0x26D3u, 0x36F2u, 0x0691u, 0x16B0u, 0x6657u, 0x7676u, 0x4615u, 0x5634u,
        0xD94Cu, 0xC96Du, 0xF90Eu, 0xE92Fu, 0x99C8u, 0x89E9u, 0xB98Au, 0xA9ABu,
        0x5844u, 0x4865u, 0x7806u, 0x6827u, 0x18C0u, 0x08E1u, 0x3882u, 0x28A3u,
        0xCB7Du, 0xDB5Cu, 0xEB3Fu, 0xFB1Eu, 0x8BF9u, 0x9BD8u, 0xABBBu, 0xBB9Au,
        0x4A75u, 0x5A54u, 0x6A37u, 0x7A16u, 0x0AF1u, 0x1AD0u, 0x2AB3u, 0x3A92u,
        0xFD2Eu, 0xED0Fu, 0xDD6Cu, 0xCD4Du, 0xBDAAu, 0xAD8Bu, 0x9DE8u, 0x8DC9u,
        0x7C26u, 0x6C07u, 0x5C64u, 0x4C45u, 0x3CA2u, 0x2C83u, 0x1CE0u, 0x0CC1u,
        0xEF1Fu, 0xFF3Eu, 0xCF5Du, 0xDF7Cu, 0xAF9Bu, 0xBFBAu, 0x8FD9u, 0x9FF8u,
        0x6E17u, 0x7E36u, 0x4E55u, 0x5E74u, 0x2E93u, 0x3EB2u, 0x0ED1u, 0x1EF0u
    };
    static_assert(sizeof(IPC_CRC16_LUT) == 512u, "CRC-16 LUT must be 512 bytes");

    /// @brief CRC-16 CCITT 계산 (LUT 기반, 조건 분기 0회)
    /// @param data  데이터 바이트 포인터
    /// @param len   바이트 수
    /// @return CRC-16 값
    /// @note  바이트당: XOR 1회 + 시프트 1회 + 테이블 참조 1회.
    ///        264B 프레임: 264회 반복, ~1.6us(168MHz).
    ///        ASIC: LUT는 512B ROM. 바이트당 순수 조합논리.
    inline uint16_t IPC_Compute_CRC16(const uint8_t* data, uint32_t len) noexcept
    {
        uint32_t crc = 0xFFFFu;
        for (uint32_t i = 0u; i < len; ++i) {
            const uint32_t idx = ((crc >> 8u) ^ static_cast<uint32_t>(data[i])) & 0xFFu;
            crc = (crc << 8u) ^ static_cast<uint32_t>(IPC_CRC16_LUT[idx]);
            crc &= 0xFFFFu;
        }
        return static_cast<uint16_t>(crc);
    }

    // ============================================================
    //  프레임 직렬화 / 역직렬화
    // ============================================================

    /// @brief 완전한 IPC 프레임을 와이어 버퍼에 직렬화
    /// @param[out] wire_buf    출력 버퍼 (최소 IPC_HEADER_SIZE + payload_len + IPC_CRC_SIZE)
    /// @param      seq         시퀀스 번호
    /// @param      cmd         명령 코드
    /// @param      payload     페이로드 (payload_len == 0이면 nullptr 가능)
    /// @param      payload_len 페이로드 길이 (바이트)
    /// @return 총 프레임 크기 (바이트), 에러 시 0
    inline uint32_t IPC_Serialize_Frame(
        uint8_t* wire_buf,
        uint8_t         seq,
        IPC_Command     cmd,
        const uint8_t* payload,
        uint16_t        payload_len) noexcept
    {
        if (wire_buf == NULL) { return 0u; }
        if (payload_len > IPC_MAX_PAYLOAD) { return 0u; }
        if ((payload == NULL) && (payload_len != 0u)) { return 0u; }

        IPC_Serialize_U16(&wire_buf[0], IPC_SYNC_WORD);
        wire_buf[2] = seq;
        wire_buf[3] = static_cast<uint8_t>(cmd);
        IPC_Serialize_U16(&wire_buf[4], payload_len);

        for (uint16_t i = 0u; i < payload_len; ++i) {
            wire_buf[IPC_HEADER_SIZE + i] = payload[i];
        }

        const uint32_t crc_region = IPC_HEADER_SIZE + static_cast<uint32_t>(payload_len);
        const uint16_t crc = IPC_Compute_CRC16(wire_buf, crc_region);
        IPC_Serialize_U16(&wire_buf[crc_region], crc);

        return crc_region + IPC_CRC_SIZE;
    }

    /// @brief 와이어 포맷 IPC 프레임을 검증 및 파싱
    /// @param[in]  wire_buf        입력 버퍼
    /// @param      wire_len        수신된 총 바이트
    /// @param[out] out_seq         추출된 시퀀스 번호
    /// @param[out] out_cmd         추출된 명령
    /// @param[out] out_payload     wire_buf 내 페이로드 시작 포인터
    /// @param[out] out_payload_len 페이로드 길이
    /// @return 성공 시 IPC_Error::OK, 그 외 에러 코드
    inline IPC_Error IPC_Parse_Frame(
        const uint8_t* wire_buf,
        uint32_t        wire_len,
        uint8_t& out_seq,
        IPC_Command& out_cmd,
        const uint8_t*& out_payload,
        uint16_t& out_payload_len) noexcept
    {
        if (wire_buf == NULL) { return IPC_Error::BUFFER_OVERFLOW; }
        if (wire_len < IPC_HEADER_SIZE + IPC_CRC_SIZE) { return IPC_Error::INVALID_LEN; }

        const uint16_t sync = IPC_Deserialize_U16(&wire_buf[0]);
        if (sync != IPC_SYNC_WORD) { return IPC_Error::CRC_MISMATCH; }

        out_seq = wire_buf[2];
        out_cmd = static_cast<IPC_Command>(wire_buf[3]);
        out_payload_len = IPC_Deserialize_U16(&wire_buf[4]);

        if (out_payload_len > IPC_MAX_PAYLOAD) { return IPC_Error::INVALID_LEN; }

        const uint32_t expected_len = IPC_HEADER_SIZE + static_cast<uint32_t>(out_payload_len) + IPC_CRC_SIZE;
        if (wire_len < expected_len) { return IPC_Error::INVALID_LEN; }

        const uint32_t crc_region = IPC_HEADER_SIZE + static_cast<uint32_t>(out_payload_len);
        const uint16_t computed_crc = IPC_Compute_CRC16(wire_buf, crc_region);
        const uint16_t received_crc = IPC_Deserialize_U16(&wire_buf[crc_region]);
        if (computed_crc != received_crc) { return IPC_Error::CRC_MISMATCH; }

        out_payload = (out_payload_len > 0u) ? &wire_buf[IPC_HEADER_SIZE] : NULL;

        return IPC_Error::OK;
    }

    // ============================================================
    //  통계 구조체
    // ============================================================

    /// @brief IPC 통신 통계 (ARM 정렬 uint32_t 원자적 안전)
    struct IPC_Statistics {
        uint32_t tx_frames;         ///< 총 송신 프레임 수
        uint32_t rx_frames;         ///< 총 수신 프레임 수
        uint32_t crc_errors;        ///< CRC 불일치 횟수
        uint32_t timeout_errors;    ///< 프레임 타임아웃 횟수
        uint32_t seq_errors;        ///< 시퀀스 불일치 횟수
        uint32_t queue_overflows;   ///< 링 버퍼 오버플로우 횟수
        uint32_t hw_faults;         ///< SPI/DMA 하드웨어 결함 횟수
        uint32_t cfi_violations;    ///< 불법 상태 전이 횟수
    };
    static_assert(sizeof(IPC_Statistics) == 32u, "IPC_Statistics must be 32 bytes");

    // ============================================================
    //  설정 구조체
    // ============================================================

    /// @brief IPC 모듈 설정 (초기화 시 1회 설정)
    struct IPC_Config {
        uint32_t spi_base_addr;     ///< SPI 주변장치 베이스 (예: SPI1=0x40013000)
        uint32_t dma_base_addr;     ///< DMA 컨트롤러 베이스 (예: DMA2=0x40026400)
        uint8_t  dma_stream_rx;     ///< SPI RX용 DMA 스트림 (0~7)
        uint8_t  dma_stream_tx;     ///< SPI TX용 DMA 스트림 (0~7)
        uint8_t  dma_channel;       ///< DMA 채널 선택 (0~7)
        uint8_t  drdy_port_index;   ///< DRDY GPIO 포트 (0=A, 1=B, ..., 5=F)
        uint8_t  drdy_pin;          ///< DRDY GPIO 핀 (0~15)
        uint8_t  reserved[3];       ///< 정렬 패딩
        uint32_t frame_timeout_ms;  ///< 프레임 수신 타임아웃
        uint32_t ping_interval_ms;  ///< 하트비트 주기 (0=비활성)
    };
    static_assert(sizeof(IPC_Config) == 24u, "IPC_Config size check");

    // ============================================================
    //  링 버퍼 엔트리
    // ============================================================

    /// @brief Lock-free IPC 프레임 링 버퍼 단일 항목
    struct IPC_Ring_Entry {
        uint8_t  data[IPC_MAX_FRAME_SIZE];  ///< 와이어 포맷 원시 프레임 (264B)
        uint16_t length;                     ///< 실제 프레임 길이
        uint8_t  padding[2];                 ///< 4바이트 정렬
    };
    static_assert(sizeof(IPC_Ring_Entry) == 268u, "IPC_Ring_Entry must be 268 bytes");
    static_assert((sizeof(IPC_Ring_Entry) & 3u) == 0u, "IPC_Ring_Entry must be 4-byte aligned");

    // ============================================================
    //  보안 소거 헬퍼
    // ============================================================

    /// @brief 보안 소거: 컴파일러 DCE 방지 포함 제로 채움
    /// @param ptr  대상 메모리
    /// @param len  소거할 바이트 수
    /// @note  volatile 쓰기로 컴파일러 DCE 방지. GCC asm clobber 이중 방어.
    ///        MSVC: /volatile:ms (기본값)가 volatile 접근을 컴파일러 배리어로 처리.
    inline void IPC_Secure_Wipe(void* ptr, uint32_t len) noexcept
    {
        if (ptr == NULL) { return; }
        volatile uint8_t* vp = static_cast<volatile uint8_t*>(ptr);
        for (uint32_t i = 0u; i < len; ++i) {
            vp[i] = 0u;
        }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" ::: "memory");
#endif
    }

} // namespace ProtectedEngine