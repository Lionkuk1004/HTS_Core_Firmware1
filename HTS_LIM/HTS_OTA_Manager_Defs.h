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

/// @file  HTS_OTA_Manager_Defs.h
/// @brief HTS OTA 매니저 공통 정의부
/// @details
///   원격 펌웨어 업데이트(OTA) 관리자. A55에서 IPC로 전달받은
///   펌웨어 이미지를 STM32 내부 Flash 듀얼 뱅크에 기록하고,
///   무결성 검증 후 뱅크 스왑으로 안전하게 업데이트.
///
///   OTA 청크 프레임 (IPC 페이로드):
///   @code
///   [OTA_CMD(1)][SEQ(2)][TOTAL_CHUNKS(2)][CHUNK_LEN(1)][CHUNK_DATA(N)][CRC16(2)]
///   @endcode
///
///   듀얼 뱅크 구조:
///   - Bank A (0x0800_0000 ~ 0x0807_FFFF): 운용 펌웨어 (512KB)
///   - Bank B (0x0808_0000 ~ 0x080F_FFFF): 수신/대기 영역 (512KB)
///   - 검증 완료 후 SYSCFG 뱅크 스왑으로 원자적 전환
///
///   설계 기준:
///   - Cortex-M4F STM32F407 (1MB Flash, 듀얼 뱅크)
///   - 롤백 방지: 버전 번호 단조증가 (OTP 영역 또는 Flash 마지막 섹터)
///   - 고빈도 NVM 갱신 시 동일 섹터 마모 — 웨어 레벨링·스페이어·쓰기 카운터는 HAL/보드 정책
///   - 힙 0, float/double 0, 나눗셈 0
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    // ============================================================
    //  OTA 명령 코드
    // ============================================================

    /// @brief OTA 명령 타입
    enum class OTA_Command : uint8_t {
        BEGIN = 0x01u,    ///< 업데이트 시작 (총 크기, 버전, 청크 수)
        CHUNK_DATA = 0x02u,    ///< 청크 데이터 전송
        VERIFY = 0x03u,    ///< 전체 이미지 검증 요청
        COMMIT = 0x04u,    ///< 뱅크 스왑 커밋
        ABORT = 0x05u,    ///< 업데이트 중단
        STATUS_REQ = 0x06u,    ///< 진행 상태 조회
        STATUS_RSP = 0x07u     ///< 진행 상태 응답
    };

    // ============================================================
    //  OTA 결과 코드
    // ============================================================

    /// @brief OTA 결과 코드 (STATUS_RSP 페이로드)
    enum class OTA_Result : uint8_t {
        OK = 0x00u,    ///< 성공
        IN_PROGRESS = 0x01u,    ///< 수신 중
        CRC_FAIL = 0x02u,    ///< CRC 검증 실패
        VERSION_FAIL = 0x03u,    ///< 롤백 방지 위반
        SIZE_FAIL = 0x04u,    ///< 이미지 크기 초과
        SEQUENCE_FAIL = 0x05u,    ///< 청크 시퀀스 오류
        FLASH_FAIL = 0x06u,    ///< Flash 기록 실패
        SIGNATURE_FAIL = 0x07u,    ///< 서명 검증 실패
        NOT_READY = 0x08u     ///< 업데이트 미시작 상태
    };

    // ============================================================
    //  Flash 뱅크 상수
    // ============================================================

    /// Flash Bank B 시작 주소 (수신 영역)
    static constexpr uint32_t OTA_BANK_B_BASE = 0x08080000u;
    /// 뱅크 크기 (512KB)
    static constexpr uint32_t OTA_BANK_SIZE = 512u * 1024u;  ///< 524,288B
    /// 청크 최대 크기 (IPC 페이로드 제한)
    static constexpr uint32_t OTA_CHUNK_MAX_SIZE = 240u;
    /// OTA 헤더 크기: CMD(1)+SEQ(2)+TOTAL(2)+LEN(1) = 6
    static constexpr uint32_t OTA_FRAME_HEADER_SIZE = 6u;
    /// CRC 후미
    static constexpr uint32_t OTA_FRAME_CRC_SIZE = 2u;
    /// 최대 청크 수 (512KB / 240B = 2185, 여유 포함)
    static constexpr uint32_t OTA_MAX_CHUNKS = 2200u;

    /// Flash 섹터 크기 (STM32F407: 128KB 섹터 4개 = Bank B)
    static constexpr uint32_t OTA_SECTOR_SIZE = 128u * 1024u;
    /// Bank B 섹터 수
    static constexpr uint32_t OTA_SECTOR_COUNT = 4u;

    // ============================================================
    //  OTA 이미지 헤더 (BEGIN 페이로드)
    // ============================================================

    /// @brief OTA 이미지 메타데이터 (BEGIN 명령 페이로드)
    struct OTA_ImageHeader {
        uint32_t total_size;        ///< 이미지 총 크기 (바이트)
        uint32_t fw_version;        ///< 펌웨어 버전 (major<<16 | minor<<8 | patch)
        uint32_t expected_crc32;    ///< 이미지 전체 CRC-32
        uint16_t total_chunks;      ///< 총 청크 수
        uint16_t chunk_size;        ///< 청크 크기 (마지막 청크 제외)
    };
    static_assert(sizeof(OTA_ImageHeader) == 16u, "OTA_ImageHeader must be 16 bytes");

    // ============================================================
    //  Flash HAL 콜백
    // ============================================================

    /// @brief Flash 하드웨어 추상 계층 콜백
    /// @note  ASIC에서는 내부 Flash 컨트롤러 레지스터로 대체.
    struct OTA_Flash_Callbacks {
        /// @brief Flash 섹터 소거
        /// @param sector_addr  섹터 시작 주소
        /// @return 성공 시 true
        bool (*erase_sector)(uint32_t sector_addr);

        /// @brief Flash 기록 (워드 단위)
        /// @param addr    기록 주소 (4바이트 정렬)
        /// @param data    데이터
        /// @param len     길이 (바이트, 4의 배수)
        /// @return 성공 시 true
        bool (*write_flash)(uint32_t addr, const uint8_t* data, uint32_t len);

        /// @brief Flash 읽기
        /// @param addr    읽기 주소
        /// @param buf     출력 버퍼
        /// @param len     길이
        /// @return 성공 시 true
        bool (*read_flash)(uint32_t addr, uint8_t* buf, uint32_t len);

        /// @brief 뱅크 스왑 실행 (SYSCFG + 리셋)
        /// @note  이 함수 호출 후 시스템은 리부팅됨 ([[noreturn]] 권장)
        void (*execute_bank_swap)(void);

        /// @brief 현재 운용 펌웨어 버전 조회
        uint32_t(*get_current_fw_version)(void);
    };

    // ============================================================
    //  OTA CFI 상태
    // ============================================================

    /// @brief OTA 상태 (비트마스크, CFI 검증)
    enum class OTA_State : uint8_t {
        IDLE = 0x00u,    ///< 대기 (업데이트 없음)
        RECEIVING = 0x01u,    ///< 청크 수신 중
        VERIFYING = 0x02u,    ///< 이미지 검증 중
        VERIFIED = 0x04u,    ///< 검증 완료 (커밋 대기)
        COMMITTING = 0x08u,    ///< 뱅크 스왑 실행 중
        ERROR = 0x10u     ///< 오류 (중단/재시작 필요)
    };

    static constexpr uint8_t OTA_VALID_STATE_MASK =
        static_cast<uint8_t>(OTA_State::RECEIVING)
        | static_cast<uint8_t>(OTA_State::VERIFYING)
        | static_cast<uint8_t>(OTA_State::VERIFIED)
        | static_cast<uint8_t>(OTA_State::COMMITTING)
        | static_cast<uint8_t>(OTA_State::ERROR);

    inline bool OTA_Is_Valid_State(OTA_State s) noexcept
    {
        const uint8_t v = static_cast<uint8_t>(s);
        if (v == 0u) { return true; }  // IDLE
        if ((v & ~OTA_VALID_STATE_MASK) != 0u) { return false; }
        return ((v & (v - 1u)) == 0u);
    }

    /// @note  IDLE->RECEIVING, RECEIVING->VERIFYING|IDLE|ERROR,
    ///        VERIFYING->VERIFIED|ERROR, VERIFIED->COMMITTING|IDLE,
    ///        COMMITTING->(system reset, no transition out),
    ///        ERROR->IDLE
    inline bool OTA_Is_Legal_Transition(OTA_State from, OTA_State to) noexcept
    {
        if (!OTA_Is_Valid_State(to)) { return false; }

        static constexpr uint8_t k_legal[6] = {
            /* IDLE       -> */ static_cast<uint8_t>(OTA_State::RECEIVING),
            /* RECEIVING  -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(OTA_State::VERIFYING)
              | static_cast<uint8_t>(OTA_State::IDLE)
              | static_cast<uint8_t>(OTA_State::ERROR)),
            /* VERIFYING  -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(OTA_State::VERIFIED)
              | static_cast<uint8_t>(OTA_State::ERROR)),
            /* VERIFIED   -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(OTA_State::COMMITTING)
              | static_cast<uint8_t>(OTA_State::IDLE)),
            /* COMMITTING -> */ 0u,  // No transition out (system reset)
            /* ERROR      -> */ static_cast<uint8_t>(OTA_State::IDLE)
        };

        uint8_t idx;
        switch (from) {
        case OTA_State::IDLE:       idx = 0u; break;
        case OTA_State::RECEIVING:  idx = 1u; break;
        case OTA_State::VERIFYING:  idx = 2u; break;
        case OTA_State::VERIFIED:   idx = 3u; break;
        case OTA_State::COMMITTING: idx = 4u; break;
        case OTA_State::ERROR:      idx = 5u; break;
        default:                    return false;
        }

        if (static_cast<uint8_t>(to) == 0u) {
            // IDLE as target: allowed from RECEIVING, VERIFIED, ERROR
            static constexpr uint8_t k_idle_src = static_cast<uint8_t>(
                static_cast<uint8_t>(OTA_State::RECEIVING)
                | static_cast<uint8_t>(OTA_State::VERIFIED)
                | static_cast<uint8_t>(OTA_State::ERROR));
            return (static_cast<uint8_t>(from) & k_idle_src) != 0u;
        }

        return (k_legal[idx] & static_cast<uint8_t>(to)) != 0u;
    }

} // namespace ProtectedEngine