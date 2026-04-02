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

/// @file  HTS_AMI_Protocol_Defs.h
/// @brief HTS AMI 프로토콜 공통 정의부 (DLMS/COSEM 경량 프로파일)
/// @details
///   IEC 62056 DLMS/COSEM 표준 기반 경량 AMI 전력량계 프로토콜.
///
///   [국제 수출 대응]
///   - OBIS 레지스트리: constexpr ROM 딕셔너리 → 국가별 테이블 주입
///   - Security Suite: ARIA-GCM(한국) / AES-GCM(글로벌) 콜백 훅
///   - Block Transfer: 48B 초과 응답 자동 청킹 (IEC 62056-53 §7.3)
///
///   설계 기준:
///   - Cortex-M4F 양산 + ASIC ROM 합성
///   - 48바이트 이내 페이로드 (AMI_METER 프리셋)
///   - Q16 고정소수점, float/double 금지, 힙 0, hot path 나눗셈 0
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    // ============================================================
    //  DLMS 서비스 코드
    // ============================================================

    enum class DLMS_Service : uint8_t {
        GET_REQUEST = 0x01u,
        GET_RESPONSE = 0x02u,
        SET_REQUEST = 0x03u,
        SET_RESPONSE = 0x04u,
        ACTION_REQUEST = 0x05u,
        ACTION_RESPONSE = 0x06u,
        EVENT_NOTIFICATION = 0x07u,
        PERIODIC_REPORT = 0x08u,
        BLOCK_TRANSFER = 0x09u    ///< [A3] 블록 전송 프레임
    };

    // ============================================================
    //  DLMS 데이터 타입 (OBIS_DictEntry보다 먼저 선언 — 순서 필수!)
    // ============================================================

    enum class DLMS_DataType : uint8_t {
        UNSIGNED_8 = 0x11u,
        UNSIGNED_16 = 0x12u,
        UNSIGNED_32 = 0x06u,
        SIGNED_16 = 0x10u,
        SIGNED_32 = 0x05u,
        OCTET_STRING = 0x09u,
        DATETIME = 0x19u
    };

    inline uint8_t DLMS_Type_Size(DLMS_DataType t) noexcept
    {
        switch (t) {
        case DLMS_DataType::UNSIGNED_8:  return 1u;
        case DLMS_DataType::UNSIGNED_16: return 2u;
        case DLMS_DataType::SIGNED_16:   return 2u;
        case DLMS_DataType::UNSIGNED_32: return 4u;
        case DLMS_DataType::SIGNED_32:   return 4u;
        case DLMS_DataType::DATETIME:    return 12u;
        default:                         return 0u;
        }
    }

    // ============================================================
    //  OBIS 코드 (Object Identification System)
    // ============================================================

    struct OBIS_Code {
        uint8_t a;
        uint8_t b;
        uint8_t c;
        uint8_t d;
        uint8_t e;
        uint8_t f;
    };
    static_assert(sizeof(OBIS_Code) == 6u, "OBIS_Code must be 6 bytes");

    // [X-5-4/5] 보안 비교 반환형 bool 금지 — uint32_t 마스크 반환
    // 0u: equal, non-zero: different
    inline uint32_t OBIS_Equal(const OBIS_Code& a, const OBIS_Code& b) noexcept
    {
        const uint8_t diff = static_cast<uint8_t>(
            (a.a ^ b.a) | (a.b ^ b.b) | (a.c ^ b.c) |
            (a.d ^ b.d) | (a.e ^ b.e) | (a.f ^ b.f));
        return static_cast<uint32_t>(diff);
    }

    // ============================================================
    //  [A1] OBIS 딕셔너리 — 국가별 테이블 주입
    // ============================================================

    union MeterValueCallback {
        uint32_t(*get_u32)(void);
        uint16_t(*get_u16)(void);
    };

    /// @brief OBIS 딕셔너리 엔트리 (ROM 상주)
    /// @note  DLMS_DataType은 위에서 이미 정의됨 — 선언 순서 보장
    /// @note  Win32(4B fn ptr) vs x64(8B fn ptr)에서 동일 24B — pack(1)+reserved 가변
#pragma pack(push, 1)
    struct OBIS_DictEntry {
        OBIS_Code           obis;       ///< OBIS 코드 (6B)
        DLMS_DataType       data_type;  ///< DLMS 타입 태그
        uint8_t             value_size; ///< 값 바이트 크기 (2 또는 4)
        MeterValueCallback  callback;   ///< 계측값 콜백
        bool                is_u16;     ///< true=get_u16, false=get_u32
#if UINTPTR_MAX == 0xFFFFFFFFu
        uint8_t             reserved[11]; ///< 32-bit: 총 24B
#else
        uint8_t             reserved[7];  ///< 64-bit: 총 24B
#endif
    };
#pragma pack(pop)
    static_assert(sizeof(OBIS_DictEntry) == 24u, "OBIS_DictEntry must be 24 bytes");

    struct OBIS_Dictionary {
        const OBIS_DictEntry* entries;
        uint8_t               count;
        uint8_t               pad[3];
    };
    static_assert(sizeof(OBIS_Dictionary) <= 16u, "OBIS_Dictionary must fit 16 bytes");

    static constexpr uint8_t AMI_MAX_DICT_ENTRIES = 16u;

    // ============================================================
    //  표준 OBIS 코드 레지스트리 (constexpr ROM)
    // ============================================================

    namespace AMI_OBIS {
        static constexpr OBIS_Code ENERGY_IMPORT_TOTAL = { 1u, 0u, 1u, 8u, 0u, 255u };
        static constexpr OBIS_Code ENERGY_EXPORT_TOTAL = { 1u, 0u, 2u, 8u, 0u, 255u };
        static constexpr OBIS_Code VOLTAGE_L1 = { 1u, 0u, 32u, 7u, 0u, 255u };
        static constexpr OBIS_Code VOLTAGE_L2 = { 1u, 0u, 52u, 7u, 0u, 255u };
        static constexpr OBIS_Code VOLTAGE_L3 = { 1u, 0u, 72u, 7u, 0u, 255u };
        static constexpr OBIS_Code CURRENT_L1 = { 1u, 0u, 31u, 7u, 0u, 255u };
        static constexpr OBIS_Code CURRENT_L2 = { 1u, 0u, 51u, 7u, 0u, 255u };
        static constexpr OBIS_Code CURRENT_L3 = { 1u, 0u, 71u, 7u, 0u, 255u };
        static constexpr OBIS_Code ACTIVE_POWER_TOTAL = { 1u, 0u, 1u, 7u, 0u, 255u };
        static constexpr OBIS_Code POWER_FACTOR_TOTAL = { 1u, 0u, 13u, 7u, 0u, 255u };
        static constexpr OBIS_Code FREQUENCY = { 1u, 0u, 14u, 7u, 0u, 255u };
        static constexpr OBIS_Code DEMAND_MAX = { 1u, 0u, 1u, 6u, 0u, 255u };
        static constexpr OBIS_Code METER_DATETIME = { 0u, 0u, 1u, 0u, 0u, 255u };
        static constexpr OBIS_Code METER_UPTIME = { 0u, 0u, 96u, 8u, 0u, 255u };
    }

    // ============================================================
    //  [A2] Security Suite 콜백 (ARIA-GCM / AES-GCM)
    // ============================================================

    struct AMI_SecuritySuite {
        bool (*encrypt)(const uint8_t* plain, uint16_t plain_len,
            uint8_t* cipher, uint16_t* cipher_len,
            uint16_t max_cipher);
        bool (*decrypt)(const uint8_t* cipher, uint16_t cipher_len,
            uint8_t* plain, uint16_t* plain_len,
            uint16_t max_plain);
    };

    // ============================================================
    //  APDU 상수
    // ============================================================

    static constexpr uint32_t AMI_APDU_HEADER_SIZE = 3u;
    static constexpr uint32_t AMI_APDU_CRC_SIZE = 2u;
    static constexpr uint32_t AMI_OBJ_HEADER_SIZE = 8u;
    static constexpr uint32_t AMI_MAX_OBJECTS = 8u;
    static constexpr uint32_t AMI_MAX_APDU_SIZE = 48u;
    static constexpr uint32_t AMI_MAX_VALUE_SIZE = 12u;

    static constexpr uint32_t AMI_SECURITY_OVERHEAD = 28u;
    static constexpr uint32_t AMI_MAX_SECURE_BUF = AMI_MAX_APDU_SIZE + AMI_SECURITY_OVERHEAD;

    static constexpr uint32_t AMI_BLOCK_HEADER_SIZE = 5u;
    static constexpr uint32_t AMI_MAX_BLOCK_DATA = AMI_MAX_APDU_SIZE
        - AMI_BLOCK_HEADER_SIZE
        - AMI_APDU_CRC_SIZE;

    // ============================================================
    //  계측 객체 항목
    // ============================================================

    struct AMI_Object {
        OBIS_Code       obis;
        DLMS_DataType   data_type;
        uint8_t         value_len;
        uint8_t         value[AMI_MAX_VALUE_SIZE];
        uint8_t         padding[4];
    };
    static_assert(sizeof(AMI_Object) == 24u, "AMI_Object must be 24 bytes");
    static_assert((sizeof(AMI_Object) & 3u) == 0u, "AMI_Object must be 4-byte aligned");

    // ============================================================
    //  AMI 세션 CFI 상태
    // ============================================================

    enum class AMI_State : uint8_t {
        OFFLINE = 0x00u,
        IDLE = 0x01u,
        REPORTING = 0x02u,
        PROCESSING = 0x04u,
        BLOCK_SENDING = 0x08u,
        ERROR = 0x10u
    };

    static constexpr uint8_t AMI_VALID_STATE_MASK =
        static_cast<uint8_t>(AMI_State::IDLE)
        | static_cast<uint8_t>(AMI_State::REPORTING)
        | static_cast<uint8_t>(AMI_State::PROCESSING)
        | static_cast<uint8_t>(AMI_State::BLOCK_SENDING)
        | static_cast<uint8_t>(AMI_State::ERROR);

    inline bool AMI_Is_Valid_State(AMI_State s) noexcept
    {
        const uint8_t v = static_cast<uint8_t>(s);
        if (v == 0u) { return true; }
        if ((v & ~AMI_VALID_STATE_MASK) != 0u) { return false; }
        return ((v & (v - 1u)) == 0u);
    }

    inline bool AMI_Is_Legal_Transition(AMI_State from, AMI_State to) noexcept
    {
        if (!AMI_Is_Valid_State(to)) { return false; }

        static constexpr uint8_t k_legal[6] = {
            /* OFFLINE       -> */ static_cast<uint8_t>(AMI_State::IDLE),
            /* IDLE          -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(AMI_State::REPORTING)
              | static_cast<uint8_t>(AMI_State::PROCESSING)
              | static_cast<uint8_t>(AMI_State::OFFLINE)),
            /* REPORTING     -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(AMI_State::IDLE)
              | static_cast<uint8_t>(AMI_State::ERROR)),
            /* PROCESSING    -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(AMI_State::IDLE)
              | static_cast<uint8_t>(AMI_State::BLOCK_SENDING)
              | static_cast<uint8_t>(AMI_State::ERROR)),
            /* BLOCK_SENDING -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(AMI_State::IDLE)
              | static_cast<uint8_t>(AMI_State::ERROR)),
            /* ERROR         -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(AMI_State::IDLE)
              | static_cast<uint8_t>(AMI_State::OFFLINE))
        };

        uint8_t idx;
        switch (from) {
        case AMI_State::OFFLINE:       idx = 0u; break;
        case AMI_State::IDLE:          idx = 1u; break;
        case AMI_State::REPORTING:     idx = 2u; break;
        case AMI_State::PROCESSING:    idx = 3u; break;
        case AMI_State::BLOCK_SENDING: idx = 4u; break;
        case AMI_State::ERROR:         idx = 5u; break;
        default:                       return false;
        }

        if (static_cast<uint8_t>(to) == 0u) {
            static constexpr uint8_t k_offline_sources = static_cast<uint8_t>(
                static_cast<uint8_t>(AMI_State::IDLE)
                | static_cast<uint8_t>(AMI_State::ERROR));
            return (static_cast<uint8_t>(from) & k_offline_sources) != 0u;
        }

        return (k_legal[idx] & static_cast<uint8_t>(to)) != 0u;
    }

} // namespace ProtectedEngine