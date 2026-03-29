#pragma once
/// @file  HTS_Network_Bridge_Defs.h
/// @brief HTS 네트워크 브릿지 공통 정의부
/// @details
///   Ethernet MAC 프레임을 B-CDMA 페이로드 크기로 분할(fragmentation) 및
///   재조립(reassembly)하는 브릿지 프로토콜의 상수, 프레임 구조를 정의한다.
///
///   분할 프레임 구조 (B-CDMA 페이로드 내부):
///   @code
///   [FRAG_FLAGS(1)][FRAG_SEQ(1)][FRAG_TOTAL(1)][FRAG_IDX(1)][PAYLOAD(N)]
///   FRAG_FLAGS: bit0=MORE_FRAGMENTS, bit1=FIRST, bit2=LAST
///   FRAG_SEQ:   프레임 시퀀스 번호 (0~255 순환)
///   FRAG_TOTAL: 이 프레임의 총 분할 수
///   FRAG_IDX:   이 분할의 인덱스 (0-based)
///   @endcode
///
///   설계 기준:
///   - Cortex-M4F 양산 + ASIC 기준
///   - 최대 이더넷 프레임 1518B -> B-CDMA 페이로드 248B -> 최대 7분할
///   - 힙 0, float/double 0, 나눗셈 0 (분할 계산은 시프트+역수곱)
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    // ============================================================
    //  브릿지 프로토콜 상수
    // ============================================================

    /// 이더넷 최대 프레임 크기 (MTU 1500 + MAC 헤더 14 + FCS 4)
    static constexpr uint32_t BRIDGE_ETH_MAX_FRAME = 1518u;

    /// B-CDMA 페이로드에서 분할 헤더를 뺀 순수 데이터 영역
    /// IPC_MAX_PAYLOAD(256) - 분할헤더(4) - 여유(4) = 248
    static constexpr uint32_t BRIDGE_FRAG_HEADER_SIZE = 4u;
    static constexpr uint32_t BRIDGE_FRAG_MAX_DATA = 248u;

    /// 최대 분할 수: ceil(1518 / 248) = 7 (Q16 역수곱: 1518 * 267 >> 16 = 6.12 -> 7)
    static constexpr uint32_t BRIDGE_MAX_FRAGMENTS = 7u;

    /// 분할 시퀀스 마스크 (8비트 순환)
    static constexpr uint8_t  BRIDGE_SEQ_MASK = 0xFFu;

    /// 재조립 타임아웃 (ms) -- 모든 분할이 도착해야 하는 제한 시간
    static constexpr uint32_t BRIDGE_REASSEMBLY_TIMEOUT = 500u;

    /// 동시 재조립 슬롯 수 (2의 거듭제곱)
    static constexpr uint32_t BRIDGE_REASSEMBLY_SLOTS = 4u;
    static constexpr uint32_t BRIDGE_REASSEMBLY_SLOT_MASK = BRIDGE_REASSEMBLY_SLOTS - 1u;
    static_assert((BRIDGE_REASSEMBLY_SLOTS& BRIDGE_REASSEMBLY_SLOT_MASK) == 0u,
        "BRIDGE_REASSEMBLY_SLOTS must be power of 2");

    // ============================================================
    //  분할 플래그 비트
    // ============================================================

    /// @brief 분할 플래그 비트 정의
    namespace FragFlag {
        static constexpr uint8_t MORE_FRAGMENTS = (1u << 0u);   ///< 후속 분할 있음
        static constexpr uint8_t FIRST = (1u << 1u);   ///< 첫 분할
        static constexpr uint8_t LAST = (1u << 2u);   ///< 마지막 분할
        static constexpr uint8_t SINGLE = FIRST | LAST; ///< 분할 없는 단일 프레임
    }  // namespace FragFlag

    // ============================================================
    //  분할 헤더 (와이어 포맷)
    // ============================================================

    /// @brief 분할 프레임 헤더 (4바이트, 와이어 1:1 매핑)
    struct FragHeader {
        uint8_t flags;      ///< 분할 플래그 (FragFlag 비트마스크)
        uint8_t seq;        ///< 프레임 시퀀스 번호
        uint8_t total;      ///< 총 분할 수
        uint8_t index;      ///< 이 분할 인덱스 (0-based)
    };
    static_assert(sizeof(FragHeader) == 4u, "FragHeader must be 4 bytes");

    // ============================================================
    //  재조립 슬롯
    // ============================================================

    /// @brief 단일 재조립 슬롯 (수신 측)
    /// @note  정적 배열. 한 이더넷 프레임의 모든 분할을 모아 재조립.
    ///        SRAM 비용: 1518 + 7 + 8 = ~1533B/슬롯.
    struct ReassemblySlot {
        uint8_t  data[BRIDGE_ETH_MAX_FRAME];            ///< 재조립 버퍼
        uint16_t data_len;                               ///< 현재까지 재조립된 길이
        uint8_t  seq;                                    ///< 프레임 시퀀스 번호
        uint8_t  expected_total;                         ///< 예상 총 분할 수
        uint8_t  received_mask;                          ///< 수신된 분할 비트맵 (최대 7비트)
        uint8_t  active;                                 ///< 슬롯 사용 중 (0/1)
        uint8_t  pad_[2];                                ///< 정렬 패딩
        uint32_t start_tick;                             ///< 첫 분할 수신 시각 (ms)
    };
    static_assert(sizeof(ReassemblySlot) == 1532u, "ReassemblySlot size check");
    static_assert((sizeof(ReassemblySlot) & 3u) == 0u, "ReassemblySlot must be 4-byte aligned");

    // ============================================================
    //  브릿지 CFI 상태
    // ============================================================

    /// @brief 브릿지 상태 (비트마스크, CFI 검증용)
    enum class BridgeState : uint8_t {
        DISABLED = 0x00u,    ///< 브릿지 비활성
        IDLE = 0x01u,    ///< 대기 (활성, 데이터 없음)
        FRAGMENTING = 0x02u,    ///< ETH->B-CDMA 분할 진행 중
        REASSEMBLING = 0x04u,    ///< B-CDMA->ETH 재조립 진행 중
        ERROR = 0x08u     ///< 오류 상태
    };

    /// 유효 BridgeState 비트 합집합
    static constexpr uint8_t BRIDGE_VALID_STATE_MASK =
        static_cast<uint8_t>(BridgeState::IDLE)
        | static_cast<uint8_t>(BridgeState::FRAGMENTING)
        | static_cast<uint8_t>(BridgeState::REASSEMBLING)
        | static_cast<uint8_t>(BridgeState::ERROR);

    /// @brief BridgeState 단일 유효 상태 검증
    inline bool Bridge_Is_Valid_State(BridgeState s) noexcept
    {
        const uint8_t v = static_cast<uint8_t>(s);
        if (v == 0u) { return true; }  // DISABLED is valid
        if ((v & ~BRIDGE_VALID_STATE_MASK) != 0u) { return false; }
        return ((v & (v - 1u)) == 0u);
    }

    /// @brief CFI 검증된 브릿지 상태 전이
    /// @note  합법 전이:
    ///        DISABLED     -> IDLE (활성화)
    ///        IDLE         -> FRAGMENTING | REASSEMBLING | DISABLED
    ///        FRAGMENTING  -> IDLE | ERROR
    ///        REASSEMBLING -> IDLE | ERROR
    ///        ERROR        -> IDLE | DISABLED
    inline bool Bridge_Is_Legal_Transition(BridgeState from, BridgeState to) noexcept
    {
        if (!Bridge_Is_Valid_State(to)) { return false; }

        static constexpr uint8_t k_legal[5] = {
            /* DISABLED     -> */ static_cast<uint8_t>(BridgeState::IDLE),
            /* IDLE         -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(BridgeState::FRAGMENTING)
              | static_cast<uint8_t>(BridgeState::REASSEMBLING)
              | static_cast<uint8_t>(BridgeState::DISABLED)),
            /* FRAGMENTING  -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(BridgeState::IDLE)
              | static_cast<uint8_t>(BridgeState::ERROR)),
            /* REASSEMBLING -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(BridgeState::IDLE)
              | static_cast<uint8_t>(BridgeState::ERROR)),
            /* ERROR        -> */ static_cast<uint8_t>(
                static_cast<uint8_t>(BridgeState::IDLE)
              | static_cast<uint8_t>(BridgeState::DISABLED))
        };

        uint8_t idx;
        switch (from) {
        case BridgeState::DISABLED:     idx = 0u; break;
        case BridgeState::IDLE:         idx = 1u; break;
        case BridgeState::FRAGMENTING:  idx = 2u; break;
        case BridgeState::REASSEMBLING: idx = 3u; break;
        case BridgeState::ERROR:        idx = 4u; break;
        default: return false;
        }

        if (static_cast<uint8_t>(to) == 0u) {
            // DISABLED(0x00) as target: allowed from IDLE(0x01) or ERROR(0x08)
            static constexpr uint8_t k_disabled_sources = static_cast<uint8_t>(
                static_cast<uint8_t>(BridgeState::IDLE)
                | static_cast<uint8_t>(BridgeState::ERROR));  // 0x09
            return (static_cast<uint8_t>(from) & k_disabled_sources) != 0u;
        }

        return (k_legal[idx] & static_cast<uint8_t>(to)) != 0u;
    }

} // namespace ProtectedEngine