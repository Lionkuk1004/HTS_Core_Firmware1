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

/// @file  HTS_Voice_Codec_Bridge_Defs.h
/// @brief HTS 음성 코덱 브릿지 공통 정의부
/// @details
///   보코더(MELP/CELP) 파라미터 프레임 — UDP 페이로드 패킹/언패킹.
///
///   - PLC(Packet Loss Concealment): 프레임 손실 시 Comfort Noise 주입
///   - 시퀀스 검증: 역전/중복 패킷 탐지 + 드롭
///   - 패딩 제거 + ASIC ROM 합성 최적화
///   - 힙 0, float/double 0, 나눗셈 0
///
///  [폰 연계: UDP 전용]
///   - Datagram 페이로드 = [codec][seq][len][frame…][CRC16] (빅엔디안 CRC)
///   - 수신: recvfrom → Feed_RX_Packet
///   - 송신: Set_Packet_Tx_Sink 에서 sendto(또는 LWIP udp_send) 콜백 등록 → Tick 시 전달
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    // ============================================================
    //  보코더 코덱 ID
    // ============================================================

    enum class VocoderCodec : uint8_t {
        MELP_600 = 0x01u,
        MELP_1200 = 0x02u,
        CELP_2400 = 0x03u,
        CELP_4800 = 0x04u,
        CODEC_COUNT = 0x05u
    };

    // ============================================================
    //  보코더 프로파일 (constexpr ROM, ASIC: 32B)
    // ============================================================

    struct VocoderProfile {
        VocoderCodec codec_id;
        uint8_t      frame_bytes;
        uint8_t      frames_per_packet;
        uint8_t      reserved;
        uint16_t     frame_period_ms;
        uint16_t     bitrate_bps;
    };
    static_assert(sizeof(VocoderProfile) == 8u, "VocoderProfile must be 8 bytes");

    // frame_period_ms=23: MELP 22.5ms 프레임을 스케줄 정렬용으로 23ms로 패딩
    // (통합 틱·UDP 페이싱과 동일 슬롯; PLC 주석의 22.5ms 물리 프레임과 정합)
    static constexpr VocoderProfile k_vocoder_profiles[] = {
        { VocoderCodec::MELP_600,  7u,   3u, 0u, 23u, 600u  },
        { VocoderCodec::MELP_1200, 11u,  2u, 0u, 23u, 1200u },
        { VocoderCodec::CELP_2400, 54u,  1u, 0u, 23u, 2400u },
        { VocoderCodec::CELP_4800, 108u, 1u, 0u, 23u, 4800u }
    };
    static_assert(
        sizeof(k_vocoder_profiles) / sizeof(k_vocoder_profiles[0])
            == static_cast<size_t>(VocoderCodec::CODEC_COUNT) - 1u,
        "k_vocoder_profiles[] must have CODEC_COUNT-1 entries (one per payload codec)");

    // ============================================================
    //  음성 프레임 상수
    // ============================================================

    static constexpr uint32_t VOICE_PKT_HEADER_SIZE = 3u;
    static constexpr uint32_t VOICE_PKT_CRC_SIZE = 2u;
    static constexpr uint32_t VOICE_MAX_FRAME_BYTES = 108u;
    static constexpr uint32_t VOICE_MAX_FRAMES_PER_PKT = 3u;
    static constexpr uint32_t VOICE_MAX_PACKET_SIZE = 128u;
    static constexpr uint32_t VOICE_BUF_COUNT = 2u;

    // ============================================================
    //  PLC (Packet Loss Concealment) 상수
    // ============================================================

    /// 연속 손실 프레임 허용 한도 — 초과 시 무음 전환
    /// MELP: 3프레임 × 22.5ms = 67.5ms → 자연스러운 감쇠
    static constexpr uint8_t PLC_MAX_CONSECUTIVE_LOSS = 3u;

    /// Comfort Noise 프레임 바이트 값 (보코더별 무음 파라미터)
    /// MELP: 모든 파라미터 0 = 무성음(Unvoiced) + 최소 에너지
    /// CELP: 모든 파라미터 0 = 무음 코드북
    /// 실제 양산 시 보코더 벤더의 SID(Silence Descriptor) 패턴으로 교체
    static constexpr uint8_t PLC_SILENCE_BYTE = 0x00u;

    // ============================================================
    //  시퀀스 검증 상수
    // ============================================================

    /// 시퀀스 윈도우: 이 범위 내의 미래 패킷만 수용
    /// 윈도우 밖 = 과거(역전) 패킷 → 드롭
    /// 8비트 시퀀스 = 256 → 윈도우 128 = 반원 비교
    static constexpr uint8_t SEQ_WINDOW = 128u;

    // ============================================================
    //  CFI 상태
    // ============================================================

    enum class VoiceState : uint8_t {
        OFFLINE = 0x00u,
        IDLE = 0x01u,
        TX_ACTIVE = 0x02u,
        RX_ACTIVE = 0x04u,
        DUPLEX = 0x08u,
        ERROR = 0x10u
    };

    static constexpr uint8_t VOICE_VALID_STATE_MASK =
        static_cast<uint8_t>(VoiceState::IDLE)
        | static_cast<uint8_t>(VoiceState::TX_ACTIVE)
        | static_cast<uint8_t>(VoiceState::RX_ACTIVE)
        | static_cast<uint8_t>(VoiceState::DUPLEX)
        | static_cast<uint8_t>(VoiceState::ERROR);

    /// 목적 상태 OFFLINE(0)은 to_mask 비트 8(0x100)으로 인코딩 — (&) 단일 검사용
    static constexpr uint32_t VOICE_TO_OFFLINE_BIT = 1u << 8u;

    /// @brief 유효 상태: 0(OFFLINE) 또는 마스크 내 단일 비트 플래그
    inline uint32_t Voice_Valid_State_U32(VoiceState s) noexcept {
        const uint32_t v = static_cast<uint32_t>(static_cast<uint8_t>(s));
        const uint32_t mask = static_cast<uint32_t>(VOICE_VALID_STATE_MASK);
        const uint32_t is_zero = static_cast<uint32_t>(v == 0u);
        const uint32_t in_mask = static_cast<uint32_t>((v & ~mask) == 0u);
        const uint32_t one_bit = static_cast<uint32_t>((v & (v - 1u)) == 0u);
        return is_zero | (in_mask & one_bit);
    }

    inline bool Voice_Is_Valid_State(VoiceState s) noexcept {
        return Voice_Valid_State_U32(s) != 0u;
    }

    /// CFI: 정의된 from 상태만 허용 (희소 256엔트리 테이블 대신 ROM 스위치)
    constexpr bool is_legal_voice_from(uint8_t v) noexcept {
        switch (v) {
        case static_cast<uint8_t>(VoiceState::OFFLINE):
        case static_cast<uint8_t>(VoiceState::IDLE):
        case static_cast<uint8_t>(VoiceState::TX_ACTIVE):
        case static_cast<uint8_t>(VoiceState::RX_ACTIVE):
        case static_cast<uint8_t>(VoiceState::DUPLEX):
        case static_cast<uint8_t>(VoiceState::ERROR):
            return true;
        default:
            return false;
        }
    }

    constexpr uint32_t voice_legal_from_allowed_mask(uint8_t from_raw) noexcept {
        switch (from_raw) {
        case static_cast<uint8_t>(VoiceState::OFFLINE):
            return static_cast<uint32_t>(VoiceState::IDLE);
        case static_cast<uint8_t>(VoiceState::IDLE):
            return static_cast<uint32_t>(VoiceState::TX_ACTIVE)
                | static_cast<uint32_t>(VoiceState::RX_ACTIVE)
                | static_cast<uint32_t>(VoiceState::DUPLEX)
                | VOICE_TO_OFFLINE_BIT;
        case static_cast<uint8_t>(VoiceState::TX_ACTIVE):
            return static_cast<uint32_t>(VoiceState::DUPLEX)
                | static_cast<uint32_t>(VoiceState::IDLE)
                | static_cast<uint32_t>(VoiceState::ERROR);
        case static_cast<uint8_t>(VoiceState::RX_ACTIVE):
            return static_cast<uint32_t>(VoiceState::DUPLEX)
                | static_cast<uint32_t>(VoiceState::IDLE)
                | static_cast<uint32_t>(VoiceState::ERROR);
        case static_cast<uint8_t>(VoiceState::DUPLEX):
            return static_cast<uint32_t>(VoiceState::TX_ACTIVE)
                | static_cast<uint32_t>(VoiceState::RX_ACTIVE)
                | static_cast<uint32_t>(VoiceState::IDLE)
                | static_cast<uint32_t>(VoiceState::ERROR);
        case static_cast<uint8_t>(VoiceState::ERROR):
            return static_cast<uint32_t>(VoiceState::IDLE)
                | VOICE_TO_OFFLINE_BIT;
        default:
            return 0u;
        }
    }

    inline bool Voice_Is_Legal_Transition(VoiceState from, VoiceState to) noexcept {
        const uint32_t fv = static_cast<uint32_t>(static_cast<uint8_t>(from));
        const uint32_t tv = static_cast<uint32_t>(static_cast<uint8_t>(to));
        if (!is_legal_voice_from(static_cast<uint8_t>(fv))) {
            return false;
        }
        const uint32_t allowed = voice_legal_from_allowed_mask(static_cast<uint8_t>(fv));
        const uint32_t to_mask = tv
            | (static_cast<uint32_t>(tv == 0u) * VOICE_TO_OFFLINE_BIT);
        const uint32_t to_ok = Voice_Valid_State_U32(to);
        const uint32_t edge_ok = static_cast<uint32_t>((allowed & to_mask) != 0u);
        return (to_ok & edge_ok) != 0u;
    }

} // namespace ProtectedEngine