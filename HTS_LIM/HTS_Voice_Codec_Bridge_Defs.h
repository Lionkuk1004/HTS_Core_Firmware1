#pragma once
/// @file  HTS_Voice_Codec_Bridge_Defs.h
/// @brief HTS 음성 코덱 브릿지 공통 정의부
/// @details
///   보코더(MELP/CELP) 파라미터 프레임 B-CDMA 패킹/언패킹.
///
///   [양산 수정]
///   - PLC(Packet Loss Concealment): 프레임 손실 시 Comfort Noise 주입
///   - 시퀀스 검증: 역전/중복 패킷 탐지 + 드롭
///   - 패딩 제거 + ASIC ROM 합성 최적화
///   - 힙 0, float/double 0, 나눗셈 0
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

    static constexpr VocoderProfile k_vocoder_profiles[4] = {
        { VocoderCodec::MELP_600,  7u,   3u, 0u, 23u, 600u  },
        { VocoderCodec::MELP_1200, 11u,  2u, 0u, 23u, 1200u },
        { VocoderCodec::CELP_2400, 54u,  1u, 0u, 23u, 2400u },
        { VocoderCodec::CELP_4800, 108u, 1u, 0u, 23u, 4800u }
    };

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

    inline bool Voice_Is_Valid_State(VoiceState s) noexcept {
        const uint8_t v = static_cast<uint8_t>(s);
        if (v == 0u) { return true; }
        if ((v & ~VOICE_VALID_STATE_MASK) != 0u) { return false; }
        return ((v & (v - 1u)) == 0u);
    }

    inline bool Voice_Is_Legal_Transition(VoiceState from, VoiceState to) noexcept {
        if (!Voice_Is_Valid_State(to)) { return false; }

        static constexpr uint8_t k_legal[6] = {
            /* OFFLINE    */ static_cast<uint8_t>(VoiceState::IDLE),
            /* IDLE       */ static_cast<uint8_t>(
                static_cast<uint8_t>(VoiceState::TX_ACTIVE)
              | static_cast<uint8_t>(VoiceState::RX_ACTIVE)
              | static_cast<uint8_t>(VoiceState::DUPLEX)
              | static_cast<uint8_t>(VoiceState::OFFLINE)),
            /* TX_ACTIVE  */ static_cast<uint8_t>(
                static_cast<uint8_t>(VoiceState::DUPLEX)
              | static_cast<uint8_t>(VoiceState::IDLE)
              | static_cast<uint8_t>(VoiceState::ERROR)),
            /* RX_ACTIVE  */ static_cast<uint8_t>(
                static_cast<uint8_t>(VoiceState::DUPLEX)
              | static_cast<uint8_t>(VoiceState::IDLE)
              | static_cast<uint8_t>(VoiceState::ERROR)),
            /* DUPLEX     */ static_cast<uint8_t>(
                static_cast<uint8_t>(VoiceState::TX_ACTIVE)
              | static_cast<uint8_t>(VoiceState::RX_ACTIVE)
              | static_cast<uint8_t>(VoiceState::IDLE)
              | static_cast<uint8_t>(VoiceState::ERROR)),
            /* ERROR      */ static_cast<uint8_t>(
                static_cast<uint8_t>(VoiceState::IDLE)
              | static_cast<uint8_t>(VoiceState::OFFLINE))
        };

        uint8_t idx;
        switch (from) {
        case VoiceState::OFFLINE:   idx = 0u; break;
        case VoiceState::IDLE:      idx = 1u; break;
        case VoiceState::TX_ACTIVE: idx = 2u; break;
        case VoiceState::RX_ACTIVE: idx = 3u; break;
        case VoiceState::DUPLEX:    idx = 4u; break;
        case VoiceState::ERROR:     idx = 5u; break;
        default:                    return false;
        }

        if (static_cast<uint8_t>(to) == 0u) {
            static constexpr uint8_t k_off_src = static_cast<uint8_t>(
                static_cast<uint8_t>(VoiceState::IDLE)
                | static_cast<uint8_t>(VoiceState::ERROR));
            return (static_cast<uint8_t>(from) & k_off_src) != 0u;
        }

        return (k_legal[idx] & static_cast<uint8_t>(to)) != 0u;
    }

} // namespace ProtectedEngine