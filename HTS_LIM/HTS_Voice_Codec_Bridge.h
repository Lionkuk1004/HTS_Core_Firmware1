#pragma once
/// @file  HTS_Voice_Codec_Bridge.h
/// @brief HTS 음성 코덱 브릿지 -- 보코더 음성 패킹/언패킹
/// @details
///   [양산 수정]
///   VCB-1 [CRIT] PLC: 패킷 손실 시 Comfort Noise 프레임 주입
///   VCB-2 [CRIT] 시퀀스 검증: 역전/중복 패킷 드롭
///   VCB-3 [HIGH] Shutdown impl_buf_ 전체 보안 소거
///   VCB-4 [MED]  생성자 memset 표준 통일
///   VCB-5 [MED]  alignas(8) Pimpl 표준 통일
///   - 패딩 제거 + ASIC ROM 합성 최적화
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_Voice_Codec_Bridge_Defs.h"
#include "HTS_IPC_Protocol_Defs.h"
#include <cstdint>
#include <atomic>

namespace ProtectedEngine {

    class HTS_IPC_Protocol;

    class HTS_Voice_Codec_Bridge final {
    public:
        HTS_Voice_Codec_Bridge() noexcept;
        ~HTS_Voice_Codec_Bridge() noexcept;

        IPC_Error Initialize(HTS_IPC_Protocol* ipc, VocoderCodec codec) noexcept;
        void Shutdown() noexcept;
        IPC_Error Set_Codec(VocoderCodec codec) noexcept;
        void Tick(uint32_t systick_ms) noexcept;

        /// @name TX 경로
        /// @{
        bool Feed_TX_Frame(const uint8_t* frame, uint8_t frame_len) noexcept;
        IPC_Error Start_TX() noexcept;
        IPC_Error Stop_TX() noexcept;
        /// @}

        /// @name RX 경로
        /// @{

        /// @brief 수신 프레임 소비 (ISR/DMA 컨텍스트)
        /// @param[out] out_frame    출력 버퍼
        /// @param      out_buf_size 버퍼 크기
        /// @param[out] out_len      실제 프레임 길이
        /// @return true=유효 프레임 또는 PLC 프레임 제공, false=출력 불가
        /// @note  [VCB-1] 패킷 손실 시 PLC Comfort Noise 프레임 자동 주입.
        ///        연속 PLC_MAX_CONSECUTIVE_LOSS 초과 시 무음(0x00) 전환.
        bool Consume_RX_Frame(uint8_t* out_frame, uint8_t out_buf_size,
            uint8_t& out_len) noexcept;

        void Feed_RX_Packet(const uint8_t* payload, uint16_t len) noexcept;
        IPC_Error Start_RX() noexcept;
        IPC_Error Stop_RX() noexcept;
        /// @}

        /// @name 상태
        /// @{
        VoiceState Get_State() const noexcept;
        VocoderCodec Get_Codec() const noexcept;
        uint32_t Get_TX_Frame_Count() const noexcept;
        uint32_t Get_RX_Frame_Count() const noexcept;
        /// @}

        HTS_Voice_Codec_Bridge(const HTS_Voice_Codec_Bridge&) = delete;
        HTS_Voice_Codec_Bridge& operator=(const HTS_Voice_Codec_Bridge&) = delete;
        HTS_Voice_Codec_Bridge(HTS_Voice_Codec_Bridge&&) = delete;
        HTS_Voice_Codec_Bridge& operator=(HTS_Voice_Codec_Bridge&&) = delete;

        static constexpr uint32_t IMPL_BUF_SIZE = 1024u;

    private:
        struct Impl;
        alignas(8) uint8_t impl_buf_[IMPL_BUF_SIZE];
        std::atomic<bool>  initialized_{ false };
    };

    static_assert(sizeof(HTS_Voice_Codec_Bridge) <= 2048u,
        "HTS_Voice_Codec_Bridge exceeds 2KB SRAM budget");

} // namespace ProtectedEngine