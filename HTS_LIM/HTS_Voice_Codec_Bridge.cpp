/// @file  HTS_Voice_Codec_Bridge.cpp
/// @brief HTS Voice Codec Bridge -- Implementation
///
/// [양산 수정]
///  VCB-1 [CRIT] PLC(Packet Loss Concealment)
///        · Consume_RX_Frame: 패킷 미도착 시 Comfort Noise 프레임 자동 주입
///        · 연속 손실 카운터(plc_consecutive_loss) 추적
///        · PLC_MAX_CONSECUTIVE_LOSS(3) 이내: 이전 프레임 반복 + 감쇠
///        · 초과 시: 무음(0x00) 전환 (보코더 Unvoiced 파라미터)
///        · 정상 프레임 수신 시 카운터 리셋
///  VCB-2 [CRIT] 시퀀스 검증
///        · Unpack_RX: pkt_seq 활성화 + 반원 비교 (SEQ_WINDOW=128)
///        · 역전(과거) 패킷 → 드롭 (rx_seq_drop_count 통계)
///        · 정상 범위 내 미래 패킷 → 수용 + expected_rx_seq 갱신
///  VCB-3 [HIGH] Shutdown impl_buf_ 전체 보안 소거
///  VCB-4 [MED]  생성자 for→memset
///  VCB-5 [MED]  alignas(8) (헤더에서 처리)
///  - 패딩 제거 + ASIC ROM 합성 최적화
///
/// @author Lim Young-jun
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_Voice_Codec_Bridge.h"
#include "HTS_IPC_Protocol.h"
#include <new>
#include <atomic>
#include <cstring>

namespace ProtectedEngine {

    // ============================================================
    //  보안 메모리 소거 (프로젝트 표준)
    // ============================================================
    static void Voice_Secure_Wipe(void* ptr, size_t size) noexcept {
        if (ptr == nullptr || size == 0u) { return; }
        volatile unsigned char* p =
            static_cast<volatile unsigned char*>(ptr);
        for (size_t i = 0u; i < size; ++i) { p[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // ============================================================
    //  Endian Helpers
    // ============================================================
    static inline void Voice_Write_U16(uint8_t* b, uint16_t v) noexcept {
        b[0] = static_cast<uint8_t>(v >> 8u);
        b[1] = static_cast<uint8_t>(v & 0xFFu);
    }
    static inline uint16_t Voice_Read_U16(const uint8_t* b) noexcept {
        return static_cast<uint16_t>(
            (static_cast<uint16_t>(b[0]) << 8u) | static_cast<uint16_t>(b[1]));
    }

    // ============================================================
    //  [VCB-2] 시퀀스 반원 비교 (8비트 래핑 안전)
    //  seq가 expected보다 "미래"이면 true (SEQ_WINDOW 이내)
    //  역전(과거) 패킷이면 false → 드롭
    //
    //  원리: (seq - expected) mod 256 < 128 → 미래
    //        (seq - expected) mod 256 >= 128 → 과거
    //  ASIC: 8비트 감산기 + MSB 비교 = 1 게이트 딜레이
    // ============================================================
    static inline bool Seq_Is_Newer(uint8_t seq, uint8_t expected) noexcept {
        const uint8_t diff = static_cast<uint8_t>(seq - expected);
        return (diff > 0u) && (diff < SEQ_WINDOW);
    }

    // ============================================================
    //  Impl Structure
    // ============================================================
    struct HTS_Voice_Codec_Bridge::Impl {
        HTS_IPC_Protocol* ipc;
        VocoderCodec   codec;
        VocoderProfile profile;
        VoiceState state;
        uint8_t    cfi_violation_count;
        uint8_t    tx_seq;
        uint8_t    pad_;
        uint32_t tx_frame_count;
        uint32_t rx_frame_count;
        uint32_t current_tick;

        // --- TX Double Buffer ---
        uint8_t  tx_buf[VOICE_BUF_COUNT][VOICE_MAX_FRAME_BYTES];
        uint8_t  tx_buf_len[VOICE_BUF_COUNT];
        std::atomic<uint8_t> tx_write_idx;
        std::atomic<bool>    tx_frame_ready;

        // --- RX Double Buffer ---
        uint8_t  rx_buf[VOICE_BUF_COUNT][VOICE_MAX_FRAME_BYTES];
        uint8_t  rx_buf_len[VOICE_BUF_COUNT];
        std::atomic<uint8_t> rx_read_idx;
        std::atomic<bool>    rx_frame_ready;

        // --- [VCB-2] 시퀀스 검증 ---
        uint8_t  expected_rx_seq;       ///< 다음 기대 시퀀스 번호
        uint32_t rx_seq_drop_count;     ///< 드롭된 역전 패킷 수 (통계)

        // --- [VCB-1] PLC 상태 ---
        uint8_t  plc_consecutive_loss;  ///< 연속 프레임 손실 카운터
        uint8_t  last_rx_frame[VOICE_MAX_FRAME_BYTES]; ///< 직전 정상 프레임 사본
        uint8_t  last_rx_frame_len;     ///< 직전 프레임 길이

        // --- Packet Build Buffer ---
        uint8_t pkt_buf[VOICE_MAX_PACKET_SIZE];

        // ============================================================
        //  CFI Transition
        // ============================================================
        bool Transition_State(VoiceState target) noexcept {
            if (!Voice_Is_Legal_Transition(state, target)) {
                if (Voice_Is_Legal_Transition(state, VoiceState::ERROR)) {
                    state = VoiceState::ERROR;
                }
                else {
                    state = VoiceState::OFFLINE;
                }
                cfi_violation_count++;
                return false;
            }
            state = target;
            return true;
        }

        // ============================================================
        //  Lookup Vocoder Profile
        // ============================================================
        static bool Lookup_Profile(VocoderCodec c, VocoderProfile& out) noexcept {
            const uint8_t idx = static_cast<uint8_t>(c);
            if (idx == 0u || idx > 4u) { return false; }
            out = k_vocoder_profiles[idx - 1u];
            return true;
        }

        // ============================================================
        //  Pack TX Frame → IPC Send
        // ============================================================
        void Pack_And_Send() noexcept {
            if (ipc == nullptr) { return; }

            const uint8_t sv = static_cast<uint8_t>(state);
            const bool tx_on =
                ((sv & static_cast<uint8_t>(VoiceState::TX_ACTIVE)) != 0u)
                || ((sv & static_cast<uint8_t>(VoiceState::DUPLEX)) != 0u);
            if (!tx_on) { return; }

            if (!tx_frame_ready.load(std::memory_order_acquire)) { return; }
            tx_frame_ready.store(false, std::memory_order_relaxed);

            const uint8_t w_idx = tx_write_idx.load(std::memory_order_acquire);
            const uint8_t r_idx = static_cast<uint8_t>(w_idx ^ 1u);
            const uint8_t frame_len = tx_buf_len[r_idx];
            if (frame_len == 0u || frame_len > profile.frame_bytes) { return; }

            uint32_t pos = 0u;
            pkt_buf[pos++] = static_cast<uint8_t>(codec);
            pkt_buf[pos++] = tx_seq;
            tx_seq = static_cast<uint8_t>(
                (static_cast<uint32_t>(tx_seq) + 1u) & 0xFFu);
            pkt_buf[pos++] = frame_len;

            for (uint8_t i = 0u; i < frame_len; ++i) {
                pkt_buf[pos + i] = tx_buf[r_idx][i];
            }
            pos += static_cast<uint32_t>(frame_len);

            const uint16_t crc = IPC_Compute_CRC16(pkt_buf, pos);
            Voice_Write_U16(&pkt_buf[pos], crc);
            pos += VOICE_PKT_CRC_SIZE;

            ipc->Send_Frame(IPC_Command::DATA_TX,
                pkt_buf, static_cast<uint16_t>(pos));
            tx_frame_count++;
        }

        // ============================================================
        //  [VCB-1+2] Unpack RX Packet → Double Buffer
        //
        //  기존: pkt_seq 주석 처리 → 도착 순서 무조건 수용
        //  수정: 시퀀스 반원 비교 → 역전 패킷 드롭
        //        정상 수신 시 PLC 카운터 리셋 + 직전 프레임 사본 저장
        // ============================================================
        void Unpack_RX(const uint8_t* payload, uint16_t len) noexcept {
            if (payload == nullptr) { return; }
            if (len < VOICE_PKT_HEADER_SIZE + VOICE_PKT_CRC_SIZE) { return; }

            const uint32_t data_region =
                static_cast<uint32_t>(len) - VOICE_PKT_CRC_SIZE;
            if (data_region < VOICE_PKT_HEADER_SIZE) { return; }
            const uint16_t computed = IPC_Compute_CRC16(payload, data_region);
            const uint16_t received = Voice_Read_U16(&payload[data_region]);
            if (computed != received) { return; }

            const VocoderCodec pkt_codec =
                static_cast<VocoderCodec>(payload[0]);
            const uint8_t pkt_seq = payload[1];
            const uint8_t pkt_frame_len = payload[2];

            if (static_cast<uint8_t>(pkt_codec) !=
                static_cast<uint8_t>(codec)) {
                return;
            }
            if (pkt_frame_len > VOICE_MAX_FRAME_BYTES) { return; }
            if ((data_region - VOICE_PKT_HEADER_SIZE) <
                static_cast<uint32_t>(pkt_frame_len)) {
                return;
            }

            // ── [VCB-2] 시퀀스 검증 ──────────────────────────
            //  반원 비교: pkt_seq가 expected_rx_seq보다 미래이거나 같으면 수용
            //  과거(역전) 패킷 → 드롭 (중복/지연 재전송)
            //  첫 패킷(expected_rx_seq==0, 초기) 시에는 무조건 수용
            if (expected_rx_seq != 0u || rx_frame_count != 0u) {
                if (pkt_seq != expected_rx_seq) {
                    if (!Seq_Is_Newer(pkt_seq, expected_rx_seq)) {
                        rx_seq_drop_count++;
                        return;
                    }
                }
            }
            expected_rx_seq = static_cast<uint8_t>(
                (static_cast<uint32_t>(pkt_seq) + 1u) & 0xFFu);

            // ── RX 더블 버퍼 기록 ─────────────────────────────
            const uint8_t r_idx = rx_read_idx.load(std::memory_order_acquire);
            const uint8_t w_idx = static_cast<uint8_t>(r_idx ^ 1u);

            for (uint8_t i = 0u; i < pkt_frame_len; ++i) {
                rx_buf[w_idx][i] = payload[VOICE_PKT_HEADER_SIZE + i];
            }
            rx_buf_len[w_idx] = pkt_frame_len;

            rx_read_idx.store(w_idx, std::memory_order_release);
            rx_frame_ready.store(true, std::memory_order_release);
            rx_frame_count++;

            // ── [VCB-1] PLC: 정상 프레임 사본 저장 + 카운터 리셋 ─
            for (uint8_t i = 0u; i < pkt_frame_len; ++i) {
                last_rx_frame[i] = payload[VOICE_PKT_HEADER_SIZE + i];
            }
            last_rx_frame_len = pkt_frame_len;
            plc_consecutive_loss = 0u;
        }
    };

    // ============================================================
    //  Public API
    // ============================================================

    HTS_Voice_Codec_Bridge::HTS_Voice_Codec_Bridge() noexcept
        : initialized_{ false }
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "HTS_Voice_Codec_Bridge::Impl exceeds IMPL_BUF_SIZE");
        std::memset(impl_buf_, 0, IMPL_BUF_SIZE);
    }

    HTS_Voice_Codec_Bridge::~HTS_Voice_Codec_Bridge() noexcept {
        Shutdown();
    }

    IPC_Error HTS_Voice_Codec_Bridge::Initialize(
        HTS_IPC_Protocol* ipc, VocoderCodec codec) noexcept
    {
        bool expected = false;
        if (!initialized_.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
            return IPC_Error::OK;
        }
        if (ipc == nullptr) {
            initialized_.store(false, std::memory_order_release);
            return IPC_Error::NOT_INITIALIZED;
        }

        Impl* impl = new (impl_buf_) Impl{};
        impl->ipc = ipc;
        impl->codec = codec;

        if (!Impl::Lookup_Profile(codec, impl->profile)) {
            impl->~Impl();
            initialized_.store(false, std::memory_order_release);
            return IPC_Error::INVALID_CMD;
        }

        impl->state = VoiceState::OFFLINE;
        impl->cfi_violation_count = 0u;
        impl->tx_seq = 0u;
        impl->tx_frame_count = 0u;
        impl->rx_frame_count = 0u;
        impl->current_tick = 0u;

        impl->tx_write_idx.store(0u, std::memory_order_relaxed);
        impl->tx_frame_ready.store(false, std::memory_order_relaxed);
        impl->rx_read_idx.store(0u, std::memory_order_relaxed);
        impl->rx_frame_ready.store(false, std::memory_order_relaxed);

        for (uint32_t b = 0u; b < VOICE_BUF_COUNT; ++b) {
            impl->tx_buf_len[b] = 0u;
            impl->rx_buf_len[b] = 0u;
        }

        // [VCB-2] 시퀀스 초기화
        impl->expected_rx_seq = 0u;
        impl->rx_seq_drop_count = 0u;

        // [VCB-1] PLC 초기화
        impl->plc_consecutive_loss = 0u;
        impl->last_rx_frame_len = 0u;
        std::memset(impl->last_rx_frame, 0, VOICE_MAX_FRAME_BYTES);

        impl->Transition_State(VoiceState::IDLE);
        return IPC_Error::OK;
    }

    // [VCB-3] Shutdown: impl_buf_ 전체 보안 소거
    void HTS_Voice_Codec_Bridge::Shutdown() noexcept {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        impl->state = VoiceState::OFFLINE;
        impl->ipc = nullptr;
        impl->~Impl();
        Voice_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
        initialized_.store(false, std::memory_order_release);
    }

    IPC_Error HTS_Voice_Codec_Bridge::Set_Codec(VocoderCodec codec) noexcept {
        if (!initialized_.load(std::memory_order_acquire)) {
            return IPC_Error::NOT_INITIALIZED;
        }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        if ((static_cast<uint8_t>(impl->state)
            & static_cast<uint8_t>(VoiceState::IDLE)) == 0u) {
            return IPC_Error::BUSY;
        }
        VocoderProfile new_profile;
        if (!Impl::Lookup_Profile(codec, new_profile)) {
            return IPC_Error::INVALID_CMD;
        }
        impl->codec = codec;
        impl->profile = new_profile;
        // PLC 사본 무효화 (코덱 변경 시 이전 프레임 호환 안 됨)
        impl->last_rx_frame_len = 0u;
        impl->plc_consecutive_loss = 0u;
        return IPC_Error::OK;
    }

    void HTS_Voice_Codec_Bridge::Tick(uint32_t systick_ms) noexcept {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        impl->current_tick = systick_ms;
        impl->Pack_And_Send();
    }

    bool HTS_Voice_Codec_Bridge::Feed_TX_Frame(
        const uint8_t* frame, uint8_t frame_len) noexcept
    {
        if (frame == nullptr) { return false; }
        if (!initialized_.load(std::memory_order_relaxed)) { return false; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        if (frame_len == 0u || frame_len > impl->profile.frame_bytes) {
            return false;
        }

        const uint8_t w_idx = impl->tx_write_idx.load(std::memory_order_relaxed);
        for (uint8_t i = 0u; i < frame_len; ++i) {
            impl->tx_buf[w_idx][i] = frame[i];
        }
        impl->tx_buf_len[w_idx] = frame_len;
        impl->tx_write_idx.store(
            static_cast<uint8_t>(w_idx ^ 1u), std::memory_order_release);
        impl->tx_frame_ready.store(true, std::memory_order_release);
        return true;
    }

    IPC_Error HTS_Voice_Codec_Bridge::Start_TX() noexcept {
        if (!initialized_.load(std::memory_order_acquire)) {
            return IPC_Error::NOT_INITIALIZED;
        }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        const uint8_t sv = static_cast<uint8_t>(impl->state);
        if ((sv & static_cast<uint8_t>(VoiceState::TX_ACTIVE)) != 0u ||
            (sv & static_cast<uint8_t>(VoiceState::DUPLEX)) != 0u) {
            return IPC_Error::OK;
        }
        VoiceState target =
            ((sv & static_cast<uint8_t>(VoiceState::RX_ACTIVE)) != 0u)
            ? VoiceState::DUPLEX : VoiceState::TX_ACTIVE;
        if (!impl->Transition_State(target)) {
            return IPC_Error::CFI_VIOLATION;
        }
        return IPC_Error::OK;
    }

    IPC_Error HTS_Voice_Codec_Bridge::Stop_TX() noexcept {
        if (!initialized_.load(std::memory_order_acquire)) {
            return IPC_Error::NOT_INITIALIZED;
        }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        const uint8_t sv = static_cast<uint8_t>(impl->state);
        if ((sv & (static_cast<uint8_t>(VoiceState::TX_ACTIVE)
            | static_cast<uint8_t>(VoiceState::DUPLEX))) == 0u) {
            return IPC_Error::OK;
        }
        VoiceState target =
            ((sv & static_cast<uint8_t>(VoiceState::DUPLEX)) != 0u)
            ? VoiceState::RX_ACTIVE : VoiceState::IDLE;
        if (!impl->Transition_State(target)) {
            return IPC_Error::CFI_VIOLATION;
        }
        return IPC_Error::OK;
    }

    // ============================================================
    //  [VCB-1] Consume_RX_Frame — PLC(Packet Loss Concealment) 통합
    //
    //  정상 수신: 프레임 복사 + PLC 카운터 리셋 → return true
    //  손실 감지 (rx_frame_ready==false):
    //   ① plc_consecutive_loss < PLC_MAX_CONSECUTIVE_LOSS:
    //      직전 프레임(last_rx_frame) 반복 주입 → return true
    //      보코더가 이전 음성을 자연스럽게 감쇠
    //   ② plc_consecutive_loss >= PLC_MAX_CONSECUTIVE_LOSS:
    //      무음 Comfort Noise(0x00) 주입 → return true
    //      보코더가 Unvoiced/Silent 모드 전환
    //   ③ last_rx_frame_len == 0 (초기 상태, 이전 프레임 없음):
    //      → return false (보코더에 줄 데이터 없음)
    // ============================================================
    bool HTS_Voice_Codec_Bridge::Consume_RX_Frame(
        uint8_t* out_frame, uint8_t out_buf_size, uint8_t& out_len) noexcept
    {
        out_len = 0u;
        if (out_frame == nullptr) { return false; }
        if (!initialized_.load(std::memory_order_relaxed)) { return false; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        // ── 정상 프레임 수신 경로 ────────────────────────────
        if (impl->rx_frame_ready.load(std::memory_order_acquire)) {
            impl->rx_frame_ready.store(false, std::memory_order_relaxed);

            const uint8_t r_idx =
                impl->rx_read_idx.load(std::memory_order_acquire);
            const uint8_t flen = impl->rx_buf_len[r_idx];
            if (flen == 0u || flen > out_buf_size) { return false; }

            for (uint8_t i = 0u; i < flen; ++i) {
                out_frame[i] = impl->rx_buf[r_idx][i];
            }
            out_len = flen;
            // PLC 카운터 리셋 (Unpack_RX에서도 리셋하지만 이중 방어)
            impl->plc_consecutive_loss = 0u;
            return true;
        }

        // ── [VCB-1] 패킷 손실 — PLC 경로 ────────────────────
        //  보코더 ISR은 20ms마다 프레임을 요구함.
        //  아무것도 주지 않으면 보코더가 Glitch/기계음 발생.
        //  PLC: 이전 프레임 반복 또는 무음 주입으로 자연스러운 감쇠.

        // 초기 상태: 이전 프레임이 한 번도 수신된 적 없음
        if (impl->last_rx_frame_len == 0u) { return false; }

        // 출력 버퍼 크기 검사
        if (impl->last_rx_frame_len > out_buf_size) { return false; }

        impl->plc_consecutive_loss++;
        const uint8_t plc_len = impl->last_rx_frame_len;

        if (impl->plc_consecutive_loss <= PLC_MAX_CONSECUTIVE_LOSS) {
            // Phase 1: 직전 프레임 반복 (보코더가 자연 감쇠 처리)
            for (uint8_t i = 0u; i < plc_len; ++i) {
                out_frame[i] = impl->last_rx_frame[i];
            }
        }
        else {
            // Phase 2: Comfort Noise (무음 파라미터)
            // 보코더별 SID(Silence Descriptor) 패턴으로 교체 가능
            for (uint8_t i = 0u; i < plc_len; ++i) {
                out_frame[i] = PLC_SILENCE_BYTE;
            }
        }

        out_len = plc_len;
        return true;
    }

    void HTS_Voice_Codec_Bridge::Feed_RX_Packet(
        const uint8_t* payload, uint16_t len) noexcept
    {
        if (payload == nullptr) { return; }
        if (len == 0u) { return; }
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        impl->Unpack_RX(payload, len);
    }

    IPC_Error HTS_Voice_Codec_Bridge::Start_RX() noexcept {
        if (!initialized_.load(std::memory_order_acquire)) {
            return IPC_Error::NOT_INITIALIZED;
        }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        const uint8_t sv = static_cast<uint8_t>(impl->state);
        if ((sv & static_cast<uint8_t>(VoiceState::RX_ACTIVE)) != 0u ||
            (sv & static_cast<uint8_t>(VoiceState::DUPLEX)) != 0u) {
            return IPC_Error::OK;
        }
        VoiceState target =
            ((sv & static_cast<uint8_t>(VoiceState::TX_ACTIVE)) != 0u)
            ? VoiceState::DUPLEX : VoiceState::RX_ACTIVE;
        if (!impl->Transition_State(target)) {
            return IPC_Error::CFI_VIOLATION;
        }
        return IPC_Error::OK;
    }

    IPC_Error HTS_Voice_Codec_Bridge::Stop_RX() noexcept {
        if (!initialized_.load(std::memory_order_acquire)) {
            return IPC_Error::NOT_INITIALIZED;
        }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        const uint8_t sv = static_cast<uint8_t>(impl->state);
        if ((sv & (static_cast<uint8_t>(VoiceState::RX_ACTIVE)
            | static_cast<uint8_t>(VoiceState::DUPLEX))) == 0u) {
            return IPC_Error::OK;
        }
        VoiceState target =
            ((sv & static_cast<uint8_t>(VoiceState::DUPLEX)) != 0u)
            ? VoiceState::TX_ACTIVE : VoiceState::IDLE;
        if (!impl->Transition_State(target)) {
            return IPC_Error::CFI_VIOLATION;
        }
        return IPC_Error::OK;
    }

    VoiceState HTS_Voice_Codec_Bridge::Get_State() const noexcept {
        if (!initialized_.load(std::memory_order_acquire)) {
            return VoiceState::OFFLINE;
        }
        return reinterpret_cast<const Impl*>(impl_buf_)->state;
    }

    VocoderCodec HTS_Voice_Codec_Bridge::Get_Codec() const noexcept {
        if (!initialized_.load(std::memory_order_acquire)) {
            return VocoderCodec::MELP_600;
        }
        return reinterpret_cast<const Impl*>(impl_buf_)->codec;
    }

    uint32_t HTS_Voice_Codec_Bridge::Get_TX_Frame_Count() const noexcept {
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        return reinterpret_cast<const Impl*>(impl_buf_)->tx_frame_count;
    }

    uint32_t HTS_Voice_Codec_Bridge::Get_RX_Frame_Count() const noexcept {
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        return reinterpret_cast<const Impl*>(impl_buf_)->rx_frame_count;
    }

} // namespace ProtectedEngine