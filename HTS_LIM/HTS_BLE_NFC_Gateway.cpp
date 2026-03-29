/// @file  HTS_BLE_NFC_Gateway.cpp
/// @brief HTS BLE/NFC Gateway -- Implementation
/// @note  ARM only. Pure ASCII. No PC/server code.
/// @author Lim Young-jun
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_BLE_NFC_Gateway.h"
#include "HTS_IPC_Protocol.h"
#include <new>
#include <atomic>

namespace ProtectedEngine {

    // ============================================================
    //  Endian Helpers (local)
    // ============================================================

    static inline void BLE_Write_U16(uint8_t* b, uint16_t v) noexcept
    {
        b[0] = static_cast<uint8_t>(v >> 8u);
        b[1] = static_cast<uint8_t>(v & 0xFFu);
    }

    static inline void BLE_Write_U32(uint8_t* b, uint32_t v) noexcept
    {
        b[0] = static_cast<uint8_t>(v >> 24u);
        b[1] = static_cast<uint8_t>((v >> 16u) & 0xFFu);
        b[2] = static_cast<uint8_t>((v >> 8u) & 0xFFu);
        b[3] = static_cast<uint8_t>(v & 0xFFu);
    }

    static inline uint16_t BLE_Read_U16(const uint8_t* b) noexcept
    {
        return static_cast<uint16_t>(
            (static_cast<uint16_t>(b[0]) << 8u) | static_cast<uint16_t>(b[1]));
    }

    static inline uint32_t BLE_Read_U32(const uint8_t* b) noexcept
    {
        return (static_cast<uint32_t>(b[0]) << 24u) |
            (static_cast<uint32_t>(b[1]) << 16u) |
            (static_cast<uint32_t>(b[2]) << 8u) |
            static_cast<uint32_t>(b[3]);
    }

    // ============================================================
    //  UART RX Ring Buffer Constants (ISR-safe, lock-free SPSC)
    // ============================================================

    static constexpr uint32_t UART_RING_SIZE = 256u;
    static constexpr uint32_t UART_RING_MASK = UART_RING_SIZE - 1u;
    static_assert((UART_RING_SIZE& UART_RING_MASK) == 0u,
        "UART_RING_SIZE must be power of 2");

    // ============================================================
    //  Impl Structure
    // ============================================================

    struct HTS_BLE_NFC_Gateway::Impl {
        // --- Dependencies ---
        HTS_IPC_Protocol* ipc;
        BLE_UART_TX_Callback uart_tx_cb;
        BLE_RX_Data_Callback rx_data_cb;

        // --- Identity ---
        LocationCode local_location;

        // --- CFI State ---
        BLE_GW_State state;
        uint8_t      cfi_violation_count;
        uint16_t     next_session_id;

        // --- Tick Tracking ---
        uint32_t     current_tick;      ///< Last systick_ms from Tick() -- used by internal methods

        // --- Sessions ---
        BLE_Session sessions[BLE_MAX_SESSIONS];

        // --- UART RX Ring (ISR -> Main, SPSC lock-free) ---
        uint8_t                uart_ring[UART_RING_SIZE];
        std::atomic<uint32_t>  uart_ring_head;  ///< Written by ISR (release)
        std::atomic<uint32_t>  uart_ring_tail;  ///< Written by Main (release)

        // --- Frame Build Buffer ---
        uint8_t frame_buf[BLE_MAX_FRAME_SIZE];

        // --- UART RX Line Buffer (assembled from ring) ---
        uint8_t  uart_line_buf[BLE_UART_RX_BUF_SIZE];
        uint16_t uart_line_pos;

        // ============================================================
        //  CFI Transition
        // ============================================================
        bool Transition_State(BLE_GW_State target) noexcept
        {
            if (!BLE_GW_Is_Legal_Transition(state, target)) {
                if (BLE_GW_Is_Legal_Transition(state, BLE_GW_State::ERROR)) {
                    state = BLE_GW_State::ERROR;
                }
                else {
                    state = BLE_GW_State::OFFLINE;
                }
                cfi_violation_count++;
                return false;
            }
            state = target;
            return true;
        }

        // ============================================================
        //  Session Management
        // ============================================================
        BLE_Session* Find_Session(uint16_t session_id) noexcept
        {
            for (uint32_t i = 0u; i < BLE_MAX_SESSIONS; ++i) {
                if (sessions[i].active != 0u && sessions[i].session_id == session_id) {
                    return &sessions[i];
                }
            }
            return nullptr;
        }

        BLE_Session* Alloc_Session(LinkType link, uint32_t tick) noexcept
        {
            for (uint32_t i = 0u; i < BLE_MAX_SESSIONS; ++i) {
                if (sessions[i].active == 0u) {
                    sessions[i].session_id = next_session_id;
                    next_session_id = static_cast<uint16_t>(
                        (static_cast<uint32_t>(next_session_id) + 1u) & BLE_SESSION_MASK);
                    sessions[i].link_type = link;
                    sessions[i].active = 1u;
                    sessions[i].location = local_location;
                    sessions[i].last_activity_tick = tick;
                    return &sessions[i];
                }
            }
            return nullptr;  // All slots busy
        }

        void Close_Session(BLE_Session& s) noexcept
        {
            s.active = 0u;
            s.session_id = 0u;
            s.link_type = LinkType::NONE;
        }

        uint32_t Count_Active_Sessions() const noexcept
        {
            uint32_t count = 0u;
            for (uint32_t i = 0u; i < BLE_MAX_SESSIONS; ++i) {
                if (sessions[i].active != 0u) { count++; }
            }
            return count;
        }

        void Check_Session_Timeouts(uint32_t tick) noexcept
        {
            for (uint32_t i = 0u; i < BLE_MAX_SESSIONS; ++i) {
                if (sessions[i].active == 0u) { continue; }
                const uint32_t elapsed = tick - sessions[i].last_activity_tick;
                if (elapsed >= BLE_SESSION_TIMEOUT) {
                    Close_Session(sessions[i]);
                }
            }
            // If no active sessions, transition to IDLE
            if (Count_Active_Sessions() == 0u &&
                (static_cast<uint8_t>(state) & static_cast<uint8_t>(BLE_GW_State::CONNECTED)) != 0u)
            {
                Transition_State(BLE_GW_State::IDLE);
            }
        }

        // ============================================================
        //  Build Gateway Frame
        // ============================================================
        uint16_t Build_Frame(BLE_MsgType msg_type, uint16_t session_id,
            const uint8_t* payload, uint16_t payload_len) noexcept
        {
            if (payload_len > BLE_MAX_PAYLOAD) { return 0u; }

            uint32_t pos = 0u;
            frame_buf[pos++] = static_cast<uint8_t>(msg_type);
            BLE_Write_U16(&frame_buf[pos], session_id);  pos += 2u;
            BLE_Write_U32(&frame_buf[pos], local_location.code);  pos += 4u;
            frame_buf[pos++] = static_cast<uint8_t>(payload_len);

            // Copy payload
            if (payload != nullptr) {
                for (uint16_t i = 0u; i < payload_len; ++i) {
                    frame_buf[pos + i] = payload[i];
                }
            }
            pos += static_cast<uint32_t>(payload_len);

            // CRC-16
            const uint16_t crc = IPC_Compute_CRC16(frame_buf, pos);
            BLE_Write_U16(&frame_buf[pos], crc);
            pos += BLE_FRAME_CRC_SIZE;

            return static_cast<uint16_t>(pos);
        }

        // ============================================================
        //  Parse Incoming Gateway Frame
        // ============================================================
        bool Parse_Frame(const uint8_t* data, uint16_t len,
            BLE_MsgType& out_type, uint16_t& out_session,
            LocationCode& out_loc, const uint8_t*& out_payload,
            uint16_t& out_payload_len) const noexcept
        {
            if (data == nullptr) { return false; }
            if (len < BLE_FRAME_HEADER_SIZE + BLE_FRAME_CRC_SIZE) { return false; }

            // CRC validation (overflow-safe)
            const uint32_t data_region = static_cast<uint32_t>(len) - BLE_FRAME_CRC_SIZE;
            const uint16_t computed = IPC_Compute_CRC16(data, data_region);
            const uint16_t received = BLE_Read_U16(&data[data_region]);
            if (computed != received) { return false; }

            out_type = static_cast<BLE_MsgType>(data[0]);
            out_session = BLE_Read_U16(&data[1]);
            out_loc.code = BLE_Read_U32(&data[3]);

            const uint8_t plen = data[7];
            if (plen > BLE_MAX_PAYLOAD) { return false; }

            // Overflow-safe bounds check
            if (data_region < BLE_FRAME_HEADER_SIZE) { return false; }
            if ((data_region - BLE_FRAME_HEADER_SIZE) < static_cast<uint32_t>(plen)) {
                return false;
            }

            out_payload = (plen > 0u) ? &data[BLE_FRAME_HEADER_SIZE] : nullptr;
            out_payload_len = static_cast<uint16_t>(plen);
            return true;
        }

        // ============================================================
        //  Process UART RX Ring (Main context)
        // ============================================================
        void Drain_UART_Ring() noexcept
        {
            const uint32_t head = uart_ring_head.load(std::memory_order_acquire);
            uint32_t tail = uart_ring_tail.load(std::memory_order_relaxed);

            while (tail != head) {
                const uint8_t byte = uart_ring[tail & UART_RING_MASK];
                tail++;

                // Simple line-based protocol: '\n' terminates a line
                if (byte == static_cast<uint8_t>('\n') || byte == static_cast<uint8_t>('\r')) {
                    if (uart_line_pos > 0u) {
                        Process_UART_Line(uart_line_buf, uart_line_pos);
                        uart_line_pos = 0u;
                    }
                }
                else {
                    if (uart_line_pos < BLE_UART_RX_BUF_SIZE) {
                        uart_line_buf[uart_line_pos] = byte;
                        uart_line_pos++;
                    }
                    // Overflow: silently drop excess bytes
                }
            }

            uart_ring_tail.store(tail, std::memory_order_release);
        }

        // ============================================================
        //  Process Single UART Line (AT response / data notification)
        // ============================================================
        void Process_UART_Line(const uint8_t* line, uint16_t len) noexcept
        {
            if (len == 0u) { return; }

            // Detect BLE connection event: "+CONN:OK"
            if (len >= 8u && line[0] == static_cast<uint8_t>('+') &&
                line[1] == static_cast<uint8_t>('C') &&
                line[2] == static_cast<uint8_t>('O') &&
                line[3] == static_cast<uint8_t>('N') &&
                line[4] == static_cast<uint8_t>('N'))
            {
                Handle_Connection_Event(LinkType::BLE);
                return;
            }

            // Detect NFC tag read: "+NFC:TAG:"
            if (len >= 9u && line[0] == static_cast<uint8_t>('+') &&
                line[1] == static_cast<uint8_t>('N') &&
                line[2] == static_cast<uint8_t>('F') &&
                line[3] == static_cast<uint8_t>('C'))
            {
                Handle_Connection_Event(LinkType::NFC);
                return;
            }

            // Detect disconnect: "+DISC"
            if (len >= 5u && line[0] == static_cast<uint8_t>('+') &&
                line[1] == static_cast<uint8_t>('D') &&
                line[2] == static_cast<uint8_t>('I') &&
                line[3] == static_cast<uint8_t>('S') &&
                line[4] == static_cast<uint8_t>('C'))
            {
                Handle_Disconnect_Event();
                return;
            }

            // Data from BLE module: "+DATA:..." -> relay to callback
            if (len >= 6u && line[0] == static_cast<uint8_t>('+') &&
                line[1] == static_cast<uint8_t>('D') &&
                line[2] == static_cast<uint8_t>('A') &&
                line[3] == static_cast<uint8_t>('T') &&
                line[4] == static_cast<uint8_t>('A') &&
                line[5] == static_cast<uint8_t>(':'))
            {
                // Data starts after "+DATA:"
                const uint16_t data_offset = 6u;
                if (len > data_offset && rx_data_cb != nullptr) {
                    BLE_Session* s = Find_Active_BLE_Session();
                    rx_data_cb(BLE_MsgType::TEXT_MESSAGE,
                        &line[data_offset],
                        static_cast<uint16_t>(len - data_offset), s);
                }
            }
        }

        // ============================================================
        //  Connection/Disconnect Handlers
        // ============================================================
        void Handle_Connection_Event(LinkType link) noexcept
        {
            // CFI: IDLE -> CONNECTED
            if ((static_cast<uint8_t>(state) & static_cast<uint8_t>(BLE_GW_State::CONNECTED)) == 0u) {
                if (!Transition_State(BLE_GW_State::CONNECTED)) { return; }
            }
            // Allocate session with ACTUAL current tick (not 0!)
            // If current_tick is 0 (before first Tick()), session will survive
            // because Check_Session_Timeouts uses elapsed = tick - last_activity.
            Alloc_Session(link, current_tick);
        }

        void Handle_Disconnect_Event() noexcept
        {
            // Close most recent session
            for (uint32_t i = 0u; i < BLE_MAX_SESSIONS; ++i) {
                if (sessions[i].active != 0u) {
                    Close_Session(sessions[i]);
                    break;
                }
            }
            if (Count_Active_Sessions() == 0u) {
                Transition_State(BLE_GW_State::IDLE);
            }
        }

        BLE_Session* Find_Active_BLE_Session() noexcept
        {
            for (uint32_t i = 0u; i < BLE_MAX_SESSIONS; ++i) {
                if (sessions[i].active != 0u) { return &sessions[i]; }
            }
            return nullptr;
        }
    };

    // ============================================================
    //  Public API
    // ============================================================

    HTS_BLE_NFC_Gateway::HTS_BLE_NFC_Gateway() noexcept
        : initialized_{ false }
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "HTS_BLE_NFC_Gateway::Impl exceeds IMPL_BUF_SIZE");

        for (uint32_t i = 0u; i < IMPL_BUF_SIZE; ++i) {
            impl_buf_[i] = 0u;
        }
    }

    HTS_BLE_NFC_Gateway::~HTS_BLE_NFC_Gateway() noexcept
    {
        Shutdown();
    }

    IPC_Error HTS_BLE_NFC_Gateway::Initialize(HTS_IPC_Protocol* ipc,
        LocationCode location_code) noexcept
    {
        bool expected = false;
        if (!initialized_.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel))
        {
            return IPC_Error::OK;
        }

        if (ipc == nullptr) {
            initialized_.store(false, std::memory_order_release);
            return IPC_Error::NOT_INITIALIZED;
        }

        Impl* impl = new (impl_buf_) Impl{};

        impl->ipc = ipc;
        impl->uart_tx_cb = nullptr;
        impl->rx_data_cb = nullptr;
        impl->local_location = location_code;
        impl->state = BLE_GW_State::OFFLINE;
        impl->cfi_violation_count = 0u;
        impl->next_session_id = 1u;
        impl->current_tick = 0u;
        impl->uart_line_pos = 0u;

        impl->uart_ring_head.store(0u, std::memory_order_relaxed);
        impl->uart_ring_tail.store(0u, std::memory_order_relaxed);

        for (uint32_t i = 0u; i < BLE_MAX_SESSIONS; ++i) {
            impl->sessions[i].active = 0u;
        }

        impl->Transition_State(BLE_GW_State::IDLE);
        return IPC_Error::OK;
    }

    void HTS_BLE_NFC_Gateway::Shutdown() noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        for (uint32_t i = 0u; i < BLE_MAX_SESSIONS; ++i) {
            impl->sessions[i].active = 0u;
        }
        IPC_Secure_Wipe(impl->frame_buf, BLE_MAX_FRAME_SIZE);
        IPC_Secure_Wipe(impl->uart_line_buf, BLE_UART_RX_BUF_SIZE);
        IPC_Secure_Wipe(impl->uart_ring, UART_RING_SIZE);
        std::atomic_thread_fence(std::memory_order_release);

        impl->state = BLE_GW_State::OFFLINE;
        impl->ipc = nullptr;
        impl->~Impl();
        initialized_.store(false, std::memory_order_release);
    }

    void HTS_BLE_NFC_Gateway::Register_UART_TX(BLE_UART_TX_Callback cb) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        reinterpret_cast<Impl*>(impl_buf_)->uart_tx_cb = cb;
    }

    void HTS_BLE_NFC_Gateway::Register_RX_Callback(BLE_RX_Data_Callback cb) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        reinterpret_cast<Impl*>(impl_buf_)->rx_data_cb = cb;
    }

    void HTS_BLE_NFC_Gateway::Tick(uint32_t systick_ms) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        // Store current tick for use by internal methods (Handle_Connection_Event etc.)
        impl->current_tick = systick_ms;

        // Check if UART ring has new data (activity indicator)
        const uint32_t ring_head = impl->uart_ring_head.load(std::memory_order_acquire);
        const uint32_t ring_tail = impl->uart_ring_tail.load(std::memory_order_relaxed);
        const bool has_uart_activity = (ring_head != ring_tail);

        // Drain UART ring (processes +CONN, +DISC, +DATA etc.)
        impl->Drain_UART_Ring();

        // Update session activity ticks ONLY when real UART data was received.
        // This prevents falsely extending timeout on idle ticks.
        if (has_uart_activity) {
            for (uint32_t i = 0u; i < BLE_MAX_SESSIONS; ++i) {
                if (impl->sessions[i].active != 0u) {
                    impl->sessions[i].last_activity_tick = systick_ms;
                }
            }
        }

        // Check and expire timed-out sessions
        impl->Check_Session_Timeouts(systick_ms);
    }

    void HTS_BLE_NFC_Gateway::Feed_UART_Byte(uint8_t byte) noexcept
    {
        if (!initialized_.load(std::memory_order_relaxed)) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        const uint32_t head = impl->uart_ring_head.load(std::memory_order_relaxed);
        const uint32_t tail = impl->uart_ring_tail.load(std::memory_order_acquire);

        // Ring full check
        if ((head - tail) >= UART_RING_SIZE) { return; }

        impl->uart_ring[head & UART_RING_MASK] = byte;
        impl->uart_ring_head.store(head + 1u, std::memory_order_release);
    }

    void HTS_BLE_NFC_Gateway::Relay_From_BCDMA(const uint8_t* payload,
        uint16_t len) noexcept
    {
        if (payload == nullptr) { return; }
        if (len == 0u) { return; }
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        // Parse incoming gateway frame
        BLE_MsgType msg_type = BLE_MsgType::TEXT_MESSAGE;
        uint16_t session_id = 0u;
        LocationCode loc{};
        const uint8_t* frame_payload = nullptr;
        uint16_t frame_payload_len = 0u;

        if (!impl->Parse_Frame(payload, len, msg_type, session_id,
            loc, frame_payload, frame_payload_len)) {
            return;
        }

        // Forward to BLE/NFC module via UART
        if (impl->uart_tx_cb != nullptr && frame_payload != nullptr && frame_payload_len > 0u) {
            impl->uart_tx_cb(frame_payload, frame_payload_len);
        }

        // Update session activity -- B-CDMA data arrival is real activity.
        // Use impl->current_tick (set by last Tick() call).
        BLE_Session* s = impl->Find_Session(session_id);
        if (s != nullptr) {
            s->last_activity_tick = impl->current_tick;
        }
    }

    IPC_Error HTS_BLE_NFC_Gateway::Send_Text(const uint8_t* text, uint16_t text_len,
        uint16_t session_id) noexcept
    {
        if (text == nullptr && text_len > 0u) { return IPC_Error::BUFFER_OVERFLOW; }
        if (text_len > BLE_MAX_PAYLOAD) { return IPC_Error::INVALID_LEN; }
        if (!initialized_.load(std::memory_order_acquire)) { return IPC_Error::NOT_INITIALIZED; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        if (impl->ipc == nullptr) { return IPC_Error::NOT_INITIALIZED; }

        // CFI: CONNECTED -> TRANSFERRING
        if (!impl->Transition_State(BLE_GW_State::TRANSFERRING)) {
            return IPC_Error::CFI_VIOLATION;
        }

        const uint16_t flen = impl->Build_Frame(
            BLE_MsgType::TEXT_MESSAGE, session_id, text, text_len);
        if (flen == 0u) {
            impl->Transition_State(BLE_GW_State::ERROR);
            return IPC_Error::BUFFER_OVERFLOW;
        }

        const IPC_Error err = impl->ipc->Send_Frame(
            IPC_Command::DATA_TX, impl->frame_buf, flen);

        // CFI: TRANSFERRING -> CONNECTED
        if (err != IPC_Error::OK) {
            impl->Transition_State(BLE_GW_State::ERROR);
            return err;
        }
        impl->Transition_State(BLE_GW_State::CONNECTED);

        // Update session activity (outbound data = real activity)
        BLE_Session* s = impl->Find_Session(session_id);
        if (s != nullptr) { s->last_activity_tick = impl->current_tick; }

        return IPC_Error::OK;
    }

    IPC_Error HTS_BLE_NFC_Gateway::Send_Voice_Trigger(uint16_t voice_index,
        uint16_t session_id) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return IPC_Error::NOT_INITIALIZED; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        if (impl->ipc == nullptr) { return IPC_Error::NOT_INITIALIZED; }

        if (!impl->Transition_State(BLE_GW_State::TRANSFERRING)) {
            return IPC_Error::CFI_VIOLATION;
        }

        uint8_t payload[2];
        BLE_Write_U16(payload, voice_index);

        const uint16_t flen = impl->Build_Frame(
            BLE_MsgType::VOICE_TRIGGER, session_id, payload, 2u);
        if (flen == 0u) {
            impl->Transition_State(BLE_GW_State::ERROR);
            return IPC_Error::BUFFER_OVERFLOW;
        }

        const IPC_Error err = impl->ipc->Send_Frame(
            IPC_Command::DATA_TX, impl->frame_buf, flen);

        if (err != IPC_Error::OK) {
            impl->Transition_State(BLE_GW_State::ERROR);
            return err;
        }
        impl->Transition_State(BLE_GW_State::CONNECTED);

        BLE_Session* sv = impl->Find_Session(session_id);
        if (sv != nullptr) { sv->last_activity_tick = impl->current_tick; }

        return IPC_Error::OK;
    }

    IPC_Error HTS_BLE_NFC_Gateway::Send_Emergency(uint16_t session_id) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return IPC_Error::NOT_INITIALIZED; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        if (impl->ipc == nullptr) { return IPC_Error::NOT_INITIALIZED; }

        if (!impl->Transition_State(BLE_GW_State::TRANSFERRING)) {
            return IPC_Error::CFI_VIOLATION;
        }

        const uint16_t flen = impl->Build_Frame(
            BLE_MsgType::EMERGENCY_CALL, session_id, nullptr, 0u);
        if (flen == 0u) {
            impl->Transition_State(BLE_GW_State::ERROR);
            return IPC_Error::BUFFER_OVERFLOW;
        }

        const IPC_Error err = impl->ipc->Send_Frame(
            IPC_Command::DATA_TX, impl->frame_buf, flen);

        if (err != IPC_Error::OK) {
            impl->Transition_State(BLE_GW_State::ERROR);
            return err;
        }
        impl->Transition_State(BLE_GW_State::CONNECTED);

        BLE_Session* se = impl->Find_Session(session_id);
        if (se != nullptr) { se->last_activity_tick = impl->current_tick; }

        return IPC_Error::OK;
    }

    BLE_GW_State HTS_BLE_NFC_Gateway::Get_State() const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return BLE_GW_State::OFFLINE; }
        return reinterpret_cast<const Impl*>(impl_buf_)->state;
    }

    uint32_t HTS_BLE_NFC_Gateway::Get_Active_Session_Count() const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        return reinterpret_cast<const Impl*>(impl_buf_)->Count_Active_Sessions();
    }

} // namespace ProtectedEngine