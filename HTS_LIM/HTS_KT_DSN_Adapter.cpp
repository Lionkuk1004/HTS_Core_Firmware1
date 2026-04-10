/// @file  HTS_KT_DSN_Adapter.cpp
/// @brief HTS KT DSN Adapter -- CBS/CMAS Disaster Alert Relay Implementation
/// @note  ARM only. Pure ASCII. No PC/server code.
/// @author Lim Young-jun
/// @copyright INNOViD 2026. All rights reserved.

// ARM Cortex-M (STM32) 전용 모듈: 비대상 플랫폼 빌드 차단
// Visual Studio Windows 정적 라이브러리는 _WIN32 로 호스트 단위검증 빌드 허용.
#if (((!defined(__arm__) && !defined(__TARGET_ARCH_ARM) && \
      !defined(__TARGET_ARCH_THUMB) && !defined(__ARM_ARCH)) || \
     defined(__aarch64__)) && !defined(_WIN32))
#error "[HTS_FATAL] HTS_KT_DSN_Adapter는 STM32 전용입니다. A55/서버 빌드에서 제외하십시오."
#endif

#include "HTS_KT_DSN_Adapter.h"
#include "HTS_IPC_Protocol.h"
#include <new>
#include <atomic>
#include <cstddef>

namespace ProtectedEngine {

    static void DSN_Secure_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) { q[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(q) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    struct DSN_Busy_Guard {
        std::atomic_flag& f;
        uint32_t locked;
        explicit DSN_Busy_Guard(std::atomic_flag& flag) noexcept
            : f(flag), locked(HTS_KT_DSN_Adapter::SECURE_FALSE) {
            if (!f.test_and_set(std::memory_order_acquire)) {
                locked = HTS_KT_DSN_Adapter::SECURE_TRUE;
            }
        }
        ~DSN_Busy_Guard() noexcept {
            if (locked == HTS_KT_DSN_Adapter::SECURE_TRUE) {
                f.clear(std::memory_order_release);
            }
        }
    };

    // ============================================================
    //  Endian Helpers
    // ============================================================

    static inline void DSN_Write_U16(uint8_t* b, uint16_t v) noexcept
    {
        b[static_cast<size_t>(0u)] = static_cast<uint8_t>(v >> 8u);
        b[static_cast<size_t>(1u)] = static_cast<uint8_t>(v & 0xFFu);
    }
    static inline void DSN_Write_U32(uint8_t* b, uint32_t v) noexcept
    {
        b[static_cast<size_t>(0u)] = static_cast<uint8_t>(v >> 24u);
        b[static_cast<size_t>(1u)] = static_cast<uint8_t>((v >> 16u) & 0xFFu);
        b[static_cast<size_t>(2u)] = static_cast<uint8_t>((v >> 8u) & 0xFFu);
        b[static_cast<size_t>(3u)] = static_cast<uint8_t>(v & 0xFFu);
    }
    static inline uint16_t DSN_Read_U16(const uint8_t* b) noexcept
    {
        return static_cast<uint16_t>(
            (static_cast<uint16_t>(b[static_cast<size_t>(0u)]) << 8u)
            | static_cast<uint16_t>(b[static_cast<size_t>(1u)]));
    }
    static inline uint32_t DSN_Read_U32(const uint8_t* b) noexcept
    {
        return (static_cast<uint32_t>(b[static_cast<size_t>(0u)]) << 24u) |
            (static_cast<uint32_t>(b[static_cast<size_t>(1u)]) << 16u) |
            (static_cast<uint32_t>(b[static_cast<size_t>(2u)]) << 8u) |
            static_cast<uint32_t>(b[static_cast<size_t>(3u)]);
    }

    /// Wire: [MSG_TYPE(1)][CRC16(2)] — CRC width matches DSN_FRAME_CRC_SIZE.
    static constexpr uint32_t DSN_HEARTBEAT_FRAME_BYTES = 1u + DSN_FRAME_CRC_SIZE;
    static_assert(DSN_HEARTBEAT_FRAME_BYTES == 3u, "DSN heartbeat: 1-byte type + CRC16");

    // ============================================================
    //  Impl Structure
    // ============================================================

    struct HTS_KT_DSN_Adapter::Impl {
        // --- Dependencies ---
        HTS_IPC_Protocol* ipc;

        // --- Identity ---
        uint32_t local_area_code;

        // --- CFI State ---
        DSN_State state;
        uint8_t   cfi_violation_count;
        uint8_t   pad_[2];

        // --- Callbacks ---
        DSN_Receive_Callbacks rx_cb;
        DSN_Channel_Callbacks ch_cb;

        // --- Timing ---
        uint32_t current_tick;
        uint32_t last_heartbeat_tick;
        bool     disaster_mode_active;  ///< BPS/chips overridden for disaster
        uint8_t  pad2_[3];

        // --- Statistics ---
        uint32_t total_alerts_received;

        // --- Active Alerts ---
        DSN_ActiveAlert alerts[DSN_MAX_ACTIVE_ALERTS];

        // --- Frame Build Buffer ---
        uint8_t frame_buf[DSN_MAX_FRAME_SIZE];

        // ============================================================
        //  CFI Transition
        // ============================================================
        uint32_t Transition_State(DSN_State target) noexcept
        {
            if (DSN_Is_Legal_Transition(state, target) != DSN_SECURE_TRUE) {
                if (DSN_Is_Legal_Transition(state, DSN_State::ERROR) == DSN_SECURE_TRUE) {
                    state = DSN_State::ERROR;
                }
                else {
                    state = DSN_State::OFFLINE;
                }
                cfi_violation_count++;
                return HTS_KT_DSN_Adapter::SECURE_FALSE;
            }
            state = target;
            return HTS_KT_DSN_Adapter::SECURE_TRUE;
        }

        // ============================================================
        //  Area Matching
        // ============================================================
        bool Is_Area_Match(uint32_t alert_area) const noexcept
        {
            // Nationwide alert
            if (alert_area == DSN_AREA_NATIONWIDE) { return true; }
            // Exact match
            if (alert_area == local_area_code) { return true; }
            // Province-level match (upper 16 bits)
            if ((alert_area & 0xFFFF0000u) == (local_area_code & 0xFFFF0000u) &&
                (alert_area & 0x0000FFFFu) == 0u)
            {
                return true;
            }
            return false;
        }

        // ============================================================
        //  Process Incoming DSN Message
        // ============================================================
        void Process_Message(const uint8_t* data, uint16_t len) noexcept
        {
            // Untrusted input validation first
            if (data == nullptr) { return; }
            if (len < DSN_FRAME_HEADER_SIZE + DSN_FRAME_CRC_SIZE) { return; }

            // CRC validation (overflow-safe)
            const uint32_t data_region = static_cast<uint32_t>(len) - DSN_FRAME_CRC_SIZE;
            if (data_region < DSN_FRAME_HEADER_SIZE) { return; }
            const uint16_t computed = IPC_Compute_CRC16(data, data_region);
            const uint16_t received = DSN_Read_U16(
                &data[static_cast<size_t>(data_region)]);
            if (computed != received) { return; }

            // Parse header
            const DSN_MsgType msg_type =
                static_cast<DSN_MsgType>(data[static_cast<size_t>(0u)]);
            const uint16_t disaster_code = DSN_Read_U16(
                &data[static_cast<size_t>(1u)]);
            const DSN_Severity severity =
                static_cast<DSN_Severity>(data[static_cast<size_t>(3u)]);
            const uint32_t area_code = DSN_Read_U32(
                &data[static_cast<size_t>(4u)]);
            const uint32_t timestamp = DSN_Read_U32(
                &data[static_cast<size_t>(8u)]);
            const uint8_t payload_len = data[static_cast<size_t>(12u)];

            // Payload bounds (overflow-safe)
            if (payload_len > DSN_MAX_TEXT_LEN) { return; }
            if ((data_region - DSN_FRAME_HEADER_SIZE) < static_cast<uint32_t>(payload_len)) {
                return;
            }

            const uint8_t* payload = (payload_len > 0u)
                ? &data[static_cast<size_t>(DSN_FRAME_HEADER_SIZE)]
                : nullptr;

            // Area matching
            if (!Is_Area_Match(area_code)) { return; }

            // Dispatch by message type
            switch (msg_type) {
            case DSN_MsgType::CBS_ALERT:
            case DSN_MsgType::CMAS_PRESIDENTIAL:
            case DSN_MsgType::CMAS_EXTREME:
            case DSN_MsgType::CMAS_SEVERE:
            case DSN_MsgType::CMAS_AMBER:
                Handle_Alert(msg_type, disaster_code, severity,
                    area_code, timestamp, payload, payload_len);
                break;

            case DSN_MsgType::CBS_UPDATE:
                Handle_Alert(msg_type, disaster_code, severity,
                    area_code, timestamp, payload, payload_len);
                break;

            case DSN_MsgType::CBS_CANCEL:
                Handle_Cancel(disaster_code, area_code);
                break;

            case DSN_MsgType::CMAS_TEST:
            case DSN_MsgType::HEARTBEAT:
            case DSN_MsgType::STATUS_REPORT:
                // Informational -- no action needed (link keepalive)
                break;

            default:
                break;
            }
        }

        // ============================================================
        //  Handle Alert
        // ============================================================
        void Handle_Alert(DSN_MsgType type, uint16_t disaster_code,
            DSN_Severity severity, uint32_t area_code,
            uint32_t timestamp, const uint8_t* text,
            uint8_t text_len) noexcept
        {
            // CFI: MONITORING -> ALERT_ACTIVE (idempotent if already ALERT_ACTIVE)
            if ((static_cast<uint8_t>(state) &
                static_cast<uint8_t>(DSN_State::ALERT_ACTIVE)) == 0u)
            {
                if (Transition_State(DSN_State::ALERT_ACTIVE) != HTS_KT_DSN_Adapter::SECURE_TRUE) { return; }
            }

            // Store in active alert slot
            DSN_ActiveAlert* slot = Find_Or_Alloc_Alert(disaster_code, area_code);
            if (slot != nullptr) {
                slot->disaster_code = disaster_code;
                slot->severity = severity;
                slot->area_code = area_code;
                slot->timestamp = timestamp;
                slot->received_tick = current_tick;
                slot->retransmit_remain = static_cast<uint8_t>(DSN_ALERT_RETRANSMIT);
                slot->last_retransmit_tick = current_tick;  // Pacing: first retransmit after interval
                slot->active = 1u;
            }

            total_alerts_received++;

            // Engage disaster mode: force low BPS for maximum range
            if (!disaster_mode_active) {
                if (ch_cb.force_bps != nullptr) {
                    ch_cb.force_bps(1200u);
                }
                if (ch_cb.force_spread_chips != nullptr) {
                    ch_cb.force_spread_chips(64u);
                }
                disaster_mode_active = true;
            }

            // Notify application (display/siren)
            if (rx_cb.on_alert != nullptr) {
                rx_cb.on_alert(type, disaster_code, severity, area_code, text, text_len);
            }

            // Relay to B-CDMA via IPC
            Relay_Alert_To_BCDMA(type, disaster_code, severity, area_code,
                timestamp, text, text_len);
        }

        // ============================================================
        //  Handle Cancel
        // ============================================================
        void Handle_Cancel(uint16_t disaster_code, uint32_t area_code) noexcept
        {
            // Deactivate matching alert slots
            for (uint32_t i = 0u; i < DSN_MAX_ACTIVE_ALERTS; ++i) {
                const size_t idx = static_cast<size_t>(i);
                if (alerts[idx].active != 0u &&
                    alerts[idx].disaster_code == disaster_code &&
                    alerts[idx].area_code == area_code)
                {
                    alerts[idx].active = 0u;
                }
            }

            // Notify application
            if (rx_cb.on_cancel != nullptr) {
                rx_cb.on_cancel(disaster_code, area_code);
            }

            // If no active alerts remain, restore normal mode
            if (Count_Active_Alerts() == 0u) {
                if (disaster_mode_active && ch_cb.restore_normal != nullptr) {
                    ch_cb.restore_normal();
                    disaster_mode_active = false;
                }
                Transition_State(DSN_State::MONITORING);
            }
        }

        // ============================================================
        //  Relay Alert to B-CDMA
        // ============================================================
        void Relay_Alert_To_BCDMA(DSN_MsgType type, uint16_t disaster_code,
            DSN_Severity severity, uint32_t area_code,
            uint32_t timestamp, const uint8_t* text,
            uint8_t text_len) noexcept
        {
            if (ipc == nullptr) { return; }

            uint32_t pos = 0u;
            frame_buf[static_cast<size_t>(pos)] = static_cast<uint8_t>(type);
            pos += 1u;
            DSN_Write_U16(&frame_buf[static_cast<size_t>(pos)], disaster_code);
            pos += 2u;
            frame_buf[static_cast<size_t>(pos)] = static_cast<uint8_t>(severity);
            pos += 1u;
            DSN_Write_U32(&frame_buf[static_cast<size_t>(pos)], area_code);
            pos += 4u;
            DSN_Write_U32(&frame_buf[static_cast<size_t>(pos)], timestamp);
            pos += 4u;
            frame_buf[static_cast<size_t>(pos)] = text_len;
            pos += 1u;

            // Copy text payload
            if (text != nullptr) {
                const uint8_t safe_len = (text_len <= DSN_MAX_TEXT_LEN)
                    ? text_len : static_cast<uint8_t>(DSN_MAX_TEXT_LEN);
                for (uint8_t i = 0u; i < safe_len; ++i) {
                    frame_buf[static_cast<size_t>(pos)
                        + static_cast<size_t>(i)] = text[i];
                }
                pos += static_cast<uint32_t>(safe_len);
            }

            // CRC-16
            const uint16_t crc = IPC_Compute_CRC16(frame_buf, pos);
            DSN_Write_U16(&frame_buf[static_cast<size_t>(pos)], crc);
            pos += DSN_FRAME_CRC_SIZE;

            ipc->Send_Frame(IPC_Command::DATA_TX,
                frame_buf, static_cast<uint16_t>(pos));
            DSN_Secure_Wipe(frame_buf, static_cast<size_t>(pos));
        }

        // ============================================================
        //  Alert Slot Management
        // ============================================================
        DSN_ActiveAlert* Find_Or_Alloc_Alert(uint16_t disaster_code,
            uint32_t area_code) noexcept
        {
            // Search existing
            for (uint32_t i = 0u; i < DSN_MAX_ACTIVE_ALERTS; ++i) {
                const size_t idx = static_cast<size_t>(i);
                if (alerts[idx].active != 0u &&
                    alerts[idx].disaster_code == disaster_code &&
                    alerts[idx].area_code == area_code)
                {
                    return &alerts[idx];
                }
            }
            // Allocate free slot
            for (uint32_t i = 0u; i < DSN_MAX_ACTIVE_ALERTS; ++i) {
                const size_t idx = static_cast<size_t>(i);
                if (alerts[idx].active == 0u) {
                    return &alerts[idx];
                }
            }
            return nullptr;  // All slots busy
        }

        uint32_t Count_Active_Alerts() const noexcept
        {
            uint32_t count = 0u;
            for (uint32_t i = 0u; i < DSN_MAX_ACTIVE_ALERTS; ++i) {
                if (alerts[static_cast<size_t>(i)].active != 0u) { count++; }
            }
            return count;
        }

        // ============================================================
        //  Retransmit Pending Alerts
        // ============================================================
        //  Retransmit Pending Alerts (PACED)
        // ============================================================
        //  Each alert has its own last_retransmit_tick.
        //  Retransmission fires only when DSN_RETRANSMIT_INTERVAL (30s)
        //  has elapsed since last send. This distributes retransmissions
        //  over 3 x 30s = 90 seconds, maximizing the chance that
        //  late-joining or intermittently shadowed terminals receive
        //  the disaster alert.
        //
        //  WITHOUT pacing (original bug):
        //    Tick#1: retx #1  Tick#2: retx #2  Tick#3: retx #3 (3ms total!)
        //    → 10 seconds later: new terminal connects → NO alert received!
        //
        //  WITH pacing (fixed):
        //    t=0s: initial send   t=30s: retx #1   t=60s: retx #2   t=90s: retx #3
        //    → terminal connecting at t=45s receives retx #2 at t=60s ✓
        // ============================================================
        void Process_Retransmissions() noexcept
        {
            for (uint32_t i = 0u; i < DSN_MAX_ACTIVE_ALERTS; ++i) {
                const size_t idx = static_cast<size_t>(i);
                if (alerts[idx].active == 0u) { continue; }
                if (alerts[idx].retransmit_remain == 0u) { continue; }

                // Pacing check: has enough time elapsed since last send?
                const uint32_t elapsed =
                    current_tick - alerts[idx].last_retransmit_tick;
                if (elapsed < DSN_RETRANSMIT_INTERVAL) { continue; }

                // Relay again (header only on retransmit, no text duplication)
                Relay_Alert_To_BCDMA(
                    DSN_MsgType::CBS_ALERT,
                    alerts[idx].disaster_code,
                    alerts[idx].severity,
                    alerts[idx].area_code,
                    alerts[idx].timestamp,
                    nullptr, 0u);

                alerts[idx].retransmit_remain--;
                // Drift-free: advance by interval, not overwrite with current_tick
                alerts[idx].last_retransmit_tick += DSN_RETRANSMIT_INTERVAL;
            }

            bool has_pending_retx = false;
            for (uint32_t j = 0u; j < DSN_MAX_ACTIVE_ALERTS; ++j) {
                const size_t jdx = static_cast<size_t>(j);
                if (alerts[jdx].active != 0u &&
                    alerts[jdx].retransmit_remain > 0u)
                {
                    has_pending_retx = true;
                    break;
                }
            }

            if (has_pending_retx) {
                if ((static_cast<uint8_t>(state) &
                    static_cast<uint8_t>(DSN_State::RETRANSMITTING)) == 0u)
                {
                    Transition_State(DSN_State::RETRANSMITTING);
                }
            }
            else if ((static_cast<uint8_t>(state) &
                static_cast<uint8_t>(DSN_State::RETRANSMITTING)) != 0u)
            {
                // All retransmissions done -> back to ALERT_ACTIVE or MONITORING
                if (Count_Active_Alerts() > 0u) {
                    Transition_State(DSN_State::ALERT_ACTIVE);
                }
                else {
                    Transition_State(DSN_State::MONITORING);
                }
            }
        }

        // ============================================================
        //  Expire Old Alerts
        // ============================================================
        void Expire_Alerts() noexcept
        {
            for (uint32_t i = 0u; i < DSN_MAX_ACTIVE_ALERTS; ++i) {
                const size_t idx = static_cast<size_t>(i);
                if (alerts[idx].active == 0u) { continue; }
                const uint32_t elapsed =
                    current_tick - alerts[idx].received_tick;
                if (elapsed >= DSN_ALERT_EXPIRY) {
                    alerts[idx].active = 0u;
                }
            }

            // If no active alerts remain, restore normal
            if (Count_Active_Alerts() == 0u && disaster_mode_active) {
                if (ch_cb.restore_normal != nullptr) {
                    ch_cb.restore_normal();
                }
                disaster_mode_active = false;
                if ((static_cast<uint8_t>(state) &
                    (static_cast<uint8_t>(DSN_State::ALERT_ACTIVE)
                        | static_cast<uint8_t>(DSN_State::RETRANSMITTING))) != 0u)
                {
                    Transition_State(DSN_State::MONITORING);
                }
            }
        }
    };

    // ============================================================
    //  Public API
    // ============================================================

    HTS_KT_DSN_Adapter::HTS_KT_DSN_Adapter() noexcept
        : initialized_{ false }
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "HTS_KT_DSN_Adapter::Impl exceeds IMPL_BUF_SIZE");

        for (uint32_t i = 0u; i < IMPL_BUF_SIZE; ++i) {
            impl_buf_[static_cast<size_t>(i)] = 0u;
        }
    }

    HTS_KT_DSN_Adapter::~HTS_KT_DSN_Adapter() noexcept
    {
        Shutdown();
    }

    IPC_Error HTS_KT_DSN_Adapter::Initialize(HTS_IPC_Protocol* ipc,
        uint32_t area_code) noexcept
    {
        DSN_Busy_Guard guard(op_busy_);
        if (guard.locked != SECURE_TRUE) { return IPC_Error::BUSY; }

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
        impl->local_area_code = area_code;
        impl->state = DSN_State::OFFLINE;
        impl->cfi_violation_count = 0u;
        impl->current_tick = 0u;
        impl->last_heartbeat_tick = 0xFFFFFFFFu;  // Lazy-init sentinel
        impl->disaster_mode_active = false;
        impl->total_alerts_received = 0u;

        impl->rx_cb.on_alert = nullptr;
        impl->rx_cb.on_cancel = nullptr;
        impl->ch_cb.force_bps = nullptr;
        impl->ch_cb.force_spread_chips = nullptr;
        impl->ch_cb.restore_normal = nullptr;

        for (uint32_t i = 0u; i < DSN_MAX_ACTIVE_ALERTS; ++i) {
            impl->alerts[static_cast<size_t>(i)].active = 0u;
        }

        impl->Transition_State(DSN_State::MONITORING);
        return IPC_Error::OK;
    }

    void HTS_KT_DSN_Adapter::Shutdown() noexcept
    {
        DSN_Busy_Guard guard(op_busy_);
        if (guard.locked != SECURE_TRUE) { return; }
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));

        // Restore normal BPS if disaster mode was active
        if (impl->disaster_mode_active && impl->ch_cb.restore_normal != nullptr) {
            impl->ch_cb.restore_normal();
        }

        impl->state = DSN_State::OFFLINE;
        impl->ipc = nullptr;

        initialized_.store(false, std::memory_order_release);

        impl->~Impl();

        DSN_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
    }

    void HTS_KT_DSN_Adapter::Register_Receive_Callbacks(
        const DSN_Receive_Callbacks& cb) noexcept
    {
        DSN_Busy_Guard guard(op_busy_);
        if (guard.locked != SECURE_TRUE) { return; }
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        std::launder(reinterpret_cast<Impl*>(impl_buf_))->rx_cb = cb;
    }

    void HTS_KT_DSN_Adapter::Register_Channel_Callbacks(
        const DSN_Channel_Callbacks& cb) noexcept
    {
        DSN_Busy_Guard guard(op_busy_);
        if (guard.locked != SECURE_TRUE) { return; }
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        std::launder(reinterpret_cast<Impl*>(impl_buf_))->ch_cb = cb;
    }

    void HTS_KT_DSN_Adapter::Feed_DSN_Message(const uint8_t* data,
        uint16_t len) noexcept
    {
        DSN_Busy_Guard guard(op_busy_);
        if (guard.locked != SECURE_TRUE) { return; }
        if (data == nullptr) { return; }
        if (len == 0u) { return; }
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        std::launder(reinterpret_cast<Impl*>(impl_buf_))->Process_Message(data, len);
    }

    void HTS_KT_DSN_Adapter::Tick(uint32_t systick_ms) noexcept
    {
        DSN_Busy_Guard guard(op_busy_);
        if (guard.locked != SECURE_TRUE) { return; }
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        impl->current_tick = systick_ms;

        // Lazy-init timing
        if (impl->last_heartbeat_tick == 0xFFFFFFFFu) {
            impl->last_heartbeat_tick = systick_ms;
            return;
        }

        // OFFLINE: do nothing
        if (static_cast<uint8_t>(impl->state) == 0u) { return; }

        // Retransmissions (disaster alerts repeated for reliability)
        impl->Process_Retransmissions();

        // Expire old alerts (auto-cancel after 1 hour)
        impl->Expire_Alerts();

        // Heartbeat (drift-free)
        if ((systick_ms - impl->last_heartbeat_tick) >= DSN_HEARTBEAT_INTERVAL) {
            if (impl->ipc != nullptr) {
                uint8_t hb[DSN_HEARTBEAT_FRAME_BYTES] = {};
                hb[static_cast<size_t>(0u)] =
                    static_cast<uint8_t>(DSN_MsgType::HEARTBEAT);
                const uint16_t crc = IPC_Compute_CRC16(hb, 1u);
                static_assert(sizeof(hb) >= 1u + DSN_FRAME_CRC_SIZE,
                    "heartbeat buffer must hold type byte + CRC16");
                DSN_Write_U16(&hb[static_cast<size_t>(1u)], crc);
                impl->ipc->Send_Frame(IPC_Command::DATA_TX, hb,
                    static_cast<uint16_t>(sizeof(hb)));
            }
            impl->last_heartbeat_tick += DSN_HEARTBEAT_INTERVAL;
        }
    }

    DSN_State HTS_KT_DSN_Adapter::Get_State() const noexcept
    {
        DSN_Busy_Guard guard(op_busy_);
        if (guard.locked != SECURE_TRUE) { return DSN_State::OFFLINE; }
        if (!initialized_.load(std::memory_order_acquire)) { return DSN_State::OFFLINE; }
        return reinterpret_cast<const Impl*>(impl_buf_)->state;
    }

    uint32_t HTS_KT_DSN_Adapter::Get_Active_Alert_Count() const noexcept
    {
        DSN_Busy_Guard guard(op_busy_);
        if (guard.locked != SECURE_TRUE) { return 0u; }
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        return reinterpret_cast<const Impl*>(impl_buf_)->Count_Active_Alerts();
    }

    uint32_t HTS_KT_DSN_Adapter::Get_Total_Alerts_Received() const noexcept
    {
        DSN_Busy_Guard guard(op_busy_);
        if (guard.locked != SECURE_TRUE) { return 0u; }
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        return reinterpret_cast<const Impl*>(impl_buf_)->total_alerts_received;
    }

} // namespace ProtectedEngine
