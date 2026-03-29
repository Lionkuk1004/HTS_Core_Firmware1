/// @file  HTS_CCTV_Security.cpp
/// @brief HTS CCTV Security Coprocessor -- Anti-Hacking Implementation
/// @note  ARM only. Pure ASCII. No PC/server code.
/// @author Lim Young-jun
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_CCTV_Security.h"
#include "HTS_IPC_Protocol.h"
#include <new>
#include <atomic>

namespace ProtectedEngine {

    // ============================================================
    //  Endian Helpers
    // ============================================================

    static inline void Sec_Write_U16(uint8_t* b, uint16_t v) noexcept
    {
        b[0] = static_cast<uint8_t>(v >> 8u);
        b[1] = static_cast<uint8_t>(v & 0xFFu);
    }

    static inline void Sec_Write_U32(uint8_t* b, uint32_t v) noexcept
    {
        b[0] = static_cast<uint8_t>(v >> 24u);
        b[1] = static_cast<uint8_t>((v >> 16u) & 0xFFu);
        b[2] = static_cast<uint8_t>((v >> 8u) & 0xFFu);
        b[3] = static_cast<uint8_t>(v & 0xFFu);
    }

    // ============================================================
    //  HMAC Key Constants
    // ============================================================

    static constexpr uint32_t HMAC_KEY_MAX_LEN = 32u;

    // ============================================================
    //  Impl Structure
    // ============================================================

    struct HTS_CCTV_Security::Impl {
        // --- Dependencies ---
        HTS_IPC_Protocol* ipc;

        // --- Identity ---
        uint32_t camera_id;

        // --- CFI State ---
        CCTV_SecState state;
        uint8_t       cfi_violation_count;
        uint8_t       hmac_key_len;
        uint8_t       pad_;

        // --- HMAC Key ---
        uint8_t hmac_key[HMAC_KEY_MAX_LEN];

        // --- Callbacks ---
        CCTV_Monitor_Callbacks mon_cb;
        CCTV_Auth_Callbacks    auth_cb;

        // --- Timing ---
        uint32_t current_tick;
        uint32_t last_fw_check_tick;
        uint32_t last_stream_check_tick;
        uint32_t last_heartbeat_tick;

        // --- Monitoring State ---
        uint32_t baseline_fw_crc;       ///< Known-good FW CRC (set at init)
        uint32_t baseline_fw_version;   ///< Known-good FW version
        uint32_t last_stream_seq;       ///< Last stream sequence (replay detect)
        uint32_t last_frame_counter;    ///< Last frame counter (frozen detect)
        uint32_t frozen_start_tick;     ///< When freeze was first detected
        uint16_t baseline_resolution;   ///< Known-good resolution
        uint8_t  baseline_codec;        ///< Known-good codec
        uint8_t  login_fail_snapshot;   ///< Last sampled login fail count

        // --- Statistics ---
        uint32_t total_event_count;
        uint32_t critical_event_count;

        // --- Event Log Ring ---
        CCTV_EventLog event_log[CCTV_EVENT_LOG_SIZE];
        uint32_t      log_head;

        // --- Event Frame Build Buffer ---
        uint8_t evt_buf[CCTV_EVT_MAX_FRAME_SIZE];

        // ============================================================
        //  CFI Transition
        // ============================================================
        bool Transition_State(CCTV_SecState target) noexcept
        {
            if (!CCTV_Sec_Is_Legal_Transition(state, target)) {
                if (CCTV_Sec_Is_Legal_Transition(state, CCTV_SecState::ERROR)) {
                    state = CCTV_SecState::ERROR;
                }
                else {
                    state = CCTV_SecState::OFFLINE;
                }
                cfi_violation_count++;
                return false;
            }
            state = target;
            return true;
        }

        // ============================================================
        //  Log Event
        // ============================================================
        void Log_Event(CCTV_EventType evt, CCTV_Severity sev) noexcept
        {
            // Search for existing entry to increment count
            for (uint32_t i = 0u; i < CCTV_EVENT_LOG_SIZE; ++i) {
                CCTV_EventLog& e = event_log[i];
                if (static_cast<uint8_t>(e.event_type) == static_cast<uint8_t>(evt)) {
                    e.count++;
                    e.last_tick = current_tick;
                    if (static_cast<uint8_t>(sev) > static_cast<uint8_t>(e.severity)) {
                        e.severity = sev;
                    }
                    return;
                }
            }

            // New event: write at ring head
            CCTV_EventLog& slot = event_log[log_head & CCTV_EVENT_LOG_MASK];
            slot.event_type = evt;
            slot.severity = sev;
            slot.count = 1u;
            slot.first_tick = current_tick;
            slot.last_tick = current_tick;
            log_head++;
        }

        // ============================================================
        //  Build and Send Event Frame
        // ============================================================
        void Send_Event(CCTV_EventType evt, CCTV_Severity sev,
            const uint8_t* detail, uint8_t detail_len) noexcept
        {
            if (ipc == nullptr) { return; }
            if (detail_len > CCTV_EVT_MAX_DETAIL) { detail_len = static_cast<uint8_t>(CCTV_EVT_MAX_DETAIL); }

            uint32_t pos = 0u;
            evt_buf[pos++] = static_cast<uint8_t>(evt);
            evt_buf[pos++] = static_cast<uint8_t>(sev);
            Sec_Write_U32(&evt_buf[pos], current_tick);   pos += 4u;
            Sec_Write_U32(&evt_buf[pos], camera_id);      pos += 4u;
            evt_buf[pos++] = detail_len;

            // Copy detail
            if (detail != nullptr) {
                for (uint8_t i = 0u; i < detail_len; ++i) {
                    evt_buf[pos + i] = detail[i];
                }
            }
            pos += static_cast<uint32_t>(detail_len);

            // Compute HMAC tag (truncated 4 bytes)
            // Use CRC-16 over (key XOR evt_buf) as lightweight MAC
            // (In production: HTS_HMAC_Bridge with SHA-256 KCMVP)
            uint8_t mac_input[4];
            Compute_Lightweight_MAC(evt_buf, pos, mac_input);
            for (uint32_t i = 0u; i < CCTV_EVT_HMAC_SIZE; ++i) {
                evt_buf[pos + i] = mac_input[i];
            }
            pos += CCTV_EVT_HMAC_SIZE;

            // Log
            Log_Event(evt, sev);
            total_event_count++;
            if (static_cast<uint8_t>(sev) >= static_cast<uint8_t>(CCTV_Severity::CRITICAL)) {
                critical_event_count++;
            }

            // Send via IPC
            ipc->Send_Frame(IPC_Command::DATA_TX,
                evt_buf, static_cast<uint16_t>(pos));
        }

        // ============================================================
        //  Lightweight MAC (CRC-based, placeholder for KCMVP HMAC)
        // ============================================================
        void Compute_Lightweight_MAC(const uint8_t* data, uint32_t len,
            uint8_t out[4]) const noexcept
        {
            // XOR key into first pass, CRC over result
            // This is NOT cryptographically secure -- placeholder for
            // HTS_HMAC_Bridge integration (KCMVP SHA-256 HMAC).
            const uint16_t crc1 = IPC_Compute_CRC16(data, len);
            // Mix with key bytes
            uint16_t crc2 = crc1;
            for (uint8_t i = 0u; i < hmac_key_len; ++i) {
                crc2 ^= static_cast<uint16_t>(
                    static_cast<uint16_t>(hmac_key[i]) << (i & 7u));
            }
            Sec_Write_U16(&out[0], crc1);
            Sec_Write_U16(&out[2], crc2);
        }

        // ============================================================
        //  Periodic Checks
        // ============================================================

        void Check_Firmware_CRC() noexcept
        {
            if (mon_cb.get_fw_crc == nullptr) { return; }
            const uint32_t live_crc = mon_cb.get_fw_crc();
            if (live_crc != baseline_fw_crc && baseline_fw_crc != 0u) {
                uint8_t detail[8];
                Sec_Write_U32(&detail[0], baseline_fw_crc);
                Sec_Write_U32(&detail[4], live_crc);
                Send_Event(CCTV_EventType::FW_CRC_FAIL,
                    CCTV_Severity::EMERGENCY, detail, 8u);
                Transition_State(CCTV_SecState::LOCKDOWN);
            }
        }

        void Check_Firmware_Version() noexcept
        {
            if (mon_cb.get_fw_version == nullptr) { return; }
            const uint32_t live_ver = mon_cb.get_fw_version();
            if (live_ver < baseline_fw_version && baseline_fw_version != 0u) {
                uint8_t detail[8];
                Sec_Write_U32(&detail[0], baseline_fw_version);
                Sec_Write_U32(&detail[4], live_ver);
                Send_Event(CCTV_EventType::FW_ROLLBACK_DETECT,
                    CCTV_Severity::CRITICAL, detail, 8u);
            }
        }

        void Check_Stream_HMAC() noexcept
        {
            if (auth_cb.verify_stream_hmac == nullptr) { return; }
            // Placeholder: in production, fetch frame hash from camera SoC
            // and verify HMAC tag with HTS_HMAC_Bridge.
            // Here we check sequence monotonicity (replay detection).
            if (auth_cb.get_stream_sequence != nullptr) {
                const uint32_t seq = auth_cb.get_stream_sequence();
                if (seq <= last_stream_seq && last_stream_seq != 0u) {
                    Send_Event(CCTV_EventType::STREAM_REPLAY_DETECT,
                        CCTV_Severity::CRITICAL, nullptr, 0u);
                }
                last_stream_seq = seq;
            }
        }

        void Check_Stream_Frozen() noexcept
        {
            if (mon_cb.get_stream_frame_counter == nullptr) { return; }
            const uint32_t fc = mon_cb.get_stream_frame_counter();
            if (fc == last_frame_counter && last_frame_counter != 0u) {
                // Frame counter stalled
                if (frozen_start_tick == 0u) {
                    frozen_start_tick = current_tick;
                }
                else {
                    const uint32_t frozen_elapsed = current_tick - frozen_start_tick;
                    if (frozen_elapsed >= CCTV_STREAM_FROZEN_TIMEOUT) {
                        Send_Event(CCTV_EventType::STREAM_FROZEN,
                            CCTV_Severity::CRITICAL, nullptr, 0u);
                        frozen_start_tick = current_tick;  // Rate limit
                    }
                }
            }
            else {
                frozen_start_tick = 0u;  // Reset on frame activity
            }
            last_frame_counter = fc;
        }

        void Check_Stream_Config() noexcept
        {
            if (mon_cb.get_stream_resolution != nullptr) {
                const uint16_t res = mon_cb.get_stream_resolution();
                if (res != baseline_resolution && baseline_resolution != 0u) {
                    Send_Event(CCTV_EventType::CODEC_MISMATCH,
                        CCTV_Severity::WARNING, nullptr, 0u);
                }
            }
            if (mon_cb.get_stream_codec_id != nullptr) {
                const uint8_t codec = mon_cb.get_stream_codec_id();
                if (codec != baseline_codec && baseline_codec != 0u) {
                    Send_Event(CCTV_EventType::CODEC_MISMATCH,
                        CCTV_Severity::WARNING, nullptr, 0u);
                }
            }
        }

        void Check_Physical_Tamper() noexcept
        {
            if (mon_cb.get_tamper_case != nullptr && mon_cb.get_tamper_case()) {
                Send_Event(CCTV_EventType::TAMPER_CASE_OPEN,
                    CCTV_Severity::EMERGENCY, nullptr, 0u);
                Transition_State(CCTV_SecState::LOCKDOWN);
            }
            if (mon_cb.get_tamper_cable != nullptr && !mon_cb.get_tamper_cable()) {
                // Cable disconnected
                Send_Event(CCTV_EventType::TAMPER_CABLE_CUT,
                    CCTV_Severity::CRITICAL, nullptr, 0u);
            }
            if (mon_cb.get_lens_brightness != nullptr) {
                const uint16_t bright = mon_cb.get_lens_brightness();
                // Sudden darkness (< Q8 threshold 5.0) = lens blocked
                if (bright < static_cast<uint16_t>(5u << 8u)) {
                    Send_Event(CCTV_EventType::TAMPER_LENS_BLOCKED,
                        CCTV_Severity::CRITICAL, nullptr, 0u);
                }
            }
            if (mon_cb.get_accel_magnitude != nullptr) {
                const uint16_t accel = mon_cb.get_accel_magnitude();
                // Sudden high acceleration (> Q8 threshold 3.0g) = forced reorientation
                if (accel > static_cast<uint16_t>(3u << 8u)) {
                    Send_Event(CCTV_EventType::TAMPER_ORIENTATION,
                        CCTV_Severity::WARNING, nullptr, 0u);
                }
            }
        }

        void Check_Network_Intrusion() noexcept
        {
            if (mon_cb.get_login_fail_count != nullptr) {
                const uint32_t fails = mon_cb.get_login_fail_count();
                const uint32_t delta = fails - static_cast<uint32_t>(login_fail_snapshot);
                if (delta >= CCTV_BRUTE_FORCE_THRESHOLD) {
                    Send_Event(CCTV_EventType::NET_BRUTE_FORCE,
                        CCTV_Severity::CRITICAL, nullptr, 0u);
                }
                login_fail_snapshot = static_cast<uint8_t>(fails & 0xFFu);
            }
        }

        void Send_Heartbeat() noexcept
        {
            Send_Event(CCTV_EventType::SYSTEM_HEARTBEAT,
                CCTV_Severity::INFO, nullptr, 0u);
        }
    };

    // ============================================================
    //  Public API
    // ============================================================

    HTS_CCTV_Security::HTS_CCTV_Security() noexcept
        : initialized_{ false }
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "HTS_CCTV_Security::Impl exceeds IMPL_BUF_SIZE");

        for (uint32_t i = 0u; i < IMPL_BUF_SIZE; ++i) {
            impl_buf_[i] = 0u;
        }
    }

    HTS_CCTV_Security::~HTS_CCTV_Security() noexcept
    {
        Shutdown();
    }

    IPC_Error HTS_CCTV_Security::Initialize(HTS_IPC_Protocol* ipc,
        uint32_t camera_id) noexcept
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
        impl->camera_id = camera_id;
        impl->state = CCTV_SecState::OFFLINE;
        impl->cfi_violation_count = 0u;
        impl->hmac_key_len = 0u;
        impl->current_tick = 0u;
        // Sentinel 0xFFFFFFFF = "not yet initialized" -- first Tick() will
        // set these to systick_ms, preventing boot-burst of all checks at once.
        impl->last_fw_check_tick = 0xFFFFFFFFu;
        impl->last_stream_check_tick = 0xFFFFFFFFu;
        impl->last_heartbeat_tick = 0xFFFFFFFFu;
        impl->baseline_fw_crc = 0u;
        impl->baseline_fw_version = 0u;
        impl->last_stream_seq = 0u;
        impl->last_frame_counter = 0u;
        impl->frozen_start_tick = 0u;
        impl->baseline_resolution = 0u;
        impl->baseline_codec = 0u;
        impl->login_fail_snapshot = 0u;
        impl->total_event_count = 0u;
        impl->critical_event_count = 0u;
        impl->log_head = 0u;

        // Zero callbacks
        impl->mon_cb.get_fw_crc = nullptr;
        impl->mon_cb.get_fw_version = nullptr;
        impl->mon_cb.get_stream_frame_counter = nullptr;
        impl->mon_cb.get_stream_resolution = nullptr;
        impl->mon_cb.get_stream_codec_id = nullptr;
        impl->mon_cb.get_tamper_case = nullptr;
        impl->mon_cb.get_tamper_cable = nullptr;
        impl->mon_cb.get_lens_brightness = nullptr;
        impl->mon_cb.get_accel_magnitude = nullptr;
        impl->mon_cb.get_login_fail_count = nullptr;
        impl->mon_cb.get_active_connections = nullptr;
        impl->auth_cb.verify_stream_hmac = nullptr;
        impl->auth_cb.get_stream_sequence = nullptr;

        // CFI: OFFLINE -> MONITORING
        impl->Transition_State(CCTV_SecState::MONITORING);

        // Take initial baselines after first callback registration
        return IPC_Error::OK;
    }

    void HTS_CCTV_Security::Shutdown() noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        // Secure wipe HMAC key
        IPC_Secure_Wipe(impl->hmac_key, HMAC_KEY_MAX_LEN);
        IPC_Secure_Wipe(impl->evt_buf, CCTV_EVT_MAX_FRAME_SIZE);
        std::atomic_thread_fence(std::memory_order_release);

        impl->state = CCTV_SecState::OFFLINE;
        impl->ipc = nullptr;
        impl->~Impl();
        initialized_.store(false, std::memory_order_release);
    }

    void HTS_CCTV_Security::Register_Monitor_Callbacks(
        const CCTV_Monitor_Callbacks& cb) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        impl->mon_cb = cb;

        // Capture baselines on first registration
        if (cb.get_fw_crc != nullptr) {
            impl->baseline_fw_crc = cb.get_fw_crc();
        }
        if (cb.get_fw_version != nullptr) {
            impl->baseline_fw_version = cb.get_fw_version();
        }
        if (cb.get_stream_resolution != nullptr) {
            impl->baseline_resolution = cb.get_stream_resolution();
        }
        if (cb.get_stream_codec_id != nullptr) {
            impl->baseline_codec = cb.get_stream_codec_id();
        }
    }

    void HTS_CCTV_Security::Register_Auth_Callbacks(
        const CCTV_Auth_Callbacks& cb) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        reinterpret_cast<Impl*>(impl_buf_)->auth_cb = cb;
    }

    IPC_Error HTS_CCTV_Security::Set_HMAC_Key(const uint8_t* key,
        uint8_t key_len) noexcept
    {
        if (key == nullptr) { return IPC_Error::INVALID_CMD; }
        if (key_len == 0u || key_len > HMAC_KEY_MAX_LEN) { return IPC_Error::INVALID_LEN; }
        if (!initialized_.load(std::memory_order_acquire)) { return IPC_Error::NOT_INITIALIZED; }

        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        // Wipe old key first
        IPC_Secure_Wipe(impl->hmac_key, HMAC_KEY_MAX_LEN);

        for (uint8_t i = 0u; i < key_len; ++i) {
            impl->hmac_key[i] = key[i];
        }
        impl->hmac_key_len = key_len;
        return IPC_Error::OK;
    }

    void HTS_CCTV_Security::Tick(uint32_t systick_ms) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        impl->current_tick = systick_ms;

        // --- Lazy-init timing on first Tick() call ---
        // Prevents boot-burst: all periodic checks would fire simultaneously
        // if last_*_tick starts at 0 and systick_ms is already past the intervals.
        // Sentinel 0xFFFFFFFF = "never run yet".
        // Stagger initial checks: FW at +0, Stream at +1/3 interval, Heartbeat at +2/3.
        if (impl->last_fw_check_tick == 0xFFFFFFFFu) {
            impl->last_fw_check_tick = systick_ms;
            impl->last_stream_check_tick = systick_ms;
            impl->last_heartbeat_tick = systick_ms;
            return;  // First tick: just initialize, no checks yet
        }

        const uint8_t sv = static_cast<uint8_t>(impl->state);

        // --- OFFLINE: do nothing ---
        if (sv == static_cast<uint8_t>(CCTV_SecState::OFFLINE)) { return; }

        // =================================================================
        //  LOCKDOWN mode: minimal operation only
        //  - Physical tamper: CONTINUE (must detect case re-close or further damage)
        //  - Heartbeat: CONTINUE (keep-alive so control center knows chip is alive)
        //  - FW CRC / Stream / Network: SKIP (camera SoC may be compromised,
        //    polling SPI/I2C could cause bus conflict or information leak)
        // =================================================================
        if ((sv & static_cast<uint8_t>(CCTV_SecState::LOCKDOWN)) != 0u) {
            impl->Check_Physical_Tamper();

            if ((systick_ms - impl->last_heartbeat_tick) >= CCTV_HEARTBEAT_INTERVAL) {
                impl->Send_Heartbeat();
                // Drift-free: advance by interval, not overwrite with systick_ms
                impl->last_heartbeat_tick += CCTV_HEARTBEAT_INTERVAL;
            }
            return;
        }

        // --- ERROR: heartbeat only (signal control center for recovery) ---
        if ((sv & static_cast<uint8_t>(CCTV_SecState::ERROR)) != 0u) {
            if ((systick_ms - impl->last_heartbeat_tick) >= CCTV_HEARTBEAT_INTERVAL) {
                impl->Send_Heartbeat();
                impl->last_heartbeat_tick += CCTV_HEARTBEAT_INTERVAL;
            }
            return;
        }

        // =================================================================
        //  MONITORING / ALERT: full operation
        // =================================================================

        // --- Periodic firmware CRC check ---
        if ((systick_ms - impl->last_fw_check_tick) >= CCTV_FW_CHECK_INTERVAL) {
            impl->Check_Firmware_CRC();
            impl->Check_Firmware_Version();
            // Drift-free advancement: add interval to last tick, not overwrite.
            // If Tick() was delayed (e.g., long ISR), next check fires sooner
            // to catch up, rather than silently extending the interval.
            impl->last_fw_check_tick += CCTV_FW_CHECK_INTERVAL;
        }

        // --- Periodic stream integrity check ---
        if ((systick_ms - impl->last_stream_check_tick) >= CCTV_STREAM_CHECK_INTERVAL) {
            impl->Check_Stream_HMAC();
            impl->Check_Stream_Frozen();
            impl->Check_Stream_Config();
            impl->last_stream_check_tick += CCTV_STREAM_CHECK_INTERVAL;
        }

        // --- Physical tamper (every tick -- real-time critical) ---
        impl->Check_Physical_Tamper();

        // --- Network intrusion (every tick) ---
        impl->Check_Network_Intrusion();

        // --- Heartbeat ---
        if ((systick_ms - impl->last_heartbeat_tick) >= CCTV_HEARTBEAT_INTERVAL) {
            impl->Send_Heartbeat();
            impl->last_heartbeat_tick += CCTV_HEARTBEAT_INTERVAL;
        }
    }

    void HTS_CCTV_Security::Report_Event(CCTV_EventType evt, CCTV_Severity severity,
        const uint8_t* detail,
        uint8_t detail_len) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        impl->Send_Event(evt, severity, detail, detail_len);

        // Auto-escalate to ALERT on WARNING+
        if (static_cast<uint8_t>(severity) >= static_cast<uint8_t>(CCTV_Severity::WARNING)) {
            if ((static_cast<uint8_t>(impl->state) &
                static_cast<uint8_t>(CCTV_SecState::MONITORING)) != 0u)
            {
                impl->Transition_State(CCTV_SecState::ALERT);
            }
        }
        // Auto-escalate to LOCKDOWN on EMERGENCY
        if (static_cast<uint8_t>(severity) >= static_cast<uint8_t>(CCTV_Severity::EMERGENCY)) {
            impl->Transition_State(CCTV_SecState::LOCKDOWN);
        }
    }

    IPC_Error HTS_CCTV_Security::Enter_Lockdown() noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return IPC_Error::NOT_INITIALIZED; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        if (!impl->Transition_State(CCTV_SecState::LOCKDOWN)) {
            return IPC_Error::CFI_VIOLATION;
        }
        impl->Send_Event(CCTV_EventType::SYSTEM_BOOT_OK,  // Reuse as lockdown notification
            CCTV_Severity::EMERGENCY, nullptr, 0u);
        return IPC_Error::OK;
    }

    IPC_Error HTS_CCTV_Security::Exit_Lockdown() noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return IPC_Error::NOT_INITIALIZED; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        if (!impl->Transition_State(CCTV_SecState::MONITORING)) {
            return IPC_Error::CFI_VIOLATION;
        }
        return IPC_Error::OK;
    }

    CCTV_SecState HTS_CCTV_Security::Get_State() const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return CCTV_SecState::OFFLINE; }
        return reinterpret_cast<const Impl*>(impl_buf_)->state;
    }

    uint32_t HTS_CCTV_Security::Get_Event_Count() const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        return reinterpret_cast<const Impl*>(impl_buf_)->total_event_count;
    }

    uint32_t HTS_CCTV_Security::Get_Critical_Count() const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        return reinterpret_cast<const Impl*>(impl_buf_)->critical_event_count;
    }

    void HTS_CCTV_Security::Get_Recent_Events(CCTV_EventLog* out_log,
        uint8_t max_count,
        uint8_t& out_count) const noexcept
    {
        out_count = 0u;
        if (out_log == nullptr || max_count == 0u) { return; }
        if (!initialized_.load(std::memory_order_acquire)) { return; }

        const Impl* impl = reinterpret_cast<const Impl*>(impl_buf_);
        const uint32_t total = (impl->log_head < CCTV_EVENT_LOG_SIZE)
            ? impl->log_head : CCTV_EVENT_LOG_SIZE;
        const uint8_t  count = (static_cast<uint8_t>(total) < max_count)
            ? static_cast<uint8_t>(total) : max_count;

        // Read from most recent backward
        for (uint8_t i = 0u; i < count; ++i) {
            const uint32_t idx = (impl->log_head - 1u - static_cast<uint32_t>(i)) & CCTV_EVENT_LOG_MASK;
            out_log[i] = impl->event_log[idx];
        }
        out_count = count;
    }

} // namespace ProtectedEngine