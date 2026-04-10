/// @file  HTS_Console_Manager.cpp
/// @brief HTS Console Manager -- STM32 Implementation
/// @note  ARM only. Pure ASCII. No PC/server code.
///
/// @author Lim Young-jun
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_Console_Manager.h"
#include "HTS_Arm_Irq_Mask_Guard.h"
#include "HTS_IPC_Protocol.h"
#include "HTS_Role_Auth.h"
#include "HTS_Secure_Logger.h"
#include <new>        // placement new
#include <atomic>
#include <cstddef>
#include <cstring>    // memcpy (channel_config 원자적 복사용)

// ============================================================
//
//  channel_config(ChannelConfig, ~28B)는 원자 타입이 아니므로
//  Apply_Param(IPC ISR 경로) vs Set_Channel_Config(앱 태스크 경로)
//  동시 접근 시 Torn Write 발생 가능.
//  -> PRIMASK(ARM: CPSID I)로 인터럽트 차단 — Armv7m_Irq_Mask_Guard(RAII)로 복원 보장.
//     memcpy 단위로 원자적 복사 보장.
//  ISR 내부에서는 중첩 진입 불가(재진입 없음) -> PRIMASK 안전.
// ============================================================

namespace ProtectedEngine {

    namespace {
        // 민감 버퍼 소거가 LTO/DCE로 제거되지 않도록 강제.
        static void Console_Secure_Wipe_Strict(void* ptr, std::size_t size) noexcept {
            volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
            while (size--) { *p++ = 0u; }
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("" ::: "memory");
#else
            std::atomic_thread_fence(std::memory_order_release);
#endif
        }

        static std::atomic<uint8_t> g_console_auth_fail_count{ 0u };
        static constexpr uint8_t CONSOLE_AUTH_FAIL_MAX = 8u;

        static bool Is_Privileged_Command(const IPC_Command cmd) noexcept {
            return (cmd == IPC_Command::CONFIG_SET) || (cmd == IPC_Command::RESET_CMD);
        }

        static bool Check_Privileged_Access(const IPC_Command cmd) noexcept {
            if (!Is_Privileged_Command(cmd)) { return true; }
            if (g_console_auth_fail_count.load(std::memory_order_acquire) >= CONSOLE_AUTH_FAIL_MAX) {
                SecureLogger::logSecurityEvent("CONSOLE_AUTH_LOCK",
                    "Console privileged command locked by retry cap.");
                return false;
            }
            if (Role_Auth::Is_Authorized(Service::CONFIG_CHANGE)) {
                g_console_auth_fail_count.store(0u, std::memory_order_release);
                return true;
            }

            const uint8_t cur = g_console_auth_fail_count.load(std::memory_order_relaxed);
            if (cur < CONSOLE_AUTH_FAIL_MAX) {
                g_console_auth_fail_count.store(static_cast<uint8_t>(cur + 1u), std::memory_order_release);
            }
            SecureLogger::logSecurityEvent("CONSOLE_AUTH_DENY",
                "Console privileged command rejected: Role_Auth failed.");
            return false;
        }
    } // namespace

    // ============================================================
    //  Default Channel Config (constexpr ROM -- ASIC synthesizable)
    // ============================================================

    static constexpr ChannelConfig k_default_channel_config = {
        BpsLevel::AUTO,             // bps_mode
        DeviceMode::SENSOR_GATEWAY, // device_mode
        64u,                        // spread_chips (64-chip default)
        1u,                         // fec_mode (HARQ)
        1u,                         // ajc_enable
        0u,                         // crypto_algo (ARIA)
        0u,                         // bridge_enable
        0u,                         // reserved
        400000u,                    // rf_frequency_khz (400 MHz)
        static_cast<uint16_t>(20u << 8u),  // rf_tx_power_q8 (20.0 dBm in Q8)
        2000u,                      // ajc_threshold
        3600u,                      // key_rotation_sec (1 hour)
        300u                        // session_timeout_sec (5 min)
    };

    // ============================================================
    //  Firmware Version (constexpr)
    // ============================================================

    static constexpr uint32_t FIRMWARE_VERSION =
        (1u << 16u) | (0u << 8u) | 0u;  // v1.0.0

    // ============================================================
    //  Impl Structure
    // ============================================================

    struct HTS_Console_Manager::Impl {
        // --- Dependencies ---
        HTS_IPC_Protocol* ipc;

        // --- State ---
        ConsoleState state;
        uint32_t     init_tick;
        uint32_t     last_tick;

        // --- Channel Configuration ---
        ChannelConfig channel_config;

        // --- Diag Callbacks ---
        DiagCallbacks diag_cb;

        // --- Device Identity ---
        uint32_t device_id;

        // --- Response Buffer (static, avoids stack pressure) ---
        uint8_t rsp_buf[IPC_MAX_PAYLOAD];

        // IPC 응답 전송 실패 시 외부에 "성공한 것처럼" 보이지 않도록 상태를 ERROR로 표면화.
        void Mark_Ipc_Response_Failed() noexcept
        {
            state = ConsoleState::ERROR;
        }

        // ============================================================
        //  Command Dispatch
        // ============================================================
        void Process_IPC_Commands() noexcept
        {
            if (ipc == nullptr) { return; }

            IPC_Command cmd = IPC_Command::PING;
            uint8_t     payload[IPC_MAX_PAYLOAD];
            uint16_t    payload_len = 0u;

            // Drain RX ring (bounded: max IPC_RING_DEPTH per tick)
            for (uint32_t drain = 0u; drain < IPC_RING_DEPTH; ++drain) {
                const IPC_Error err = ipc->Receive_Frame(
                    cmd, payload, IPC_MAX_PAYLOAD, payload_len);
                if (err != IPC_Error::OK) { break; }
                if (payload_len > IPC_MAX_PAYLOAD) { continue; }
                if (!Check_Privileged_Access(cmd)) { continue; }

                switch (cmd) {
                case IPC_Command::CONFIG_SET:
                    Handle_Config_Set(payload, payload_len);
                    break;
                case IPC_Command::CONFIG_GET:
                    Handle_Config_Get(payload, payload_len);
                    break;
                case IPC_Command::STATUS_REQ:
                    Handle_Status_Req();
                    break;
                case IPC_Command::DIAG_REQ:
                    Handle_Diag_Req();
                    break;
                case IPC_Command::RESET_CMD:
                    Handle_Reset_Cmd();
                    break;
                default:
                    // Unknown command -- ignore (ACK already sent by IPC layer)
                    break;
                }
            }
        }

        // ============================================================
        //  CONFIG_SET Handler
        // ============================================================
        void Handle_Config_Set(const uint8_t* payload, uint16_t len) noexcept
        {
            if (payload == nullptr || len == 0u) { return; }

            uint32_t offset = 0u;
            while (offset < static_cast<uint32_t>(len)) {
                ParamId  pid = ParamId::BPS_MODE;
                uint8_t  val_buf[TLV_MAX_VALUE] = { 0u, 0u, 0u, 0u };
                uint8_t  val_len = 0u;

                const uint32_t consumed = TLV_Parse(
                    &payload[offset], static_cast<uint32_t>(len) - offset,
                    pid, val_buf, val_len);
                if (consumed == 0u) { break; }
                offset += consumed;

                Apply_Param(pid, val_buf, val_len);
            }

            // Send CONFIG_RSP with current config snapshot
            Send_Config_Response();
        }

        // ============================================================
        //  CONFIG_GET Handler
        // ============================================================
        void Handle_Config_Get(const uint8_t* payload, uint16_t len) noexcept
        {
            if (payload == nullptr || len == 0u) {
                // No specific param requested -- send full config
                Send_Config_Response();
                return;
            }

            // Build response with requested params
            uint32_t rsp_len = 0u;
            uint32_t offset = 0u;

            while (offset < static_cast<uint32_t>(len)) {
                ParamId  pid = ParamId::BPS_MODE;
                uint8_t  dummy_val[TLV_MAX_VALUE] = { 0u, 0u, 0u, 0u };
                uint8_t  dummy_len = 0u;

                const uint32_t consumed = TLV_Parse(
                    &payload[offset], static_cast<uint32_t>(len) - offset,
                    pid, dummy_val, dummy_len);
                if (consumed == 0u) { break; }
                offset += consumed;

                if (rsp_len >= IPC_MAX_PAYLOAD - TLV_MAX_SIZE) { break; }
                const uint32_t remain = IPC_MAX_PAYLOAD - rsp_len;
                const uint32_t written =
                    Serialize_Param(pid, &rsp_buf[rsp_len], remain);
                if (written == 0u) { break; }
                rsp_len += written;
            }

            if ((rsp_len > 0u) && (ipc != nullptr)) {
                const IPC_Error se = ipc->Send_Frame(IPC_Command::CONFIG_RSP,
                    rsp_buf, static_cast<uint16_t>(rsp_len));
                if (se != IPC_Error::OK) {
                    Mark_Ipc_Response_Failed();
                }
            }
        }

        // ============================================================
        //  STATUS_REQ Handler
        // ============================================================
        void Handle_Status_Req() noexcept
        {
            if (ipc == nullptr) { return; }

            DiagReport report;
            Build_Report(report);

            // Serialize DiagReport to wire (endian-independent)
            uint32_t pos = 0u;
            Serialize_U32(&rsp_buf[pos], report.uptime_sec);          pos += 4u;
            Serialize_U32(&rsp_buf[pos], report.firmware_version);    pos += 4u;
            Serialize_U32(&rsp_buf[pos], report.device_id);           pos += 4u;
            Serialize_U16(&rsp_buf[pos], report.current_bps);         pos += 2u;
            Serialize_U16(&rsp_buf[pos], report.snr_proxy_q8);        pos += 2u;
            Serialize_U16(&rsp_buf[pos], report.jamming_level);       pos += 2u;
            Serialize_U16(&rsp_buf[pos], report.temperature_q8);      pos += 2u;
            Serialize_U32(&rsp_buf[pos], report.crc_error_count);     pos += 4u;
            Serialize_U32(&rsp_buf[pos], report.harq_retx_count);     pos += 4u;
            Serialize_U32(&rsp_buf[pos], report.sram_usage_bytes);    pos += 4u;
            Serialize_U32(&rsp_buf[pos], report.flash_crc);           pos += 4u;
            rsp_buf[pos] = report.link_state;       pos += 1u;
            rsp_buf[pos] = report.device_mode;      pos += 1u;
            rsp_buf[pos] = report.bps_mode;         pos += 1u;
            rsp_buf[pos] = report.secure_boot_state; pos += 1u;

            const IPC_Error se = ipc->Send_Frame(IPC_Command::STATUS_RSP,
                rsp_buf, static_cast<uint16_t>(pos));
            if (se != IPC_Error::OK) {
                Mark_Ipc_Response_Failed();
            }
        }

        // ============================================================
        //  DIAG_REQ Handler (same as STATUS but uses DIAG_RSP command)
        // ============================================================
        void Handle_Diag_Req() noexcept
        {
            if (ipc == nullptr) { return; }

            DiagReport report;
            Build_Report(report);

            // Same serialization as status
            uint32_t pos = 0u;
            Serialize_U32(&rsp_buf[pos], report.uptime_sec);          pos += 4u;
            Serialize_U32(&rsp_buf[pos], report.firmware_version);    pos += 4u;
            Serialize_U32(&rsp_buf[pos], report.device_id);           pos += 4u;
            Serialize_U16(&rsp_buf[pos], report.current_bps);         pos += 2u;
            Serialize_U16(&rsp_buf[pos], report.snr_proxy_q8);        pos += 2u;
            Serialize_U16(&rsp_buf[pos], report.jamming_level);       pos += 2u;
            Serialize_U16(&rsp_buf[pos], report.temperature_q8);      pos += 2u;
            Serialize_U32(&rsp_buf[pos], report.crc_error_count);     pos += 4u;
            Serialize_U32(&rsp_buf[pos], report.harq_retx_count);     pos += 4u;
            Serialize_U32(&rsp_buf[pos], report.sram_usage_bytes);    pos += 4u;
            Serialize_U32(&rsp_buf[pos], report.flash_crc);           pos += 4u;
            rsp_buf[pos] = report.link_state;       pos += 1u;
            rsp_buf[pos] = report.device_mode;      pos += 1u;
            rsp_buf[pos] = report.bps_mode;         pos += 1u;
            rsp_buf[pos] = report.secure_boot_state; pos += 1u;

            const IPC_Error se = ipc->Send_Frame(IPC_Command::DIAG_RSP,
                rsp_buf, static_cast<uint16_t>(pos));
            if (se != IPC_Error::OK) {
                Mark_Ipc_Response_Failed();
            }
        }

        // ============================================================
        //  RESET_CMD Handler
        // ============================================================
        void Handle_Reset_Cmd() noexcept
        {
            // Restore default config
            channel_config = k_default_channel_config;
            state = ConsoleState::ONLINE;
        }

        // ============================================================
        //  Apply Single Parameter
        // ============================================================
        void Apply_Param(ParamId pid, const uint8_t* val, uint8_t len) noexcept
        {
            //  Apply_Param은 IPC 수신 경로(Tick -> Process_IPC_Commands)에서 호출.
            //  Set_Channel_Config는 앱 태스크 경로에서 호출.
            //  두 경로가 channel_config 멤버를 바이트 단위로 동시 수정 시
            //  Torn Write 발생 -> 트랜시버 오동작(엉뚱한 RF 주파수/변조).
            //  -> PRIMASK 크리티컬 섹션으로 원자적 단일 파라미터 수정 보장.
            Armv7m_Irq_Mask_Guard irq;
            switch (pid) {
            case ParamId::BPS_MODE:
                if (len >= 1u && val[0] < static_cast<uint8_t>(BpsLevel::LEVEL_COUNT)) {
                    channel_config.bps_mode = static_cast<BpsLevel>(val[0]);
                }
                break;
            case ParamId::DEVICE_MODE:
                if (len >= 1u && val[0] < static_cast<uint8_t>(DeviceMode::MODE_COUNT)) {
                    channel_config.device_mode = static_cast<DeviceMode>(val[0]);
                }
                break;
            case ParamId::SPREAD_CHIPS:
                if (len >= 1u) {
                    // Validate: 1, 16, or 64 only
                    const uint8_t c = val[0];
                    if (c == 1u || c == 16u || c == 64u) {
                        channel_config.spread_chips = c;
                    }
                }
                break;
            case ParamId::FEC_MODE:
                if (len >= 1u && val[0] <= 2u) {
                    channel_config.fec_mode = val[0];
                }
                break;
            case ParamId::AJC_ENABLE:
                if (len >= 1u) {
                    channel_config.ajc_enable = (val[0] != 0u) ? 1u : 0u;
                }
                break;
            case ParamId::CRYPTO_ALGO:
                if (len >= 1u && val[0] <= 1u) {
                    channel_config.crypto_algo = val[0];
                }
                break;
            case ParamId::RF_FREQUENCY:
                if (len >= 4u) {
                    channel_config.rf_frequency_khz = Deserialize_U32(val);
                }
                break;
            case ParamId::RF_TX_POWER:
                if (len >= 2u) {
                    channel_config.rf_tx_power_q8 = Deserialize_U16(val);
                }
                break;
            case ParamId::AJC_THRESHOLD:
                if (len >= 2u) {
                    channel_config.ajc_threshold = Deserialize_U16(val);
                }
                break;
            case ParamId::KEY_ROTATION_SEC:
                if (len >= 4u) {
                    channel_config.key_rotation_sec = Deserialize_U32(val);
                }
                break;
            case ParamId::SESSION_TIMEOUT_SEC:
                if (len >= 4u) {
                    channel_config.session_timeout_sec = Deserialize_U32(val);
                }
                break;
            case ParamId::BRIDGE_ENABLE:
                if (len >= 1u) {
                    channel_config.bridge_enable = (val[0] != 0u) ? 1u : 0u;
                }
                break;
            default:
                // Read-only or unknown param -- silently ignore
                break;
            }
        }

        // ============================================================
        //  Serialize Single Parameter for Response
        // ============================================================
        uint32_t Serialize_Param(ParamId pid, uint8_t* buf, uint32_t remain) noexcept
        {
            if (buf == nullptr || remain < TLV_MAX_SIZE) { return 0u; }

            uint8_t val[TLV_MAX_VALUE] = { 0u, 0u, 0u, 0u };
            uint8_t val_len = 0u;

            switch (pid) {
            case ParamId::BPS_MODE:
                val[0] = static_cast<uint8_t>(channel_config.bps_mode);
                val_len = 1u;
                break;
            case ParamId::BPS_CURRENT:
                if (diag_cb.get_current_bps != nullptr) {
                    Serialize_U16_Arr(val, diag_cb.get_current_bps());
                }
                val_len = 2u;
                break;
            case ParamId::DEVICE_MODE:
                val[0] = static_cast<uint8_t>(channel_config.device_mode);
                val_len = 1u;
                break;
            case ParamId::SPREAD_CHIPS:
                val[0] = channel_config.spread_chips;
                val_len = 1u;
                break;
            case ParamId::FEC_MODE:
                val[0] = channel_config.fec_mode;
                val_len = 1u;
                break;
            case ParamId::AJC_ENABLE:
                val[0] = channel_config.ajc_enable;
                val_len = 1u;
                break;
            case ParamId::CRYPTO_ALGO:
                val[0] = channel_config.crypto_algo;
                val_len = 1u;
                break;
            case ParamId::RF_FREQUENCY:
                Serialize_U32_Arr(val, channel_config.rf_frequency_khz);
                val_len = 4u;
                break;
            case ParamId::RF_TX_POWER:
                Serialize_U16_Arr(val, channel_config.rf_tx_power_q8);
                val_len = 2u;
                break;
            case ParamId::BRIDGE_ENABLE:
                val[0] = channel_config.bridge_enable;
                val_len = 1u;
                break;
            default:
                return 0u;  // Unknown or diagnostic param
            }

            return TLV_Serialize(buf, pid, val, val_len);
        }

        // ============================================================
        //  Send Full Config Response
        // ============================================================
        void Send_Config_Response() noexcept
        {
            if (ipc == nullptr) { return; }

            uint32_t pos = 0u;
            // Serialize key config params as TLV chain
            static constexpr ParamId k_config_params[] = {
                ParamId::BPS_MODE,
                ParamId::DEVICE_MODE,
                ParamId::SPREAD_CHIPS,
                ParamId::FEC_MODE,
                ParamId::AJC_ENABLE,
                ParamId::CRYPTO_ALGO,
                ParamId::RF_FREQUENCY,
                ParamId::RF_TX_POWER,
                ParamId::BRIDGE_ENABLE
            };
            static constexpr uint32_t k_param_count =
                sizeof(k_config_params) / sizeof(k_config_params[0]);

            for (uint32_t i = 0u; i < k_param_count; ++i) {
                if (pos >= IPC_MAX_PAYLOAD - TLV_MAX_SIZE) { break; }
                const uint32_t remain = IPC_MAX_PAYLOAD - pos;
                const uint32_t written = Serialize_Param(
                    k_config_params[i], &rsp_buf[pos], remain);
                if (written == 0u) { break; }
                pos += written;
            }

            if (pos > 0u) {
                const IPC_Error se = ipc->Send_Frame(IPC_Command::CONFIG_RSP,
                    rsp_buf, static_cast<uint16_t>(pos));
                if (se != IPC_Error::OK) {
                    Mark_Ipc_Response_Failed();
                }
            }
        }

        // ============================================================
        //  Build Diagnostic Report
        // ============================================================
        void Build_Report(DiagReport& r) const noexcept
        {
            const uint32_t elapsed = last_tick - init_tick;
            // ms -> sec: use Q16 reciprocal multiply instead of division
            // 1/1000 ~ 1049/2^20 = 1049 * elapsed >> 20
            // Accuracy: 0.02% error for values up to 4,294,967 sec (~49.7 days)
            static constexpr uint32_t RECIP_1000_Q20 = 1049u;
            r.uptime_sec = static_cast<uint32_t>(
                (static_cast<uint64_t>(elapsed) * RECIP_1000_Q20) >> 20u);

            r.firmware_version = FIRMWARE_VERSION;
            r.device_id = device_id;

            r.current_bps = (diag_cb.get_current_bps != nullptr)
                ? diag_cb.get_current_bps() : 0u;
            r.snr_proxy_q8 = (diag_cb.get_snr_proxy_q8 != nullptr)
                ? diag_cb.get_snr_proxy_q8() : 0u;
            r.jamming_level = (diag_cb.get_jamming_level != nullptr)
                ? diag_cb.get_jamming_level() : 0u;
            r.temperature_q8 = (diag_cb.get_temperature_q8 != nullptr)
                ? diag_cb.get_temperature_q8() : 0u;
            r.crc_error_count = (diag_cb.get_crc_error_count != nullptr)
                ? diag_cb.get_crc_error_count() : 0u;
            r.harq_retx_count = (diag_cb.get_harq_retx_count != nullptr)
                ? diag_cb.get_harq_retx_count() : 0u;
            r.sram_usage_bytes = (diag_cb.get_sram_usage != nullptr)
                ? diag_cb.get_sram_usage() : 0u;
            r.flash_crc = (diag_cb.get_flash_crc != nullptr)
                ? diag_cb.get_flash_crc() : 0u;

            r.link_state = (ipc != nullptr && ipc->Is_Link_Alive() == HTS_IPC_Protocol::SECURE_TRUE) ? 1u : 0u;
            r.device_mode = static_cast<uint8_t>(channel_config.device_mode);
            r.bps_mode = static_cast<uint8_t>(channel_config.bps_mode);
            r.secure_boot_state = 1u;  // TODO: read from POST_Manager
        }

        // ============================================================
        //  Endian Helpers (local, avoids Defs.h dependency chain)
        // ============================================================
        static void Serialize_U16(uint8_t* b, uint16_t v) noexcept
        {
            b[0] = static_cast<uint8_t>(v >> 8u);
            b[1] = static_cast<uint8_t>(v & 0xFFu);
        }
        static void Serialize_U32(uint8_t* b, uint32_t v) noexcept
        {
            b[0] = static_cast<uint8_t>(v >> 24u);
            b[1] = static_cast<uint8_t>((v >> 16u) & 0xFFu);
            b[2] = static_cast<uint8_t>((v >> 8u) & 0xFFu);
            b[3] = static_cast<uint8_t>(v & 0xFFu);
        }
        static uint16_t Deserialize_U16(const uint8_t* b) noexcept
        {
            return static_cast<uint16_t>(
                (static_cast<uint16_t>(b[0]) << 8u) | static_cast<uint16_t>(b[1]));
        }
        static uint32_t Deserialize_U32(const uint8_t* b) noexcept
        {
            return (static_cast<uint32_t>(b[0]) << 24u) |
                (static_cast<uint32_t>(b[1]) << 16u) |
                (static_cast<uint32_t>(b[2]) << 8u) |
                static_cast<uint32_t>(b[3]);
        }
        // Array variants (for TLV value serialization)
        static void Serialize_U16_Arr(uint8_t* b, uint16_t v) noexcept { Serialize_U16(b, v); }
        static void Serialize_U32_Arr(uint8_t* b, uint32_t v) noexcept { Serialize_U32(b, v); }
    };

    // Build-time size verification
    // sizeof(Impl) checked inside constructor (member access context)

    // ============================================================
    //  Public API
    // ============================================================

    HTS_Console_Manager::HTS_Console_Manager() noexcept
        : initialized_{ false }
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "HTS_Console_Manager::Impl exceeds IMPL_BUF_SIZE");

        for (uint32_t i = 0u; i < IMPL_BUF_SIZE; ++i) {
            impl_buf_[i] = 0u;
        }
    }

    HTS_Console_Manager::~HTS_Console_Manager() noexcept
    {
        Shutdown();
    }

    IPC_Error HTS_Console_Manager::Initialize(HTS_IPC_Protocol* ipc) noexcept
    {
        //
        //  초기화 순서: initializing_ CAS → ipc 검증 → placement new → initialized_.store(release)
        bool init_expected = false;
        if (!initializing_.compare_exchange_strong(
            init_expected, true, std::memory_order_acq_rel))
        {
            // 이미 초기화 중 또는 완료 -- 중복 호출 차단
            return IPC_Error::OK;
        }

        // initializing_=true 획득: 이 스레드만 초기화 진행권 보유
        // initialized_는 아직 false -> 소비자(Tick/Get*/Set*) 접근 차단됨

        if (ipc == nullptr) {
            // 파라미터 오류 -> initializing_ 해제 후 반환
            initializing_.store(false, std::memory_order_release);
            return IPC_Error::NOT_INITIALIZED;
        }

        // placement new -- Impl 생성자 호출
        Impl* impl = new (impl_buf_) Impl{};

        // 전체 멤버 초기화 완료
        impl->ipc = ipc;
        impl->state = ConsoleState::OFFLINE;
        impl->init_tick = 0u;
        impl->last_tick = 0u;
        impl->channel_config = k_default_channel_config;
        impl->device_id = 0x48545300u;  // "HTS\0" as uint32_t

        // Zero callbacks
        impl->diag_cb.get_current_bps = nullptr;
        impl->diag_cb.get_snr_proxy_q8 = nullptr;
        impl->diag_cb.get_jamming_level = nullptr;
        impl->diag_cb.get_temperature_q8 = nullptr;
        impl->diag_cb.get_crc_error_count = nullptr;
        impl->diag_cb.get_harq_retx_count = nullptr;
        impl->diag_cb.get_sram_usage = nullptr;
        impl->diag_cb.get_flash_crc = nullptr;

        impl->state = ConsoleState::ONLINE;

        //  -> 소비자 acquire 로드와 release-acquire 쌍 형성
        //  -> 위의 모든 쓰기가 소비자에게 가시화됨
        initialized_.store(true, std::memory_order_release);
        // 초기화 완료: 재진입 차단 락 해제
        initializing_.store(false, std::memory_order_release);

        return IPC_Error::OK;
    }

    void HTS_Console_Manager::Shutdown() noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }

        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        impl->ipc = nullptr;
        impl->state = ConsoleState::OFFLINE;

        Console_Secure_Wipe_Strict(impl->rsp_buf, IPC_MAX_PAYLOAD);
        std::atomic_thread_fence(std::memory_order_release);

        impl->~Impl();

        Console_Secure_Wipe_Strict(impl_buf_, IMPL_BUF_SIZE);

        initialized_.store(false, std::memory_order_release);
        // 종료 완료: 다음 Initialize() 허용
        initializing_.store(false, std::memory_order_release);
    }

    void HTS_Console_Manager::Register_Callbacks(const DiagCallbacks& cb) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        impl->diag_cb = cb;
    }

    void HTS_Console_Manager::Tick(uint32_t systick_ms) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }

        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        if (impl->init_tick == 0u) { impl->init_tick = systick_ms; }
        impl->last_tick = systick_ms;

        impl->Process_IPC_Commands();
    }

    void HTS_Console_Manager::Get_Channel_Config(ChannelConfig& out_config) const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) {
            out_config = k_default_channel_config;
            return;
        }
        const Impl* impl = std::launder(reinterpret_cast<const Impl*>(impl_buf_));
        //  Apply_Param(IPC 경로)과 동시 실행 시 부분 읽기 방지
        Armv7m_Irq_Mask_Guard irq;
        std::memcpy(&out_config, &impl->channel_config, sizeof(ChannelConfig));
    }

    IPC_Error HTS_Console_Manager::Set_Channel_Config(const ChannelConfig& config) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) {
            return IPC_Error::NOT_INITIALIZED;
        }
        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));

        // Validate critical fields
        if (static_cast<uint8_t>(config.bps_mode) >=
            static_cast<uint8_t>(BpsLevel::LEVEL_COUNT)) {
            return IPC_Error::INVALID_CMD;
        }
        if (static_cast<uint8_t>(config.device_mode) >=
            static_cast<uint8_t>(DeviceMode::MODE_COUNT)) {
            return IPC_Error::INVALID_CMD;
        }

        //  Apply_Param(IPC 경로)과 동시 실행 시 구조체 찢어짐 방지
        //  (RF 주파수 상위/하위 바이트가 각각 다른 설정에서 오는 현상 차단)
        Armv7m_Irq_Mask_Guard irq;
        std::memcpy(&impl->channel_config, &config, sizeof(ChannelConfig));
        return IPC_Error::OK;
    }

    ConsoleState HTS_Console_Manager::Get_State() const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) {
            return ConsoleState::OFFLINE;
        }
        const Impl* impl = std::launder(reinterpret_cast<const Impl*>(impl_buf_));
        return impl->state;
    }

    void HTS_Console_Manager::Build_Diag_Report(DiagReport& out_report) const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) {
            out_report = DiagReport{};
            return;
        }
        const Impl* impl = std::launder(reinterpret_cast<const Impl*>(impl_buf_));
        impl->Build_Report(out_report);
    }

    void HTS_Console_Manager::Notify_BPS_Change(uint16_t new_bps) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        if (impl->ipc == nullptr) { return; }

        uint8_t payload[2];
        Impl::Serialize_U16(payload, new_bps);
        const IPC_Error se =
            impl->ipc->Send_Frame(IPC_Command::BPS_NOTIFY, payload, 2u);
        if (se != IPC_Error::OK) {
            impl->state = ConsoleState::ERROR;
        }
    }

    void HTS_Console_Manager::Alert_Jamming(uint16_t level) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        if (impl->ipc == nullptr) { return; }

        uint8_t payload[2];
        Impl::Serialize_U16(payload, level);
        const IPC_Error se =
            impl->ipc->Send_Frame(IPC_Command::JAMMING_ALERT, payload, 2u);
        if (se != IPC_Error::OK) {
            impl->state = ConsoleState::ERROR;
        }
    }

} // namespace ProtectedEngine
