/// @file  HTS_Modbus_Gateway.cpp
/// @brief HTS Modbus Gateway -- Multi-PHY Industrial Protocol Converter
/// @note  ARM only. Pure ASCII. No PC/server code.
/// @author Lim Young-jun
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_Modbus_Gateway.h"
#include "HTS_IPC_Protocol.h"
#include <new>
#include <atomic>
#include <cstring>  // [FIX-D2] memset

namespace ProtectedEngine {

#if (defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
     defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)) && \
    !defined(__aarch64__)
#define HTS_MODBUS_PRIMASK_SHUTDOWN 1
#else
#define HTS_MODBUS_PRIMASK_SHUTDOWN 0
#endif

    namespace {
        struct Modbus_Busy_Guard {
            std::atomic_flag& f;
            bool locked;
            explicit Modbus_Busy_Guard(std::atomic_flag& flag) noexcept
                : f(flag), locked(false) {
                if (!f.test_and_set(std::memory_order_acquire)) {
                    locked = true;
                }
            }
            ~Modbus_Busy_Guard() noexcept {
                if (locked) {
                    f.clear(std::memory_order_release);
                }
            }
        };
    } // namespace

    // ============================================================
    //  Modbus 평문 페이로드(tx_buf/rx_buf/gw_rsp_buf) 잔류 방지
    // ============================================================
    static void Modbus_Secure_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) { q[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // ============================================================
    //  Endian Helpers (Modbus uses big-endian for registers)
    // ============================================================

    static inline void MB_Write_U16(uint8_t* b, uint16_t v) noexcept
    {
        b[0] = static_cast<uint8_t>(v >> 8u);
        b[1] = static_cast<uint8_t>(v & 0xFFu);
    }
    static inline uint16_t MB_Read_U16(const uint8_t* b) noexcept
    {
        return static_cast<uint16_t>(
            (static_cast<uint16_t>(b[0]) << 8u) | static_cast<uint16_t>(b[1]));
    }

    // ============================================================
    //  Impl Structure
    // ============================================================

    struct HTS_Modbus_Gateway::Impl {
        // --- Dependencies ---
        HTS_IPC_Protocol* ipc;

        // --- PHY ---
        Modbus_PHY_Callbacks phy_cb;

        // --- CFI State ---
        Modbus_State state;
        uint8_t      cfi_violation_count;
        uint8_t      pad_[2];

        // --- Timing ---
        uint32_t current_tick;
        uint32_t request_sent_tick;  ///< Timeout tracking

        // --- Statistics ---
        uint32_t request_count;
        uint32_t error_count;

        // --- Auto-Poll Items ---
        Modbus_PollItem poll_items[MODBUS_MAX_POLL_ITEMS];

        // --- TX/RX Frame Buffers ---
        uint8_t tx_buf[MODBUS_GW_MAX_FRAME];
        uint8_t rx_buf[MODBUS_GW_MAX_FRAME];
        uint8_t gw_rsp_buf[MODBUS_GW_MAX_FRAME];  ///< GW response to B-CDMA

        // ============================================================
        //  CFI Transition
        // ============================================================
        bool Transition_State(Modbus_State target) noexcept
        {
            if (!Modbus_Is_Legal_Transition(state, target)) {
                if (Modbus_Is_Legal_Transition(state, Modbus_State::ERROR)) {
                    state = Modbus_State::ERROR;
                }
                else {
                    state = Modbus_State::OFFLINE;
                }
                cfi_violation_count++;
                return false;
            }
            state = target;
            return true;
        }

        // ============================================================
        //  Build Modbus RTU Frame (with Modbus CRC)
        // ============================================================
        uint16_t Build_RTU_Frame(uint8_t slave_addr, uint8_t func_code,
            const uint8_t* data, uint8_t data_len) noexcept
        {
            if (data_len > MODBUS_MAX_PDU_DATA) { return 0u; }

            uint16_t pos = 0u;
            tx_buf[pos++] = slave_addr;
            tx_buf[pos++] = func_code;
            if (data != nullptr) {
                for (uint8_t i = 0u; i < data_len; ++i) {
                    tx_buf[pos++] = data[i];
                }
            }

            // Modbus RTU CRC-16 (polynomial 0xA001, NOT CCITT)
            const uint16_t crc = Modbus_CRC16(tx_buf, pos);
            // Modbus CRC is little-endian on wire (low byte first!)
            tx_buf[pos++] = static_cast<uint8_t>(crc & 0xFFu);
            tx_buf[pos++] = static_cast<uint8_t>(crc >> 8u);

            return pos;
        }

        // ============================================================
        //  Execute Modbus Request (PHY-independent)
        // ============================================================
        uint16_t Execute_Request(Modbus_PHY phy, uint8_t slave_addr,
            uint8_t func_code, const uint8_t* data,
            uint8_t data_len, uint8_t* rsp_buf_out,
            uint16_t rsp_buf_size) noexcept
        {
            // Build RTU frame
            const uint16_t frame_len = Build_RTU_Frame(slave_addr, func_code,
                data, data_len);
            if (frame_len == 0u) { return 0u; }

            // Send via appropriate PHY
            bool sent = false;
            const uint8_t phy_val = static_cast<uint8_t>(phy);

            if (phy_val >= static_cast<uint8_t>(Modbus_PHY::RS485) &&
                phy_val <= static_cast<uint8_t>(Modbus_PHY::RS422))
            {
                // Serial PHY: RS-485 needs DE control
                if (phy_val == static_cast<uint8_t>(Modbus_PHY::RS485) &&
                    phy_cb.rs485_set_de != nullptr)
                {
                    phy_cb.rs485_set_de(true);  // TX enable
                }

                if (phy_cb.uart_send != nullptr) {
                    sent = phy_cb.uart_send(phy, tx_buf, frame_len);
                }

                if (phy_val == static_cast<uint8_t>(Modbus_PHY::RS485) &&
                    phy_cb.rs485_set_de != nullptr)
                {
                    phy_cb.rs485_set_de(false);  // Back to RX
                }
            }
            else if (phy_val == static_cast<uint8_t>(Modbus_PHY::TCP))
            {
                // Modbus TCP: strip RTU CRC, add MBAP header
                // For now: pass PDU directly (TCP layer handles framing)
                if (phy_cb.tcp_send != nullptr) {
                    sent = phy_cb.tcp_send(0u, 502u,
                        tx_buf, static_cast<uint16_t>(frame_len - 2u));
                }
            }
            else if (phy_val == static_cast<uint8_t>(Modbus_PHY::ANALOG_4_20))
            {
                // 4-20mA: synthesize read response from ADC
                return Synthesize_Analog_Response(data, data_len,
                    rsp_buf_out, rsp_buf_size);
            }

            if (!sent) {
                error_count++;
                return 0u;
            }

            request_count++;
            request_sent_tick = current_tick;

            // Receive response (blocking with timeout in HAL)
            uint16_t rsp_len = 0u;
            if (phy_val >= static_cast<uint8_t>(Modbus_PHY::RS485) &&
                phy_val <= static_cast<uint8_t>(Modbus_PHY::RS422))
            {
                if (phy_cb.uart_receive != nullptr) {
                    rsp_len = phy_cb.uart_receive(phy, rx_buf, MODBUS_GW_MAX_FRAME);
                }
            }
            else if (phy_val == static_cast<uint8_t>(Modbus_PHY::TCP))
            {
                if (phy_cb.tcp_receive != nullptr) {
                    rsp_len = phy_cb.tcp_receive(rx_buf, MODBUS_GW_MAX_FRAME);
                }
            }

            if (rsp_len < 4u) {  // Min: ADDR(1)+FC(1)+DATA(0)+CRC(2)
                error_count++;
                return 0u;
            }

            // Validate Modbus RTU CRC
            const uint16_t rsp_data_len = static_cast<uint16_t>(rsp_len - 2u);
            const uint16_t computed_crc = Modbus_CRC16(rx_buf, rsp_data_len);
            // Modbus CRC is little-endian
            const uint16_t received_crc = static_cast<uint16_t>(
                static_cast<uint16_t>(rx_buf[rsp_data_len])
                | (static_cast<uint16_t>(rx_buf[rsp_data_len + 1u]) << 8u));

            if (computed_crc != received_crc) {
                error_count++;
                return 0u;
            }

            // Check for exception response
            if ((rx_buf[1] & ModbusFC::EXCEPTION_FLAG) != 0u) {
                error_count++;
            }

            // Copy response (excluding CRC) to output
            const uint16_t copy_len = (rsp_data_len <= rsp_buf_size)
                ? rsp_data_len : rsp_buf_size;
            if (rsp_buf_out != nullptr) {
                for (uint16_t i = 0u; i < copy_len; ++i) {
                    rsp_buf_out[i] = rx_buf[i];
                }
            }
            return copy_len;
        }

        // ============================================================
        //  Synthesize 4-20mA Analog Response
        // ============================================================
        uint16_t Synthesize_Analog_Response(const uint8_t* data, uint8_t data_len,
            uint8_t* rsp_buf_out,
            uint16_t rsp_buf_size) noexcept
        {
            if (phy_cb.adc_read == nullptr) { return 0u; }
            if (rsp_buf_out == nullptr || rsp_buf_size < 5u) { return 0u; }

            // Parse: start_reg(2) + reg_count(2) from data
            if (data_len < 4u) { return 0u; }
            const uint16_t start_ch = MB_Read_U16(&data[0]);
            const uint16_t count = MB_Read_U16(&data[2]);

            if (count == 0u || count > 8u) { return 0u; }  // Max 8 ADC channels

            // Build Modbus-style response: ADDR(0)+FC(0x04)+BYTE_COUNT+DATA
            uint16_t pos = 0u;
            rsp_buf_out[pos++] = 0u;  // Virtual slave addr
            rsp_buf_out[pos++] = ModbusFC::READ_INPUT_REGS;
            const uint8_t byte_count = static_cast<uint8_t>(count << 1u);  // 2 bytes per reg
            rsp_buf_out[pos++] = byte_count;

            for (uint16_t ch = 0u; ch < count; ++ch) {
                const uint8_t channel = static_cast<uint8_t>(
                    (start_ch + ch) & 0x07u);  // Clamp to 0~7
                const uint16_t raw_adc = phy_cb.adc_read(channel);

                // Scale 4-20mA to 0~65535 (Q16)
                // scaled = (raw - 4mA_offset) * 65535 / (20mA - 4mA)
                // = (raw - 819) * 65535 / 3276
                // Avoid division: use Q16 reciprocal
                // 65535/3276 ~ 20.0 -> use (raw-819) * 20 (approx, good enough for 12-bit)
                // More precise: * 1310 >> 6 (Q6: 65535/3276 = 20.004 ~ 1280/64 = 20.0)
                uint16_t scaled = 0u;
                if (raw_adc > ANALOG_4MA_ADC_VALUE) {
                    const uint32_t diff = static_cast<uint32_t>(raw_adc) -
                        static_cast<uint32_t>(ANALOG_4MA_ADC_VALUE);
                    // Q6 reciprocal: 65535/3276 ~ 1280/64 = 20.0
                    scaled = static_cast<uint16_t>((diff * 1280u) >> 6u);
                }

                if (pos + 2u > rsp_buf_size) { break; }
                MB_Write_U16(&rsp_buf_out[pos], scaled);
                pos += 2u;
            }
            return pos;
        }

        // ============================================================
        //  Process GW Command from B-CDMA
        // ============================================================
        void Handle_GW_Command(const uint8_t* payload, uint16_t len) noexcept
        {
            if (len < MODBUS_GW_HEADER_SIZE) { return; }

            const GW_Command cmd = static_cast<GW_Command>(payload[0]);
            const Modbus_PHY phy = static_cast<Modbus_PHY>(payload[1]);
            const uint8_t slave_addr = payload[2];
            const uint8_t func_code = payload[3];
            const uint8_t data_len = payload[4];

            // Validate
            if (static_cast<uint8_t>(phy) == 0u ||
                static_cast<uint8_t>(phy) >= static_cast<uint8_t>(Modbus_PHY::PHY_COUNT))
            {
                return;
            }
            if (data_len > MODBUS_MAX_PDU_DATA) { return; }
            if (len < MODBUS_GW_HEADER_SIZE + static_cast<uint16_t>(data_len)) { return; }

            const uint8_t* req_data = (data_len > 0u) ? &payload[MODBUS_GW_HEADER_SIZE] : nullptr;

            switch (cmd) {
            case GW_Command::MODBUS_REQUEST: {
                // CFI: IDLE -> REQUESTING
                if (!Transition_State(Modbus_State::REQUESTING)) { return; }

                const uint16_t rsp_len = Execute_Request(
                    phy, slave_addr, func_code, req_data, data_len,
                    gw_rsp_buf, MODBUS_GW_MAX_FRAME);

                // CFI: REQUESTING -> IDLE
                Transition_State(Modbus_State::IDLE);

                // Send response back to B-CDMA
                if (rsp_len > 0u && ipc != nullptr) {
                    // Clamp response length: combined[] holds hdr(2) + rsp_data,
                    // so rsp_data must not exceed MODBUS_GW_MAX_FRAME - 2.
                    // Without this clamp: rsp_len=MAX -> combined[2+MAX-1] = OOB!
                    static constexpr uint16_t GW_HDR_OVERHEAD = 2u;
                    const uint16_t safe_rsp_len = (rsp_len <= MODBUS_GW_MAX_FRAME - GW_HDR_OVERHEAD)
                        ? rsp_len
                        : static_cast<uint16_t>(MODBUS_GW_MAX_FRAME - GW_HDR_OVERHEAD);

                    uint8_t combined[MODBUS_GW_MAX_FRAME];
                    combined[0] = static_cast<uint8_t>(GW_Command::MODBUS_RESPONSE);
                    combined[1] = static_cast<uint8_t>(phy);
                    for (uint16_t i = 0u; i < safe_rsp_len; ++i) {
                        combined[GW_HDR_OVERHEAD + i] = gw_rsp_buf[i];
                    }
                    ipc->Send_Frame(IPC_Command::DATA_TX,
                        combined, static_cast<uint16_t>(GW_HDR_OVERHEAD + safe_rsp_len));
                }
                break;
            }

            case GW_Command::POLL_CONFIG:
                // Parse poll item from payload and add
                if (data_len >= 8u && req_data != nullptr) {
                    Modbus_PollItem item;
                    item.slave_addr = req_data[0];
                    item.func_code = req_data[1];
                    item.start_reg = MB_Read_U16(&req_data[2]);
                    item.reg_count = MB_Read_U16(&req_data[4]);
                    item.interval_sec = MB_Read_U16(&req_data[6]);
                    item.last_poll_tick = current_tick;
                    item.active = 1u;
                    item.phy_type = static_cast<uint8_t>(phy);
                    Add_Poll_Item_Internal(item);
                }
                break;

            default:
                break;
            }
        }

        // ============================================================
        //  Auto-Poll Execution
        // ============================================================
        void Execute_Polls() noexcept
        {
            for (uint32_t i = 0u; i < MODBUS_MAX_POLL_ITEMS; ++i) {
                if (poll_items[i].active == 0u) { continue; }
                if (poll_items[i].interval_sec == 0u) { continue; }

                // Pacing: interval_sec * 1000 (ms)
                // Use shift: sec * 1024 ~ sec * 1000 (2.4% error, acceptable)
                const uint32_t interval_ms = static_cast<uint32_t>(
                    poll_items[i].interval_sec) << 10u;
                const uint32_t elapsed = current_tick - poll_items[i].last_poll_tick;
                if (elapsed < interval_ms) { continue; }

                // CFI: IDLE -> POLLING (idempotent)
                if ((static_cast<uint8_t>(state) & static_cast<uint8_t>(Modbus_State::POLLING)) == 0u) {
                    if (!Transition_State(Modbus_State::POLLING)) { continue; }
                }

                // Build read request: start_reg(2) + count(2)
                uint8_t req_data[4];
                MB_Write_U16(&req_data[0], poll_items[i].start_reg);
                MB_Write_U16(&req_data[2], poll_items[i].reg_count);

                const uint16_t rsp_len = Execute_Request(
                    static_cast<Modbus_PHY>(poll_items[i].phy_type),
                    poll_items[i].slave_addr,
                    poll_items[i].func_code,
                    req_data, 4u,
                    gw_rsp_buf, MODBUS_GW_MAX_FRAME);

                // Drift-free pacing
                poll_items[i].last_poll_tick += interval_ms;

                // Report to B-CDMA
                if (rsp_len > 0u && ipc != nullptr) {
                    static constexpr uint16_t GW_HDR_OVERHEAD = 2u;
                    const uint16_t safe_rsp_len = (rsp_len <= MODBUS_GW_MAX_FRAME - GW_HDR_OVERHEAD)
                        ? rsp_len
                        : static_cast<uint16_t>(MODBUS_GW_MAX_FRAME - GW_HDR_OVERHEAD);

                    uint8_t report[MODBUS_GW_MAX_FRAME];
                    report[0] = static_cast<uint8_t>(GW_Command::POLL_REPORT);
                    report[1] = poll_items[i].phy_type;
                    for (uint16_t j = 0u; j < safe_rsp_len; ++j) {
                        report[GW_HDR_OVERHEAD + j] = gw_rsp_buf[j];
                    }
                    ipc->Send_Frame(IPC_Command::DATA_TX,
                        report, static_cast<uint16_t>(GW_HDR_OVERHEAD + safe_rsp_len));
                }
            }

            // If no more polls pending, return to IDLE
            if ((static_cast<uint8_t>(state) & static_cast<uint8_t>(Modbus_State::POLLING)) != 0u) {
                Transition_State(Modbus_State::IDLE);
            }
        }

        // ============================================================
        //  Internal Poll Item Management
        // ============================================================
        uint8_t Add_Poll_Item_Internal(const Modbus_PollItem& item) noexcept
        {
            for (uint32_t i = 0u; i < MODBUS_MAX_POLL_ITEMS; ++i) {
                if (poll_items[i].active == 0u) {
                    poll_items[i] = item;
                    poll_items[i].last_poll_tick = current_tick;
                    return static_cast<uint8_t>(i);
                }
            }
            return 0xFFu;
        }
    };

    // ============================================================
    //  Public API
    // ============================================================

    HTS_Modbus_Gateway::HTS_Modbus_Gateway() noexcept
        : initialized_{ false }
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "HTS_Modbus_Gateway::Impl exceeds IMPL_BUF_SIZE");

        // [OPT] byte loop → memset (LDMIA/STMIA burst)
        std::memset(impl_buf_, 0, IMPL_BUF_SIZE);
    }

    HTS_Modbus_Gateway::~HTS_Modbus_Gateway() noexcept
    {
        Shutdown();
    }

    IPC_Error HTS_Modbus_Gateway::Initialize(HTS_IPC_Protocol* ipc) noexcept
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
        impl->state = Modbus_State::OFFLINE;
        impl->cfi_violation_count = 0u;
        impl->current_tick = 0u;
        impl->request_sent_tick = 0u;
        impl->request_count = 0u;
        impl->error_count = 0u;

        impl->phy_cb.uart_send = nullptr;
        impl->phy_cb.uart_receive = nullptr;
        impl->phy_cb.uart_configure = nullptr;
        impl->phy_cb.tcp_send = nullptr;
        impl->phy_cb.tcp_receive = nullptr;
        impl->phy_cb.adc_read = nullptr;
        impl->phy_cb.rs485_set_de = nullptr;

        for (uint32_t i = 0u; i < MODBUS_MAX_POLL_ITEMS; ++i) {
            impl->poll_items[i].active = 0u;
        }

        impl->Transition_State(Modbus_State::IDLE);
        return IPC_Error::OK;
    }

    void HTS_Modbus_Gateway::Shutdown() noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }

#if HTS_MODBUS_PRIMASK_SHUTDOWN && (defined(__GNUC__) || defined(__clang__))
        uint32_t primask_saved;
        __asm__ __volatile__("mrs %0, primask\n\t"
            "cpsid i"
            : "=r"(primask_saved) :: "memory");
#endif
        while (op_busy_.test_and_set(std::memory_order_acquire)) {}

        if (!initialized_.load(std::memory_order_acquire)) {
            op_busy_.clear(std::memory_order_release);
#if HTS_MODBUS_PRIMASK_SHUTDOWN && (defined(__GNUC__) || defined(__clang__))
            __asm__ __volatile__("msr primask, %0" :: "r"(primask_saved) : "memory");
#endif
            return;
        }

        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        impl->state = Modbus_State::OFFLINE;
        impl->ipc = nullptr;
        impl->~Impl();

        //  tx_buf(256B) + rx_buf(256B) + gw_rsp_buf(256B) = 768B 전체 소거
        //  소멸자만 호출하면 데이터가 SRAM에 잔류 (Data Remanence)
        //  → 메모리 덤프 공격 시 산업 제어 명령 노출
        Modbus_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);

        initialized_.store(false, std::memory_order_release);
        op_busy_.clear(std::memory_order_release);

#if HTS_MODBUS_PRIMASK_SHUTDOWN && (defined(__GNUC__) || defined(__clang__))
        __asm__ __volatile__("msr primask, %0" :: "r"(primask_saved) : "memory");
#endif
    }

    void HTS_Modbus_Gateway::Register_PHY_Callbacks(
        const Modbus_PHY_Callbacks& cb) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Modbus_Busy_Guard g(op_busy_);
        if (!g.locked) { return; }
        reinterpret_cast<Impl*>(impl_buf_)->phy_cb = cb;
    }

    void HTS_Modbus_Gateway::Configure_UART(Modbus_PHY phy,
        const Modbus_UART_Config& cfg) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Modbus_Busy_Guard g(op_busy_);
        if (!g.locked) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        if (impl->phy_cb.uart_configure != nullptr) {
            impl->phy_cb.uart_configure(phy, &cfg);
        }
    }

    void HTS_Modbus_Gateway::Process_GW_Command(const uint8_t* payload,
        uint16_t len) noexcept
    {
        if (payload == nullptr) { return; }
        if (len < MODBUS_GW_HEADER_SIZE) { return; }
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Modbus_Busy_Guard g(op_busy_);
        if (!g.locked) { return; }
        reinterpret_cast<Impl*>(impl_buf_)->Handle_GW_Command(payload, len);
    }

    uint8_t HTS_Modbus_Gateway::Add_Poll_Item(const Modbus_PollItem& item) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return 0xFFu; }
        Modbus_Busy_Guard g(op_busy_);
        if (!g.locked) { return 0xFFu; }
        return reinterpret_cast<Impl*>(impl_buf_)->Add_Poll_Item_Internal(item);
    }

    void HTS_Modbus_Gateway::Remove_Poll_Item(uint8_t slot_idx) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Modbus_Busy_Guard g(op_busy_);
        if (!g.locked) { return; }
        if (slot_idx >= MODBUS_MAX_POLL_ITEMS) { return; }
        reinterpret_cast<Impl*>(impl_buf_)->poll_items[slot_idx].active = 0u;
    }

    void HTS_Modbus_Gateway::Tick(uint32_t systick_ms) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Modbus_Busy_Guard g(op_busy_);
        if (!g.locked) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        impl->current_tick = systick_ms;

        if (static_cast<uint8_t>(impl->state) == 0u) { return; }  // OFFLINE

        impl->Execute_Polls();
    }

    uint16_t HTS_Modbus_Gateway::Send_Request(Modbus_PHY phy, uint8_t slave_addr,
        uint8_t func_code, const uint8_t* data,
        uint8_t data_len, uint8_t* rsp_buf,
        uint16_t rsp_buf_size) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        Modbus_Busy_Guard g(op_busy_);
        if (!g.locked) { return 0u; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        if (!impl->Transition_State(Modbus_State::REQUESTING)) { return 0u; }

        const uint16_t rsp_len = impl->Execute_Request(
            phy, slave_addr, func_code, data, data_len, rsp_buf, rsp_buf_size);

        impl->Transition_State(Modbus_State::IDLE);
        return rsp_len;
    }

    Modbus_State HTS_Modbus_Gateway::Get_State() const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return Modbus_State::OFFLINE; }
        Modbus_Busy_Guard g(op_busy_);
        if (!g.locked) { return Modbus_State::OFFLINE; }
        return reinterpret_cast<const Impl*>(impl_buf_)->state;
    }

    uint32_t HTS_Modbus_Gateway::Get_Request_Count() const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        Modbus_Busy_Guard g(op_busy_);
        if (!g.locked) { return 0u; }
        return reinterpret_cast<const Impl*>(impl_buf_)->request_count;
    }

    uint32_t HTS_Modbus_Gateway::Get_Error_Count() const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        Modbus_Busy_Guard g(op_busy_);
        if (!g.locked) { return 0u; }
        return reinterpret_cast<const Impl*>(impl_buf_)->error_count;
    }

} // namespace ProtectedEngine
