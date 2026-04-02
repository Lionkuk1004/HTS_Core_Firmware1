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
    static constexpr uint32_t BLE_INIT_NONE = 0u;
    static constexpr uint32_t BLE_INIT_BUSY = 1u;
    static constexpr uint32_t BLE_INIT_READY = 2u;

    // LTO/DCE 환경에서 민감 버퍼 소거가 제거되지 않도록 보장.
    static void BLE_Secure_Wipe_Strict(void* ptr, std::size_t size) noexcept
    {
        volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
        while (size--) { *p++ = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" ::: "memory");
#else
        std::atomic_thread_fence(std::memory_order_seq_cst);
#endif
    }

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

        // --- AT TX 전용 버퍼 ---
        //  frame_buf(128B) 재사용 → AT+SEND 헤더+페이로드+트레일러 오버플로
        //  별도 버퍼 (BLE_MAX_PAYLOAD + AT 헤더 15B + 트레일러 2B + 여유)
        static constexpr uint32_t AT_TX_BUF_SIZE = BLE_MAX_PAYLOAD + 20u;
        uint8_t at_tx_buf[AT_TX_BUF_SIZE];

        // --- UART RX Line Buffer (assembled from ring) ---
        uint8_t  uart_line_buf[BLE_UART_RX_BUF_SIZE];
        uint16_t uart_line_pos;
        bool     uart_line_overflow;  ///< 오버플로 시 라인 폐기
        uint16_t uart_data_remaining; ///< +DATA 바이트 카운팅 (0=AT모드)
        bool     uart_skip_trailing_lf; ///< \r 후 \n 소각

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
            BLE_Write_U32(&frame_buf[pos],
                static_cast<uint32_t>(local_location.code >> 32u));  pos += 4u;
            BLE_Write_U32(&frame_buf[pos],
                static_cast<uint32_t>(local_location.code & 0xFFFFFFFFu));  pos += 4u;
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
            // LocationCode 8바이트: [3..10]
            out_loc.code = (static_cast<uint64_t>(BLE_Read_U32(&data[3])) << 32u)
                | static_cast<uint64_t>(BLE_Read_U32(&data[7]));

            const uint8_t plen = data[11];
            if (plen > BLE_MAX_PAYLOAD) { return false; }

            // Overflow-safe bounds check
            if (data_region < BLE_FRAME_HEADER_SIZE) { return false; }
            //  (data_region - HEADER) < plen → 패딩 바이트 허용 → Smuggling
            //  != 정확 일치 → 1바이트라도 불일치 시 거부
            if ((data_region - BLE_FRAME_HEADER_SIZE) != static_cast<uint32_t>(plen)) {
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

                //  +DATA:<len> 파싱 후 정확히 <len> 바이트를 \n 무시하고 수집
                //  → 인밴드 AT 인젝션 원천 차단 (개행 파싱 중단)
                if (uart_data_remaining > 0u) {
                    //  "+DATA:10\r\n<binary>" → \r에서 라인 분할 → 데이터 모드 진입
                    //  다음 바이트 \n은 CRLF 잔여 → 페이로드 아님 → 1회 소각
                    if (uart_skip_trailing_lf) {
                        uart_skip_trailing_lf = false;
                        if (byte == static_cast<uint8_t>('\n')) {
                            continue;  // CRLF 잔여 \n 소각 (카운트 미차감)
                        }
                    }
                    if (uart_line_pos < BLE_UART_RX_BUF_SIZE) {
                        uart_line_buf[uart_line_pos] = byte;
                        uart_line_pos++;
                    }
                    uart_data_remaining--;
                    if (uart_data_remaining == 0u) {
                        // 데이터 수집 완료 → 콜백 전달
                        if (rx_data_cb != nullptr) {
                            BLE_Session* ds = Find_Active_BLE_Session();
                            if (ds != nullptr) {
                                rx_data_cb(BLE_MsgType::TEXT_MESSAGE,
                                    uart_line_buf, uart_line_pos, ds);
                            }
                        }
                        uart_line_pos = 0u;
                    }
                    continue;
                }

                // AT 커맨드 모드: '\n' 기반 라인 파싱
                if (byte == static_cast<uint8_t>('\n') || byte == static_cast<uint8_t>('\r')) {
                    if (uart_line_overflow) {
                        uart_line_pos = 0u;
                        uart_line_overflow = false;
                        continue;
                    }
                    if (uart_line_pos > 0u) {
                        Process_UART_Line(uart_line_buf, uart_line_pos);
                        if (uart_data_remaining > 0u) {
                            uart_skip_trailing_lf = true;
                            //  Process_UART_Line이 인라인 페이로드를 uart_line_buf에
                            //  복사하고 uart_line_pos = inline_avail로 설정한 경우,
                            //  여기서 0으로 덮어쓰면 선행 바이트 영구 파괴
                            //  → 데이터 수집 모드에서는 커서 초기화 금지
                        }
                        else {
                            uart_line_pos = 0u;
                        }
                    }
                }
                else {
                    if (uart_line_pos < BLE_UART_RX_BUF_SIZE) {
                        uart_line_buf[uart_line_pos] = byte;
                        uart_line_pos++;
                    }
                    else {
                        uart_line_overflow = true;
                    }
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

            //
            //  길이만 파싱 → uart_data_remaining = dlen
            //        → 이미 line_buf에 있는 페이로드 증발 → 위상 편이
            //  구분자(,) 이후 인라인 바이트를 먼저 소비
            //        → 부족분만 uart_data_remaining으로 설정
            if (len >= 7u && line[0] == static_cast<uint8_t>('+') &&
                line[1] == static_cast<uint8_t>('D') &&
                line[2] == static_cast<uint8_t>('A') &&
                line[3] == static_cast<uint8_t>('T') &&
                line[4] == static_cast<uint8_t>('A') &&
                line[5] == static_cast<uint8_t>(':'))
            {
                // "+DATA:<len>[,<payload>]" → ASCII 숫자 파싱
                uint16_t dlen = 0u;
                uint16_t cursor = 6u;
                for (; cursor < len; ++cursor) {
                    const uint8_t ch = line[cursor];
                    if (ch >= static_cast<uint8_t>('0') && ch <= static_cast<uint8_t>('9')) {
                        const uint16_t digits =
                            static_cast<uint16_t>(cursor - 6u + 1u);
                        // 길이 필드는 최대 3자리(0~999)까지만 허용
                        if (digits > 3u) { return; }
                        const uint16_t digit =
                            static_cast<uint16_t>(ch - static_cast<uint8_t>('0'));
                        if (dlen > static_cast<uint16_t>((65535u - digit) / 10u)) {
                            return;  // uint16_t 래핑 차단
                        }
                        dlen = static_cast<uint16_t>(dlen * 10u + (ch - static_cast<uint8_t>('0')));
                    }
                    else {
                        cursor++;  // 구분자(, 또는 :) 건너뛰기
                        break;
                    }
                }
                if (dlen == 0u || dlen > BLE_MAX_PAYLOAD) { return; }

                // 인라인 바이트: 구분자 이후 line_buf에 이미 존재하는 페이로드
                const uint16_t inline_avail = (cursor < len)
                    ? static_cast<uint16_t>(len - cursor) : 0u;

                if (inline_avail >= dlen) {
                    // 전체 페이로드가 이미 line_buf에 존재 → 즉시 전달
                    if (rx_data_cb != nullptr) {
                        BLE_Session* ds = Find_Active_BLE_Session();
                        if (ds != nullptr) {
                            rx_data_cb(BLE_MsgType::TEXT_MESSAGE,
                                &line[cursor], dlen, ds);
                        }
                    }
                    // uart_data_remaining = 0 (추가 수집 불필요)
                }
                else {
                    // 부분 페이로드 → 인라인분 line_buf에 복사 + 잔여분 카운팅
                    uart_line_pos = 0u;
                    for (uint16_t i = 0u; i < inline_avail; ++i) {
                        uart_line_buf[i] = line[cursor + i];
                    }
                    uart_line_pos = inline_avail;
                    uart_data_remaining = static_cast<uint16_t>(dlen - inline_avail);
                }
                return;
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
            //
            //  정순(i=0→N) 탐색 → 첫 번째 활성 세션 무조건 파괴
            //        → 다중 세션 시 50% 확률로 엉뚱한 세션 암살
            //
            //  역순(i=N→0) 탐색 → 가장 최근 할당 세션 종료
            //   근거: BLE/NFC 모듈은 LIFO 순서로 +DISC 발행 (마지막 연결이 먼저 끊김)
            //         역순 탐색이 정순보다 올바른 세션을 닫을 확률이 높음
            //
            //  [아키텍처 한계] AT 프로토콜에 세션 식별자 부재
            //   +DISC만으로는 어느 링크가 끊어졌는지 100% 식별 불가.
            //   양산 시 다음 중 택일 필수:
            //    (a) BLE_MAX_SESSIONS=1 단일 연결 전용으로 축소
            //    (b) AT+DISC:<conn_id> 확장 파서 구현 (모듈 스펙 의존)
            for (uint32_t i = BLE_MAX_SESSIONS; i > 0u; --i) {
                if (sessions[i - 1u].active != 0u) {
                    Close_Session(sessions[i - 1u]);
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
        : init_state_{ BLE_INIT_NONE }
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
        uint32_t expected = BLE_INIT_NONE;
        if (!init_state_.compare_exchange_strong(
            expected, BLE_INIT_BUSY, std::memory_order_acq_rel))
        {
            return (expected == BLE_INIT_READY)
                ? IPC_Error::OK
                : IPC_Error::NOT_INITIALIZED;
        }

        if (ipc == nullptr) {
            init_state_.store(BLE_INIT_NONE, std::memory_order_release);
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
        impl->uart_line_overflow = false;
        impl->uart_data_remaining = 0u;
        impl->uart_skip_trailing_lf = false;

        impl->uart_ring_head.store(0u, std::memory_order_relaxed);
        impl->uart_ring_tail.store(0u, std::memory_order_relaxed);

        for (uint32_t i = 0u; i < BLE_MAX_SESSIONS; ++i) {
            impl->sessions[i].active = 0u;
        }

        impl->Transition_State(BLE_GW_State::IDLE);
        init_state_.store(BLE_INIT_READY, std::memory_order_release);
        return IPC_Error::OK;
    }

    void HTS_BLE_NFC_Gateway::Shutdown() noexcept
    {
        if (init_state_.load(std::memory_order_acquire) != BLE_INIT_READY) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        for (uint32_t i = 0u; i < BLE_MAX_SESSIONS; ++i) {
            impl->sessions[i].active = 0u;
        }
        BLE_Secure_Wipe_Strict(impl->frame_buf, BLE_MAX_FRAME_SIZE);
        BLE_Secure_Wipe_Strict(impl->at_tx_buf, Impl::AT_TX_BUF_SIZE);  // AT TX 버퍼 소거
        BLE_Secure_Wipe_Strict(impl->uart_line_buf, BLE_UART_RX_BUF_SIZE);
        BLE_Secure_Wipe_Strict(impl->uart_ring, UART_RING_SIZE);
        std::atomic_thread_fence(std::memory_order_release);

        impl->state = BLE_GW_State::OFFLINE;
        impl->ipc = nullptr;
        impl->~Impl();

        BLE_Secure_Wipe_Strict(impl_buf_, IMPL_BUF_SIZE);

        init_state_.store(BLE_INIT_NONE, std::memory_order_release);
    }

    void HTS_BLE_NFC_Gateway::Register_UART_TX(BLE_UART_TX_Callback cb) noexcept
    {
        if (init_state_.load(std::memory_order_acquire) != BLE_INIT_READY) { return; }
        reinterpret_cast<Impl*>(impl_buf_)->uart_tx_cb = cb;
    }

    void HTS_BLE_NFC_Gateway::Register_RX_Callback(BLE_RX_Data_Callback cb) noexcept
    {
        if (init_state_.load(std::memory_order_acquire) != BLE_INIT_READY) { return; }
        reinterpret_cast<Impl*>(impl_buf_)->rx_data_cb = cb;
    }

    void HTS_BLE_NFC_Gateway::Tick(uint32_t systick_ms) noexcept
    {
        if (init_state_.load(std::memory_order_acquire) != BLE_INIT_READY) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        // Store current tick for use by internal methods (Handle_Connection_Event etc.)
        impl->current_tick = systick_ms;

        // Drain UART ring (processes +CONN, +DISC, +DATA etc.)
        impl->Drain_UART_Ring();

        //  has_uart_activity → 모든 활성 세션 tick 갱신
        //        → BLE 사용자 통신으로 NFC 세션까지 수명 연장 → 좀비 세션
        //  삭제. 세션 tick은 해당 세션이 식별된 문맥에서만 개별 갱신:
        //   · Relay_From_BCDMA: Find_Session(session_id) → s->last_activity_tick
        //   · Send_Text/Voice/Emergency: 게이트키퍼 s → s->last_activity_tick
        //   · Drain_UART_Ring DATA_BODY: Find_Active_BLE_Session() → ds->tick

        // Check and expire timed-out sessions
        impl->Check_Session_Timeouts(systick_ms);
    }

    void HTS_BLE_NFC_Gateway::Feed_UART_Byte(uint8_t byte) noexcept
    {
        if (init_state_.load(std::memory_order_acquire) != BLE_INIT_READY) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        //
        //  SPSC Lock-free → 단일 ISR에서는 안전
        //        BUT: DMA완료 ISR + UART RX ISR 중첩 시 head 포인터 경합
        //        → 동일 슬롯 이중 쓰기 → 바이트 유실 + 링 포인터 오염
        //
        //  PRIMASK로 head 읽기~쓰기 원자적 보호 (~10사이클)
        //        UART 바이트 간격 ~87µs@115200bps → 10cyc 차단 영향 0
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
        uint32_t primask;
        __asm__ __volatile__("mrs %0, primask\n\tcpsid i"
            : "=r"(primask) : : "memory");
#endif

        const uint32_t head = impl->uart_ring_head.load(std::memory_order_relaxed);
        const uint32_t tail = impl->uart_ring_tail.load(std::memory_order_acquire);

        if ((head - tail) < UART_RING_SIZE) {
            impl->uart_ring[head & UART_RING_MASK] = byte;
            impl->uart_ring_head.store(head + 1u, std::memory_order_release);
        }

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
        __asm__ __volatile__("msr primask, %0" : : "r"(primask) : "memory");
#endif
    }

    void HTS_BLE_NFC_Gateway::Relay_From_BCDMA(const uint8_t* payload,
        uint16_t len) noexcept
    {
        if (payload == nullptr) { return; }
        if (len == 0u) { return; }
        if (init_state_.load(std::memory_order_acquire) != BLE_INIT_READY) { return; }
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

        //  loc 추출 후 미검증 → 타 안내판 프레임도 무단 릴레이
        //  loc.code ≠ local → Drop (자기 위치 프레임만 수용)
        //  예외: loc.code == 0 → 브로드캐스트 (전체 안내판 대상)
        if (loc.code != 0u && loc.code != impl->local_location.code) {
            return;  // 타 안내판 프레임 → 폐기
        }

        BLE_Session* s = impl->Find_Session(session_id);
        if (s == nullptr) { return; }

        //  msg_type 무시 → 모든 패킷 AT+SEND 릴레이 (바보 파이프)
        //  TEXT/VOICE → AT+SEND, SESSION_CLOSE → 세션 파기 + AT+DISC
        switch (msg_type) {
        case BLE_MsgType::TEXT_MESSAGE:
        case BLE_MsgType::VOICE_TRIGGER:
        case BLE_MsgType::DEVICE_INFO:
        {
            // 데이터 메시지 → AT+SEND 원자적 릴레이
            if (impl->uart_tx_cb != nullptr && frame_payload != nullptr && frame_payload_len > 0u) {
                uint32_t tx_pos = 0u;
                impl->at_tx_buf[tx_pos++] = static_cast<uint8_t>('A');
                impl->at_tx_buf[tx_pos++] = static_cast<uint8_t>('T');
                impl->at_tx_buf[tx_pos++] = static_cast<uint8_t>('+');
                impl->at_tx_buf[tx_pos++] = static_cast<uint8_t>('S');
                impl->at_tx_buf[tx_pos++] = static_cast<uint8_t>('E');
                impl->at_tx_buf[tx_pos++] = static_cast<uint8_t>('N');
                impl->at_tx_buf[tx_pos++] = static_cast<uint8_t>('D');
                impl->at_tx_buf[tx_pos++] = static_cast<uint8_t>('=');
                uint16_t rem = frame_payload_len;
                if (rem >= 100u) {
                    impl->at_tx_buf[tx_pos++] = static_cast<uint8_t>('0' + static_cast<uint8_t>(rem / 100u));
                    rem = static_cast<uint16_t>(rem % 100u);
                    impl->at_tx_buf[tx_pos++] = static_cast<uint8_t>('0' + static_cast<uint8_t>(rem / 10u));
                    impl->at_tx_buf[tx_pos++] = static_cast<uint8_t>('0' + static_cast<uint8_t>(rem % 10u));
                }
                else if (rem >= 10u) {
                    impl->at_tx_buf[tx_pos++] = static_cast<uint8_t>('0' + static_cast<uint8_t>(rem / 10u));
                    impl->at_tx_buf[tx_pos++] = static_cast<uint8_t>('0' + static_cast<uint8_t>(rem % 10u));
                }
                else {
                    impl->at_tx_buf[tx_pos++] = static_cast<uint8_t>('0' + static_cast<uint8_t>(rem));
                }
                impl->at_tx_buf[tx_pos++] = static_cast<uint8_t>('\r');
                impl->at_tx_buf[tx_pos++] = static_cast<uint8_t>('\n');
                for (uint16_t i = 0u; i < frame_payload_len; ++i) {
                    impl->at_tx_buf[tx_pos++] = frame_payload[i];
                }
                impl->at_tx_buf[tx_pos++] = static_cast<uint8_t>('\r');
                impl->at_tx_buf[tx_pos++] = static_cast<uint8_t>('\n');
                impl->uart_tx_cb(impl->at_tx_buf, static_cast<uint16_t>(tx_pos));
            }
            break;
        }
        case BLE_MsgType::SESSION_CLOSE:
            // 관제센터 강제 세션 종료 → 로컬 파기 + AT+DISC
            impl->Close_Session(*s);
            if (impl->uart_tx_cb != nullptr) {
                const uint8_t disc_cmd[] = { 'A','T','+','D','I','S','C','\r','\n' };
                impl->uart_tx_cb(disc_cmd, 9u);
            }
            if (impl->Count_Active_Sessions() == 0u) {
                impl->Transition_State(BLE_GW_State::IDLE);
            }
            return;
        case BLE_MsgType::HEARTBEAT:
            break;  // 틱 갱신만
        default:
            break;  // 미구현 제어 메시지 → Drop
        }

        // Update session activity
        s->last_activity_tick = impl->current_tick;
    }

    IPC_Error HTS_BLE_NFC_Gateway::Send_Text(const uint8_t* text, uint16_t text_len,
        uint16_t session_id) noexcept
    {
        if (text == nullptr && text_len > 0u) { return IPC_Error::BUFFER_OVERFLOW; }
        if (text_len > BLE_MAX_PAYLOAD) { return IPC_Error::INVALID_LEN; }
        if (init_state_.load(std::memory_order_acquire) != BLE_INIT_READY) { return IPC_Error::NOT_INITIALIZED; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        if (impl->ipc == nullptr) { return IPC_Error::NOT_INITIALIZED; }

        //  전송 완료 후 마지막에 Find_Session → 유령 세션도 망으로 송신
        //  전송 전 선검증 → nullptr이면 즉각 거부
        BLE_Session* s = impl->Find_Session(session_id);
        if (s == nullptr) { return IPC_Error::CFI_VIOLATION; }

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
        s->last_activity_tick = impl->current_tick;

        return IPC_Error::OK;
    }

    IPC_Error HTS_BLE_NFC_Gateway::Send_Voice_Trigger(uint16_t voice_index,
        uint16_t session_id) noexcept
    {
        if (init_state_.load(std::memory_order_acquire) != BLE_INIT_READY) { return IPC_Error::NOT_INITIALIZED; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        if (impl->ipc == nullptr) { return IPC_Error::NOT_INITIALIZED; }

        BLE_Session* sv_check = impl->Find_Session(session_id);
        if (sv_check == nullptr) { return IPC_Error::CFI_VIOLATION; }

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

        // 게이트키퍼에서 확보한 sv_check 재사용 (중복 조회 제거)
        sv_check->last_activity_tick = impl->current_tick;

        return IPC_Error::OK;
    }

    IPC_Error HTS_BLE_NFC_Gateway::Send_Emergency(uint16_t session_id) noexcept
    {
        if (init_state_.load(std::memory_order_acquire) != BLE_INIT_READY) { return IPC_Error::NOT_INITIALIZED; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        if (impl->ipc == nullptr) { return IPC_Error::NOT_INITIALIZED; }

        BLE_Session* se_check = impl->Find_Session(session_id);
        if (se_check == nullptr) { return IPC_Error::CFI_VIOLATION; }

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

        // 게이트키퍼에서 확보한 se_check 재사용 (중복 조회 제거)
        se_check->last_activity_tick = impl->current_tick;

        return IPC_Error::OK;
    }

    BLE_GW_State HTS_BLE_NFC_Gateway::Get_State() const noexcept
    {
        if (init_state_.load(std::memory_order_acquire) != BLE_INIT_READY) { return BLE_GW_State::OFFLINE; }
        return reinterpret_cast<const Impl*>(impl_buf_)->state;
    }

    uint32_t HTS_BLE_NFC_Gateway::Get_Active_Session_Count() const noexcept
    {
        if (init_state_.load(std::memory_order_acquire) != BLE_INIT_READY) { return 0u; }
        return reinterpret_cast<const Impl*>(impl_buf_)->Count_Active_Sessions();
    }

} // namespace ProtectedEngine
