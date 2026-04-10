/// @file  HTS_Network_Bridge.cpp
/// @brief HTS Network Bridge -- Ethernet <-> B-CDMA Implementation
/// @note  ARM only. Pure ASCII. No PC/server code.
/// @author Lim Young-jun
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_Network_Bridge.h"
#include "HTS_IPC_Protocol.h"
#include <new>
#include <atomic>
#include <cstring>   // memcpy, memset

namespace ProtectedEngine {
    struct Bridge_Busy_Guard {
        std::atomic_flag& f;
        uint32_t locked;
        explicit Bridge_Busy_Guard(std::atomic_flag& flag) noexcept
            : f(flag), locked(BRIDGE_SECURE_FALSE) {
            if (!f.test_and_set(std::memory_order_acquire)) {
                locked = BRIDGE_SECURE_TRUE;
            }
        }
        ~Bridge_Busy_Guard() noexcept {
            if (locked == BRIDGE_SECURE_TRUE) {
                f.clear(std::memory_order_release);
            }
        }
    };

    //  BRIDGE_MAX_FRAGMENTS ≤ 8 보장 — 초과 시 즉시 빌드 실패
    //  향후 MAX_FRAGMENTS 증가 시 received_mask를 uint16_t/uint32_t로 확장 필수
    static_assert(BRIDGE_MAX_FRAGMENTS <= 8u,
        "BRIDGE_MAX_FRAGMENTS > 8: received_mask(uint8_t) overflow. "
        "Upgrade ReassemblySlot::received_mask to uint16_t.");

    // ============================================================
    //  Impl Structure
    // ============================================================

    struct HTS_Network_Bridge::Impl {
        // --- Dependencies ---
        HTS_IPC_Protocol* ipc;
        Bridge_ETH_Callback eth_callback;

        // --- CFI State ---
        BridgeState state;
        uint8_t     cfi_violation_count;
        uint8_t     tx_seq;     ///< TX fragmentation sequence counter
        uint8_t     pad_[1];

        // --- Statistics ---
        uint32_t tx_frag_count;
        uint32_t rx_reassembled_count;
        uint32_t timeout_count;
        uint32_t crc_error_count;

        // --- Reassembly Slots ---
        ReassemblySlot slots[BRIDGE_REASSEMBLY_SLOTS];

        // --- TX fragment buffer (single frame at a time) ---
        uint8_t tx_frag_buf[BRIDGE_FRAG_HEADER_SIZE + BRIDGE_FRAG_MAX_DATA];

        // ============================================================
        //  CFI Transition
        // ============================================================
        uint32_t Transition_State(BridgeState target) noexcept
        {
            if (Bridge_Is_Legal_Transition(state, target) != BRIDGE_SECURE_TRUE) {
                if (Bridge_Is_Legal_Transition(state, BridgeState::ERROR) == BRIDGE_SECURE_TRUE) {
                    state = BridgeState::ERROR;
                }
                else {
                    state = BridgeState::DISABLED;
                }
                cfi_violation_count++;
                return BRIDGE_SECURE_FALSE;
            }
            state = target;
            return BRIDGE_SECURE_TRUE;
        }

        // ============================================================
        //  Fragment ETH Frame and Send via IPC
        // ============================================================
        IPC_Error Do_Fragment_And_Send(const uint8_t* eth_frame,
            uint16_t eth_len) noexcept
        {
            if (ipc == nullptr) { return IPC_Error::NOT_INITIALIZED; }
            if (eth_frame == nullptr || eth_len == 0u) { return IPC_Error::INVALID_LEN; }
            if (eth_len > BRIDGE_ETH_MAX_FRAME) { return IPC_Error::INVALID_LEN; }

            // CFI: IDLE -> FRAGMENTING
            if (Transition_State(BridgeState::FRAGMENTING) != BRIDGE_SECURE_TRUE) {
                return IPC_Error::CFI_VIOLATION;
            }

            // [OPT-1] ceil: UDIV 1회
            //  Cortex-M4 하드웨어 UDIV: 비2의제곱 나눗셈도 단일 명령어
            //  BRIDGE_FRAG_MAX_DATA=248 (2의 거듭제곱 아님) — UDIV 사용
            uint32_t total_u32 = 0u;
            uint32_t remain_u32 = static_cast<uint32_t>(eth_len);
            while (remain_u32 > 0u && total_u32 < BRIDGE_MAX_FRAGMENTS) {
                ++total_u32;
                if (remain_u32 > BRIDGE_FRAG_MAX_DATA) {
                    remain_u32 -= BRIDGE_FRAG_MAX_DATA;
                }
                else {
                    remain_u32 = 0u;
                }
            }
            const uint8_t total = static_cast<uint8_t>(total_u32);

            if (total == 0u) {
                Transition_State(BridgeState::ERROR);
                return IPC_Error::INVALID_LEN;
            }

            const uint8_t seq = tx_seq;
            tx_seq = static_cast<uint8_t>((static_cast<uint32_t>(tx_seq) + 1u) & BRIDGE_SEQ_MASK);

            uint32_t offset = 0u;
            for (uint8_t idx = 0u; idx < total; ++idx) {
                // Compute this fragment's data length
                const uint32_t remaining = static_cast<uint32_t>(eth_len) - offset;
                const uint32_t chunk = (remaining < BRIDGE_FRAG_MAX_DATA)
                    ? remaining : BRIDGE_FRAG_MAX_DATA;

                // Build fragment header
                uint8_t flags = 0u;
                if (idx == 0u) { flags |= FragFlag::FIRST; }
                if (idx == static_cast<uint8_t>(total - 1u)) { flags |= FragFlag::LAST; }
                if (idx < static_cast<uint8_t>(total - 1u)) { flags |= FragFlag::MORE_FRAGMENTS; }

                tx_frag_buf[0] = flags;
                tx_frag_buf[1] = seq;
                tx_frag_buf[2] = total;
                tx_frag_buf[3] = idx;

                // [OPT-2] memcpy 블록 복사
                std::memcpy(&tx_frag_buf[BRIDGE_FRAG_HEADER_SIZE],
                    &eth_frame[offset], chunk);

                // Send via IPC
                const uint16_t frag_total_len = static_cast<uint16_t>(
                    BRIDGE_FRAG_HEADER_SIZE + chunk);
                const IPC_Error err = ipc->Send_Frame(
                    IPC_Command::DATA_TX, tx_frag_buf, frag_total_len);

                if (err != IPC_Error::OK) {
                    Transition_State(BridgeState::ERROR);
                    return err;
                }

                offset += chunk;
                tx_frag_count++;
            }

            // CFI: FRAGMENTING -> IDLE
            Transition_State(BridgeState::IDLE);
            return IPC_Error::OK;
        }

        // ============================================================
        //  Feed Fragment into Reassembly Engine (CFI-protected)
        // ============================================================
        uint32_t Do_Feed_Fragment(const uint8_t* frag_payload, uint16_t frag_len,
            uint32_t systick_ms) noexcept
        {
            if (frag_payload == nullptr) { return BRIDGE_SECURE_FALSE; }
            if (frag_len < BRIDGE_FRAG_HEADER_SIZE) { return BRIDGE_SECURE_FALSE; }

            // --- CFI: IDLE -> REASSEMBLING ---
            // Must be in IDLE (or already REASSEMBLING for multi-fragment flow).
            // Blocks: DISABLED/ERROR/FRAGMENTING states from entering reassembly.
            if ((static_cast<uint8_t>(state) & static_cast<uint8_t>(BridgeState::REASSEMBLING)) == 0u) {
                if (Transition_State(BridgeState::REASSEMBLING) != BRIDGE_SECURE_TRUE) {
                    return BRIDGE_SECURE_FALSE;
                }
            }

            // Parse fragment header
            const uint8_t flags = frag_payload[0];
            const uint8_t seq = frag_payload[1];
            const uint8_t total = frag_payload[2];
            const uint8_t idx = frag_payload[3];

            // --- Input validation ---
            if (total == 0u || total > BRIDGE_MAX_FRAGMENTS) {
                Transition_State(BridgeState::IDLE);
                return BRIDGE_SECURE_FALSE;
            }
            if (idx >= total) {
                Transition_State(BridgeState::IDLE);
                return BRIDGE_SECURE_FALSE;
            }

            const uint16_t data_len = static_cast<uint16_t>(frag_len - BRIDGE_FRAG_HEADER_SIZE);
            if (data_len > BRIDGE_FRAG_MAX_DATA) {
                Transition_State(BridgeState::IDLE);
                return BRIDGE_SECURE_FALSE;
            }

            // Find or allocate reassembly slot
            ReassemblySlot* slot = Find_Or_Alloc_Slot(seq, total, systick_ms);
            if (slot == nullptr) {
                Transition_State(BridgeState::IDLE);
                return BRIDGE_SECURE_FALSE;
            }

            // --- CRITICAL: Teardrop attack defense ---
            // Reject fragments whose 'total' field disagrees with the slot's
            // expected_total (set when the slot was first allocated).
            //
            // Attack scenario without this check:
            //   1. Normal fragments 0,1,2 arrive (total=7). mask=0b111.
            //   2. Attacker injects {idx=2, total=3}.
            //   3. expected_mask = (1<<3)-1 = 0b111 matches mask -> PREMATURE COMPLETION
            //   4. Incomplete garbage frame floods into Ethernet.
            //
            // Fix: Compare incoming 'total' against slot->expected_total.
            //      Any mismatch -> reject + invalidate slot (potential attack).
            if (total != slot->expected_total) {
                // Mismatch: either corruption or deliberate Teardrop attack.
                // Invalidate entire slot to prevent partial-data exploitation.
                slot->active = 0u;
                slot->received_mask = 0u;
                IPC_Secure_Wipe(slot->data, BRIDGE_ETH_MAX_FRAME);
                Transition_State(BridgeState::IDLE);
                return BRIDGE_SECURE_FALSE;
            }

            // Compute data offset in reassembly buffer
            // offset = idx * BRIDGE_FRAG_MAX_DATA (no division needed)
            const uint32_t data_offset = static_cast<uint32_t>(idx) * BRIDGE_FRAG_MAX_DATA;
            if (data_offset > BRIDGE_ETH_MAX_FRAME) {
                Transition_State(BridgeState::IDLE);
                return BRIDGE_SECURE_FALSE;
            }
            const uint32_t frame_remain = BRIDGE_ETH_MAX_FRAME - data_offset;
            if (static_cast<uint32_t>(data_len) > frame_remain) {
                Transition_State(BridgeState::IDLE);
                return BRIDGE_SECURE_FALSE;
            }

            // --- Duplicate fragment detection ---
            // Reject if this index was already received (replay/reflection attack)
            const uint8_t idx_bit = static_cast<uint8_t>(1u << idx);
            if ((slot->received_mask & idx_bit) != 0u) {
                // Already received this index -- silently ignore (not an error)
                Transition_State(BridgeState::IDLE);
                return BRIDGE_SECURE_FALSE;
            }

            // [OPT-2] memcpy 블록 복사
            const uint8_t* src = &frag_payload[BRIDGE_FRAG_HEADER_SIZE];
            std::memcpy(&slot->data[data_offset], src, data_len);

            // Update received bitmask
            slot->received_mask |= idx_bit;

            // Track total data length (last fragment determines final size)
            if ((flags & FragFlag::LAST) != 0u) {
                slot->data_len = static_cast<uint16_t>(data_offset + data_len);
            }

            // --- Reassembly completion check ---
            // MUST use slot->expected_total (trusted, set at allocation time),
            // NEVER the incoming packet's 'total' field (untrusted wire data).
            const uint8_t expected_mask = static_cast<uint8_t>(
                (1u << slot->expected_total) - 1u);

            if (slot->received_mask == expected_mask) {
                // All fragments received -- deliver to Ethernet
                if (eth_callback != nullptr && slot->data_len > 0u) {
                    eth_callback(slot->data, slot->data_len);
                }
                rx_reassembled_count++;

                // Secure wipe and free slot
                IPC_Secure_Wipe(slot->data, BRIDGE_ETH_MAX_FRAME);
                slot->active = 0u;
                slot->received_mask = 0u;

                // CFI: REASSEMBLING -> IDLE
                Transition_State(BridgeState::IDLE);
                return BRIDGE_SECURE_TRUE;
            }

            // Not complete yet -- remain in REASSEMBLING
            // (Next Feed_Fragment call will skip the IDLE->REASSEMBLING transition
            //  because state is already REASSEMBLING)
            return BRIDGE_SECURE_FALSE;
        }

        // ============================================================
        //  Find or Allocate Reassembly Slot
        // ============================================================
        ReassemblySlot* Find_Or_Alloc_Slot(uint8_t seq, uint8_t total,
            uint32_t systick_ms) noexcept
        {
            // Search for existing slot with same sequence
            for (uint32_t i = 0u; i < BRIDGE_REASSEMBLY_SLOTS; ++i) {
                if (slots[i].active != 0u && slots[i].seq == seq) {
                    return &slots[i];
                }
            }

            // Allocate new slot (find first free or oldest timed-out)
            for (uint32_t i = 0u; i < BRIDGE_REASSEMBLY_SLOTS; ++i) {
                if (slots[i].active == 0u) {
                    Init_Slot(slots[i], seq, total, systick_ms);
                    return &slots[i];
                }
            }

            // All slots busy -- evict oldest
            uint32_t oldest_idx = 0u;
            uint32_t oldest_age = 0u;
            for (uint32_t i = 0u; i < BRIDGE_REASSEMBLY_SLOTS; ++i) {
                const uint32_t age = systick_ms - slots[i].start_tick;
                if (age > oldest_age) {
                    oldest_age = age;
                    oldest_idx = i;
                }
            }
            timeout_count++;
            Init_Slot(slots[oldest_idx], seq, total, systick_ms);
            return &slots[oldest_idx];
        }

        // ============================================================
        //  Initialize Reassembly Slot
        // ============================================================
        static void Init_Slot(ReassemblySlot& s, uint8_t seq, uint8_t total,
            uint32_t tick) noexcept
        {
            // [OPT-2] memset 제로화
            std::memset(s.data, 0, BRIDGE_ETH_MAX_FRAME);
            s.data_len = 0u;
            s.seq = seq;
            s.expected_total = total;
            s.received_mask = 0u;
            s.active = 1u;
            s.start_tick = tick;
        }

        // ============================================================
        //  Timeout Check
        // ============================================================
        void Check_Timeouts(uint32_t systick_ms) noexcept
        {
            bool any_active = false;
            for (uint32_t i = 0u; i < BRIDGE_REASSEMBLY_SLOTS; ++i) {
                if (slots[i].active == 0u) { continue; }
                const uint32_t elapsed = systick_ms - slots[i].start_tick;
                if (elapsed >= BRIDGE_REASSEMBLY_TIMEOUT) {
                    // Timed out: secure wipe (may contain plaintext ETH data)
                    IPC_Secure_Wipe(slots[i].data, BRIDGE_ETH_MAX_FRAME);
                    slots[i].active = 0u;
                    slots[i].received_mask = 0u;
                    timeout_count++;
                }
                else {
                    any_active = true;
                }
            }

            // If no active reassembly slots remain and we're in REASSEMBLING,
            // transition back to IDLE so the CFI gate is properly closed.
            if (!any_active &&
                (static_cast<uint8_t>(state) & static_cast<uint8_t>(BridgeState::REASSEMBLING)) != 0u) {
                Transition_State(BridgeState::IDLE);
            }
        }
    };

    // ============================================================
    //  Public API
    // ============================================================

    HTS_Network_Bridge::HTS_Network_Bridge() noexcept
        : initialized_{ false }
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "HTS_Network_Bridge::Impl exceeds IMPL_BUF_SIZE");

        // [OPT-2] memset 제로화
        std::memset(impl_buf_, 0, IMPL_BUF_SIZE);
    }

    HTS_Network_Bridge::~HTS_Network_Bridge() noexcept
    {
        Shutdown();
    }

    IPC_Error HTS_Network_Bridge::Initialize(HTS_IPC_Protocol* ipc) noexcept
    {
        Bridge_Busy_Guard guard(op_busy_);
        if (guard.locked != BRIDGE_SECURE_TRUE) { return IPC_Error::BUSY; }
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
        impl->eth_callback = nullptr;
        impl->state = BridgeState::DISABLED;
        impl->cfi_violation_count = 0u;
        impl->tx_seq = 0u;
        impl->tx_frag_count = 0u;
        impl->rx_reassembled_count = 0u;
        impl->timeout_count = 0u;
        impl->crc_error_count = 0u;

        for (uint32_t i = 0u; i < BRIDGE_REASSEMBLY_SLOTS; ++i) {
            impl->slots[i].active = 0u;
            impl->slots[i].received_mask = 0u;
        }

        // CFI: DISABLED -> IDLE
        impl->Transition_State(BridgeState::IDLE);

        return IPC_Error::OK;
    }

    void HTS_Network_Bridge::Shutdown() noexcept
    {
        Bridge_Busy_Guard guard(op_busy_);
        if (guard.locked != BRIDGE_SECURE_TRUE) { return; }
        if (!initialized_.load(std::memory_order_acquire)) { return; }

        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        // 파괴·소거 전에 공개 API 차단 — ~Impl/버퍼 소거 중 Feed/Fragment UAF 방지
        initialized_.store(false, std::memory_order_release);

        // Secure wipe reassembly slots (may contain plaintext ETH data)
        for (uint32_t i = 0u; i < BRIDGE_REASSEMBLY_SLOTS; ++i) {
            IPC_Secure_Wipe(impl->slots[i].data, BRIDGE_ETH_MAX_FRAME);
            impl->slots[i].active = 0u;
        }
        IPC_Secure_Wipe(impl->tx_frag_buf, sizeof(impl->tx_frag_buf));
        std::atomic_thread_fence(std::memory_order_release);

        impl->state = BridgeState::DISABLED;
        impl->ipc = nullptr;
        impl->~Impl();
        IPC_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
    }

    void HTS_Network_Bridge::Register_ETH_Callback(Bridge_ETH_Callback cb) noexcept
    {
        Bridge_Busy_Guard guard(op_busy_);
        if (guard.locked != BRIDGE_SECURE_TRUE) { return; }
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        impl->eth_callback = cb;
    }

    IPC_Error HTS_Network_Bridge::Fragment_And_Send(
        const uint8_t* eth_frame, uint16_t eth_len) noexcept
    {
        Bridge_Busy_Guard guard(op_busy_);
        if (guard.locked != BRIDGE_SECURE_TRUE) { return IPC_Error::BUSY; }
        if (!initialized_.load(std::memory_order_acquire)) {
            return IPC_Error::NOT_INITIALIZED;
        }
        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        return impl->Do_Fragment_And_Send(eth_frame, eth_len);
    }

    uint32_t HTS_Network_Bridge::Feed_Fragment(
        const uint8_t* frag_payload, uint16_t frag_len,
        uint32_t systick_ms) noexcept
    {
        Bridge_Busy_Guard guard(op_busy_);
        if (guard.locked != BRIDGE_SECURE_TRUE) { return BRIDGE_SECURE_FALSE; }
        if (!initialized_.load(std::memory_order_acquire)) { return BRIDGE_SECURE_FALSE; }
        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        return impl->Do_Feed_Fragment(frag_payload, frag_len, systick_ms);
    }

    void HTS_Network_Bridge::Tick(uint32_t systick_ms) noexcept
    {
        Bridge_Busy_Guard guard(op_busy_);
        if (guard.locked != BRIDGE_SECURE_TRUE) { return; }
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        impl->Check_Timeouts(systick_ms);
    }

    BridgeState HTS_Network_Bridge::Get_State() const noexcept
    {
        Bridge_Busy_Guard guard(op_busy_);
        if (guard.locked != BRIDGE_SECURE_TRUE) { return BridgeState::DISABLED; }
        if (!initialized_.load(std::memory_order_acquire)) {
            return BridgeState::DISABLED;
        }
        const Impl* impl = reinterpret_cast<const Impl*>(impl_buf_);
        return impl->state;
    }

    uint32_t HTS_Network_Bridge::Get_TX_Fragment_Count() const noexcept
    {
        Bridge_Busy_Guard guard(op_busy_);
        if (guard.locked != BRIDGE_SECURE_TRUE) { return 0u; }
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        const Impl* impl = reinterpret_cast<const Impl*>(impl_buf_);
        return impl->tx_frag_count;
    }

    uint32_t HTS_Network_Bridge::Get_RX_Reassembled_Count() const noexcept
    {
        Bridge_Busy_Guard guard(op_busy_);
        if (guard.locked != BRIDGE_SECURE_TRUE) { return 0u; }
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        const Impl* impl = reinterpret_cast<const Impl*>(impl_buf_);
        return impl->rx_reassembled_count;
    }

    uint32_t HTS_Network_Bridge::Get_Timeout_Count() const noexcept
    {
        Bridge_Busy_Guard guard(op_busy_);
        if (guard.locked != BRIDGE_SECURE_TRUE) { return 0u; }
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        const Impl* impl = reinterpret_cast<const Impl*>(impl_buf_);
        return impl->timeout_count;
    }

} // namespace ProtectedEngine
