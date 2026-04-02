/// @file  HTS_Holo_Dispatcher.cpp
/// @brief HTS 4D Holographic Dispatcher -- V400 Integration Shim
/// @note  ARM only. Pure ASCII. No PC/server code.
///
///  Integration strategy:
///  - Existing Dispatcher handles VIDEO_1/16/VOICE/DATA unchanged
///  - This shim handles VOICE_HOLO/DATA_HOLO/RESILIENT_HOLO
///  - Zero modifications to existing code
///  - Output format: I/Q int16_t chips (identical to Dispatcher output)
///
/// @author Lim Young-jun
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_Holo_Dispatcher.h"
#include "HTS_Secure_Memory.h"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace ProtectedEngine {

    namespace {
        /// int32 / 32 — SDIV·부호형 >> 의존 없음 (양수 기반 uint32_t 시프트)
        static inline int32_t Int32_Div32_TruncZero(int32_t v) noexcept {
            const uint32_t uv = static_cast<uint32_t>(v);
            if (v >= 0) {
                return static_cast<int32_t>(uv >> 5u);
            }
            const uint32_t mag = static_cast<uint32_t>(0u - uv);
            return -static_cast<int32_t>(mag >> 5u);
        }

        /// int32 / 2 — 소프트 디시전 누적, SDIV·부호형 >> 의존 없음
        static inline int32_t Int32_Div2_TruncZero(int32_t sum) noexcept {
            const uint32_t us = static_cast<uint32_t>(sum);
            if (sum >= 0) {
                return static_cast<int32_t>(us >> 1u);
            }
            const uint32_t mag = static_cast<uint32_t>(0u - us);
            return -static_cast<int32_t>(mag >> 1u);
        }

        struct Holo_Dispatch_Busy_Guard final {
            std::atomic<uint32_t>* gate;
            uint32_t locked;
            explicit Holo_Dispatch_Busy_Guard(std::atomic<uint32_t>& g) noexcept
                : gate(&g), locked(HTS_Holo_Dispatcher::SECURE_FALSE) {
                uint32_t expected = HTS_Holo_Dispatcher::LOCK_FREE;
                if (gate->compare_exchange_strong(expected, HTS_Holo_Dispatcher::LOCK_BUSY,
                    std::memory_order_acq_rel, std::memory_order_relaxed)) {
                    locked = HTS_Holo_Dispatcher::SECURE_TRUE;
                }
            }
            ~Holo_Dispatch_Busy_Guard() noexcept {
                if (locked == HTS_Holo_Dispatcher::SECURE_TRUE) {
                    gate->store(HTS_Holo_Dispatcher::LOCK_FREE, std::memory_order_release);
                }
            }
            Holo_Dispatch_Busy_Guard(const Holo_Dispatch_Busy_Guard&) = delete;
            Holo_Dispatch_Busy_Guard& operator=(const Holo_Dispatch_Busy_Guard&) = delete;
        };
    } // namespace

    // ============================================================
    //  Helper: bytes to BPSK bits (+1/-1)
    // ============================================================

    static uint16_t Bytes_To_BPSK(const uint8_t* bytes, size_t byte_len,
        int8_t* bpsk_bits, uint16_t max_bits) noexcept
    {
        if (bpsk_bits == nullptr) { return 0u; }
        if (byte_len > 0u && bytes == nullptr) { return 0u; }
        uint16_t bit_idx = 0u;
        for (size_t b = 0u; b < byte_len; ++b) {
            for (int i = 7; i >= 0; --i) {
                if (bit_idx >= max_bits) { return bit_idx; }
                const uint32_t byte_u = static_cast<uint32_t>(bytes[static_cast<size_t>(b)]);
                const uint32_t shifted = byte_u >> static_cast<uint32_t>(i);
                const uint8_t bit = static_cast<uint8_t>(shifted & 1u);
                bpsk_bits[static_cast<size_t>(bit_idx)] =
                    (bit != 0u) ? static_cast<int8_t>(1) : static_cast<int8_t>(-1);
                ++bit_idx;
            }
        }
        return bit_idx;
    }

    // ============================================================
    //  Helper: BPSK bits (+1/-1) to bytes
    // ============================================================

    static size_t BPSK_To_Bytes(const int8_t* bpsk_bits, uint16_t bit_count,
        uint8_t* bytes, size_t max_bytes) noexcept
    {
        if (bpsk_bits == nullptr || bytes == nullptr) { return 0u; }
        // Round up to bytes (uint16_t 상한 내에서 size_t로 산출 — J-1 언더/오버 방어)
        const size_t byte_count_full =
            (static_cast<size_t>(bit_count) + static_cast<size_t>(7u)) >> static_cast<size_t>(3u);
        size_t byte_count = byte_count_full;
        if (byte_count > max_bytes) {
            byte_count = max_bytes;
        }

        std::memset(bytes, 0, byte_count);
        for (uint16_t i = 0u; i < bit_count; ++i) {
            const size_t bi = static_cast<size_t>(static_cast<uint32_t>(i) >> 3u);
            if (bi >= byte_count) { break; }
            if (bpsk_bits[static_cast<size_t>(i)] > 0) {
                const uint32_t base = static_cast<uint32_t>(bytes[bi]);
                const uint32_t sh = 7u - (static_cast<uint32_t>(i) & 7u);
                const uint32_t mask = static_cast<uint32_t>(1u) << sh;
                bytes[bi] = static_cast<uint8_t>(base | mask);
            }
        }
        return byte_count;
    }

    // ============================================================
    //  Public API
    // ============================================================

    HTS_Holo_Dispatcher::HTS_Holo_Dispatcher() noexcept
        : engine_()
        , current_mode_(HoloPayload::DATA_HOLO)
        , pad_{}
    {
    }

    HTS_Holo_Dispatcher::~HTS_Holo_Dispatcher() noexcept
    {
        // Shutdown() 경유 금지 — try-lock 실패 시 파쇄 누락 방지(락과 무관 강제 소거)
        engine_.Shutdown();
        current_mode_.store(HoloPayload::DATA_HOLO, std::memory_order_release);
    }

    uint32_t HTS_Holo_Dispatcher::Initialize(const uint32_t master_seed[4]) noexcept
    {
        if (master_seed == nullptr) { return SECURE_FALSE; }
        Holo_Dispatch_Busy_Guard guard(dispatch_busy_);
        if (guard.locked != SECURE_TRUE) { return SECURE_FALSE; }

        // Initialize with default DATA profile
        const HoloTensor_Profile prof = Holo_Mode_To_Profile(HoloPayload::DATA_HOLO);
        return (engine_.Initialize(master_seed, &prof) == HTS_Holo_Tensor_4D::SECURE_TRUE)
            ? SECURE_TRUE : SECURE_FALSE;
    }

    uint32_t HTS_Holo_Dispatcher::Shutdown() noexcept
    {
        Holo_Dispatch_Busy_Guard guard(dispatch_busy_);
        if (guard.locked != SECURE_TRUE) { return SECURE_FALSE; }
        engine_.Shutdown();
        current_mode_.store(HoloPayload::DATA_HOLO, std::memory_order_release);
        return SECURE_TRUE;
    }

    uint32_t HTS_Holo_Dispatcher::Rotate_Seed(const uint32_t new_seed[4]) noexcept
    {
        if (new_seed == nullptr) { return SECURE_FALSE; }
        Holo_Dispatch_Busy_Guard guard(dispatch_busy_);
        if (guard.locked != SECURE_TRUE) { return SECURE_FALSE; }
        engine_.Rotate_Seed(new_seed);
        return SECURE_TRUE;
    }

    uint8_t HTS_Holo_Dispatcher::Select_Mode(const HTS_RF_Metrics* metrics) const noexcept
    {
        if (metrics == nullptr) { return HoloPayload::DATA_HOLO; }

        const int32_t  snr = metrics->snr_proxy.load(std::memory_order_acquire);
        const uint32_t ajc = metrics->ajc_nf.load(std::memory_order_acquire);

        // Priority 1: HEAVY jamming -> RESILIENT (maximum protection)
        if (ajc >= HoloThreshold::AJC_MODERATE || snr < HoloThreshold::SNR_MODERATE) {
            return HoloPayload::RESILIENT_HOLO;
        }

        // Priority 2: QUIET channel -> VOICE_HOLO (speed priority)
        if (ajc < HoloThreshold::AJC_QUIET && snr >= HoloThreshold::SNR_QUIET) {
            return HoloPayload::VOICE_HOLO;
        }

        // Priority 3: Moderate -> DATA_HOLO (balanced)
        return HoloPayload::DATA_HOLO;
    }

    size_t HTS_Holo_Dispatcher::Build_Holo_Packet(uint8_t mode, const uint8_t* info,
        size_t info_len, int16_t amp,
        int16_t* out_I, int16_t* out_Q,
        size_t max_chips) noexcept
    {
        Holo_Dispatch_Busy_Guard guard(dispatch_busy_);
        if (guard.locked != SECURE_TRUE) { return 0u; }

        // Validate inputs (O-4: 외부 버퍼 포인터·경계 — H-1: nullptr 묵인 차단)
        if (info == nullptr || out_I == nullptr || out_Q == nullptr) { return 0u; }
        if (info_len == 0u || info_len > 16u) { return 0u; }
        if (max_chips == 0u) { return 0u; }
        if (!HoloPayload::Is_Holo_Mode(mode)) { return 0u; }

        // Get profile for this mode
        const HoloTensor_Profile prof = Holo_Mode_To_Profile(mode);
        if (engine_.Set_Profile(&prof) != HTS_Holo_Tensor_4D::SECURE_TRUE) {
            return 0u;
        }
        const uint16_t K = prof.block_bits;
        const uint16_t N = prof.chip_count;
        const uint16_t bytes_per_block = static_cast<uint16_t>(
            static_cast<uint32_t>(K) >> 3u);  // K/8

        if (bytes_per_block == 0u || K > HOLO_MAX_BLOCK_BITS) { return 0u; }

        // Calculate number of blocks needed
        // num_blocks = ceil(info_len / bytes_per_block) via bounded counter
        uint16_t num_blocks = 0u;
        {
            uint16_t accum = 0u;
            // info_len은 size_t 전체로 비교 — uint32_t 등으로 축소하지 않음 (B-CDMA 검수)
            while (accum < info_len) {
                accum = static_cast<uint16_t>(
                    static_cast<uint32_t>(accum) + static_cast<uint32_t>(bytes_per_block));
                ++num_blocks;
                if (num_blocks > 64u) { return 0u; }  // Sanity limit
            }
        }

        const size_t total_chips_sz =
            static_cast<size_t>(num_blocks) * static_cast<size_t>(N);
        if (total_chips_sz > max_chips) { return 0u; }

        // Encode each block
        size_t chip_pos = 0u;
        for (uint16_t blk = 0u; blk < num_blocks; ++blk) {
            // Extract bytes for this block
            const size_t byte_offset = static_cast<size_t>(
                static_cast<uint32_t>(blk) * static_cast<uint32_t>(bytes_per_block));
            const size_t remaining_sz = (info_len > byte_offset)
                ? (info_len - byte_offset) : 0u;
            const size_t block_bytes = (remaining_sz >= static_cast<size_t>(bytes_per_block))
                ? static_cast<size_t>(bytes_per_block) : remaining_sz;

            // Convert to BPSK bits
            int8_t data_bits[HOLO_MAX_BLOCK_BITS];
            std::memset(data_bits, 1, sizeof(data_bits));  // Pad with +1
            if (block_bytes > 0u) {
                Bytes_To_BPSK(&info[byte_offset], block_bytes,
                    data_bits, K);
            }

            // 4D Holographic encode
            int8_t chip_bpsk[HOLO_CHIP_COUNT];
            if (engine_.Encode_Block(data_bits, K, chip_bpsk, N) != HTS_Holo_Tensor_4D::SECURE_TRUE) {
                SecureMemory::secureWipe(static_cast<void*>(data_bits), sizeof(data_bits));
                SecureMemory::secureWipe(static_cast<void*>(chip_bpsk), sizeof(chip_bpsk));
                return 0u;
            }

            // Convert soft chips to I/Q (proportional scaling)
            // chip ranges from -(L*K) to +(L*K), max 32 for our profiles
            // Scale: (chip * amp) / 32 — SDIV 대신 Int32_Div32_TruncZero (비트 시프트)
            for (uint16_t i = 0u; i < N; ++i) {
                const int32_t prod = static_cast<int32_t>(
                    chip_bpsk[static_cast<size_t>(i)]) *
                    static_cast<int32_t>(amp);
                const int32_t val = Int32_Div32_TruncZero(prod);
                const size_t out_idx = chip_pos;
                // Clamp to int16_t (defensive)
                if (val > 32767) { out_I[out_idx] = 32767; out_Q[out_idx] = 32767; }
                else if (val < -32767) { out_I[out_idx] = -32767; out_Q[out_idx] = -32767; }
                else {
                    out_I[out_idx] = static_cast<int16_t>(val);
                    out_Q[out_idx] = static_cast<int16_t>(val);
                }
                ++chip_pos;
            }

            SecureMemory::secureWipe(static_cast<void*>(static_cast<int8_t*>(data_bits)), sizeof(data_bits));
            SecureMemory::secureWipe(static_cast<void*>(static_cast<int8_t*>(chip_bpsk)), sizeof(chip_bpsk));

            // NOTE: Time slot is NOT advanced internally.
            // MAC layer must call Sync_Time_Slot(frame_no) or Advance_Time()
            // at frame boundary to keep TX/RX PRNG seeds synchronized.
        }

        current_mode_.store(mode, std::memory_order_release);
        return chip_pos;
    }

    uint32_t HTS_Holo_Dispatcher::Decode_Holo_Block(const int16_t* rx_I, const int16_t* rx_Q,
        uint16_t chip_count, uint64_t valid_mask,
        uint8_t* out_data, size_t* out_len) noexcept
    {
        Holo_Dispatch_Busy_Guard guard(dispatch_busy_);
        if (guard.locked != SECURE_TRUE) { return SECURE_FALSE; }

        if (rx_I == nullptr || rx_Q == nullptr) { return SECURE_FALSE; }
        if (out_data == nullptr || out_len == nullptr) { return SECURE_FALSE; }
        if (chip_count == 0u) { return SECURE_FALSE; }
        *out_len = 0u;

        const HoloTensor_Profile prof =
            Holo_Mode_To_Profile(current_mode_.load(std::memory_order_acquire));
        if (engine_.Set_Profile(&prof) != HTS_Holo_Tensor_4D::SECURE_TRUE) {
            return SECURE_FALSE;
        }
        const uint16_t K = prof.block_bits;
        const uint16_t N = prof.chip_count;
        const uint16_t bytes_per_block = static_cast<uint16_t>(
            static_cast<uint32_t>(K) >> 3u);

        if (N == 0u || bytes_per_block == 0u) { return SECURE_FALSE; }
        if (chip_count < N) { return SECURE_FALSE; }

        // Calculate number of blocks in received data
        // num_blocks = chip_count / N via bounded counter (no division)
        uint16_t num_blocks = 0u;
        {
            uint16_t accum = 0u;
            while (static_cast<uint32_t>(accum) + static_cast<uint32_t>(N)
                   <= static_cast<uint32_t>(chip_count)) {
                accum = static_cast<uint16_t>(
                    static_cast<uint32_t>(accum) + static_cast<uint32_t>(N));
                ++num_blocks;
                if (num_blocks > 64u) { break; }
            }
        }
        if (num_blocks == 0u) { return SECURE_FALSE; }

        size_t total_bytes = 0u;
        for (uint16_t blk = 0u; blk < num_blocks; ++blk) {
            const size_t chip_offset = static_cast<size_t>(
                static_cast<uint32_t>(blk) * static_cast<uint32_t>(N));

            //
            //  누적합은 int32 — (I+Q)/2 대신 ASR >>1 (SDIV 회피, soft-decision 유지)
            int16_t rx_soft[HOLO_CHIP_COUNT];
            for (uint16_t i = 0u; i < N; ++i) {
                const size_t sidx = chip_offset + static_cast<size_t>(i);
                const int32_t sum = static_cast<int32_t>(rx_I[sidx]) +
                    static_cast<int32_t>(rx_Q[sidx]);
                const int32_t combined = Int32_Div2_TruncZero(sum);
                // int16_t 범위 클램핑 (방어적)
                if (combined > 32767) { rx_soft[static_cast<size_t>(i)] = 32767; }
                else if (combined < -32767) { rx_soft[static_cast<size_t>(i)] = -32767; }
                else { rx_soft[static_cast<size_t>(i)] = static_cast<int16_t>(combined); }
            }

            // Decode
            int8_t recovered_bits[HOLO_MAX_BLOCK_BITS];
            if (engine_.Decode_Block(rx_soft, N, valid_mask, recovered_bits, K) != HTS_Holo_Tensor_4D::SECURE_TRUE) {
                SecureMemory::secureWipe(static_cast<void*>(static_cast<int16_t*>(rx_soft)), sizeof(rx_soft));
                SecureMemory::secureWipe(static_cast<void*>(static_cast<int8_t*>(recovered_bits)), sizeof(recovered_bits));
                return SECURE_FALSE;
            }

            // Convert bits to bytes
            const size_t max_remain = (total_bytes >= 16u)
                ? 0u : (16u - total_bytes);
            if (max_remain == 0u) {
                SecureMemory::secureWipe(static_cast<void*>(static_cast<int16_t*>(rx_soft)), sizeof(rx_soft));
                SecureMemory::secureWipe(static_cast<void*>(static_cast<int8_t*>(recovered_bits)), sizeof(recovered_bits));
                break;
            }
            const size_t block_bytes = BPSK_To_Bytes(recovered_bits, K,
                &out_data[total_bytes], max_remain);
            total_bytes += block_bytes;

            SecureMemory::secureWipe(static_cast<void*>(static_cast<int16_t*>(rx_soft)), sizeof(rx_soft));
            SecureMemory::secureWipe(static_cast<void*>(static_cast<int8_t*>(recovered_bits)), sizeof(recovered_bits));

            // NOTE: Time slot is NOT advanced internally.
            // MAC layer must call Sync_Time_Slot(frame_no) or Advance_Time()
            // at frame boundary to keep TX/RX PRNG seeds synchronized.
        }

        *out_len = total_bytes;
        return SECURE_TRUE;
    }

    uint32_t HTS_Holo_Dispatcher::Advance_Time() noexcept
    {
        Holo_Dispatch_Busy_Guard guard(dispatch_busy_);
        if (guard.locked != SECURE_TRUE) { return SECURE_FALSE; }
        return engine_.Advance_Time_Slot();
    }

    uint32_t HTS_Holo_Dispatcher::Sync_Time_Slot(uint32_t frame_no) noexcept
    {
        Holo_Dispatch_Busy_Guard guard(dispatch_busy_);
        if (guard.locked != SECURE_TRUE) { return SECURE_FALSE; }
        return engine_.Set_Time_Slot(frame_no);
    }

    uint8_t HTS_Holo_Dispatcher::Get_Current_Mode() const noexcept
    {
        return current_mode_.load(std::memory_order_acquire);
    }

    void HTS_Holo_Dispatcher::Set_Current_Mode(uint8_t mode) noexcept
    {
        if (HoloPayload::Is_Holo_Mode(mode)) {
            current_mode_.store(mode, std::memory_order_release);
        }
    }

} // namespace ProtectedEngine
