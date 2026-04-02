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
#include <cstring>
#include <atomic>

namespace ProtectedEngine {

    namespace {
        static constexpr uint32_t HOLO_LOCK_FREE = 0x13579BDFu;
        static constexpr uint32_t HOLO_LOCK_BUSY = 0x2468ACE0u;

        struct Holo_Dispatch_Busy_Guard final {
            std::atomic<uint32_t>* gate;
            uint32_t locked;
            explicit Holo_Dispatch_Busy_Guard(std::atomic<uint32_t>& g) noexcept
                : gate(&g), locked(HTS_Holo_Dispatcher::SECURE_FALSE) {
                uint32_t expected = HOLO_LOCK_FREE;
                if (gate->compare_exchange_strong(expected, HOLO_LOCK_BUSY,
                    std::memory_order_acq_rel, std::memory_order_relaxed)) {
                    locked = HTS_Holo_Dispatcher::SECURE_TRUE;
                }
            }
            ~Holo_Dispatch_Busy_Guard() noexcept {
                if (locked == HTS_Holo_Dispatcher::SECURE_TRUE) {
                    gate->store(HOLO_LOCK_FREE, std::memory_order_release);
                }
            }
            Holo_Dispatch_Busy_Guard(const Holo_Dispatch_Busy_Guard&) = delete;
            Holo_Dispatch_Busy_Guard& operator=(const Holo_Dispatch_Busy_Guard&) = delete;
        };
    } // namespace

    // ============================================================
    //  Helper: bytes to BPSK bits (+1/-1)
    // ============================================================

    static uint16_t Bytes_To_BPSK(const uint8_t* bytes, int byte_len,
        int8_t* bpsk_bits, uint16_t max_bits) noexcept
    {
        uint16_t bit_idx = 0u;
        for (int b = 0; b < byte_len; ++b) {
            for (int i = 7; i >= 0; --i) {
                if (bit_idx >= max_bits) { return bit_idx; }
                bpsk_bits[bit_idx] = ((bytes[b] >> static_cast<uint8_t>(i)) & 1u)
                    ? static_cast<int8_t>(1) : static_cast<int8_t>(-1);
                bit_idx++;
            }
        }
        return bit_idx;
    }

    // ============================================================
    //  Helper: BPSK bits (+1/-1) to bytes
    // ============================================================

    static int BPSK_To_Bytes(const int8_t* bpsk_bits, uint16_t bit_count,
        uint8_t* bytes, int max_bytes) noexcept
    {
        // Round up to bytes
        int byte_count = static_cast<int>((static_cast<uint32_t>(bit_count) + 7u) >> 3u);
        if (byte_count > max_bytes) { byte_count = max_bytes; }

        std::memset(bytes, 0, static_cast<size_t>(byte_count));
        for (uint16_t i = 0u; i < bit_count; ++i) {
            if (static_cast<int>(i >> 3u) >= byte_count) { break; }
            if (bpsk_bits[i] > 0) {
                bytes[i >> 3u] |= static_cast<uint8_t>(1u << (7u - (i & 7u)));
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
        Shutdown();
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

    void HTS_Holo_Dispatcher::Shutdown() noexcept
    {
        Holo_Dispatch_Busy_Guard guard(dispatch_busy_);
        if (guard.locked != SECURE_TRUE) { return; }
        engine_.Shutdown();
        current_mode_.store(HoloPayload::DATA_HOLO, std::memory_order_release);
    }

    void HTS_Holo_Dispatcher::Rotate_Seed(const uint32_t new_seed[4]) noexcept
    {
        if (new_seed == nullptr) { return; }
        Holo_Dispatch_Busy_Guard guard(dispatch_busy_);
        if (guard.locked != SECURE_TRUE) { return; }
        engine_.Rotate_Seed(new_seed);
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

    int HTS_Holo_Dispatcher::Build_Holo_Packet(uint8_t mode, const uint8_t* info,
        int info_len, int16_t amp,
        int16_t* out_I, int16_t* out_Q,
        int max_chips) noexcept
    {
        Holo_Dispatch_Busy_Guard guard(dispatch_busy_);
        if (guard.locked != SECURE_TRUE) { return 0; }

        // Validate inputs
        if (info == nullptr || out_I == nullptr || out_Q == nullptr) { return 0; }
        if (info_len <= 0 || info_len > 16) { return 0; }
        if (!HoloPayload::Is_Holo_Mode(mode)) { return 0; }

        // Get profile for this mode
        const HoloTensor_Profile prof = Holo_Mode_To_Profile(mode);
        engine_.Set_Profile(&prof);  // Sync engine to requested mode
        const uint16_t K = prof.block_bits;
        const uint16_t N = prof.chip_count;
        const uint16_t bytes_per_block = static_cast<uint16_t>(K >> 3u);  // K/8

        if (bytes_per_block == 0u || K > HOLO_MAX_BLOCK_BITS) { return 0; }

        // Calculate number of blocks needed
        // num_blocks = ceil(info_len / bytes_per_block) via bounded counter
        uint16_t num_blocks = 0u;
        {
            uint16_t accum = 0u;
            while (accum < static_cast<uint16_t>(info_len)) {
                accum = static_cast<uint16_t>(accum + bytes_per_block);
                num_blocks++;
                if (num_blocks > 64u) { return 0; }  // Sanity limit
            }
        }

        const int total_chips = static_cast<int>(num_blocks) * static_cast<int>(N);
        if (total_chips > max_chips) { return 0; }

        // Encode each block
        int chip_pos = 0;
        for (uint16_t blk = 0u; blk < num_blocks; ++blk) {
            // Extract bytes for this block
            const int byte_offset = static_cast<int>(blk) * static_cast<int>(bytes_per_block);
            const int remaining = info_len - byte_offset;
            const int block_bytes = (remaining >= static_cast<int>(bytes_per_block))
                ? static_cast<int>(bytes_per_block) : remaining;

            // Convert to BPSK bits
            int8_t data_bits[HOLO_MAX_BLOCK_BITS];
            std::memset(data_bits, 1, sizeof(data_bits));  // Pad with +1
            if (block_bytes > 0) {
                Bytes_To_BPSK(&info[byte_offset], block_bytes, data_bits, K);
            }

            // 4D Holographic encode
            int8_t chip_bpsk[HOLO_CHIP_COUNT];
            if (engine_.Encode_Block(data_bits, K, chip_bpsk, N) != HTS_Holo_Tensor_4D::SECURE_TRUE) {
                return 0;
            }

            // Convert soft chips to I/Q (proportional scaling)
            // chip ranges from -(L*K) to +(L*K), max 32 for our profiles
            // Scale: val = chip * amp / 32 (round toward zero for signed symmetry)
            // Preserves holographic amplitude information through RF chain
            for (uint16_t i = 0u; i < N; ++i) {
                const int32_t val = (static_cast<int32_t>(chip_bpsk[i]) *
                    static_cast<int32_t>(amp)) / 32;
                // Clamp to int16_t (defensive)
                if (val > 32767) { out_I[chip_pos] = 32767; out_Q[chip_pos] = 32767; }
                else if (val < -32767) { out_I[chip_pos] = -32767; out_Q[chip_pos] = -32767; }
                else {
                    out_I[chip_pos] = static_cast<int16_t>(val);
                    out_Q[chip_pos] = static_cast<int16_t>(val);
                }
                chip_pos++;
            }

            // NOTE: Time slot is NOT advanced internally.
            // MAC layer must call Sync_Time_Slot(frame_no) or Advance_Time()
            // at frame boundary to keep TX/RX PRNG seeds synchronized.
        }

        current_mode_.store(mode, std::memory_order_release);
        return chip_pos;
    }

    uint32_t HTS_Holo_Dispatcher::Decode_Holo_Block(const int16_t* rx_I, const int16_t* rx_Q,
        uint16_t chip_count, uint64_t valid_mask,
        uint8_t* out_data, int* out_len) noexcept
    {
        Holo_Dispatch_Busy_Guard guard(dispatch_busy_);
        if (guard.locked != SECURE_TRUE) { return SECURE_FALSE; }

        if (rx_I == nullptr || rx_Q == nullptr) { return SECURE_FALSE; }
        if (out_data == nullptr || out_len == nullptr) { return SECURE_FALSE; }
        *out_len = 0;

        const HoloTensor_Profile prof =
            Holo_Mode_To_Profile(current_mode_.load(std::memory_order_acquire));
        engine_.Set_Profile(&prof);  // Sync engine to current mode
        const uint16_t K = prof.block_bits;
        const uint16_t N = prof.chip_count;
        const uint16_t bytes_per_block = static_cast<uint16_t>(K >> 3u);

        if (N == 0u || bytes_per_block == 0u) { return SECURE_FALSE; }
        if (chip_count < N) { return SECURE_FALSE; }

        // Calculate number of blocks in received data
        // num_blocks = chip_count / N via bounded counter (no division)
        uint16_t num_blocks = 0u;
        {
            uint16_t accum = 0u;
            while (accum + N <= chip_count) {
                accum = static_cast<uint16_t>(accum + N);
                num_blocks++;
                if (num_blocks > 64u) { break; }
            }
        }
        if (num_blocks == 0u) { return SECURE_FALSE; }

        int total_bytes = 0;
        for (uint16_t blk = 0u; blk < num_blocks; ++blk) {
            const int chip_offset = static_cast<int>(blk) * static_cast<int>(N);

            //
            //  누적합은 int32 범위 내 — >>8 없이 (I+Q)/2만 수행해 Q16 soft-decision 유지
            int16_t rx_soft[HOLO_CHIP_COUNT];
            for (uint16_t i = 0u; i < N; ++i) {
                const int32_t combined = (static_cast<int32_t>(rx_I[chip_offset + i]) +
                    static_cast<int32_t>(rx_Q[chip_offset + i])) / 2;
                // int16_t 범위 클램핑 (방어적)
                if (combined > 32767) { rx_soft[i] = 32767; }
                else if (combined < -32767) { rx_soft[i] = -32767; }
                else { rx_soft[i] = static_cast<int16_t>(combined); }
            }

            // Decode
            int8_t recovered_bits[HOLO_MAX_BLOCK_BITS];
            if (engine_.Decode_Block(rx_soft, N, valid_mask, recovered_bits, K) != HTS_Holo_Tensor_4D::SECURE_TRUE) {
                return SECURE_FALSE;
            }

            // Convert bits to bytes
            const int max_remain = 16 - total_bytes;
            if (max_remain <= 0) { break; }
            const int block_bytes = BPSK_To_Bytes(recovered_bits, K,
                &out_data[total_bytes], max_remain);
            total_bytes += block_bytes;

            // NOTE: Time slot is NOT advanced internally.
            // MAC layer must call Sync_Time_Slot(frame_no) or Advance_Time()
            // at frame boundary to keep TX/RX PRNG seeds synchronized.
        }

        *out_len = total_bytes;
        return SECURE_TRUE;
    }

    void HTS_Holo_Dispatcher::Advance_Time() noexcept
    {
        Holo_Dispatch_Busy_Guard guard(dispatch_busy_);
        if (guard.locked != SECURE_TRUE) { return; }
        engine_.Advance_Time_Slot();
    }

    void HTS_Holo_Dispatcher::Sync_Time_Slot(uint32_t frame_no) noexcept
    {
        Holo_Dispatch_Busy_Guard guard(dispatch_busy_);
        if (guard.locked != SECURE_TRUE) { return; }
        engine_.Set_Time_Slot(frame_no);
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
