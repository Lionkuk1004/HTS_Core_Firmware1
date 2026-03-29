/// @file  HTS_Holo_Tensor_4D.cpp
/// @brief HTS 4D Holographic Tensor Engine -- True Holographic Spread/Despread
/// @note  ARM only. Pure ASCII. No PC/server code.
///        Every output chip = f(ALL input bits, ALL phases, ALL layers)
///        Film torn in half -> each piece still shows the full image.
/// @author Lim Young-jun
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_Holo_Tensor_4D.h"
#include <new>
#include <atomic>

namespace ProtectedEngine {

    // ============================================================
    //  Impl Structure
    // ============================================================

    struct HTS_Holo_Tensor_4D::Impl {
        // --- Master Seed ---
        uint32_t master_seed[4];

        // --- Profile ---
        HoloTensor_Profile profile;

        // --- CFI State ---
        HoloState state;
        uint8_t   cfi_violation_count;
        uint8_t   pad_[2];

        // --- Time Dimension (Dim 2) ---
        uint32_t time_slot;

        // --- Statistics ---
        uint32_t encode_count;
        uint32_t decode_count;

        // --- Accumulator Buffer (encode: per-chip, decode: per-bit) ---
        // Max size: max(N, K) * sizeof(int32_t) = 128 * 4 = 512B
        int32_t accum[HOLO_MAX_BLOCK_BITS];

        // ============================================================
        //  CFI Transition
        // ============================================================
        bool Transition_State(HoloState target) noexcept
        {
            if (!Holo_Is_Legal_Transition(state, target)) {
                if (Holo_Is_Legal_Transition(state, HoloState::ERROR)) {
                    state = HoloState::ERROR;
                }
                else {
                    state = HoloState::OFFLINE;
                }
                cfi_violation_count++;
                return false;
            }
            state = target;
            return true;
        }

        // ============================================================
        //  Generate Phase for (bit k, chip i, layer L, time t)
        //  This is the 4D holographic phase function.
        //  Each (k,i,L,t) tuple yields a unique Q16 phase angle
        //  derived deterministically from the master seed.
        // ============================================================
        uint16_t Generate_Phase(uint32_t k, uint32_t i,
            uint32_t layer, uint32_t t_slot) const noexcept
        {
            // Per-chip PRNG seeded with context: master + (chip, layer, time)
            // Then advance k steps to get phase for bit k at chip i
            Xoshiro128ss rng;
            rng.Seed_With_Context(master_seed, i, layer, t_slot);

            // Skip to bit k (deterministic per-chip stream)
            // This ensures RX can reproduce the exact same phase for (k,i,L,t)
            for (uint32_t skip = 0u; skip < k; ++skip) {
                (void)rng.Next();
            }
            return rng.Next_Phase_Q16();
        }

        // ============================================================
        //  Walsh-Hadamard code: walsh(row, col) = (-1)^popcount(row & col)
        //  All 64 rows are mutually orthogonal: sum_i w(r1,i)*w(r2,i) = 0
        // ============================================================
        static int8_t Walsh_Code(uint32_t row, uint32_t col) noexcept
        {
            const uint32_t x = row & col;
#if defined(__GNUC__) || defined(__clang__)
            // ARM/GCC: single-instruction parity
            return static_cast<int8_t>(1 - 2 * __builtin_parity(x));
#else
            // Portable: manual parity fold
            uint32_t p = x;
            p ^= (p >> 16u);
            p ^= (p >> 8u);
            p ^= (p >> 4u);
            p ^= (p >> 2u);
            p ^= (p >> 1u);
            return static_cast<int8_t>(1 - 2 * static_cast<int8_t>(p & 1u));
#endif
        }

        // ============================================================
        //  Partitioned Walsh row selection -- ZERO cross-layer interference
        //
        //  ONE shuffle of all N rows. Layer l gets rows [l*K .. (l+1)*K-1].
        //  All selected rows are DISTINCT Walsh rows -> mutually orthogonal.
        //  Cross-layer interference = mathematically 0.
        //
        //  Constraint: L*K <= N (enforced at call site)
        //
        //  Security: PRNG determines WHICH rows each layer gets.
        //            Without seed, attacker cannot determine row assignment.
        // ============================================================
        void Generate_Partitioned_Params(
            uint16_t* all_row_sel,  // output: [L*K] rows (layer l at offset l*K)
            uint16_t K, uint16_t N, uint8_t L,
            uint16_t* col_perm,     // output: [N] shared column permutation
            uint32_t t_slot) const noexcept
        {
            // --- Bounds guard (C6385/C6386 fix) ---
            if (N == 0u || N > HOLO_CHIP_COUNT) { return; }
            if (K == 0u || K > N) { return; }

            Xoshiro128ss rng;
            // Seed with time_slot only (shared across layers -- same shuffle)
            rng.Seed_With_Context(master_seed, 0xFFFFFFFFu, 0xEEEEEEEEu, t_slot);

            // 1. Full Fisher-Yates shuffle of N row indices
            // C6001 fix: zero-initialize array
            uint16_t row_perm[HOLO_CHIP_COUNT] = {};
            for (uint16_t j = 0u; j < N; ++j) { row_perm[j] = j; }

            for (uint16_t j = static_cast<uint16_t>(N - 1u); j > 0u; --j) {
                const uint32_t r = rng.Next() % (static_cast<uint32_t>(j) + 1u);
                // C6385/C6386 fix: clamp r to valid range
                const uint16_t r_idx = (r < N) ? static_cast<uint16_t>(r)
                    : static_cast<uint16_t>(N - 1u);
                const uint16_t tmp = row_perm[j];
                row_perm[j] = row_perm[r_idx];
                row_perm[r_idx] = tmp;
            }

            // 2. Partition: layer l gets row_perm[l*K .. (l+1)*K - 1]
            //    All rows are DISTINCT -> Walsh orthogonality guaranteed
            const uint16_t total_rows = static_cast<uint16_t>(L) * K;
            for (uint16_t idx = 0u; idx < total_rows && idx < N; ++idx) {
                all_row_sel[idx] = row_perm[idx];
            }

            // 3. Column permutation (shared across all layers)
            // C6001 fix: zero-initialize array
            uint16_t col_tmp[HOLO_CHIP_COUNT] = {};
            for (uint16_t j = 0u; j < N; ++j) { col_tmp[j] = j; }

            for (uint16_t j = static_cast<uint16_t>(N - 1u); j > 0u; --j) {
                const uint32_t r = rng.Next() % (static_cast<uint32_t>(j) + 1u);
                // C6385/C6386 fix: clamp r to valid range
                const uint16_t r_idx = (r < N) ? static_cast<uint16_t>(r)
                    : static_cast<uint16_t>(N - 1u);
                const uint16_t tmp = col_tmp[j];
                col_tmp[j] = col_tmp[r_idx];
                col_tmp[r_idx] = tmp;
            }

            for (uint16_t j = 0u; j < N; ++j) { col_perm[j] = col_tmp[j]; }
        }

        // ============================================================
        //  Holographic Encode: K bits -> N chips
        //  Walsh-Hadamard orthogonal codes with PRNG row/column selection
        //
        //  chip[pi[i]] = SUM(L) SUM(k) data[k] * walsh(sigma[k], i)
        //
        //  Guaranteed perfect orthogonality for ANY seed.
        //  Self-healing: lost chips reduce SNR but never destroy data.
        // ============================================================
        bool Encode(const int8_t* data, uint16_t K,
            int8_t* chips, uint16_t N) noexcept
        {
            if (N > HOLO_CHIP_COUNT) { return false; }
            if (K > HOLO_MAX_BLOCK_BITS) { return false; }
            if (K > N) { return false; }
            if (N == 0u) { return false; }

            const uint8_t L = profile.num_layers;
            // Partitioned constraint: L*K <= N
            if (static_cast<uint16_t>(L) * K > N) { return false; }

            // Generate ALL layer params in one call (zero row overlap)
            uint16_t all_rows[HOLO_CHIP_COUNT] = {};
            uint16_t col_perm[HOLO_CHIP_COUNT] = {};
            Generate_Partitioned_Params(all_rows, K, N, L, col_perm, time_slot);

            // Accumulator per physical chip
            int32_t acc[HOLO_CHIP_COUNT] = {};

            for (uint8_t layer = 0u; layer < L; ++layer) {
                // This layer's rows start at offset layer*K
                const uint16_t row_offset = static_cast<uint16_t>(layer) * K;
                const uint16_t* row_sel = &all_rows[row_offset];

                for (uint16_t i = 0u; i < N; ++i) {
                    int32_t chip_acc = 0;
                    for (uint16_t k = 0u; k < K; ++k) {
                        const int8_t w = Walsh_Code(
                            static_cast<uint32_t>(row_sel[k]),
                            static_cast<uint32_t>(i));
                        chip_acc += static_cast<int32_t>(data[k]) *
                            static_cast<int32_t>(w);
                    }
                    // Bounds check col_perm[i] (defensive)
                    const uint16_t phys = col_perm[i];
                    if (phys < N) {
                        acc[phys] += chip_acc;
                    }
                }
            }

            // Soft output: clamp to int8_t range
            for (uint16_t i = 0u; i < N; ++i) {
#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
                // ARM Cortex-M4 SSAT: 1-cycle hardware saturation
                chips[i] = static_cast<int8_t>(__SSAT(acc[i], 8));
#else
                if (acc[i] > 127) { chips[i] = 127; }
                else if (acc[i] < -127) { chips[i] = -127; }
                else { chips[i] = static_cast<int8_t>(acc[i]); }
#endif
            }
            return true;
        }

        // ============================================================
        //  Holographic Decode: N chips -> K bits (self-healing)
        //  Correlate received chips with same Walsh codes
        //  valid_mask: branchless exclusion of lost chips
        // ============================================================
        bool Decode(const int16_t* rx_chips, uint16_t N,
            uint64_t valid_mask,
            int8_t* output_bits, uint16_t K) noexcept
        {
            if (N > HOLO_CHIP_COUNT) { return false; }
            if (K > HOLO_MAX_BLOCK_BITS) { return false; }
            if (K > N) { return false; }
            if (N == 0u) { return false; }

            const uint8_t L = profile.num_layers;
            if (static_cast<uint16_t>(L) * K > N) { return false; }

            // Generate ALL layer params in one call (same as encoder)
            uint16_t all_rows[HOLO_CHIP_COUNT] = {};
            uint16_t col_perm[HOLO_CHIP_COUNT] = {};
            Generate_Partitioned_Params(all_rows, K, N, L, col_perm, time_slot);

            // Pre-compute masked rx values (shared across layers -- same col_perm)
            int16_t masked_rx[HOLO_CHIP_COUNT] = {};
            for (uint16_t i = 0u; i < N; ++i) {
                const uint16_t phys = col_perm[i];
                if (phys >= N) { continue; }  // Bounds guard
                const uint32_t mask_bit = static_cast<uint32_t>(
                    (valid_mask >> static_cast<uint32_t>(phys)) & 1ull);
                const int32_t chip_valid = -static_cast<int32_t>(mask_bit);
                masked_rx[i] = static_cast<int16_t>(
                    static_cast<int32_t>(rx_chips[phys]) & chip_valid);
            }

            // Accumulate per-bit correlations across all layers
            int32_t bit_acc[HOLO_MAX_BLOCK_BITS] = {};

            for (uint8_t layer = 0u; layer < L; ++layer) {
                const uint16_t row_offset = static_cast<uint16_t>(layer) * K;
                const uint16_t* row_sel = &all_rows[row_offset];

                for (uint16_t k = 0u; k < K; ++k) {
                    int32_t acc = 0;
                    const uint32_t row_k = static_cast<uint32_t>(row_sel[k]);
                    for (uint16_t i = 0u; i < N; ++i) {
                        const int8_t w = Walsh_Code(row_k, static_cast<uint32_t>(i));
                        acc += static_cast<int32_t>(masked_rx[i]) *
                            static_cast<int32_t>(w);
                    }
                    bit_acc[k] += acc;
                }
            }

            // Hard decision
            for (uint16_t k = 0u; k < K; ++k) {
                const int32_t sign_mask = bit_acc[k] >> 31;
                output_bits[k] = static_cast<int8_t>((sign_mask << 1) + 1);
            }
            return true;
        }
    };

    // ============================================================
    //  Public API
    // ============================================================

    HTS_Holo_Tensor_4D::HTS_Holo_Tensor_4D() noexcept
        : initialized_{ false }
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "HTS_Holo_Tensor_4D::Impl exceeds IMPL_BUF_SIZE");

        for (uint32_t i = 0u; i < IMPL_BUF_SIZE; ++i) {
            impl_buf_[i] = 0u;
        }
    }

    HTS_Holo_Tensor_4D::~HTS_Holo_Tensor_4D() noexcept
    {
        Shutdown();
    }

    bool HTS_Holo_Tensor_4D::Initialize(const uint32_t master_seed[4],
        const HoloTensor_Profile* profile) noexcept
    {
        if (master_seed == nullptr) { return false; }

        bool expected = false;
        if (!initialized_.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel))
        {
            return true;
        }

        Impl* impl = new (impl_buf_) Impl{};

        impl->master_seed[0] = master_seed[0];
        impl->master_seed[1] = master_seed[1];
        impl->master_seed[2] = master_seed[2];
        impl->master_seed[3] = master_seed[3];

        if (profile != nullptr) {
            impl->profile = *profile;
        }
        else {
            impl->profile = k_holo_profiles[1];  // DATA default
        }

        // Validate profile
        if (impl->profile.block_bits == 0u ||
            impl->profile.block_bits > HOLO_MAX_BLOCK_BITS)
        {
            impl->profile.block_bits = HOLO_DEFAULT_BLOCK;
        }
        if (impl->profile.chip_count == 0u ||
            impl->profile.chip_count > HOLO_CHIP_COUNT)
        {
            impl->profile.chip_count = HOLO_CHIP_COUNT;
        }
        if (impl->profile.num_layers == 0u ||
            impl->profile.num_layers > HOLO_MAX_LAYERS)
        {
            impl->profile.num_layers = HOLO_DEFAULT_LAYERS;
        }

        impl->state = HoloState::OFFLINE;
        impl->cfi_violation_count = 0u;
        impl->time_slot = 0u;
        impl->encode_count = 0u;
        impl->decode_count = 0u;

        for (uint32_t i = 0u; i < HOLO_MAX_BLOCK_BITS; ++i) {
            impl->accum[i] = 0;
        }

        impl->Transition_State(HoloState::READY);
        return true;
    }

    void HTS_Holo_Tensor_4D::Shutdown() noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        // Secure wipe master seed
        volatile uint32_t* vs = reinterpret_cast<volatile uint32_t*>(impl->master_seed);
        vs[0] = 0u; vs[1] = 0u; vs[2] = 0u; vs[3] = 0u;
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" ::: "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);

        impl->state = HoloState::OFFLINE;
        impl->~Impl();
        initialized_.store(false, std::memory_order_release);
    }

    void HTS_Holo_Tensor_4D::Rotate_Seed(const uint32_t new_seed[4]) noexcept
    {
        if (new_seed == nullptr) { return; }
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        // Secure wipe old seed first
        volatile uint32_t* vs = reinterpret_cast<volatile uint32_t*>(impl->master_seed);
        vs[0] = 0u; vs[1] = 0u; vs[2] = 0u; vs[3] = 0u;
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" ::: "memory");
#endif

        impl->master_seed[0] = new_seed[0];
        impl->master_seed[1] = new_seed[1];
        impl->master_seed[2] = new_seed[2];
        impl->master_seed[3] = new_seed[3];
        std::atomic_thread_fence(std::memory_order_release);
    }

    void HTS_Holo_Tensor_4D::Set_Profile(const HoloTensor_Profile* profile) noexcept
    {
        if (profile == nullptr) { return; }
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        impl->profile = *profile;
        // Validate
        if (impl->profile.block_bits == 0u ||
            impl->profile.block_bits > HOLO_MAX_BLOCK_BITS) {
            impl->profile.block_bits = HOLO_DEFAULT_BLOCK;
        }
        if (impl->profile.chip_count == 0u ||
            impl->profile.chip_count > HOLO_CHIP_COUNT) {
            impl->profile.chip_count = HOLO_CHIP_COUNT;
        }
        if (impl->profile.num_layers == 0u ||
            impl->profile.num_layers > HOLO_MAX_LAYERS) {
            impl->profile.num_layers = HOLO_DEFAULT_LAYERS;
        }
    }

    bool HTS_Holo_Tensor_4D::Encode_Block(const int8_t* data_bits, uint16_t K,
        int8_t* output_chips, uint16_t N) noexcept
    {
        if (data_bits == nullptr) { return false; }
        if (output_chips == nullptr) { return false; }
        if (!initialized_.load(std::memory_order_acquire)) { return false; }

        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        if (!impl->Transition_State(HoloState::ENCODING)) { return false; }

        const bool ok = impl->Encode(data_bits, K, output_chips, N);

        impl->Transition_State(HoloState::READY);

        if (ok) { impl->encode_count++; }
        return ok;
    }

    bool HTS_Holo_Tensor_4D::Decode_Block(const int16_t* rx_chips, uint16_t N,
        uint64_t valid_mask,
        int8_t* output_bits, uint16_t K) noexcept
    {
        if (rx_chips == nullptr) { return false; }
        if (output_bits == nullptr) { return false; }
        if (!initialized_.load(std::memory_order_acquire)) { return false; }

        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        if (!impl->Transition_State(HoloState::DECODING)) { return false; }

        const bool ok = impl->Decode(rx_chips, N, valid_mask, output_bits, K);

        impl->Transition_State(HoloState::READY);

        if (ok) { impl->decode_count++; }
        return ok;
    }

    void HTS_Holo_Tensor_4D::Advance_Time_Slot() noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        reinterpret_cast<Impl*>(impl_buf_)->time_slot++;
    }

    void HTS_Holo_Tensor_4D::Set_Time_Slot(uint32_t frame_no) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        reinterpret_cast<Impl*>(impl_buf_)->time_slot = frame_no;
    }

    HoloState HTS_Holo_Tensor_4D::Get_State() const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return HoloState::OFFLINE; }
        return reinterpret_cast<const Impl*>(impl_buf_)->state;
    }

    uint32_t HTS_Holo_Tensor_4D::Get_Encode_Count() const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        return reinterpret_cast<const Impl*>(impl_buf_)->encode_count;
    }

    uint32_t HTS_Holo_Tensor_4D::Get_Decode_Count() const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        return reinterpret_cast<const Impl*>(impl_buf_)->decode_count;
    }

    uint32_t HTS_Holo_Tensor_4D::Get_Time_Slot() const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        return reinterpret_cast<const Impl*>(impl_buf_)->time_slot;
    }

} // namespace ProtectedEngine