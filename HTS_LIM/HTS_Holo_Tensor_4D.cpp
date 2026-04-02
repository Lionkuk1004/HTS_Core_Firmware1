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
#include <cstring>

namespace ProtectedEngine {
    namespace {
        struct Holo4D_Busy_Guard final {
            std::atomic_flag* flag;
            bool locked;
            explicit Holo4D_Busy_Guard(std::atomic_flag& f) noexcept
                : flag(&f), locked(false) {
                locked = !flag->test_and_set(std::memory_order_acq_rel);
            }
            ~Holo4D_Busy_Guard() noexcept {
                if (locked) { flag->clear(std::memory_order_release); }
            }
            Holo4D_Busy_Guard(const Holo4D_Busy_Guard&) = delete;
            Holo4D_Busy_Guard& operator=(const Holo4D_Busy_Guard&) = delete;
        };
    }

    static void Holo4D_Secure_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) { q[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

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

        // --- Accumulator Buffer (encode: per-chip N, decode: per-bit K) ---
        //  기존: accum[HOLO_MAX_BLOCK_BITS(128)] — 비트(K) 기준만 고려
        //  위험: Encode에서 accum[0..N-1] (N=칩수) 인덱싱 → N > 128 시 OOB
        //  현재: MAX_BLOCK(128) > CHIP_COUNT(64) → 우연히 안전
        //  수정: 양쪽 최대값 보증 + static_assert로 빌드타임 검증
        static constexpr uint16_t ACCUM_SIZE =
            (HOLO_MAX_BLOCK_BITS >= HOLO_CHIP_COUNT)
            ? HOLO_MAX_BLOCK_BITS : HOLO_CHIP_COUNT;
        int32_t accum[ACCUM_SIZE];

        // 빌드타임 보증: accum이 Encode(N칩) + Decode(K비트) 양쪽 커버
        static_assert(ACCUM_SIZE >= HOLO_CHIP_COUNT,
            "accum must cover max chip count (Encode)");
        static_assert(ACCUM_SIZE >= HOLO_MAX_BLOCK_BITS,
            "accum must cover max block bits (Decode)");

        //  Encode/Decode 공유 (시간적 분리: 동시 호출 불가)
        uint16_t scratch_rows[HOLO_CHIP_COUNT];  // all_row_sel + Fisher-Yates
        uint16_t scratch_perm[HOLO_CHIP_COUNT];  // col_perm + col Fisher-Yates
        int16_t  scratch_rx[HOLO_CHIP_COUNT];    // masked_rx (Decode 전용)

        // ============================================================
        //  CFI Transition
        // ============================================================
        uint32_t Transition_State(HoloState target) noexcept
        {
            if (!Holo_Is_Legal_Transition(state, target)) {
                if (Holo_Is_Legal_Transition(state, HoloState::ERROR)) {
                    state = HoloState::ERROR;
                }
                else {
                    state = HoloState::OFFLINE;
                }
                cfi_violation_count++;
                return HTS_Holo_Tensor_4D::SECURE_FALSE;
            }
            state = target;
            return HTS_Holo_Tensor_4D::SECURE_TRUE;
        }

        //  기존: 매 (k,i) 호출마다 RNG 재시딩 + k번 스킵 = O(K²)
        //  수정: (i, layer, t) 당 1회 시딩 → k루프에서 Next_Phase_Q16만 호출
        //  131,072회 → 4,096회 RNG 호출 (32× 가속)

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
            uint32_t t_slot) noexcept
        {
            // --- Bounds guard (C6385/C6386 fix) ---
            if (N == 0u || N > HOLO_CHIP_COUNT) { return; }
            if (K == 0u || K > N) { return; }

            Xoshiro128ss rng;
            // Seed with time_slot only (shared across layers -- same shuffle)
            rng.Seed_With_Context(master_seed, 0xFFFFFFFFu, 0xEEEEEEEEu, t_slot);

            // 1. Full Fisher-Yates shuffle of N row indices
            // C6001 fix: zero-initialize array
            for (uint16_t j = 0u; j < N; ++j) { scratch_rows[j] = j; }

            for (uint16_t j = static_cast<uint16_t>(N - 1u); j > 0u; --j) {
                const uint32_t range = static_cast<uint32_t>(j) + 1u;
                const uint32_t r = static_cast<uint32_t>(
                    (static_cast<uint64_t>(rng.Next()) * range) >> 32u);
                const uint16_t r_idx = (r < N) ? static_cast<uint16_t>(r)
                    : static_cast<uint16_t>(N - 1u);
                const uint16_t tmp = scratch_rows[j];
                scratch_rows[j] = scratch_rows[r_idx];
                scratch_rows[r_idx] = tmp;
            }

            // 2. Partition: layer l gets row_perm[l*K .. (l+1)*K - 1]
            //    All rows are DISTINCT -> Walsh orthogonality guaranteed
            const uint16_t total_rows = static_cast<uint16_t>(L) * K;
            for (uint16_t idx = 0u; idx < total_rows && idx < N; ++idx) {
                all_row_sel[idx] = scratch_rows[idx];
            }

            // 3. Column permutation (shared across all layers)
            // C6001 fix: zero-initialize array
            for (uint16_t j = 0u; j < N; ++j) { scratch_perm[j] = j; }

            for (uint16_t j = static_cast<uint16_t>(N - 1u); j > 0u; --j) {
                const uint32_t range2 = static_cast<uint32_t>(j) + 1u;
                const uint32_t r = static_cast<uint32_t>(
                    (static_cast<uint64_t>(rng.Next()) * range2) >> 32u);
                const uint16_t r_idx = (r < N) ? static_cast<uint16_t>(r)
                    : static_cast<uint16_t>(N - 1u);
                const uint16_t tmp = scratch_perm[j];
                scratch_perm[j] = scratch_perm[r_idx];
                scratch_perm[r_idx] = tmp;
            }

            for (uint16_t j = 0u; j < N; ++j) { col_perm[j] = scratch_perm[j]; }
        }

        // ============================================================
        //  Holographic Encode: K bits -> N chips
        //
        //  하이브리드 방식:
        //   N ≤ 16: Walsh 좌표 (VOICE 실시간, 완벽 직교, 3× 빠름)
        //     chip[pi[i]] = SUM(L) SUM(k) data[k] * walsh(sigma[k], i)
        //
        //   N > 16: 홀로그램 위상 투영 (DATA/RESILIENT, 10^19K 보안)
        //     chip[pi[i]] = SUM(L) SUM(k) data[k] * cos(phase(k,i,L,t))
        //     Generate_Phase() + Cos_Q15() 연결
        //     Spot 재밍 위상 분산 효과
        // ============================================================
        uint32_t Encode(const int8_t* data, uint16_t K,
            int8_t* chips, uint16_t N) noexcept
        {
            if (N > HOLO_CHIP_COUNT) { return HTS_Holo_Tensor_4D::SECURE_FALSE; }
            if (K > HOLO_MAX_BLOCK_BITS) { return HTS_Holo_Tensor_4D::SECURE_FALSE; }
            if (K > N) { return HTS_Holo_Tensor_4D::SECURE_FALSE; }
            if (N == 0u) { return HTS_Holo_Tensor_4D::SECURE_FALSE; }
            //  비2의거듭제곱 N(예: 48) → 계층 간 직교성 붕괴 → 복구 불가
            //  검사: (N & (N-1)) == 0 ↔ N이 정확히 2의거듭제곱
            if ((N & static_cast<uint16_t>(N - 1u)) != 0u) {
                return HTS_Holo_Tensor_4D::SECURE_FALSE;
            }

            const uint8_t L = profile.num_layers;
            if (static_cast<uint16_t>(L) * K > N) { return HTS_Holo_Tensor_4D::SECURE_FALSE; }

            // Column permutation + Binary Phase Mask 생성
            Generate_Partitioned_Params(scratch_rows, K, N, L, scratch_perm, time_slot);

            // [Binary Phase Mask] 전 모드 적용 (16/64칩 공통)
            //  보안: +2^N (16칩: +2^16=65536, 64칩: +2^64)
            //  비용: N회 XOR (16칩: 16cyc = 0.1μs, 무시)
            uint64_t mask_bits = 0u;
            {
                Xoshiro128ss mask_rng;
                mask_rng.Seed_With_Context(master_seed,
                    0xBBBBBBBBu, 0xCCCCCCCCu, time_slot);
                mask_bits = (static_cast<uint64_t>(mask_rng.Next()) << 32u)
                    | static_cast<uint64_t>(mask_rng.Next());
            }

            std::memset(accum, 0, N * sizeof(int32_t));

            // ── 통합 Walsh 홀로그램 투영 (16/64칩 공통) ──
            //  chip[pi[i]] = mask[i] × SUM(L,k) data[k] × walsh(σ[k], i)
            //  직교성: mask² = 1 → Walsh 직교성 100% 보존
            //  자가치유: 균일 에너지(±1) → 최적 홀로그램
            for (uint8_t layer = 0u; layer < L; ++layer) {
                const uint16_t row_offset =
                    static_cast<uint16_t>(layer) * K;
                const uint16_t* row_sel = &scratch_rows[row_offset];

                for (uint16_t i = 0u; i < N; ++i) {
                    int32_t chip_acc = 0;
                    for (uint16_t k = 0u; k < K; ++k) {
                        const int8_t w = Walsh_Code(
                            static_cast<uint32_t>(row_sel[k]),
                            static_cast<uint32_t>(i));
                        chip_acc += static_cast<int32_t>(data[k]) *
                            static_cast<int32_t>(w);
                    }
                    // Binary Phase Mask: ±1 부호 반전 (XOR 등가)
                    //  mask bit=0 → +1, mask bit=1 → -1
                    const int32_t ms = 1 - (static_cast<int32_t>(
                        (mask_bits >> i) & 1ull) << 1);
                    const uint16_t phys = scratch_perm[i];
                    if (phys < N) { accum[phys] += chip_acc * ms; }
                }
            }

            // Soft output: clamp to int8_t range
            for (uint16_t i = 0u; i < N; ++i) {
#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
                chips[i] = static_cast<int8_t>(__SSAT(accum[i], 8));
#else
                if (accum[i] > 127) { chips[i] = 127; }
                else if (accum[i] < -127) { chips[i] = -127; }
                else { chips[i] = static_cast<int8_t>(accum[i]); }
#endif
            }
            return HTS_Holo_Tensor_4D::SECURE_TRUE;
        }

        // ============================================================
        //  Holographic Decode: N chips -> K bits (self-healing)
        //  통합 Walsh 홀로그램 역투영 + Binary Phase Mask
        //  valid_mask: branchless exclusion of lost chips
        // ============================================================
        uint32_t Decode(const int16_t* rx_chips, uint16_t N,
            uint64_t valid_mask,
            int8_t* output_bits, uint16_t K) noexcept
        {
            if (N > HOLO_CHIP_COUNT) { return HTS_Holo_Tensor_4D::SECURE_FALSE; }
            if (K > HOLO_MAX_BLOCK_BITS) { return HTS_Holo_Tensor_4D::SECURE_FALSE; }
            if (K > N) { return HTS_Holo_Tensor_4D::SECURE_FALSE; }
            if (N == 0u) { return HTS_Holo_Tensor_4D::SECURE_FALSE; }
            if ((N & static_cast<uint16_t>(N - 1u)) != 0u) {
                return HTS_Holo_Tensor_4D::SECURE_FALSE;
            }

            const uint8_t L = profile.num_layers;
            if (static_cast<uint16_t>(L) * K > N) { return HTS_Holo_Tensor_4D::SECURE_FALSE; }

            Generate_Partitioned_Params(scratch_rows, K, N, L, scratch_perm, time_slot);

            // [Binary Phase Mask] 전 모드 적용 (Encode와 동일)
            uint64_t mask_bits = 0u;
            {
                Xoshiro128ss mask_rng;
                mask_rng.Seed_With_Context(master_seed,
                    0xBBBBBBBBu, 0xCCCCCCCCu, time_slot);
                mask_bits = (static_cast<uint64_t>(mask_rng.Next()) << 32u)
                    | static_cast<uint64_t>(mask_rng.Next());
            }

            // Pre-compute: valid_mask + col_perm + binary phase mask 통합
            std::memset(scratch_rx, 0, N * sizeof(int16_t));
            for (uint16_t i = 0u; i < N; ++i) {
                const uint16_t phys = scratch_perm[i];
                if (phys >= N) { continue; }
                const uint32_t vbit = static_cast<uint32_t>(
                    (valid_mask >> static_cast<uint32_t>(phys)) & 1ull);
                const int32_t chip_valid = -static_cast<int32_t>(vbit);
                int32_t rx_val =
                    static_cast<int32_t>(rx_chips[phys]) & chip_valid;
                // Binary Phase Mask 적용 (mask²=1 → 역투영 자동 성립)
                const int32_t ms = 1 - (static_cast<int32_t>(
                    (mask_bits >> i) & 1ull) << 1);
                scratch_rx[i] = static_cast<int16_t>(rx_val * ms);
            }

            std::memset(accum, 0, K * sizeof(int32_t));

            // ── 통합 Walsh 상관 디코딩 (16/64칩 공통) ──
            //  bit[k] = SUM(L) SUM(valid_i) rx'[i] × walsh(σ[k], i)
            //  rx'[i]에 이미 mask 적용됨 → 내부 루프 동일
            for (uint8_t layer = 0u; layer < L; ++layer) {
                const uint16_t row_offset =
                    static_cast<uint16_t>(layer) * K;
                const uint16_t* row_sel = &scratch_rows[row_offset];

                for (uint16_t k = 0u; k < K; ++k) {
                    int32_t acc = 0;
                    const uint32_t row_k =
                        static_cast<uint32_t>(row_sel[k]);
                    for (uint16_t i = 0u; i < N; ++i) {
                        const int8_t w = Walsh_Code(
                            row_k, static_cast<uint32_t>(i));
                        acc += static_cast<int32_t>(scratch_rx[i]) *
                            static_cast<int32_t>(w);
                    }
                    accum[k] += acc;
                }
            }

            // Hard decision (branchless sign extraction)
            for (uint16_t k = 0u; k < K; ++k) {
                const int32_t sign_mask = accum[k] >> 31;
                output_bits[k] = static_cast<int8_t>((sign_mask << 1) + 1);
            }
            return HTS_Holo_Tensor_4D::SECURE_TRUE;
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

        std::memset(impl_buf_, 0, IMPL_BUF_SIZE);
    }

    HTS_Holo_Tensor_4D::~HTS_Holo_Tensor_4D() noexcept
    {
        Shutdown();
    }

    uint32_t HTS_Holo_Tensor_4D::Initialize(const uint32_t master_seed[4],
        const HoloTensor_Profile* profile) noexcept
    {
        if (master_seed == nullptr) { return SECURE_FALSE; }
        Holo4D_Busy_Guard guard(op_busy_);
        if (!guard.locked) { return SECURE_FALSE; }

        bool expected = false;
        if (!initialized_.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel))
        {
            return SECURE_TRUE;
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

        if (impl->Transition_State(HoloState::READY) != SECURE_TRUE) {
            return SECURE_FALSE;
        }
        return SECURE_TRUE;
    }

    void HTS_Holo_Tensor_4D::Shutdown() noexcept
    {
        Holo4D_Busy_Guard guard(op_busy_);
        if (!guard.locked) { return; }
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        impl->~Impl();

        //  패딩 영역 + accum + scratch 모두 파쇄
        Holo4D_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);

        initialized_.store(false, std::memory_order_release);
    }

    void HTS_Holo_Tensor_4D::Rotate_Seed(const uint32_t new_seed[4]) noexcept
    {
        if (new_seed == nullptr) { return; }
        Holo4D_Busy_Guard guard(op_busy_);
        if (!guard.locked) { return; }
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
        Holo4D_Busy_Guard guard(op_busy_);
        if (!guard.locked) { return; }
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

    uint32_t HTS_Holo_Tensor_4D::Encode_Block(const int8_t* data_bits, uint16_t K,
        int8_t* output_chips, uint16_t N) noexcept
    {
        if (data_bits == nullptr) { return SECURE_FALSE; }
        if (output_chips == nullptr) { return SECURE_FALSE; }
        Holo4D_Busy_Guard guard(op_busy_);
        if (!guard.locked) { return SECURE_FALSE; }
        if (!initialized_.load(std::memory_order_acquire)) { return SECURE_FALSE; }

        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        if (impl->Transition_State(HoloState::ENCODING) != SECURE_TRUE) {
            return SECURE_FALSE;
        }

        const uint32_t ok = impl->Encode(data_bits, K, output_chips, N);

        impl->Transition_State(HoloState::READY);

        if (ok == SECURE_TRUE) { impl->encode_count++; }
        return ok;
    }

    uint32_t HTS_Holo_Tensor_4D::Decode_Block(const int16_t* rx_chips, uint16_t N,
        uint64_t valid_mask,
        int8_t* output_bits, uint16_t K) noexcept
    {
        if (rx_chips == nullptr) { return SECURE_FALSE; }
        if (output_bits == nullptr) { return SECURE_FALSE; }
        Holo4D_Busy_Guard guard(op_busy_);
        if (!guard.locked) { return SECURE_FALSE; }
        if (!initialized_.load(std::memory_order_acquire)) { return SECURE_FALSE; }

        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        if (impl->Transition_State(HoloState::DECODING) != SECURE_TRUE) {
            return SECURE_FALSE;
        }

        const uint32_t ok = impl->Decode(rx_chips, N, valid_mask, output_bits, K);

        impl->Transition_State(HoloState::READY);

        if (ok == SECURE_TRUE) { impl->decode_count++; }
        return ok;
    }

    void HTS_Holo_Tensor_4D::Advance_Time_Slot() noexcept
    {
        Holo4D_Busy_Guard guard(op_busy_);
        if (!guard.locked) { return; }
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        reinterpret_cast<Impl*>(impl_buf_)->time_slot++;
    }

    void HTS_Holo_Tensor_4D::Set_Time_Slot(uint32_t frame_no) noexcept
    {
        Holo4D_Busy_Guard guard(op_busy_);
        if (!guard.locked) { return; }
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        reinterpret_cast<Impl*>(impl_buf_)->time_slot = frame_no;
    }

    HoloState HTS_Holo_Tensor_4D::Get_State() const noexcept
    {
        Holo4D_Busy_Guard guard(op_busy_);
        if (!guard.locked) { return HoloState::OFFLINE; }
        if (!initialized_.load(std::memory_order_acquire)) { return HoloState::OFFLINE; }
        return reinterpret_cast<const Impl*>(impl_buf_)->state;
    }

    uint32_t HTS_Holo_Tensor_4D::Get_Encode_Count() const noexcept
    {
        Holo4D_Busy_Guard guard(op_busy_);
        if (!guard.locked) { return 0u; }
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        return reinterpret_cast<const Impl*>(impl_buf_)->encode_count;
    }

    uint32_t HTS_Holo_Tensor_4D::Get_Decode_Count() const noexcept
    {
        Holo4D_Busy_Guard guard(op_busy_);
        if (!guard.locked) { return 0u; }
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        return reinterpret_cast<const Impl*>(impl_buf_)->decode_count;
    }

    uint32_t HTS_Holo_Tensor_4D::Get_Time_Slot() const noexcept
    {
        Holo4D_Busy_Guard guard(op_busy_);
        if (!guard.locked) { return 0u; }
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        return reinterpret_cast<const Impl*>(impl_buf_)->time_slot;
    }

} // namespace ProtectedEngine
