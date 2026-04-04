/// @file  HTS_Holo_Tensor_4D.cpp
/// @brief HTS 4D Holographic Tensor Engine -- True Holographic Spread/Despread
/// @note  ARM only. Pure ASCII. No PC/server code.
///        Every output chip = f(ALL input bits, ALL phases, ALL layers)
///        Film torn in half -> each piece still shows the full image.
/// @author Lim Young-jun
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_Holo_Tensor_4D.h"
#include "HTS_Arm_Irq_Mask_Guard.h"
#include "HTS_Secure_Memory.h"
#include <new>
#include <atomic>
#include <cstring>
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#include <intrin.h>
#endif

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#if defined(__has_include)
#if __has_include(<cmsis_compiler.h>)
#include <cmsis_compiler.h>
#elif __has_include("cmsis_compiler.h")
#include "cmsis_compiler.h"
#endif
#else
#include <cmsis_compiler.h>
#endif
#endif

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
        //  accum[HOLO_MAX_BLOCK_BITS(128)] — 비트(K) 기준만 고려
        //  위험: Encode에서 accum[0..N-1] (N=칩수) 인덱싱 → N > 128 시 OOB
        //  현재: MAX_BLOCK(128) > CHIP_COUNT(64) → 우연히 안전
        //  양쪽 최대값 보증 + static_assert로 빌드타임 검증
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

        /// D-2: 인코드/디코드 후 Walsh 행·열 순열·마스크 가공 흔적 제거 (SRAM 평문 잔존 방지)
        void Wipe_Sensitive_Scratch() noexcept
        {
            SecureMemory::secureWipe(static_cast<void*>(scratch_rows), sizeof(scratch_rows));
            SecureMemory::secureWipe(static_cast<void*>(scratch_perm), sizeof(scratch_perm));
            SecureMemory::secureWipe(static_cast<void*>(scratch_rx), sizeof(scratch_rx));
            SecureMemory::secureWipe(static_cast<void*>(accum), sizeof(accum));
            // LTO/DSE: 소거가 다음 사용 전까지 “죽은 저장”으로 제거되지 않도록 펜스 고정
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("" ::: "memory");
#endif
            std::atomic_thread_fence(std::memory_order_release);
        }

        // ============================================================
        //  Walsh-Hadamard: walsh(row,col) = (-1)^popcount(row & col)
        //  HOLO_CHIP_COUNT ≤ 64 → ROM 64×64 LUT (핫루프 패리티·분기 제거, 수식 동일)
        // ============================================================
        struct Walsh64Lut final {
            int8_t t[64][64];
            // MSVC: 루프 constexpr ctor + static constexpr 객체는 C2131(비상수) — static const 런타임 1회 초기화
            Walsh64Lut() noexcept : t{} {
                for (uint32_t r = 0u; r < 64u; ++r) {
                    for (uint32_t c = 0u; c < 64u; ++c) {
                        uint32_t x = r & c;
                        x ^= (x >> 16u);
                        x ^= (x >> 8u);
                        x ^= (x >> 4u);
                        x ^= (x >> 2u);
                        x ^= (x >> 1u);
                        t[r][c] = static_cast<int8_t>(
                            1 - 2 * static_cast<int32_t>(x & 1u));
                    }
                }
            }
        };
        static inline const Walsh64Lut k_walsh64{};

        static int8_t Walsh_Code(uint32_t row, uint32_t col) noexcept
        {
            return k_walsh64.t[row & 63u][col & 63u];
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
            for (uint16_t j = 0u; j < N; ++j) {
                scratch_rows[static_cast<size_t>(j)] = j;
            }

            for (uint16_t j = static_cast<uint16_t>(N - 1u); j > 0u; --j) {
                const uint32_t range = static_cast<uint32_t>(j) + 1u;
                const uint32_t r = static_cast<uint32_t>(
                    (static_cast<uint64_t>(rng.Next()) * range) >> 32u);
                // 글리치·분기 왜곡 완화: r ∈ [0, range) 산술 클램프 (분기 없음, O(1))
                const int32_t dr =
                    static_cast<int32_t>(r) - static_cast<int32_t>(range);
                const uint32_t mask = static_cast<uint32_t>(dr >> 31);
                const uint16_t r_idx = static_cast<uint16_t>(
                    (r & mask) | ((range - 1u) & ~mask));
                const uint16_t tmp = scratch_rows[static_cast<size_t>(j)];
                scratch_rows[static_cast<size_t>(j)] =
                    scratch_rows[static_cast<size_t>(r_idx)];
                scratch_rows[static_cast<size_t>(r_idx)] = tmp;
            }

            // 2. Partition: layer l gets row_perm[l*K .. (l+1)*K - 1]
            //    All rows are DISTINCT -> Walsh orthogonality guaranteed
            const uint32_t L32 = static_cast<uint32_t>(L);
            const uint32_t K32p = static_cast<uint32_t>(K);
            const uint16_t total_rows = static_cast<uint16_t>(L32 * K32p);
            for (uint16_t idx = 0u; idx < total_rows && idx < N; ++idx) {
                all_row_sel[static_cast<size_t>(idx)] =
                    scratch_rows[static_cast<size_t>(idx)];
            }

            // 3. Column permutation (shared across all layers)
            // C6001 fix: zero-initialize array
            for (uint16_t j = 0u; j < N; ++j) {
                scratch_perm[static_cast<size_t>(j)] = j;
            }

            for (uint16_t j = static_cast<uint16_t>(N - 1u); j > 0u; --j) {
                const uint32_t range2 = static_cast<uint32_t>(j) + 1u;
                const uint32_t r = static_cast<uint32_t>(
                    (static_cast<uint64_t>(rng.Next()) * range2) >> 32u);
                const int32_t dr2 =
                    static_cast<int32_t>(r) - static_cast<int32_t>(range2);
                const uint32_t mask2 = static_cast<uint32_t>(dr2 >> 31);
                const uint16_t r_idx = static_cast<uint16_t>(
                    (r & mask2) | ((range2 - 1u) & ~mask2));
                const uint16_t tmp = scratch_perm[static_cast<size_t>(j)];
                scratch_perm[static_cast<size_t>(j)] =
                    scratch_perm[static_cast<size_t>(r_idx)];
                scratch_perm[static_cast<size_t>(r_idx)] = tmp;
            }

            for (uint16_t j = 0u; j < N; ++j) {
                col_perm[static_cast<size_t>(j)] =
                    scratch_perm[static_cast<size_t>(j)];
            }
        }

        // ============================================================
        //  Holographic Encode: K bits -> N chips
        //
        //  구현(본 빌드): Walsh-Mask-Permutation 전 구간 공통
        //   - 레이어별 분할 행 선택 + 열 순열(PRNG) + 이진 위상 마스크
        //   - chip[pi[i]] = mask[i] × SUM(L,k) data[k] × walsh(σ[k], i)
        //   Cos_Q15 / Sin_Q15 (Defs.h)는 보조·확장용 API이며 본 Encode 경로는 미사용.
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
            const uint32_t L32e = static_cast<uint32_t>(L);
            const uint32_t K32e = static_cast<uint32_t>(K);
            const uint32_t N32e = static_cast<uint32_t>(N);
            if (L32e * K32e > N32e) { return HTS_Holo_Tensor_4D::SECURE_FALSE; }

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

            std::memset(accum, 0, static_cast<size_t>(N) * sizeof(int32_t));

            // ── 통합 Walsh 홀로그램 투영 (16/64칩 공통) ──
            //  chip[π[i]] = mask[i] × Σ_L Σ_k data[k]×walsh(σ[k],i)  — ms(i)는 L과 무관
            //  루프: i 바깥 → ms·phys 1회, Σ_L 후 accum[phys] += sumL×ms (동치·마스크 추출 L배↓)
            //  최적화: k 루프 4비트(4요소) 전개 → 분기·루프 오버헤드 감소, MAC 연속성 향상
            for (uint16_t i = 0u; i < N; ++i) {
                const int32_t ms = 1 - (static_cast<int32_t>(
                    (mask_bits >> static_cast<uint64_t>(i)) & 1ull) << 1);
                const uint16_t phys = scratch_perm[static_cast<size_t>(i)];
                const uint32_t col_i = static_cast<uint32_t>(i);
                int32_t sumL = 0;
                for (uint8_t layer = 0u; layer < L; ++layer) {
                    const uint16_t row_offset = static_cast<uint16_t>(
                        static_cast<uint32_t>(layer) * K32e);
                    const uint16_t* row_sel =
                        &scratch_rows[static_cast<size_t>(row_offset)];
                    int32_t chip_acc = 0;
                    uint16_t k = 0u;
                    for (; k + 3u < K; k += 4u) {
                        const int32_t dk0 =
                            static_cast<int32_t>(data[static_cast<size_t>(k)]);
                        const int32_t dk1 =
                            static_cast<int32_t>(data[static_cast<size_t>(k + 1u)]);
                        const int32_t dk2 =
                            static_cast<int32_t>(data[static_cast<size_t>(k + 2u)]);
                        const int32_t dk3 =
                            static_cast<int32_t>(data[static_cast<size_t>(k + 3u)]);
                        const uint32_t rk0 =
                            static_cast<uint32_t>(row_sel[static_cast<size_t>(k)]);
                        const uint32_t rk1 =
                            static_cast<uint32_t>(row_sel[static_cast<size_t>(k + 1u)]);
                        const uint32_t rk2 =
                            static_cast<uint32_t>(row_sel[static_cast<size_t>(k + 2u)]);
                        const uint32_t rk3 =
                            static_cast<uint32_t>(row_sel[static_cast<size_t>(k + 3u)]);
                        const int32_t w0 =
                            static_cast<int32_t>(Walsh_Code(rk0, col_i));
                        const int32_t w1 =
                            static_cast<int32_t>(Walsh_Code(rk1, col_i));
                        const int32_t w2 =
                            static_cast<int32_t>(Walsh_Code(rk2, col_i));
                        const int32_t w3 =
                            static_cast<int32_t>(Walsh_Code(rk3, col_i));
                        chip_acc += dk0 * w0 + dk1 * w1 + dk2 * w2 + dk3 * w3;
                    }
                    for (; k < K; ++k) {
                        const int8_t w = Walsh_Code(
                            static_cast<uint32_t>(row_sel[static_cast<size_t>(k)]),
                            col_i);
                        chip_acc += static_cast<int32_t>(data[static_cast<size_t>(k)]) *
                            static_cast<int32_t>(w);
                    }
                    sumL += chip_acc;
                }
                accum[static_cast<size_t>(phys)] += sumL * ms;
            }

            // Soft output: clamp to int8_t range
            for (uint16_t i = 0u; i < N; ++i) {
#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
                chips[static_cast<size_t>(i)] = static_cast<int8_t>(
                    __SSAT(accum[static_cast<size_t>(i)], 8));
#else
                if (accum[static_cast<size_t>(i)] > 127) {
                    chips[static_cast<size_t>(i)] = 127;
                }
                else if (accum[static_cast<size_t>(i)] < -127) {
                    chips[static_cast<size_t>(i)] = -127;
                }
                else {
                    chips[static_cast<size_t>(i)] =
                        static_cast<int8_t>(accum[static_cast<size_t>(i)]);
                }
#endif
            }
            Wipe_Sensitive_Scratch();
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
            const uint32_t L32d = static_cast<uint32_t>(L);
            const uint32_t K32d = static_cast<uint32_t>(K);
            const uint32_t N32d = static_cast<uint32_t>(N);
            if (L32d * K32d > N32d) { return HTS_Holo_Tensor_4D::SECURE_FALSE; }

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
            std::memset(scratch_rx, 0, static_cast<size_t>(N) * sizeof(int16_t));
            for (uint16_t i = 0u; i < N; ++i) {
                const uint16_t phys = scratch_perm[static_cast<size_t>(i)];
                const uint32_t phys_u = static_cast<uint32_t>(phys) & 63u;
                const uint32_t vbit = static_cast<uint32_t>(
                    (valid_mask >> phys_u) & 1ull);
                const int32_t chip_valid = -static_cast<int32_t>(vbit);
                int32_t rx_val =
                    static_cast<int32_t>(rx_chips[static_cast<size_t>(phys_u)]) & chip_valid;
                // Binary Phase Mask 적용 (mask²=1 → 역투영 자동 성립)
                const int32_t ms = 1 - (static_cast<int32_t>(
                    (mask_bits >> static_cast<uint64_t>(i)) & 1ull) << 1);
                scratch_rx[static_cast<size_t>(i)] =
                    static_cast<int16_t>(rx_val * ms);
            }

            std::memset(accum, 0, static_cast<size_t>(K) * sizeof(int32_t));

            // ── 통합 Walsh 상관 디코딩 (16/64칩 공통) ──
            //  bit[k] = Σ_L Σ_i rx'[i]×walsh(σ[k],i) — k 바깥: accum[k] 1회 가산
            //  최적화: i 루프 4칩(4요소) 전개 → 역상관 MAC 연속성·브랜치 예측 부담 완화
            for (uint16_t k = 0u; k < K; ++k) {
                int32_t sumL = 0;
                for (uint8_t layer = 0u; layer < L; ++layer) {
                    const uint16_t row_offset = static_cast<uint16_t>(
                        static_cast<uint32_t>(layer) * K32d);
                    const uint16_t* row_sel =
                        &scratch_rows[static_cast<size_t>(row_offset)];
                    const uint32_t row_k =
                        static_cast<uint32_t>(row_sel[static_cast<size_t>(k)]);
                    int32_t acc = 0;
                    uint16_t ii = 0u;
                    for (; ii + 3u < N; ii += 4u) {
                        const uint32_t i0 = static_cast<uint32_t>(ii);
                        const uint32_t i1 = static_cast<uint32_t>(ii + 1u);
                        const uint32_t i2 = static_cast<uint32_t>(ii + 2u);
                        const uint32_t i3 = static_cast<uint32_t>(ii + 3u);
                        const int32_t w0 =
                            static_cast<int32_t>(Walsh_Code(row_k, i0));
                        const int32_t w1 =
                            static_cast<int32_t>(Walsh_Code(row_k, i1));
                        const int32_t w2 =
                            static_cast<int32_t>(Walsh_Code(row_k, i2));
                        const int32_t w3 =
                            static_cast<int32_t>(Walsh_Code(row_k, i3));
                        const int32_t r0 =
                            static_cast<int32_t>(scratch_rx[static_cast<size_t>(ii)]);
                        const int32_t r1 =
                            static_cast<int32_t>(scratch_rx[static_cast<size_t>(ii + 1u)]);
                        const int32_t r2 =
                            static_cast<int32_t>(scratch_rx[static_cast<size_t>(ii + 2u)]);
                        const int32_t r3 =
                            static_cast<int32_t>(scratch_rx[static_cast<size_t>(ii + 3u)]);
                        acc += r0 * w0 + r1 * w1 + r2 * w2 + r3 * w3;
                    }
                    for (; ii < N; ++ii) {
                        const int8_t w = Walsh_Code(
                            row_k, static_cast<uint32_t>(ii));
                        acc += static_cast<int32_t>(scratch_rx[static_cast<size_t>(ii)]) *
                            static_cast<int32_t>(w);
                    }
                    sumL += acc;
                }
                accum[static_cast<size_t>(k)] += sumL;
            }

            // Hard decision: 부호 비트는 uint32_t로 추출 (>>/<< on signed UB·MISRA 회피)
            for (uint16_t k = 0u; k < K; ++k) {
                const uint32_t sign_bit =
                    static_cast<uint32_t>(accum[static_cast<size_t>(k)]) >> 31u;
                output_bits[static_cast<size_t>(k)] = static_cast<int8_t>(
                    1 - 2 * static_cast<int32_t>(sign_bit));
            }
            Wipe_Sensitive_Scratch();
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
        if (!initialized_.load(std::memory_order_acquire)) {
            return;
        }
        // 진행 중 Encode/Decode가 impl_buf_를 사용하는 동안 파쇄 금지 → 락 확보까지 스핀
        while (op_busy_.test_and_set(std::memory_order_acq_rel)) {
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
            _mm_pause();
#elif defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))
            __builtin_ia32_pause();
#elif defined(__arm__) && !defined(__aarch64__)
            // Cortex-M3+: WFE/완화 스핀; 미지원 툴체인은 컴파일러 배리어만
#if defined(__ARM_ARCH) && (__ARM_ARCH >= 7)
            __asm__ __volatile__("yield" ::: "memory");
#else
            __asm__ __volatile__("" ::: "memory");
#endif
#else
            ;
#endif
        }

        // Cortex-M: 동일 코어 ISR이 락을 쓰지 않는 경로까지 차단(단일코어 전제)
#if defined(__arm__) && !defined(__aarch64__)
        Armv7m_Irq_Mask_Guard irq_primask;
#endif

        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        impl->~Impl();
        SecureMemory::secureWipe(static_cast<void*>(impl_buf_), IMPL_BUF_SIZE);
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" ::: "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);

        initialized_.store(false, std::memory_order_release);
        op_busy_.clear(std::memory_order_release);
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
            impl->accum[static_cast<size_t>(i)] = 0;
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

        //  패딩 영역 + accum + scratch 모두 파쇄 (D-2: SecureMemory::secureWipe)
        SecureMemory::secureWipe(static_cast<void*>(impl_buf_), IMPL_BUF_SIZE);

        initialized_.store(false, std::memory_order_release);
    }

    void HTS_Holo_Tensor_4D::Rotate_Seed(const uint32_t new_seed[4]) noexcept
    {
        if (new_seed == nullptr) { return; }
        Holo4D_Busy_Guard guard(op_busy_);
        if (!guard.locked) { return; }
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        SecureMemory::secureWipe(static_cast<void*>(impl->master_seed), sizeof(impl->master_seed));

        impl->master_seed[0] = new_seed[0];
        impl->master_seed[1] = new_seed[1];
        impl->master_seed[2] = new_seed[2];
        impl->master_seed[3] = new_seed[3];
        std::atomic_thread_fence(std::memory_order_release);
    }

    uint32_t HTS_Holo_Tensor_4D::Set_Profile(const HoloTensor_Profile* profile) noexcept
    {
        if (profile == nullptr) { return SECURE_FALSE; }
        Holo4D_Busy_Guard guard(op_busy_);
        if (!guard.locked) { return SECURE_FALSE; }
        if (!initialized_.load(std::memory_order_acquire)) { return SECURE_FALSE; }
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
        return SECURE_TRUE;
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

    uint32_t HTS_Holo_Tensor_4D::Advance_Time_Slot() noexcept
    {
        Holo4D_Busy_Guard guard(op_busy_);
        if (!guard.locked) { return SECURE_FALSE; }
        if (!initialized_.load(std::memory_order_acquire)) { return SECURE_FALSE; }
        reinterpret_cast<Impl*>(impl_buf_)->time_slot++;
        return SECURE_TRUE;
    }

    uint32_t HTS_Holo_Tensor_4D::Set_Time_Slot(uint32_t frame_no) noexcept
    {
        Holo4D_Busy_Guard guard(op_busy_);
        if (!guard.locked) { return SECURE_FALSE; }
        if (!initialized_.load(std::memory_order_acquire)) { return SECURE_FALSE; }
        reinterpret_cast<Impl*>(impl_buf_)->time_slot = frame_no;
        return SECURE_TRUE;
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
