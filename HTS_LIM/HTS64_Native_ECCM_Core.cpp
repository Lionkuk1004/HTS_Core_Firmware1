// =============================================================================
/// @file   HTS64_Native_ECCM_Core.cpp
/// @brief  64칩 ECCM 수신 엔진 구현
/// @target STM32F407VGT6 (Cortex-M4F, 168 MHz) / PC 시뮬레이션
///
/// @see HTS64_Native_ECCM_Core.hpp
// =============================================================================
#include "HTS64_Native_ECCM_Core.hpp"
#include "HTS_RF_Metrics.h"   // ajc_nf 기록용 (선택적)
#include "HTS_Secure_Memory.h"
#include <atomic>
#include <climits>
#include <cstdint>
#include <new>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

static_assert(sizeof(uint32_t) == 4u, "uint32_t must be 4 bytes");
static_assert(sizeof(int16_t) == 2u, "int16_t must be 2 bytes");
static_assert(sizeof(int32_t) == 4u, "int32_t must be 4 bytes");

namespace ProtectedEngine {

    // =============================================================================
    //  모듈 상수
    // =============================================================================

    static constexpr int      N = 64;   ///< Walsh 코드 길이 (칩 수)
    static constexpr uint32_t MIN_NF = 1u;   ///< NF IIR 0-값 방어 가드
    static constexpr uint32_t CLEAN_TH = 50u;  ///< 무간섭 판별 baseline 임계

    static_assert(N % 4 == 0,
        "N must be a multiple of 4 for exact Q25/Q75 index derivation");

    /// @brief Q75/Q25 비율 임계값 (CW 감지)
    static constexpr uint32_t CW_RATIO_TH = 4u;

    /// @brief 32비트 argmax 안전 피크 임계값
    static constexpr int32_t ARGMAX_SAFE_PEAK = 46340;

    /// @brief Q25/Q75 인덱스 — N에서 자동 파생 (J-3)
    static constexpr int Q25_IDX = N / 4 - 1;       // 15 (N=64)
    static constexpr int Q75_IDX = 3 * N / 4 - 1;   // 47 (N=64)

    /// @brief OS-CFAR 오경보 마진 팩터 (left-shift 적용)
    ///  CFAR 임계: th = nf^2 * N << CFAR_MARGIN_SHIFT
    ///  근거: OS-CFAR 표준 마진 α=1.5~4.0. α=2는 오경보율 50% 감소
    ///         동시에 최소 SNR 요구값 +3dB (재밍 환경 적합)
    ///  값 조정: CFAR_MARGIN_SHIFT=1(α=2) → 오경보 -50%, 감도 -3dB
    ///           필드 환경에서 SNR 여유가 충분하면 SHIFT=2(α=4)도 가능
    static constexpr int CFAR_MARGIN_SHIFT = 1;  ///< α = 2^SHIFT = 2

    /// @brief 소프트 클리핑 상한 = punch 이하로 강제 클램프
    ///  punch = baseline << PUNCH_SHIFT (기본 3 = 8배)
    ///  clip_u가 punch보다 크면 EMP 펄스 에너지가 필터링 없이 통과
    ///  → clip_u = min(clip_u, punch - 1) 로 항상 punch 내측 보장
    static constexpr int PUNCH_SHIFT = 3;         ///< punch = baseline << 3

    // =============================================================================
    //  내부 유틸리티
    // =============================================================================

    static constexpr uint32_t fast_abs(int32_t x) noexcept {
        const int32_t mask = x >> 31;
        return static_cast<uint32_t>((x ^ mask) - mask);
    }

    /// Cortex-M4: 비정렬 int16/int32 로드 → UsageFault 방지 (B-2 / H-5)
    static bool ptr_aligned_for(const void* p, size_t align) noexcept {
        if (p == nullptr) {
            return false;
        }
        const uintptr_t a = reinterpret_cast<uintptr_t>(p);
        const uintptr_t m = align - 1u;
        return (a & m) == 0u;
    }

    static bool iq_pair_aligned(const int16_t* a, const int16_t* b) noexcept {
        return ptr_aligned_for(a, alignof(int16_t))
            && ptr_aligned_for(b, alignof(int16_t));
    }

    static bool fwht_pair_aligned(const int32_t* a, const int32_t* b) noexcept {
        return ptr_aligned_for(a, alignof(int32_t))
            && ptr_aligned_for(b, alignof(int32_t));
    }

    /// @brief Q8 비율 clip8/m — 런타임 UDIV 없음 (CLZ 역수 근사)
    /// @details m≥2^msb 이므로 clip8/m ≤ clip8/2^msb = clip8>>msb. 상한 근사로 소프트 클립(피크 억제)에 적합.
    static uint32_t ratio_q8_from_clip8_m(uint32_t clip8, uint32_t m) noexcept {
        m |= 1u;
        unsigned msb;
#if defined(__GNUC__) || defined(__clang__)
        msb = 31u - static_cast<unsigned>(__builtin_clz(m));
#elif defined(_MSC_VER)
        unsigned long idx = 0;
        _BitScanReverse(&idx, m);
        msb = static_cast<unsigned>(idx);
#else
        msb = 0u;
        for (uint32_t t = m; t > 1u; t >>= 1u) { ++msb; }
#endif
        uint32_t r = clip8 >> msb;
        if (r > 255u) { r = 255u; }
        return r;
    }

    static constexpr int16_t clamp_i16(int32_t v) noexcept {
        if (v > INT16_MAX) { return INT16_MAX; }
        if (v < INT16_MIN) { return INT16_MIN; }
        return static_cast<int16_t>(v);
    }

    static void swap_u32(uint32_t& a, uint32_t& b) noexcept {
        const uint32_t t = a; a = b; b = t;
    }

    /// @brief Quickselect O(N) — k번째 최솟값 반환
    /// 가드 카운터: guard = N×4 = 256 → WCET 결정론
    static uint32_t nth_select(uint32_t* a, int n, int k) noexcept {
        if (a == nullptr || n <= 0 || k < 0 || k >= n) {
            return 0u;
        }
        int lo = 0, hi = n - 1;
        int guard = n << 2;
        while (lo < hi && --guard > 0) {
            const int mid = lo + ((hi - lo) >> 1);
            if (a[mid] < a[lo]) { swap_u32(a[lo], a[mid]); }
            if (a[hi] < a[lo]) { swap_u32(a[lo], a[hi]); }
            if (a[mid] < a[hi]) { swap_u32(a[mid], a[hi]); }
            const uint32_t pivot = a[hi];
            int store = lo;
            for (int i = lo; i < hi; ++i) {
                if (a[i] < pivot) { swap_u32(a[store], a[i]); ++store; }
            }
            swap_u32(a[store], a[hi]);
            if (store == k) { return a[store]; }
            if (store < k) { lo = store + 1; }
            else { hi = store - 1; }
        }
        return a[lo];
    }

    // =============================================================================
    //  Pimpl 구현체
    //
    //   인스턴스당 1스레드 전용. PRNG CAS는 원자적이나 kH/kL 쌍 일관성 미보장.
    //   동일 인스턴스 동시 Decode 호출 시 키 쌍 뒤섞임 → 복호 실패.
    //   STM32 단일 스레드 환경에서는 무해.
    //
    //   mags[64]+union(sorted/sI)[64]+sQ[64]=768B + atomic 3개 ≈ 784B
    //   래퍼 sizeof(HTS64_Native_ECCM_Core) ≈ 2056B와 구분할 것
    // =============================================================================

    struct HTS64_Native_ECCM_Core::Impl {

        std::atomic<uint32_t> prng{ 0u };
        std::atomic<uint32_t> nf_q16{ 100u << 16u };
        std::atomic<bool>     cal{ false };

        uint32_t mags[N] = {};
        //  sorted: extract_and_descramble 전반부에서 nth_select용 (파괴적)
        //  sI:     extract_and_descramble 후반부 + FWHT에서 사용
        //  sorted 소비 완료 후 sI 기록 → 메모리 공유 안전
        //  절감: 256B (uint32_t[64])
        union {
            uint32_t sorted[N];   // nth_select 전용 (파괴적 읽기)
            int32_t  sI[N];       // 스크램블 해제 I + FWHT
        } scratch_ = {};          // 익명 union 제로 초기화 (MSVC C26495)
        int32_t  sQ[N] = {};

        // ── Lock-Free PRNG (Xorshift32) — CAS 스핀 상한 (I-2 / N-3, ISR·RTOS 행업 방지)
        uint32_t next_prng() noexcept {
            constexpr unsigned kMaxCas = 256u;
            for (unsigned spin = 0u; spin < kMaxCas; ++spin) {
                uint32_t o = prng.load(std::memory_order_relaxed);
                uint32_t nv = o;
                nv ^= nv << 13u;
                nv ^= nv >> 17u;
                nv ^= nv << 5u;
                if (prng.compare_exchange_weak(
                    o, nv,
                    std::memory_order_relaxed,
                    std::memory_order_relaxed)) {
                    return nv;
                }
            }
            uint32_t o = prng.load(std::memory_order_relaxed);
            uint32_t nv = o;
            nv ^= nv << 13u;
            nv ^= nv >> 17u;
            nv ^= nv << 5u;
            prng.store(nv, std::memory_order_relaxed);
            return nv;
        }

        // ── Lock-Free NF IIR (alpha = 1/16) — CAS 스핀 상한 (I-2)
        void update_nf(uint32_t e) noexcept {
            constexpr unsigned kMaxCas = 256u;
            for (unsigned spin = 0u; spin < kMaxCas; ++spin) {
                uint32_t o = nf_q16.load(std::memory_order_relaxed);
                const uint32_t decay = o - (o >> 4u);
                const uint32_t input = e << 12u;
                const uint32_t nw =
                    (input > (UINT32_MAX - decay)) ? UINT32_MAX : (decay + input);
                if (nf_q16.compare_exchange_weak(
                    o, nw,
                    std::memory_order_relaxed,
                    std::memory_order_relaxed)) {
                    return;
                }
            }
            uint32_t o = nf_q16.load(std::memory_order_relaxed);
            const uint32_t decay = o - (o >> 4u);
            const uint32_t input = e << 12u;
            const uint32_t nw =
                (input > (UINT32_MAX - decay)) ? UINT32_MAX : (decay + input);
            nf_q16.store(nw, std::memory_order_relaxed);
        }

        // ── FWHT 64점 In-Place ──
        static void FWHT(int32_t* d) noexcept {
            for (int len = 1; len < N; len <<= 1) {
                for (int i = 0; i < N; i += 2 * len) {
                    for (int j = 0; j < len; ++j) {
                        const int32_t u = d[i + j];
                        const int32_t v = d[i + len + j];
                        d[i + j] = u + v;
                        d[i + len + j] = u - v;
                    }
                }
            }
        }

        // ── ECCM 키 비트 추출 ──
        static bool kb(uint32_t kH, uint32_t kL, int i) noexcept {
            return i < 32
                ? (((kH >> (31u - static_cast<uint32_t>(i))) & 1u) != 0u)
                : (((kL >> (31u - static_cast<uint32_t>(i - 32))) & 1u) != 0u);
        }

        // =========================================================================
        /// @brief 진폭 추출 + 4단 적응형 클리퍼 + 스크램블 해제
        // =========================================================================
        uint32_t extract_and_descramble(
            const int16_t* rI, const int16_t* rQ,
            uint32_t kH, uint32_t kL) noexcept {

            for (int i = 0; i < N; ++i) {
                mags[i] = fast_abs(static_cast<int32_t>(rI[i]))
                    + fast_abs(static_cast<int32_t>(rQ[i]));
                scratch_.sorted[i] = mags[i];
            }

            uint32_t baseline = nth_select(scratch_.sorted, N, Q25_IDX);
            if (baseline < MIN_NF) { baseline = MIN_NF; }

            uint32_t q75 = nth_select(scratch_.sorted, N, Q75_IDX);
            if (q75 < baseline) { q75 = baseline; }

            const bool is_cw_like = (q75 > baseline * CW_RATIO_TH);
            const bool is_clean = (baseline < CLEAN_TH);
            //  하드코딩 << 3u — PUNCH_SHIFT 상수화
            const uint32_t punch = baseline << static_cast<uint32_t>(PUNCH_SHIFT);

            int32_t clip = is_cw_like
                ? static_cast<int32_t>(q75 << 2u)
                : static_cast<int32_t>(baseline << 2u);
            if (clip < 4) { clip = 4; }

            //
            //  clip_u = min(clip_u_raw, punch) — clip와 punch 사이 갭 제거, mags>punch는 영점 소거
            //
            const uint32_t clip_u_raw = static_cast<uint32_t>(clip);
            const uint32_t clip_u = (clip_u_raw < punch) ? clip_u_raw : punch;
            const uint32_t clip8 = clip_u << 8u;

            for (int i = 0; i < N; ++i) {
                int32_t si = static_cast<int32_t>(rI[i]);
                int32_t sq = static_cast<int32_t>(rQ[i]);

                if (!is_clean) {
                    if (mags[i] > punch) {
                        si = 0; sq = 0;
                    }
                    else if (mags[i] > clip_u) {
                        // si/sq는 이미 int32_t — ratio_q8만 캐스트
                        const uint32_t ratio_q8 = ratio_q8_from_clip8_m(clip8, mags[i]);
                        const int32_t r_q8 = static_cast<int32_t>(ratio_q8);
                        si = (si * r_q8) >> 8;
                        sq = (sq * r_q8) >> 8;
                    }
                }

                if (kb(kH, kL, i)) { si = -si; sq = -sq; }
                scratch_.sI[i] = si;
                sQ[i] = sq;
            }
            return baseline;
        }

        // ── NF 기반 적응형 에너지 임계 (th = nf² × N) ──
        uint64_t adaptive_threshold() const noexcept {
            uint32_t nf = nf_q16.load(std::memory_order_relaxed) >> 16u;
            if (nf < MIN_NF) { nf = MIN_NF; }
            //  th = nf^2 * N  (α=1.0)
            //    → 오경보 조건: best_actual >= th 에서 α=1.0은
            //      노이즈 피크가 통계적으로 th를 넘을 확률이 높음
            //  th = nf^2 * N << CFAR_MARGIN_SHIFT  (α=2^1=2.0)
            //    → 임계값 2배 상승 → 오경보율 이론상 50% 감소
            //    → 정상 수신 신호는 nf의 수배 이상이므로 miss 없음
            //  오버플로 안전성:
            //    nf 최대 ≈ 65534 (int16_t 합산 최대)
            //    nf^2 * N = 65534^2 * 64 = 2.74e11 < UINT64_MAX (1.8e19) ✓
            //    << 1 후에도 5.48e11 < UINT64_MAX ✓
            const uint64_t base_th =
                static_cast<uint64_t>(nf)
                * static_cast<uint64_t>(nf)
                * static_cast<uint64_t>(N);
            return base_th << static_cast<uint64_t>(CFAR_MARGIN_SHIFT);
        }

        // =========================================================================
        /// @brief 디코드 공통 코어 (Hard/Soft 공용)
        // =========================================================================
        int8_t decode_core(const int16_t* rI, const int16_t* rQ,
            int32_t* fI, int32_t* fQ, bool hard) noexcept {
            if (!iq_pair_aligned(rI, rQ)) {
                return -1;
            }
            if (!hard && ((fI == nullptr) || (fQ == nullptr)
                || !fwht_pair_aligned(fI, fQ))) {
                return -1;
            }
            if (!cal.load(std::memory_order_acquire)) { return -1; }

            const uint32_t kH = next_prng();
            const uint32_t kL = next_prng();

            const uint32_t baseline = extract_and_descramble(rI, rQ, kH, kL);
            update_nf(baseline);

            FWHT(scratch_.sI);
            FWHT(sQ);

            if (!hard && (fI != nullptr) && (fQ != nullptr)) {
                for (int i = 0; i < N; ++i) { fI[i] = scratch_.sI[i]; fQ[i] = sQ[i]; }
            }

            // Step 1: 피크 탐색 → 적응형 시프트 결정
            uint32_t peak = 0u;
            for (int m = 0; m < N; ++m) {
                const uint32_t a = fast_abs(scratch_.sI[m]);
                const uint32_t b = fast_abs(sQ[m]);
                if (a > peak) { peak = a; }
                if (b > peak) { peak = b; }
            }
            int shift = 0;
            while ((peak > static_cast<uint32_t>(ARGMAX_SAFE_PEAK)) && (shift < 16)) {
                peak >>= 1u;
                ++shift;
            }

            // Step 2: 32비트 argmax 루프
            uint32_t best_scaled = 0u;
            uint8_t  dec = 0xFFu;
            for (int m = 0; m < N; ++m) {
                const int32_t  si_s = scratch_.sI[m] >> shift;
                const int32_t  sq_s = sQ[m] >> shift;
                const int64_t si64 = static_cast<int64_t>(si_s);
                const int64_t sq64 = static_cast<int64_t>(sq_s);
                const uint64_t e64 =
                    static_cast<uint64_t>(si64 * si64 + sq64 * sq64);
                const uint32_t e = static_cast<uint32_t>(
                    (e64 > static_cast<uint64_t>(UINT32_MAX))
                        ? static_cast<uint64_t>(UINT32_MAX)
                        : e64);
                if (e > best_scaled) { best_scaled = e; dec = static_cast<uint8_t>(m); }
            }

            // Step 3: 최선 빈 1회 64비트 임계값 비교
            if (dec == 0xFFu) { return -1; }
            const uint64_t best_actual =
                static_cast<uint64_t>(
                    static_cast<int64_t>(scratch_.sI[dec]) * scratch_.sI[dec]
                    + static_cast<int64_t>(sQ[dec]) * sQ[dec]);
            const uint64_t th = adaptive_threshold();
            return (best_actual < th) ? static_cast<int8_t>(-1)
                : static_cast<int8_t>(dec);
        }

        // ── 스크램블 해제 전용 (FWHT 생략) ──
        void descramble_3stage(const int16_t* rI, const int16_t* rQ,
            int16_t* oI, int16_t* oQ) noexcept {
            if (!iq_pair_aligned(rI, rQ)
                || !iq_pair_aligned(oI, oQ)) {
                return;
            }
            if (!cal.load(std::memory_order_acquire)) { return; }
            const uint32_t kH = next_prng();
            const uint32_t kL = next_prng();
            extract_and_descramble(rI, rQ, kH, kL);
            for (int i = 0; i < N; ++i) {
                oI[i] = clamp_i16(scratch_.sI[i]);
                oQ[i] = clamp_i16(sQ[i]);
            }
        }

        ~Impl() noexcept {
            prng.store(0u, std::memory_order_relaxed);
            nf_q16.store(0u, std::memory_order_relaxed);
            cal.store(false, std::memory_order_relaxed);
            std::atomic_thread_fence(std::memory_order_release);
            SecureMemory::secureWipe(static_cast<void*>(mags), sizeof(mags));
            SecureMemory::secureWipe(static_cast<void*>(&scratch_), sizeof(scratch_));
            SecureMemory::secureWipe(static_cast<void*>(sQ), sizeof(sQ));
        }
    };

    // =============================================================================
    //  컴파일 타임 크기 검증 + get_impl()
    // =============================================================================

    HTS64_Native_ECCM_Core::Impl* HTS64_Native_ECCM_Core::get_impl() noexcept {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE를 초과합니다 — 버퍼 크기를 늘려주세요");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 요구가 impl_buf_(IMPL_BUF_ALIGN)를 초과합니다");
        return impl_valid_.load(std::memory_order_acquire)
            ? reinterpret_cast<Impl*>(impl_buf_)
            : nullptr;
    }

    const HTS64_Native_ECCM_Core::Impl*
        HTS64_Native_ECCM_Core::get_impl() const noexcept {
        return impl_valid_.load(std::memory_order_acquire)
            ? reinterpret_cast<const Impl*>(impl_buf_)
            : nullptr;
    }

    // =============================================================================
    //  생성자 / 소멸자
    // =============================================================================

    HTS64_Native_ECCM_Core::HTS64_Native_ECCM_Core(uint32_t seed) noexcept
    {
        SecureMemory::secureWipe(static_cast<void*>(impl_buf_), sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl();
        impl_valid_.store(true, std::memory_order_release);

        Impl* p = get_impl();
        if (p != nullptr) {
            p->prng.store(
                (seed == 0u) ? 0xDEADBEEFu : seed,
                std::memory_order_relaxed);
        }
    }

    HTS64_Native_ECCM_Core::~HTS64_Native_ECCM_Core() noexcept {
        p_metrics_.store(nullptr, std::memory_order_release);
        Impl* p = get_impl();
        impl_valid_.store(false, std::memory_order_release);
        if (p != nullptr) { p->~Impl(); }
        SecureMemory::secureWipe(static_cast<void*>(impl_buf_), sizeof(impl_buf_));
    }

    // =============================================================================
    //  Public API
    // =============================================================================

    void HTS64_Native_ECCM_Core::Reseed(uint32_t epoch_seed) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        p->prng.store(
            (epoch_seed == 0u) ? 0xDEADBEEFu : epoch_seed,
            std::memory_order_release);
    }

    // =========================================================================
    /// @brief 노이즈 캘리브레이션 — NF IIR 필터 초기화
    ///
    /// @pre nI, nQ 배열 크기 >= N(64) * nf
    ///      함수 내부에서 포인터 산술(nI += N)로 순차 접근하므로
    ///      배열이 부족하면 OOB 읽기 발생 — 호출자가 경계 보장할 것
    ///
    /// CAS 가드: compare_exchange_strong으로 1회만 진입
    // =========================================================================
    bool HTS64_Native_ECCM_Core::Calibrate(
        const int16_t* nI, const int16_t* nQ, uint32_t nf) noexcept
    {
        Impl* p = get_impl();
        if ((p == nullptr) || (nI == nullptr) || (nQ == nullptr) || (nf == 0u)
            || !iq_pair_aligned(nI, nQ)) {
            return false;
        }

        //  nf 루프로 nI += N 반복 → 호출자가 N*nf 크기 보장 필수
        //  문제: V400은 Feed_Chip 1프레임(64칩)만 전달 → nf>1이면 OOB 즉사
        //  nf를 1로 클램프하여 단일 프레임만 처리
        //  캘리브레이션 정밀도: update_nf IIR 필터가 프레임별로 수렴 → 1프레임 충분
        if (nf > 1u) { nf = 1u; }

        bool expected = false;
        if (!p->cal.compare_exchange_strong(
            expected, true,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
            return true;
        }

        for (uint32_t f = 0u; f < nf; ++f) {
            uint32_t s = 0u;
            for (int i = 0; i < N; ++i) {
                s += fast_abs(static_cast<int32_t>(nI[i]))
                    + fast_abs(static_cast<int32_t>(nQ[i]));
            }
            p->update_nf(s >> 6u);
        }
        return true;
    }

    bool HTS64_Native_ECCM_Core::is_calibrated() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) && p->cal.load(std::memory_order_acquire);
    }

    void HTS64_Native_ECCM_Core::reset_calibration() noexcept {
        Impl* p = get_impl();
        if (p != nullptr) { p->cal.store(false, std::memory_order_release); }
    }

    int8_t HTS64_Native_ECCM_Core::Decode_BareMetal_IQ(
        const int16_t* rI, const int16_t* rQ) noexcept
    {
        Impl* p = get_impl();
        if ((p == nullptr) || (rI == nullptr) || (rQ == nullptr)
            || !iq_pair_aligned(rI, rQ)) {
            return -1;
        }
        const int8_t result = p->decode_core(rI, rQ, nullptr, nullptr, true);
        HTS_RF_Metrics* const pm =
            p_metrics_.load(std::memory_order_acquire);
        if (pm != nullptr) {
            const uint32_t nf_int =
                p->nf_q16.load(std::memory_order_relaxed) >> 16u;
            pm->ajc_nf.store(nf_int, std::memory_order_release);
        }
        return result;
    }

    int8_t HTS64_Native_ECCM_Core::Decode_Soft_IQ(
        const int16_t* rI, const int16_t* rQ,
        int32_t* fI, int32_t* fQ) noexcept
    {
        Impl* p = get_impl();
        if ((p == nullptr) || (rI == nullptr) || (rQ == nullptr)
            || (fI == nullptr) || (fQ == nullptr)
            || !iq_pair_aligned(rI, rQ) || !fwht_pair_aligned(fI, fQ)) {
            return -1;
        }
        const int8_t result = p->decode_core(rI, rQ, fI, fQ, false);
        HTS_RF_Metrics* const pm =
            p_metrics_.load(std::memory_order_acquire);
        if (pm != nullptr) {
            const uint32_t nf_int =
                p->nf_q16.load(std::memory_order_relaxed) >> 16u;
            pm->ajc_nf.store(nf_int, std::memory_order_release);
        }
        return result;
    }

    void HTS64_Native_ECCM_Core::Set_RF_Metrics(
        HTS_RF_Metrics* p) noexcept
    {
        p_metrics_.store(p, std::memory_order_release);
    }

    void HTS64_Native_ECCM_Core::Descramble_IQ(
        const int16_t* rI, const int16_t* rQ,
        int16_t* oI, int16_t* oQ) noexcept
    {
        Impl* p = get_impl();
        if ((p == nullptr) || (rI == nullptr) || (rQ == nullptr)
            || (oI == nullptr) || (oQ == nullptr)
            || !iq_pair_aligned(rI, rQ) || !iq_pair_aligned(oI, oQ)) {
            return;
        }
        p->descramble_3stage(rI, rQ, oI, oQ);
    }

} // namespace ProtectedEngine
