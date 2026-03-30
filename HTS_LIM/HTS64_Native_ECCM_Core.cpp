// =============================================================================
/// @file   HTS64_Native_ECCM_Core.cpp
/// @brief  64칩 ECCM 수신 엔진 구현
/// @target STM32F407VGT6 (Cortex-M4F, 168 MHz) / PC 시뮬레이션
///
/// @see HTS64_Native_ECCM_Core.hpp
///
/// [양산 수정 이력 — 32건]
///  BUG-01~19 (이전 세션)
///  BUG-20 [CRIT] soft_clip int64_t 나눗셈 → Q8 역수 곱셈
///  BUG-21 [HIGH] seq_cst → release × 2곳 (소거 배리어 정책 통일)
///  BUG-22 [MED]  U-A: sizeof(Impl) ≈ 1040B 경고 (BUG-32 수치 수정)
///  BUG-23 [MED]  U-B: sizeof ≤ 4096 static_assert SRAM 예산 검증
///  BUG-24 [LOW]  D-2: SecWipe MSVC volatile char→uint8_t 프로젝트 통일
///  BUG-25 [MED]  J-3: Q25/Q75 인덱스(15,47) → N 파생 constexpr
///  BUG-26 [LOW]  nth_select 가드 카운터 추가 (V400 통일, WCET 결정론)
///  BUG-27 [HIGH] N % 4 == 0 static_assert 추가
///  BUG-28 [HIGH] Calibrate() cal TOCTOU → compare_exchange_strong CAS
///  BUG-29 [MED]  extract_and_descramble 소프트 클리핑 중복 static_cast 제거
///  BUG-30 [LOW]  Calibrate() @pre Doxygen 사전조건 추가
///  BUG-31 [LOW]  PRNG 스레드 안전성 Doxygen 주석 보강
///  BUG-32 [LOW]  sizeof(Impl) Doxygen 수치 재검증 (2056B → 약 1040B)
// =============================================================================
#include "HTS64_Native_ECCM_Core.hpp"
#include "HTS_RF_Metrics.h"   // ajc_nf 기록용 (선택적)
#include <atomic>
#include <climits>
#include <cstdint>
#include <cstring>
#include <new>

static_assert(sizeof(uint32_t) == 4u, "uint32_t must be 4 bytes");
static_assert(sizeof(int16_t) == 2u, "int16_t must be 2 bytes");
static_assert(sizeof(int32_t) == 4u, "int32_t must be 4 bytes");

namespace ProtectedEngine {
    // [FIX-WIPE] 3중 방어 보안 소거 — impl_buf_ 전체 파쇄
    static void Native_ECCM_Core_Secure_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) { q[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }


    // =============================================================================
    //  모듈 상수
    // =============================================================================

    static constexpr int      N = 64;   ///< Walsh 코드 길이 (칩 수)
    static constexpr uint32_t MIN_NF = 1u;   ///< NF IIR 0-값 방어 가드
    static constexpr uint32_t CLEAN_TH = 50u;  ///< 무간섭 판별 baseline 임계

    // [BUG-27] N이 4의 배수가 아니면 Q25/Q75 인덱스 파생이 부정확해짐
    static_assert(N % 4 == 0,
        "N must be a multiple of 4 for exact Q25/Q75 index derivation");

    /// @brief Q75/Q25 비율 임계값 (CW 감지 — BUG-19)
    static constexpr uint32_t CW_RATIO_TH = 4u;

    /// @brief 32비트 argmax 안전 피크 임계값 (BUG-17)
    static constexpr int32_t ARGMAX_SAFE_PEAK = 46340;

    /// @brief Q25/Q75 인덱스 — N에서 자동 파생 (BUG-25 J-3)
    static constexpr int Q25_IDX = N / 4 - 1;       // 15 (N=64)
    static constexpr int Q75_IDX = 3 * N / 4 - 1;   // 47 (N=64)

    // =============================================================================
    //  내부 유틸리티
    // =============================================================================

    static void SecWipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        std::memset(p, 0, n);
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    static constexpr uint32_t fast_abs(int32_t x) noexcept {
        const int32_t mask = x >> 31;
        return static_cast<uint32_t>((x ^ mask) - mask);
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
    /// [BUG-26] 가드 카운터: guard = N×4 = 256 → WCET 결정론
    static uint32_t nth_select(uint32_t* a, int n, int k) noexcept {
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
    //  [BUG-31] 스레드 안전성:
    //   인스턴스당 1스레드 전용. PRNG CAS는 원자적이나 kH/kL 쌍 일관성 미보장.
    //   동일 인스턴스 동시 Decode 호출 시 키 쌍 뒤섞임 → 복호 실패.
    //   STM32 단일 스레드 환경에서는 무해.
    //
    //  [BUG-32] sizeof(Impl) ≈ 1040B
    //   mags[64]+sorted[64]+sI[64]+sQ[64]=1024B + atomic 3개 ≈ 1040B
    //   래퍼 sizeof(HTS64_Native_ECCM_Core) ≈ 2056B와 구분할 것
    // =============================================================================

    struct HTS64_Native_ECCM_Core::Impl {

        std::atomic<uint32_t> prng{ 0u };
        std::atomic<uint32_t> nf_q16{ 100u << 16u };
        std::atomic<bool>     cal{ false };

        uint32_t mags[N] = {};
        uint32_t sorted[N] = {};
        int32_t  sI[N] = {};
        int32_t  sQ[N] = {};

        // ── Lock-Free PRNG (Xorshift32) ──
        uint32_t next_prng() noexcept {
            uint32_t o = prng.load(std::memory_order_relaxed);
            uint32_t nv;
            do {
                nv = o;
                nv ^= nv << 13u;
                nv ^= nv >> 17u;
                nv ^= nv << 5u;
            } while (!prng.compare_exchange_weak(
                o, nv, std::memory_order_relaxed, std::memory_order_relaxed));
            return nv;
        }

        // ── Lock-Free NF IIR (alpha = 1/16) ──
        void update_nf(uint32_t e) noexcept {
            uint32_t o = nf_q16.load(std::memory_order_relaxed);
            uint32_t nw;
            do {
                const uint32_t decay = o - (o >> 4u);
                const uint32_t input = e << 12u;
                nw = (input > (UINT32_MAX - decay)) ? UINT32_MAX : (decay + input);
            } while (!nf_q16.compare_exchange_weak(
                o, nw, std::memory_order_relaxed, std::memory_order_relaxed));
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
                sorted[i] = mags[i];
            }

            uint32_t baseline = nth_select(sorted, N, Q25_IDX);
            if (baseline < MIN_NF) { baseline = MIN_NF; }

            uint32_t q75 = nth_select(sorted, N, Q75_IDX);
            if (q75 < baseline) { q75 = baseline; }

            const bool is_cw_like = (q75 > baseline * CW_RATIO_TH);
            const bool is_clean = (baseline < CLEAN_TH);
            const uint32_t punch = baseline << 3u;

            int32_t clip = is_cw_like
                ? static_cast<int32_t>(q75 << 2u)
                : static_cast<int32_t>(baseline << 2u);
            if (clip < 4) { clip = 4; }

            const uint32_t clip_u = static_cast<uint32_t>(clip);
            const uint32_t clip8 = clip_u << 8u;

            for (int i = 0; i < N; ++i) {
                int32_t si = static_cast<int32_t>(rI[i]);
                int32_t sq = static_cast<int32_t>(rQ[i]);

                if (!is_clean) {
                    if (mags[i] > punch) {
                        si = 0; sq = 0;
                    }
                    else if (mags[i] > clip_u) {
                        // [BUG-29] 중복 static_cast 제거
                        // si/sq는 이미 int32_t — ratio_q8만 캐스트
                        const uint32_t ratio_q8 = clip8 / mags[i];
                        const int32_t r_q8 = static_cast<int32_t>(ratio_q8);
                        si = (si * r_q8) >> 8;
                        sq = (sq * r_q8) >> 8;
                    }
                }

                if (kb(kH, kL, i)) { si = -si; sq = -sq; }
                sI[i] = si;
                sQ[i] = sq;
            }
            return baseline;
        }

        // ── NF 기반 적응형 에너지 임계 (th = nf² × N) ──
        uint64_t adaptive_threshold() const noexcept {
            uint32_t nf = nf_q16.load(std::memory_order_relaxed) >> 16u;
            if (nf < MIN_NF) { nf = MIN_NF; }
            return static_cast<uint64_t>(nf)
                * static_cast<uint64_t>(nf)
                * static_cast<uint64_t>(N);
        }

        // =========================================================================
        /// @brief 디코드 공통 코어 (Hard/Soft 공용)
        // =========================================================================
        int8_t decode_core(const int16_t* rI, const int16_t* rQ,
            int32_t* fI, int32_t* fQ, bool hard) noexcept {
            if (!cal.load(std::memory_order_acquire)) { return -1; }

            const uint32_t kH = next_prng();
            const uint32_t kL = next_prng();

            const uint32_t baseline = extract_and_descramble(rI, rQ, kH, kL);
            update_nf(baseline);

            FWHT(sI);
            FWHT(sQ);

            if (!hard && (fI != nullptr) && (fQ != nullptr)) {
                for (int i = 0; i < N; ++i) { fI[i] = sI[i]; fQ[i] = sQ[i]; }
            }

            // Step 1: 피크 탐색 → 적응형 시프트 결정
            uint32_t peak = 0u;
            for (int m = 0; m < N; ++m) {
                const uint32_t a = fast_abs(sI[m]);
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
                const int32_t  si_s = sI[m] >> shift;
                const int32_t  sq_s = sQ[m] >> shift;
                const uint32_t e = static_cast<uint32_t>(si_s * si_s)
                    + static_cast<uint32_t>(sq_s * sq_s);
                if (e > best_scaled) { best_scaled = e; dec = static_cast<uint8_t>(m); }
            }

            // Step 3: 최선 빈 1회 64비트 임계값 비교
            if (dec == 0xFFu) { return -1; }
            const uint64_t best_actual =
                static_cast<uint64_t>(
                    static_cast<int64_t>(sI[dec]) * sI[dec]
                    + static_cast<int64_t>(sQ[dec]) * sQ[dec]);
            const uint64_t th = adaptive_threshold();
            return (best_actual < th) ? static_cast<int8_t>(-1)
                : static_cast<int8_t>(dec);
        }

        // ── 스크램블 해제 전용 (FWHT 생략) ──
        void descramble_3stage(const int16_t* rI, const int16_t* rQ,
            int16_t* oI, int16_t* oQ) noexcept {
            if (!cal.load(std::memory_order_acquire)) { return; }
            const uint32_t kH = next_prng();
            const uint32_t kL = next_prng();
            extract_and_descramble(rI, rQ, kH, kL);
            for (int i = 0; i < N; ++i) {
                oI[i] = clamp_i16(sI[i]);
                oQ[i] = clamp_i16(sQ[i]);
            }
        }

        ~Impl() noexcept {
            prng.store(0u, std::memory_order_relaxed);
            nf_q16.store(0u, std::memory_order_relaxed);
            cal.store(false, std::memory_order_relaxed);
            std::atomic_thread_fence(std::memory_order_release);
            SecWipe(mags, sizeof(mags));
            SecWipe(sorted, sizeof(sorted));
            SecWipe(sI, sizeof(sI));
            SecWipe(sQ, sizeof(sQ));
        }
    };

    // =============================================================================
    //  컴파일 타임 크기 검증 + get_impl()
    // =============================================================================

    HTS64_Native_ECCM_Core::Impl* HTS64_Native_ECCM_Core::get_impl() noexcept {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE를 초과합니다 — 버퍼 크기를 늘려주세요");
        static_assert(alignof(Impl) <= 8u,
            "Impl 정렬 요구가 impl_buf_의 alignas(8)를 초과합니다");
        return impl_valid_ ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }

    const HTS64_Native_ECCM_Core::Impl*
        HTS64_Native_ECCM_Core::get_impl() const noexcept {
        return impl_valid_
            ? reinterpret_cast<const Impl*>(impl_buf_)
            : nullptr;
    }

    // =============================================================================
    //  생성자 / 소멸자
    // =============================================================================

    HTS64_Native_ECCM_Core::HTS64_Native_ECCM_Core(uint32_t seed) noexcept
        : impl_valid_(false)
    {
        SecWipe(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl();
        impl_valid_ = true;

        Impl* p = get_impl();
        if (p != nullptr) {
            p->prng.store(
                (seed == 0u) ? 0xDEADBEEFu : seed,
                std::memory_order_relaxed);
        }
    }

    HTS64_Native_ECCM_Core::~HTS64_Native_ECCM_Core() noexcept {
        Impl* p = get_impl();
        if (p != nullptr) {
            p->~Impl();
            // [FIX-WIPE] impl_buf_ 전체 3중 방어 소거
            Native_ECCM_Core_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
        }
        SecWipe(impl_buf_, sizeof(impl_buf_));
        impl_valid_ = false;
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
    /// [BUG-28] CAS 가드: compare_exchange_strong으로 1회만 진입
    // =========================================================================
    bool HTS64_Native_ECCM_Core::Calibrate(
        const int16_t* nI, const int16_t* nQ, uint32_t nf) noexcept
    {
        Impl* p = get_impl();
        if ((p == nullptr) || (nI == nullptr) || (nQ == nullptr) || (nf == 0u)) {
            return false;
        }

        // [BUG-28] CAS: 이미 완료 또는 다른 스레드 진행 중이면 즉시 반환
        bool expected = false;
        if (!p->cal.compare_exchange_strong(
            expected, true,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
            return true;  // expected == true → 이미 캘리브레이션 완료
        }

        // CAS 성공: cal=true 선점. 이 스레드만 캘리브레이션 수행
        for (uint32_t f = 0u; f < nf; ++f) {
            uint32_t s = 0u;
            for (int i = 0; i < N; ++i) {
                s += fast_abs(static_cast<int32_t>(nI[i]))
                    + fast_abs(static_cast<int32_t>(nQ[i]));
            }
            p->update_nf(s >> 6u);
            nI += N;
            nQ += N;
        }
        // cal은 CAS에서 이미 true — 추가 store 불필요
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
        if ((p == nullptr) || (rI == nullptr) || (rQ == nullptr)) { return -1; }
        const int8_t result = p->decode_core(rI, rQ, nullptr, nullptr, true);
        if (p_metrics_ != nullptr) {
            const uint32_t nf_int =
                p->nf_q16.load(std::memory_order_relaxed) >> 16u;
            p_metrics_->ajc_nf.store(nf_int, std::memory_order_release);
        }
        return result;
    }

    int8_t HTS64_Native_ECCM_Core::Decode_Soft_IQ(
        const int16_t* rI, const int16_t* rQ,
        int32_t* fI, int32_t* fQ) noexcept
    {
        Impl* p = get_impl();
        if ((p == nullptr) || (rI == nullptr) || (rQ == nullptr)
            || (fI == nullptr) || (fQ == nullptr)) {
            return -1;
        }
        const int8_t result = p->decode_core(rI, rQ, fI, fQ, false);
        if (p_metrics_ != nullptr) {
            const uint32_t nf_int =
                p->nf_q16.load(std::memory_order_relaxed) >> 16u;
            p_metrics_->ajc_nf.store(nf_int, std::memory_order_release);
        }
        return result;
    }

    void HTS64_Native_ECCM_Core::Set_RF_Metrics(
        HTS_RF_Metrics* p) noexcept
    {
        p_metrics_ = p;
    }

    void HTS64_Native_ECCM_Core::Descramble_IQ(
        const int16_t* rI, const int16_t* rQ,
        int16_t* oI, int16_t* oQ) noexcept
    {
        Impl* p = get_impl();
        if ((p == nullptr) || (rI == nullptr) || (rQ == nullptr)
            || (oI == nullptr) || (oQ == nullptr)) {
            return;
        }
        p->descramble_3stage(rI, rQ, oI, oQ);
    }

} // namespace ProtectedEngine