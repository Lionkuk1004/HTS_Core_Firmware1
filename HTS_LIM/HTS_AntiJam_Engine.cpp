// =========================================================================
// HTS_AntiJam_Engine.cpp — 3층 통합 항재밍 엔진
// Target: STM32F407 (Cortex-M4F, 168MHz, SRAM 192KB)
//
//  1층) AJC: 판정 귀환 간섭 제거 (정상성 게이팅 포함)
//  2층) Adaptive Punch: 돌출 칩 0 처리 (Clip 없음)
//  3층) Spatial Null: 16칩 서브밴드 투영 제거
//
// [제약] float 0, double 0, 나눗셈 0, try-catch 0, 힙 0
// =========================================================================
#include "HTS_AntiJam_Engine.h"
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace ProtectedEngine {

    namespace {

        /// Cortex-M4F: 단일 SSAT(16). PC·기타 타깃은 동일 산술(콜드 폴백).
        static inline int16_t ssat_i16_(int32_t v) noexcept {
#if defined(__GNUC__) && defined(__ARM_ARCH) && (__ARM_ARCH >= 6)
            return static_cast<int16_t>(__builtin_arm_ssat(v, 16));
#else
            if (v > 32767) { v = 32767; }
            else if (v < -32768) { v = -32768; }
            return static_cast<int16_t>(v);
#endif
        }

        /// HTS64_Native_ECCM_Core::sort_u32_constant_time_adjacent 와 동일 —
        /// N=64 고정, 63×64/2=2016회 인접 비교(데이터 종속 분기 없음).
        static constexpr int kSortN = 64;
        static_assert(
            static_cast<size_t>(kSortN) * static_cast<size_t>(kSortN - 1) / 2u
                == 2016u,
            "constant-time adjacent sort trip count");

        static void sort_u32_ct_adjacent_64(uint32_t* a) noexcept {
            if (a == nullptr) { return; }
            for (int pass = 0; pass < kSortN - 1; ++pass) {
                const int imax = kSortN - 1 - pass;
                for (int i = 0; i < imax; ++i) {
                    const uint32_t x = a[i];
                    const uint32_t y = a[i + 1];
                    const uint32_t gt = static_cast<uint32_t>(x > y);
                    const uint32_t m = 0u - gt;
                    a[i]     = (x & ~m) | (y & m);
                    a[i + 1] = (y & ~m) | (x & m);
                }
            }
        }

        static void fill_sort_work_pad_(
            uint32_t* work, const uint32_t* src, int nc) noexcept {
            for (int i = 0; i < nc; ++i) {
                work[i] = src[static_cast<size_t>(i)];
            }
            for (int i = nc; i < kSortN; ++i) {
                work[i] = 0xFFFFFFFFu;
            }
        }
        // LTO/DCE에 memset이 제거되지 않도록 volatile 스토어 + 배리어
        // (jprof_/SubNull: 세션 간 간섭 프로파일 잔존 방지)
        void AntiJam_Secure_Wipe(void* ptr, size_t size) noexcept {
            if (ptr == nullptr || size == 0u) { return; }
            volatile unsigned char* p =
                static_cast<volatile unsigned char*>(ptr);
            for (size_t i = 0u; i < size; ++i) { p[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
            std::atomic_thread_fence(std::memory_order_release);
        }
    } // namespace

    // ── Q8 사인파 LUT (cw_cancel_64_()와 동일 — 일관성 유지) ──
    // sin(2π×k/8)×256, k=0..7
    static constexpr int16_t k_cw_lut8[8] = {
        0, 181, 256, 181, 0, -181, -256, -181
    };

    int AntiJamEngine::clz32_(uint32_t x) noexcept {
        if (x == 0u) return 32;
#if defined(__GNUC__) || defined(__clang__)
        return __builtin_clz(x);
#else
        int n = 0;
        if (x <= 0x0000FFFFu) { n += 16; x <<= 16; }
        if (x <= 0x00FFFFFFu) { n += 8; x <<= 8; }
        if (x <= 0x0FFFFFFFu) { n += 4; x <<= 4; }
        if (x <= 0x3FFFFFFFu) { n += 2; x <<= 2; }
        if (x <= 0x7FFFFFFFu) { n += 1; }
        return n;
#endif
    }

    static inline int32_t clamp_i32_(int64_t v) noexcept {
        if (v > 2147483647LL) return 2147483647;
        if (v < -2147483648LL) return -2147483648LL;
        return static_cast<int32_t>(v);
    }

    // =====================================================================
    //  생성자 / Reset
    // =====================================================================
    AntiJamEngine::AntiJamEngine() noexcept
        : mismatch_ema_(0u), update_count_(0u),
        ajc_reliable_(false), barrage_bypass_(false), num_subs_(0)
    {
        Reset(16);
    }

    void AntiJamEngine::Reset(int nc) noexcept {
        AntiJam_Secure_Wipe(jprof_I_, sizeof(jprof_I_));
        AntiJam_Secure_Wipe(jprof_Q_, sizeof(jprof_Q_));
        mismatch_ema_ = 0u;
        ajc_reliable_ = false;
        barrage_bypass_ = false;
        update_count_ = 0u;

        num_subs_ = (nc <= SUB_NC) ? 1 : (nc >> 4);
        if (num_subs_ > MAX_SUBS) num_subs_ = MAX_SUBS;
        for (int s = 0; s < MAX_SUBS; ++s) {
            AntiJam_Secure_Wipe(&subs_[s], sizeof(SubNull));
            for (int i = 0; i < SUB_NC; ++i)
                subs_[s].eigvec[i] = 1024;
            subs_[s].count = 0;
            subs_[s].active = false;
        }
        AntiJam_Secure_Wipe(null_cov_, sizeof(null_cov_));
        AntiJam_Secure_Wipe(null_v_, sizeof(null_v_));
        AntiJam_Secure_Wipe(null_nv_, sizeof(null_nv_));
    }

    void AntiJamEngine::Set_AdaptiveBarrageBypass(bool on) noexcept {
        barrage_bypass_ = on;
    }

    // =====================================================================
    //
    //  [동작 원리]
    //   cw_cancel_64_()가 상관 연산으로 추정한 ja_I, ja_Q를 받아서
    //   64칩 전체의 CW 파형을 LUT로 재구성하고 jprof_[]에 직접 기록합니다.
    //
    //  [스케일 일치]
    //   ajc_apply_()는 jprof_[i] >> EMA_SHIFT(4)를 간섭 추정값으로 사용합니다.
    //   따라서 jprof_에 저장할 때 실제값을 EMA_SHIFT만큼 좌시프트해야
    //   ajc_apply_()가 꺼낼 때 정확한 CW 값이 나옵니다.
    //
    //   CW 파형:  cw[i] = (ja × lut[i%8]) >> 8   (Q8 역정규화)
    //   저장값:   jprof_[i] = cw[i] << EMA_SHIFT
    //   꺼낼 때:  jprof_[i] >> EMA_SHIFT = cw[i]  → 수치 오차 없음
    //
    //  [STATIONARITY 해소]
    //   mismatch_ema_를 낮은 값으로 초기화해서 ajc_reliable_ = true를
    //   즉시 확보합니다. 이후 Update_AJC()가 실제 mismatch를 반영하면서
    //   자연스럽게 수렴합니다.
    //
    //  [오버플로 증명]
    //   ja 최대 = 65,534 (corr_max >> 13)
    //   lut 최대 = 256
    //   (ja × lut) >> 8 최대 = (65534 × 256) >> 8 = 65,534 < INT32_MAX
    //   cw[i] << EMA_SHIFT 최대 = 65534 × 16 = 1,048,544 < INT32_MAX ✓
    // =====================================================================
    void AntiJamEngine::Seed_CW_Profile(int32_t ja_I, int32_t ja_Q) noexcept {
        // 64칩 CW 파형을 LUT로 재구성하여 jprof_[]에 직접 대입
        // is_preamble=true 방식과 동일한 스케일: pure_J << EMA_SHIFT
        for (int i = 0; i < MAX_NC; ++i) {
            const int32_t lut = static_cast<int32_t>(k_cw_lut8[i & 7u]);

            // Q8 역정규화: (ja × lut) >> 8 = 실제 CW 진폭
            const int32_t cw_I = clamp_i32_(
                (static_cast<int64_t>(ja_I) * static_cast<int64_t>(lut)) >> 8);
            const int32_t cw_Q = clamp_i32_(
                (static_cast<int64_t>(ja_Q) * static_cast<int64_t>(lut)) >> 8);

            // EMA 스케일로 저장 (ajc_apply_가 >>EMA_SHIFT로 꺼냄)
            // 비정상 입력(EMI/비트플립) 대비: 좌시프트도 포화(clamp) 저장
            jprof_I_[i] = clamp_i32_(
                static_cast<int64_t>(cw_I) << EMA_SHIFT);
            jprof_Q_[i] = clamp_i32_(
                static_cast<int64_t>(cw_Q) << EMA_SHIFT);
        }

        // mismatch_ema_ 재초기화
        // STATIONARITY_TH=3000, 판단식: mismatch_ema_ >> 2 > TH
        // → mismatch_ema_ < TH × 4 = 12000 이면 ajc_reliable_ = true
        // 1000으로 설정하여 즉시 신뢰 상태 확보
        mismatch_ema_ = 1000u;

        // AJC 즉시 활성화 — 첫 심볼부터 CW 제거 작동
        ajc_reliable_ = true;

        // 고속 수렴 단계 스킵 (이미 좋은 초기값을 가지고 있음)
        update_count_ = FAST_PHASE;
    }

    // =====================================================================
    //  [1층] AJC Apply — 정상성 게이팅 포함
    // =====================================================================
    void AntiJamEngine::ajc_apply_(int16_t* I, int16_t* Q, int nc) noexcept {
        if (!ajc_reliable_) return;

        for (int i = 0; i < nc; ++i) {
            const int32_t ci = static_cast<int32_t>(I[i]) -
                (jprof_I_[i] >> EMA_SHIFT);
            const int32_t cq = static_cast<int32_t>(Q[i]) -
                (jprof_Q_[i] >> EMA_SHIFT);
            I[i] = ssat_i16_(ci);
            Q[i] = ssat_i16_(cq);
        }
    }

    // =====================================================================
    //  [2층] Adaptive Hole Punch
    // =====================================================================
    void AntiJamEngine::adaptive_punch_(int16_t* I, int16_t* Q, int nc) noexcept {
        if (nc > MAX_NC) return;
        uint32_t* const mags = sort_nc_scratch_;
        uint32_t* const work = sort_u64_work_;
        for (int i = 0; i < nc; ++i) {
            mags[i] = fast_abs_(static_cast<int32_t>(I[i])) +
                fast_abs_(static_cast<int32_t>(Q[i]));
        }
        fill_sort_work_pad_(work, mags, nc);
        sort_u32_ct_adjacent_64(work);
        int q25 = nc >> 2;
        if (q25 < 1) q25 = 1;
        uint32_t bl = work[q25 - 1];
        if (bl < 1u) bl = 1u;
        if (bl < 50u || bl > 2000u) return;

        uint32_t max_mag = 0u;
        for (int i = 0; i < nc; ++i)
            if (mags[i] > max_mag) max_mag = mags[i];

        uint32_t K;
        if (max_mag > bl * 20u) K = 4u;
        else if (max_mag > bl * 5u) K = 8u;
        else                         K = 16u;

        const uint32_t punch = bl * K;
        for (int i = 0; i < nc; ++i) {
            if (mags[i] > punch) { I[i] = 0; Q[i] = 0; }
        }
    }

    // =====================================================================
    //  [3층] Spatial Null
    // =====================================================================
    void AntiJamEngine::null_accumulate_sub_(SubNull& s,
        const int16_t* I, const int16_t* Q) noexcept {
        const int slot = s.count & (MAX_ACC - 1);
        for (int i = 0; i < SUB_NC; ++i) {
            const int32_t vi = static_cast<int32_t>(I[i]);
            const int32_t vq = static_cast<int32_t>(Q[i]);
            const int32_t si = ((vi >> 31) << 1) + 1;
            const int32_t sq = ((vq >> 31) << 1) + 1;
            s.signs_I[slot][i] = static_cast<int8_t>(si);
            s.signs_Q[slot][i] = static_cast<int8_t>(sq);
        }
        s.count++;
        const int K = (s.count < MAX_ACC) ? s.count : MAX_ACC;
        if (K < MIN_ACC) { s.active = false; return; }

        AntiJam_Secure_Wipe(null_cov_, sizeof(null_cov_));
        for (int k = 0; k < K; ++k)
            for (int i = 0; i < SUB_NC; ++i)
                for (int j = i; j < SUB_NC; ++j) {
                    const int32_t vv_ij =
                        static_cast<int32_t>(s.signs_I[k][i]) *
                            static_cast<int32_t>(s.signs_I[k][j]) +
                        static_cast<int32_t>(s.signs_Q[k][i]) *
                            static_cast<int32_t>(s.signs_Q[k][j]);
                    null_cov_[i][j] += vv_ij;
                    if (i != j) null_cov_[j][i] += vv_ij;
                }

        for (int i = 0; i < SUB_NC; ++i) {
            null_v_[i] = s.eigvec[i];
        }

        for (int iter = 0; iter < PWR_ITER; ++iter) {
            for (int i = 0; i < SUB_NC; ++i) {
                null_nv_[i] = 0;
            }
            for (int i = 0; i < SUB_NC; ++i)
                for (int j = 0; j < SUB_NC; ++j)
                    null_nv_[i] += null_cov_[i][j] * null_v_[j];

            uint32_t ma = 1u;
            for (int i = 0; i < SUB_NC; ++i) {
                uint32_t a = fast_abs_(null_nv_[i]);
                if (a > ma) ma = a;
            }
            const int sh = (31 - clz32_(ma)) - 10;
            if (sh > 0) {
                for (int i = 0; i < SUB_NC; ++i) {
                    null_v_[i] = null_nv_[i] >> sh;
                }
            }
            else if (sh < 0) {
                for (int i = 0; i < SUB_NC; ++i) {
                    null_v_[i] = null_nv_[i] << -sh;
                }
            }
            else {
                for (int i = 0; i < SUB_NC; ++i) {
                    null_v_[i] = null_nv_[i];
                }
            }
        }

        int64_t vCv = 0, vv = 0;
        for (int i = 0; i < SUB_NC; ++i) {
            int32_t Cv = 0;
            for (int j = 0; j < SUB_NC; ++j) {
                Cv += null_cov_[i][j] * null_v_[j];
            }
            vCv += static_cast<int64_t>(null_v_[i]) * static_cast<int64_t>(Cv);
            vv += static_cast<int64_t>(null_v_[i]) * static_cast<int64_t>(null_v_[i]);
        }
        s.active = (vv > 0) &&
            (vCv > static_cast<int64_t>(K) * 4 * vv);
        for (int i = 0; i < SUB_NC; ++i) {
            s.eigvec[i] = null_v_[i];
        }
    }

    void AntiJamEngine::null_apply_sub_(const SubNull& s,
        int16_t* I, int16_t* Q) noexcept {
        if (!s.active) return;
        int32_t vdv = 0;
        for (int i = 0; i < SUB_NC; ++i) vdv += s.eigvec[i] * s.eigvec[i];
        if (vdv <= 0) return;
        const int bits = 31 - clz32_(static_cast<uint32_t>(vdv));

        for (int ch = 0; ch < 2; ++ch) {
            int16_t* d = (ch == 0) ? I : Q;
            int64_t proj = 0;
            for (int i = 0; i < SUB_NC; ++i)
                proj += static_cast<int64_t>(s.eigvec[i]) *
                    static_cast<int64_t>(d[i]);
            for (int i = 0; i < SUB_NC; ++i) {
                const int32_t c = static_cast<int32_t>(d[i]) -
                    static_cast<int32_t>(
                        (proj * static_cast<int64_t>(s.eigvec[i])) >> bits);
                d[i] = ssat_i16_(c);
            }
        }
    }

    // =====================================================================
    //  Adaptive Bypass — 블록 단위 스캔 (힙·부동·가변 나눗셈 없음)
    //
    //  ajc_reliable_==false (바라지·미학습): 극단 포화(|I|+|Q|)만 구조적 타격으로
    //  간주 → 그 외는 3층 미가동(Bypass). ajc_reliable_==true(CW 시딩 등)는 스캔 생략.
    // =====================================================================
    void AntiJamEngine::reset_spatial_null_only_() noexcept {
        for (int s = 0; s < MAX_SUBS; ++s) {
            AntiJam_Secure_Wipe(&subs_[s], sizeof(SubNull));
            for (int i = 0; i < SUB_NC; ++i)
                subs_[s].eigvec[i] = 1024;
            subs_[s].count = 0;
            subs_[s].active = false;
        }
        AntiJam_Secure_Wipe(null_cov_, sizeof(null_cov_));
        AntiJam_Secure_Wipe(null_v_, sizeof(null_v_));
        AntiJam_Secure_Wipe(null_nv_, sizeof(null_nv_));
    }

    bool AntiJamEngine::block_looks_impulsive_nc_(
        const int16_t* I, const int16_t* Q, int nc) noexcept
    {
        if (!I || !Q || nc <= 0 || nc > MAX_NC) return false;

        uint32_t* const wq = sort_nc_scratch_;
        uint32_t* const wmed = sort_u64_work_;
        uint32_t maxv = 0u;
        uint64_t sum_m = 0u;
        unsigned hot_chips = 0u;
        unsigned above_halfmax = 0u;

        static constexpr uint32_t k_hot_chip = 26000u;
        for (int i = 0; i < nc; ++i) {
            const uint32_t m = fast_abs_(static_cast<int32_t>(I[i]))
                + fast_abs_(static_cast<int32_t>(Q[i]));
            wq[static_cast<size_t>(i)] = m;
            sum_m += static_cast<uint64_t>(m);
            if (m > maxv) maxv = m;
            if (m >= k_hot_chip) ++hot_chips;
        }

        // 다수 칩이 동시에 고전력 → 광대역 클리핑/바라지형 플로어 (단일 EMP 스파이크 아님)
        static constexpr unsigned k_hot_many = 12u;
        if (hot_chips >= k_hot_many) return false;

        // 최대 진폭의 절반 이상인 칩이 많으면 ‘넓게 퍼진 상단 에너지’(바라지)로 간주
        // (단일/소수 칩 스파이크 EMP는 max/2 초과가 소수개 → 통과)
        if (maxv >= 1u) {
            const uint32_t halfmax = maxv >> 1;
            for (int i = 0; i < nc; ++i) {
                const uint32_t m = wq[static_cast<size_t>(i)];
                if (m > halfmax) ++above_halfmax;
            }
        }
        static constexpr unsigned k_many_above_half = 10u;
        if (above_halfmax >= k_many_above_half) return false;

        fill_sort_work_pad_(wmed, wq, nc);
        sort_u32_ct_adjacent_64(wmed);

        int q25 = nc >> 2;
        if (q25 < 1) q25 = 1;
        uint32_t bl = wmed[q25 - 1];
        if (bl < 1u) bl = 1u;
        if (bl < 50u || bl > 2000u) return false;

        const int k_med = (nc >> 1) - 1;
        const int k_idx = (k_med >= 0) ? k_med : 0;
        uint32_t med = wmed[k_idx];
        if (med < 1u) med = 1u;

        static constexpr uint32_t k_near_sat = 31000u;
        if (maxv < k_near_sat) return false;

        // 크레스트 팩터(PAPR 근사): max×N > k×sum → 피크가 블록 평균 에너지를 지배
        // 바라지에서 우발적 1칩 포화 + 나머지 양호 시 sum이 커져 바이패스
        static constexpr uint32_t k_crest_q = 5u;
        {
            const uint64_t lhs =
                static_cast<uint64_t>(maxv) * static_cast<uint64_t>(static_cast<uint32_t>(nc));
            const uint64_t rhs = sum_m * static_cast<uint64_t>(k_crest_q);
            if (lhs <= rhs) return false;
        }

        // 중앙값이 이미 올라간 블록은 ‘고른 플로어 상승’에 가깝다 → 바이패스
        static constexpr uint32_t k_quiet_median = 10000u;
        static constexpr uint32_t k_peak_over_median = 8u;
        return (maxv > med * k_peak_over_median) && (med < k_quiet_median);
    }

    // =====================================================================
    //  Process — 3층 전체 적용 (광대역 바라지 시 Adaptive Bypass)
    // =====================================================================
    void AntiJamEngine::Process(int16_t* I, int16_t* Q, int nc) noexcept {
        if (!I || !Q || nc <= 0 || nc > MAX_NC) return;
        if (!ajc_reliable_) {
            if (barrage_bypass_ || !block_looks_impulsive_nc_(I, Q, nc)) {
                reset_spatial_null_only_();
                return;
            }
        }
        ajc_apply_(I, Q, nc);
        adaptive_punch_(I, Q, nc);
        const int nsub = (nc <= SUB_NC) ? 1 : (nc >> 4);
        for (int s = 0; s < nsub && s < MAX_SUBS; ++s) {
            null_accumulate_sub_(subs_[s], I + s * SUB_NC, Q + s * SUB_NC);
            null_apply_sub_(subs_[s], I + s * SUB_NC, Q + s * SUB_NC);
        }
    }

    // =====================================================================
    //  Update_AJC — 판정 귀환 + 정상성 게이팅 (기존 코드 유지)
    // =====================================================================
    void AntiJamEngine::Update_AJC(const int16_t* orig_I,
        const int16_t* orig_Q,
        int8_t sym, uint32_t best_e, uint32_t second_e,
        int nc, bool is_preamble) noexcept {
        if (!orig_I || !orig_Q) return;
        if (nc <= 0 || nc > MAX_NC) return;

        bool confident = is_preamble;
        if (!confident) {
            confident = (second_e <= (0xFFFFFFFFu / 3u))
                && (best_e > second_e * 3u);
        }
        if (!confident) return;
        if (sym < 0 || sym >= nc) return;

        const uint32_t sym_u = static_cast<uint32_t>(sym);

        int32_t corr_I = 0, corr_Q = 0;
        for (int i = 0; i < nc; ++i) {
            int32_t w = (popc32_(sym_u & static_cast<uint32_t>(i)) & 1u)
                ? -1 : 1;
            corr_I += static_cast<int32_t>(orig_I[i]) * w;
            corr_Q += static_cast<int32_t>(orig_Q[i]) * w;
        }
        const int nc_shift =
            (nc <= 1) ? 0 : (31 - clz32_(static_cast<uint32_t>(nc)));

        //  I/Q 각각 corr/N 스케일 — 합산 평균으로 위상 왜곡 방지
        const int32_t amp_I = corr_I >> nc_shift;  // I축 진폭 (부호 보존)
        const int32_t amp_Q = corr_Q >> nc_shift;  // Q축 진폭 (부호 보존)

        uint32_t mismatch_sum = 0u;
        for (int i = 0; i < nc; ++i) {
            int32_t w = (popc32_(sym_u & static_cast<uint32_t>(i)) & 1u)
                ? -1 : 1;
            const int32_t my_sig_I = amp_I * w;
            const int32_t my_sig_Q = amp_Q * w;
            const int32_t pure_J_I = static_cast<int32_t>(orig_I[i]) - my_sig_I;
            const int32_t pure_J_Q = static_cast<int32_t>(orig_Q[i]) - my_sig_Q;
            const int32_t pred_J_I = jprof_I_[i] >> EMA_SHIFT;
            const int32_t pred_J_Q = jprof_Q_[i] >> EMA_SHIFT;
            mismatch_sum += fast_abs_(pure_J_I - pred_J_I)
                + fast_abs_(pure_J_Q - pred_J_Q);
        }
        uint32_t mismatch = mismatch_sum >> nc_shift;

        mismatch_ema_ = mismatch_ema_ - (mismatch_ema_ >> 2u) + mismatch;
        uint32_t ema_avg = mismatch_ema_ >> 2u;

        if (is_preamble) {
            ajc_reliable_ = true;
        }
        else if (ema_avg > STATIONARITY_TH) {
            ajc_reliable_ = false;
            return;
        }
        else {
            ajc_reliable_ = true;
        }

        for (int i = 0; i < nc; ++i) {
            int32_t w = (popc32_(sym_u & static_cast<uint32_t>(i)) & 1u)
                ? -1 : 1;
            const int32_t my_sig_I = amp_I * w;
            const int32_t my_sig_Q = amp_Q * w;
            const int32_t pure_J_I = static_cast<int32_t>(orig_I[i]) - my_sig_I;
            const int32_t pure_J_Q = static_cast<int32_t>(orig_Q[i]) - my_sig_Q;

            if (is_preamble) {
                jprof_I_[i] = pure_J_I << EMA_SHIFT;
                jprof_Q_[i] = pure_J_Q << EMA_SHIFT;
            }
            else {
                jprof_I_[i] += pure_J_I - (jprof_I_[i] >> EMA_SHIFT);
                jprof_Q_[i] += pure_J_Q - (jprof_Q_[i] >> EMA_SHIFT);
            }
        }
    }

} // namespace ProtectedEngine
