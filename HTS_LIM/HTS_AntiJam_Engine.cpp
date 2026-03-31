// =========================================================================
// HTS_AntiJam_Engine.cpp — 3층 통합 항재밍 엔진
// Target: STM32F407 (Cortex-M4F, 168MHz, SRAM 192KB)
//
//  1층) AJC: 판정 귀환 간섭 제거 (정상성 게이팅 포함)
//  2층) Adaptive Punch: 돌출 칩 0 처리 (Clip 없음)
//  3층) Spatial Null: 16칩 서브밴드 투영 제거
//
//  [세션 10 수정]
//   BUG-44 [CRIT] Seed_CW_Profile() 구현
//          cw_cancel_64_()의 ja_I/ja_Q를 jprof_[]에 직접 주입
//          CW 17~19dB 닭-달걀 문제 완전 해소
//
// [제약] float 0, double 0, 나눗셈 0, try-catch 0, 힙 0
// =========================================================================
#include "HTS_AntiJam_Engine.h"
#include <cstring>
#include <atomic>

namespace ProtectedEngine {

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

    static void swap_u32(uint32_t& a, uint32_t& b) noexcept {
        uint32_t t = a; a = b; b = t;
    }

    uint32_t AntiJamEngine::nth_select_(uint32_t* a, int n, int k) noexcept {
        int lo = 0, hi = n - 1;
        while (lo < hi) {
            int mid = lo + ((hi - lo) >> 1);
            if (a[mid] < a[lo]) swap_u32(a[lo], a[mid]);
            if (a[hi] < a[lo]) swap_u32(a[lo], a[hi]);
            if (a[mid] < a[hi]) swap_u32(a[mid], a[hi]);
            uint32_t pivot = a[hi];
            int store = lo;
            for (int i = lo; i < hi; ++i) {
                if (a[i] < pivot) { swap_u32(a[store], a[i]); ++store; }
            }
            swap_u32(a[store], a[hi]);
            if (store == k) return a[store];
            if (store < k) lo = store + 1;
            else            hi = store - 1;
        }
        return a[lo];
    }

    // =====================================================================
    //  생성자 / Reset
    // =====================================================================
    AntiJamEngine::AntiJamEngine() noexcept
        : mismatch_ema_(0u), ajc_reliable_(false),
        update_count_(0u), num_subs_(0)
    {
        Reset(16);
    }

    void AntiJamEngine::Reset(int nc) noexcept {
        std::memset(jprof_I_, 0, sizeof(jprof_I_));
        std::memset(jprof_Q_, 0, sizeof(jprof_Q_));
        mismatch_ema_ = 0u;
        ajc_reliable_ = false;
        update_count_ = 0u;

        num_subs_ = (nc <= SUB_NC) ? 1 : (nc >> 4);
        if (num_subs_ > MAX_SUBS) num_subs_ = MAX_SUBS;
        for (int s = 0; s < MAX_SUBS; ++s) {
            std::memset(&subs_[s], 0, sizeof(SubNull));
            for (int i = 0; i < SUB_NC; ++i)
                subs_[s].eigvec[i] = 1024;
            subs_[s].count = 0;
            subs_[s].active = false;
        }
    }

    // =====================================================================
    //  [BUG-44] Seed_CW_Profile — CW 프로파일 직접 시딩
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
            const int32_t cw_I = (ja_I * lut) >> 8;
            const int32_t cw_Q = (ja_Q * lut) >> 8;

            // EMA 스케일로 저장 (ajc_apply_가 >>EMA_SHIFT로 꺼냄)
            jprof_I_[i] = cw_I << EMA_SHIFT;
            jprof_Q_[i] = cw_Q << EMA_SHIFT;
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
            int32_t ci = static_cast<int32_t>(I[i]) -
                (jprof_I_[i] >> EMA_SHIFT);
            int32_t cq = static_cast<int32_t>(Q[i]) -
                (jprof_Q_[i] >> EMA_SHIFT);
            if (ci > 32767) ci = 32767;
            else if (ci < -32768) ci = -32768;
            if (cq > 32767) cq = 32767;
            else if (cq < -32768) cq = -32768;
            I[i] = static_cast<int16_t>(ci);
            Q[i] = static_cast<int16_t>(cq);
        }
    }

    // =====================================================================
    //  [2층] Adaptive Hole Punch
    // =====================================================================
    void AntiJamEngine::adaptive_punch_(int16_t* I, int16_t* Q, int nc) noexcept {
        if (nc > MAX_NC) return;
        uint32_t mags[MAX_NC] = {}, sorted[MAX_NC] = {};
        for (int i = 0; i < nc; ++i) {
            mags[i] = fast_abs_(static_cast<int32_t>(I[i])) +
                fast_abs_(static_cast<int32_t>(Q[i]));
            sorted[i] = mags[i];
        }
        int q25 = nc >> 2;
        if (q25 < 1) q25 = 1;
        uint32_t bl = nth_select_(sorted, nc, q25 - 1);
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
        const int slot = (s.count < MAX_ACC) ? s.count : (s.count % MAX_ACC);
        for (int i = 0; i < SUB_NC; ++i) {
            s.signs_I[slot][i] = (I[i] >= 0) ? int8_t(1) : int8_t(-1);
            s.signs_Q[slot][i] = (Q[i] >= 0) ? int8_t(1) : int8_t(-1);
        }
        s.count++;
        const int K = (s.count < MAX_ACC) ? s.count : MAX_ACC;
        if (K < MIN_ACC) { s.active = false; return; }

        int32_t cov[SUB_NC][SUB_NC] = {};
        for (int k = 0; k < K; ++k)
            for (int i = 0; i < SUB_NC; ++i)
                for (int j = i; j < SUB_NC; ++j) {
                    int32_t v = int32_t(s.signs_I[k][i]) * int32_t(s.signs_I[k][j])
                        + int32_t(s.signs_Q[k][i]) * int32_t(s.signs_Q[k][j]);
                    cov[i][j] += v;
                    if (i != j) cov[j][i] += v;
                }

        int32_t v[SUB_NC] = {};
        for (int i = 0; i < SUB_NC; ++i) v[i] = s.eigvec[i];

        for (int iter = 0; iter < PWR_ITER; ++iter) {
            int32_t nv[SUB_NC] = {};
            for (int i = 0; i < SUB_NC; ++i)
                for (int j = 0; j < SUB_NC; ++j)
                    nv[i] += cov[i][j] * v[j];

            uint32_t ma = 1u;
            for (int i = 0; i < SUB_NC; ++i) {
                uint32_t a = fast_abs_(nv[i]);
                if (a > ma) ma = a;
            }
            const int sh = (31 - clz32_(ma)) - 10;
            if (sh > 0) for (int i = 0; i < SUB_NC; ++i) v[i] = nv[i] >> sh;
            else if (sh < 0) for (int i = 0; i < SUB_NC; ++i) v[i] = nv[i] << -sh;
            else             for (int i = 0; i < SUB_NC; ++i) v[i] = nv[i];
        }

        int64_t vCv = 0, vv = 0;
        for (int i = 0; i < SUB_NC; ++i) {
            int32_t Cv = 0;
            for (int j = 0; j < SUB_NC; ++j) Cv += cov[i][j] * v[j];
            vCv += int64_t(v[i]) * int64_t(Cv);
            vv += int64_t(v[i]) * int64_t(v[i]);
        }
        s.active = (vv > 0) && (vCv > int64_t(K) * 4 * vv);
        for (int i = 0; i < SUB_NC; ++i) s.eigvec[i] = v[i];
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
                proj += int64_t(s.eigvec[i]) * int64_t(d[i]);
            for (int i = 0; i < SUB_NC; ++i) {
                int32_t c = int32_t(d[i]) -
                    int32_t((proj * int64_t(s.eigvec[i])) >> bits);
                if (c > 32767) c = 32767;
                else if (c < -32768) c = -32768;
                d[i] = int16_t(c);
            }
        }
    }

    // =====================================================================
    //  Process — 3층 전체 적용
    // =====================================================================
    void AntiJamEngine::Process(int16_t* I, int16_t* Q, int nc) noexcept {
        if (!I || !Q || nc <= 0 || nc > MAX_NC) return;
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

        bool confident = is_preamble || (best_e > second_e * 3u);
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
        int nc_shift = 0;
        { int tmp = nc; while (tmp > 1) { nc_shift++; tmp >>= 1; } }

        // [BUG-FIX FATAL] I/Q 위상 독립 진폭 복원
        //  기존: amp = (|corr_I|+|corr_Q|)/2/N → I/Q 위상 뭉개기
        //   → 위상≠45° 시 my_sig에 인공 오차 주입 → Phantom Jamming
        //  수정: corr_I/N, corr_Q/N → I축/Q축 독립 부호 보존 진폭
        //   → walsh(sym,i) 곱셈으로 각 칩 원본 신호 정확 복원
        const int32_t amp_I = corr_I >> nc_shift;  // I축 진폭 (부호 보존)
        const int32_t amp_Q = corr_Q >> nc_shift;  // Q축 진폭 (부호 보존)

        // [BUG-FIX FATAL] mismatch: I+Q 양축 합산 (기존 I만 → Q 누락)
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
            // [BUG-FIX FATAL] I/Q 독립 복원 (위상 독립성 보존)
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