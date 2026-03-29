// =============================================================================
// HTS_V400_Dispatcher.cpp — V400 동적 모뎀 디스패처 + 3층 항재밍 통합
//
// [세션 10 수정]
//  BUG-44 [CRIT] cw_cancel_64_()에서 AJC 프로파일 직접 시딩
//         CW 17~19dB 닭-달걀 문제 해소:
//         - ja_I/ja_Q 추정 후 ajc_.Seed_CW_Profile() 호출
//         - AJC가 sym 판정 없이 첫 심볼부터 CW 제거 작동
//         - ajc_enabled_ 체크로 벤치마크 OFF 모드와 분리
// =============================================================================
#include "HTS_V400_Dispatcher.hpp"
#include "HTS_RF_Metrics.h"   // Tick_Adaptive_BPS 용
#include <cstring>
#include <atomic>

namespace ProtectedEngine {

    // ── [BUG-54] HARQ Q채널 — CCM 배치 file-scope 배열 ──
    //  sizeof(HTS_V400_Dispatcher)에서 제외하기 위해 클래스 외부 정의.
    //  생성자에서 harq_Q_ 포인터를 이 배열에 연결.
    //  ARM: .ccm_data 섹션 → linker가 CCM(0x10000000, 64KB)에 배치
    //  PC:  일반 BSS (.bss) — 테스트 시 제약 없음
    HTS_CCM_SECTION
        static int32_t g_harq_Q_ccm[FEC_HARQ::NSYM64][FEC_HARQ::C64] = {};

    static_assert(sizeof(int16_t) == 2, "int16_t must be 2 bytes");
    static_assert(sizeof(int32_t) == 4, "int32_t must be 4 bytes");
    static_assert(sizeof(uint64_t) == 8, "uint64_t required for FWHT energy");

    // ── Q8 사인파 LUT (sin(2π×k/8)×256) ──
    // AntiJamEngine.cpp의 k_cw_lut8와 동일한 값 — 두 모듈 일관성 유지
    static constexpr int16_t k_cw_lut8[8] = {
        0, 181, 256, 181, 0, -181, -256, -181
    };

    static constexpr uint32_t popc32(uint32_t x) noexcept {
        x = x - ((x >> 1u) & 0x55555555u);
        x = (x & 0x33333333u) + ((x >> 2u) & 0x33333333u);
        return (((x + (x >> 4u)) & 0x0F0F0F0Fu) * 0x01010101u) >> 24u;
    }

    static constexpr uint32_t fast_abs(int32_t x) noexcept {
        int32_t m = x >> 31;
        return static_cast<uint32_t>((x ^ m) - m);
    }

    static void sec_wipe(void* p, size_t n) noexcept {
        if (!p || !n) return;
        std::memset(p, 0, n);
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        // [BUG-48] seq_cst → release (D-2 소거 배리어 정책 통일)
        std::atomic_thread_fence(std::memory_order_release);
    }

    static void fwht_raw(int32_t* d, int n) noexcept {
        for (int len = 1; len < n; len <<= 1)
            for (int i = 0; i < n; i += 2 * len)
                for (int j = 0; j < len; ++j) {
                    int32_t u = d[i + j], v = d[i + len + j];
                    d[i + j] = u + v;
                    d[i + len + j] = u - v;
                }
    }

    static int8_t walsh_dec(const int16_t* I, const int16_t* Q, int n) noexcept {
        // [BUG-49] static 제거 → 자동 저장소 (재진입성 보장)
        // 512B 스택 추가 — Cortex-M4 스택 여유 내 허용
        int32_t sI[64], sQ[64];
        for (int i = 0; i < n; ++i) { sI[i] = I[i]; sQ[i] = Q[i]; }
        fwht_raw(sI, n);
        fwht_raw(sQ, n);
        uint64_t best = 0u;
        uint8_t dec = 0xFFu;
        for (int m = 0; m < n; ++m) {
            uint64_t e = static_cast<uint64_t>(
                static_cast<int64_t>(sI[m]) * sI[m] +
                static_cast<int64_t>(sQ[m]) * sQ[m]);
            if (e > best) { best = e; dec = static_cast<uint8_t>(m); }
        }
        return (best == 0u) ? -1 : static_cast<int8_t>(dec);
    }

    HTS_V400_Dispatcher::SymDecResult
        HTS_V400_Dispatcher::walsh_dec_full_(
            const int16_t* I, const int16_t* Q, int n) noexcept {
        for (int i = 0; i < n; ++i) {
            dec_wI_[i] = I[i]; dec_wQ_[i] = Q[i];
        }
        fwht_raw(dec_wI_, n);
        fwht_raw(dec_wQ_, n);

        const int bps = (n == 64) ? cur_bps64_ : 4;
        const int valid = 1 << bps;
        const int search = (valid < n) ? valid : n;

        uint64_t best = 0u, second = 0u;
        uint8_t dec = 0xFFu;
        for (int m = 0; m < search; ++m) {
            uint64_t e = static_cast<uint64_t>(
                static_cast<int64_t>(dec_wI_[m]) * dec_wI_[m] +
                static_cast<int64_t>(dec_wQ_[m]) * dec_wQ_[m]);
            if (e > best) {
                second = best; best = e; dec = static_cast<uint8_t>(m);
            }
            else if (e > second) { second = e; }
        }
        return {
            (best == 0u) ? static_cast<int8_t>(-1) : static_cast<int8_t>(dec),
            static_cast<uint32_t>(best >> 16u),
            static_cast<uint32_t>(second >> 16u)
        };
    }

    static void walsh_enc(uint8_t sym, int n, int16_t amp,
        int16_t* oI, int16_t* oQ) noexcept {
        for (int j = 0; j < n; ++j) {
            uint32_t p = popc32(static_cast<uint32_t>(sym) &
                static_cast<uint32_t>(j)) & 1u;
            int16_t ch = p ? static_cast<int16_t>(-amp) : amp;
            oI[j] = ch; oQ[j] = ch;
        }
    }

    static void swap_u32(uint32_t& a, uint32_t& b) noexcept {
        uint32_t t = a; a = b; b = t;
    }

    static uint32_t nth_select(uint32_t* a, int n, int k) noexcept {
        int lo = 0, hi = n - 1;
        int guard = n << 2;
        while (lo < hi && --guard > 0) {
            int mid = lo + ((hi - lo) >> 1);
            if (a[mid] < a[lo]) swap_u32(a[lo], a[mid]);
            if (a[hi] < a[lo]) swap_u32(a[lo], a[hi]);
            if (a[mid] < a[hi]) swap_u32(a[mid], a[hi]);
            uint32_t pivot = a[hi];
            int store = lo;
            for (int i = lo; i < hi; ++i)
                if (a[i] < pivot) { swap_u32(a[store], a[i]); ++store; }
            swap_u32(a[store], a[hi]);
            if (store == k) return a[store];
            if (store < k) lo = store + 1;
            else            hi = store - 1;
        }
        return a[lo];
    }

    // =====================================================================
    //  soft_clip_iq — 아웃라이어 소프트 클리핑
    //
    //  [BUG-45] int64_t / int64_t 나눗셈 완전 제거 — Q8 역수 곱셈
    //
    //  [문제]
    //   기존: (int64_t(I[i]) * clip) / m → __aeabi_ldivmod (~200cyc × 2)
    //   칩당 400사이클, 아웃라이어 10개 → 4,000사이클 낭비
    //
    //  [증명: Q8 역수가 안전한 이유]
    //   Guard: mags[i] > clip << 1 → m > 2 × clip → clip/m < 0.5
    //
    //   ① ratio_q8 = (clip << 8) / m
    //      clip max = 262140 (= 65535 << 2)
    //      clip << 8 = 67,107,840 < UINT32_MAX(4.29B) → 32비트 UDIV 안전
    //
    //   ② ratio_q8 상한: clip×256 / (2×clip+1) < 128 (모든 clip ≥ 1)
    //
    //   ③ I[i] × ratio_q8: |32768| × 127 = 4,161,536 < INT32_MAX
    //      → 32비트 MUL 안전, 64비트 연산 0회
    //
    //   ④ 결과: (I[i] × ratio_q8) >> 8 → int16_t 범위 내 (≤ 16384)
    //
    //  [성능] UDIV(12) + MUL×2(2) = 14cyc (기존 400cyc → 28× 가속)
    //  [오차] ±1/256 ≈ 0.4% (소프트 클리퍼 근사 특성상 무해)
    // =====================================================================
    static void soft_clip_iq(int16_t* I, int16_t* Q, int nc) noexcept {
        if (nc <= 0 || nc > 64) return;
        uint32_t mags[64] = {}, sorted[64] = {};
        for (int i = 0; i < nc; ++i) {
            mags[i] = fast_abs(static_cast<int32_t>(I[i])) +
                fast_abs(static_cast<int32_t>(Q[i]));
            sorted[i] = mags[i];
        }
        int q_idx = nc >> 2;
        if (q_idx < 1) q_idx = 1;
        uint32_t bl = nth_select(sorted, nc, q_idx - 1);
        if (bl < 1u) bl = 1u;
        const uint32_t clip = bl << 2u;
        if (clip < 4u) return;

        // [BUG-45] clip << 8 오버플로우 방어 static_assert
        //  clip max = 65535 << 2 = 262140
        //  clip << 8 = 262140 × 256 = 67,107,840 < UINT32_MAX
        static_assert(
            static_cast<uint64_t>(65535u) * 4u * 256u < 0xFFFFFFFFULL,
            "clip << 8 overflows uint32_t");

        const uint32_t clip8 = clip << 8u;  // Q8 스케일링 (UDIV 1회 공유)

        for (int i = 0; i < nc; ++i) {
            if (mags[i] > (clip << 1u)) {
                // [BUG-45] Q8 역수 곱셈: 64비트 나눗셈 0회
                //  ratio_q8 = clip/m in Q8 → 항상 < 128
                //  I × ratio_q8 → |32768 × 127| = 4.16M < INT32_MAX
                const uint32_t ratio_q8 = clip8 / mags[i];
                I[i] = static_cast<int16_t>(
                    (static_cast<int32_t>(I[i]) *
                        static_cast<int32_t>(ratio_q8)) >> 8);
                Q[i] = static_cast<int16_t>(
                    (static_cast<int32_t>(Q[i]) *
                        static_cast<int32_t>(ratio_q8)) >> 8);
            }
        }
    }

    // [BUG-50] 블랙홀 임계값 (J-3 매직넘버 금지)
    static constexpr uint32_t k_BH_NOISE_FLOOR = 50u;   // baseline 하한 (무간섭 판별)
    static constexpr uint32_t k_BH_SATURATION = 8000u;  // baseline 상한 (ADC 포화 방어)

    void HTS_V400_Dispatcher::blackhole_(int16_t* I, int16_t* Q, int nc) noexcept {
        if (nc > 64) return;
        uint32_t mags[64] = {}, sorted[64] = {};
        for (int i = 0; i < nc; ++i) {
            mags[i] = fast_abs(static_cast<int32_t>(I[i])) +
                fast_abs(static_cast<int32_t>(Q[i]));
            sorted[i] = mags[i];
        }
        int q25 = nc >> 2;
        if (q25 < 1) q25 = 1;
        uint32_t bl = nth_select(sorted, nc, q25 - 1);
        if (bl < 1u) bl = 1u;
        if (bl < k_BH_NOISE_FLOOR || bl > k_BH_SATURATION) return;
        uint32_t punch = bl << 3u;
        for (int i = 0; i < nc; ++i)
            if (mags[i] > punch) { I[i] = 0; Q[i] = 0; }
    }

    // =====================================================================
    //  [BUG-41/44] cw_cancel_64_ — CW 사전 소거 + AJC 프로파일 시딩
    //
    //  [BUG-41] 기존 동작: 상관 추정 → CW 제거 → 신호 정제
    //
    //  [BUG-44] 신규 추가: CW 진폭 추정 직후 ajc_.Seed_CW_Profile() 호출
    //   → jprof_[]에 CW 파형을 직접 주입
    //   → AJC가 sym 판정 귀환 없이 첫 심볼부터 CW 제거 작동
    //   → CW 17~19dB 닭-달걀 문제 해소
    //   → ajc_enabled_ == false 시 시딩 생략 (벤치마크 분리 유지)
    //
    //  [처리 순서]
    //   1) 상관 계산: corr = Σ r[i] × lut[i%8]
    //   2) 진폭 추정: ja = corr >> 13
    //   3) 가드 체크: |ja_I| + |ja_Q| < 30 이면 조기 반환 (무간섭)
    //   4) [BUG-44] AJC 시딩: ajc_.Seed_CW_Profile(ja_I, ja_Q)
    //   5) CW 제거: r[i] -= (ja × lut[i%8]) >> 8
    // =====================================================================
    void HTS_V400_Dispatcher::cw_cancel_64_(int16_t* I, int16_t* Q) noexcept {
        if (!cw_cancel_enabled_) { return; }

        // Step 1: 상관 계산 (Q8 기준)
        int32_t corr_I = 0, corr_Q = 0;
        for (int i = 0; i < 64; ++i) {
            const int32_t lut = static_cast<int32_t>(k_cw_lut8[i & 7u]);
            corr_I += static_cast<int32_t>(I[i]) * lut;
            corr_Q += static_cast<int32_t>(Q[i]) * lut;
        }

        // Step 2: 진폭 추정 (Σlut² ≈ 2^21, Q8 역정규화 = >>13)
        const int32_t ja_I = corr_I >> 13;
        const int32_t ja_Q = corr_Q >> 13;

        // Step 3: 가드 — 노이즈 수준이면 조기 반환
        static constexpr int32_t CW_CANCEL_NOISE_TH = 30;
        if (fast_abs(ja_I) + fast_abs(ja_Q) <
            static_cast<uint32_t>(CW_CANCEL_NOISE_TH)) {
            return;
        }

        // Step 4: [BUG-44] AJC 프로파일 직접 시딩
        // ja_I/ja_Q를 AJC에 전달하여 jprof_[]를 즉시 초기화합니다.
        // 이렇게 하면 AJC는 Update_AJC()의 sym 판정 결과를 기다리지
        // 않고도 첫 심볼부터 CW 파형을 알고 제거할 수 있습니다.
        // ajc_enabled_ == false이면 시딩을 건너뛰어 벤치마크 분리 유지.
        if (ajc_enabled_) {
            ajc_.Seed_CW_Profile(ja_I, ja_Q);
        }

        // Step 5: CW 제거 — r[i] -= (ja × lut[i%8]) >> 8
        for (int i = 0; i < 64; ++i) {
            const int32_t lut = static_cast<int32_t>(k_cw_lut8[i & 7u]);

            int32_t new_I = static_cast<int32_t>(I[i]) - ((ja_I * lut) >> 8);
            if (new_I > INT16_MAX) new_I = INT16_MAX;
            if (new_I < -INT16_MAX) new_I = -INT16_MAX;
            I[i] = static_cast<int16_t>(new_I);

            int32_t new_Q = static_cast<int32_t>(Q[i]) - ((ja_Q * lut) >> 8);
            if (new_Q > INT16_MAX) new_Q = INT16_MAX;
            if (new_Q < -INT16_MAX) new_Q = -INT16_MAX;
            Q[i] = static_cast<int16_t>(new_Q);
        }
    }

    // =====================================================================
    //  생성자 / 소멸자
    // =====================================================================
    HTS_V400_Dispatcher::HTS_V400_Dispatcher() noexcept
        : phase_(RxPhase::WAIT_SYNC)
        , cur_mode_(PayloadMode::UNKNOWN)
        , active_video_(PayloadMode::VIDEO_1)
        , seed_(0x12345678u)
        , tx_seq_(0u), rx_seq_(0u)
        , on_pkt_(nullptr), on_ctrl_(nullptr)
        , buf_I_{}, buf_Q_{}
        , buf_idx_(0), pre_phase_(0)
        , hdr_syms_{}, hdr_count_(0), hdr_fail_(0)
        , pay_cps_(0), pay_total_(0), pay_recv_(0)
        , harq_round_(0), max_harq_(0)
        , vid_fail_(0), vid_succ_(0)
        , v1_rx_{}, v1_idx_(0)
        , rx_{}, sym_idx_(0), harq_inited_(false)
        , harq_Q_(g_harq_Q_ccm)          // [BUG-54] CCM 배열 포인터 연결
        , wb_{}                         // [BUG-52] wb_tx_+wb_rx_ → wb_
        , ajc_(), ajc_last_nc_(0)
        , orig_acc_{}
        , orig_I_{}, orig_Q_{}
        , cw_cancel_enabled_(true)
        , ajc_enabled_(true)
        , dec_wI_{}, dec_wQ_{}
    {
    }

    HTS_V400_Dispatcher::~HTS_V400_Dispatcher() noexcept {
        sec_wipe(&seed_, sizeof(seed_));
        sec_wipe(&rx_, sizeof(rx_));
        sec_wipe(v1_rx_, sizeof(v1_rx_));
        sec_wipe(&wb_, sizeof(wb_));          // [BUG-52] 단일 wb_
        sec_wipe(buf_I_, sizeof(buf_I_));
        sec_wipe(buf_Q_, sizeof(buf_Q_));
        sec_wipe(hdr_syms_, sizeof(hdr_syms_));
        sec_wipe(orig_I_, sizeof(orig_I_));
        sec_wipe(orig_Q_, sizeof(orig_Q_));
        sec_wipe(&orig_acc_, sizeof(orig_acc_));
        sec_wipe(&ajc_, sizeof(ajc_));
        sec_wipe(harq_Q_, sizeof(g_harq_Q_ccm));  // [BUG-54] CCM Q채널 보안 소거
    }

    void HTS_V400_Dispatcher::Set_Seed(uint32_t s) noexcept { seed_ = s; }
    void HTS_V400_Dispatcher::Set_Packet_Callback(PacketCB cb) noexcept { on_pkt_ = cb; }
    void HTS_V400_Dispatcher::Set_Control_Callback(ControlCB cb) noexcept { on_ctrl_ = cb; }
    RxPhase     HTS_V400_Dispatcher::Get_Phase()           const noexcept { return phase_; }
    PayloadMode HTS_V400_Dispatcher::Get_Mode()            const noexcept { return cur_mode_; }
    int         HTS_V400_Dispatcher::Get_Video_Fail_Count()const noexcept { return vid_fail_; }
    int         HTS_V400_Dispatcher::Get_Current_BPS64()   const noexcept { return cur_bps64_; }

    void HTS_V400_Dispatcher::Update_Adaptive_BPS(uint32_t nf) noexcept {
        const int new_bps = FEC_HARQ::bps_from_nf(nf);
        if (new_bps >= FEC_HARQ::BPS64_MIN &&
            new_bps <= FEC_HARQ::BPS64_MAX) {
            cur_bps64_ = new_bps;
        }
    }

    void HTS_V400_Dispatcher::Set_RF_Metrics(
        HTS_RF_Metrics* p) noexcept
    {
        // 비소유 포인터 저장 — nullptr 허용 (Tick 무동작 모드)
        p_metrics_ = p;
    }

    void HTS_V400_Dispatcher::Tick_Adaptive_BPS() noexcept
    {
        if (p_metrics_ == nullptr) { return; }

        // metrics.current_bps (컨트롤러가 갱신한 값)를 읽어 cur_bps64_에 반영
        // acquire: HTS_Adaptive_BPS_Controller::Update의 release와 쌍을 이룸
        const uint8_t bps = p_metrics_->current_bps.load(
            std::memory_order_acquire);

        // FEC_HARQ 유효 범위 검증 후 적용
        if (bps >= static_cast<uint8_t>(FEC_HARQ::BPS64_MIN) &&
            bps <= static_cast<uint8_t>(FEC_HARQ::BPS64_MAX)) {
            cur_bps64_ = static_cast<int>(bps);
        }
    }

    void HTS_V400_Dispatcher::full_reset_() noexcept {
        // [BUG-44] full_reset_는 phase_ 직접 기록 (set_phase_ 재귀 방지)
        // WAIT_SYNC 전이는 모든 상태에서 무조건 합법
        phase_ = RxPhase::WAIT_SYNC;
        cur_mode_ = PayloadMode::UNKNOWN;
        buf_idx_ = 0; pre_phase_ = 0;
        hdr_count_ = 0; hdr_fail_ = 0;
        pay_recv_ = 0; v1_idx_ = 0;
        sym_idx_ = 0; harq_round_ = 0;
        harq_inited_ = false;
        std::memset(&rx_, 0, sizeof(rx_));
        std::memset(v1_rx_, 0, sizeof(v1_rx_));
        std::memset(orig_I_, 0, sizeof(orig_I_));
        std::memset(orig_Q_, 0, sizeof(orig_Q_));
        std::memset(&orig_acc_, 0, sizeof(orig_acc_));
        std::memset(&wb_, 0, sizeof(wb_));            // [BUG-52] 단일 wb_
        std::memset(harq_Q_, 0, sizeof(g_harq_Q_ccm));  // [BUG-54] CCM Q채널 초기화
    }

    // =====================================================================
    //  [BUG-44] CFI 상태 전이 검증 (항목⑬)
    //
    //  비트마스크 합법 전이 테이블 — Constant-time (분기 0개)
    //
    //   key = (from << 2) | to  →  4비트 인덱스
    //   합법 키: 0(WS→WS), 1(WS→RH), 4(RH→WS), 6(RH→RP), 8(RP→WS)
    //   LEGAL_MASK = bit0|bit1|bit4|bit6|bit8 = 0x153
    //
    //   불법 전이 감지 시 full_reset_()으로 안전 상태 강제 복귀
    //   → ROP/글리치로 READ_HEADER를 건너뛰는 공격 차단
    //     (WAIT_SYNC → READ_PAYLOAD 불법 = 헤더 인증 우회)
    // =====================================================================
    bool HTS_V400_Dispatcher::set_phase_(RxPhase target) noexcept {
        const uint32_t f = static_cast<uint32_t>(phase_);
        const uint32_t t = static_cast<uint32_t>(target);
        const uint32_t key = (f << 2u) | t;

        // Constant-time: 시프트 + AND 1회 (~2cyc ARM)
        // 합법 키: 0,1,4,6,8 → 비트마스크 0x153
        constexpr uint32_t LEGAL_MASK =
            (1u << 0u) |    // WAIT_SYNC    → WAIT_SYNC    (reset)
            (1u << 1u) |    // WAIT_SYNC    → READ_HEADER  (프리앰블 매칭)
            (1u << 4u) |    // READ_HEADER  → WAIT_SYNC    (헤더 실패)
            (1u << 6u) |    // READ_HEADER  → READ_PAYLOAD (헤더 성공)
            (1u << 8u);     // READ_PAYLOAD → WAIT_SYNC    (디코딩 완료)

        const bool legal = (key < 12u) && (((LEGAL_MASK >> key) & 1u) != 0u);

        if (legal) {
            phase_ = target;
            return true;
        }

        // 불법 전이: 안전 상태로 강제 복귀
        full_reset_();
        return false;
    }

    void HTS_V400_Dispatcher::Reset() noexcept {
        full_reset_();
        ajc_.Reset(16);
        ajc_last_nc_ = 0;
    }

    bool HTS_V400_Dispatcher::parse_hdr_(PayloadMode& mode, int& plen) noexcept {
        uint16_t hdr = (static_cast<uint16_t>(hdr_syms_[0]) << 6u) |
            static_cast<uint16_t>(hdr_syms_[1]);
        uint8_t mb = static_cast<uint8_t>((hdr >> 10u) & 0x03u);
        plen = static_cast<int>(hdr & 0x03FFu);
        switch (mb) {
        case 0u: mode = PayloadMode::VIDEO_1;  return (plen == FEC_HARQ::NSYM1);
        case 1u: mode = PayloadMode::VIDEO_16; return (plen == FEC_HARQ::NSYM16);
        case 2u: mode = PayloadMode::VOICE;    return (plen == FEC_HARQ::NSYM16);
        case 3u: {
            mode = PayloadMode::DATA;
            const int bps = FEC_HARQ::bps_from_nsym(plen);
            if (bps < FEC_HARQ::BPS64_MIN || bps > FEC_HARQ::BPS64_MAX) return false;
            if (plen != FEC_HARQ::nsym_for_bps(bps)) return false;
            cur_bps64_ = bps;
            return true;
        }
        default: mode = PayloadMode::UNKNOWN; return false;
        }
    }

    void HTS_V400_Dispatcher::on_sym_() noexcept {
        pay_recv_++;

        if (cur_mode_ == PayloadMode::VIDEO_1) {
            if (v1_idx_ < 80) { v1_rx_[v1_idx_++] = buf_I_[0]; }
            else { full_reset_(); return; }
        }
        else if (cur_mode_ == PayloadMode::VIDEO_16 ||
            cur_mode_ == PayloadMode::VOICE ||
            cur_mode_ == PayloadMode::DATA) {

            const int nc = (cur_mode_ == PayloadMode::DATA) ? 64 : 16;

            std::memcpy(orig_I_, buf_I_, nc * sizeof(int16_t));
            std::memcpy(orig_Q_, buf_Q_, nc * sizeof(int16_t));

            // [BUG-41/44] CW 소거 + AJC 시딩 (DATA 64칩 전용)
            if (cur_mode_ == PayloadMode::DATA) {
                cw_cancel_64_(buf_I_, buf_Q_);
            }

            if (ajc_enabled_) {
                ajc_.Process(buf_I_, buf_Q_, nc);
            }
            soft_clip_iq(buf_I_, buf_Q_, nc);

            if (nc == 16) {
                if (sym_idx_ < FEC_HARQ::NSYM16) {
                    // [BUG-51] sI/sQ 저장 삭제 → HARQ 즉시 누적
                    FEC_HARQ::Feed16_1sym(rx_.m16, buf_I_, buf_Q_, sym_idx_);

                    // [BUG-53] orig_acc_ int8_t 양자화 (상위 8비트)
                    for (int c = 0; c < nc; ++c) {
                        orig_acc_.acc16.oI[sym_idx_][c] =
                            static_cast<int8_t>(orig_I_[c] >> 8);
                        orig_acc_.acc16.oQ[sym_idx_][c] =
                            static_cast<int8_t>(orig_Q_[c] >> 8);
                    }
                    sym_idx_++;
                }
                else { full_reset_(); return; }
            }
            else {
                const int nsym64 = cur_nsym64_();
                if (sym_idx_ < nsym64) {
                    // [BUG-51] HARQ I채널 즉시 누적 (SRAM)
                    for (int c = 0; c < nc; ++c) {
                        rx_.m64_I.aI[sym_idx_][c] +=
                            static_cast<int32_t>(buf_I_[c]);
                    }
                    // [BUG-54] HARQ Q채널 즉시 누적 (CCM)
                    for (int c = 0; c < nc; ++c) {
                        harq_Q_[sym_idx_][c] +=
                            static_cast<int32_t>(buf_Q_[c]);
                    }

                    // [BUG-53] orig_acc_ int8_t 양자화 (상위 8비트)
                    for (int c = 0; c < nc; ++c) {
                        orig_acc_.acc64.oI[sym_idx_][c] =
                            static_cast<int8_t>(orig_I_[c] >> 8);
                        orig_acc_.acc64.oQ[sym_idx_][c] =
                            static_cast<int8_t>(orig_Q_[c] >> 8);
                    }
                    sym_idx_++;
                }
                else { full_reset_(); return; }
            }

            SymDecResult r = walsh_dec_full_(buf_I_, buf_Q_, nc);
            if (ajc_enabled_) {
                ajc_.Update_AJC(orig_I_, orig_Q_,
                    r.sym, r.best_e, r.second_e, nc);
            }
        }

        buf_idx_ = 0;
        if (pay_recv_ >= pay_total_) try_decode_();
    }

    void HTS_V400_Dispatcher::try_decode_() noexcept {
        DecodedPacket pkt = {};
        pkt.mode = cur_mode_; pkt.success = false;
        uint32_t il = seed_ ^ (rx_seq_ * 0xA5A5A5A5u);

        if (cur_mode_ == PayloadMode::VIDEO_1) {
            pkt.success = FEC_HARQ::Decode1(v1_rx_, pkt.data, &pkt.data_len);
            pkt.harq_k = 1;
            handle_video_(pkt.success);
            if (on_pkt_) on_pkt_(pkt);
            rx_seq_++; full_reset_();
        }
        else if (cur_mode_ == PayloadMode::VIDEO_16 ||
            cur_mode_ == PayloadMode::VOICE) {
            if (!harq_inited_) { FEC_HARQ::Init16(rx_.m16); harq_inited_ = true; }
            // [BUG-51] Feed16 삭제 — on_sym_()에서 Feed16_1sym으로 이미 누적
            FEC_HARQ::Advance_Round_16(rx_.m16);
            harq_round_++;
            pkt.success = FEC_HARQ::Decode16(rx_.m16, pkt.data,
                &pkt.data_len, il, wb_);   // [BUG-52] wb_rx_ → wb_
            pkt.harq_k = harq_round_;
            if (pkt.success || harq_round_ >= max_harq_) {
                if (pkt.success) harq_feedback_seed_(pkt.data, pkt.data_len, 16, il);
                if (cur_mode_ == PayloadMode::VIDEO_16) handle_video_(pkt.success);
                if (on_pkt_) on_pkt_(pkt);
                rx_seq_++; full_reset_();
            }
            else { pay_recv_ = 0; sym_idx_ = 0; set_phase_(RxPhase::WAIT_SYNC); }
        }
        else if (cur_mode_ == PayloadMode::DATA) {
            if (!harq_inited_) {
                // [BUG-54] I/Q 분리 초기화
                std::memset(rx_.m64_I.aI, 0, sizeof(rx_.m64_I.aI));
                rx_.m64_I.k = 0;
                rx_.m64_I.ok = false;
                std::memset(harq_Q_, 0, sizeof(g_harq_Q_ccm));
                harq_inited_ = true;
            }
            // [BUG-51] Feed64_A 삭제 — on_sym_()에서 인라인으로 이미 누적
            // [BUG-54] HARQ 라운드 증가
            if (!rx_.m64_I.ok) rx_.m64_I.k++;
            harq_round_++;

            // [BUG-54] I/Q 분리 Decode — Decode_Core_Split 사용
            //  harq_I(SRAM) + harq_Q(CCM) → 별도 포인터 전달
            {
                const int bps = cur_bps64_;
                if (bps >= FEC_HARQ::BPS64_MIN && bps <= FEC_HARQ::BPS64_MAX) {
                    const int nsym = FEC_HARQ::nsym_for_bps(bps);
                    pkt.success = FEC_HARQ::Decode_Core_Split(
                        &rx_.m64_I.aI[0][0],  // I → SRAM
                        &harq_Q_[0][0],        // Q → CCM
                        nsym, FEC_HARQ::C64, bps,
                        pkt.data, &pkt.data_len, il, wb_);  // [BUG-52]
                }
            }
            pkt.harq_k = harq_round_;
            if (pkt.success || harq_round_ >= max_harq_) {
                if (pkt.success) {
                    rx_.m64_I.ok = true;  // [BUG-54] 디코드 성공 플래그
                    harq_feedback_seed_(pkt.data, pkt.data_len, 64, il);
                }
                if (on_pkt_) on_pkt_(pkt);
                rx_seq_++; full_reset_();
            }
            else { pay_recv_ = 0; sym_idx_ = 0; set_phase_(RxPhase::WAIT_SYNC); }
        }
    }

    void HTS_V400_Dispatcher::harq_feedback_seed_(
        const uint8_t* data, int data_len, int nc, uint32_t il) noexcept {
        if (!data || data_len <= 0) return;
        if (nc == 16) {
            uint8_t correct_syms[FEC_HARQ::NSYM16] = {};
            const int enc_n = FEC_HARQ::Encode16(
                data, data_len, correct_syms, il, wb_);  // [BUG-52]
            if (enc_n <= 0) return;
            const int nsym = (sym_idx_ < FEC_HARQ::NSYM16)
                ? sym_idx_ : FEC_HARQ::NSYM16;
            for (int s = 0; s < nsym; ++s) {
                if (ajc_enabled_) {
                    // [BUG-53] int8_t→int16_t 스택 복원 (AJC API 호환)
                    int16_t tmp_I[16], tmp_Q[16];
                    for (int c = 0; c < nc; ++c) {
                        tmp_I[c] = static_cast<int16_t>(
                            static_cast<int16_t>(orig_acc_.acc16.oI[s][c]) << 8);
                        tmp_Q[c] = static_cast<int16_t>(
                            static_cast<int16_t>(orig_acc_.acc16.oQ[s][c]) << 8);
                    }
                    ajc_.Update_AJC(tmp_I, tmp_Q,
                        static_cast<int8_t>(correct_syms[s]),
                        0xFFFFFFFFu, 0u, nc, true);
                }
            }
        }
        else if (nc == 64) {
            const int nsym64 = cur_nsym64_();
            uint8_t correct_syms[FEC_HARQ::NSYM64] = {};
            const int enc_n = FEC_HARQ::Encode64_A(
                data, data_len, correct_syms, il, cur_bps64_, wb_);  // [BUG-52]
            if (enc_n <= 0) return;
            const int nsym = (sym_idx_ < nsym64) ? sym_idx_ : nsym64;
            for (int s = 0; s < nsym; ++s) {
                if (ajc_enabled_) {
                    // [BUG-53] int8_t→int16_t 스택 복원 (AJC API 호환)
                    int16_t tmp_I[64], tmp_Q[64];
                    for (int c = 0; c < nc; ++c) {
                        tmp_I[c] = static_cast<int16_t>(
                            static_cast<int16_t>(orig_acc_.acc64.oI[s][c]) << 8);
                        tmp_Q[c] = static_cast<int16_t>(
                            static_cast<int16_t>(orig_acc_.acc64.oQ[s][c]) << 8);
                    }
                    ajc_.Update_AJC(tmp_I, tmp_Q,
                        static_cast<int8_t>(correct_syms[s]),
                        0xFFFFFFFFu, 0u, nc, true);
                }
            }
        }
    }

    void HTS_V400_Dispatcher::handle_video_(bool ok) noexcept {
        if (ok) {
            vid_succ_++; vid_fail_ = 0;
            if (active_video_ == PayloadMode::VIDEO_16 &&
                vid_succ_ >= VIDEO_RECOVER_TH) {
                active_video_ = PayloadMode::VIDEO_1; vid_succ_ = 0;
                if (on_ctrl_) on_ctrl_(PayloadMode::VIDEO_1);
            }
        }
        else {
            vid_fail_++; vid_succ_ = 0;
            if (active_video_ == PayloadMode::VIDEO_1 &&
                vid_fail_ >= VIDEO_FAIL_TH) {
                active_video_ = PayloadMode::VIDEO_16; vid_fail_ = 0;
                if (on_ctrl_) on_ctrl_(PayloadMode::VIDEO_16);
            }
        }
    }

    int HTS_V400_Dispatcher::Build_Packet(PayloadMode mode,
        const uint8_t* info, int ilen, int16_t amp,
        int16_t* oI, int16_t* oQ, int max_c) noexcept {
        if (!info || !oI || !oQ) return 0;
        int pos = 0;
        if (pos + 128 > max_c) return 0;
        walsh_enc(PRE_SYM0, 64, amp, &oI[pos], &oQ[pos]); pos += 64;
        walsh_enc(PRE_SYM1, 64, amp, &oI[pos], &oQ[pos]); pos += 64;

        uint8_t mb = 0u; int psyms = 0;
        switch (mode) {
        case PayloadMode::VIDEO_1:  mb = 0u; psyms = FEC_HARQ::NSYM1;  break;
        case PayloadMode::VIDEO_16: mb = 1u; psyms = FEC_HARQ::NSYM16; break;
        case PayloadMode::VOICE:    mb = 2u; psyms = FEC_HARQ::NSYM16; break;
        case PayloadMode::DATA:     mb = 3u; psyms = cur_nsym64_();     break;
        default: return 0;
        }
        uint16_t hdr = (static_cast<uint16_t>(mb & 0x03u) << 10u) |
            (static_cast<uint16_t>(psyms) & 0x03FFu);
        if (pos + 128 > max_c) return 0;
        walsh_enc(static_cast<uint8_t>((hdr >> 6u) & 0x3Fu), 64, amp,
            &oI[pos], &oQ[pos]); pos += 64;
        walsh_enc(static_cast<uint8_t>(hdr & 0x3Fu), 64, amp,
            &oI[pos], &oQ[pos]); pos += 64;

        uint32_t il = seed_ ^ (tx_seq_ * 0xA5A5A5A5u);

        if (mode == PayloadMode::VIDEO_1) {
            uint8_t syms[80] = {};
            int n = FEC_HARQ::Encode1(info, ilen, syms);
            if (pos + n > max_c) return 0;
            for (int s = 0; s < n; ++s) {
                oI[pos] = syms[s] ? static_cast<int16_t>(-amp) : amp;
                oQ[pos] = oI[pos]; pos++;
            }
        }
        else if (mode == PayloadMode::VIDEO_16 || mode == PayloadMode::VOICE) {
            uint8_t syms[FEC_HARQ::NSYM16] = {};
            const int enc_n = FEC_HARQ::Encode16(info, ilen, syms, il, wb_);  // [BUG-52]
            if (enc_n <= 0) return 0;
            for (int s = 0; s < FEC_HARQ::NSYM16; ++s) {
                if (pos + 16 > max_c) return 0;
                walsh_enc(syms[s], 16, amp, &oI[pos], &oQ[pos]); pos += 16;
            }
        }
        else if (mode == PayloadMode::DATA) {
            const int nsym = cur_nsym64_();
            uint8_t syms[FEC_HARQ::NSYM64] = {};
            const int enc_n = FEC_HARQ::Encode64_A(
                info, ilen, syms, il, cur_bps64_, wb_);  // [BUG-52]
            if (enc_n <= 0) return 0;
            for (int s = 0; s < nsym; ++s) {
                if (pos + 64 > max_c) return 0;
                walsh_enc(syms[s], 64, amp, &oI[pos], &oQ[pos]); pos += 64;
            }
        }
        tx_seq_++;
        return pos;
    }

    void HTS_V400_Dispatcher::Feed_Chip(int16_t rx_I, int16_t rx_Q) noexcept {
        if (buf_idx_ >= 64) return;
        buf_I_[buf_idx_] = rx_I; buf_Q_[buf_idx_] = rx_Q; buf_idx_++;

        if (phase_ == RxPhase::WAIT_SYNC) {
            if (buf_idx_ == 64) {
                int16_t wI[64], wQ[64];
                std::memcpy(wI, buf_I_, 64 * sizeof(int16_t));
                std::memcpy(wQ, buf_Q_, 64 * sizeof(int16_t));

                cw_cancel_64_(wI, wQ);
                if (ajc_enabled_) { ajc_.Process(wI, wQ, 64); }
                soft_clip_iq(wI, wQ, 64);

                int8_t sym = walsh_dec(wI, wQ, 64);
                bool matched = false;
                if (pre_phase_ == 0) {
                    if (sym == static_cast<int8_t>(PRE_SYM0)) {
                        pre_phase_ = 1; matched = true;
                    }
                }
                else {
                    if (sym == static_cast<int8_t>(PRE_SYM1)) {
                        set_phase_(RxPhase::READ_HEADER);
                        hdr_count_ = 0; hdr_fail_ = 0; matched = true;
                    }
                    pre_phase_ = 0;
                }
                if (matched) { buf_idx_ = 0; }
                else {
                    // [BUG-46] memmove → 인라인 수동 시프트 (Ultra-Hot Path)
                    //
                    // 이 코드는 WAIT_SYNC에서 칩 1개당 1회 실행됩니다.
                    // 프리앰블 탐색 중 수십만 칩이 연속으로 도착하므로
                    // 함수 호출 오버헤드가 누적되면 수신기 전체 성능이 저하됩니다.
                    //
                    // memmove 비용: BL(3) + PUSH/POP(4) + 오버랩체크(2) + 복사(32) = ~41cyc
                    // 인라인 루프:  63× LDR.H/STR.H 파이프라인 = ~16cyc (2.5× 가속)
                    //
                    // 방향 고정(왼쪽 1칸 시프트): 오버랩 검사 불필요
                    // src = buf[k+1], dst = buf[k] → 항상 src > dst → forward 안전
                    for (int k = 0; k < 63; ++k) {
                        buf_I_[k] = buf_I_[k + 1];
                        buf_Q_[k] = buf_Q_[k + 1];
                    }
                    buf_idx_ = 63;
                }
            }
        }
        else if (phase_ == RxPhase::READ_HEADER) {
            if (buf_idx_ == 64) {
                int16_t wI[64], wQ[64];
                std::memcpy(wI, buf_I_, 64 * sizeof(int16_t));
                std::memcpy(wQ, buf_Q_, 64 * sizeof(int16_t));

                cw_cancel_64_(wI, wQ);
                if (ajc_enabled_) { ajc_.Process(wI, wQ, 64); }
                soft_clip_iq(wI, wQ, 64);

                int8_t sym = walsh_dec(wI, wQ, 64);
                if (sym >= 0 && sym < 64) {
                    hdr_syms_[hdr_count_] = static_cast<uint8_t>(sym);
                    hdr_count_++;
                }
                else {
                    hdr_fail_++;
                    if (hdr_fail_ >= HDR_FAIL_MAX) full_reset_();
                }
                if (hdr_count_ >= HDR_SYMS) {
                    PayloadMode mode; int plen = 0;
                    if (parse_hdr_(mode, plen)) {
                        cur_mode_ = mode;
                        pay_cps_ = (mode == PayloadMode::VIDEO_1) ? 1 :
                            (mode == PayloadMode::DATA) ? 64 : 16;
                        pay_total_ = plen; pay_recv_ = 0;
                        v1_idx_ = 0; sym_idx_ = 0;
                        max_harq_ = (mode == PayloadMode::VIDEO_1 ||
                            mode == PayloadMode::VIDEO_16) ? 1 :
                            (mode == PayloadMode::VOICE) ? FEC_HARQ::VOICE_K
                            : FEC_HARQ::DATA_K;
                        set_phase_(RxPhase::READ_PAYLOAD); buf_idx_ = 0;
                        if (pay_cps_ != ajc_last_nc_) {
                            ajc_.Reset(pay_cps_);
                            ajc_last_nc_ = pay_cps_;
                        }
                    }
                    else { full_reset_(); }
                }
                if (phase_ == RxPhase::READ_HEADER) buf_idx_ = 0;
            }
        }
        else if (phase_ == RxPhase::READ_PAYLOAD) {
            if (buf_idx_ >= pay_cps_) on_sym_();
        }
    }

} // namespace ProtectedEngine