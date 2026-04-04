// =============================================================================
// HTS_V400_Dispatcher.cpp — V400 동적 모뎀 디스패처 + 3층 항재밍 통합
//
// [동작 메모]
//  cw_cancel_64_: ja_I/ja_Q 추정 후 ajc_.Seed_CW_Profile — 첫 심볼부터 CW 제거
//  try_decode_: Q채널 HARQ는 harq_Q_[0] (행 포인터)로 Decode_Core_Split에 전달
//               (&harq_Q_[0][0] 금지 — 2차원 배열 타입과 혼동 시 HardFault)
//
#include "HTS_V400_Dispatcher.hpp"
#include "HTS_RF_Metrics.h"   // Tick_Adaptive_BPS 용
#include "HTS_Secure_Memory.h"
#include <cstring>
#include <atomic>

namespace ProtectedEngine {

    // ── HARQ Q채널 — CCM 배치 file-scope 배열 ───────────────────
    //  sizeof(HTS_V400_Dispatcher)에서 제외하기 위해 클래스 외부 정의.
    //  생성자에서 harq_Q_ 포인터를 이 배열에 연결.
    //  초기화 생략: .bss zero-fill + full_reset_에서 memset
    //  PC: 일반 BSS (.bss) — 테스트 시 제약 없음
    HTS_CCM_SECTION
        static int32_t g_harq_Q_ccm[FEC_HARQ::NSYM64][FEC_HARQ::C64];

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
        const uint32_t m = 0u - static_cast<uint32_t>(x < 0);
        return (static_cast<uint32_t>(x) ^ m) + m;
    }

    static void fwht_raw(int32_t* d, int n) noexcept {
        if (n == 64) {
            for (int i = 0; i < 64; i += 2) {
                int32_t u = d[i], v = d[i + 1];
                d[i] = u + v; d[i + 1] = u - v;
            }
            for (int i = 0; i < 64; i += 4) {
                int32_t u = d[i], v = d[i + 2];
                d[i] = u + v; d[i + 2] = u - v;
                u = d[i + 1]; v = d[i + 3];
                d[i + 1] = u + v; d[i + 3] = u - v;
            }
            for (int i = 0; i < 64; i += 8) {
                for (int k = 0; k < 4; ++k) {
                    int32_t u = d[i + k], v = d[i + 4 + k];
                    d[i + k] = u + v; d[i + 4 + k] = u - v;
                }
            }
            for (int i = 0; i < 64; i += 16) {
                for (int k = 0; k < 8; ++k) {
                    int32_t u = d[i + k], v = d[i + 8 + k];
                    d[i + k] = u + v; d[i + 8 + k] = u - v;
                }
            }
            for (int i = 0; i < 64; i += 32) {
                for (int k = 0; k < 16; ++k) {
                    int32_t u = d[i + k], v = d[i + 16 + k];
                    d[i + k] = u + v; d[i + 16 + k] = u - v;
                }
            }
            for (int k = 0; k < 32; ++k) {
                int32_t u = d[k], v = d[k + 32];
                d[k] = u + v; d[k + 32] = u - v;
            }
            return;
        }
        if (n == 16) {
            for (int i = 0; i < 16; i += 2) {
                int32_t u = d[i], v = d[i + 1];
                d[i] = u + v; d[i + 1] = u - v;
            }
            for (int i = 0; i < 16; i += 4) {
                int32_t u = d[i], v = d[i + 2];
                d[i] = u + v; d[i + 2] = u - v;
                u = d[i + 1]; v = d[i + 3];
                d[i + 1] = u + v; d[i + 3] = u - v;
            }
            for (int i = 0; i < 16; i += 8) {
                for (int k = 0; k < 4; ++k) {
                    int32_t u = d[i + k], v = d[i + 4 + k];
                    d[i + k] = u + v; d[i + 4 + k] = u - v;
                }
            }
            for (int k = 0; k < 8; ++k) {
                int32_t u = d[k], v = d[k + 8];
                d[k] = u + v; d[k + 8] = u - v;
            }
            return;
        }
        for (int len = 1; len < n; len <<= 1) {
            for (int i = 0; i < n; i += 2 * len) {
                for (int j = 0; j < len; ++j) {
                    int32_t u = d[i + j], v = d[i + len + j];
                    d[i + j] = u + v;
                    d[i + len + j] = u - v;
                }
            }
        }
    }

    //  스택 512B(sI[64]+sQ[64]) 제거, dec_wI_/dec_wQ_ 멤버 재활용

    HTS_V400_Dispatcher::SymDecResult
        HTS_V400_Dispatcher::walsh_dec_full_(
            const int16_t* I, const int16_t* Q, int n) noexcept {
        if (I == nullptr || Q == nullptr || n <= 0) {
            return {
                static_cast<int8_t>(-1), 0u, 0u
            };
        }
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
            const uint64_t e = static_cast<uint64_t>(
                static_cast<int64_t>(dec_wI_[m]) * dec_wI_[m] +
                static_cast<int64_t>(dec_wQ_[m]) * dec_wQ_[m]);
            const uint32_t c_gt_best = static_cast<uint32_t>(e > best);
            const uint32_t c_gt_sec =
                static_cast<uint32_t>(e <= best) & static_cast<uint32_t>(e > second);
            second = second * (1ull - static_cast<uint64_t>(c_gt_best))
                * (1ull - static_cast<uint64_t>(c_gt_sec))
                + best * static_cast<uint64_t>(c_gt_best)
                + e * static_cast<uint64_t>(c_gt_sec);
            best = best * (1ull - static_cast<uint64_t>(c_gt_best))
                + e * static_cast<uint64_t>(c_gt_best);
            dec = static_cast<uint8_t>(
                static_cast<uint32_t>(m) * c_gt_best
                + static_cast<uint32_t>(dec) * (1u - c_gt_best));
        }
        return {
            (best == 0u) ? static_cast<int8_t>(-1) : static_cast<int8_t>(dec),
            static_cast<uint32_t>(best >> 16u),
            static_cast<uint32_t>(second >> 16u)
        };
    }

    // ── I=Q 동일 모드 (재밍 방어) ──

    // ── [적응형 I/Q] I/Q 독립 디코딩 ──────────────────────────
    //  I 채널과 Q 채널을 분리하여 각각 FWHT 수행
    //  한 칩 구간에서 2개 심볼 획득 → 처리량 2배
    //  각 채널의 에너지는 I² 또는 Q² 단독 (합산하지 않음)
    //  → I=Q 동일 대비 −3dB, 평시(NF<10dB) 충분
    HTS_V400_Dispatcher::SymDecResultSplit
        HTS_V400_Dispatcher::walsh_dec_split_(
            const int16_t* I, const int16_t* Q, int n) noexcept {
        if (I == nullptr || Q == nullptr || n <= 0) {
            return {
                static_cast<int8_t>(-1), static_cast<int8_t>(-1),
                0u, 0u, 0u, 0u
            };
        }

        // I 채널 FWHT
        for (int i = 0; i < n; ++i) { dec_wI_[i] = I[i]; }
        fwht_raw(dec_wI_, n);

        // Q 채널 FWHT
        for (int i = 0; i < n; ++i) { dec_wQ_[i] = Q[i]; }
        fwht_raw(dec_wQ_, n);

        const int bps = (n == 64) ? cur_bps64_ : 4;
        const int valid = 1 << bps;
        const int search = (valid < n) ? valid : n;

        // I 채널 최대 에너지 빈 탐색
        uint64_t bestI = 0u, secI = 0u;
        uint8_t decI = 0xFFu;
        for (int m = 0; m < search; ++m) {
            const uint64_t e = static_cast<uint64_t>(
                static_cast<int64_t>(dec_wI_[m]) * dec_wI_[m]);
            const uint32_t c_gt_best = static_cast<uint32_t>(e > bestI);
            const uint32_t c_gt_sec =
                static_cast<uint32_t>(e <= bestI) & static_cast<uint32_t>(e > secI);
            secI = secI * (1ull - static_cast<uint64_t>(c_gt_best))
                * (1ull - static_cast<uint64_t>(c_gt_sec))
                + bestI * static_cast<uint64_t>(c_gt_best)
                + e * static_cast<uint64_t>(c_gt_sec);
            bestI = bestI * (1ull - static_cast<uint64_t>(c_gt_best))
                + e * static_cast<uint64_t>(c_gt_best);
            decI = static_cast<uint8_t>(
                static_cast<uint32_t>(m) * c_gt_best
                + static_cast<uint32_t>(decI) * (1u - c_gt_best));
        }

        uint64_t bestQ = 0u, secQ = 0u;
        uint8_t decQ = 0xFFu;
        for (int m = 0; m < search; ++m) {
            const uint64_t e = static_cast<uint64_t>(
                static_cast<int64_t>(dec_wQ_[m]) * dec_wQ_[m]);
            const uint32_t c_gt_best = static_cast<uint32_t>(e > bestQ);
            const uint32_t c_gt_sec =
                static_cast<uint32_t>(e <= bestQ) & static_cast<uint32_t>(e > secQ);
            secQ = secQ * (1ull - static_cast<uint64_t>(c_gt_best))
                * (1ull - static_cast<uint64_t>(c_gt_sec))
                + bestQ * static_cast<uint64_t>(c_gt_best)
                + e * static_cast<uint64_t>(c_gt_sec);
            bestQ = bestQ * (1ull - static_cast<uint64_t>(c_gt_best))
                + e * static_cast<uint64_t>(c_gt_best);
            decQ = static_cast<uint8_t>(
                static_cast<uint32_t>(m) * c_gt_best
                + static_cast<uint32_t>(decQ) * (1u - c_gt_best));
        }

        return {
            (bestI == 0u) ? static_cast<int8_t>(-1) : static_cast<int8_t>(decI),
            (bestQ == 0u) ? static_cast<int8_t>(-1) : static_cast<int8_t>(decQ),
            static_cast<uint32_t>(bestI >> 16u),
            static_cast<uint32_t>(secI >> 16u),
            static_cast<uint32_t>(bestQ >> 16u),
            static_cast<uint32_t>(secQ >> 16u)
        };
    }
    static void walsh_enc(uint8_t sym, int n, int16_t amp,
        int16_t* oI, int16_t* oQ) noexcept {
        const int32_t ampi = static_cast<int32_t>(amp);
        for (int j = 0; j < n; ++j) {
            const uint32_t p = popc32(static_cast<uint32_t>(sym) &
                static_cast<uint32_t>(j)) & 1u;
            const int16_t ch = static_cast<int16_t>(
                ampi * (1 - 2 * static_cast<int32_t>(p)));
            oI[j] = ch; oQ[j] = ch;
        }
    }

    // ── [적응형 I/Q] I/Q 독립 모드 (평시 2배 처리량) ──
    //  sym_I → I 채널, sym_Q → Q 채널에 독립 Walsh 인코딩
    //  처리량 2배: 동일 칩 수로 2개 심볼 전송
    static void walsh_enc_split(uint8_t sym_I, uint8_t sym_Q, int n,
        int16_t amp, int16_t* oI, int16_t* oQ) noexcept {
        const int32_t ampi = static_cast<int32_t>(amp);
        for (int j = 0; j < n; ++j) {
            const uint32_t pI = popc32(static_cast<uint32_t>(sym_I) &
                static_cast<uint32_t>(j)) & 1u;
            const uint32_t pQ = popc32(static_cast<uint32_t>(sym_Q) &
                static_cast<uint32_t>(j)) & 1u;
            oI[j] = static_cast<int16_t>(
                ampi * (1 - 2 * static_cast<int32_t>(pI)));
            oQ[j] = static_cast<int16_t>(
                ampi * (1 - 2 * static_cast<int32_t>(pQ)));
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
    //  64비트 나눗셈 대신 Q8 비율: ratio_q8=(clip<<8)/m, (I·ratio_q8)>>8 등 32비트 경로
    //  clip 상한은 아래 static_assert 및 루프 가드와 일치
    // =====================================================================
    static void soft_clip_iq(int16_t* I, int16_t* Q, int nc,
        uint32_t* mags, uint32_t* sorted) noexcept {
        if (I == nullptr || Q == nullptr || mags == nullptr ||
            sorted == nullptr) {
            return;
        }
        if (nc <= 0 || nc > 64) return;
        for (int i = 0; i < nc; ++i) { mags[i] = 0u; sorted[i] = 0u; }
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

        //  clip max = 65535 << 2 = 262140
        //  clip << 8 = 262140 × 256 = 67,107,840 < UINT32_MAX
        static_assert(
            static_cast<uint64_t>(65535u) * 4u * 256u < 0xFFFFFFFFULL,
            "clip << 8 overflows uint32_t");

        const uint32_t clip8 = clip << 8u;
        const uint32_t thresh = clip << 1u;

        //  항상 ratio 계산 + 비트마스크로 선택 (타이밍 일정)
        for (int i = 0; i < nc; ++i) {
            const uint32_t m = mags[i] | 1u;  // div-by-zero 방지 (branchless)
            const uint32_t raw_ratio = clip8 / m;
            // ratio 클램프: >255 → 255 (branchless, C4146 방지)
            const int32_t diff256 = 255 - static_cast<int32_t>(raw_ratio);
            const uint32_t over_mask = static_cast<uint32_t>(diff256 >> 31);
            const uint32_t ratio_q8 = (raw_ratio | over_mask) & 0xFFu;

            const int32_t cI = (static_cast<int32_t>(I[i]) *
                static_cast<int32_t>(ratio_q8)) >> 8;
            const int32_t cQ = (static_cast<int32_t>(Q[i]) *
                static_cast<int32_t>(ratio_q8)) >> 8;

            // mask = 0xFFFFFFFF if mags > thresh, 0 otherwise
            const int32_t diff = static_cast<int32_t>(mags[i])
                - static_cast<int32_t>(thresh) - 1;
            const int32_t mask = ~(diff >> 31);

            I[i] = static_cast<int16_t>(
                (cI & mask) | (static_cast<int32_t>(I[i]) & ~mask));
            Q[i] = static_cast<int16_t>(
                (cQ & mask) | (static_cast<int32_t>(Q[i]) & ~mask));
        }
    }

    static constexpr uint32_t k_BH_NOISE_FLOOR = 50u;   // baseline 하한 (무간섭 판별)
    static constexpr uint32_t k_BH_SATURATION = 8000u;  // baseline 상한 (ADC 포화 방어)

    void HTS_V400_Dispatcher::blackhole_(int16_t* I, int16_t* Q, int nc) noexcept {
        if (I == nullptr || Q == nullptr || nc <= 0) return;
        if (nc > 64) return;
        for (int i = 0; i < nc; ++i) { scratch_mag_[i] = 0u; scratch_sort_[i] = 0u; }
        for (int i = 0; i < nc; ++i) {
            scratch_mag_[i] = fast_abs(static_cast<int32_t>(I[i])) +
                fast_abs(static_cast<int32_t>(Q[i]));
            scratch_sort_[i] = scratch_mag_[i];
        }
        int q25 = nc >> 2;
        if (q25 < 1) q25 = 1;
        uint32_t bl = nth_select(scratch_sort_, nc, q25 - 1);
        if (bl < 1u) bl = 1u;
        if (bl < k_BH_NOISE_FLOOR || bl > k_BH_SATURATION) return;
        uint32_t punch = bl << 3u;
        for (int i = 0; i < nc; ++i) {
            const uint32_t kill = static_cast<uint32_t>(scratch_mag_[i] > punch);
            const int32_t km = -static_cast<int32_t>(kill);
            I[i] = static_cast<int16_t>(static_cast<int32_t>(I[i]) & ~km);
            Q[i] = static_cast<int16_t>(static_cast<int32_t>(Q[i]) & ~km);
        }
    }

    // =====================================================================
    //
    //
    //   → jprof_[]에 CW 파형을 직접 주입
    //   → AJC가 sym 판정 귀환 없이 첫 심볼부터 CW 제거 작동
    //   → CW 17~19dB 닭-달걀 문제 해소
    //   → ajc_enabled_ == false 시 시딩 생략 (벤치마크 분리 유지)
    //
    //  [처리 순서]
    //   1) 상관 계산: corr = Σ r[i] × lut[i%8]
    //   2) 진폭 추정: ja = corr >> 13
    //   3) 가드 체크: |ja_I| + |ja_Q| < 30 이면 조기 반환 (무간섭)
    //   4) AJC 시딩: ajc_.Seed_CW_Profile(ja_I, ja_Q)
    //   5) CW 제거: r[i] -= (ja × lut[i%8]) >> 8
    // =====================================================================
    void HTS_V400_Dispatcher::cw_cancel_64_(int16_t* I, int16_t* Q) noexcept {
        if (!cw_cancel_enabled_) { return; }
        if (I == nullptr || Q == nullptr) { return; }

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

        // Step 3: 노이즈 가드 — 비트마스크 (조기 반환 제거)
        static constexpr int32_t CW_CANCEL_NOISE_TH = 30;
        const uint32_t ja_sum = fast_abs(ja_I) + fast_abs(ja_Q);
        // active = 0xFFFFFFFF if ja_sum >= TH, 0 if below (branchless)
        const int32_t guard_diff = static_cast<int32_t>(ja_sum)
            - CW_CANCEL_NOISE_TH;
        const int32_t active = ~(guard_diff >> 31);
        // 마스킹: 노이즈 수준이면 ja=0 → 제거량=0 (동작 동일, 타이밍 일정)
        const int32_t m_ja_I = ja_I & active;
        const int32_t m_ja_Q = ja_Q & active;

        // Step 4: AJC 프로파일 시딩 (active 시에만 유효 값 전달)
        if (ajc_enabled_) {
            ajc_.Seed_CW_Profile(m_ja_I, m_ja_Q);
        }

        // Step 5: CW 제거 — branchless 포화 클램프
        for (int i = 0; i < 64; ++i) {
            const int32_t lut = static_cast<int32_t>(k_cw_lut8[i & 7u]);

            int32_t new_I = static_cast<int32_t>(I[i]) - ((m_ja_I * lut) >> 8);
            // branchless clamp to [-32767, 32767]
            const int32_t hiI = (new_I - INT16_MAX) >> 31;
            const int32_t loI = (new_I + INT16_MAX) >> 31;
            new_I = (new_I & hiI) | (INT16_MAX & ~hiI);
            new_I = (new_I & ~loI) | (static_cast<int32_t>(-INT16_MAX) & loI);
            I[i] = static_cast<int16_t>(new_I);

            int32_t new_Q = static_cast<int32_t>(Q[i]) - ((m_ja_Q * lut) >> 8);
            const int32_t hiQ = (new_Q - INT16_MAX) >> 31;
            const int32_t loQ = (new_Q + INT16_MAX) >> 31;
            new_Q = (new_Q & hiQ) | (INT16_MAX & ~hiQ);
            new_Q = (new_Q & ~loQ) | (static_cast<int32_t>(-INT16_MAX) & loQ);
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
        , harq_Q_(g_harq_Q_ccm)          // CCM 배열 포인터 연결
        , wb_{}                         // wb 유니온 (반이중 TDM)
        , ajc_(), ajc_last_nc_(0)
        , orig_acc_{}
        , orig_I_{}, orig_Q_{}
        , cw_cancel_enabled_(true)
        , ajc_enabled_(true)
        , dec_wI_{}, dec_wQ_{}
    {
    }

    HTS_V400_Dispatcher::~HTS_V400_Dispatcher() noexcept {
        // [CRIT] sizeof(*this) 통째 wipe 금지 — 멤버 역순 소멸 전 다른 서브객체 손상.
        // AntiJamEngine: 가상 함수 없음 → Reset 후 스토리지 secureWipe, 그다음 암시적 ~ (trivial).
        // 순서: CCM → full_reset_(HARQ/work 버퍼) → 칩/워킹 스크래치 → 시퀀스/시드
        //       → 콜백/메트릭 무효화 → ajc_.Reset → ajc_ 스토리지 파쇄
        SecureMemory::secureWipe(
            static_cast<void*>(g_harq_Q_ccm), sizeof(g_harq_Q_ccm));
        full_reset_();

        SecureMemory::secureWipe(static_cast<void*>(buf_I_), sizeof(buf_I_));
        SecureMemory::secureWipe(static_cast<void*>(buf_Q_), sizeof(buf_Q_));
        SecureMemory::secureWipe(static_cast<void*>(dec_wI_), sizeof(dec_wI_));
        SecureMemory::secureWipe(static_cast<void*>(dec_wQ_), sizeof(dec_wQ_));
        SecureMemory::secureWipe(
            static_cast<void*>(scratch_mag_), sizeof(scratch_mag_));
        SecureMemory::secureWipe(
            static_cast<void*>(scratch_sort_), sizeof(scratch_sort_));
        SecureMemory::secureWipe(static_cast<void*>(&seed_), sizeof(seed_));
        SecureMemory::secureWipe(static_cast<void*>(&tx_seq_), sizeof(tx_seq_));
        SecureMemory::secureWipe(static_cast<void*>(&rx_seq_), sizeof(rx_seq_));
        SecureMemory::secureWipe(
            static_cast<void*>(hdr_syms_), sizeof(hdr_syms_));

        on_pkt_ = nullptr;
        on_ctrl_ = nullptr;
        p_metrics_ = nullptr;

        ajc_.Reset(16);
        SecureMemory::secureWipe(static_cast<void*>(&ajc_), sizeof(ajc_));
        ajc_last_nc_ = 0;
    }

    void HTS_V400_Dispatcher::Set_Seed(uint32_t s) noexcept { seed_ = s; }
    void HTS_V400_Dispatcher::Set_Packet_Callback(PacketCB cb) noexcept { on_pkt_ = cb; }
    void HTS_V400_Dispatcher::Set_Control_Callback(ControlCB cb) noexcept { on_ctrl_ = cb; }
    RxPhase     HTS_V400_Dispatcher::Get_Phase()           const noexcept { return phase_; }
    PayloadMode HTS_V400_Dispatcher::Get_Mode()            const noexcept { return cur_mode_; }
    int         HTS_V400_Dispatcher::Get_Video_Fail_Count()const noexcept { return vid_fail_; }
    int         HTS_V400_Dispatcher::Get_Current_BPS64()   const noexcept { return cur_bps64_; }
    IQ_Mode     HTS_V400_Dispatcher::Get_IQ_Mode()         const noexcept { return iq_mode_; }

    void HTS_V400_Dispatcher::Update_Adaptive_BPS(uint32_t nf) noexcept {
        const int new_bps = FEC_HARQ::bps_from_nf(nf);
        if (new_bps >= FEC_HARQ::BPS64_MIN_OPERABLE &&
            new_bps <= FEC_HARQ::BPS64_MAX) {
            cur_bps64_ = new_bps;
        }
        // IQ 모드 전환은 Tick_Adaptive_BPS()에서만 수행 (히스테리시스 보장)
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

        const RxPhase prev_phase = phase_;
        const int     prev_bps   = cur_bps64_;
        const IQ_Mode prev_iq    = iq_mode_;
        uint32_t need_reset = 0u;

        const uint8_t bps = p_metrics_->current_bps.load(
            std::memory_order_acquire);

        if (bps >= static_cast<uint8_t>(FEC_HARQ::BPS64_MIN) &&
            bps <= static_cast<uint8_t>(FEC_HARQ::BPS64_MAX)) {
            const int new_bps = FEC_HARQ::bps_clamp_runtime(static_cast<int>(bps));
            if (new_bps != prev_bps) {
                cur_bps64_ = new_bps;
                need_reset |= static_cast<uint32_t>(prev_phase != RxPhase::WAIT_SYNC);
            }
        }

        // ── 적응형 I/Q 모드 전환 (히스테리시스) ──────────────
        const uint32_t nf = p_metrics_->ajc_nf.load(
            std::memory_order_acquire);

        if (nf >= NF_IQ_SAME_TH) {
            iq_mode_ = IQ_Mode::IQ_SAME;
            iq_upgrade_count_ = 0u;
            if (cur_bps64_ > FEC_HARQ::BPS64_MIN_OPERABLE) {
                cur_bps64_ = FEC_HARQ::BPS64_MIN_OPERABLE;
                need_reset |= static_cast<uint32_t>(prev_phase != RxPhase::WAIT_SYNC);
            }
            if (prev_iq != IQ_Mode::IQ_SAME) {
                need_reset |= static_cast<uint32_t>(prev_phase != RxPhase::WAIT_SYNC);
            }
        }
        else if (nf < NF_IQ_SPLIT_TH) {
            if (iq_upgrade_count_ < IQ_UPGRADE_GUARD) {
                iq_upgrade_count_++;
            }
            if (iq_upgrade_count_ >= IQ_UPGRADE_GUARD) {
                iq_mode_ = IQ_Mode::IQ_INDEPENDENT;
                if (cur_bps64_ < IQ_BPS_PEACETIME) {
                    cur_bps64_ = IQ_BPS_PEACETIME;
                    need_reset |= static_cast<uint32_t>(prev_phase != RxPhase::WAIT_SYNC);
                }
                if (prev_iq != IQ_Mode::IQ_INDEPENDENT) {
                    need_reset |= static_cast<uint32_t>(prev_phase != RxPhase::WAIT_SYNC);
                }
            }
        }
        else {
            iq_upgrade_count_ = 0u;
        }

        if (need_reset != 0u) { full_reset_(); }
    }

    void HTS_V400_Dispatcher::full_reset_() noexcept {
        // WAIT_SYNC 전이는 모든 상태에서 무조건 합법
        phase_ = RxPhase::WAIT_SYNC;
        cur_mode_ = PayloadMode::UNKNOWN;
        buf_idx_ = 0; pre_phase_ = 0;
        wait_sync_head_ = 0;
        wait_sync_count_ = 0;
        hdr_count_ = 0; hdr_fail_ = 0;
        pay_recv_ = 0; v1_idx_ = 0;
        sym_idx_ = 0; harq_round_ = 0;
        harq_inited_ = false;
        SecureMemory::secureWipe(static_cast<void*>(&rx_), sizeof(rx_));
        SecureMemory::secureWipe(static_cast<void*>(v1_rx_), sizeof(v1_rx_));
        SecureMemory::secureWipe(static_cast<void*>(orig_I_), sizeof(orig_I_));
        SecureMemory::secureWipe(static_cast<void*>(orig_Q_), sizeof(orig_Q_));
        SecureMemory::secureWipe(static_cast<void*>(&orig_acc_), sizeof(orig_acc_));
        SecureMemory::secureWipe(static_cast<void*>(&wb_), sizeof(wb_));
        if (harq_Q_ != nullptr) {
            SecureMemory::secureWipe(
                static_cast<void*>(harq_Q_), sizeof(g_harq_Q_ccm));
        }
    }

    // =====================================================================
    //
    //  CFI: key=(from<<2)|to, 12슬롯 LUT + 인덱스 클램프, 반환 풀비트 마스크
    // =====================================================================
    uint32_t HTS_V400_Dispatcher::set_phase_(RxPhase target) noexcept {
        const uint32_t f = static_cast<uint32_t>(phase_);
        const uint32_t t = static_cast<uint32_t>(target);
        const uint32_t key = (f << 2u) | t;

        // LUT + 클램프 인덱스 — key 글리치 시에도 OOB 없음 (>=12 → 슬롯 11 = 불법)
        static constexpr uint8_t k_trans_legal[12] = {
            1u, 1u, 0u, 0u,
            1u, 0u, 1u, 0u,
            1u, 0u, 0u, 0u
        };
        const uint32_t k_ok = static_cast<uint32_t>(key < 12u);
        const uint32_t idx = key * k_ok + 11u * (1u - k_ok);
        const uint32_t legal_u = static_cast<uint32_t>(k_trans_legal[idx]);

        if (legal_u != 0u) {
            phase_ = target;
            return PHASE_TRANSFER_MASK_OK;
        }

        full_reset_();
        return PHASE_TRANSFER_MASK_FAIL;
    }

    void HTS_V400_Dispatcher::Reset() noexcept {
        full_reset_();
        ajc_.Reset(16);
        ajc_last_nc_ = 0;
    }

    uint32_t HTS_V400_Dispatcher::parse_hdr_(PayloadMode& mode, int& plen) noexcept {
        const uint16_t hdr = (static_cast<uint16_t>(hdr_syms_[0]) << 6u) |
            static_cast<uint16_t>(hdr_syms_[1]);

        const uint8_t mb = static_cast<uint8_t>((hdr >> 10u) & 0x03u);
        const uint32_t rx_iq_split = static_cast<uint32_t>((hdr & HDR_IQ_BIT) != 0u);
        plen = static_cast<int>(hdr & 0x01FFu);

        iq_mode_ = static_cast<IQ_Mode>(
            static_cast<uint32_t>(IQ_Mode::IQ_INDEPENDENT) * rx_iq_split
            + static_cast<uint32_t>(IQ_Mode::IQ_SAME) * (1u - rx_iq_split));

        static constexpr PayloadMode k_hdr_modes[4] = {
            PayloadMode::VIDEO_1,
            PayloadMode::VIDEO_16,
            PayloadMode::VOICE,
            PayloadMode::DATA,
        };
        mode = k_hdr_modes[static_cast<size_t>(mb & 3u)];

        const uint32_t m0 = static_cast<uint32_t>(mb == 0u);
        const uint32_t m1 = static_cast<uint32_t>(mb == 1u);
        const uint32_t m2 = static_cast<uint32_t>(mb == 2u);
        const uint32_t m3 = static_cast<uint32_t>(mb == 3u);
        const uint32_t plen_ok_v1 = static_cast<uint32_t>(plen == FEC_HARQ::NSYM1);
        const uint32_t plen_ok_v16 = static_cast<uint32_t>(plen == FEC_HARQ::NSYM16);

        const int bps = FEC_HARQ::bps_from_nsym(plen);
        const uint32_t bps_ge =
            static_cast<uint32_t>(bps >= FEC_HARQ::BPS64_MIN_OPERABLE);
        const uint32_t bps_le = static_cast<uint32_t>(bps <= FEC_HARQ::BPS64_MAX);
        const uint32_t plen_sym =
            static_cast<uint32_t>(plen == FEC_HARQ::nsym_for_bps(bps));
        const uint32_t data_ok = m3 & bps_ge & bps_le & plen_sym;

        const uint32_t ok_u =
            (m0 & plen_ok_v1) | (m1 & plen_ok_v16) | (m2 & plen_ok_v16) | data_ok;

        const int d_int = static_cast<int>(data_ok);
        cur_bps64_ = bps * d_int + cur_bps64_ * (1 - d_int);

        return static_cast<uint32_t>(0u - ok_u);
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

            if (cur_mode_ == PayloadMode::DATA) {
                cw_cancel_64_(buf_I_, buf_Q_);
            }

            if (ajc_enabled_) {
                ajc_.Process(buf_I_, buf_Q_, nc);
            }
            soft_clip_iq(buf_I_, buf_Q_, nc, scratch_mag_, scratch_sort_);

            if (nc == 16) {
                if (sym_idx_ < FEC_HARQ::NSYM16) {
                    FEC_HARQ::Feed16_1sym(rx_.m16, buf_I_, buf_Q_, sym_idx_);

                    for (int c = 0; c < nc; ++c) {
                        const uint8_t hiI = static_cast<uint8_t>(
                            (orig_I_[c] >> 12) & 0x0Fu);
                        const uint8_t hiQ = static_cast<uint8_t>(
                            (orig_Q_[c] >> 12) & 0x0Fu);
                        orig_acc_.acc16.iq4[sym_idx_][c] =
                            static_cast<uint8_t>((hiI << 4u) | hiQ);
                    }
                    sym_idx_++;
                }
                else { full_reset_(); return; }
            }
            else {
                const int nsym64 = cur_nsym64_();

                if (iq_mode_ == IQ_Mode::IQ_INDEPENDENT) {
                    // ── [적응형 I/Q] I/Q 독립 RX: 칩슬롯당 2심볼 ──
                    //  I 채널 → 짝수 sym_idx_, Q 채널 → 홀수 sym_idx_
                    //  HARQ I 누적기: 짝수 심볼 전용
                    //  HARQ Q 누적기: 홀수 심볼 전용
                    const int si_I = sym_idx_;      // I 채널 심볼 인덱스
                    const int si_Q = sym_idx_ + 1;  // Q 채널 심볼 인덱스

                    if (si_Q < nsym64) {
                        // I 채널 HARQ 누적 (짝수 심볼)
                        for (int c = 0; c < nc; ++c) {
                            rx_.m64_I.aI[si_I][c] +=
                                static_cast<int32_t>(buf_I_[c]);
                        }
                        // Q 채널 HARQ 누적 (홀수 심볼)
                        for (int c = 0; c < nc; ++c) {
                            rx_.m64_I.aI[si_Q][c] +=
                                static_cast<int32_t>(buf_Q_[c]);
                        }

                        for (int c = 0; c < nc; ++c) {
                            const uint8_t hiI = static_cast<uint8_t>(
                                (orig_I_[c] >> 12) & 0x0Fu);
                            orig_acc_.acc64.iq4[si_I][c] =
                                static_cast<uint8_t>(hiI << 4u);
                            const uint8_t hiQ = static_cast<uint8_t>(
                                (orig_Q_[c] >> 12) & 0x0Fu);
                            orig_acc_.acc64.iq4[si_Q][c] =
                                static_cast<uint8_t>(hiQ << 4u);
                        }
                        sym_idx_ += 2;
                        pay_recv_++;  // 칩슬롯 기준 카운트
                    }
                    else { full_reset_(); return; }
                }
                else {
                    // ── I=Q 동일 모드 (기존) ──
                    if (sym_idx_ < nsym64) {
                        for (int c = 0; c < nc; ++c) {
                            rx_.m64_I.aI[sym_idx_][c] +=
                                static_cast<int32_t>(buf_I_[c]);
                        }
                        for (int c = 0; c < nc; ++c) {
                            harq_Q_[sym_idx_][c] +=
                                static_cast<int32_t>(buf_Q_[c]);
                        }

                        for (int c = 0; c < nc; ++c) {
                            const uint8_t hiI = static_cast<uint8_t>(
                                (orig_I_[c] >> 12) & 0x0Fu);
                            const uint8_t hiQ = static_cast<uint8_t>(
                                (orig_Q_[c] >> 12) & 0x0Fu);
                            orig_acc_.acc64.iq4[sym_idx_][c] =
                                static_cast<uint8_t>((hiI << 4u) | hiQ);
                        }
                        sym_idx_++;
                    }
                    else { full_reset_(); return; }
                }
            }

            // [적응형 I/Q] AJC 피드백: IQ 모드에 따라 디코딩 방식 분기
            if (iq_mode_ == IQ_Mode::IQ_INDEPENDENT && nc == 64) {
                // I/Q 독립: 각 채널 분리 FWHT → 2심볼 디코딩
                SymDecResultSplit rs = walsh_dec_split_(buf_I_, buf_Q_, nc);
                if (ajc_enabled_) {
                    // I/Q 독립: 채널별 Update_AJC (sym_Q=-1이면 내부에서 갱신 스킵 가능)

                    // ① I 채널 AJC 갱신
                    ajc_.Update_AJC(orig_I_, orig_Q_,
                        rs.sym_I, rs.best_eI, rs.second_eI, nc);

                    // ② Q 채널 AJC 갱신
                    ajc_.Update_AJC(orig_I_, orig_Q_,
                        rs.sym_Q, rs.best_eQ, rs.second_eQ, nc);
                }
            }
            else {
                // I=Q 동일: 결합 FWHT
                SymDecResult r = walsh_dec_full_(buf_I_, buf_Q_, nc);
                if (ajc_enabled_) {
                    ajc_.Update_AJC(orig_I_, orig_Q_,
                        r.sym, r.best_e, r.second_e, nc);
                }
            }
        }

        buf_idx_ = 0;
        if (pay_recv_ >= pay_total_) try_decode_();
    }

    void HTS_V400_Dispatcher::try_decode_() noexcept {
        DecodedPacket pkt = {};
        pkt.mode = cur_mode_;
        pkt.success_mask = DecodedPacket::DECODE_MASK_FAIL;
        uint32_t il = seed_ ^ (rx_seq_ * 0xA5A5A5A5u);

        if (cur_mode_ == PayloadMode::VIDEO_1) {
            pkt.success_mask = static_cast<uint32_t>(0u
                - static_cast<uint32_t>(
                    FEC_HARQ::Decode1(v1_rx_, pkt.data, &pkt.data_len)));
            pkt.harq_k = 1;
            handle_video_(pkt.success_mask);
            if (on_pkt_ != nullptr) { on_pkt_(pkt); }
            rx_seq_++; full_reset_();
        }
        else if (cur_mode_ == PayloadMode::VIDEO_16 ||
            cur_mode_ == PayloadMode::VOICE) {
            FEC_HARQ::Advance_Round_16(rx_.m16);
            harq_round_++;
            pkt.success_mask = static_cast<uint32_t>(0u
                - static_cast<uint32_t>(FEC_HARQ::Decode16(rx_.m16, pkt.data,
                    &pkt.data_len, il, wb_)));
            pkt.harq_k = harq_round_;
            const uint32_t dec_ok =
                static_cast<uint32_t>(pkt.success_mask != 0u);
            const uint32_t harq_ex =
                static_cast<uint32_t>(harq_round_ >= max_harq_);
            const uint32_t finish = dec_ok | harq_ex;
            if (finish != 0u) {
                if (dec_ok != 0u) {
                    harq_feedback_seed_(pkt.data, pkt.data_len, 16, il);
                }
                if (cur_mode_ == PayloadMode::VIDEO_16) {
                    handle_video_(pkt.success_mask);
                }
                if (on_pkt_ != nullptr) { on_pkt_(pkt); }
                rx_seq_++; full_reset_();
            }
            else { pay_recv_ = 0; sym_idx_ = 0; set_phase_(RxPhase::WAIT_SYNC); }
        }
        else if (cur_mode_ == PayloadMode::DATA) {
            if (!rx_.m64_I.ok) rx_.m64_I.k++;
            harq_round_++;

            {
                const int bps = cur_bps64_;
                if (bps >= FEC_HARQ::BPS64_MIN_OPERABLE &&
                    bps <= FEC_HARQ::BPS64_MAX) {
                    const int nsym = FEC_HARQ::nsym_for_bps(bps);
                    pkt.success_mask = static_cast<uint32_t>(0u
                        - static_cast<uint32_t>(FEC_HARQ::Decode_Core_Split(
                            &rx_.m64_I.aI[0][0],
                            harq_Q_[0],
                            nsym, FEC_HARQ::C64, bps,
                            pkt.data, &pkt.data_len, il, wb_)));
                }
            }
            pkt.harq_k = harq_round_;
            const uint32_t dec_ok =
                static_cast<uint32_t>(pkt.success_mask != 0u);
            const uint32_t harq_ex =
                static_cast<uint32_t>(harq_round_ >= max_harq_);
            const uint32_t finish = dec_ok | harq_ex;
            if (finish != 0u) {
                if (dec_ok != 0u) {
                    rx_.m64_I.ok = true;
                    harq_feedback_seed_(pkt.data, pkt.data_len, 64, il);
                }
                if (on_pkt_ != nullptr) { on_pkt_(pkt); }
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
                data, data_len, correct_syms, il, wb_);
            if (enc_n <= 0) {
                SecureMemory::secureWipe(
                    static_cast<void*>(correct_syms), sizeof(correct_syms));
                return;
            }
            const int nsym = (sym_idx_ < FEC_HARQ::NSYM16)
                ? sym_idx_ : FEC_HARQ::NSYM16;
            for (int s = 0; s < nsym; ++s) {
                if (ajc_enabled_) {
                    int16_t tmp_I[16], tmp_Q[16];
                    for (int c = 0; c < nc; ++c) {
                        const uint8_t pk = orig_acc_.acc16.iq4[s][c];
                        int32_t nI = static_cast<int32_t>((pk >> 4u) & 0x0Fu);
                        nI -= ((nI & 0x8) << 1);
                        tmp_I[c] = static_cast<int16_t>(nI << 12);
                        int32_t nQ = static_cast<int32_t>(pk & 0x0Fu);
                        nQ -= ((nQ & 0x8) << 1);
                        tmp_Q[c] = static_cast<int16_t>(nQ << 12);
                    }
                    ajc_.Update_AJC(tmp_I, tmp_Q,
                        static_cast<int8_t>(correct_syms[s]),
                        0xFFFFFFFFu, 0u, nc, true);
                }
            }
            SecureMemory::secureWipe(
                static_cast<void*>(correct_syms), sizeof(correct_syms));
        }
        else if (nc == 64) {
            const int nsym64 = cur_nsym64_();
            uint8_t correct_syms[FEC_HARQ::NSYM64] = {};
            const int enc_n = FEC_HARQ::Encode64_A(
                data, data_len, correct_syms, il, cur_bps64_, wb_);
            if (enc_n <= 0) {
                SecureMemory::secureWipe(
                    static_cast<void*>(correct_syms), sizeof(correct_syms));
                return;
            }
            const int nsym = (sym_idx_ < nsym64) ? sym_idx_ : nsym64;
            for (int s = 0; s < nsym; ++s) {
                if (ajc_enabled_) {
                    for (int c = 0; c < nc; ++c) {
                        const uint8_t pk = orig_acc_.acc64.iq4[s][c];
                        int32_t nI = static_cast<int32_t>((pk >> 4u) & 0x0Fu);
                        nI -= ((nI & 0x8) << 1);
                        orig_I_[c] = static_cast<int16_t>(nI << 12);
                        int32_t nQ = static_cast<int32_t>(pk & 0x0Fu);
                        nQ -= ((nQ & 0x8) << 1);
                        orig_Q_[c] = static_cast<int16_t>(nQ << 12);
                    }
                    ajc_.Update_AJC(orig_I_, orig_Q_,
                        static_cast<int8_t>(correct_syms[s]),
                        0xFFFFFFFFu, 0u, nc, true);
                }
            }
            SecureMemory::secureWipe(
                static_cast<void*>(correct_syms), sizeof(correct_syms));
        }
    }

    void HTS_V400_Dispatcher::handle_video_(uint32_t decode_ok_mask) noexcept {
        const uint32_t ok = decode_ok_mask & 1u;
        if (ok != 0u) {
            vid_succ_++; vid_fail_ = 0;
            if (active_video_ == PayloadMode::VIDEO_16 &&
                vid_succ_ >= VIDEO_RECOVER_TH) {
                active_video_ = PayloadMode::VIDEO_1; vid_succ_ = 0;
                if (on_ctrl_ != nullptr) { on_ctrl_(PayloadMode::VIDEO_1); }
            }
        }
        else {
            vid_fail_++; vid_succ_ = 0;
            if (active_video_ == PayloadMode::VIDEO_1 &&
                vid_fail_ >= VIDEO_FAIL_TH) {
                active_video_ = PayloadMode::VIDEO_16; vid_fail_ = 0;
                if (on_ctrl_ != nullptr) { on_ctrl_(PayloadMode::VIDEO_16); }
            }
        }
    }

    int HTS_V400_Dispatcher::Build_Packet(PayloadMode mode,
        const uint8_t* info, int ilen, int16_t amp,
        int16_t* oI, int16_t* oQ, int max_c) noexcept {
        if (info == nullptr || oI == nullptr || oQ == nullptr) return 0;
        if (ilen < 0 || max_c <= 0) return 0;
        int pos = 0;
        if (pos + 128 > max_c) return 0;
        walsh_enc(PRE_SYM0, 64, amp, &oI[pos], &oQ[pos]); pos += 64;
        walsh_enc(PRE_SYM1, 64, amp, &oI[pos], &oQ[pos]); pos += 64;

        static constexpr uint8_t k_tx_mb[4] = { 0u, 1u, 2u, 3u };
        static constexpr int k_tx_psyms[4] = {
            FEC_HARQ::NSYM1,
            FEC_HARQ::NSYM16,
            FEC_HARQ::NSYM16,
            0
        };
        const uint32_t mi = static_cast<uint32_t>(mode);
        if (mi > 3u) { return 0; }
        const uint8_t mb = k_tx_mb[mi];
        const int psyms = (mi == 3u) ? cur_nsym64_() : k_tx_psyms[mi];

        // [적응형 I/Q] 헤더: [mode 2bit][IQ 1bit][plen 9bit] = 12bit
        //  프리앰블+헤더는 항상 I=Q 고정 (walsh_enc = oI=oQ)
        //  IQ 비트는 뒤따르는 페이로드의 I/Q 모드를 수신기에 알림
        const uint16_t iq_bit =
            (iq_mode_ == IQ_Mode::IQ_INDEPENDENT) ? HDR_IQ_BIT : 0u;
        uint16_t hdr = (static_cast<uint16_t>(mb & 0x03u) << 10u) |
            iq_bit |
            (static_cast<uint16_t>(psyms) & 0x01FFu);
        if (pos + 128 > max_c) return 0;
        walsh_enc(static_cast<uint8_t>((hdr >> 6u) & 0x3Fu), 64, amp,
            &oI[pos], &oQ[pos]); pos += 64;
        walsh_enc(static_cast<uint8_t>(hdr & 0x3Fu), 64, amp,
            &oI[pos], &oQ[pos]); pos += 64;

        uint32_t il = seed_ ^ (tx_seq_ * 0xA5A5A5A5u);

        if (mode == PayloadMode::VIDEO_1) {
            uint8_t syms[80] = {};
            int n = FEC_HARQ::Encode1(info, ilen, syms);
            if (n <= 0) {
                SecureMemory::secureWipe(static_cast<void*>(syms), sizeof(syms));
                return 0;
            }
            {
                const int space = max_c - pos;
                if (space < n) {
                    SecureMemory::secureWipe(static_cast<void*>(syms), sizeof(syms));
                    return 0;
                }
            }
            for (int s = 0; s < n; ++s) {
                oI[pos] = syms[s] ? static_cast<int16_t>(-amp) : amp;
                oQ[pos] = oI[pos]; pos++;
            }
            SecureMemory::secureWipe(static_cast<void*>(syms), sizeof(syms));
        }
        else if (mode == PayloadMode::VIDEO_16 || mode == PayloadMode::VOICE) {
            uint8_t syms[FEC_HARQ::NSYM16] = {};
            const int enc_n = FEC_HARQ::Encode16(info, ilen, syms, il, wb_);
            if (enc_n <= 0) {
                SecureMemory::secureWipe(static_cast<void*>(syms), sizeof(syms));
                return 0;
            }
            for (int s = 0; s < FEC_HARQ::NSYM16; ++s) {
                const int space = max_c - pos;
                if (space < 16) {
                    SecureMemory::secureWipe(static_cast<void*>(syms), sizeof(syms));
                    return 0;
                }
                walsh_enc(syms[s], 16, amp, &oI[pos], &oQ[pos]); pos += 16;
            }
            SecureMemory::secureWipe(static_cast<void*>(syms), sizeof(syms));
        }
        else if (mode == PayloadMode::DATA) {
            const int nsym = cur_nsym64_();
            uint8_t syms[FEC_HARQ::NSYM64] = {};
            const int enc_n = FEC_HARQ::Encode64_A(
                info, ilen, syms, il, cur_bps64_, wb_);
            if (enc_n <= 0) {
                SecureMemory::secureWipe(static_cast<void*>(syms), sizeof(syms));
                return 0;
            }

            if (iq_mode_ == IQ_Mode::IQ_INDEPENDENT) {
                // [적응형 I/Q] I/Q 독립: 2심볼/칩슬롯 → 칩 수 절반
                //  짝수 인덱스 → I 채널, 홀수 인덱스 → Q 채널
                for (int s = 0; s < nsym; s += 2) {
                    const int space = max_c - pos;
                    if (space < 64) {
                        SecureMemory::secureWipe(static_cast<void*>(syms), sizeof(syms));
                        return 0;
                    }
                    const uint8_t sI = syms[s];
                    const uint8_t sQ = (s + 1 < nsym)
                        ? syms[s + 1] : 0u;  // 홀수 심볼일 때 패딩
                    walsh_enc_split(sI, sQ, 64, amp,
                        &oI[pos], &oQ[pos]);
                    pos += 64;
                }
            }
            else {
                // I=Q 동일: 기존 방식 (재밍 방어)
                for (int s = 0; s < nsym; ++s) {
                    const int space = max_c - pos;
                    if (space < 64) {
                        SecureMemory::secureWipe(static_cast<void*>(syms), sizeof(syms));
                        return 0;
                    }
                    walsh_enc(syms[s], 64, amp,
                        &oI[pos], &oQ[pos]);
                    pos += 64;
                }
            }
            SecureMemory::secureWipe(static_cast<void*>(syms), sizeof(syms));
        }
        tx_seq_++;
        return pos;
    }

    void HTS_V400_Dispatcher::Feed_Chip(int16_t rx_I, int16_t rx_Q) noexcept {
        if (phase_ == RxPhase::WAIT_SYNC) {
            if (wait_sync_count_ >= 64) return;
            const int widx = (wait_sync_head_ + wait_sync_count_) & 63;
            buf_I_[widx] = rx_I;
            buf_Q_[widx] = rx_Q;
            wait_sync_count_++;
            if (wait_sync_count_ < 64) return;

            for (int j = 0; j < 64; ++j) {
                const int p = (wait_sync_head_ + j) & 63;
                orig_I_[j] = buf_I_[p];
                orig_Q_[j] = buf_Q_[p];
            }

            cw_cancel_64_(orig_I_, orig_Q_);
            if (ajc_enabled_) { ajc_.Process(orig_I_, orig_Q_, 64); }
            soft_clip_iq(orig_I_, orig_Q_, 64, scratch_mag_, scratch_sort_);

            SymDecResult r0 = walsh_dec_full_(orig_I_, orig_Q_, 64);
            int8_t sym = r0.sym;
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
            if (matched) {
                wait_sync_head_ = 0;
                wait_sync_count_ = 0;
                buf_idx_ = 0;
            }
            else {
                wait_sync_head_ = (wait_sync_head_ + 1) & 63;
                wait_sync_count_ = 63;
            }
            return;
        }

        if (buf_idx_ >= 64) return;
        buf_I_[buf_idx_] = rx_I; buf_Q_[buf_idx_] = rx_Q; buf_idx_++;

        if (phase_ == RxPhase::READ_HEADER) {
            if (buf_idx_ == 64) {
                std::memcpy(orig_I_, buf_I_, 64 * sizeof(int16_t));
                std::memcpy(orig_Q_, buf_Q_, 64 * sizeof(int16_t));

                cw_cancel_64_(orig_I_, orig_Q_);
                if (ajc_enabled_) { ajc_.Process(orig_I_, orig_Q_, 64); }
                soft_clip_iq(orig_I_, orig_Q_, 64, scratch_mag_, scratch_sort_);

                SymDecResult rh = walsh_dec_full_(orig_I_, orig_Q_, 64);
                int8_t sym = rh.sym;
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
                    if (parse_hdr_(mode, plen) != 0u) {
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

                        //  try_decode_ 내부에서 Init → Feed 이후라 데이터 파괴
                        //  READ_PAYLOAD 진입 시 첫 라운드만 Init
                        if (!harq_inited_) {
                            if (mode == PayloadMode::VIDEO_16 ||
                                mode == PayloadMode::VOICE) {
                                FEC_HARQ::Init16(rx_.m16);
                            }
                            else if (mode == PayloadMode::DATA) {
                                SecureMemory::secureWipe(
                                    static_cast<void*>(rx_.m64_I.aI),
                                    sizeof(rx_.m64_I.aI));
                                rx_.m64_I.k = 0;
                                rx_.m64_I.ok = false;
                                if (harq_Q_ != nullptr) {
                                    SecureMemory::secureWipe(
                                        static_cast<void*>(harq_Q_),
                                        sizeof(g_harq_Q_ccm));
                                }
                            }
                            harq_inited_ = true;
                        }

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
