// =============================================================================
// HTS_V400_Dispatcher.cpp — V400 동적 모뎀 디스패처 + 3층 항재밍 통합
//
// [동작 메모]
//  cw_cancel_64_: ja_I/ja_Q 추정 후 ajc_.Seed_CW_Profile — 첫 심볼부터 CW 제거
//  try_decode_: Q채널 HARQ는 harq_Q_[0] (행 포인터)로 Decode_Core_Split에 전달
//               (&harq_Q_[0][0] 금지 — 2차원 배열 타입과 혼동 시 HardFault)
//
#include "HTS_V400_Dispatcher.hpp"
#include "HTS_RF_Metrics.h" // Tick_Adaptive_BPS 용
#include "HTS_Secure_Memory.h"
#include <atomic>
#include <climits>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstddef>
// [진단] Barrage30 등 PC 하네스 — ir_chip_I_[0]·harq_round_ 스냅샷 (기본
// 0=비활성)
extern "C" volatile int g_hts_ir_diag_chip0 = 0;
extern "C" volatile int g_hts_ir_diag_feed_idx = -1;
extern "C" void Mock_RF_Synth_Set_Channel(uint8_t channel) noexcept {
    const unsigned ch = static_cast<unsigned>(channel) & 0x7Fu;
    std::printf("[Mock_RF_Synth] ch=%u\n", ch);
}
namespace ProtectedEngine {
// 파일 범위 스크래치: 단일 디스패처 실행 컨텍스트(반이중)·해당 경로 재진입 없음
// 가정. NSYM64 ≥ NSYM16 이므로 Encode 심볼 버퍼 겸용.
alignas(64) static uint8_t g_v400_sym_scratch[FEC_HARQ::NSYM64];
alignas(16) static int16_t g_v400_harq_fb_tmp_I[16];
alignas(16) static int16_t g_v400_harq_fb_tmp_Q[16];
static_assert(sizeof(g_v400_sym_scratch) >= FEC_HARQ::NSYM16,
              "sym scratch must cover NSYM16 encode");
// ── HARQ CCM union: Chase Q 누적 ↔ IR 칩 버퍼 + IR_RxState (SRAM 추가 0) ─
//  Chase: harq_Q[NSYM64][C64] int32 — 기존 g_harq_Q_ccm 와 동일 레이아웃
//  IR:    chip_I/chip_Q int16 + IR_RxState — 모드 전환 시 full_reset_ 에서 전체
//  wipe
struct V400HarqCcmChase {
    int32_t harq_Q[FEC_HARQ::NSYM64][FEC_HARQ::C64];
};
struct V400HarqCcmIr {
    int16_t chip_I[FEC_HARQ::NSYM64][FEC_HARQ::C64];
    int16_t chip_Q[FEC_HARQ::NSYM64][FEC_HARQ::C64];
    FEC_HARQ::IR_RxState ir_state;
};
alignas(64) HTS_CCM_SECTION static union {
    V400HarqCcmChase chase;
    V400HarqCcmIr ir;
} g_harq_ccm_union;
static_assert(sizeof(g_harq_ccm_union) >= sizeof(V400HarqCcmChase),
              "CCM union must hold Chase harq_Q");
static_assert(sizeof(g_harq_ccm_union) >= sizeof(V400HarqCcmIr),
              "CCM union must hold IR chip buffers + IR_RxState");
static_assert(sizeof(int16_t) == 2, "int16_t must be 2 bytes");
static_assert(sizeof(int32_t) == 4, "int32_t must be 4 bytes");
static_assert(sizeof(uint64_t) == 8, "uint64_t required for FWHT energy");
// IR 64칩 SIC: 다음 라운드 수신 칩에서 Walsh 예상 성분 감산 (CCM 외 정적, 칩
// 버퍼와 동일 차원)
alignas(64) static int16_t g_sic_exp_I[FEC_HARQ::NSYM64][FEC_HARQ::C64];
alignas(64) static int16_t g_sic_exp_Q[FEC_HARQ::NSYM64][FEC_HARQ::C64];
// ── [BUG-FIX-PRE2] 프리앰블 연판정 누적 버퍼 ──
//  pre_reps_ 반복 프리앰블의 칩 레벨 I/Q 누적
//  FWHT는 누적 완료 후 1회만 수행 → 신호 coherent ×N, 잡음 √N
alignas(64) static int32_t g_pre_acc_I[64] = {};
alignas(64) static int32_t g_pre_acc_Q[64] = {};
static int g_pre_acc_n = 0;
// ── Q8 사인파 LUT (sin(2π×k/8)×256) ──
// AntiJamEngine.cpp의 k_cw_lut8와 동일한 값 — 두 모듈 일관성 유지
static constexpr int16_t k_cw_lut8[8] = {0, 181, 256, 181, 0, -181, -256, -181};
static constexpr uint32_t popc32(uint32_t x) noexcept {
    x = x - ((x >> 1u) & 0x55555555u);
    x = (x & 0x33333333u) + ((x >> 2u) & 0x33333333u);
    return (((x + (x >> 4u)) & 0x0F0F0F0Fu) * 0x01010101u) >> 24u;
}
static constexpr uint32_t fast_abs(int32_t x) noexcept {
    const uint32_t m = 0u - static_cast<uint32_t>(x < 0);
    return (static_cast<uint32_t>(x) ^ m) + m;
}
static void fwht_raw(int32_t *d, int n) noexcept {
    if (n == 64) {
        for (int i = 0; i < 64; i += 2) {
            int32_t u = d[i], v = d[i + 1];
            d[i] = u + v;
            d[i + 1] = u - v;
        }
        for (int i = 0; i < 64; i += 4) {
            int32_t u = d[i], v = d[i + 2];
            d[i] = u + v;
            d[i + 2] = u - v;
            u = d[i + 1];
            v = d[i + 3];
            d[i + 1] = u + v;
            d[i + 3] = u - v;
        }
        for (int i = 0; i < 64; i += 8) {
            for (int k = 0; k < 4; ++k) {
                int32_t u = d[i + k], v = d[i + 4 + k];
                d[i + k] = u + v;
                d[i + 4 + k] = u - v;
            }
        }
        for (int i = 0; i < 64; i += 16) {
            for (int k = 0; k < 8; ++k) {
                int32_t u = d[i + k], v = d[i + 8 + k];
                d[i + k] = u + v;
                d[i + 8 + k] = u - v;
            }
        }
        for (int i = 0; i < 64; i += 32) {
            for (int k = 0; k < 16; ++k) {
                int32_t u = d[i + k], v = d[i + 16 + k];
                d[i + k] = u + v;
                d[i + 16 + k] = u - v;
            }
        }
        for (int k = 0; k < 32; ++k) {
            int32_t u = d[k], v = d[k + 32];
            d[k] = u + v;
            d[k + 32] = u - v;
        }
        return;
    }
    if (n == 16) {
        for (int i = 0; i < 16; i += 2) {
            int32_t u = d[i], v = d[i + 1];
            d[i] = u + v;
            d[i + 1] = u - v;
        }
        for (int i = 0; i < 16; i += 4) {
            int32_t u = d[i], v = d[i + 2];
            d[i] = u + v;
            d[i + 2] = u - v;
            u = d[i + 1];
            v = d[i + 3];
            d[i + 1] = u + v;
            d[i + 3] = u - v;
        }
        for (int i = 0; i < 16; i += 8) {
            for (int k = 0; k < 4; ++k) {
                int32_t u = d[i + k], v = d[i + 4 + k];
                d[i + k] = u + v;
                d[i + 4 + k] = u - v;
            }
        }
        for (int k = 0; k < 8; ++k) {
            int32_t u = d[k], v = d[k + 8];
            d[k] = u + v;
            d[k + 8] = u - v;
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
alignas(64) static const int16_t k_walsh_dummy_iq_[64] = {};
// ── [BUG-FIX-PRE1] 부호 상관 기반 심볼 검출 ──
//  기존: max(fI²+fQ²) → 제곱이 부호 파괴 → 잡음 빈 63개 중 1개가 신호 초과 시
//  오검출 수정: max(fI+fQ)   → TX가 I=Q 동일 전송 → 신호 항상 양수, 잡음 ±상쇄
//  효과: 프리앰블·헤더·페이로드 심볼 검출 한계 ~10dB 확장
//  best_e/second_e: AJC 호환용 에너지 (검출된 빈의 I²+Q² 그대로 산출)
HTS_V400_Dispatcher::SymDecResult
HTS_V400_Dispatcher::walsh_dec_full_(const int16_t *I, const int16_t *Q, int n,
                                     bool cap_search_to_bps) noexcept {
    const uint32_t p_ok =
        static_cast<uint32_t>((I != nullptr) & (Q != nullptr) &
                              static_cast<uint32_t>((n == 16) | (n == 64)));
    const int n_eff = ((n == 16) | (n == 64)) ? n : 64;
    const int16_t *srcI = (p_ok != 0u) ? I : k_walsh_dummy_iq_;
    const int16_t *srcQ = (p_ok != 0u) ? Q : k_walsh_dummy_iq_;
    for (int i = 0; i < n_eff; ++i) {
        dec_wI_[i] = srcI[i];
        dec_wQ_[i] = srcQ[i];
    }
    fwht_raw(dec_wI_, n_eff);
    fwht_raw(dec_wQ_, n_eff);
    int search = n_eff;
    if (cap_search_to_bps && n_eff == 64) {
        const int bps = cur_bps64_;
        const int valid = 1 << bps;
        search = (valid < n_eff) ? valid : n_eff;
    }
    // ── 부호 상관 기반 피크 탐색 (branchless) ──
    //  corr = fI + fQ: TX가 I=Q이므로 신호 빈은 항상 양수 편향
    //  잡음 빈: 평균 0 → 신호 빈이 최대 상관값
    //  max|corr| = 2 × 64 × 32767 = 4,194,176 < INT32_MAX ✓
    int32_t best_c = INT32_MIN;
    int32_t second_c = INT32_MIN;
    uint8_t dec = 0xFFu;
    uint8_t dec2 = 0xFFu;
    for (int m = 0; m < search; ++m) {
        const int32_t c =
            static_cast<int32_t>(dec_wI_[m]) + static_cast<int32_t>(dec_wQ_[m]);
        // 0/1 플래그 → 0x00000000/0xFFFFFFFF 풀 마스크 변환
        const uint32_t m_gt_best = 0u - static_cast<uint32_t>(c > best_c);
        const uint32_t m_gt_sec =
            0u - ((~m_gt_best & 1u) & static_cast<uint32_t>(c > second_c));
        const uint32_t m_none = ~(m_gt_best | m_gt_sec);
        // second 갱신: best가 밀려오거나 sec 직접 갱신
        second_c =
            static_cast<int32_t>((static_cast<uint32_t>(best_c) & m_gt_best) |
                                 (static_cast<uint32_t>(c) & m_gt_sec) |
                                 (static_cast<uint32_t>(second_c) & m_none));
        dec2 = static_cast<uint8_t>((static_cast<uint32_t>(dec) & m_gt_best) |
                                    (static_cast<uint32_t>(m) & m_gt_sec) |
                                    (static_cast<uint32_t>(dec2) & m_none));
        // best 갱신
        best_c =
            static_cast<int32_t>((static_cast<uint32_t>(c) & m_gt_best) |
                                 (static_cast<uint32_t>(best_c) & ~m_gt_best));
        dec = static_cast<uint8_t>((static_cast<uint32_t>(m) & m_gt_best) |
                                   (static_cast<uint32_t>(dec) & ~m_gt_best));
    }
    const int32_t mk = -static_cast<int32_t>(p_ok);
    const int8_t sym_raw = (best_c == INT32_MIN) ? static_cast<int8_t>(-1)
                                                 : static_cast<int8_t>(dec);
    const int8_t sym_out =
        static_cast<int8_t>((static_cast<int32_t>(sym_raw) & mk) |
                            (static_cast<int32_t>(-1) & ~mk));
    // AJC 호환: 검출된 빈의 에너지 산출
    const uint32_t bi = static_cast<uint32_t>(dec) & 63u;
    const uint32_t si = static_cast<uint32_t>(dec2) & 63u;
    const uint64_t be64 =
        static_cast<uint64_t>(static_cast<int64_t>(dec_wI_[bi]) * dec_wI_[bi] +
                              static_cast<int64_t>(dec_wQ_[bi]) * dec_wQ_[bi]);
    const uint64_t se64 =
        static_cast<uint64_t>(static_cast<int64_t>(dec_wI_[si]) * dec_wI_[si] +
                              static_cast<int64_t>(dec_wQ_[si]) * dec_wQ_[si]);
    uint32_t be = static_cast<uint32_t>(be64 >> 16u);
    uint32_t se = static_cast<uint32_t>(se64 >> 16u);
    be &= static_cast<uint32_t>(mk);
    se &= static_cast<uint32_t>(mk);
    return {sym_out, be, se};
}
// ── I=Q 동일 모드 (재밍 방어) ──
// ── [적응형 I/Q] I/Q 독립 디코딩 ──────────────────────────
//  I 채널과 Q 채널을 분리하여 각각 FWHT 수행
//  한 칩 구간에서 2개 심볼 획득 → 처리량 2배
//  각 채널의 에너지는 I² 또는 Q² 단독 (합산하지 않음)
//  → I=Q 동일 대비 −3dB, 평시(NF<10dB) 충분
HTS_V400_Dispatcher::SymDecResultSplit
HTS_V400_Dispatcher::walsh_dec_split_(const int16_t *I, const int16_t *Q,
                                      int n) noexcept {
    const uint32_t p_ok =
        static_cast<uint32_t>((I != nullptr) & (Q != nullptr) &
                              static_cast<uint32_t>((n == 16) | (n == 64)));
    const int n_eff = ((n == 16) | (n == 64)) ? n : 64;
    const int16_t *srcI = (p_ok != 0u) ? I : k_walsh_dummy_iq_;
    const int16_t *srcQ = (p_ok != 0u) ? Q : k_walsh_dummy_iq_;
    for (int i = 0; i < n_eff; ++i) {
        dec_wI_[i] = srcI[i];
    }
    fwht_raw(dec_wI_, n_eff);
    for (int i = 0; i < n_eff; ++i) {
        dec_wQ_[i] = srcQ[i];
    }
    fwht_raw(dec_wQ_, n_eff);
    const int bps = (n_eff == 64) ? cur_bps64_ : 4;
    const int valid = 1 << bps;
    const int search = (valid < n_eff) ? valid : n_eff;
    // I 채널 최대 에너지 빈 탐색
    uint64_t bestI = 0u, secI = 0u;
    uint8_t decI = 0xFFu;
    for (int m = 0; m < search; ++m) {
        const uint64_t e = static_cast<uint64_t>(
            static_cast<int64_t>(dec_wI_[m]) * dec_wI_[m]);
        const uint32_t c_gt_best = static_cast<uint32_t>(e > bestI);
        const uint32_t c_gt_sec =
            static_cast<uint32_t>(e <= bestI) & static_cast<uint32_t>(e > secI);
        secI = secI * (1ull - static_cast<uint64_t>(c_gt_best)) *
                   (1ull - static_cast<uint64_t>(c_gt_sec)) +
               bestI * static_cast<uint64_t>(c_gt_best) +
               e * static_cast<uint64_t>(c_gt_sec);
        bestI = bestI * (1ull - static_cast<uint64_t>(c_gt_best)) +
                e * static_cast<uint64_t>(c_gt_best);
        decI = static_cast<uint8_t>(static_cast<uint32_t>(m) * c_gt_best +
                                    static_cast<uint32_t>(decI) *
                                        (1u - c_gt_best));
    }
    uint64_t bestQ = 0u, secQ = 0u;
    uint8_t decQ = 0xFFu;
    for (int m = 0; m < search; ++m) {
        const uint64_t e = static_cast<uint64_t>(
            static_cast<int64_t>(dec_wQ_[m]) * dec_wQ_[m]);
        const uint32_t c_gt_best = static_cast<uint32_t>(e > bestQ);
        const uint32_t c_gt_sec =
            static_cast<uint32_t>(e <= bestQ) & static_cast<uint32_t>(e > secQ);
        secQ = secQ * (1ull - static_cast<uint64_t>(c_gt_best)) *
                   (1ull - static_cast<uint64_t>(c_gt_sec)) +
               bestQ * static_cast<uint64_t>(c_gt_best) +
               e * static_cast<uint64_t>(c_gt_sec);
        bestQ = bestQ * (1ull - static_cast<uint64_t>(c_gt_best)) +
                e * static_cast<uint64_t>(c_gt_best);
        decQ = static_cast<uint8_t>(static_cast<uint32_t>(m) * c_gt_best +
                                    static_cast<uint32_t>(decQ) *
                                        (1u - c_gt_best));
    }
    const int32_t mk = -static_cast<int32_t>(p_ok);
    const int8_t symI_raw =
        (bestI == 0u) ? static_cast<int8_t>(-1) : static_cast<int8_t>(decI);
    const int8_t symQ_raw =
        (bestQ == 0u) ? static_cast<int8_t>(-1) : static_cast<int8_t>(decQ);
    uint32_t bIe = static_cast<uint32_t>(bestI >> 16u);
    uint32_t sIe = static_cast<uint32_t>(secI >> 16u);
    uint32_t bQe = static_cast<uint32_t>(bestQ >> 16u);
    uint32_t sQe = static_cast<uint32_t>(secQ >> 16u);
    bIe &= static_cast<uint32_t>(mk);
    sIe &= static_cast<uint32_t>(mk);
    bQe &= static_cast<uint32_t>(mk);
    sQe &= static_cast<uint32_t>(mk);
    return {static_cast<int8_t>((static_cast<int32_t>(symI_raw) & mk) |
                                (static_cast<int32_t>(-1) & ~mk)),
            static_cast<int8_t>((static_cast<int32_t>(symQ_raw) & mk) |
                                (static_cast<int32_t>(-1) & ~mk)),
            bIe,
            sIe,
            bQe,
            sQe};
}
static void walsh_enc(uint8_t sym, int n, int16_t amp, int16_t *oI,
                      int16_t *oQ) noexcept {
    const int32_t ampi = static_cast<int32_t>(amp);
    for (int j = 0; j < n; ++j) {
        const uint32_t p =
            popc32(static_cast<uint32_t>(sym) & static_cast<uint32_t>(j)) & 1u;
        const int16_t ch =
            static_cast<int16_t>(ampi * (1 - 2 * static_cast<int32_t>(p)));
        oI[j] = ch;
        oQ[j] = ch;
    }
}
// ── [적응형 I/Q] I/Q 독립 모드 (평시 2배 처리량) ──
//  sym_I → I 채널, sym_Q → Q 채널에 독립 Walsh 인코딩
//  처리량 2배: 동일 칩 수로 2개 심볼 전송
static void walsh_enc_split(uint8_t sym_I, uint8_t sym_Q, int n, int16_t amp,
                            int16_t *oI, int16_t *oQ) noexcept {
    const int32_t ampi = static_cast<int32_t>(amp);
    for (int j = 0; j < n; ++j) {
        const uint32_t pI =
            popc32(static_cast<uint32_t>(sym_I) & static_cast<uint32_t>(j)) &
            1u;
        const uint32_t pQ =
            popc32(static_cast<uint32_t>(sym_Q) & static_cast<uint32_t>(j)) &
            1u;
        oI[j] = static_cast<int16_t>(ampi * (1 - 2 * static_cast<int32_t>(pI)));
        oQ[j] = static_cast<int16_t>(ampi * (1 - 2 * static_cast<int32_t>(pQ)));
    }
}
/// AntiJam_Engine::sort_u32_ct_adjacent_64 와 동일 — N=64, 2016 인접 교환(고정
/// 트립).
static constexpr int kSoftClipSortN = 64;
static_assert(static_cast<std::size_t>(kSoftClipSortN) *
                      static_cast<std::size_t>(kSoftClipSortN - 1) / 2u ==
                  2016u,
              "soft-clip sort trip count");
static void sort_u32_ct_adjacent_64_dispatch(uint32_t *a) noexcept {
    if (a == nullptr) {
        return;
    }
    for (int pass = 0; pass < kSoftClipSortN - 1; ++pass) {
        const int imax = kSoftClipSortN - 1 - pass;
        for (int i = 0; i < imax; ++i) {
            const uint32_t x = a[i];
            const uint32_t y = a[i + 1];
            const uint32_t gt = static_cast<uint32_t>(x > y);
            const uint32_t m = 0u - gt;
            a[i] = (x & ~m) | (y & m);
            a[i + 1] = (y & ~m) | (x & m);
        }
    }
}
static void fill_u32_pad_max_(uint32_t *work, const uint32_t *src,
                              int nc) noexcept {
    for (int i = 0; i < nc; ++i) {
        work[static_cast<std::size_t>(i)] = src[static_cast<std::size_t>(i)];
    }
    for (int i = nc; i < kSoftClipSortN; ++i) {
        work[static_cast<std::size_t>(i)] = 0xFFFFFFFFu;
    }
}
static inline int32_t clamp_abs_branchless_i32_(int32_t v,
                                                int32_t cap) noexcept {
    const int32_t neg_cap = -cap;
    const uint32_t under = static_cast<uint32_t>(v < neg_cap);
    const uint32_t over = static_cast<uint32_t>(v > cap);
    const int32_t ku = -static_cast<int32_t>(under);
    const int32_t ko = -static_cast<int32_t>(over);
    return (neg_cap & ku) | (cap & ko) | (v & ~(ku | ko));
}
static inline int16_t ssat16_dispatch_(int32_t v) noexcept {
#if defined(__GNUC__) && defined(__ARM_ARCH) && (__ARM_ARCH >= 6)
    return static_cast<int16_t>(__builtin_arm_ssat(v, 16));
#else
    const uint32_t ov_hi = static_cast<uint32_t>(v > 32767);
    const uint32_t ov_lo = static_cast<uint32_t>(v < -32768);
    const int32_t msk = -static_cast<int32_t>(ov_hi | ov_lo);
    const int32_t repl = (32767 & -static_cast<int32_t>(ov_hi)) |
                         (-32768 & -static_cast<int32_t>(ov_lo));
    return static_cast<int16_t>((v & ~msk) | (repl & msk));
#endif
}
// =====================================================================
//  soft_clip_iq — 아웃라이어 소프트 클리핑
//
//  분위(clip)는 UDIV 없는 상수 시간 인접 정렬로 산출.
//  초과 구간은 UDIV 비율 대신 L∞ 포화(±bl) + 비트마스크(고정 루프 비용).
// =====================================================================
static void soft_clip_iq(int16_t *I, int16_t *Q, int nc, uint32_t *mags,
                         uint32_t *sorted) noexcept {
    if (I == nullptr || Q == nullptr || mags == nullptr || sorted == nullptr) {
        return;
    }
    if (nc <= 0 || nc > 64)
        return;
    for (int i = 0; i < nc; ++i) {
        mags[i] = 0u;
        sorted[i] = 0u;
    }
    for (int i = 0; i < nc; ++i) {
        mags[i] = fast_abs(static_cast<int32_t>(I[i])) +
                  fast_abs(static_cast<int32_t>(Q[i]));
        sorted[i] = mags[i];
    }
    int q_idx = nc >> 2;
    if (q_idx < 1)
        q_idx = 1;
    fill_u32_pad_max_(sorted, mags, nc);
    sort_u32_ct_adjacent_64_dispatch(sorted);
    uint32_t bl = sorted[static_cast<std::size_t>(q_idx - 1)];
    if (bl < 1u)
        bl = 1u;
    const uint32_t clip = bl << 2u;
    const uint32_t clip_active = static_cast<uint32_t>(clip >= 4u);
    const uint32_t thresh = clip << 1u;
    static_assert(static_cast<uint64_t>(65535u) * 4u * 256u < 0xFFFFFFFFULL,
                  "clip domain");
    uint32_t cap_u = bl;
    const uint32_t cap_ov = 0u - static_cast<uint32_t>(cap_u > 32767u);
    cap_u = (cap_u & ~cap_ov) | (32767u & cap_ov);
    const int32_t cap_s = static_cast<int32_t>(cap_u);
    for (int i = 0; i < nc; ++i) {
        const uint32_t gt =
            static_cast<uint32_t>(mags[i] > thresh) & clip_active;
        const int32_t mk = -static_cast<int32_t>(gt);
        const int32_t vi0 = static_cast<int32_t>(I[i]);
        const int32_t vq0 = static_cast<int32_t>(Q[i]);
        const int32_t vi1 = clamp_abs_branchless_i32_(vi0, cap_s);
        const int32_t vq1 = clamp_abs_branchless_i32_(vq0, cap_s);
        I[i] = static_cast<int16_t>((vi1 & mk) | (vi0 & ~mk));
        Q[i] = static_cast<int16_t>((vq1 & mk) | (vq0 & ~mk));
    }
}
static constexpr uint32_t k_BH_NOISE_FLOOR = 50u; // baseline 하한 (무간섭 판별)
static constexpr uint32_t k_BH_SATURATION =
    8000u; // baseline 상한 (ADC 포화 방어)
void HTS_V400_Dispatcher::blackhole_(int16_t *I, int16_t *Q, int nc) noexcept {
    if (I == nullptr || Q == nullptr || nc <= 0)
        return;
    if (nc > 64)
        return;
    for (int i = 0; i < nc; ++i) {
        scratch_mag_[i] = 0u;
        scratch_sort_[i] = 0u;
    }
    for (int i = 0; i < nc; ++i) {
        scratch_mag_[i] = fast_abs(static_cast<int32_t>(I[i])) +
                          fast_abs(static_cast<int32_t>(Q[i]));
        scratch_sort_[i] = scratch_mag_[i];
    }
    int q25 = nc >> 2;
    if (q25 < 1)
        q25 = 1;
    fill_u32_pad_max_(scratch_sort_, scratch_mag_, nc);
    sort_u32_ct_adjacent_64_dispatch(scratch_sort_);
    uint32_t bl = scratch_sort_[static_cast<std::size_t>(q25 - 1)];
    if (bl < 1u)
        bl = 1u;
    if (bl < k_BH_NOISE_FLOOR || bl > k_BH_SATURATION)
        return;
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
void HTS_V400_Dispatcher::cw_cancel_64_(int16_t *I, int16_t *Q) noexcept {
    if (!cw_cancel_enabled_) {
        return;
    }
    if (I == nullptr || Q == nullptr) {
        return;
    }
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
    const int32_t guard_diff =
        static_cast<int32_t>(ja_sum) - CW_CANCEL_NOISE_TH;
    const int32_t active = ~(guard_diff >> 31);
    // 마스킹: 노이즈 수준이면 ja=0 → 제거량=0 (동작 동일, 타이밍 일정)
    const int32_t m_ja_I = ja_I & active;
    const int32_t m_ja_Q = ja_Q & active;
    // Step 4: AJC 프로파일 시딩 (active 시에만 유효 값 전달)
    if (ajc_enabled_) {
        ajc_.Seed_CW_Profile(m_ja_I, m_ja_Q);
    } else {
        // Step 5: CW 수동 차감 — ajc 비활성 시에만 (이중 차감 방지)
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
}
// =====================================================================
//  생성자 / 소멸자
// =====================================================================
HTS_V400_Dispatcher::HTS_V400_Dispatcher() noexcept
    : phase_(RxPhase::WAIT_SYNC), cur_mode_(PayloadMode::UNKNOWN),
      active_video_(PayloadMode::VIDEO_1), seed_(0x12345678u), tx_seq_(0u),
      rx_seq_(0u), on_pkt_(nullptr), on_ctrl_(nullptr), buf_I_{}, buf_Q_{},
      buf_idx_(0), pre_phase_(0), pre_reps_(1), pre_boost_(1), hdr_syms_{},
      hdr_count_(0), hdr_fail_(0), pay_cps_(0), pay_total_(0), pay_recv_(0),
      harq_round_(0), max_harq_(0), vid_fail_(0), vid_succ_(0), v1_rx_{},
      v1_idx_(0), rx_{}, sym_idx_(0), harq_inited_(false), retx_ready_(false),
      harq_Q_(g_harq_ccm_union.chase.harq_Q),
      ir_chip_I_(&g_harq_ccm_union.ir.chip_I[0][0]),
      ir_chip_Q_(&g_harq_ccm_union.ir.chip_Q[0][0]),
      ir_state_(&g_harq_ccm_union.ir.ir_state), sic_ir_enabled_(false),
      sic_expect_valid_(false), sic_walsh_amp_(300),
      wb_{} // wb 유니온 (반이중 TDM)
      ,
      ajc_(), ajc_last_nc_(0), orig_acc_{}, orig_I_{}, orig_Q_{},
      cw_cancel_enabled_(true), soft_clip_policy_(SoftClipPolicy::ALWAYS),
      ajc_enabled_(true), dec_wI_{}, dec_wQ_{} {}
HTS_V400_Dispatcher::~HTS_V400_Dispatcher() noexcept {
    // [CRIT] sizeof(*this) 통째 wipe 금지 — 멤버 역순 소멸 전 다른 서브객체
    // 손상. AntiJamEngine: 가상 함수 없음 → Reset 후 스토리지 secureWipe,
    // 그다음 암시적 ~ (trivial). 순서: CCM → full_reset_(HARQ/work 버퍼) →
    // 칩/워킹 스크래치 → 시퀀스/시드
    //       → 콜백/메트릭 무효화 → ajc_.Reset → ajc_ 스토리지 파쇄
    SecureMemory::secureWipe(static_cast<void *>(&g_harq_ccm_union),
                             sizeof(g_harq_ccm_union));
    SecureMemory::secureWipe(static_cast<void *>(g_sic_exp_I),
                             sizeof(g_sic_exp_I));
    SecureMemory::secureWipe(static_cast<void *>(g_sic_exp_Q),
                             sizeof(g_sic_exp_Q));
    full_reset_();
    SecureMemory::secureWipe(static_cast<void *>(buf_I_), sizeof(buf_I_));
    SecureMemory::secureWipe(static_cast<void *>(buf_Q_), sizeof(buf_Q_));
    SecureMemory::secureWipe(static_cast<void *>(dec_wI_), sizeof(dec_wI_));
    SecureMemory::secureWipe(static_cast<void *>(dec_wQ_), sizeof(dec_wQ_));
    SecureMemory::secureWipe(static_cast<void *>(scratch_mag_),
                             sizeof(scratch_mag_));
    SecureMemory::secureWipe(static_cast<void *>(scratch_sort_),
                             sizeof(scratch_sort_));
    SecureMemory::secureWipe(static_cast<void *>(&seed_), sizeof(seed_));
    SecureMemory::secureWipe(static_cast<void *>(&tx_seq_), sizeof(tx_seq_));
    SecureMemory::secureWipe(static_cast<void *>(&rx_seq_), sizeof(rx_seq_));
    SecureMemory::secureWipe(static_cast<void *>(hdr_syms_), sizeof(hdr_syms_));
    on_pkt_ = nullptr;
    on_ctrl_ = nullptr;
    p_metrics_ = nullptr;
    ajc_.Reset(16);
    SecureMemory::secureWipe(static_cast<void *>(&ajc_), sizeof(ajc_));
    ajc_last_nc_ = 0;
}
void HTS_V400_Dispatcher::Set_Seed(uint32_t s) noexcept { seed_ = s; }
void HTS_V400_Dispatcher::Set_Packet_Callback(PacketCB cb) noexcept {
    on_pkt_ = cb;
}
void HTS_V400_Dispatcher::Set_Control_Callback(ControlCB cb) noexcept {
    on_ctrl_ = cb;
}
RxPhase HTS_V400_Dispatcher::Get_Phase() const noexcept { return phase_; }
PayloadMode HTS_V400_Dispatcher::Get_Mode() const noexcept { return cur_mode_; }
int HTS_V400_Dispatcher::Get_Video_Fail_Count() const noexcept {
    return vid_fail_;
}
int HTS_V400_Dispatcher::Get_Current_BPS64() const noexcept {
    return cur_bps64_;
}
IQ_Mode HTS_V400_Dispatcher::Get_IQ_Mode() const noexcept { return iq_mode_; }
void HTS_V400_Dispatcher::Set_IR_Mode(bool enable) noexcept {
    if (ir_mode_ != enable) {
        ir_mode_ = enable;
        full_reset_();
    }
}
bool HTS_V400_Dispatcher::Get_IR_Mode() const noexcept { return ir_mode_; }
void HTS_V400_Dispatcher::Set_IR_SIC_Enabled(bool enable) noexcept {
    if (sic_ir_enabled_ == enable) {
        return;
    }
    sic_ir_enabled_ = enable;
    sic_expect_valid_ = false;
    std::memset(g_sic_exp_I, 0, sizeof(g_sic_exp_I));
    std::memset(g_sic_exp_Q, 0, sizeof(g_sic_exp_Q));
}
bool HTS_V400_Dispatcher::Get_IR_SIC_Enabled() const noexcept {
    return sic_ir_enabled_;
}
void HTS_V400_Dispatcher::Set_SIC_Walsh_Amp(int16_t amp) noexcept {
    sic_walsh_amp_ = amp;
}
void HTS_V400_Dispatcher::fill_sic_expected_64_() noexcept {
    sic_expect_valid_ = false;
    if (!sic_ir_enabled_ || ir_state_ == nullptr) {
        return;
    }
    if (ir_state_->sic_tentative_valid == 0u) {
        return;
    }
    std::memset(g_sic_exp_I, 0, sizeof(g_sic_exp_I));
    std::memset(g_sic_exp_Q, 0, sizeof(g_sic_exp_Q));
    uint8_t *const syms = g_v400_sym_scratch;
    const int rv_fb = (ir_rv_ + 3) & 3;
    const uint32_t il = seed_ ^ (rx_seq_ * 0xA5A5A5A5u);
    const int enc_n =
        FEC_HARQ::Encode64_IR(ir_state_->sic_tentative, FEC_HARQ::MAX_INFO,
                              syms, il, cur_bps64_, rv_fb, wb_);
    if (enc_n <= 0) {
        SecureMemory::secureWipe(static_cast<void *>(syms),
                                 sizeof(g_v400_sym_scratch));
        return;
    }
    for (int s = 0; s < enc_n; ++s) {
        walsh_enc(syms[static_cast<std::size_t>(s)], 64, sic_walsh_amp_,
                  &g_sic_exp_I[static_cast<std::size_t>(s)][0],
                  &g_sic_exp_Q[static_cast<std::size_t>(s)][0]);
    }
    sic_expect_valid_ = true;
    SecureMemory::secureWipe(static_cast<void *>(syms),
                             sizeof(g_v400_sym_scratch));
}
void HTS_V400_Dispatcher::Update_Adaptive_BPS(uint32_t nf) noexcept {
    // HTS_RF_Metrics + HTS_Adaptive_BPS_Controller 경로가 연결된 경우
    // current_bps의 단일 진실은 컨트롤러(히스테리시스)이다.
    // bps_from_nf(nf)로 cur_bps64_를 즉시 덮어쓰면 Tick_Adaptive_BPS()가
    // 방금 올린 BPS를 한 프레임 만에 되돌리는 이중 경로 충돌이 난다.
    if (p_metrics_ != nullptr) {
        (void)nf;
        return;
    }
    const int new_bps = FEC_HARQ::bps_from_nf(nf);
    if (new_bps >= FEC_HARQ::BPS64_MIN_OPERABLE &&
        new_bps <= FEC_HARQ::BPS64_MAX) {
        cur_bps64_ = new_bps;
    }
    // IQ 모드 전환은 Tick_Adaptive_BPS()에서만 수행 (히스테리시스 보장)
}
void HTS_V400_Dispatcher::Set_Lab_BPS64(int bps) noexcept {
    cur_bps64_ = FEC_HARQ::bps_clamp_runtime(bps);
}
void HTS_V400_Dispatcher::Set_Lab_IQ_Mode_Jam_Harness() noexcept {
    iq_mode_ = IQ_Mode::IQ_SAME;
    iq_upgrade_count_ = 0u;
}
void HTS_V400_Dispatcher::Set_RF_Metrics(HTS_RF_Metrics *p) noexcept {
    // 비소유 포인터 저장 — nullptr 허용 (Tick 무동작 모드)
    p_metrics_ = p;
}
void HTS_V400_Dispatcher::Tick_Adaptive_BPS() noexcept {
    if (p_metrics_ == nullptr) {
        return;
    }
    const RxPhase prev_phase = phase_;
    const int prev_bps = cur_bps64_;
    const IQ_Mode prev_iq = iq_mode_;
    uint32_t need_reset = 0u;
    const uint8_t bps = p_metrics_->current_bps.load(std::memory_order_acquire);
    if (bps >= static_cast<uint8_t>(FEC_HARQ::BPS64_MIN) &&
        bps <= static_cast<uint8_t>(FEC_HARQ::BPS64_MAX)) {
        const int new_bps = FEC_HARQ::bps_clamp_runtime(static_cast<int>(bps));
        if (new_bps != prev_bps) {
            cur_bps64_ = new_bps;
            need_reset |=
                static_cast<uint32_t>(prev_phase != RxPhase::WAIT_SYNC);
        }
    }
    // ── 적응형 I/Q 모드 전환 (히스테리시스) ──────────────
    const uint32_t nf = p_metrics_->ajc_nf.load(std::memory_order_acquire);
    if (nf >= NF_IQ_SAME_TH) {
        iq_mode_ = IQ_Mode::IQ_SAME;
        iq_upgrade_count_ = 0u;
        if (cur_bps64_ > FEC_HARQ::BPS64_MIN_OPERABLE) {
            cur_bps64_ = FEC_HARQ::BPS64_MIN_OPERABLE;
            need_reset |=
                static_cast<uint32_t>(prev_phase != RxPhase::WAIT_SYNC);
        }
        if (prev_iq != IQ_Mode::IQ_SAME) {
            need_reset |=
                static_cast<uint32_t>(prev_phase != RxPhase::WAIT_SYNC);
        }
    } else if (nf < NF_IQ_SPLIT_TH) {
        if (iq_upgrade_count_ < IQ_UPGRADE_GUARD) {
            iq_upgrade_count_++;
        }
        if (iq_upgrade_count_ >= IQ_UPGRADE_GUARD) {
            iq_mode_ = IQ_Mode::IQ_INDEPENDENT;
            if (cur_bps64_ < IQ_BPS_PEACETIME) {
                cur_bps64_ = IQ_BPS_PEACETIME;
                need_reset |=
                    static_cast<uint32_t>(prev_phase != RxPhase::WAIT_SYNC);
            }
            if (prev_iq != IQ_Mode::IQ_INDEPENDENT) {
                need_reset |=
                    static_cast<uint32_t>(prev_phase != RxPhase::WAIT_SYNC);
            }
        }
    } else {
        iq_upgrade_count_ = 0u;
    }
    if (ir_mode_) {
        iq_mode_ = IQ_Mode::IQ_SAME;
        iq_upgrade_count_ = 0u;
    }
    if (need_reset != 0u) {
        full_reset_();
    }
}
void HTS_V400_Dispatcher::full_reset_() noexcept {
    // WAIT_SYNC 전이는 모든 상태에서 무조건 합법
    phase_ = RxPhase::WAIT_SYNC;
    rf_settle_chips_remaining_ = 0;
    cur_mode_ = PayloadMode::UNKNOWN;
    buf_idx_ = 0;
    pre_phase_ = 0;
    first_c63_ = 0;
    m63_gap_ = 0;
    wait_sync_head_ = 0;
    wait_sync_count_ = 0;
    hdr_count_ = 0;
    hdr_fail_ = 0;
    pay_recv_ = 0;
    v1_idx_ = 0;
    sym_idx_ = 0;
    harq_round_ = 0;
    harq_inited_ = false;
    SecureMemory::secureWipe(static_cast<void *>(&rx_), sizeof(rx_));
    SecureMemory::secureWipe(static_cast<void *>(v1_rx_), sizeof(v1_rx_));
    SecureMemory::secureWipe(static_cast<void *>(orig_I_), sizeof(orig_I_));
    SecureMemory::secureWipe(static_cast<void *>(orig_Q_), sizeof(orig_Q_));
    SecureMemory::secureWipe(static_cast<void *>(&orig_acc_),
                             sizeof(orig_acc_));
    SecureMemory::secureWipe(static_cast<void *>(&wb_), sizeof(wb_));
    // CCM union 전체 — file-scope `g_harq_ccm_union` 직접 참조 (Chase/IR 공용)
    SecureMemory::secureWipe(static_cast<void *>(&g_harq_ccm_union),
                             sizeof(g_harq_ccm_union));
    ir_rv_ = 0;
    sic_expect_valid_ = false;
    retx_ready_ = false;
    std::memset(g_sic_exp_I, 0, sizeof(g_sic_exp_I));
    std::memset(g_sic_exp_Q, 0, sizeof(g_sic_exp_Q));
    // [BUG-FIX-PRE2] 프리앰블 누적 버퍼 초기화
    std::memset(g_pre_acc_I, 0, sizeof(g_pre_acc_I));
    std::memset(g_pre_acc_Q, 0, sizeof(g_pre_acc_Q));
    g_pre_acc_n = 0;
    if (ir_mode_ && ir_state_ != nullptr) {
        FEC_HARQ::IR_Init(*ir_state_);
    }
}
// =====================================================================
//
//  CFI: key=(from<<2)|to, 16슬롯 LUT(RF_SETTLING 포함) + 클램프
// =====================================================================
uint32_t HTS_V400_Dispatcher::set_phase_(RxPhase target) noexcept {
    const uint32_t f = static_cast<uint32_t>(phase_);
    const uint32_t t = static_cast<uint32_t>(target);
    const uint32_t key = (f << 2u) | t;
    static constexpr uint8_t k_trans_legal[16] = {
        1u, 1u, 0u, 1u, 1u, 0u, 1u, 1u, 1u, 0u, 0u, 1u, 1u, 0u, 0u, 0u};
    const uint32_t k_ok = static_cast<uint32_t>(key < 16u);
    const uint32_t idx = key * k_ok + 15u * (1u - k_ok);
    const uint32_t legal_u = static_cast<uint32_t>(k_trans_legal[idx]);
    const uint32_t p = static_cast<uint32_t>(phase_);
    phase_ = static_cast<RxPhase>(t * legal_u + p * (1u - legal_u));
    if (legal_u == 0u) {
        full_reset_();
        return PHASE_TRANSFER_MASK_FAIL;
    }
    return PHASE_TRANSFER_MASK_OK;
}
void HTS_V400_Dispatcher::fhss_abort_rx_for_hop_() noexcept {
    buf_idx_ = 0;
    wait_sync_head_ = 0;
    wait_sync_count_ = 0;
    pre_phase_ = 0;
    first_c63_ = 0;
    m63_gap_ = 0;
    hdr_count_ = 0;
    hdr_fail_ = 0;
    pay_recv_ = 0;
    pay_total_ = 0;
    pay_cps_ = 0;
    v1_idx_ = 0;
    sym_idx_ = 0;
    harq_round_ = 0;
    harq_inited_ = false;
    retx_ready_ = false;
    cur_mode_ = PayloadMode::UNKNOWN;
}
uint8_t HTS_V400_Dispatcher::FHSS_Derive_Channel(uint32_t seed,
                                                 uint32_t seq) noexcept {
    uint32_t x = seed ^ seq;
    x ^= x << 13u;
    x ^= x >> 17u;
    x ^= x << 5u;
    x ^= seq << 15u;
    x ^= seed >> 3u;
    x ^= (seq << 7u) ^ (seed << 11u);
    return static_cast<uint8_t>(x & static_cast<uint32_t>(0x7Fu));
}
uint8_t HTS_V400_Dispatcher::FHSS_Request_Hop_As_Tx() noexcept {
    const uint32_t in_settle =
        static_cast<uint32_t>(phase_ == RxPhase::RF_SETTLING);
    if (in_settle != 0u) {
        return static_cast<uint8_t>(0xFFu);
    }
    const uint8_t ch = FHSS_Derive_Channel(seed_, tx_seq_);
    Mock_RF_Synth_Set_Channel(ch);
    tx_seq_ = tx_seq_ + 1u;
    fhss_abort_rx_for_hop_();
    rf_settle_chips_remaining_ = FHSS_SETTLE_CHIPS;
    const uint32_t ph_ok = set_phase_(RxPhase::RF_SETTLING);
    if (ph_ok == PHASE_TRANSFER_MASK_FAIL) {
        return static_cast<uint8_t>(0xFFu);
    }
    return ch;
}
uint8_t HTS_V400_Dispatcher::FHSS_Request_Hop_As_Rx() noexcept {
    const uint32_t in_settle =
        static_cast<uint32_t>(phase_ == RxPhase::RF_SETTLING);
    if (in_settle != 0u) {
        return static_cast<uint8_t>(0xFFu);
    }
    const uint8_t ch = FHSS_Derive_Channel(seed_, rx_seq_);
    Mock_RF_Synth_Set_Channel(ch);
    rx_seq_ = rx_seq_ + 1u;
    fhss_abort_rx_for_hop_();
    rf_settle_chips_remaining_ = FHSS_SETTLE_CHIPS;
    const uint32_t ph_ok = set_phase_(RxPhase::RF_SETTLING);
    if (ph_ok == PHASE_TRANSFER_MASK_FAIL) {
        return static_cast<uint8_t>(0xFFu);
    }
    return ch;
}
bool HTS_V400_Dispatcher::FHSS_Is_Rf_Settling() const noexcept {
    return static_cast<uint32_t>(phase_) ==
           static_cast<uint32_t>(RxPhase::RF_SETTLING);
}
void HTS_V400_Dispatcher::Reset() noexcept {
    full_reset_();
    ajc_.Reset(16);
    ajc_last_nc_ = 0;
}
uint32_t HTS_V400_Dispatcher::parse_hdr_(PayloadMode &mode,
                                         int &plen) noexcept {
    const uint16_t hdr = (static_cast<uint16_t>(hdr_syms_[0]) << 6u) |
                         static_cast<uint16_t>(hdr_syms_[1]);
    const uint8_t mb = static_cast<uint8_t>((hdr >> 10u) & 0x03u);
    const uint32_t rx_iq_split =
        static_cast<uint32_t>((hdr & HDR_IQ_BIT) != 0u);
    plen = static_cast<int>(hdr & 0x01FFu);
    iq_mode_ = static_cast<IQ_Mode>(
        static_cast<uint32_t>(IQ_Mode::IQ_INDEPENDENT) * rx_iq_split +
        static_cast<uint32_t>(IQ_Mode::IQ_SAME) * (1u - rx_iq_split));
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
    const uint32_t plen_ok_v16 =
        static_cast<uint32_t>(plen == FEC_HARQ::NSYM16);
    const int bps = FEC_HARQ::bps_from_nsym(plen);
    const uint32_t bps_ge =
        static_cast<uint32_t>(bps >= FEC_HARQ::BPS64_MIN_OPERABLE);
    const uint32_t bps_le = static_cast<uint32_t>(bps <= FEC_HARQ::BPS64_MAX);
    const uint32_t plen_sym =
        static_cast<uint32_t>(plen == FEC_HARQ::nsym_for_bps(bps));
    const uint32_t data_ok = m3 & bps_ge & bps_le & plen_sym;
    const uint32_t ok_u = (m0 & plen_ok_v1) | (m1 & plen_ok_v16) |
                          (m2 & plen_ok_v16) | data_ok;
    const int d_int = static_cast<int>(data_ok);
    cur_bps64_ =
        (bps * static_cast<int>(data_ok)) + (cur_bps64_ * (1 - d_int));
    if (ir_mode_) {
        iq_mode_ = IQ_Mode::IQ_SAME;
        iq_upgrade_count_ = 0u;
    }
    return static_cast<uint32_t>(0u - ok_u);
}
void HTS_V400_Dispatcher::on_sym_() noexcept {
    pay_recv_++;
    if (cur_mode_ == PayloadMode::VIDEO_1) {
        if (v1_idx_ < 80) {
            v1_rx_[v1_idx_++] = buf_I_[0];
        } else {
            full_reset_();
            return;
        }
    } else if (cur_mode_ == PayloadMode::VIDEO_16 ||
               cur_mode_ == PayloadMode::VOICE ||
               cur_mode_ == PayloadMode::DATA) {
        const int nc = (cur_mode_ == PayloadMode::DATA) ? 64 : 16;
        /* IR-HARQ: RV마다 송신 파형이 다르므로 칩 도메인 += 금지.
           결합은 FEC Decode*_IR 의 ir_state_(LLR)에서만 수행; 수신 칩은 매 심볼
           덮어쓰기. */
        std::memcpy(orig_I_, buf_I_, nc * sizeof(int16_t));
        std::memcpy(orig_Q_, buf_Q_, nc * sizeof(int16_t));
        if (cur_mode_ == PayloadMode::DATA) {
            cw_cancel_64_(buf_I_, buf_Q_);
        }
        if (ajc_enabled_) {
            ajc_.Process(buf_I_, buf_Q_, nc);
        }
        /* BUG-FIX-SC3: retx 경로 soft_clip 비활성화 — IR LLR 누적 품질 보존 */
        if (!retx_ready_ && soft_clip_policy_ != SoftClipPolicy::NEVER) {
            soft_clip_iq(buf_I_, buf_Q_, nc, scratch_mag_, scratch_sort_);
        }
        if (nc == 16) {
            if (sym_idx_ < FEC_HARQ::NSYM16) {
                if (ir_mode_) {
                    /* BUG-FIX-IR2: IR 칩은 raw(orig) 누적 —
                     * cw_cancel/AJC/soft_clip buf 변형 제외 */
                    const int base = sym_idx_ * FEC_HARQ::C16;
                    for (int c = 0; c < nc; ++c) {
                        ir_chip_I_[base + c] = orig_I_[c];
                        ir_chip_Q_[base + c] = orig_Q_[c];
                    }
                } else {
                    FEC_HARQ::Feed16_1sym(rx_.m16, buf_I_, buf_Q_, sym_idx_);
                }
                for (int c = 0; c < nc; ++c) {
                    const uint8_t hiI =
                        static_cast<uint8_t>((orig_I_[c] >> 12) & 0x0Fu);
                    const uint8_t hiQ =
                        static_cast<uint8_t>((orig_Q_[c] >> 12) & 0x0Fu);
                    orig_acc_.acc16.iq4[sym_idx_][c] =
                        static_cast<uint8_t>((hiI << 4u) | hiQ);
                }
                sym_idx_++;
            } else {
                full_reset_();
                return;
            }
        } else {
            const int nsym64 = cur_nsym64_();
            if (iq_mode_ == IQ_Mode::IQ_INDEPENDENT && !ir_mode_) {
                // ── [적응형 I/Q] I/Q 독립 RX: 칩슬롯당 2심볼 ──
                //  I 채널 → 짝수 sym_idx_, Q 채널 → 홀수 sym_idx_
                //  HARQ I 누적기: 짝수 심볼 전용
                //  HARQ Q 누적기: 홀수 심볼 전용
                const int si_I = sym_idx_;     // I 채널 심볼 인덱스
                const int si_Q = sym_idx_ + 1; // Q 채널 심볼 인덱스
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
                        const uint8_t hiI =
                            static_cast<uint8_t>((orig_I_[c] >> 12) & 0x0Fu);
                        orig_acc_.acc64.iq4[si_I][c] =
                            static_cast<uint8_t>(hiI << 4u);
                        const uint8_t hiQ =
                            static_cast<uint8_t>((orig_Q_[c] >> 12) & 0x0Fu);
                        orig_acc_.acc64.iq4[si_Q][c] =
                            static_cast<uint8_t>(hiQ << 4u);
                    }
                    sym_idx_ += 2;
                    pay_recv_++; // 칩슬롯 기준 카운트
                } else {
                    full_reset_();
                    return;
                }
            } else {
                // ── I=Q 동일 또는 IR-HARQ (칩 보관) ──
                if (sym_idx_ < nsym64) {
                    if (ir_mode_) {
                        /* BUG-FIX-IR2: IR 칩은 raw(orig) 기준 + SIC — buf
                         * 전처리 경로 미사용 */
                        const int base = sym_idx_ * FEC_HARQ::C64;
                        const uint32_t use_sic_u =
                            static_cast<uint32_t>(sic_expect_valid_) & 1u;
                        for (int c = 0; c < nc; ++c) {
                            int32_t vi = static_cast<int32_t>(orig_I_[c]);
                            int32_t vq = static_cast<int32_t>(orig_Q_[c]);
                            const int32_t subI =
                                static_cast<int32_t>(
                                    g_sic_exp_I[static_cast<std::size_t>(
                                        sym_idx_)]
                                               [static_cast<std::size_t>(c)]) *
                                static_cast<int32_t>(use_sic_u);
                            const int32_t subQ =
                                static_cast<int32_t>(
                                    g_sic_exp_Q[static_cast<std::size_t>(
                                        sym_idx_)]
                                               [static_cast<std::size_t>(c)]) *
                                static_cast<int32_t>(use_sic_u);
                            vi -= subI;
                            vq -= subQ;
                            ir_chip_I_[base + c] = ssat16_dispatch_(vi);
                            ir_chip_Q_[base + c] = ssat16_dispatch_(vq);
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
                    } else {
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
                } else {
                    full_reset_();
                    return;
                }
            }
        }
        // [적응형 I/Q] AJC 피드백: IQ 모드에 따라 디코딩 방식 분기
        if (iq_mode_ == IQ_Mode::IQ_INDEPENDENT && !ir_mode_ && nc == 64) {
            // I/Q 독립: 각 채널 분리 FWHT → 2심볼 디코딩
            SymDecResultSplit rs = walsh_dec_split_(buf_I_, buf_Q_, nc);
            if (ajc_enabled_) {
                // I/Q 독립: 채널별 Update_AJC (sym_Q=-1이면 내부에서 갱신 스킵
                // 가능)
                // ① I 채널 AJC 갱신
                ajc_.Update_AJC(orig_I_, orig_Q_, rs.sym_I, rs.best_eI,
                                rs.second_eI, nc);
                // ② Q 채널 AJC 갱신
                ajc_.Update_AJC(orig_I_, orig_Q_, rs.sym_Q, rs.best_eQ,
                                rs.second_eQ, nc);
            }
        } else {
            // I=Q 동일: 결합 FWHT
            SymDecResult r = walsh_dec_full_(buf_I_, buf_Q_, nc);
            if (ajc_enabled_) {
                ajc_.Update_AJC(orig_I_, orig_Q_, r.sym, r.best_e, r.second_e,
                                nc);
            }
        }
    }
    buf_idx_ = 0;
    if (pay_recv_ >= pay_total_)
        try_decode_();
}
void HTS_V400_Dispatcher::try_decode_() noexcept {
    // [BUG-FIX-IR5] wb_ 초기화: Encode 잔류 데이터가 Decode 경로를 오염시키는
    // 것을 방지. 16칩(NSYM16=172)은 wb_ 사용 영역이 작아 영향 없으나,
    // 64칩(NSYM64=172, BPS=4)은 전체 TOTAL_CODED(688) 슬롯을 사용하므로 필수.
    std::memset(&wb_, 0, sizeof(wb_));
    DecodedPacket pkt = {};
    pkt.mode = cur_mode_;
    pkt.success_mask = DecodedPacket::DECODE_MASK_FAIL;
    uint32_t il = seed_ ^ (rx_seq_ * 0xA5A5A5A5u);
    /* WorkBuf: try_decode_ 진입 시 memset 초기화 완료 (BUG-FIX-IR5). */
    if (cur_mode_ == PayloadMode::VIDEO_1) {
        pkt.success_mask =
            static_cast<uint32_t>(0u - static_cast<uint32_t>(FEC_HARQ::Decode1(
                                           v1_rx_, pkt.data, &pkt.data_len)));
        pkt.harq_k = 1;
        handle_video_(pkt.success_mask);
        if (on_pkt_ != nullptr) {
            on_pkt_(pkt);
        }
        rx_seq_++;
        full_reset_();
    } else if (cur_mode_ == PayloadMode::VIDEO_16 ||
               cur_mode_ == PayloadMode::VOICE) {
        if (ir_mode_) {
            harq_round_++;
            const int rv = ir_rv_;
            if (g_hts_ir_diag_chip0 != 0 && ir_chip_I_ != nullptr &&
                ir_state_ != nullptr) {
                std::printf("[IR-DIAG] pre-Decode16_IR feed=%d harq_round_=%d "
                            "ir_chip_I_[0]=%d ir_state.rounds_done=%d\n",
                            static_cast<int>(g_hts_ir_diag_feed_idx),
                            harq_round_, static_cast<int>(ir_chip_I_[0]),
                            ir_state_->rounds_done);
            }
            pkt.success_mask = static_cast<uint32_t>(
                0u - static_cast<uint32_t>(
                         (ir_state_ != nullptr && ir_chip_I_ != nullptr &&
                          ir_chip_Q_ != nullptr &&
                          FEC_HARQ::Decode16_IR(
                              ir_chip_I_, ir_chip_Q_, FEC_HARQ::NSYM16,
                              FEC_HARQ::C16, FEC_HARQ::BPS16, il, rv,
                              *ir_state_, pkt.data, &pkt.data_len, wb_))));
            ir_rv_ = (ir_rv_ + 1) & 3;
            sic_expect_valid_ = false;
        } else {
            FEC_HARQ::Advance_Round_16(rx_.m16);
            harq_round_++;
            pkt.success_mask = static_cast<uint32_t>(
                0u - static_cast<uint32_t>(FEC_HARQ::Decode16(
                         rx_.m16, pkt.data, &pkt.data_len, il, wb_)));
        }
        pkt.harq_k = harq_round_;
        const uint32_t dec_ok = static_cast<uint32_t>(pkt.success_mask != 0u);
        const uint32_t harq_ex =
            static_cast<uint32_t>(harq_round_ >= max_harq_);
        // 연속모드에서는 harq 소진을 하네스 외부(feeds 루프)에서 관리
        // max_harq_는 DATA_K(32)로 통일하여 VOICE도 32라운드 누적 허용
        const uint32_t finish = dec_ok | harq_ex;
        if (finish != 0u) {
            if (dec_ok != 0u) {
                harq_feedback_seed_(pkt.data, pkt.data_len, 16, il);
            }
            if (cur_mode_ == PayloadMode::VIDEO_16) {
                handle_video_(pkt.success_mask);
            }
            if (on_pkt_ != nullptr) {
                on_pkt_(pkt);
            }
            rx_seq_++;
            full_reset_();
        } else {
            pay_recv_ = 0;
            sym_idx_ = 0;
            /* IR 칩: on_sym_ 라운드마다 덮어쓰기 — memset 불필요 */
            /* BUG-FIX-RETX5: 실패 시 READ_PAYLOAD 유지, 재동기 회피 */
            retx_ready_ = true;
            buf_idx_ = 0;
            // set_phase_(RxPhase::WAIT_SYNC);
        }
    } else if (cur_mode_ == PayloadMode::DATA) {
        harq_round_++;
        if (ir_mode_) {
                const int bps = cur_bps64_;
                if (bps >= FEC_HARQ::BPS64_MIN_OPERABLE &&
                    bps <= FEC_HARQ::BPS64_MAX && ir_state_ != nullptr &&
                    ir_chip_I_ != nullptr && ir_chip_Q_ != nullptr) {
                    const int nsym_ir = FEC_HARQ::nsym_for_bps(bps);
                    const int rv = ir_rv_;
                    if (g_hts_ir_diag_chip0 != 0) {
                        std::printf(
                            "[IR-DIAG] pre-Decode64_IR feed=%d harq_round_=%d "
                            "ir_chip_I_[0]=%d ir_state.rounds_done=%d\n",
                            static_cast<int>(g_hts_ir_diag_feed_idx),
                            harq_round_, static_cast<int>(ir_chip_I_[0]),
                            ir_state_->rounds_done);
                        std::printf(
                            "[IR-DIAG] Decode64_IR args: bps=%d nsym_ir=%d "
                            "il=0x%08x rv=%d rounds_done=%d\n",
                            bps, nsym_ir, static_cast<unsigned>(il), rv,
                            ir_state_->rounds_done);
                    }
                    pkt.success_mask = static_cast<uint32_t>(
                        0u -
                        static_cast<uint32_t>(FEC_HARQ::Decode64_IR(
                            ir_chip_I_, ir_chip_Q_, nsym_ir, FEC_HARQ::C64, bps,
                            il, rv, *ir_state_, pkt.data, &pkt.data_len, wb_)));
                }
                ir_rv_ = (ir_rv_ + 1) & 3;
                {
                    const int bps_sic = cur_bps64_;
                    const bool ir64_attempt =
                        (bps_sic >= FEC_HARQ::BPS64_MIN_OPERABLE &&
                         bps_sic <= FEC_HARQ::BPS64_MAX &&
                         ir_state_ != nullptr && ir_chip_I_ != nullptr &&
                         ir_chip_Q_ != nullptr);
                    if (ir64_attempt) {
                        if (pkt.success_mask != 0u) {
                            sic_expect_valid_ = false;
                        } else if (sic_ir_enabled_) {
                            fill_sic_expected_64_();
                        } else {
                            sic_expect_valid_ = false;
                        }
                    } else {
                        sic_expect_valid_ = false;
                    }
                }
            } else {
                sic_expect_valid_ = false;
                if (!rx_.m64_I.ok)
                    rx_.m64_I.k++;
                {
                    const int bps = cur_bps64_;
                    if (bps >= FEC_HARQ::BPS64_MIN_OPERABLE &&
                        bps <= FEC_HARQ::BPS64_MAX) {
                        const int nsym = FEC_HARQ::nsym_for_bps(bps);
                        pkt.success_mask = static_cast<uint32_t>(
                            0u -
                            static_cast<uint32_t>(FEC_HARQ::Decode_Core_Split(
                                &rx_.m64_I.aI[0][0], harq_Q_[0], nsym,
                                FEC_HARQ::C64, bps, pkt.data, &pkt.data_len, il,
                                wb_)));
                    }
                }
            }
        pkt.harq_k = harq_round_;
        const uint32_t dec_ok = static_cast<uint32_t>(pkt.success_mask != 0u);
        const uint32_t harq_ex =
            static_cast<uint32_t>(harq_round_ >= max_harq_);
        const uint32_t finish = dec_ok | harq_ex;
        if (finish != 0u) {
            if (dec_ok != 0u) {
                if (!ir_mode_) {
                    rx_.m64_I.ok = true;
                }
                harq_feedback_seed_(pkt.data, pkt.data_len, 64, il);
            }
            if (on_pkt_ != nullptr) {
                on_pkt_(pkt);
            }
            rx_seq_++;
            full_reset_();
        } else {
            pay_recv_ = 0;
            sym_idx_ = 0;
            /* IR 칩: on_sym_ 라운드마다 덮어쓰기 — memset 불필요 */
            /* BUG-FIX-RETX5: 실패 시 READ_PAYLOAD 유지, 재동기 회피 */
            retx_ready_ = true;
            buf_idx_ = 0;
            // set_phase_(RxPhase::WAIT_SYNC);
        }
    }
}
void HTS_V400_Dispatcher::harq_feedback_seed_(const uint8_t *data, int data_len,
                                              int nc, uint32_t il) noexcept {
    if (!data || data_len <= 0)
        return;
    if (nc == 16) {
        uint8_t *const correct_syms = g_v400_sym_scratch;
        int enc_n = 0;
        if (ir_mode_) {
            const int rv_fb = (ir_rv_ + 3) & 3;
            enc_n = FEC_HARQ::Encode16_IR(data, data_len, correct_syms, il,
                                          rv_fb, wb_);
        } else {
            enc_n = FEC_HARQ::Encode16(data, data_len, correct_syms, il, wb_);
        }
        if (enc_n <= 0) {
            SecureMemory::secureWipe(static_cast<void *>(correct_syms),
                                     sizeof(g_v400_sym_scratch));
            return;
        }
        const int nsym =
            (sym_idx_ < FEC_HARQ::NSYM16) ? sym_idx_ : FEC_HARQ::NSYM16;
        int16_t *const tmp_I = g_v400_harq_fb_tmp_I;
        int16_t *const tmp_Q = g_v400_harq_fb_tmp_Q;
        for (int s = 0; s < nsym; ++s) {
            if (ajc_enabled_) {
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
        SecureMemory::secureWipe(static_cast<void *>(tmp_I),
                                 sizeof(g_v400_harq_fb_tmp_I));
        SecureMemory::secureWipe(static_cast<void *>(tmp_Q),
                                 sizeof(g_v400_harq_fb_tmp_Q));
        SecureMemory::secureWipe(static_cast<void *>(correct_syms),
                                 sizeof(g_v400_sym_scratch));
    } else if (nc == 64) {
        const int nsym64 = cur_nsym64_();
        uint8_t *const correct_syms = g_v400_sym_scratch;
        int enc_n = 0;
        if (ir_mode_) {
            // try_decode_: Decode64_IR 직후 ir_rv_ 가 +1 되므로
            // 피드백용 직전 라운드 RV ≡ (ir_rv_ + 3) & 3
            const int rv_fb = (ir_rv_ + 3) & 3;
            enc_n = FEC_HARQ::Encode64_IR(data, data_len, correct_syms, il,
                                          cur_bps64_, rv_fb, wb_);
        } else {
            enc_n = FEC_HARQ::Encode64_A(data, data_len, correct_syms, il,
                                         cur_bps64_, wb_);
        }
        if (enc_n <= 0) {
            SecureMemory::secureWipe(static_cast<void *>(correct_syms),
                                     sizeof(g_v400_sym_scratch));
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
        SecureMemory::secureWipe(static_cast<void *>(correct_syms),
                                 sizeof(g_v400_sym_scratch));
    }
}
void HTS_V400_Dispatcher::handle_video_(uint32_t decode_ok_mask) noexcept {
    const uint32_t ok = decode_ok_mask & 1u;
    if (ok != 0u) {
        vid_succ_++;
        vid_fail_ = 0;
        if (active_video_ == PayloadMode::VIDEO_16 &&
            vid_succ_ >= VIDEO_RECOVER_TH) {
            active_video_ = PayloadMode::VIDEO_1;
            vid_succ_ = 0;
            if (on_ctrl_ != nullptr) {
                on_ctrl_(PayloadMode::VIDEO_1);
            }
        }
    } else {
        vid_fail_++;
        vid_succ_ = 0;
        if (active_video_ == PayloadMode::VIDEO_1 &&
            vid_fail_ >= VIDEO_FAIL_TH) {
            active_video_ = PayloadMode::VIDEO_16;
            vid_fail_ = 0;
            if (on_ctrl_ != nullptr) {
                on_ctrl_(PayloadMode::VIDEO_16);
            }
        }
    }
}
namespace {
alignas(64) static int16_t g_bp_sink_i[64];
alignas(64) static int16_t g_bp_sink_q[64];
static inline int16_t *bp_dst_i(int16_t *oI, int pos,
                                std::uintptr_t okm) noexcept {
    const std::uintptr_t p = reinterpret_cast<std::uintptr_t>(&oI[pos]);
    return reinterpret_cast<int16_t *>(
        (p & okm) |
        (reinterpret_cast<std::uintptr_t>(g_bp_sink_i) & ~okm));
}
static inline int16_t *bp_dst_q(int16_t *oQ, int pos,
                                std::uintptr_t okm) noexcept {
    const std::uintptr_t p = reinterpret_cast<std::uintptr_t>(&oQ[pos]);
    return reinterpret_cast<int16_t *>(
        (p & okm) |
        (reinterpret_cast<std::uintptr_t>(g_bp_sink_q) & ~okm));
}
} // namespace
int HTS_V400_Dispatcher::Build_Packet(PayloadMode mode, const uint8_t *info,
                                      int ilen, int16_t amp, int16_t *oI,
                                      int16_t *oQ, int max_c) noexcept {
    if (phase_ == RxPhase::RF_SETTLING) {
        return 0;
    }
    if (info == nullptr || oI == nullptr || oQ == nullptr)
        return 0;
    if (ilen < 0 || max_c <= 0)
        return 0;
    /* 신규 PDU 송신: 인코드 RV는 0부터 (try_decode_ 첫 라운드 rv=0 과 정합) */
    ir_rv_ = 0;
    /* BUG-FIX-PRE5: 프리앰블 반복 폐기, amp 부스트로 교체.
       프리앰블+헤더를 boost 배 진폭으로 전송.
       RX: 동기·헤더는 Walsh 인덱스 0..63 — walsh_dec_full_(…, cap=false)로
       전빈 탐색. 페이로드만 2^BPS 제한(cap=true)으로 FEC 심볼 집합과 정합. */
    const int16_t pre_amp =
        static_cast<int16_t>(static_cast<int32_t>(amp) * pre_boost_);
    // [BUG-FIX-PRE2] 프리앰블 반복 전송 — pre_reps_ × PRE_SYM0 + 1 × PRE_SYM1
    const int pre_chips = (pre_reps_ + 1) * 64;
    const uint32_t il = seed_ ^ (tx_seq_ * 0xA5A5A5A5u);
    static constexpr uint8_t k_tx_mb[4] = {0u, 1u, 2u, 3u};
    static constexpr int k_tx_psyms[4] = {FEC_HARQ::NSYM1, FEC_HARQ::NSYM16,
                                          FEC_HARQ::NSYM16, 0};
    const uint32_t mi = static_cast<uint32_t>(mode);
    if (mi > 3u) {
        return 0;
    }
    const uint32_t u0 = static_cast<uint32_t>(mi == 0u);
    const uint32_t u1 = static_cast<uint32_t>(mi == 1u);
    const uint32_t u2 = static_cast<uint32_t>(mi == 2u);
    const uint32_t u3 = static_cast<uint32_t>(mi == 3u);
    const uint32_t u16 = u1 | u2;
    const uint8_t mb = k_tx_mb[mi];
    const int nsym64_live = cur_nsym64_();
    // TPE: header psyms — LUT + DATA runtime nsym64
    const int psyms =
        k_tx_psyms[mi] + static_cast<int>(u3) * nsym64_live;
    const uint32_t ir_hdr_iq_same_u = static_cast<uint32_t>(ir_mode_);
    const uint32_t iq_ind_u =
        static_cast<uint32_t>(iq_mode_ == IQ_Mode::IQ_INDEPENDENT);
    const uint16_t iq_bit =
        static_cast<uint16_t>((iq_ind_u & (1u - ir_hdr_iq_same_u)) *
                              static_cast<uint32_t>(HDR_IQ_BIT));
    uint16_t hdr = (static_cast<uint16_t>(mb & 0x03u) << 10u) | iq_bit |
                   (static_cast<uint16_t>(psyms) & 0x01FFu);

    uint8_t syms_v1[80] = {};
    uint8_t syms16_ir[FEC_HARQ::NSYM16] = {};
    uint8_t syms16_pl[FEC_HARQ::NSYM16] = {};
    uint8_t syms64_ir[FEC_HARQ::NSYM64] = {};
    uint8_t syms64_pl[FEC_HARQ::NSYM64] = {};
    const int irb = static_cast<int>(ir_mode_);

    const int il_v1 = ilen * static_cast<int>(u0);
    const int il_16 = ilen * static_cast<int>(u16);
    const int il_64 = ilen * static_cast<int>(u3);

    const int n_v1 = FEC_HARQ::Encode1(info, il_v1, syms_v1);
    const int enc16_ir =
        FEC_HARQ::Encode16_IR(info, il_16, syms16_ir, il, ir_rv_, wb_);
    const int enc16_pl = FEC_HARQ::Encode16(info, il_16, syms16_pl, il, wb_);
    const int enc16 = enc16_ir * irb + enc16_pl * (1 - irb);
    const int enc64_ir = FEC_HARQ::Encode64_IR(info, il_64, syms64_ir, il,
                                               cur_bps64_, ir_rv_, wb_);
    const int enc64_pl =
        FEC_HARQ::Encode64_A(info, il_64, syms64_pl, il, cur_bps64_, wb_);
    const int enc64 = enc64_ir * irb + enc64_pl * (1 - irb);

    // IR/plain 선택 (TPE 비트마스크 — 분기 없음)
    uint8_t syms16[FEC_HARQ::NSYM16] = {};
    uint8_t syms64[FEC_HARQ::NSYM64] = {};
    const uint32_t ir_mask = 0u - static_cast<uint32_t>(irb);
    const uint32_t pl_mask = ~ir_mask;
    for (int i = 0; i < FEC_HARQ::NSYM16; ++i) {
        syms16[i] = static_cast<uint8_t>(
            (static_cast<uint32_t>(syms16_ir[i]) & ir_mask) |
            (static_cast<uint32_t>(syms16_pl[i]) & pl_mask));
    }
    for (int i = 0; i < FEC_HARQ::NSYM64; ++i) {
        syms64[i] = static_cast<uint8_t>(
            (static_cast<uint32_t>(syms64_ir[i]) & ir_mask) |
            (static_cast<uint32_t>(syms64_pl[i]) & pl_mask));
    }

    // TPE: per-mode encode validity — inactive mode is always “ok”
    const uint32_t ok_v1 =
        (1u - u0) | (0u - static_cast<uint32_t>(n_v1 > 0));
    const uint32_t ok_16 =
        (1u - u16) | (0u - static_cast<uint32_t>(enc16 > 0));
    const uint32_t ok_64 =
        (1u - u3) | (0u - static_cast<uint32_t>(enc64 > 0));
    uint32_t go_enc = ~(0u);
    go_enc &= ok_v1 & ok_16 & ok_64;

    // TPE: pay chip budget from masked mode contributions
    int pay_raw = (n_v1 * static_cast<int>(u0)) +
                  (FEC_HARQ::NSYM16 * 16 * static_cast<int>(u16)) +
                  (nsym64_live * 64 * static_cast<int>(u3));
    pay_raw &= -static_cast<int>(go_enc & 1u);
    const int total_need = pre_chips + 128 + pay_raw;
    uint32_t go = go_enc;
    go &= static_cast<uint32_t>(total_need <= max_c);

    // TPE: pointer sink mask — intptr_t sign, no 0ull−bit wrap
    const std::uintptr_t okm = static_cast<std::uintptr_t>(
        -static_cast<std::intptr_t>(go & 1u));
    const int inc = static_cast<int>(go & 1u);

    int pos = 0;
    for (int r = 0; r < pre_reps_; ++r) {
        walsh_enc(PRE_SYM0, 64, pre_amp, bp_dst_i(oI, pos, okm),
                  bp_dst_q(oQ, pos, okm));
        pos += 64 * inc;
    }
    walsh_enc(PRE_SYM1, 64, pre_amp, bp_dst_i(oI, pos, okm),
              bp_dst_q(oQ, pos, okm));
    pos += 64 * inc;
    walsh_enc(static_cast<uint8_t>((hdr >> 6u) & 0x3Fu), 64, pre_amp,
              bp_dst_i(oI, pos, okm), bp_dst_q(oQ, pos, okm));
    pos += 64 * inc;
    walsh_enc(static_cast<uint8_t>(hdr & 0x3Fu), 64, pre_amp,
              bp_dst_i(oI, pos, okm), bp_dst_q(oQ, pos, okm));
    pos += 64 * inc;

    const int n_send_v1 = n_v1 * inc * static_cast<int>(u0);
    for (int s = 0; s < n_send_v1; ++s) {
        const uint8_t sv = syms_v1[static_cast<std::size_t>(s)];
        const uint32_t nz = 0u - static_cast<uint32_t>(sv != 0u);
        const int32_t amp32 = static_cast<int32_t>(amp);
        const int32_t v32 =
            amp32 + (static_cast<int32_t>(nz) & (-2 * amp32));
        const int16_t v = static_cast<int16_t>(v32);
        int16_t *const di = bp_dst_i(oI, pos, okm);
        int16_t *const dq = bp_dst_q(oQ, pos, okm);
        di[0] = v;
        dq[0] = v;
        pos += inc;
    }
    SecureMemory::secureWipe(static_cast<void *>(syms_v1), sizeof(syms_v1));

    const int n_send16 = FEC_HARQ::NSYM16 * inc * static_cast<int>(u16);
    for (int s = 0; s < n_send16; ++s) {
        walsh_enc(syms16[static_cast<std::size_t>(s)], 16, amp,
                  bp_dst_i(oI, pos, okm), bp_dst_q(oQ, pos, okm));
        pos += 16 * inc;
    }
    SecureMemory::secureWipe(static_cast<void *>(syms16), sizeof(syms16));
    SecureMemory::secureWipe(static_cast<void *>(syms16_ir), sizeof(syms16_ir));
    SecureMemory::secureWipe(static_cast<void *>(syms16_pl), sizeof(syms16_pl));

    // TPE: DATA split path gated by u3 — non-DATA ⇒ 0 Walsh iterations
    const uint32_t split_u =
        static_cast<uint32_t>(static_cast<uint32_t>(!ir_mode_) &
                              iq_ind_u & u3);
    const int npairs = ((nsym64_live + 1) / 2) * inc * static_cast<int>(u3);
    const int nwal = nsym64_live * inc * static_cast<int>(u3);
    const int n_spl = npairs * static_cast<int>(split_u & 1u);
    const int n_sim = nwal * static_cast<int>((split_u ^ 1u) & 1u);
    for (int p = 0; p < n_spl; ++p) {
        const int s = p * 2;
        const uint8_t sI = syms64[static_cast<std::size_t>(s)];
        const uint32_t s2u = static_cast<uint32_t>(s + 1);
        const uint32_t nsymu = static_cast<uint32_t>(nsym64_live);
        const uint32_t have2 = 0u - static_cast<uint32_t>(s2u < nsymu);
        const size_t idx2 =
            static_cast<size_t>(s2u) & static_cast<size_t>(have2);
        const uint8_t sQ = static_cast<uint8_t>(
            static_cast<uint32_t>(syms64[idx2]) & (have2 & 0xFFu));
        walsh_enc_split(sI, sQ, 64, amp, bp_dst_i(oI, pos, okm),
                        bp_dst_q(oQ, pos, okm));
        pos += 64 * inc;
    }
    for (int s = 0; s < n_sim; ++s) {
        walsh_enc(syms64[static_cast<std::size_t>(s)], 64, amp,
                  bp_dst_i(oI, pos, okm), bp_dst_q(oQ, pos, okm));
        pos += 64 * inc;
    }
    SecureMemory::secureWipe(static_cast<void *>(syms64), sizeof(syms64));
    SecureMemory::secureWipe(static_cast<void *>(syms64_ir), sizeof(syms64_ir));
    SecureMemory::secureWipe(static_cast<void *>(syms64_pl), sizeof(syms64_pl));

    tx_seq_ += static_cast<uint32_t>(go & 1u);
    return pos;
}
/* BUG-FIX-RETX3: HARQ 연속모드 TX — 프리앰블/헤더 생략 */
int HTS_V400_Dispatcher::Build_Retx(PayloadMode mode, const uint8_t *info,
                                    int ilen, int16_t amp, int16_t *oI,
                                    int16_t *oQ, int max_c) noexcept {
    if (phase_ == RxPhase::RF_SETTLING) {
        return 0;
    }
    if (info == nullptr || oI == nullptr || oQ == nullptr)
        return 0;
    if (ilen < 0 || max_c <= 0)
        return 0;
    int pos = 0;
    /* Build_Packet가 tx_seq_++ 한 뒤이므로 Retx il은 직전 송신
       시퀀스(tx_seq_-1)와 수신 il(seed_ ^ rx_seq_*0xA5A5A5A5) 정합 */
    const uint32_t tx_seq_prev = (tx_seq_ > 0u) ? (tx_seq_ - 1u) : 0u;
    const uint32_t il = seed_ ^ (tx_seq_prev * 0xA5A5A5A5u);
    const uint32_t mi = static_cast<uint32_t>(mode);
    if (mi > 3u || mi == 0u) {
        return 0;
    }
    const uint32_t u1 = static_cast<uint32_t>(mi == 1u);
    const uint32_t u2 = static_cast<uint32_t>(mi == 2u);
    const uint32_t u3 = static_cast<uint32_t>(mi == 3u);
    const uint32_t u16 = u1 | u2;
    const uint32_t iq_ind_u =
        static_cast<uint32_t>(iq_mode_ == IQ_Mode::IQ_INDEPENDENT);

    uint8_t syms16_ir[FEC_HARQ::NSYM16] = {};
    uint8_t syms16_pl[FEC_HARQ::NSYM16] = {};
    uint8_t syms64_ir[FEC_HARQ::NSYM64] = {};
    uint8_t syms64_pl[FEC_HARQ::NSYM64] = {};
    const int irb = static_cast<int>(ir_mode_);

    const int il_16 = ilen * static_cast<int>(u16);
    const int il_64 = ilen * static_cast<int>(u3);

    const int enc16_ir =
        FEC_HARQ::Encode16_IR(info, il_16, syms16_ir, il, ir_rv_, wb_);
    const int enc16_pl = FEC_HARQ::Encode16(info, il_16, syms16_pl, il, wb_);
    const int enc16 = enc16_ir * irb + enc16_pl * (1 - irb);

    const int enc64_ir = FEC_HARQ::Encode64_IR(info, il_64, syms64_ir, il,
                                               cur_bps64_, ir_rv_, wb_);
    const int enc64_pl =
        FEC_HARQ::Encode64_A(info, il_64, syms64_pl, il, cur_bps64_, wb_);
    const int enc64 = enc64_ir * irb + enc64_pl * (1 - irb);

    // IR/plain 선택 (TPE 비트마스크)
    uint8_t syms16[FEC_HARQ::NSYM16] = {};
    uint8_t syms64[FEC_HARQ::NSYM64] = {};
    const uint32_t ir_mask = 0u - static_cast<uint32_t>(irb);
    const uint32_t pl_mask = ~ir_mask;
    for (int i = 0; i < FEC_HARQ::NSYM16; ++i) {
        syms16[i] = static_cast<uint8_t>(
            (static_cast<uint32_t>(syms16_ir[i]) & ir_mask) |
            (static_cast<uint32_t>(syms16_pl[i]) & pl_mask));
    }
    for (int i = 0; i < FEC_HARQ::NSYM64; ++i) {
        syms64[i] = static_cast<uint8_t>(
            (static_cast<uint32_t>(syms64_ir[i]) & ir_mask) |
            (static_cast<uint32_t>(syms64_pl[i]) & pl_mask));
    }

    const uint32_t bad_enc =
        (u16 & (0u - static_cast<uint32_t>(enc16 <= 0))) |
        (u3 & (0u - static_cast<uint32_t>(enc64 <= 0)));
    if (bad_enc != 0u) {
        SecureMemory::secureWipe(static_cast<void *>(syms16), sizeof(syms16));
        SecureMemory::secureWipe(static_cast<void *>(syms16_ir), sizeof(syms16_ir));
        SecureMemory::secureWipe(static_cast<void *>(syms16_pl), sizeof(syms16_pl));
        SecureMemory::secureWipe(static_cast<void *>(syms64), sizeof(syms64));
        SecureMemory::secureWipe(static_cast<void *>(syms64_ir), sizeof(syms64_ir));
        SecureMemory::secureWipe(static_cast<void *>(syms64_pl), sizeof(syms64_pl));
        return 0;
    }

    const int n16_loop = FEC_HARQ::NSYM16 * static_cast<int>(u16);
    for (int s = 0; s < n16_loop; ++s) {
        const int space = max_c - pos;
        if (space < 16) {
            SecureMemory::secureWipe(static_cast<void *>(syms16),
                                     sizeof(syms16));
            SecureMemory::secureWipe(static_cast<void *>(syms16_ir),
                                     sizeof(syms16_ir));
            SecureMemory::secureWipe(static_cast<void *>(syms16_pl),
                                     sizeof(syms16_pl));
            SecureMemory::secureWipe(static_cast<void *>(syms64),
                                     sizeof(syms64));
            SecureMemory::secureWipe(static_cast<void *>(syms64_ir),
                                     sizeof(syms64_ir));
            SecureMemory::secureWipe(static_cast<void *>(syms64_pl),
                                     sizeof(syms64_pl));
            return 0;
        }
        walsh_enc(syms16[static_cast<std::size_t>(s)], 16, amp, &oI[pos],
                  &oQ[pos]);
        pos += 16;
    }

    const int nsym = cur_nsym64_() * static_cast<int>(u3);
    const uint32_t split_u =
        static_cast<uint32_t>(static_cast<uint32_t>(!ir_mode_) & iq_ind_u &
                              u3);
    const int npairs = ((nsym + 1) / 2) * static_cast<int>(u3);
    const int n_spl = npairs * static_cast<int>(split_u & 1u);
    const int n_sim =
        nsym * static_cast<int>(u3) * static_cast<int>((split_u ^ 1u) & 1u);

    for (int p = 0; p < n_spl; ++p) {
        const int s = p * 2;
        const int space = max_c - pos;
        if (space < 64) {
            SecureMemory::secureWipe(static_cast<void *>(syms16),
                                     sizeof(syms16));
            SecureMemory::secureWipe(static_cast<void *>(syms16_ir),
                                     sizeof(syms16_ir));
            SecureMemory::secureWipe(static_cast<void *>(syms16_pl),
                                     sizeof(syms16_pl));
            SecureMemory::secureWipe(static_cast<void *>(syms64),
                                     sizeof(syms64));
            SecureMemory::secureWipe(static_cast<void *>(syms64_ir),
                                     sizeof(syms64_ir));
            SecureMemory::secureWipe(static_cast<void *>(syms64_pl),
                                     sizeof(syms64_pl));
            return 0;
        }
        const uint8_t sI = syms64[static_cast<std::size_t>(s)];
        const uint32_t s2u = static_cast<uint32_t>(s + 1);
        const uint32_t nsymu = static_cast<uint32_t>(nsym);
        const uint32_t have2 = 0u - static_cast<uint32_t>(s2u < nsymu);
        const size_t idx2 =
            static_cast<size_t>(s2u) & static_cast<size_t>(have2);
        const uint8_t sQ = static_cast<uint8_t>(
            static_cast<uint32_t>(syms64[idx2]) & (have2 & 0xFFu));
        walsh_enc_split(sI, sQ, 64, amp, &oI[pos], &oQ[pos]);
        pos += 64;
    }
    for (int s = 0; s < n_sim; ++s) {
        const int space = max_c - pos;
        if (space < 64) {
            SecureMemory::secureWipe(static_cast<void *>(syms16),
                                     sizeof(syms16));
            SecureMemory::secureWipe(static_cast<void *>(syms16_ir),
                                     sizeof(syms16_ir));
            SecureMemory::secureWipe(static_cast<void *>(syms16_pl),
                                     sizeof(syms16_pl));
            SecureMemory::secureWipe(static_cast<void *>(syms64),
                                     sizeof(syms64));
            SecureMemory::secureWipe(static_cast<void *>(syms64_ir),
                                     sizeof(syms64_ir));
            SecureMemory::secureWipe(static_cast<void *>(syms64_pl),
                                     sizeof(syms64_pl));
            return 0;
        }
        walsh_enc(syms64[static_cast<std::size_t>(s)], 64, amp, &oI[pos],
                  &oQ[pos]);
        pos += 64;
    }

    SecureMemory::secureWipe(static_cast<void *>(syms16), sizeof(syms16));
    SecureMemory::secureWipe(static_cast<void *>(syms16_ir), sizeof(syms16_ir));
    SecureMemory::secureWipe(static_cast<void *>(syms16_pl), sizeof(syms16_pl));
    SecureMemory::secureWipe(static_cast<void *>(syms64), sizeof(syms64));
    SecureMemory::secureWipe(static_cast<void *>(syms64_ir), sizeof(syms64_ir));
    SecureMemory::secureWipe(static_cast<void *>(syms64_pl), sizeof(syms64_pl));
    return pos;
}
void HTS_V400_Dispatcher::Feed_Chip(int16_t rx_I, int16_t rx_Q) noexcept {
    if (phase_ == RxPhase::RF_SETTLING) {
        (void)rx_I;
        (void)rx_Q;
        const uint32_t nz =
            static_cast<uint32_t>(rf_settle_chips_remaining_ > 0);
        rf_settle_chips_remaining_ -= static_cast<int>(nz);
        if (rf_settle_chips_remaining_ == 0) {
            (void)set_phase_(RxPhase::WAIT_SYNC);
        }
        return;
    }
    if (phase_ == RxPhase::WAIT_SYNC) {
        // ════════════════════════════════════════════════
        //  2단계 하이브리드 동기화 (Sync & Accumulate)
        //
        //  Phase 0 (슬라이딩 탐색):
        //   1심볼(64칩) 단위 FWHT, 1칩 슬라이드
        //   PRE_SYM0 검출 → 타이밍 락 → Phase 1
        //
        //  Phase 1 (제자리 누적):
        //   타이밍 고정, 64칩 정렬 수집
        //   PRE_SYM0 → 누적 (에너지 증폭)
        //   PRE_SYM1 → 동기 완료 → READ_HEADER
        // ════════════════════════════════════════════════
        if (wait_sync_count_ >= 64)
            return;
        const int widx = (wait_sync_head_ + wait_sync_count_) & 63;
        buf_I_[widx] = rx_I;
        buf_Q_[widx] = rx_Q;
        wait_sync_count_++;
        if (wait_sync_count_ < 64)
            return;
        for (int j = 0; j < 64; ++j) {
            const int p = (wait_sync_head_ + j) & 63;
            orig_I_[j] = buf_I_[p];
            orig_Q_[j] = buf_Q_[p];
        }
        cw_cancel_64_(orig_I_, orig_Q_);
        if (ajc_enabled_) {
            ajc_.Process(orig_I_, orig_Q_, 64);
        }
        if (soft_clip_policy_ != SoftClipPolicy::NEVER) {
            soft_clip_iq(orig_I_, orig_Q_, 64, scratch_mag_, scratch_sort_);
        }
        if (pre_phase_ == 0) {
            // ── Phase 0: 누적 기반 프리앰블 검출 ──
            //  매 64칩 윈도우를 g_pre_acc_I/Q에 누적
            //  누적 후 FWHT → PRE_SYM0 검출 시도
            //  신호: coherent ×N, 잡음: √N → SNR ∝ √N
            //  pre_reps_=8 → +9dB 동기 이득
            if (g_pre_acc_n == 0) {
                // 첫 윈도우: 누적 버퍼 초기화
                for (int j = 0; j < 64; ++j) {
                    g_pre_acc_I[j] = static_cast<int32_t>(orig_I_[j]);
                    g_pre_acc_Q[j] = static_cast<int32_t>(orig_Q_[j]);
                }
                g_pre_acc_n = 1;
            } else {
                // 후속 윈도우: coherent 누적
                for (int j = 0; j < 64; ++j) {
                    g_pre_acc_I[j] += static_cast<int32_t>(orig_I_[j]);
                    g_pre_acc_Q[j] += static_cast<int32_t>(orig_Q_[j]);
                }
                g_pre_acc_n++;
            }

            // 누적 버퍼로 FWHT → 검출 시도
            for (int j = 0; j < 64; ++j) {
                dec_wI_[j] = g_pre_acc_I[j];
                dec_wQ_[j] = g_pre_acc_Q[j];
            }
            fwht_raw(dec_wI_, 64);
            fwht_raw(dec_wQ_, 64);
            int32_t best_c = INT32_MIN;
            uint8_t best_m = 0u;
            for (int m = 0; m < 64; ++m) {
                const int32_t c = dec_wI_[m] + dec_wQ_[m];
                const uint32_t gt = 0u - static_cast<uint32_t>(c > best_c);
                best_c =
                    static_cast<int32_t>((static_cast<uint32_t>(c) & gt) |
                                         (static_cast<uint32_t>(best_c) & ~gt));
                best_m =
                    static_cast<uint8_t>((static_cast<uint32_t>(m) & gt) |
                                         (static_cast<uint32_t>(best_m) & ~gt));
            }

            // ── First Partial Reference: 신호 레벨 독립 검출 ──
            static constexpr int32_t k_NOISE_FLOOR = 100;

            if (best_m == PRE_SYM0 && best_c > k_NOISE_FLOOR) {
                m63_gap_ = 0;
                if (first_c63_ == 0) {
                    first_c63_ = best_c;
                } else if (static_cast<int64_t>(best_c) >
                           static_cast<int64_t>(first_c63_) * 3) {
                    pre_phase_ = 1;
                    wait_sync_head_ = 0;
                    wait_sync_count_ = 0;
                    buf_idx_ = 0;
                    first_c63_ = 0;
                    m63_gap_ = 0;
                }
            } else {
                m63_gap_++;
                if (m63_gap_ > 128) {
                    first_c63_ = 0;
                }
            }

            if (g_pre_acc_n >= pre_reps_ && pre_phase_ == 0) {
                std::memset(g_pre_acc_I, 0, sizeof(g_pre_acc_I));
                std::memset(g_pre_acc_Q, 0, sizeof(g_pre_acc_Q));
                g_pre_acc_n = 0;
                wait_sync_head_ = (wait_sync_head_ + 1) & 63;
                wait_sync_count_ = 63;
            } else if (pre_phase_ == 0 && g_pre_acc_n < pre_reps_) {
                wait_sync_head_ = 0;
                wait_sync_count_ = 0;
            }
        } else {
            // ── Phase 1: 제자리 누적 (타이밍 락 상태) ──
            SymDecResult r0 = walsh_dec_full_(orig_I_, orig_Q_, 64, false);
            int8_t sym = r0.sym;
            if (sym == static_cast<int8_t>(PRE_SYM1)) {
                // ── 동기 완료 → READ_HEADER ──
                set_phase_(RxPhase::READ_HEADER);
                hdr_count_ = 0;
                hdr_fail_ = 0;
                wait_sync_head_ = 0;
                wait_sync_count_ = 0;
                buf_idx_ = 0;
            } else if (sym == static_cast<int8_t>(PRE_SYM0)) {
                // ── PRE_SYM0 반복: 제자리 누적 ──
                for (int j = 0; j < 64; ++j) {
                    g_pre_acc_I[j] += static_cast<int32_t>(orig_I_[j]);
                    g_pre_acc_Q[j] += static_cast<int32_t>(orig_Q_[j]);
                }
                g_pre_acc_n++;
                wait_sync_head_ = 0;
                wait_sync_count_ = 0;
                buf_idx_ = 0;
            } else {
                // 예상 외 심볼 → Phase 0 리셋
                pre_phase_ = 0;
                first_c63_ = 0;
                m63_gap_ = 0;
                std::memset(g_pre_acc_I, 0, sizeof(g_pre_acc_I));
                std::memset(g_pre_acc_Q, 0, sizeof(g_pre_acc_Q));
                g_pre_acc_n = 0;
                wait_sync_head_ = (wait_sync_head_ + 1) & 63;
                wait_sync_count_ = 63;
            }
        }
        return;
    }
    if (buf_idx_ >= 64)
        return;
    buf_I_[buf_idx_] = rx_I;
    buf_Q_[buf_idx_] = rx_Q;
    buf_idx_++;
    if (phase_ == RxPhase::READ_HEADER) {
        if (buf_idx_ == 64) {
            std::memcpy(orig_I_, buf_I_, 64 * sizeof(int16_t));
            std::memcpy(orig_Q_, buf_Q_, 64 * sizeof(int16_t));
            cw_cancel_64_(orig_I_, orig_Q_);
            if (ajc_enabled_) {
                ajc_.Process(orig_I_, orig_Q_, 64);
            }
            /* BUG-FIX-SC2: soft_clip 정책 분기 — ALWAYS=기존동작,
             * SYNC_ONLY=페이로드OFF, NEVER=전체OFF */
            if (soft_clip_policy_ != SoftClipPolicy::NEVER) {
                soft_clip_iq(orig_I_, orig_Q_, 64, scratch_mag_, scratch_sort_);
            }
            SymDecResult rh = walsh_dec_full_(orig_I_, orig_Q_, 64, false);
            int8_t sym = rh.sym;
            if (sym >= 0 && sym < 64) {
                hdr_syms_[hdr_count_] = static_cast<uint8_t>(sym);
                hdr_count_++;
            } else {
                hdr_fail_++;
                if (hdr_fail_ >= HDR_FAIL_MAX)
                    full_reset_();
            }
            if (hdr_count_ >= HDR_SYMS) {
                PayloadMode mode;
                int plen = 0;
                if (parse_hdr_(mode, plen) != 0u) {
                    cur_mode_ = mode;
                    pay_cps_ = (mode == PayloadMode::VIDEO_1) ? 1
                               : (mode == PayloadMode::DATA)  ? 64
                                                              : 16;
                    pay_total_ = plen;
                    pay_recv_ = 0;
                    v1_idx_ = 0;
                    sym_idx_ = 0;
                    max_harq_ = FEC_HARQ::DATA_K; // 모든 모드에서 32
                    set_phase_(RxPhase::READ_PAYLOAD);
                    buf_idx_ = 0;
                    //  try_decode_ 내부에서 Init → Feed 이후라 데이터 파괴
                    //  READ_PAYLOAD 진입 시 첫 라운드만 Init
                    if (!harq_inited_) {
                        if (mode == PayloadMode::VIDEO_16 ||
                            mode == PayloadMode::VOICE) {
                            if (ir_mode_) {
                                SecureMemory::secureWipe(
                                    static_cast<void *>(&g_harq_ccm_union),
                                    sizeof(g_harq_ccm_union));
                                if (ir_state_ != nullptr) {
                                    FEC_HARQ::IR_Init(*ir_state_);
                                }
                                ir_rv_ = 0;
                            } else {
                                FEC_HARQ::Init16(rx_.m16);
                            }
                        } else if (mode == PayloadMode::DATA) {
                            // DATA READ_PAYLOAD: CCM union 전체 한 회 wipe
                            SecureMemory::secureWipe(
                                static_cast<void *>(&g_harq_ccm_union),
                                sizeof(g_harq_ccm_union));
                            if (ir_mode_) {
                                if (ir_state_ != nullptr) {
                                    FEC_HARQ::IR_Init(*ir_state_);
                                }
                                ir_rv_ = 0;
                            } else {
                                SecureMemory::secureWipe(
                                    static_cast<void *>(rx_.m64_I.aI),
                                    sizeof(rx_.m64_I.aI));
                                rx_.m64_I.k = 0;
                                rx_.m64_I.ok = false;
                            }
                        }
                        harq_inited_ = true;
                    }
                    if (pay_cps_ != ajc_last_nc_) {
                        ajc_.Reset(pay_cps_);
                        ajc_last_nc_ = pay_cps_;
                    }
                } else {
                    full_reset_();
                }
            }
            if (phase_ == RxPhase::READ_HEADER)
                buf_idx_ = 0;
        }
    } else if (phase_ == RxPhase::READ_PAYLOAD) {
        if (buf_idx_ >= pay_cps_)
            on_sym_();
    }
}
/* BUG-FIX-RETX4: HARQ 연속모드 RX */
void HTS_V400_Dispatcher::Feed_Retx_Chip(int16_t rx_I, int16_t rx_Q) noexcept {
    if (phase_ == RxPhase::RF_SETTLING) {
        return;
    }
    if (!retx_ready_ || phase_ != RxPhase::READ_PAYLOAD)
        return;
    if (buf_idx_ >= 64)
        return;
    buf_I_[buf_idx_] = rx_I;
    buf_Q_[buf_idx_] = rx_Q;
    buf_idx_++;
    if (buf_idx_ >= pay_cps_)
        on_sym_();
}
void HTS_V400_Dispatcher::Inject_Payload_Phase(PayloadMode mode,
                                               int bps) noexcept {
    // 동기/헤더 단계를 건너뛰고 READ_PAYLOAD로 직접 진입
    // IR 상태 초기화 포함
    full_reset_();

    cur_mode_ = mode;
    if (mode == PayloadMode::DATA) {
        cur_bps64_ = FEC_HARQ::bps_clamp_runtime(bps);
        pay_cps_ = 64;
        pay_total_ = FEC_HARQ::nsym_for_bps(cur_bps64_);
    } else if (mode == PayloadMode::VOICE || mode == PayloadMode::VIDEO_16) {
        pay_cps_ = 16;
        pay_total_ = FEC_HARQ::NSYM16;
    } else {
        return; // VIDEO_1은 미지원
    }

    pay_recv_ = 0;
    sym_idx_ = 0;
    max_harq_ = FEC_HARQ::DATA_K;
    phase_ = RxPhase::READ_PAYLOAD;
    buf_idx_ = 0;

    // HARQ/IR 초기화
    SecureMemory::secureWipe(static_cast<void *>(&g_harq_ccm_union),
                             sizeof(g_harq_ccm_union));
    if (ir_mode_ && ir_state_ != nullptr) {
        FEC_HARQ::IR_Init(*ir_state_);
    }
    ir_rv_ = 0;
    harq_inited_ = true;
    retx_ready_ = false;

    if (pay_cps_ != ajc_last_nc_) {
        ajc_.Reset(pay_cps_);
        ajc_last_nc_ = pay_cps_;
    }
}
} // namespace ProtectedEngine
