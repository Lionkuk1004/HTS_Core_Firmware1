// =============================================================================
// HTS_FEC_HARQ.cpp — V400 3모드 (1칩/16칩/64칩)
// Target: STM32F407VGT6 (Cortex-M4F) / PC
//
#include "HTS_FEC_HARQ.hpp"
#include <array>
#include <climits>
#include <cstring>

namespace ProtectedEngine {

    // 컴파일 타임 고정 스택 버퍼 — VLA/alloca 경로 배제 (임베디드 규약)
    static constexpr std::size_t k_conv_out_sz =
        static_cast<std::size_t>(FEC_HARQ::CONV_OUT);
    static constexpr std::size_t k_fwht_buf_sz =
        static_cast<std::size_t>(FEC_HARQ::C64);
    static constexpr std::size_t k_llr_buf_sz =
        static_cast<std::size_t>(FEC_HARQ::BPS64_MAX);

    static_assert(FEC_HARQ::BPS64_MAX >= 1,
        "BPS64_MAX must be positive");
    static_assert(FEC_HARQ::BPS64_MAX <= FEC_HARQ::C64,
        "Bin_To_LLR bps exceeds scratch");

    template <int N>
    static inline void FWHT_Fixed(int32_t* d) noexcept {
        for (int len = 1; len < N; len <<= 1) {
            for (int i = 0; i < N; i += (len << 1)) {
                for (int j = 0; j < len; ++j) {
                    const int32_t u = d[i + j];
                    const int32_t v = d[i + len + j];
                    d[i + j] = u + v;
                    d[i + len + j] = u - v;
                }
            }
        }
    }

    // ── CRC-16/CCITT ──
    uint16_t FEC_HARQ::CRC16(const uint8_t* d, int len) noexcept {
        if (!d || len <= 0) return 0u;
        uint16_t crc = 0xFFFFu;
        for (int i = 0; i < len; ++i) {
            crc ^= static_cast<uint16_t>(d[i]) << 8u;
            for (int b = 0; b < 8; ++b)
                crc = (crc & 0x8000u)
                ? static_cast<uint16_t>((crc << 1u) ^ 0x1021u)
                : static_cast<uint16_t>(crc << 1u);
        }
        return crc;
    }

    // ── FWHT (int32_t, 가변 크기: 16 또는 64) ───────────────────
    void FEC_HARQ::FWHT(int32_t* d, int n) noexcept {
        if (d == nullptr || n <= 1) { return; }
        if (n == 16) { FWHT_Fixed<16>(d); return; }
        if (n == 64) { FWHT_Fixed<64>(d); return; }

        for (int len = 1; len < n; len <<= 1) {
            for (int i = 0; i < n; i += (len << 1)) {
                for (int j = 0; j < len; ++j) {
                    const int32_t u = d[i + j];
                    const int32_t v = d[i + len + j];
                    d[i + j] = u + v;
                    d[i + len + j] = u - v;
                }
            }
        }
    }

    // ── 7비트 Popcount LUT ──
    static constexpr uint8_t k_pc7_lut[128] = {
        0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4,
        1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,
        1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,
        2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
        1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,
        2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
        2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
        3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7
    };

    static constexpr int pc7(uint8_t x) noexcept {
        return k_pc7_lut[x & 0x7Fu];
    }

    // ── Conv Encoder ──
    void FEC_HARQ::Conv_Encode(const uint8_t* in, int n, uint8_t* out) noexcept {
        uint8_t sr = 0u;
        for (int i = 0; i < n; ++i) {
            uint8_t r = static_cast<uint8_t>(((in[i] & 1u) << 6u) | sr);
            out[2 * i] = static_cast<uint8_t>(pc7(r & G0) & 1);
            out[2 * i + 1] = static_cast<uint8_t>(pc7(r & G1) & 1);
            sr = static_cast<uint8_t>((r >> 1u) & 0x3Fu);
        }
    }

    // ── Soft Viterbi ───────────────────────────────────────────
    //
    void FEC_HARQ::Viterbi_Decode(const int32_t* soft, int nc,
        uint8_t* out, int no, WorkBuf& wb) noexcept {
        if (!soft || !out || nc < 2 || no < 1) return;

        // ⑨ T = nc>>1
        const int T = nc >> 1;
        //  steps 상한 VIT_STEPS — surv/tb 배열 경계와 일치
        const int steps = (T < VIT_STEPS) ? T : VIT_STEPS;

        static constexpr int32_t DEAD_STATE = -1000000000;

        for (int s = 0; s < 64; ++s) wb.pm[0][s] = DEAD_STATE;
        wb.pm[0][0] = 0;
        int cur = 0;

        for (int t = 0; t < steps; ++t) {
            int nxt = 1 - cur;
            for (int s = 0; s < 64; ++s) wb.pm[nxt][s] = DEAD_STATE;
            int32_t s0 = soft[2 * t], s1 = soft[2 * t + 1];

            for (int st = 0; st < 64; ++st) {
                if (wb.pm[cur][st] <= DEAD_STATE) continue;
                for (int bit = 0; bit <= 1; ++bit) {
                    uint8_t r = static_cast<uint8_t>(
                        (static_cast<uint8_t>(bit) << 6u) |
                        static_cast<uint8_t>(st));
                    int ns = static_cast<int>((r >> 1u) & 0x3Fu);
                    int e0 = pc7(static_cast<uint8_t>(r & G0)) & 1;
                    int e1 = pc7(static_cast<uint8_t>(r & G1)) & 1;
                    int32_t bm = s0 * (1 - 2 * e0) + s1 * (1 - 2 * e1);
                    int32_t np = wb.pm[cur][st] + bm;
                    if (np > wb.pm[nxt][ns]) {
                        wb.pm[nxt][ns] = np;
                        wb.surv[t][ns] = static_cast<uint8_t>(st);
                    }
                }
            }
            cur = nxt;
        }

        int state = 0;
        for (int t = steps - 1; t >= 0; --t) {
            wb.tb[t] = static_cast<uint8_t>((state >> 5) & 1);
            state = static_cast<int>(wb.surv[t][state]);
        }
        for (int i = 0; i < no && i < steps; ++i) out[i] = wb.tb[i];
    }

    // ── LLR: MAX-LOG-MAP + Viterbi 안전 스케일링 ────────────────
    void FEC_HARQ::Bin_To_LLR(const int32_t* fI, const int32_t* fQ,
        int nc, int bps, int32_t* llr) noexcept {

        const int nsym = 1 << bps;
        const int valid = (nsym < nc) ? nsym : nc;

        uint32_t energy[64] = {};
        uint32_t peak = 0u;
        for (int m = 0; m < valid; ++m) {
            const int32_t fi = fI[m];
            const int32_t fq = fQ[m];

            // Square of signed values (no 64-bit storage):
            // abs(x) in uint32_t, then square in uint64_t, finally clamp.
            const uint32_t ufi = static_cast<uint32_t>(fi);
            const uint32_t ufq = static_cast<uint32_t>(fq);
            const uint32_t mask_i = static_cast<uint32_t>(fi >> 31);
            const uint32_t mask_q = static_cast<uint32_t>(fq >> 31);
            const uint32_t abs_i = (ufi ^ mask_i) - mask_i;
            const uint32_t abs_q = (ufq ^ mask_q) - mask_q;

            const uint64_t sq_i = static_cast<uint64_t>(abs_i) *
                static_cast<uint64_t>(abs_i);
            const uint64_t sq_q = static_cast<uint64_t>(abs_q) *
                static_cast<uint64_t>(abs_q);
            const uint64_t e64 = sq_i + sq_q;
            const uint32_t e32 = (e64 > 0xFFFFFFFFull)
                ? 0xFFFFFFFFu : static_cast<uint32_t>(e64);

            energy[m] = e32;
            if (e32 > peak) { peak = e32; }
        }

        int shift = 0;
        //
        //  오버플로 경로: combined = REP(4) × llr_max
        //                bm = 2 × combined
        //                pm = VIT_STEPS(88) × bm
        //
        //  LIMIT=1M: pm_max = 88×2×4×1M = 704M (INT32_MAX의 32.8%, 마진 3배)
        //  LIMIT=100K: pm_max = 88×2×4×100K = 70.4M (INT32_MAX의 3.3%, 마진 30배)
        //
        //  100K에서도 Soft Decision 정밀도 충분:
        //   High SNR: energy~10^12 → shift~27 → llr=max0-max1 ≈ ±100K
        //   Low SNR:  energy~10^6  → shift~0  → llr=max0-max1 ≈ ±50K
        //   양자화 해상도: 100,000 단계 (17비트 상당) → Viterbi 성능 영향 0
        static constexpr uint32_t VITERBI_SAFE_LIMIT = 100000u;
        while (peak > VITERBI_SAFE_LIMIT && shift < 31) {
            peak >>= 1;
            shift++;
        }

        for (int b = 0; b < bps; ++b) {
            uint32_t max0 = 0u, max1 = 0u;
            for (int m = 0; m < valid; ++m) {
                const uint32_t e = energy[m] >> static_cast<uint32_t>(shift);
                if ((m >> (bps - 1 - b)) & 1) {
                    if (e > max1) { max1 = e; }
                }
                else {
                    if (e > max0) { max0 = e; }
                }
            }
            if (max0 >= max1) {
                llr[b] = static_cast<int32_t>(max0 - max1);
            }
            else {
                llr[b] = -static_cast<int32_t>(max1 - max0);
            }
        }
    }

    // ── Xorshift PRNG ──
    static uint32_t xs(uint32_t s) noexcept {
        s ^= s << 13u; s ^= s >> 17u; s ^= s << 5u;
        return s;
    }

    // Lemire fast range reduction: [0, range) 균등 매핑 (mod/div 회피)
    static inline uint32_t fast_range32(uint32_t x, uint32_t range) noexcept {
        return static_cast<uint32_t>(
            (static_cast<uint64_t>(x) * static_cast<uint64_t>(range)) >> 32u);
    }

    // =====================================================================
    //  [항목⑨ 주석] Fisher-Yates 셔플 — 모듈로(%) 불가피 사유
    //
    //  분모 (i+1)은 매 반복마다 1씩 감소하는 가변값이므로
    //  2의 거듭제곱 시프트/마스크로 대체할 수 없습니다.
    //  균등 분포 보장을 위해 정확한 나머지 연산이 필수입니다.
    //
    //  ARM UDIV: 2~12cyc/회 × TOTAL_CODED(688) ≈ 최대 8,256cyc
    //  이는 패킷당 1회 실행 (TX 인코딩 또는 RX 디코딩 시)이므로
    //  168MHz 기준 ~49µs — 실시간 제약(1ms 프레임) 내 충분합니다.
    //
    //  대안 검토:
    //   · 비트 마스크 + 리젝션: 균등 분포 보장하나 루프 비결정론
    //   · 곱셈 기반 (Lemire): 64비트 곱셈 필요 → ARM __aeabi_lmul
    //   → 현재 UDIV가 가장 단순하고 결정론적 (양산 안정성 우선)
    // =====================================================================

    static_assert(FEC_HARQ::TOTAL_CODED <= 1024,
        "TOTAL_CODED > 1024: Fisher-Yates UDIV 오버헤드 재검토 필요");

    void FEC_HARQ::Bit_Interleave(uint8_t* bits, int n, uint32_t seed) noexcept {
        if (!bits || n < 2) return;
        if (n > TOTAL_CODED) return;
        uint32_t s = (seed == 0u) ? 0xDEADBEEFu : seed;
        for (int i = n - 1; i > 0; --i) {
            s = xs(s);
            const uint32_t range = static_cast<uint32_t>(i + 1);
            const int j = static_cast<int>(fast_range32(s, range));
            uint8_t t = bits[i]; bits[i] = bits[j]; bits[j] = t;
        }
    }

    void FEC_HARQ::Bit_Deinterleave(int32_t* soft, int n, uint32_t seed,
        WorkBuf& wb) noexcept {
        if (!soft || n < 2) return;
        if (n > TOTAL_CODED) return;
        for (int i = 0; i < n; ++i) {
            wb.perm[i] = static_cast<uint16_t>(i);
        }
        uint32_t s = (seed == 0u) ? 0xDEADBEEFu : seed;
        for (int i = n - 1; i > 0; --i) {
            s = xs(s);
            const uint32_t range = static_cast<uint32_t>(i + 1);
            const int j = static_cast<int>(fast_range32(s, range));
            const uint16_t t = wb.perm[i];
            wb.perm[i] = wb.perm[static_cast<size_t>(j)];
            wb.perm[static_cast<size_t>(j)] = t;
        }
        std::memset(wb.tmp_soft, 0, sizeof(wb.tmp_soft));
        for (int i = 0; i < n; ++i) {
            wb.tmp_soft[static_cast<size_t>(wb.perm[i])] = soft[i];
        }
        for (int i = 0; i < n; ++i) soft[i] = wb.tmp_soft[i];
    }

    void FEC_HARQ::Gen_Perm(uint32_t seed, uint8_t* p, int n) noexcept {
        if (!p || n <= 0 || n > C64) return;
        for (int i = 0; i < n; ++i) p[i] = static_cast<uint8_t>(i);
        uint32_t s = (seed == 0u) ? 0xDEADBEEFu : seed;
        for (int i = n - 1; i > 0; --i) {
            s = xs(s);
            const uint32_t range = static_cast<uint32_t>(i + 1);
            const int j = static_cast<int>(fast_range32(s, range));
            uint8_t t = p[i]; p[i] = p[j]; p[j] = t;
        }
    }

    void FEC_HARQ::Interleave(int16_t* I, int16_t* Q,
        const uint8_t* p, int n) noexcept {
        if (!I || !Q || !p || n <= 0 || n > C64) return;
        int16_t tI[C64] = {}, tQ[C64] = {};
        for (int i = 0; i < n; ++i) { tI[p[i]] = I[i]; tQ[p[i]] = Q[i]; }
        for (int i = 0; i < n; ++i) { I[i] = tI[i]; Q[i] = tQ[i]; }
    }

    void FEC_HARQ::Deinterleave(int16_t* I, int16_t* Q,
        const uint8_t* p, int n) noexcept {
        if (!I || !Q || !p || n <= 0 || n > C64) return;
        int16_t tI[C64] = {}, tQ[C64] = {};
        for (int i = 0; i < n; ++i) { tI[i] = I[p[i]]; tQ[i] = Q[p[i]]; }
        for (int i = 0; i < n; ++i) { I[i] = tI[i]; Q[i] = tQ[i]; }
    }

    // =================================================================
    //  Encode Core
    // =================================================================
    int FEC_HARQ::Encode_Core(const uint8_t* info, int len, uint8_t* syms,
        uint32_t il, int bps, int nsym, WorkBuf& wb) noexcept {
        if (!info || !syms || len < 1 || len > MAX_INFO) return 0;

        std::array<uint8_t, static_cast<std::size_t>(MAX_INFO + 2)> coded{};
        for (int i = 0; i < len; ++i) coded[static_cast<std::size_t>(i)] = info[i];
        uint16_t crc = CRC16(coded.data(), MAX_INFO);
        coded[static_cast<std::size_t>(MAX_INFO)] =
            static_cast<uint8_t>(crc >> 8u);
        coded[static_cast<std::size_t>(MAX_INFO + 1)] =
            static_cast<uint8_t>(crc & 0xFFu);

        std::array<uint8_t, static_cast<std::size_t>(CONV_IN)> in_bits{};
        for (int i = 0; i < INFO_BITS; ++i)
            in_bits[static_cast<std::size_t>(i)] = static_cast<uint8_t>(
                (coded[static_cast<std::size_t>(i >> 3)] >>
                    (7 - (i & 7))) & 1u);

        std::array<uint8_t, k_conv_out_sz> conv{};
        Conv_Encode(in_bits.data(), CONV_IN, conv.data());

        for (int r = 0; r < REP; ++r)
            for (int i = 0; i < CONV_OUT; ++i)
                wb.rep[r * CONV_OUT + i] = conv[static_cast<std::size_t>(i)];

        Bit_Interleave(wb.rep, TOTAL_CODED, il);

        int idx = 0;
        for (int s = 0; s < nsym; ++s) {
            uint8_t sym = 0u;
            for (int b = 0; b < bps; ++b) {
                int bi = s * bps + b;
                if (bi < TOTAL_CODED)
                    sym |= static_cast<uint8_t>(wb.rep[bi] << (bps - 1 - b));
            }
            syms[idx++] = sym;
        }
        return idx;
    }

    // =================================================================
    //  Decode Core
    // =================================================================
    bool FEC_HARQ::Decode_Core(const int32_t* accI, const int32_t* accQ,
        int nsym, int nc, int bps, uint8_t* out, int* olen,
        uint32_t il, WorkBuf& wb) noexcept {
        if (!accI || !accQ || !out || !olen) return false;
        if (nsym <= 0 || nc <= 0 || bps <= 0) return false;
        if (bps > BPS64_MAX) {
            *olen = 0;
            return false;
        }

        // Encode 경로는 항상 TOTAL_CODED 비트를 인터리브함(Bit_Interleave(..., TOTAL_CODED)).
        // 심볼 격자(nsym×bps)가 그보다 작으면 LLR 슬롯이 비어 복호화가 붕괴됨.
        const int64_t llr_slots =
            static_cast<int64_t>(nsym) * static_cast<int64_t>(bps);
        if (llr_slots < static_cast<int64_t>(TOTAL_CODED)) {
            *olen = 0;
            return false;
        }

        std::memset(wb.all_llr, 0, sizeof(wb.all_llr));

        // FWHT(d, nc) / Bin_To_LLR 는 [0, nc) / [0, bps) 만 사용 — nc·bps 칩 이후 슬롯은 미사용
        std::array<int32_t, k_fwht_buf_sz> fI;
        std::array<int32_t, k_fwht_buf_sz> fQ;
        std::array<int32_t, k_llr_buf_sz> llr{};

        for (int sym = 0; sym < nsym; ++sym) {
            const int base = sym * nc;
            std::memcpy(
                fI.data(),
                accI + base,
                static_cast<std::size_t>(nc) * sizeof(int32_t));
            std::memcpy(
                fQ.data(),
                accQ + base,
                static_cast<std::size_t>(nc) * sizeof(int32_t));
            FWHT(fI.data(), nc);
            FWHT(fQ.data(), nc);

            Bin_To_LLR(fI.data(), fQ.data(), nc, bps, llr.data());

            for (int b = 0; b < bps; ++b) {
                const int bi = sym * bps + b;
                if (bi < TOTAL_CODED) {
                    wb.all_llr[bi] = llr[static_cast<std::size_t>(b)];
                }
            }
        }

        // 역순열 길이는 인코더와 동일하게 TOTAL_CODED(perm/tmp_soft/all_llr 경계와 일치)
        Bit_Deinterleave(wb.all_llr, TOTAL_CODED, il, wb);

        std::memset(wb.combined, 0, sizeof(wb.combined));
        for (int r = 0; r < REP; ++r)
            for (int i = 0; i < CONV_OUT; ++i)
                wb.combined[i] += wb.all_llr[r * CONV_OUT + i];

        std::array<uint8_t, static_cast<std::size_t>(CONV_IN)> dec{};
        Viterbi_Decode(wb.combined, CONV_OUT, dec.data(), CONV_IN, wb);

        std::array<uint8_t, static_cast<std::size_t>(MAX_INFO + 2)> rx{};
        for (int i = 0; i < INFO_BITS; ++i)
            if (dec[static_cast<std::size_t>(i)]) {
                rx[static_cast<std::size_t>(i >> 3)] |=
                    static_cast<uint8_t>(1u << (7 - (i & 7)));
            }

        uint16_t calc = CRC16(rx.data(), MAX_INFO);
        uint16_t stored = (static_cast<uint16_t>(
            rx[static_cast<std::size_t>(MAX_INFO)]) << 8u) |
            static_cast<uint16_t>(rx[static_cast<std::size_t>(MAX_INFO + 1)]);

        if (calc == stored) {
            for (int i = 0; i < MAX_INFO; ++i) {
                out[i] = rx[static_cast<std::size_t>(i)];
            }
            *olen = MAX_INFO;
            return true;
        }
        *olen = 0;
        return false;
    }

    // ── 16칩 래퍼 ──
    int FEC_HARQ::Encode16(const uint8_t* info, int len,
        uint8_t* syms, uint32_t il, WorkBuf& wb) noexcept {
        return Encode_Core(info, len, syms, il, BPS16, NSYM16, wb);
    }

    void FEC_HARQ::Init16(RxState16& s) noexcept {
        std::memset(&s, 0, sizeof(s));
    }

    void FEC_HARQ::Feed16(RxState16& s, const int16_t I[][C16],
        const int16_t Q[][C16]) noexcept {
        if (s.ok) return;
        for (int sym = 0; sym < NSYM16; ++sym)
            for (int c = 0; c < C16; ++c) {
                s.aI[sym][c] += static_cast<int32_t>(I[sym][c]);
                s.aQ[sym][c] += static_cast<int32_t>(Q[sym][c]);
            }
        s.k++;
    }

    bool FEC_HARQ::Decode16(const RxState16& s, uint8_t* out,
        int* len, uint32_t il, WorkBuf& wb) noexcept {
        return Decode_Core(&s.aI[0][0], &s.aQ[0][0],
            NSYM16, C16, BPS16, out, len, il, wb);
    }

    // ── 64칩 래퍼 ──
    int FEC_HARQ::Encode64(const uint8_t* info, int len,
        uint8_t* syms, uint32_t il, WorkBuf& wb) noexcept {
        return Encode_Core(info, len, syms, il, BPS64, NSYM64, wb);
    }

    void FEC_HARQ::Init64(RxState64& s) noexcept {
        std::memset(&s, 0, sizeof(s));
    }

    void FEC_HARQ::Feed64(RxState64& s, const int16_t I[][C64],
        const int16_t Q[][C64]) noexcept {
        if (s.ok) return;
        for (int sym = 0; sym < NSYM64; ++sym)
            for (int c = 0; c < C64; ++c) {
                s.aI[sym][c] += static_cast<int32_t>(I[sym][c]);
                s.aQ[sym][c] += static_cast<int32_t>(Q[sym][c]);
            }
        s.k++;
    }

    bool FEC_HARQ::Decode64(const RxState64& s, uint8_t* out,
        int* len, uint32_t il, WorkBuf& wb) noexcept {
        return Decode_Core(&s.aI[0][0], &s.aQ[0][0],
            NSYM64, C64, BPS64, out, len, il, wb);
    }

    // ── 적응형 64칩 API ──
    int FEC_HARQ::Encode64_A(const uint8_t* info, int len,
        uint8_t* syms, uint32_t il, int bps, WorkBuf& wb) noexcept {
        if (bps < BPS64_MIN || bps > BPS64_MAX) return 0;
        return Encode_Core(info, len, syms, il, bps, nsym_for_bps(bps), wb);
    }

    void FEC_HARQ::Feed64_A(RxState64& s, const int16_t I[][C64],
        const int16_t Q[][C64], int nsym) noexcept {
        if (s.ok) return;
        if (nsym > NSYM64) nsym = NSYM64;
        for (int sym = 0; sym < nsym; ++sym)
            for (int c = 0; c < C64; ++c) {
                s.aI[sym][c] += static_cast<int32_t>(I[sym][c]);
                s.aQ[sym][c] += static_cast<int32_t>(Q[sym][c]);
            }
        s.k++;
    }

    // ── Feed16_1sym — 16칩 심볼 1개 즉시 HARQ 누적 ─────────────
    void FEC_HARQ::Feed16_1sym(RxState16& s, const int16_t* I,
        const int16_t* Q, int sym_idx) noexcept {
        if (s.ok) return;
        if (sym_idx < 0 || sym_idx >= NSYM16) return;
        if (!I || !Q) return;
        for (int c = 0; c < C16; ++c) {
            s.aI[sym_idx][c] += static_cast<int32_t>(I[c]);
            s.aQ[sym_idx][c] += static_cast<int32_t>(Q[c]);
        }
    }

    // ── Feed64_1sym — 64칩 심볼 1개 즉시 HARQ 누적 ─────────────
    void FEC_HARQ::Feed64_1sym(RxState64& s, const int16_t* I,
        const int16_t* Q, int sym_idx) noexcept {
        if (s.ok) return;
        if (sym_idx < 0 || sym_idx >= NSYM64) return;
        if (!I || !Q) return;
        for (int c = 0; c < C64; ++c) {
            s.aI[sym_idx][c] += static_cast<int32_t>(I[c]);
            s.aQ[sym_idx][c] += static_cast<int32_t>(Q[c]);
        }
    }

    // ── Advance_Round — 스트리밍 Feed 후 라운드 카운터 증가 ─────
    void FEC_HARQ::Advance_Round_16(RxState16& s) noexcept {
        if (!s.ok) s.k++;
    }

    void FEC_HARQ::Advance_Round_64(RxState64& s) noexcept {
        if (!s.ok) s.k++;
    }

    bool FEC_HARQ::Decode64_A(const RxState64& s, uint8_t* out,
        int* len, uint32_t il, int bps, WorkBuf& wb) noexcept {
        if (bps < BPS64_MIN || bps > BPS64_MAX) return false;
        return Decode_Core(&s.aI[0][0], &s.aQ[0][0],
            nsym_for_bps(bps), C64, bps, out, len, il, wb);
    }

    // ── Decode_Core_Split — I/Q 분리 배치용 Decode 래퍼 ──────────
    bool FEC_HARQ::Decode_Core_Split(
        const int32_t* accI, const int32_t* accQ,
        int nsym, int nc, int bps,
        uint8_t* out, int* len, uint32_t il, WorkBuf& wb) noexcept {
        if (!accI || !accQ || !out || !len) return false;
        if (nsym <= 0 || nc <= 0) return false;
        if (bps < BPS64_MIN || bps > BPS64_MAX) return false;
        return Decode_Core(accI, accQ, nsym, nc, bps, out, len, il, wb);
    }

    // ── 1칩 BPSK ──
    int FEC_HARQ::Encode1(const uint8_t* info, int len, uint8_t* syms) noexcept {
        if (!info || !syms || len < 1 || len > MAX_INFO) return 0;
        uint8_t coded[MAX_INFO + 2] = {};
        for (int i = 0; i < len; ++i) coded[i] = info[i];
        uint16_t crc = CRC16(coded, MAX_INFO);
        coded[MAX_INFO] = static_cast<uint8_t>(crc >> 8u);
        coded[MAX_INFO + 1] = static_cast<uint8_t>(crc & 0xFFu);
        for (int i = 0; i < INFO_BITS; ++i)
            syms[i] = static_cast<uint8_t>(
                (coded[i >> 3] >> (7 - (i & 7))) & 1u);
        return INFO_BITS;
    }

    bool FEC_HARQ::Decode1(const int16_t* rx_I, uint8_t* out, int* len) noexcept {
        if (!rx_I || !out || !len) return false;
        uint8_t rx[MAX_INFO + 2] = {};
        for (int i = 0; i < INFO_BITS; ++i) {
            uint8_t bit = (rx_I[i] < 0) ? 1u : 0u;
            if (bit) rx[i >> 3] |= static_cast<uint8_t>(1u << (7 - (i & 7)));
        }
        uint16_t calc = CRC16(rx, MAX_INFO);
        uint16_t stored = (static_cast<uint16_t>(rx[MAX_INFO]) << 8u) |
            static_cast<uint16_t>(rx[MAX_INFO + 1]);
        if (calc == stored) {
            for (int i = 0; i < MAX_INFO; ++i) out[i] = rx[i];
            *len = MAX_INFO;
            return true;
        }
        *len = 0;
        return false;
    }

} // namespace ProtectedEngine
