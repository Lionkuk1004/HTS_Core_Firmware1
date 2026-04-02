// =============================================================================
/// @file  HTS_FEC_HARQ.hpp
/// @brief V400 3모드 FEC + HARQ (1칩/16칩/64칩)
/// @target STM32F407VGT6 (Cortex-M4F) / PC
///
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [3모드 운용]
//   VIDEO:  1칩(K=1) → 16칩(K=1) 폴백. FEC 없음, 속도 최우선.
//   VOICE: 16칩 MAX_K=5. Conv(K=7)+Viterbi+Rep4. 지연 ≤8ms.
//   DATA:  64칩 MAX_K=800. Conv(K=7)+Viterbi+Rep4. 무결성.
//
//  [TX 사용법 — 64칩 DATA 모드 기준]
//   FEC_HARQ::WorkBuf wb{};
//   uint8_t syms[FEC_HARQ::NSYM64];
//   int nsym = FEC_HARQ::Encode64(info, 8, syms, il_seed, wb);
//
//  [RX 사용법 — HARQ 루프 (스트리밍)]
//   FEC_HARQ::RxState64 state{};
//   FEC_HARQ::Init64(state);
//   for (int k = 0; k < MAX_K; ++k) {
//       for (int s = 0; s < nsym; ++s) {
//           // ... 수신 칩 I[64], Q[64] → 심볼 1개분 ...
//           FEC_HARQ::Feed64_1sym(state, I, Q, s);
//       }
//       FEC_HARQ::Advance_Round(state);
//       if (FEC_HARQ::Decode64(state, out, &olen, il_seed, wb))
//           break;  // CRC 통과 → 성공
//   }
//
//  [적응형 BPS — 64칩 4단]
//   BPS=3(230심볼): 군용/강재밍 — 최대 보호
//   BPS=4(172심볼): 중간 간섭
//   BPS=5(138심볼): 약한 간섭
//   BPS=6(115심볼): AMI 평시 — 최고 속도
//   TX: Encode64_A(info, len, syms, il, bps, wb)
//   RX: Feed64_1sym(state, I, Q, sym_idx) → Decode64_A(state, out, len, il, bps, wb)
//
//  [메모리 요구량]
//   WorkBuf: ~15KB (Viterbi 실측 사용량 최적화)
//   RxState64: ~115KB (HARQ 누적 I/Q 버퍼)
//   ⚠ 스택 배치 시 ARM 스택 한계 주의
//
//  [보안 설계]
//   CRC-16/CCITT: 데이터 무결성 검증
//   Bit_Interleave: Fisher-Yates 결정론적 셔플 (시드 기반)
//   Gen_Perm + Interleave/Deinterleave: 칩 순열 인터리빙
//   정적 전용 클래스 — 인스턴스화 불가 (상태 없음)
//
#pragma once
#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    class FEC_HARQ {
    public:
        static constexpr int MAX_INFO = 8;
        static constexpr int CRC_BITS = 16;
        static constexpr int INFO_BITS = MAX_INFO * 8 + CRC_BITS;
        static constexpr int CONV_K = 7;
        static constexpr int TAIL = CONV_K - 1;
        static constexpr int CONV_IN = INFO_BITS + TAIL;
        static constexpr int CONV_OUT = CONV_IN * 2;
        static constexpr int REP = 4;
        static constexpr int TOTAL_CODED = CONV_OUT * REP;

        static constexpr uint8_t G0 = 0x79u;  // Conv 생성 다항식 (공개 표준)
        static constexpr uint8_t G1 = 0x5Bu;
        static constexpr int NSTATES = 64;

        static constexpr int C16 = 16;
        static constexpr int BPS16 = 4;
        static constexpr int NSYM16 = (TOTAL_CODED + BPS16 - 1) / BPS16;

        static constexpr int C64 = 64;

        // ── 적응형 BPS (NF+AJC 기반 실시간 전환) ──
        //
        // [양산 4단 — BPS=3~6, NSYM64=230]
        //  BPS=6: AMI 평시 (115심볼, 19.6dB) — 최고 속도
        //  BPS=5: AMI 약간섭 (138심볼, 20.8dB)
        //  BPS=4: AMI 중간섭 (172심볼, 21.4dB)
        //  BPS=3: 군용/강재밍 (230심볼, 22.6dB) — 최대 보호
        //
        // [향후 확장 — BPS=1~2, 별도 SRAM 확보 후 활성화]
        //  BPS=2: 발전소/극한 (344심볼, 24.4dB)
        //  BPS=1: 변전소 탭전환 (688심볼, 27.4dB) — BPSK
        //
        static constexpr int BPS64_MIN = 3;   // 양산: 최대 보호 (군용급)
        static constexpr int BPS64_MAX = 6;   // 양산: 최고 속도 (AMI 평시)
        static constexpr int BPS64 = BPS64_MIN;  // 버퍼 크기 결정용
        static constexpr int NSYM64 = (TOTAL_CODED + BPS64_MIN - 1) / BPS64_MIN;

        /// @brief BPS → 심볼 수 (컴파일 타임 계산)
        static constexpr int nsym_for_bps(int bps) noexcept {
            return (TOTAL_CODED + bps - 1) / bps;
        }
        // BPS=3→230, 4→172, 5→138, 6→115

        /// @brief nsym → BPS 역추론 (RX: 헤더 payload_length에서 자동 판별)
        static constexpr int bps_from_nsym(int nsym) noexcept {
            if (nsym >= nsym_for_bps(3)) return 3;  // 230
            if (nsym >= nsym_for_bps(4)) return 4;  // 172
            if (nsym >= nsym_for_bps(5)) return 5;  // 138
            return 6;                                 // 115
        }

        // ── NF 임계값 — 적응형 BPS 전환 기준 (J-3) ────────────────
        static constexpr uint32_t NF_HEAVY_JAM = 2000u;  // 강력 재밍 → BPS=3
        static constexpr uint32_t NF_MED_JAM = 500u;   // 중간 간섭 → BPS=4
        static constexpr uint32_t NF_LIGHT_JAM = 200u;   // 약한 간섭 → BPS=5
        //                                                   // ≤200 청정 → BPS=6

        /// @brief NF → BPS 결정 (적응형 변조의 핵심 — 4단)
        static constexpr int bps_from_nf(uint32_t nf) noexcept {
            if (nf > NF_HEAVY_JAM) return BPS64_MIN;    // 3: 최대 보호
            if (nf > NF_MED_JAM)   return 4;            // 16-ary
            if (nf > NF_LIGHT_JAM) return 5;            // 32-ary
            return BPS64_MAX;                             // 6: 최고 속도
        }

        static constexpr int C1 = 1;
        static constexpr int NSYM1 = INFO_BITS;

        static constexpr int VIDEO_K = 1;
        static constexpr int VOICE_K = 5;
        static constexpr int DATA_K = 800;

        // ── Viterbi 실측 사용량 기반 WorkBuf 최적화 ───────────────
        //
        //  Viterbi_Decode: steps = CONV_OUT / 2 = 86
        //   → surv[t] 최대 t = 85, tb[t] 최대 t = 85
        //   → surv[88][64] + tb[88] 충분 (88 = 8-byte align)
        //
        //  Bit_Interleave/Deinterleave: 인덱스 < TOTAL_CODED = 688
        //   → perm[688], tmp_soft[688], all_llr[688] 충분
        //
        //  WorkBuf: 30,816B → 14,488B (−16,328B = −53.0%)
        //
        static constexpr int VIT_STEPS =
            ((CONV_OUT / 2) + 7) & ~7;  // 86 → 88 (8-align)

        // ── 워킹 버퍼 (호출자가 할당, DI 주입) ─────────────────────
        // 재진입성 100% 보장. 전역/스택/동적 할당 자유.
        /// @warning sizeof(WorkBuf) ≈ 15KB — ARM에서 전역 또는 정적 배치 권장.
        struct WorkBuf {
            int32_t  pm[2][64];
            uint8_t  surv[VIT_STEPS][64];       // Viterbi 경로 256→88
            uint8_t  tb[VIT_STEPS];             // traceback 256→88
            uint16_t perm[TOTAL_CODED];       // 순열 인덱스 1024→688
            int32_t  tmp_soft[TOTAL_CODED];     // 소프트 메트릭 1024→688
            uint8_t  rep[TOTAL_CODED];
            int32_t  all_llr[TOTAL_CODED];      // LLR 1024→688
            int32_t  combined[CONV_OUT];
        };

        // ── int64_t → int32_t (메모리 50% 절감) ───────────────────
        // 누적 최대: DATA_K(800) × 32767 = 26.2M ≪ INT32_MAX(2.14B)
        // FWHT 64칩 ×64 증폭 후: 1.68B < INT32_MAX (21.9% 여유)
        struct RxState16 {
            int32_t aI[NSYM16][C16];
            int32_t aQ[NSYM16][C16];
            int k;
            bool ok;
        };
        /// @warning sizeof(RxState64) ≈ 115KB (aI/aQ[230][64]×int32_t×2)
        ///          ARM 스택 배치 금지 — 반드시 전역/정적 변수로 배치할 것.
        struct RxState64 {
            int32_t aI[NSYM64][C64];
            int32_t aQ[NSYM64][C64];
            int k;
            bool ok;
        };

        // ── TX ──
        [[nodiscard]] static int Encode16(const uint8_t* info, int len,
            uint8_t* syms, uint32_t il, WorkBuf& wb) noexcept;
        [[nodiscard]] static int Encode64(const uint8_t* info, int len,
            uint8_t* syms, uint32_t il, WorkBuf& wb) noexcept;

        // [적응형] TX — bps 지정 (3~6), 반환값 = 실제 심볼 수
        [[nodiscard]] static int Encode64_A(const uint8_t* info, int len,
            uint8_t* syms, uint32_t il, int bps, WorkBuf& wb) noexcept;

        // V400_Dispatcher는 이미 5인자(WorkBuf&) 오버로드만 사용

        [[nodiscard]] static int Encode1(const uint8_t* info, int len,
            uint8_t* syms) noexcept;

        // ── RX ──
        static void Init16(RxState16& s) noexcept;
        static void Init64(RxState64& s) noexcept;

        // ── 심볼 단위 스트리밍 Feed ───────────────────────────────
        //
        //  [수학적 등가성]
        //   Feed64(state, sI, sQ) = 심볼 전체 일괄 누적
        //     → Σ_{sym=0}^{nsym-1} sI[sym][c] 를 aI[sym][c]에 누적
        //
        //   Feed64_1sym(state, I, Q, sym_idx) = 심볼 1개 즉시 누적
        //     → I[c]를 aI[sym_idx][c]에 즉시 누적
        //
        //   덧셈의 교환·결합 법칙에 의해 결과 100.0% 동일
        //
        //  [HARQ 다중 라운드 안전성]
        //   라운드 K: Feed64_1sym × nsym → Advance_Round
        //   라운드 K+1: Feed64_1sym × nsym → Advance_Round
        //   → aI[sym][c]에 K+1번째 값이 누적 (기존 Feed64과 동일)
        //
        //  [용도] V400_Dispatcher::on_sym_()에서 sI/sQ 중간 버퍼 제거용
        //

        /// @brief 16칩 심볼 1개 즉시 HARQ 누적
        /// @param s        HARQ 누적 상태
        /// @param I        수신 I 칩 배열 (길이 C16=16)
        /// @param Q        수신 Q 칩 배열 (길이 C16=16)
        /// @param sym_idx  현재 심볼 인덱스 (0 ≤ sym_idx < NSYM16)
        static void Feed16_1sym(RxState16& s, const int16_t* I,
            const int16_t* Q, int sym_idx) noexcept;

        /// @brief 64칩 심볼 1개 즉시 HARQ 누적
        /// @param s        HARQ 누적 상태
        /// @param I        수신 I 칩 배열 (길이 C64=64)
        /// @param Q        수신 Q 칩 배열 (길이 C64=64)
        /// @param sym_idx  현재 심볼 인덱스 (0 ≤ sym_idx < NSYM64)
        static void Feed64_1sym(RxState64& s, const int16_t* I,
            const int16_t* Q, int sym_idx) noexcept;

        /// @brief HARQ 라운드 카운터 증가 (1sym 스트리밍 시 라운드 종료 호출)
        static void Advance_Round_16(RxState16& s) noexcept;
        static void Advance_Round_64(RxState64& s) noexcept;

        // 일괄 Feed 인터페이스 (하위 호환 유지 — PC 테스트용)
        static void Feed16(RxState16& s, const int16_t I[][C16],
            const int16_t Q[][C16]) noexcept;
        static void Feed64(RxState64& s, const int16_t I[][C64],
            const int16_t Q[][C64]) noexcept;

        // [적응형] Feed — nsym 지정 (실제 심볼 수만 누적)
        static void Feed64_A(RxState64& s, const int16_t I[][C64],
            const int16_t Q[][C64], int nsym) noexcept;

        [[nodiscard]] static bool Decode16(const RxState16& s,
            uint8_t* out, int* len, uint32_t il, WorkBuf& wb) noexcept;
        [[nodiscard]] static bool Decode64(const RxState64& s,
            uint8_t* out, int* len, uint32_t il, WorkBuf& wb) noexcept;

        // [적응형] Decode — bps 지정
        [[nodiscard]] static bool Decode64_A(const RxState64& s,
            uint8_t* out, int* len, uint32_t il, int bps,
            WorkBuf& wb) noexcept;

        [[nodiscard]] static bool Decode1(const int16_t* rx_I,
            uint8_t* out, int* len) noexcept;

        // ── I/Q 분리 배치용 Decode 래퍼 ───────────────────────────
        //  harq_I(SRAM)와 harq_Q(CCM)가 물리적으로 분리되어
        //  RxState64 구조체를 직접 전달할 수 없을 때 사용.
        //  내부적으로 Decode_Core(accI, accQ, ...)에 단순 위임.
        [[nodiscard]] static bool Decode_Core_Split(
            const int32_t* accI, const int32_t* accQ,
            int nsym, int nc, int bps,
            uint8_t* out, int* len, uint32_t il, WorkBuf& wb) noexcept;

        static uint16_t CRC16(const uint8_t* d, int len) noexcept;

        static void Gen_Perm(uint32_t seed, uint8_t* perm, int n) noexcept;
        static void Interleave(int16_t* I, int16_t* Q,
            const uint8_t* p, int n) noexcept;
        static void Deinterleave(int16_t* I, int16_t* Q,
            const uint8_t* p, int n) noexcept;

    private:
        static void FWHT(int32_t* d, int n) noexcept;
        static void Conv_Encode(const uint8_t* in, int n, uint8_t* out) noexcept;
        static void Viterbi_Decode(const int32_t* soft, int nc,
            uint8_t* out, int no, WorkBuf& wb) noexcept;
        /// @param n 비트 길이 — FEC 경로에서는 `TOTAL_CODED`(688) 고정. `WorkBuf::perm`/`tmp_soft` 상한.
        static void Bit_Interleave(uint8_t* bits, int n, uint32_t seed) noexcept;
        static void Bit_Deinterleave(int32_t* soft, int n, uint32_t seed,
            WorkBuf& wb) noexcept;
        static void Bin_To_LLR(const int32_t* fI, const int32_t* fQ,
            int nc, int bps, int32_t* llr) noexcept;
        static int Encode_Core(const uint8_t* info, int len, uint8_t* syms,
            uint32_t il, int bps, int nsym, WorkBuf& wb) noexcept;
        static bool Decode_Core(const int32_t* accI, const int32_t* accQ,
            int nsym, int nc, int bps, uint8_t* out, int* len, uint32_t il,
            WorkBuf& wb) noexcept;

        FEC_HARQ() = delete;
    };

    //  VIT_STEPS = 88 ≥ CONV_OUT/2 = 86 (Viterbi 최대 단계)
    //  TOTAL_CODED = 688 (perm/tmp_soft/all_llr 최대 인덱스 + 1)
    static_assert(FEC_HARQ::VIT_STEPS >= FEC_HARQ::CONV_OUT / 2,
        "VIT_STEPS too small for Viterbi traceback");
    static_assert(FEC_HARQ::TOTAL_CODED <= 1024,
        "TOTAL_CODED exceeds original buffer limit");
    static_assert(sizeof(FEC_HARQ::WorkBuf) <= 15360u,
        "WorkBuf exceeds 15KB — perm[] storage shrink required");
    static_assert(sizeof(FEC_HARQ::RxState64) <= 128u * 1024u,
        "RxState64 exceeds 128KB — NSYM64 또는 C64 재검토 필요");

} // namespace ProtectedEngine
