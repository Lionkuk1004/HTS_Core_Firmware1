// =========================================================================
/// @file  HTS_AntiJam_Engine.h
/// @brief 3층 통합 항재밍 엔진 (AJC + Adaptive Punch + Spatial Null)
/// @target STM32F407 (Cortex-M4F, 168MHz, SRAM 192KB)
///
///  1층) AJC: 판정 귀환 간섭 제거 (비파괴, 정상성 게이팅)
///  2층) Adaptive Punch: 환경 적응 돌출 칩 제거 (Clip 없음)
///  3층) Spatial Null: 16칩 서브밴드 투영 제거
///
///  [정상성 게이팅]
///   비정상 재머(Pulse 등) 감지 시 AJC 자동 비활성화
///   → Hole Punch만 작동 → RAW 이상 보장
///
///  [세션 10 수정 이력]
///   BUG-44 [CRIT] CW 17~19dB 닭-달걀 문제 해소
///          Seed_CW_Profile() 신규 추가:
///          cw_cancel_64_()가 추정한 CW 진폭(ja_I, ja_Q)을
///          jprof_[]에 직접 주입하여 판정 귀환 없이 AJC가
///          첫 심볼부터 CW를 제거할 수 있도록 함.
///          mismatch_ema_ 재초기화로 STATIONARITY 게이팅 해소.
///
///  [제약] float 0, double 0, 나눗셈 0, try-catch 0, 힙 0
// =========================================================================
#pragma once
#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    class AntiJamEngine {
    public:
        static constexpr int MAX_NC = 64;
        static constexpr int SUB_NC = 16;
        static constexpr int MAX_SUBS = MAX_NC / SUB_NC;
        static constexpr int MAX_ACC = 12;
        static constexpr int MIN_ACC = 6;
        static constexpr int PWR_ITER = 3;

        AntiJamEngine() noexcept;
        void Reset(int nc) noexcept;
        void Process(int16_t* I, int16_t* Q, int nc) noexcept;

        void Update_AJC(const int16_t* orig_I, const int16_t* orig_Q,
            int8_t sym, uint32_t best_e, uint32_t second_e,
            int nc, bool is_preamble = false) noexcept;

        // ── [BUG-44] CW 프로파일 직접 시딩 ──────────────────────────────
        /// @brief cw_cancel_64_()의 상관 추정값을 jprof_[]에 직접 주입
        ///
        /// [목적]
        ///   CW 17~19dB 구간에서 발생하는 닭-달걀 문제를 해소합니다.
        ///   기존 방식은 Update_AJC()가 올바른 sym 판정을 받아야만
        ///   jprof_[]를 갱신할 수 있었습니다. CW가 강해서 디코딩이
        ///   실패하면 sym=-1이 되어 갱신이 영구히 차단됩니다.
        ///
        /// [해결 원리]
        ///   cw_cancel_64_()는 이미 CW 진폭 ja_I, ja_Q를 계산합니다.
        ///   이 값과 Q8 LUT를 곱하면 64칩 전체 CW 파형을 정확히
        ///   재구성할 수 있고, 이것을 jprof_[]에 바로 기록합니다.
        ///   AJC는 심볼 판정 결과를 기다리지 않고도 첫 심볼부터
        ///   CW 패턴을 알게 됩니다.
        ///
        /// [스케일 일치 증명]
        ///   jprof_[i] 저장 스케일 = pure_J << EMA_SHIFT(4) = 값×16
        ///   CW 파형 = (ja × lut[i%8]) >> 8
        ///   주입값  = cw[i] << EMA_SHIFT → ajc_apply_()가
        ///             jprof_[i] >> EMA_SHIFT = cw[i]를 꺼냄 → 수치 오차 0
        ///
        /// @param ja_I  I 채널 CW 진폭 추정값 (corr_I >> 13)
        /// @param ja_Q  Q 채널 CW 진폭 추정값 (corr_Q >> 13)
        /// @note  nc=64 고정 (cw_cancel_64_()는 항상 64칩 처리)
        void Seed_CW_Profile(int32_t ja_I, int32_t ja_Q) noexcept;

    private:
        static constexpr int      EMA_SHIFT = 4;      ///< α = 1/16
        static constexpr int      EMA_FAST = 2;      ///< α = 1/4
        static constexpr uint32_t FAST_PHASE = 4u;
        static constexpr uint32_t STATIONARITY_TH = 3000u;

        int32_t  jprof_I_[MAX_NC];
        int32_t  jprof_Q_[MAX_NC];
        uint32_t mismatch_ema_;
        bool     ajc_reliable_;
        uint32_t update_count_;

        struct SubNull {
            int8_t  signs_I[MAX_ACC][SUB_NC];
            int8_t  signs_Q[MAX_ACC][SUB_NC];
            int32_t eigvec[SUB_NC];
            int     count;
            bool    active;
        };
        SubNull subs_[MAX_SUBS];
        int     num_subs_;

        void ajc_apply_(int16_t* I, int16_t* Q, int nc) noexcept;
        void adaptive_punch_(int16_t* I, int16_t* Q, int nc) noexcept;
        void null_accumulate_sub_(SubNull& s,
            const int16_t* I, const int16_t* Q) noexcept;
        void null_apply_sub_(const SubNull& s,
            int16_t* I, int16_t* Q) noexcept;

        static constexpr uint32_t popc32_(uint32_t x) noexcept {
            x -= (x >> 1u) & 0x55555555u;
            x = (x & 0x33333333u) + ((x >> 2u) & 0x33333333u);
            return (((x + (x >> 4u)) & 0x0F0F0F0Fu) * 0x01010101u) >> 24u;
        }
        static constexpr uint32_t fast_abs_(int32_t x) noexcept {
            const int32_t m = x >> 31;
            return static_cast<uint32_t>((x ^ m) - m);
        }
        static int      clz32_(uint32_t x) noexcept;
        static uint32_t nth_select_(uint32_t* a, int n, int k) noexcept;
    };

} // namespace ProtectedEngine