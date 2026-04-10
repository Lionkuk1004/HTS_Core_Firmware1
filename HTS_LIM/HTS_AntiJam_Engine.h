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
///  [Adaptive Bypass — 광대역 바라지]
///   64칩 블록의 피크·에너지 분포를 스캔: 피크 대 평균·중앙값 비가 낮으면
///   BARRAGE형(백색소음 플로어)으로 보고 AJC/펀치/널을 가동하지 않고 원본 유지.
///   CW/EMP 등 뾰족한 간섭만 기존 3층 필터 가동.
///
///  CW 17~19dB 구간: Seed_CW_Profile()로 jprof_[] 시딩, mismatch_ema_ 재초기화.
///
///  [제약] float 0, double 0, 나눗셈 0, try-catch 0, 힙 0
// =========================================================================
#pragma once
// ─────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────
//  [사용법] 기본 사용 예시를 여기에 기재하세요.
//  [메모리] sizeof(클래스명) 확인 후 전역/정적 배치 필수.
//  [보안]   복사/이동 연산자 = delete (키 소재 복제 차단).
//
//  ⚠ [파트너사 필수 확인]
//    HW 레지스터 주소(UART/WDT 등)는 보드 설계에 맞게 교체.
//    IRQ 번호는 STM32F407 RM0090 벡터 테이블 기준으로 교체.
// ─────────────────────────────────────────────────────────

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    class AntiJamEngine {
    public:
        static constexpr int MAX_NC = 64;
        static constexpr int SUB_NC = 16;
        static constexpr int MAX_SUBS = MAX_NC / SUB_NC;
        /// 링 슬롯 — 2의 거듭제곱 (슬롯 = count & (MAX_ACC-1), %/UDIV 없음)
        static constexpr int MAX_ACC = 16;
        static constexpr int MIN_ACC = 6;
        static constexpr int PWR_ITER = 3;

        AntiJamEngine() noexcept;
        void Reset(int nc) noexcept;
        void Process(int16_t* I, int16_t* Q, int nc) noexcept;

        /// @brief 광대역 바라지(BARRAGE)로 확정된 경우 3층 필터를 끄고 원본 유지
        /// @note ajc_reliable_==false 일 때만 적용. CW 시딩·Update_AJC로 신뢰 확보 시 무시.
        void Set_AdaptiveBarrageBypass(bool on) noexcept;

        void Update_AJC(const int16_t* orig_I, const int16_t* orig_Q,
            int8_t sym, uint32_t best_e, uint32_t second_e,
            int nc, bool is_preamble = false) noexcept;

        // ── CW 프로파일 직접 시딩 ───────────────────────────────────
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
        /// @note  구현부에서 64비트 중간 연산 + int32 포화(clamp)로
        ///        곱셈/EMA 좌시프트 저장 단계의 오버플로우를 차단합니다.
        void Seed_CW_Profile(int32_t ja_I, int32_t ja_Q) noexcept;

    private:
        static constexpr int      EMA_SHIFT = 4;      ///< α = 1/16
        static constexpr int      EMA_FAST = 2;      ///< α = 1/4
        static constexpr uint32_t FAST_PHASE = 4u;
        static constexpr uint32_t STATIONARITY_TH = 3000u;

        int32_t  jprof_I_[MAX_NC];
        int32_t  jprof_Q_[MAX_NC];
        uint32_t mismatch_ema_;
        uint32_t update_count_;
        bool     ajc_reliable_;
        bool     barrage_bypass_;

        struct SubNull {
            int8_t  signs_I[MAX_ACC][SUB_NC];
            int8_t  signs_Q[MAX_ACC][SUB_NC];
            int32_t eigvec[SUB_NC];
            int     count;
            bool    active;
        };
        SubNull subs_[MAX_SUBS];
        int     num_subs_;

        /// Spatial null 공분산·파워법 벡터 — 스택 1KB+ 대신 객체 내 고정 버퍼
        int32_t null_cov_[SUB_NC][SUB_NC];
        int32_t null_v_[SUB_NC];
        int32_t null_nv_[SUB_NC];

        /// Adaptive punch / impulsive 스캔 — 대형 스택 배열 제거 (MAX_NC·64 정렬 워크)
        uint32_t sort_nc_scratch_[MAX_NC];
        uint32_t sort_u64_work_[64];

        void ajc_apply_(int16_t* I, int16_t* Q, int nc) noexcept;
        void adaptive_punch_(int16_t* I, int16_t* Q, int nc) noexcept;
        void null_accumulate_sub_(SubNull& s,
            const int16_t* I, const int16_t* Q) noexcept;
        void null_apply_sub_(const SubNull& s,
            int16_t* I, int16_t* Q) noexcept;

        /// Bypass 시 jprof/AJC 유지, Spatial-Null 누적만 초기화 (광대역 구간 오염 방지)
        void reset_spatial_null_only_() noexcept;

        /// ajc_reliable_==false 일 때만: 고크레스트·저중앙값·소수 핫칩 → true(3층), 그 외 Bypass
        bool block_looks_impulsive_nc_(
            const int16_t* I, const int16_t* Q, int nc) noexcept;

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
    };

} // namespace ProtectedEngine