// =============================================================================
/// @file  HTS_V400_Dispatcher.hpp
/// @brief V400 동적 모뎀 디스패처 + 3층 항재밍 엔진 통합
/// @target ARM Cortex-M4 (STM32F407, 168MHz, SRAM 192KB)
///
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [설계 목적]
//  4종 페이로드(VIDEO_1, VIDEO_16, VOICE, DATA)를 자동 판별하여
//  64칩/16칩/1칩 Walsh 변복조 + FEC-HARQ + 3층 항재밍을 수행합니다.
//
//  [TX 사용법]
//   HTS_V400_Dispatcher disp;
//   disp.Set_Seed(seed);
//   int chips = disp.Build_Packet(
//       PayloadMode::DATA, info, 8, 300, outI, outQ, 16000);
//
//  [RX 사용법]
//   disp.Set_Packet_Callback(on_packet);
//   for (each chip) disp.Feed_Chip(rx_I, rx_Q);
//   → 콜백으로 DecodedPacket 수신
//
//  [상태 머신 (RxPhase)]
//   ┌─────────────┐  프리앰블 매칭   ┌──────────────┐
//   │  WAIT_SYNC  │ ──────────────→ │ READ_HEADER  │
//   └─────────────┘                  └──────────────┘
//         ↑  실패/완료                     │ 헤더 파싱 성공
//         └──────────────────────┐         ↓
//                                │  ┌──────────────┐
//                                └──│ READ_PAYLOAD │
//                                   └──────────────┘
//
//  [CFI 검증 (항목⑬)]
//   모든 phase_ 전이는 set_phase_()를 경유하며,
//   비트마스크 기반 합법 전이 테이블로 검증합니다.
//   불법 전이(예: WAIT_SYNC → READ_PAYLOAD) 감지 시
//   즉시 full_reset_()으로 안전 상태 복귀합니다.
//   → ROP/글리치로 헤더 인증을 우회하는 공격 차단
//
//  [DATA 64칩 수신 파이프라인]
//   ① cw_cancel_64_()  8칩 주기 CW 사전 소거
//   ② ajc_.Process()   AJC 브로드밴드 간섭 제거
//   ③ soft_clip_iq()   아웃라이어 소프트 클립
//   ④ HARQ 즉시 누적 + walsh_dec_full_ → ajc_.Update_AJC
//
//  [SRAM 최적화 이력 — BUG-51~54]
//   BUG-51: sI/sQ 중간 버퍼 제거 (HARQ 스트리밍 직접 누적) −58KB
//   BUG-52: wb_tx_+wb_rx_ → wb_ 유니온 (반이중 TDM)     −45KB
//   BUG-53: orig_acc_ int16→int8 양자화 (AJC LMS 안전)   −29KB
//   BUG-54: harq I/Q 분리 (aQ → CCM 배치)                 배치 변경
//
//  [최종 메모리 배치]
//   SRAM1+2 (128KB): harq_I_(58KB) + wb_(15KB) + orig_acc_(29KB) + etc
//   CCM     (64KB):  harq_Q_(58KB) + MSP 스택(4KB)
//   총 사용 ~178KB / 192KB (14.3KB = 7.4% 마진)
//
//  [제약]    fp32 0, fp64 0, try-catch 0, 힙 0
//
//  [양산 수정 이력 — 54건]
//   BUG-51 [CRIT] sI/sQ 제거 → Feed16_1sym/Feed64_1sym 스트리밍 전환
//   BUG-52 [CRIT] wb_ 유니온화 (반이중 증명: TX/RX 동시 접근 불가)
//   BUG-53 [HIGH] orig_acc_ int8_t 양자화 (AJC LMS σq << σth 검증)
//   BUG-54 [HIGH] harq I/Q → RxAccum_I(SRAM) + RxAccum_Q(CCM) 분리
//   BUG-41 [CRIT] SecureMemory::secureWipe — D-2/X-5-1 구현은 HTS_Secure_Memory.cpp
//          (호스트·타깃 동일 3중 방어; 본 모듈은 호출부만)
//   BUG-55 [검수 KB] static_assert 실측: sizeof(HTS_V400_Dispatcher) < 128*1024;
//          NSYM16/NSYM64 ≤ 256 (orig_acc_); harq_Q_는 CCM 외부 배열
//
/// @warning sizeof(HTS_V400_Dispatcher) ≈ 120KB (SRAM 부분만)
///          harq_Q_는 CCM에 별도 배치. 반드시 전역/정적 변수로 배치할 것.
///          스택 선언 시 Cortex-M4 즉시 오버플로우.
//
// ─────────────────────────────────────────────────────────────────────────
// =============================================================================
#pragma once
#include <cstdint>
#include <cstddef>
#include "HTS_FEC_HARQ.hpp"
#include "HTS_AntiJam_Engine.h"

namespace ProtectedEngine {

    /// @brief HTS_RF_Metrics 전방 선언 (적응형 BPS 인수용)
    struct HTS_RF_Metrics;

    /// @brief 페이로드 모드 (4종 + 미식별)
    enum class PayloadMode : uint8_t {
        VIDEO_1 = 0x00u,   ///< 1칩 BPSK 영상 (K=1, 속도 최우선)
        VIDEO_16 = 0x01u,   ///< 16칩 Walsh 영상 (K=1, FEC 없음)
        VOICE = 0x02u,   ///< 16칩 Walsh 음성 (MAX_K=5, ≤8ms)
        DATA = 0x03u,   ///< 64칩 Walsh 데이터 (MAX_K=800, 무결성)
        UNKNOWN = 0xFFu    ///< 미식별 (헤더 파싱 실패)
    };

    /// @brief I/Q 채널 모드 — 적응형 전환
    /// @note  NF 기반 자동 전환: 평시 I/Q 독립(2배 처리량) ↔ 재밍 시 I=Q 동일(+3dB)
    enum class IQ_Mode : uint8_t {
        IQ_SAME = 0u,        ///< I=Q 동일 심볼 (재밍 방어, +3dB 다이버시티)
        IQ_INDEPENDENT = 1u  ///< I/Q 독립 심볼 (평시, 2배 처리량)
    };

    /// @brief RX 수신 상태 머신 단계
    /// @note  [항목⑬] 모든 전이는 set_phase_()로 CFI 검증
    enum class RxPhase : uint8_t {
        WAIT_SYNC = 0u,  ///< 프리앰블 탐색 대기
        READ_HEADER = 1u,  ///< 헤더 심볼 수신 중
        READ_PAYLOAD = 2u   ///< 페이로드 심볼 수신 중
    };

    /// @brief 디코딩 완료 패킷 구조체
    struct DecodedPacket {
        PayloadMode mode;       ///< 페이로드 모드
        uint8_t data[8];        ///< 디코딩된 데이터 (최대 8바이트)
        int data_len;           ///< 유효 데이터 길이
        int harq_k;             ///< HARQ 라운드 수 (1 = 단일 전송 성공)
        bool success;           ///< CRC 검증 통과 여부
    };

    // ── [BUG-54] CCM 섹션 매크로 ──
    //  STM32F407 CCM (0x10000000, 64KB): DMA 불가, CPU만 접근
    //  HARQ 누적은 CPU 연산 전용 → CCM 배치 안전
    //
    //   .ccm_data: 초기값 포함 → .bin에 108KB 데이터 임베드 (펌웨어 폭발)
    //   .ccm_bss:  초기값 없음 → .bin 크기 0 (부팅 시 startup이 제로필)
    //
    //  ★ 링커 스크립트(.ld) 필수 추가:
    //   CCM (rwx) : ORIGIN = 0x10000000, LENGTH = 64K
    //   .ccm_bss (NOLOAD) : {
    //       _sccm_bss = .;
    //       *(.ccm_bss)
    //       _eccm_bss = .;
    //   } > CCM
    //
    //  ★ startup_stm32.s 필수 추가 (Reset_Handler 내):
    //   @ CCM BSS Zero-Fill
    //   ldr r0, =_sccm_bss
    //   ldr r1, =_eccm_bss
    //   movs r2, #0
    //   ccm_bss_loop:
    //     cmp r0, r1
    //     bge ccm_bss_done
    //     str r2, [r0], #4
    //     b ccm_bss_loop
    //   ccm_bss_done:
    //
    //  ★ 런타임 안전망: full_reset_()에서 memset(g_harq_Q_ccm, 0, sizeof)
    //     이미 적용됨 → startup 누락 시에도 첫 패킷 수신 전 제로화 보장
#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
#define HTS_CCM_SECTION  __attribute__((section(".ccm_bss")))
#else
#define HTS_CCM_SECTION  /* PC: 섹션 속성 무시 */
#endif

    /// @brief V400 동적 모뎀 디스패처 + 3층 항재밍 엔진
    class HTS_V400_Dispatcher {
    public:
        /// @brief 패킷 수신 완료 콜백 타입
        using PacketCB = void(*)(const DecodedPacket&);
        /// @brief 모드 전환 알림 콜백 타입
        using ControlCB = void(*)(PayloadMode);

        /// @brief 디스패처 생성 (WAIT_SYNC 초기 상태)
        HTS_V400_Dispatcher() noexcept;
        /// @brief 소멸자 — CCM·버퍼·시드 개별 secureWipe (this 통째 wipe 없음: ajc_ UB 방지)
        ~HTS_V400_Dispatcher() noexcept;

        /// 상태 복제/이동 방지 (HARQ 누적 버퍼 + AJC 학습 상태)
        HTS_V400_Dispatcher(const HTS_V400_Dispatcher&) = delete;
        HTS_V400_Dispatcher& operator=(const HTS_V400_Dispatcher&) = delete;

        /// @brief PRNG 시드 설정 (TX/RX 동기화)
        /// @param seed  32비트 시드 (0 → 내부 폴백)
        void Set_Seed(uint32_t seed) noexcept;

        /// @brief 패킷 수신 콜백 등록
        /// @param cb  콜백 함수 포인터 (nullptr 허용 = 콜백 해제)
        void Set_Packet_Callback(PacketCB cb) noexcept;

        /// @brief 모드 전환 콜백 등록
        /// @param cb  콜백 함수 포인터 (nullptr 허용)
        void Set_Control_Callback(ControlCB cb) noexcept;

        /// @brief TX 패킷 빌드 (프리앰블 + 헤더 + FEC 인코딩 + Walsh 변조)
        int Build_Packet(PayloadMode mode, const uint8_t* info, int info_len,
            int16_t amp, int16_t* out_I, int16_t* out_Q, int max_chips) noexcept;

        /// @brief RX 칩 1개 주입 (ISR 또는 메인 루프에서 연속 호출)
        void Feed_Chip(int16_t rx_I, int16_t rx_Q) noexcept;

        /// @brief 상태 머신 + AJC + HARQ 전체 초기화
        void Reset() noexcept;

        /// @brief 현재 I/Q 모드 조회
        [[nodiscard]] IQ_Mode Get_IQ_Mode() const noexcept;

        /// @brief AJC 노이즈 플로어 기반 적응형 BPS 갱신
        void Update_Adaptive_BPS(uint32_t nf) noexcept;

        /// @brief RF 측정값 컨테이너 주입 (선택적)
        void Set_RF_Metrics(HTS_RF_Metrics* p) noexcept;

        /// @brief 매 프레임 적응형 BPS 갱신
        void Tick_Adaptive_BPS() noexcept;

        // ── CW 소거기 ON/OFF (벤치마크 비교용, 양산 기본값 true) ──
        void Set_CW_Cancel(bool enable) noexcept { cw_cancel_enabled_ = enable; }
        [[nodiscard]] bool Get_CW_Cancel() const noexcept { return cw_cancel_enabled_; }

        // ── AJC ON/OFF (벤치마크 전용, 양산 기본값 true) ──
        void Set_AJC_Enabled(bool enable) noexcept { ajc_enabled_ = enable; }
        [[nodiscard]] bool Get_AJC_Enabled() const noexcept { return ajc_enabled_; }

        /// @brief 현재 적응형 BPS 반환 (3~6)
        [[nodiscard]] int         Get_Current_BPS64()   const noexcept;
        /// @brief 현재 RX 상태 머신 단계 반환
        [[nodiscard]] RxPhase     Get_Phase()            const noexcept;
        /// @brief 현재 페이로드 모드 반환
        [[nodiscard]] PayloadMode Get_Mode()             const noexcept;
        /// @brief VIDEO 모드 연속 실패 횟수 반환
        [[nodiscard]] int         Get_Video_Fail_Count() const noexcept;

        /// @brief VIDEO 모드 폴백 임계값
        static constexpr int     VIDEO_FAIL_TH = 2;
        /// @brief VIDEO 모드 복귀 임계값
        static constexpr int     VIDEO_RECOVER_TH = 5;
        /// @brief 프리앰블 심볼 0 (0x3F = Walsh row 63)
        static constexpr uint8_t PRE_SYM0 = 0x3Fu;
        /// @brief 프리앰블 심볼 1 (0x00 = Walsh row 0)
        static constexpr uint8_t PRE_SYM1 = 0x00u;
        /// @brief 헤더 심볼 수
        static constexpr int     HDR_SYMS = 2;

    private:
        RxPhase     phase_;             ///< 현재 RX 상태 (CFI 보호)
        PayloadMode cur_mode_;          ///< 현재 페이로드 모드
        PayloadMode active_video_;      ///< 활성 VIDEO 모드 (1칩/16칩)
        uint32_t    seed_;              ///< PRNG 마스터 시드
        uint32_t    tx_seq_;            ///< TX 시퀀스 번호
        uint32_t    rx_seq_;            ///< RX 시퀀스 번호
        PacketCB    on_pkt_;            ///< 패킷 수신 콜백
        ControlCB   on_ctrl_;           ///< 모드 전환 콜백

        int16_t buf_I_[64] = {};        ///< 칩 수집 버퍼 I
        int16_t buf_Q_[64] = {};        ///< 칩 수집 버퍼 Q
        int     buf_idx_;               ///< 버퍼 현재 인덱스

        int     pre_phase_;             ///< 프리앰블 매칭 단계 (0 또는 1)
        uint8_t hdr_syms_[2] = {};      ///< 수신된 헤더 심볼
        int     hdr_count_;             ///< 수신된 헤더 심볼 수
        int     hdr_fail_;              ///< 헤더 디코딩 연속 실패 수
        static constexpr int HDR_FAIL_MAX = 3;  ///< 헤더 실패 허용 횟수

        int pay_cps_;                   ///< 현재 페이로드 칩 수 (1/16/64)
        int pay_total_;                 ///< 페이로드 총 심볼 수
        int pay_recv_;                  ///< 수신된 페이로드 심볼 수
        int harq_round_;                ///< 현재 HARQ 라운드
        int max_harq_;                  ///< 최대 HARQ 라운드 (모드별)
        int vid_fail_;                  ///< VIDEO 연속 실패 카운터
        int vid_succ_;                  ///< VIDEO 연속 성공 카운터

        int16_t v1_rx_[80] = {};        ///< 1칩 BPSK 수신 버퍼
        int     v1_idx_;                ///< 1칩 버퍼 인덱스

        // ── [BUG-51] HARQ 누적 상태 (sI/sQ 중간 버퍼 제거) ──
        //
        //  기존: rx_ union { m16{harq,sI,sQ}, m64{harq,sI,sQ} }
        //   → sI/sQ는 on_sym_()에서 저장 후 try_decode_()에서 Feed로 일괄 누적
        //   → sI/sQ 57.5KB 낭비 (Feed = 단순 덧셈, 스트리밍과 결과 동일)
        //
        //  수정: rx_ union { m16{harq}, m64_I{harq_I_} }
        //   → on_sym_()에서 Feed16_1sym/Feed64_1sym으로 즉시 누적
        //   → sI/sQ 배열 완전 제거 (−58,880B)
        //
        union {
            FEC_HARQ::RxState16 m16;
            struct {
                int32_t aI[FEC_HARQ::NSYM64][FEC_HARQ::C64];
                int k;
                bool ok;
            } m64_I;
        } rx_;

        // ── [BUG-54] HARQ Q채널 — CCM 배치 (DMA 불가, CPU 연산 전용) ──
        //
        //  harq.aQ[230][64] = 58,880B → CCM(64KB)에 별도 배치
        //  실제 배열은 .cpp에 file-scope static으로 정의 (sizeof 제외)
        //  포인터만 클래스 멤버로 보유
        //
        //  linker script 예시:
        //    .ccm_bss (NOLOAD) : { _sccm_bss = .; *(.ccm_bss) _eccm_bss = .; } > CCM
        //
        int32_t(*harq_Q_)[FEC_HARQ::C64];  ///< CCM 배치 Q채널 포인터

        int  sym_idx_;                  ///< 현재 심볼 인덱스
        bool harq_inited_;              ///< HARQ 상태 초기화 완료 여부

        // ── [BUG-52] WorkBuf 유니온화 (반이중 TDM) ──
        //
        //  [반이중 증명]
        //   B-CDMA = 반이중(Half-Duplex): TX/RX 동시 실행 불가
        //   Feed_Chip(RX)과 Build_Packet(TX)은 모두 메인 루프 컨텍스트
        //   단일 Cortex-M4 코어에서 선점(preempt) 없이 순차 실행
        //   → wb_ 동시 접근 불가능
        //
        //  [try_decode_ 내부 순차 사용]
        //   Decode64_A(... wb_)  → Viterbi 사용 (wb_.pm/surv/tb)
        //   harq_feedback_seed_(... wb_) → Encode 사용 (wb_.perm/rep)
        //   → 시간적 분리 확인: Decode 완료 후 Encode 시작
        //
        //  절감: 2 × 30,816B → 1 × 15,864B = −45,768B
        //
        FEC_HARQ::WorkBuf wb_{};

        AntiJamEngine ajc_;             ///< 3층 항재밍 엔진
        int ajc_last_nc_{ 0 };          ///< 마지막 AJC 칩 수 (리셋 판단)

        int cur_bps64_{ FEC_HARQ::BPS64_MAX };  ///< 현재 64칩 BPS (3~6)
        /// @brief 현재 BPS에 대응하는 심볼 수 반환
        int cur_nsym64_() const noexcept {
            return FEC_HARQ::nsym_for_bps(cur_bps64_);
        }

        // ── 적응형 I/Q 모드 ──────────────────────────────────────
        //  평시: IQ_INDEPENDENT → BPS×2 처리량 (NF < NF_IQ_SPLIT_TH)
        //  재밍: IQ_SAME → +3dB 다이버시티 (NF ≥ NF_IQ_SAME_TH)
        //  히스테리시스: SPLIT_TH < SAME_TH (떨림 방지)
        IQ_Mode iq_mode_{ IQ_Mode::IQ_SAME };  ///< 현재 I/Q 모드 (기본: 안전)
        static constexpr uint32_t NF_IQ_SPLIT_TH = 10u;   ///< dB 이하 → I/Q 독립
        static constexpr uint32_t NF_IQ_SAME_TH = 20u;   ///< dB 이상 → I=Q 동일
        static constexpr int IQ_BPS_PEACETIME = 5;         ///< 평시 최적 BPS

        // ── 히스테리시스 안정화 ──────────────────────────────────
        //  올리기: 연속 UPGRADE_GUARD 패킷 이상 NF<SPLIT_TH 유지
        //  내리기: NF>SAME_TH 즉시 (안전 우선, 지연 0)
        uint32_t iq_upgrade_count_{ 0u };  ///< 올리기 조건 연속 충족 카운터
        static constexpr uint32_t IQ_UPGRADE_GUARD = 8u;   ///< 올리기 지연 (8패킷)

        // ── 헤더 IQ 비트 ──────────────────────────────────────
        //  [mode 2bit][IQ 1bit][payload_len 9bit] = 12bit
        //  프리앰블+헤더: 항상 I=Q 고정 (블라인드 딜레마 해결)
        static constexpr uint16_t HDR_IQ_BIT = (1u << 9u);  ///< bit9 = IQ 모드

        // ── [BUG-53] 원본 심볼 누적 (AJC 결정지향 피드백용) ──
        //
        //  [8비트 양자화 안전성 증명]
        //   STM32F407 ADC = 12비트 유효. 하위 4~5비트 = 열잡음(σth ≈ ±16)
        //   int16_t→int8_t: 상위 8비트 보존 (>> 8 시프트)
        //   양자화 잡음 σq ≈ 0.5 LSB << σth → LMS 가중치 갱신 무영향
        //   AJC Update_AJC 내부: Δw = μ·error·x_ref
        //   x_ref 양자화 → Δw 오차 < 3% → 수렴점 동일
        //
        //   1바이트 = [I 상위 4비트][Q 상위 4비트]
        //   절감: int8_t×230×64×2 = 29,440B → uint8_t×230×64 = 14,720B (−50%)
        //   AJC LMS: σq(4bit) = 2048 << σth(4000~16000), 수렴 영향 무시
        //
        union {
            struct {
                uint8_t iq4[FEC_HARQ::NSYM16][16];  // I[3:0]|Q[3:0] packed
            } acc16;
            struct {
                uint8_t iq4[FEC_HARQ::NSYM64][64];  // I[3:0]|Q[3:0] packed
            } acc64;
        } orig_acc_;

        int16_t orig_I_[64] = {};       ///< 원본 I (AJC 전, 현재 심볼)
        int16_t orig_Q_[64] = {};       ///< 원본 Q (AJC 전, 현재 심볼)

        bool cw_cancel_enabled_{ true };  ///< CW 소거기 활성화 (양산 기본 true)
        bool ajc_enabled_{ true };        ///< AJC 활성화 (양산 기본 true)

        /// @brief RF 측정값 (비소유 포인터, nullptr 허용)
        HTS_RF_Metrics* p_metrics_{ nullptr };

        // ── [BUG-44] CFI 상태 전이 검증 (항목⑬) ──────────────────
        //
        //  합법 전이 테이블 (비트마스크 인코딩):
        //   key = (from << 2) | to  →  4비트 인덱스
        //
        //   key=0: WAIT_SYNC(0)    → WAIT_SYNC(0)    ✓ (reset)
        //   key=1: WAIT_SYNC(0)    → READ_HEADER(1)   ✓ (프리앰블 매칭)
        //   key=4: READ_HEADER(1)  → WAIT_SYNC(0)    ✓ (헤더 실패)
        //   key=6: READ_HEADER(1)  → READ_PAYLOAD(2)  ✓ (헤더 성공)
        //   key=8: READ_PAYLOAD(2) → WAIT_SYNC(0)    ✓ (디코딩 완료)
        //
        //   나머지 전이 = 불법 (ROP/글리치/헤더 인증 우회)
        //   → full_reset_()으로 안전 상태 강제 복귀
        //
        //  Constant-time: 분기 0개, 시프트+AND 1회 (~2cyc ARM)

        bool set_phase_(RxPhase target) noexcept;

        /// @brief 내부 도우미 함수
        bool parse_hdr_(PayloadMode& mode, int& plen) noexcept;
        void on_sym_() noexcept;
        void try_decode_() noexcept;
        void handle_video_(bool ok) noexcept;
        void full_reset_() noexcept;
        void harq_feedback_seed_(const uint8_t* data, int data_len,
            int nc, uint32_t il) noexcept;

        int32_t dec_wI_[64] = {};       ///< Walsh 디코딩 워킹 버퍼 I
        int32_t dec_wQ_[64] = {};       ///< Walsh 디코딩 워킹 버퍼 Q

        //  mags[64] + sorted[64] = 512B (soft_clip_iq, blackhole_ 공유)
        //  시간적 분리: soft_clip_iq 완료 후 blackhole_ 호출
        uint32_t scratch_mag_[64] = {};
        uint32_t scratch_sort_[64] = {};

        /// @brief Walsh 디코딩 결과 (심볼 + 에너지)
        struct SymDecResult {
            int8_t   sym;       ///< 디코딩된 심볼 (-1 = 실패)
            uint32_t best_e;    ///< 최대 에너지 빈
            uint32_t second_e;  ///< 차순위 에너지 빈
        };

        /// @brief I/Q 독립 디코딩 결과 (I, Q 채널 각각)
        struct SymDecResultSplit {
            int8_t   sym_I;      ///< I 채널 심볼 (-1 = 실패)
            int8_t   sym_Q;      ///< Q 채널 심볼 (-1 = 실패)
            uint32_t best_eI;    ///< I 채널 최대 에너지
            uint32_t second_eI;  ///< I 채널 차순위 에너지
            uint32_t best_eQ;    ///< Q 채널 최대 에너지
            uint32_t second_eQ;  ///< Q 채널 차순위 에너지
        };

        SymDecResult walsh_dec_full_(
            const int16_t* I, const int16_t* Q, int n) noexcept;

        /// @brief I/Q 독립 디코딩 — 각 채널 FWHT 분리 수행
        SymDecResultSplit walsh_dec_split_(
            const int16_t* I, const int16_t* Q, int n) noexcept;

        /// @brief 블랙홀 처리 (아웃라이어 칩 소거)
        void blackhole_(int16_t* I, int16_t* Q, int nc) noexcept;

        /// @brief CW Pre-Canceller (64칩 전용, 8칩 주기)
        void cw_cancel_64_(int16_t* I, int16_t* Q) noexcept;
    };

    // ── [BUG-54] SRAM 예산 정적 검증 ──
    //  harq_Q_ (CCM)는 V400_Dispatcher 외부 배치이므로 sizeof에 미포함
    //  sizeof(V400_Dispatcher) = SRAM 부분만 = ~120KB
    //
    //  [모든 플랫폼 검증 — #if __arm__ 가드 제거]
    //  PC(MSVC) 빌드에서도 오버플로우를 사전 탐지하기 위함
    static_assert(sizeof(HTS_V400_Dispatcher) < 128u * 1024u,
        "Dispatcher SRAM portion exceeds 128KB (SRAM1+2 budget)");
    static_assert(FEC_HARQ::NSYM16 <= 256, "NSYM16 exceeds orig_acc_ buffer");
    static_assert(FEC_HARQ::NSYM64 <= 256, "NSYM64 exceeds orig_acc_ buffer");

} // namespace ProtectedEngine
