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
//   FHSS: 임의 단계 → RF_SETTLING(PLL 안정·Blanking) → WAIT_SYNC
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
//  [최종 메모리 배치]
//   SRAM1+2 (128KB): harq_I_(58KB) + wb_(15KB) + orig_acc_(29KB) + etc
//   CCM     (64KB):  harq_Q_(58KB) + MSP 스택(4KB)
//   총 사용 ~178KB / 192KB (14.3KB = 7.4% 마진)
//
//  [정렬] HTS_V400_Dispatcher.cpp: g_harq_ccm_union·g_sic_exp_*·k_walsh_dummy_iq_
//        및 파일 범위 스크래치(g_v400_sym_scratch 등)에 alignas(64/16) 적용.
//
//  [제약]    fp32 0, fp64 0, try-catch 0, 힙 0
//  [보안 소거] D-2/X-5-1 구현은 HTS_Secure_Memory.cpp — 본 모듈은 호출부
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
        READ_PAYLOAD = 2u,  ///< 페이로드 심볼 수신 중
        RF_SETTLING = 3u   ///< RF PLL 안정 구간 — 칩 송수신 Blanking(타이머는 Feed_Chip 경유)
    };

    /* BUG-FIX-RETX: HARQ 연속모드 soft_clip 정책 */
    /* BUG-FIX-SC1: soft_clip 정책 플래그 추가 — 페이로드 절벽 방지 */
    enum class SoftClipPolicy : uint8_t {
        ALWAYS    = 0u,   // 전 구간 ON (기존 동작, 기본값)
        SYNC_ONLY = 1u,   // 프리앰블/헤더만 ON, 페이로드 OFF (양산 권장)
        NEVER     = 2u    // 전 구간 OFF (벤치 전용, 프리앰블/헤더도 OFF)
    };

    /// @brief 디코딩 완료 패킷 구조체
    struct DecodedPacket {
        static constexpr uint32_t DECODE_MASK_OK = 0xFFFFFFFFu;
        static constexpr uint32_t DECODE_MASK_FAIL = 0x00000000u;

        PayloadMode mode;       ///< 페이로드 모드
        uint8_t data[8];        ///< 디코딩된 데이터 (최대 8바이트)
        int data_len;           ///< 유효 데이터 길이
        int harq_k;             ///< HARQ 라운드 수 (1 = 단일 전송 성공)
        /// CRC/디코드 성공: DECODE_MASK_OK, 실패: DECODE_MASK_FAIL (호출부 & 마스크 결합)
        uint32_t success_mask{ DECODE_MASK_FAIL };
    };

    // ── CCM 섹션 매크로 ─────────────────────────────────────────
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
    //  ★ 런타임 안전망: full_reset_()에서 g_harq_ccm_union 전체 wipe
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
        /// @brief 소멸자 — CCM·버퍼·시드·ajc_ 스토리지 개별 secureWipe (this 통째 wipe 없음)
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

        int Build_Retx(PayloadMode mode, const uint8_t* info, int ilen,
            int16_t amp, int16_t* oI, int16_t* oQ, int max_c) noexcept;
        void Feed_Retx_Chip(int16_t rx_I, int16_t rx_Q) noexcept;
        bool Is_Retx_Ready() const noexcept { return retx_ready_; }

        /// @brief [테스트 전용] 동기/헤더를 건너뛰고 READ_PAYLOAD 상태로 직접 진입
        /// @param mode 페이로드 모드 (VIDEO_16, VOICE, DATA)
        /// @param bps  DATA 모드 BPS (VOICE/VIDEO_16에서는 무시)
        /// @note 양산 코드에서 호출 금지 — PC 테스트 하네스 전용
        void Inject_Payload_Phase(PayloadMode mode, int bps) noexcept;

        /// @brief RX 칩 1개 주입 (ISR 또는 메인 루프에서 연속 호출)
        void Feed_Chip(int16_t rx_I, int16_t rx_Q) noexcept;

        /// @brief 상태 머신 + AJC + HARQ 전체 초기화
        void Reset() noexcept;

        /// @brief 현재 I/Q 모드 조회
        [[nodiscard]] IQ_Mode Get_IQ_Mode() const noexcept;

        /// @brief AJC 노이즈 플로어 기반 적응형 BPS 갱신
        void Update_Adaptive_BPS(uint32_t nf) noexcept;

        /// @brief PC·시험 하네스: 64칩 DATA BPS(3~6) 직접 설정 (`bps_clamp_runtime`).
        void Set_Lab_BPS64(int bps) noexcept;
        /// @brief 재밍 시험 하네스: I/Q 모드 IQ_SAME 고정.
        void Set_Lab_IQ_Mode_Jam_Harness() noexcept;

        /// @brief RF 측정값 컨테이너 주입 (선택적)
        void Set_RF_Metrics(HTS_RF_Metrics* p) noexcept;

        /// @brief 매 프레임 적응형 BPS 갱신
        void Tick_Adaptive_BPS() noexcept;

        /// @brief IR-HARQ 모드 전환. 변경 시 `full_reset_`로 HARQ 상태 초기화.
        void Set_IR_Mode(bool enable) noexcept;
        [[nodiscard]] bool Get_IR_Mode() const noexcept;

        /* BUG-FIX-PRE1: 프리앰블 반복 — 고재밍 동기 확보 (상한 200, 테스트·양산 튜닝). */
        void Set_Preamble_Reps(int reps) noexcept {
            pre_reps_ = (reps < 1) ? 1 : (reps > 200) ? 200 : reps;
        }
        [[nodiscard]] int Get_Preamble_Reps() const noexcept { return pre_reps_; }

        void Set_Preamble_Boost(int boost) noexcept {
            pre_boost_ = (boost < 1) ? 1 : (boost > 4) ? 4 : boost;
        }
        [[nodiscard]] int Get_Preamble_Boost() const noexcept { return pre_boost_; }

        /// @brief IR DATA·64칩·IQ_SAME SIC — CRC 실패 후 재인코딩 예상 칩을 다음 라운드에서 감산
        /// @note 기본값 OFF. 필요 시 `Set_IR_SIC_Enabled(true)` 로 활성화.
        void Set_IR_SIC_Enabled(bool enable) noexcept;
        [[nodiscard]] bool Get_IR_SIC_Enabled() const noexcept;
        /// @brief SIC용 Walsh 진폭 — TX `Build_Packet(..., amp, ...)` 와 동일 스케일 권장 (기본 300)
        void Set_SIC_Walsh_Amp(int16_t amp) noexcept;

        /// @brief IR-HARQ 1라운드 RTT (ms) — HTS 독자 링크; 양산 시 실측·스케줄로 확정.
        /// @note Chase/소프트 텐서 벤치의 `LTE_HARQ_Controller::HARQ_RTT_MS`(8ms)와 별도.
        ///       PC 벤치 `HTS_Fractal_Channel_Compare` 가 IR 경로 지연 proxy에 동기화.
        static constexpr double IR_HARQ_RTT_MS = 4.0;

        // ── CW 소거기 ON/OFF (벤치마크 비교용, 양산 기본값 true) ──
        void Set_CW_Cancel(bool enable) noexcept { cw_cancel_enabled_ = enable; }
        [[nodiscard]] bool Get_CW_Cancel() const noexcept { return cw_cancel_enabled_; }

        // ── AJC ON/OFF (벤치마크 전용, 양산 기본값 true) ──
        void Set_AJC_Enabled(bool enable) noexcept { ajc_enabled_ = enable; }
        [[nodiscard]] bool Get_AJC_Enabled() const noexcept { return ajc_enabled_; }

        void Set_SoftClip_Policy(SoftClipPolicy p) noexcept { soft_clip_policy_ = p; }
        SoftClipPolicy Get_SoftClip_Policy() const noexcept { return soft_clip_policy_; }

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

        /// @brief FHSS 도약 채널(0~127) — `seed`·`seq` 혼합, `/`·`%` 없음(`& 0x7F`만)
        [[nodiscard]] static uint8_t FHSS_Derive_Channel(
            uint32_t seed, uint32_t seq) noexcept;

        /// @brief TX 역할 도약: 현재 `tx_seq_`로 채널 산출 후 시퀀스 증가·Blanking 진입
        /// @return 0~127 정상, 0xFF 이미 RF_SETTLING 또는 전이 실패
        [[nodiscard]] uint8_t FHSS_Request_Hop_As_Tx() noexcept;

        /// @brief RX 역할 도약: 현재 `rx_seq_`로 채널 산출 후 시퀀스 증가·Blanking 진입
        [[nodiscard]] uint8_t FHSS_Request_Hop_As_Rx() noexcept;

        [[nodiscard]] bool FHSS_Is_Rf_Settling() const noexcept;

        /// @brief RF PLL 안정 슬롯 수(64칩 1심볼 분량)
        static constexpr int FHSS_SETTLE_CHIPS = 64;

    private:
        RxPhase     phase_;             ///< 현재 RX 상태 (CFI 보호)
        PayloadMode cur_mode_;          ///< 현재 페이로드 모드
        PayloadMode active_video_;      ///< 활성 VIDEO 모드 (1칩/16칩)
        uint32_t    seed_;              ///< PRNG 마스터 시드
        uint32_t    tx_seq_;            ///< TX 시퀀스 번호
        uint32_t    rx_seq_;            ///< RX 시퀀스 번호
        int         rf_settle_chips_remaining_{ 0 }; ///< RF_SETTLING 남은 칩 슬롯
        PacketCB    on_pkt_;            ///< 패킷 수신 콜백
        ControlCB   on_ctrl_;           ///< 모드 전환 콜백

        int16_t buf_I_[64] = {};        ///< 칩 수집 버퍼 I
        int16_t buf_Q_[64] = {};        ///< 칩 수집 버퍼 Q
        int     buf_idx_;               ///< 버퍼 현재 인덱스
        /// WAIT_SYNC 전용: 64칩 링(물리 시프트 없음), 선형 복사는 orig_ 로만
        int     wait_sync_head_{ 0 };
        int     wait_sync_count_{ 0 };

        int     pre_phase_;             ///< 프리앰블 매칭 단계 (0 또는 1)
        int     pre_reps_ = 1;
        int     pre_boost_ = 1;  ///< 프리앰블 진폭 배수 (1=기존, 2=+6dB, 4=+12dB)
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

        // ── HARQ 누적 상태 (스트리밍 직접 누적) ───────────────────
        //
        //  rx_ union { m16{harq,sI,sQ}, m64{harq,sI,sQ} }
        //   → sI/sQ는 on_sym_()에서 저장 후 try_decode_()에서 Feed로 일괄 누적
        //   → sI/sQ 57.5KB 낭비 (Feed = 단순 덧셈, 스트리밍과 결과 동일)
        //
        //  rx_ union { m16{harq}, m64_I{harq_I_} }
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

        // ── HARQ Q채널 — CCM 배치 (DMA 불가, CPU 연산 전용) ───────
        //
        //  harq.aQ[230][64] = 58,880B → CCM(64KB)에 별도 배치
        //  실제 배열은 .cpp에 file-scope static으로 정의 (sizeof 제외)
        //  포인터만 클래스 멤버로 보유
        //
        //  linker script 예시:
        //    .ccm_bss (NOLOAD) : { _sccm_bss = .; *(.ccm_bss) _eccm_bss = .; } > CCM
        //
        // Chase Q 누적 행 포인터 — `g_harq_ccm_union.chase.harq_Q` 와 동일 선두
        int32_t(*harq_Q_)[FEC_HARQ::C64];

        // ── IR-HARQ (DATA·64칩·IQ_SAME 전용) ─────────────────────────────
        //  `IR_RxState`·칩 버퍼는 .cpp 의 CCM union(`g_harq_ccm_union.ir`)에 두고
        //  포인터만 보유 — Chase `harq_Q` 와 SRAM 추가 0으로 공용화.
        bool ir_mode_{ false };
        int  ir_rv_{ 0 };
        int16_t* ir_chip_I_;
        int16_t* ir_chip_Q_;
        FEC_HARQ::IR_RxState* ir_state_;

        bool sic_ir_enabled_{ false };   ///< IR 64칩 SIC (기본 OFF)
        bool sic_expect_valid_{ false }; ///< 직전 실패 라운드에서 예상 칩 생성됨
        int16_t sic_walsh_amp_{ 300 };   ///< Walsh 인코드 진폭 (Build_Packet amp 정합)

        int  sym_idx_;                  ///< 현재 심볼 인덱스
        bool harq_inited_;              ///< HARQ 상태 초기화 완료 여부
        bool retx_ready_;

        // ── WorkBuf 유니온 (반이중 TDM) ───────────────────────────
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

        // ── 원본 심볼 누적 (AJC 결정지향 피드백용) ─────────────────
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
        SoftClipPolicy soft_clip_policy_ = SoftClipPolicy::ALWAYS;
        bool ajc_enabled_{ true };        ///< AJC 활성화 (양산 기본 true)

        /// @brief RF 측정값 (비소유 포인터, nullptr 허용)
        HTS_RF_Metrics* p_metrics_{ nullptr };

        // ── CFI 상태 전이 검증 (항목⑬) ───────────────────────────
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
        //  구현: 16슬롯 LUT(4상태) + key 클램프(>=16 → 불법 슬롯), 반환은 풀비트 마스크

        void fhss_abort_rx_for_hop_() noexcept;

        static constexpr uint32_t PHASE_TRANSFER_MASK_OK = 0xFFFFFFFFu;
        static constexpr uint32_t PHASE_TRANSFER_MASK_FAIL = 0x00000000u;

        uint32_t set_phase_(RxPhase target) noexcept;

        /// @brief 내부 도우미 함수 — 성공 시 PARSE_HDR_MASK_OK
        static constexpr uint32_t PARSE_HDR_MASK_OK = 0xFFFFFFFFu;
        static constexpr uint32_t PARSE_HDR_MASK_FAIL = 0x00000000u;
        uint32_t parse_hdr_(PayloadMode& mode, int& plen) noexcept;

        /// Decode64_IR 실패 직후: `sic_tentative`·직전 RV로 예상 칩 버퍼 채움
        void fill_sic_expected_64_() noexcept;
        void on_sym_() noexcept;
        void try_decode_() noexcept;
        void handle_video_(uint32_t decode_ok_mask) noexcept;
        void full_reset_() noexcept;
        void harq_feedback_seed_(const uint8_t* data, int data_len,
            int nc, uint32_t il) noexcept;

        int32_t dec_wI_[64] = {};       ///< Walsh 디코딩 워킹 버퍼 I
        int32_t dec_wQ_[64] = {};       ///< Walsh 디코딩 워킹 버퍼 Q

        //  mags[64] + sorted[64] = 512B (soft_clip_iq, blackhole_ 공유)
        //  시간적 분리: soft_clip_iq 완료 후 blackhole_ 호출
        uint32_t scratch_mag_[64] = {};
        uint32_t scratch_sort_[64] = {};

        int32_t first_c63_ = 0; ///< FPR: preamble first m=63 energy
        int32_t m63_gap_ = 0;   ///< FPR: consecutive non-m63 gap count

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

        /// @param cap_search_to_bps true=페이로드용(에너지 탐색을 2^BPS로 제한),
        /// false=프리앰블·헤더(0..63 Walsh 전체). BPS<6 시 동기 필수.
        SymDecResult walsh_dec_full_(const int16_t* I, const int16_t* Q, int n,
                                     bool cap_search_to_bps = true) noexcept;

        /// @brief I/Q 독립 디코딩 — 각 채널 FWHT 분리 수행
        SymDecResultSplit walsh_dec_split_(
            const int16_t* I, const int16_t* Q, int n) noexcept;

        /// @brief 블랙홀 처리 (아웃라이어 칩 소거)
        void blackhole_(int16_t* I, int16_t* Q, int nc) noexcept;

        /// @brief CW Pre-Canceller (64칩 전용, 8칩 주기)
        void cw_cancel_64_(int16_t* I, int16_t* Q) noexcept;
    };

    // ── SRAM budget static checks ─────────────────────────────
    //  harq_Q_ (CCM) is placed outside V400_Dispatcher; not in sizeof.
    //  sizeof(V400_Dispatcher) counts SRAM-resident portion only (~120KiB).
    //
    //  All platforms (no __arm__ guard): catch oversize on PC/MSVC too.
    static_assert(sizeof(HTS_V400_Dispatcher) < 128u * 1024u,
        "HTS_V400_Dispatcher exceeds 128 KiB static RAM budget");
    static_assert(FEC_HARQ::NSYM16 <= 256, "NSYM16 exceeds orig_acc_ buffer");
    static_assert(FEC_HARQ::NSYM64 <= 256, "NSYM64 exceeds orig_acc_ buffer");

} // namespace ProtectedEngine

/// @brief Mock RF 합성기 채널 설정 (벤치/검증 — HTS_V400_Dispatcher.cpp)
extern "C" void Mock_RF_Synth_Set_Channel(uint8_t channel) noexcept;
