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

/// @file  HTS_Holo_Dispatcher.h
/// @brief HTS 4D 홀로그램 디스패처 — 기존 V400 Dispatcher 연동 심(shim)
/// @details
///   기존 V400 Dispatcher를 수정하지 않고, 4D 홀로그램 텐서 인코딩/디코딩을
///   기존 칩 I/Q 인터페이스에 연결하는 연동 모듈.
///
///  [아키텍처 NOTE — 파이프라인 연결 구조]
///
///  실제 코드베이스에서 Holo_Dispatcher는 FEC_HARQ를 include/호출하지 않으며,
///  HTS_V400_Dispatcher 경유 호출도 없다.
///  실제 데이터 흐름:
///
///    Holo_Dispatcher::Build_Holo_Packet / Decode_Holo_Block
///        └─▶ HTS_Holo_Tensor_4D::Encode_Block / Decode_Block
///
///  별도 계층으로, HTS_V400_Dispatcher는 VIDEO/VOICE/DATA 모드에서
///  FEC_HARQ(Encode/Decode/Decode_Core_Split 등)를 사용한다 — 홀로 모드와
///  분리된 경로이다.
///
///  백서·검수 기준서의 "직접 파이프라인" 표현은 논리적 흐름 기술일 수 있으며
///  물리적 include/호출과 다를 수 있다. 관련 문서 개정 시 본 NOTE를 참고할 것.
///
///   연동 구조:
///   @code
///   [기존 Dispatcher]                     [HoloDispatch (신규)]
///   Build_Packet(VIDEO_1/16/VOICE/DATA)   Build_Holo_Packet(VOICE/DATA/RESILIENT_HOLO)
///       → Walsh encode → I/Q chips           → 4D HoloTensor encode → I/Q chips
///   Feed_Chip → walsh_dec → FEC_HARQ      Feed_Holo_Chips → HoloTensor decode → output
///   @endcode
///
///   사용법:
///   @code
///   // 초기화 (전역)
///   static HTS_Holo_Dispatcher g_holo;
///   g_holo.Initialize(master_seed);
///
///   // TX: 기존 Dispatcher 대신 또는 alongside 호출
///   uint8_t mode = g_holo.Select_Mode(metrics);  // SNR/AJC 기반 자동 선택
///   if (HoloPayload::Is_Holo_Mode(mode)) {
///       size_t chips = g_holo.Build_Holo_Packet(mode, data, len, amp, outI, outQ, max);
///   } else {
///       int chips = dispatcher.Build_Packet(...);  // 기존 경로
///   }
///
///   // RX: 홀로 모드 감지 시
///   g_holo.Feed_Holo_Block(rxI, rxQ, N, valid_mask, out_data, &out_len);
///   @endcode
///
/// @warning sizeof(HTS_Holo_Dispatcher) ~ 1.2KB. 전역/정적 배치 권장.
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_Holo_Dispatcher_Defs.h"
#include "HTS_Holo_Tensor_4D.h"
#include "HTS_RF_Metrics.h"
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace ProtectedEngine {

    /// @brief 4D 홀로그램 디스패처 연동 모듈
    ///
    /// @warning sizeof ~ 1.2KB. 전역/정적 배치 권장.
    class HTS_Holo_Dispatcher final {
    public:
        static constexpr uint32_t SECURE_TRUE = 0x5A5A5A5Au;
        static constexpr uint32_t SECURE_FALSE = 0xA5A5A5A5u;
        /// dispatch_busy_ try-lock 게이트 (SSOT — .cpp Holo_Dispatch_Busy_Guard와 동일 값)
        static constexpr uint32_t LOCK_FREE = 0x13579BDFu;
        static constexpr uint32_t LOCK_BUSY = 0x2468ACE0u;

        HTS_Holo_Dispatcher() noexcept;
        ~HTS_Holo_Dispatcher() noexcept;

        /// @brief 초기화 (마스터 시드)
        /// @param master_seed  128비트 마스터 시드
        /// @return 성공 시 SECURE_TRUE, 실패 시 SECURE_FALSE
        uint32_t Initialize(const uint32_t master_seed[4]) noexcept;

        /// @brief 종료 (엔진 파쇄 + 모드 리셋)
        /// @return 락 획득·파쇄 완료 시 SECURE_TRUE, try-lock 실패 시 SECURE_FALSE (재시도)
        [[nodiscard]] uint32_t Shutdown() noexcept;

        /// @brief 시드 회전 (기존 Security_Session 키 갱신 연동)
        /// @return 락 획득·엔진 갱신 성공 시 SECURE_TRUE, nullptr/try-lock 실패 시 SECURE_FALSE (재시도)
        [[nodiscard]] uint32_t Rotate_Seed(const uint32_t new_seed[4]) noexcept;

        /// @brief SNR/AJC 기반 자동 모드 선택
        /// @param metrics  RF 측정값 (nullable → DATA_HOLO 기본)
        /// @return HoloPayload 모드 코드
        uint8_t Select_Mode(const HTS_RF_Metrics* metrics) const noexcept;

        /// @brief TX: 홀로그램 패킷 빌드 (4D 텐서 → I/Q 칩)
        /// @param mode      HoloPayload::VOICE_HOLO / DATA_HOLO / RESILIENT_HOLO
        /// @param info      원본 데이터 바이트
        /// @param info_len  데이터 길이
        /// @param amp       송신 진폭 (Q15)
        /// @param out_I     출력 I 칩 배열
        /// @param out_Q     출력 Q 칩 배열
        /// @param max_chips 출력 배열 최대 크기
        /// @return 생성된 칩 수 (0=실패)
        size_t Build_Holo_Packet(uint8_t mode, const uint8_t* info, size_t info_len,
            int16_t amp, int16_t* out_I, int16_t* out_Q,
            size_t max_chips) noexcept;

        /// @brief RX: 홀로그램 블록 디코딩 (I/Q 칩 → 데이터 복원)
        /// @param rx_I       수신 I 칩
        /// @param rx_Q       수신 Q 칩
        /// @param chip_count 칩 수
        /// @param valid_mask 유효 칩 비트맵 (0xFFFF..=전체 유효)
        /// @param out_data   복원 데이터 (최대 16바이트)
        /// @param out_len    복원 데이터 길이(바이트)
        /// @return 성공 시 SECURE_TRUE, 실패 시 SECURE_FALSE
        uint32_t Decode_Holo_Block(const int16_t* rx_I, const int16_t* rx_Q,
            uint16_t chip_count, uint64_t valid_mask,
            uint8_t* out_data, size_t* out_len) noexcept;

        /// @brief 시간 슬롯 전진 (프레임 경계에서 호출)
        /// @return 락 획득·엔진 갱신 성공 시 SECURE_TRUE, try-lock 실패 시 SECURE_FALSE (재시도)
        [[nodiscard]] uint32_t Advance_Time() noexcept;

        /// @brief 글로벌 프레임 번호 기반 시간 슬롯 동기화
        /// @param frame_no  MAC 계층에서 전달하는 글로벌 프레임 번호
        /// @details TX/RX 노드가 동일 frame_no를 사용하면 PRNG 시드가
        ///          자동 동기화되어 독립적 Advance_Time 호출에 의한
        ///          시간 슬롯 어긋남(de-sync)이 발생하지 않는다.
        /// @return 락 획득·동기화 성공 시 SECURE_TRUE, try-lock 실패 시 SECURE_FALSE (재시도)
        [[nodiscard]] uint32_t Sync_Time_Slot(uint32_t frame_no) noexcept;

        /// @brief 현재 활성 홀로 모드
        uint8_t Get_Current_Mode() const noexcept;

        /// @brief 홀로 모드 수동 설정 (RX 헤더 파싱 후 호출)
        void Set_Current_Mode(uint8_t mode) noexcept;

        // -- 복사/이동 금지 --
        HTS_Holo_Dispatcher(const HTS_Holo_Dispatcher&) = delete;
        HTS_Holo_Dispatcher& operator=(const HTS_Holo_Dispatcher&) = delete;
        HTS_Holo_Dispatcher(HTS_Holo_Dispatcher&&) = delete;
        HTS_Holo_Dispatcher& operator=(HTS_Holo_Dispatcher&&) = delete;

    private:
        HTS_Holo_Tensor_4D engine_;
        std::atomic<uint8_t> current_mode_{ HoloPayload::DATA_HOLO };
        std::atomic<uint32_t> dispatch_busy_{ LOCK_FREE };
        uint8_t pad_[3] = {};   ///< Alignment padding (C26495 fix)
    };

} // namespace ProtectedEngine