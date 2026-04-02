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

/// @file  HTS_Holo_Tensor_4D.h
/// @brief HTS 4D 홀로그램 텐서 엔진 — 진정한 홀로그램 확산/역확산 (통신 전용)
/// @details
///   물리 홀로그램 필름 원리를 디지털 통신에 적용.
///   모든 출력 칩이 모든 입력 비트의 위상 간섭 패턴을 담는다.
///   칩 50% 손실 시에도 전체 데이터 복원 가능 (자가 치유).
///
///   TX 흐름:
///   @code
///   int8_t data[K];     // 입력 비트 블록 (±1 BPSK)
///   int8_t chips[N];    // 출력 칩 (±1 BPSK, 기존 RF 체인 호환)
///   engine.Encode_Block(data, K, chips, N);
///   // chips → BB1_Core_Engine → RF
///   @endcode
///
///   RX 흐름:
///   @code
///   int16_t rx_soft[N]; // 수신 소프트 심볼 (Q8, ±128)
///   int8_t  recovered[K];
///   engine.Decode_Block(rx_soft, N, valid_mask, recovered, K);
///   // valid_mask: 유효 칩 비트맵 (재밍/페이딩 손실 표시)
///   @endcode
///
/// @warning sizeof(HTS_Holo_Tensor_4D) ~ 1KB. 전역/정적 배치 권장.
///          Impl 내부 누산기 버퍼 크기 = HOLO_MAX_BLOCK_BITS * 4B.
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_Holo_Tensor_4D_Defs.h"
#include <cstdint>
#include <atomic>

namespace ProtectedEngine {

    /// @brief 4D 홀로그램 텐서 엔진
    ///
    /// @warning sizeof ~ 1KB. 전역/정적 배치 권장.
    class HTS_Holo_Tensor_4D final {
    public:
        static constexpr uint32_t SECURE_TRUE = 0x5A5A5A5Au;
        static constexpr uint32_t SECURE_FALSE = 0xA5A5A5A5u;

        HTS_Holo_Tensor_4D() noexcept;
        ~HTS_Holo_Tensor_4D() noexcept;

        /// @brief 초기화 (마스터 시드 + 프로파일)
        /// @param master_seed  128비트 마스터 시드 (4 x uint32_t)
        /// @param profile      운용 프로파일 (nullptr → 기본 DATA 프로파일)
        /// @return 성공 시 SECURE_TRUE, 실패 시 SECURE_FALSE
        uint32_t Initialize(const uint32_t master_seed[4],
            const HoloTensor_Profile* profile) noexcept;

        /// @brief 종료 및 시드 보안 소거
        void Shutdown() noexcept;

        /// @brief 마스터 시드 갱신 (키 회전, 보안 소거 포함)
        void Rotate_Seed(const uint32_t new_seed[4]) noexcept;

        /// @brief 운용 프로파일 동적 전환 (Initialize 후 모드 변경 시)
        void Set_Profile(const HoloTensor_Profile* profile) noexcept;

        /// @brief TX: 블록 인코딩 (K비트 → N칩, 진정한 홀로그램 간섭)
        /// @param data_bits    입력 비트 배열 (±1, 길이 K)
        /// @param K            블록 크기 (비트 수)
        /// @param output_chips 출력 칩 배열 (±1 BPSK, 길이 N)
        /// @param N            칩 수
        /// @return 성공 시 SECURE_TRUE, 실패 시 SECURE_FALSE
        uint32_t Encode_Block(const int8_t* data_bits, uint16_t K,
            int8_t* output_chips, uint16_t N) noexcept;

        /// @brief RX: 블록 디코딩 (N칩 → K비트, 자가 치유 복원)
        /// @param rx_chips     수신 소프트 심볼 (Q8, 길이 N)
        /// @param N            칩 수
        /// @param valid_mask   유효 칩 비트맵 (bit i=1: 칩 i 유효)
        /// @param output_bits  복원 비트 배열 (±1, 길이 K)
        /// @param K            블록 크기
        /// @return 성공 시 SECURE_TRUE, 실패 시 SECURE_FALSE
        uint32_t Decode_Block(const int16_t* rx_chips, uint16_t N,
            uint64_t valid_mask,
            int8_t* output_bits, uint16_t K) noexcept;

        /// @brief 시간 슬롯 전진 (Dim 2)
        void Advance_Time_Slot() noexcept;

        /// @brief 글로벌 프레임 번호 기반 시간 슬롯 동기화
        /// @param frame_no  MAC 계층 글로벌 프레임 번호
        /// @details TX/RX 노드가 동일 frame_no를 사용하면 PRNG 시드 동기화.
        ///          내부 time_slot을 frame_no로 직접 설정한다.
        void Set_Time_Slot(uint32_t frame_no) noexcept;

        /// @name 상태
        /// @{
        HoloState Get_State() const noexcept;
        uint32_t Get_Encode_Count() const noexcept;
        uint32_t Get_Decode_Count() const noexcept;
        uint32_t Get_Time_Slot() const noexcept;
        /// @}

        // -- 복사/이동 금지 --
        HTS_Holo_Tensor_4D(const HTS_Holo_Tensor_4D&) = delete;
        HTS_Holo_Tensor_4D& operator=(const HTS_Holo_Tensor_4D&) = delete;
        HTS_Holo_Tensor_4D(HTS_Holo_Tensor_4D&&) = delete;
        HTS_Holo_Tensor_4D& operator=(HTS_Holo_Tensor_4D&&) = delete;

        static constexpr uint32_t IMPL_BUF_SIZE = 1024u;

    private:
        struct Impl;
        alignas(4) uint8_t impl_buf_[IMPL_BUF_SIZE];
        std::atomic<bool>  initialized_{ false };
        mutable std::atomic_flag op_busy_ = ATOMIC_FLAG_INIT;
    };

    static_assert(sizeof(HTS_Holo_Tensor_4D) <= 2048u,
        "HTS_Holo_Tensor_4D exceeds 2KB SRAM budget");

} // namespace ProtectedEngine