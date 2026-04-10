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

/// @file  HTS_Holo_Dispatcher_Defs.h
/// @brief HTS 4D 홀로그램 디스패처 연동 정의부
/// @details
///   기존 V400 Dispatcher(PayloadMode 4종)에 4D 홀로그램 모드를
///   추가하기 위한 정의. 기존 코드 수정 0줄.
///
///   모드 전략:
///   - VIDEO_1/VIDEO_16: 기존 BB1 유지 (속도 우선)
///   - VOICE_HOLO:  K=8, N=64, L=2 (12us, 음성 자가치유)
///   - DATA_HOLO:   K=16, N=64, L=2 (390us, 검침/IoT)
///   - RESILIENT_HOLO: K=8, N=64, L=4 (1.56ms, 재밍/변전소)
///
///   자동 전환:
///   - SNR >= 10, AJC < 500    -> VOICE_HOLO
///   - SNR >= 5,  AJC < 2000   -> DATA_HOLO
///   - SNR < 5  OR AJC >= 2000 -> RESILIENT_HOLO
///   - VIDEO 모드 진입 시       -> 기존 BB1 (Dispatcher가 처리)
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_Holo_Tensor_4D_Defs.h"
#include <cstdint>

namespace ProtectedEngine {

    // ============================================================
    //  확장 페이로드 모드
    // ============================================================

    /// @brief 확장 페이로드 모드 (기존 + 4D 홀로그램)
    /// @note  기존 PayloadMode(0x00~0x03, 0xFF)와 값 충돌 없음.
    ///        Dispatcher에서 0x10 이상이면 HoloDispatch로 위임.
    namespace HoloPayload {
        // --- 기존 모드 (수정 없음, 참조용) ---
        static constexpr uint8_t VIDEO_1 = 0x00u;
        static constexpr uint8_t VIDEO_16 = 0x01u;
        static constexpr uint8_t VOICE_LEGACY = 0x02u;
        static constexpr uint8_t DATA_LEGACY = 0x03u;

        // --- 4D 홀로그램 모드 (신규, 0x10~) ---
        static constexpr uint8_t VOICE_HOLO = 0x10u;  ///< K=8, N=64, L=2
        static constexpr uint8_t DATA_HOLO = 0x11u;  ///< K=16, N=64, L=2
        static constexpr uint8_t RESILIENT_HOLO = 0x12u;  ///< K=8, N=64, L=4

        /// @brief 모드가 4D 홀로그램인지 판별
        /// @note  보안 경로에서는 호출 결과를 즉시 사용하고, 캐시된 bool 재사용을 금지.
        inline bool Is_Holo_Mode(uint8_t mode) noexcept
        {
            return (mode >= VOICE_HOLO && mode <= RESILIENT_HOLO);
        }
    }  // namespace HoloPayload

    // ============================================================
    //  자동 모드 선택 임계값 (BPS Controller 연동)
    // ============================================================

    /// @note  기존 HTS_Adaptive_BPS_Controller의 임계값과 동일한 구조.
    ///        BPS Controller가 BPS를 결정한 후, 이 임계값으로 홀로 모드를 선택.
    namespace HoloThreshold {
        /// AJC < 500 AND SNR >= 10 -> VOICE_HOLO (속도 우선)
        static constexpr uint32_t AJC_QUIET = 500u;
        static constexpr int32_t  SNR_QUIET = 10;

        /// AJC < 2000 AND SNR >= 5 -> DATA_HOLO (균형)
        static constexpr uint32_t AJC_MODERATE = 2000u;
        static constexpr int32_t  SNR_MODERATE = 5;

        /// AJC >= 2000 OR SNR < 5 -> RESILIENT_HOLO (보호 우선)
        // (위 조건에 해당하지 않으면 자동 RESILIENT)
    }  // namespace HoloThreshold

    // ============================================================
    //  홀로그램 모드별 프로파일 매핑
    // ============================================================

    /// @brief 모드 → 프로파일 변환 (constexpr ROM, HTS_Holo_Tensor_4D_Defs.h 와 바이트 동일)
    /// @note VOICE_HOLO 는 반드시 K=8, N=64, L=2 (잘못된 K=16,N=16,L=1 프리셋 금지)
    inline constexpr HoloTensor_Profile Holo_Mode_To_Profile(uint8_t mode) noexcept
    {
        switch (mode) {
        case HoloPayload::VOICE_HOLO:
            return { 8u, 64u, 2u, {0, 0, 0} };
        case HoloPayload::DATA_HOLO:
            return { 16u, 64u, 2u, {0, 0, 0} };
        case HoloPayload::RESILIENT_HOLO:
            return { 8u, 64u, 4u, {0, 0, 0} };
        default:
            return { 16u, 64u, 2u, {0, 0, 0} };
        }
    }

    static_assert(Holo_Mode_To_Profile(HoloPayload::VOICE_HOLO).block_bits
                      == k_holo_profiles[0].block_bits
                  && Holo_Mode_To_Profile(HoloPayload::VOICE_HOLO).chip_count
                      == k_holo_profiles[0].chip_count
                  && Holo_Mode_To_Profile(HoloPayload::VOICE_HOLO).num_layers
                      == k_holo_profiles[0].num_layers,
        "VOICE holo profile must match k_holo_profiles[0] (K=8,N=64,L=2)");
    static_assert(Holo_Mode_To_Profile(HoloPayload::DATA_HOLO).block_bits
                      == k_holo_profiles[1].block_bits
                  && Holo_Mode_To_Profile(HoloPayload::DATA_HOLO).chip_count
                      == k_holo_profiles[1].chip_count
                  && Holo_Mode_To_Profile(HoloPayload::DATA_HOLO).num_layers
                      == k_holo_profiles[1].num_layers,
        "DATA holo profile must match k_holo_profiles[1]");
    static_assert(Holo_Mode_To_Profile(HoloPayload::RESILIENT_HOLO).block_bits
                      == k_holo_profiles[2].block_bits
                  && Holo_Mode_To_Profile(HoloPayload::RESILIENT_HOLO).chip_count
                      == k_holo_profiles[2].chip_count
                  && Holo_Mode_To_Profile(HoloPayload::RESILIENT_HOLO).num_layers
                      == k_holo_profiles[2].num_layers,
        "RESILIENT holo profile must match k_holo_profiles[2]");

    // ============================================================
    //  헤더 인코딩 (기존 Dispatcher 호환)
    // ============================================================

    /// @brief 홀로 모드 헤더의 모드 비트 (기존 mb=3(DATA)에 확장 플래그)
    /// @note  기존 헤더: mb(2비트) | plen(10비트)
    ///        mb=3 + plen 상위 2비트=11 → 홀로 모드 식별자
    ///        plen 하위 8비트 → 서브모드(VOICE/DATA/RESILIENT)
    static constexpr uint16_t HOLO_HEADER_FLAG = 0x0300u;  ///< plen[9:8]=11 = 홀로 플래그

} // namespace ProtectedEngine