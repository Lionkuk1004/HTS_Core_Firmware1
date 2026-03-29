// =========================================================================
// HTS_Rx_Sync_Detector.h
// B-CDMA CFAR 기반 동기화 피크 검출기 — 공개 인터페이스
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [CFAR 동작 원리]
//   1. 상관도 버퍼 순회 → 양수 에너지 합산 / 양수 개수 = 노이즈 플로어
//   2. 임계치 = 노이즈 플로어 × threshold_multiplier
//   3. 임계치 초과 최대 피크의 인덱스 반환 (없으면 -1)
//
//  [사용법]
//   1. 생성: HTS_Rx_Sync_Detector(tier)
//      → 초기화 실패(OOM) 시 impl_valid_=false → Detect_Sync_Peak가 -1 반환
//
//   2. (선택) Set_CFAR_Multiplier(multiplier)
//   3. Detect_Sync_Peak(correlation_buffer, buffer_size)
//      → ≥0: 피크 인덱스 (동기 획득), -1: 피크 없음
//
//  [메모리 요구량]
//   sizeof(HTS_Rx_Sync_Detector) ≈ IMPL_BUF_SIZE + impl_valid_ + padding
//   Impl: HTS_Phy_Config(≈36B) + int32_t(4B) ≈ 48B → IMPL_BUF_SIZE = 256B
//
//  [보안 설계]
//   상태 없는 순수 검출기 — 보안 소거 불필요
//   impl_buf_: 소멸자에서 SecWipe — 전체 이중 소거
//   복사/이동: = delete (단일 인스턴스 원칙)
//
//  [양산 수정 이력]
//   BUG-01~08 (헤더→전방선언, Pimpl, static_assert 이동, Get_Config→개별접근자,
//              MIN_CFAR→.cpp, ARM selftest 가드, Self-Contained,
//              노이즈 플로어 분모 수정)
//   BUG-09 [CRIT] unique_ptr + make_unique + try-catch(ctor) → placement new
//          · impl_buf_[256] alignas(8)
//          · 소멸자 = default → 명시적 p->~Impl() + SecWipe
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    // 전방 선언 (HTS_Dynamic_Config.h include 제거)
    enum class HTS_Phy_Tier : uint8_t;

    // HTS_RF_Metrics 전방 선언 (Detect_Sync_Peak 선택적 인수용)
    struct HTS_RF_Metrics;

    class HTS_Rx_Sync_Detector {
    public:
        /// @brief CFAR 동기화 피크 검출기 생성
        /// @param tier  HTS_Phy_Tier::TIER_32_IQ 또는 TIER_64_ECCM
        /// @note  초기화 실패(OOM) 시 impl_valid_=false → Detect_Sync_Peak가 -1
        explicit HTS_Rx_Sync_Detector(HTS_Phy_Tier tier) noexcept;

        /// @brief 소멸자 — Impl 소멸자 호출 후 impl_buf_ SecWipe
        ~HTS_Rx_Sync_Detector() noexcept;

        /// 단일 인스턴스 원칙 — 상태 공유 버그 컴파일 시점 차단
        HTS_Rx_Sync_Detector(const HTS_Rx_Sync_Detector&) = delete;
        HTS_Rx_Sync_Detector& operator=(const HTS_Rx_Sync_Detector&) = delete;
        HTS_Rx_Sync_Detector(HTS_Rx_Sync_Detector&&) = delete;
        HTS_Rx_Sync_Detector& operator=(HTS_Rx_Sync_Detector&&) = delete;

        /// @brief CFAR 임계치 배수 동적 조정 (최소 1로 클램프)
        void Set_CFAR_Multiplier(int32_t multiplier) noexcept;

        /// @brief 현재 CFAR 배수 반환 (impl_valid_=false 시 1)
        int32_t Get_CFAR_Multiplier() const noexcept;

        /// @brief 현재 칩 수 반환 (impl_valid_=false 시 0)
        uint32_t Get_Chip_Count() const noexcept;

        /// @brief CFAR 기본 배수 반환 (impl_valid_=false 시 1)
        int32_t Get_Default_CFAR_Mult() const noexcept;

        /// @brief CFAR 피크 검출
        /// @param correlation_buffer  int32_t 상관도 배열 (nullptr 불가)
        /// @param buffer_size         원소 수 (0 불가)
        /// @param p_metrics           [선택] SNR 프록시 기록 대상 (nullptr 허용)
        ///                            비nullptr 시 metrics.snr_proxy 갱신:
        ///                            snr_proxy = max_value / noise_floor (정수비)
        ///                            양수 0개 시 snr_proxy = 0 으로 기록
        /// @return ≥0: 피크 인덱스 (동기 성공), -1: 피크 없음 또는 방어 반환
        [[nodiscard]]
        int32_t Detect_Sync_Peak(
            const int32_t* correlation_buffer,
            size_t          buffer_size,
            HTS_RF_Metrics* p_metrics = nullptr) noexcept;

    private:
        // ── [BUG-09] Pimpl In-Place Storage (zero-heap) ──────────────
        // Impl = HTS_Phy_Config(≈36B) + threshold_multiplier(4B) ≈ 48B
        // alignof(Impl) = 4 (int32_t) → alignas(8) 초과 정렬로 안전
        static constexpr size_t IMPL_BUF_SIZE = 256u;
        static constexpr size_t IMPL_BUF_ALIGN = 8u;

        struct Impl;  ///< CFAR 상태 + 체급 설정 은닉

        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        bool impl_valid_ = false;

        Impl* get_impl() noexcept;
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine