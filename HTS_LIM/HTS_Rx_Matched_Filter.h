// =========================================================================
// HTS_Rx_Matched_Filter.h
// B-CDMA 교차 상관 정합 필터 — 공개 인터페이스
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  이 모듈은 B-CDMA 수신단의 교차 상관(Cross-Correlation) 정합 필터입니다.
//
//  [정합 필터 원리]
//   out[i] = Σ(j=0..N-1) rx[i+j] × ref[j] >> 16
//
//  [메모리 요구량]
//   sizeof(HTS_Rx_Matched_Filter) ≈ IMPL_BUF_SIZE + impl_valid_ + padding
//   Impl: HTS_Sys_Config(32B) + int32_t[64](256B) + ref_len(4B) ≈ 296B → IMPL_BUF_SIZE = 320B
//   기준 시퀀스 데이터: int32_t[64] 정적 배열 (256B, 힙 0)
//
//  [보안 설계]
//   기준 시퀀스: Set 교체 시 기존 소거 + 소멸자 소거
//   impl_buf_: 소멸자에서 SecWipe — 전체 이중 소거
//   복사/이동: = delete (PN 시퀀스 복제 방지)
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>
#include <atomic>

namespace ProtectedEngine {

    // 전방 선언 (HTS_Dynamic_Config.h include 제거)
    enum class HTS_Sys_Tier : uint8_t;

    class HTS_Rx_Matched_Filter {
    public:
        /// @brief 교차 상관 정합 필터 생성
        /// @param tier  시스템 체급 (향후 필터 크기 자동 조정 예약)
        /// @note  초기화 실패(OOM) 시 impl_valid_=false → 모든 함수 false
        explicit HTS_Rx_Matched_Filter(HTS_Sys_Tier tier) noexcept;

        /// @brief 소멸자 — Impl 소멸자 호출 후 impl_buf_ SecWipe
        ~HTS_Rx_Matched_Filter() noexcept;

        /// 기준 시퀀스 = 보안 자산 → 복사 경로 차단
        HTS_Rx_Matched_Filter(const HTS_Rx_Matched_Filter&) = delete;
        HTS_Rx_Matched_Filter& operator=(const HTS_Rx_Matched_Filter&) = delete;
        HTS_Rx_Matched_Filter(HTS_Rx_Matched_Filter&&) = delete;
        HTS_Rx_Matched_Filter& operator=(HTS_Rx_Matched_Filter&&) = delete;

        /// @brief 기준 시퀀스(대역 확산 코드) 설정
        /// @param seq_data  Q16 기준 시퀀스 배열 (nullptr 불가)
        /// @param size      요소 수 (0 불가)
        /// @return true=성공, false=nullptr/0/OOM
        /// @post   기존 시퀀스는 교체 전 보안 소거
        [[nodiscard]] bool Set_Reference_Sequence(
            const int32_t* seq_data, size_t size) noexcept;

        /// @brief Q16 교차 상관 연산
        /// @param rx_q16_data      수신 Q16 데이터 (nullptr 불가)
        /// @param rx_size          수신 데이터 요소 수 (>= ref_len 필수)
        /// @param out_correlation  출력 버퍼 (호출자 할당, 최소 rx_size - ref_len + 1)
        /// @return true=성공, false=파라미터 오류 또는 기준 시퀀스 미설정
        [[nodiscard]] bool Apply_Filter(
            const int32_t* __restrict rx_q16_data, size_t rx_size,
            int32_t* __restrict out_correlation) noexcept;

    private:
        // ── Pimpl In-Place Storage (zero-heap) ───────────────────
        // Impl = HTS_Sys_Config(≈32B) + int32_t[64](256B) + ref_len(4B) ≈ 296B
        // 정적 impl_buf_, 힙 0
        static constexpr size_t IMPL_BUF_SIZE = 320u;
        static constexpr size_t IMPL_BUF_ALIGN = 8u;

        struct Impl;  ///< 기준 시퀀스 + 체급 설정 은닉

        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        std::atomic<bool> impl_valid_{ false };

        Impl* get_impl() noexcept;
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine