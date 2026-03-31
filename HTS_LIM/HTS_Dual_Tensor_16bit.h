// =========================================================================
// HTS_Dual_Tensor_16bit.h
// B-CDMA 듀얼 레인 텐서 파이프라인 — 공개 인터페이스
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [파이프라인 단계]
//   ① 16-bit 센서 데이터 → 32-bit 패킹
//   ② Security_Pipeline 보안 변환 (ARIA/LEA + VDF + 위상 난독화)
//   ③ 3D Soft FEC 인코딩 + 블록 인터리빙
//   ④ Gaussian 펄스 셰이핑 (GMSK 기저대역 성형)
//   ⑤ Xoroshiro128++ 듀얼 레인 암호 패킹
//   ⑥ DMA 전송 버퍼 출력
//
//  [사용법]
//   Dual_Tensor_Pipeline pipe(0.3, 31);  // bt=0.3, taps=31
//   if (pipe.Execute_Dual_Processing(sensor, len, nonce, abort)) {
//       const uint32_t* data = pipe.Get_Dual_Lane_Data();
//       size_t size = pipe.Get_Dual_Lane_Size();
//       DMA_Start(data, size);
//   }
//
//  [메모리 요구량]
//   sizeof(Dual_Tensor_Pipeline) ≈ IMPL_BUF_SIZE(20KB) + metadata(8B)
//   Impl 내부: Gaussian_Pulse_Shaper, Security_Pipeline 등 서브모듈
//   dual_lane_buffer: uint32_t[4096] = 16KB (정적, 힙 0회)
//   ⚠ 반드시 전역/정적 변수로 배치 (스택 배치 시 20KB 스택 소모)
//
//  [보안 설계]
//   중간 암호 파생 데이터: RAII_Secure_Wiper로 모든 경로 소거 보장
//   impl_buf_: 소멸자에서 SecWipe — Impl 전체 이중 소거
//   복사/이동: = delete (키 소재/암호 상태 복제 경로 원천 차단)
//   Get_Master_Seed: Raw API (힙 0회, ARM Zero-Heap 준수)
//
//  [양산 수정 이력 — 21건]
//   BUG-01~14 (이전 세션: RAII UAF, clamp, RotL64, Pimpl placement new)
//   BUG-15 [CRIT] Impl try-catch 제거 (-fno-exceptions)
//   BUG-16 [CRIT] Execute try-catch 래퍼 제거
//   BUG-17 [CRIT] dual_lane_buffer vector → 정적 배열[4096]
//   BUG-18 [HIGH] seq_cst → release (배리어 정책 통일)
//   BUG-19 [HIGH] Get_Master_Seed → Get_Master_Seed_Raw
//   BUG-20 [PENDING] double/vector 외부 API 의존 (3D_FEC 검수 후 전환)
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>
#include <atomic>

namespace ProtectedEngine {

    class Dual_Tensor_Pipeline {
    public:
        /// @brief 듀얼 레인 텐서 파이프라인 생성
        /// @param bt_product  대역폭 × 심볼 주기 (GMSK 표준: 0.3)
        /// @param filter_taps 가우시안 필터 탭 수 (홀수, 예: 31)
        /// @note  [PENDING] bt_product double → Q16 고정소수점 전환 예정
        ///        (Gaussian_Pulse_Shaper API 변경 후)
        Dual_Tensor_Pipeline(
            double bt_product, size_t filter_taps) noexcept;

        /// @brief 소멸자 — Impl 소멸자 호출 후 impl_buf_ 전체 SecWipe
        ~Dual_Tensor_Pipeline() noexcept;

        /// 키 소재/암호 상태 복사 경로 원천 차단
        Dual_Tensor_Pipeline(const Dual_Tensor_Pipeline&) = delete;
        Dual_Tensor_Pipeline& operator=(const Dual_Tensor_Pipeline&) = delete;
        Dual_Tensor_Pipeline(Dual_Tensor_Pipeline&&) = delete;
        Dual_Tensor_Pipeline& operator=(Dual_Tensor_Pipeline&&) = delete;

        /// @brief 듀얼 레인 텐서 처리 (매 프레임 호출)
        /// @param raw_sensor_data  16비트 센서 배열 (nullptr 불가)
        /// @param data_len         요소 수 (0 불가)
        /// @param packet_nonce     프레임별 고유 논스 (CTR 모드 IV 혼합)
        /// @param abort_signal     외부 중단 시그널 (atomic, ISR 안전)
        /// @return true=성공, false=실패 또는 중단
        /// @post   모든 중간 보안 데이터는 RAII로 소거 보장
        [[nodiscard]] bool Execute_Dual_Processing(
            const uint16_t* raw_sensor_data, size_t data_len,
            uint32_t packet_nonce,
            std::atomic<bool>& abort_signal) noexcept;

        /// @brief Auto_Scaler가 결정한 최적 텐서 개수
        /// @return 텐서 수 (impl_valid_=false 시 0)
        [[nodiscard]]
        size_t Get_Active_Tensor_Count() const noexcept;

        // ── [BUG-17] 듀얼 레인 버퍼 접근 (Raw API — ARM/PC 공용) ────

        /// @brief 생성된 DMA 전송 버퍼 (raw 포인터)
        /// @return 듀얼 레인 배열 포인터 (impl_valid_=false 시 nullptr)
        [[nodiscard]]
        const uint32_t* Get_Dual_Lane_Data() const noexcept;

        /// @brief DMA 전송 유효 길이
        /// @return 듀얼 레인 원소 수 (impl_valid_=false 시 0)
        [[nodiscard]]
        size_t Get_Dual_Lane_Size() const noexcept;

    private:
        // ── [BUG-14/17/20] Pimpl In-Place Storage ──────────────────────
        //  [BUG-20+FIX] vector/double 완전 제거 → 정적 int8_t 워킹 버퍼
        //   ARM: work_A(17.2KB) + work_B(17.2KB) + temp_sec(6KB)
        //        + dual_lane(16KB) + sub-modules(~3KB) ≈ 60KB
        //        INTLV_DIM=26 → dim³=17,576 ≥ MAX_RAW_BITS(16,384)
        //   PC:  work_A(256KB) + fec_bits(256KB) + tx_signal(16KB) + temp_sec(12KB)
        //        + dual_lane(16KB) + sub-modules(~3KB) ≈ 559KB
        //   [BUG-FIX] union→독립배열 분리로 +16KB 증가 (fec_bits/tx_signal 수명 격리)
#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
        static constexpr size_t IMPL_BUF_SIZE = 65536u;   // 64KB
#else
        static constexpr size_t IMPL_BUF_SIZE = 589824u;  // 576KB (+16KB: union→독립배열)
#endif
        static constexpr size_t IMPL_BUF_ALIGN = 8u;

        struct Impl;  ///< 구현 세부사항 완전 은닉 (ABI 안정성 보장)

        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        bool impl_valid_ = false;  ///< placement new 성공 여부

        /// @brief Pimpl 내부 접근자 (impl_valid_ 검증 포함)
        Impl* get_impl() noexcept;
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine