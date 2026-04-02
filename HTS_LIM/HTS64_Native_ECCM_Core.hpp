// =============================================================================
/// @file   HTS64_Native_ECCM_Core.hpp
/// @brief  64칩 ECCM 수신 엔진 — Walsh-Hadamard 항재밍
/// @target STM32F407VGT6 (Cortex-M4F, 168 MHz) / PC 시뮬레이션
///
/// 이 모듈은 64칩 Walsh 확산 코드 기반 수신 엔진입니다.
/// 수신 I/Q 칩 배열에 대해 다음 파이프라인을 수행합니다.
///   ① PRNG 키 비트 스크램블 해제
///   ② 4단 적응형 클리퍼 (CW 감지 → clip 자동 조정 → 제로킬 / 소프트 축소 / 패스)
///   ③ Fast Walsh-Hadamard Transform (FWHT, 64점)
///   ④ 32비트 argmax → 에너지 임계 판정 (NF 기반 적응형)
///
/// @par 양산 수정 이력 — 30건
///  - BUG-16 @b [CRIT] unique_ptr Pimpl → placement new (zero-heap)
///  - BUG-17 @b [HIGH] decode_core 핫패스 32비트 argmax 최적화
///  - BUG-18 @b [MED]  is_barrage 자살 스위치 제거 → !is_clean 단일 조건
///  - BUG-19 @b [HIGH] CW 15dB 사각지대 해소\n
///           Q75/Q25 비율로 CW형 간섭을 감지하고,\n
///           clip을 Q75×4로 상향하여 소프트 클리핑 유발 고조파를 차단.\n
///           Barrage 경로는 clip=Q25×4 유지 → 기존 성능 퇴행 없음.
///  - BUG-22 @b [MED]  U-A: sizeof(Impl) ≈ 1040B (BUG-32 수치 수정)
///  - BUG-23 @b [MED]  U-B: sizeof ≤ 4096 static_assert SRAM 예산 검증
///  - BUG-24 @b [LOW]  D-2: SecWipe → SecureMemory (BUG-36 최종 통일)
///  - BUG-27 @b [HIGH] N % 4 == 0 static_assert 추가
///  - BUG-28 @b [HIGH] Calibrate() CAS 가드 (TOCTOU 방지)
///  - BUG-29 @b [MED]  소프트 클리핑 중복 static_cast 제거
///  - BUG-30 @b [LOW]  Calibrate() @pre 사전조건 문서화
///  - BUG-31 @b [LOW]  스레드 안전성 문서 보강
///  - BUG-32 @b [LOW]  sizeof(Impl) 수치 재검증 (2056B → 약 1040B)
///  - BUG-36 @b [CRIT] SecWipe → SecureMemory::secureWipe (D-2), impl_valid_ atomic
///  - BUG-41 @b [CRIT] D-2 소거 구현 정합 — HTS_Secure_Memory.cpp Force_Secure_Wipe
///           (GCC/Clang memory clobber + MSVC _ReadWriteBarrier + release fence)
///  - BUG-37 @b [HIGH] impl_buf_ alignas(64) — placement new 정렬 여유(SIMD/DMA/캐시라인)
///  - BUG-38 @b [MED]  p_metrics_ std::atomic — Set vs Decode 핫패스 레이스 제거
///
/// @warning sizeof(HTS64_Native_ECCM_Core) ≈ 2056B (impl_buf_[2048] 내장)
///          sizeof(Impl) ≈ 1040B (impl_buf_ 내부에 placement new)
///          전역/정적 변수로 배치 권장 — 스택 선언 시 Cortex-M4 여유 주의
///
/// @par 스레드 안전성 [BUG-31]
///  인스턴스당 1스레드 전용입니다.
///  PRNG CAS(next_prng)는 원자적이나, kH/kL 키 쌍 일관성은 보장하지 않습니다.
///  동일 인스턴스에 대해 Decode_BareMetal_IQ / Decode_Soft_IQ를
///  여러 스레드에서 동시 호출하면 키 쌍이 뒤섞여 복호 실패합니다.
///  STM32 단일 스레드 환경에서는 무해합니다.
///
/// @par 설계 제약 (양산 필수)
///  - @c float / @c double 사용 금지
///  - @c try-catch 사용 금지
///  - 힙 할당(@c new / @c delete) 금지 — placement new만 허용
///  - @c int64_t 는 소프트 클리핑 곱셈·임계값 비교 내부에서만 허용
// =============================================================================
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

#include <atomic>
#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    // HTS_RF_Metrics 전방 선언 (Set_RF_Metrics 인수용)
    struct HTS_RF_Metrics;

    // =============================================================================
    /// @brief 64칩 ECCM 수신 엔진
    // =============================================================================
    class HTS64_Native_ECCM_Core {
    public:

        static constexpr int CHIPS = 64;

        explicit HTS64_Native_ECCM_Core(uint32_t master_seed) noexcept;
        ~HTS64_Native_ECCM_Core() noexcept;

        /// @cond DELETED
        HTS64_Native_ECCM_Core(const HTS64_Native_ECCM_Core&) = delete;
        HTS64_Native_ECCM_Core& operator=(const HTS64_Native_ECCM_Core&) = delete;
        HTS64_Native_ECCM_Core(HTS64_Native_ECCM_Core&&) = delete;
        HTS64_Native_ECCM_Core& operator=(HTS64_Native_ECCM_Core&&) = delete;
        /// @endcond

        /// @brief 노이즈 캘리브레이션 — NF IIR 필터 초기화
        /// @pre noise_I, noise_Q: 각각 CHIPS(64)개 이상, int16_t 2바이트 정렬 필수 (Cortex-M 비정렬 UsageFault 방지)
        /// @note n_frames>1 은 OOB 방지를 위해 내부에서 1로 클램프 — 실질 단일 64칩 프레임만 사용
        /// @note [BUG-28] CAS 가드: 동시 호출 시 1스레드만 진입, 나머지 즉시 true 반환
        [[nodiscard]]
        bool Calibrate(const int16_t* noise_I, const int16_t* noise_Q,
            uint32_t n_frames = 72u) noexcept;

        [[nodiscard]] bool is_calibrated() const noexcept;
        void reset_calibration() noexcept;
        void Reseed(uint32_t epoch_seed) noexcept;

        /// @param rx_I, rx_Q  CHIPS(64) 샘플, 2바이트 정렬 필수
        [[nodiscard]]
        int8_t Decode_BareMetal_IQ(const int16_t* rx_I,
            const int16_t* rx_Q) noexcept;

        /// @param rx_I, rx_Q  CHIPS(64), 2바이트 정렬 / fwht_* 4바이트 정렬 필수
        [[nodiscard]]
        int8_t Decode_Soft_IQ(const int16_t* rx_I, const int16_t* rx_Q,
            int32_t* fwht_I, int32_t* fwht_Q) noexcept;

        /// @param rx_I, rx_Q, out_I, out_Q  각 CHIPS(64), 2바이트 정렬 필수
        void Descramble_IQ(const int16_t* rx_I, const int16_t* rx_Q,
            int16_t* out_I, int16_t* out_Q) noexcept;

        /// @brief RF 측정값 컨테이너 주입 (선택적)
        /// @param p  HTS_RF_Metrics 포인터 (nullptr 허용 — 미주입 시 측정값 기록 안 함)
        /// @note  Decode_BareMetal_IQ / Decode_Soft_IQ 호출 시
        ///        ajc_nf = (nf_q16 >> 16) 을 p->ajc_nf 에 release로 기록
        /// @note  수명: p가 가리키는 객체는 이 ECCM 인스턴스보다 오래 살아야 함
        void Set_RF_Metrics(HTS_RF_Metrics* p) noexcept;

    private:
        static constexpr size_t IMPL_BUF_SIZE = 2048u;
        /// Pimpl 버퍼 정렬 — Impl 요구 ≤ 이 값(컴파일 타임 assert, .cpp)
        static constexpr size_t IMPL_BUF_ALIGN = 64u;
        struct Impl;
        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        /// placement 생존 — const get_impl()에서 load 가능하도록 mutable
        mutable std::atomic<bool> impl_valid_{ false };

        /// 비소유 포인터 — nullptr이면 측정값 기록 안 함 (원자적 load/store)
        std::atomic<HTS_RF_Metrics*> p_metrics_{ nullptr };

        Impl* get_impl() noexcept;
        const Impl* get_impl() const noexcept;
    };

    // impl_buf_[2048] + bool + pointer + 패딩 ≈ 2056B
    // CCM 64KB의 3% 이내 — 스택 배치 시 여유 확인 필요
    static_assert(sizeof(HTS64_Native_ECCM_Core) <= 4096u,
        "HTS64_Native_ECCM_Core exceeds 4KB — impl_buf_ 또는 멤버 축소 필요");

} // namespace ProtectedEngine
