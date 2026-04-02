// =========================================================================
// HTS_Secure_Boot_Verify.h
// 보안 부팅 검증자 — Flash 펌웨어 무결성 검사
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [목적]
//  전원 ON → main() 진입 전 구간에서 Flash 전체의 무결성을 검증하는
//  첫 번째 방어선. 펌웨어 변조 시 안전 모드로 전환하여
//  변조 코드의 무선 송출을 차단합니다.
//
//  [사용법]
//   1. startup_stm32.s에서 main() 호출 전:
//      bl HTS_Secure_Boot_Check    (C 링크 함수)
//   2. main()에서:
//      if (!HTS_Secure_Boot_Verify::Is_Verified()) { enter_safe_mode(); }
//   3. 또는 C++ API:
//      HTS_Secure_Boot_Verify verifier;
//      auto result = verifier.Verify_Firmware();
//
//  [안전 모드]
//   최소 기능: UART 콘솔 + OTA 수신 + LED 경고 점멸
//   무선 TX 차단: 변조 펌웨어가 무선 공격 수행 방지
//
//  [KCMVP/NIS 인증]
//   보안 부팅 구현 = 인증 필수 요건
//   Flash 해시 대조: HTS_ConstantTimeUtil::compare (K-4, cpp)
//
//  @warning sizeof ≈ 520B — 전역/정적 배치 권장
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>

// ── C 링크 함수 (startup_stm32.s에서 호출 가능) ─────────────────────
#ifdef __cplusplus
extern "C" {
#endif

    /// @brief 부팅 시 펌웨어 무결성 검사 (startup에서 호출)
    /// @return 0 = 검증 성공, 1 = 실패 → 안전 모드 진입
    /// @note  C 링크: 어셈블리에서 `bl HTS_Secure_Boot_Check` 호출 가능
    int32_t HTS_Secure_Boot_Check(void);

    /// @brief 검증 결과 조회 (main에서 호출)
    /// @return 0 = 미검증/실패, 1 = 검증 성공
    int32_t HTS_Secure_Boot_Is_Verified(void);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

namespace ProtectedEngine {

    /// @brief 부팅 검증 결과 코드
    enum class BootVerifyResult : uint8_t {
        OK = 0x00u,   ///< 검증 성공
        HASH_MISMATCH = 0x01u,   ///< 해시 불일치 (변조 감지)
        OTP_READ_FAIL = 0x02u,   ///< OTP 기대 해시 읽기 실패
        FLASH_READ_FAIL = 0x03u,   ///< Flash 읽기 오류
        NOT_PROVISIONED = 0x04u,   ///< OTP에 기대 해시 미기록
        RETRY_FAIL = 0x05u,   ///< 재시도 후에도 실패 (안전 모드)
    };

    class HTS_Secure_Boot_Verify {
    public:
        /// @brief Flash 검증 영역 크기 (512KB)
        static constexpr uint32_t FIRMWARE_SIZE = 512u * 1024u;

        /// @brief LSH-256 해시 크기 (32바이트)
        static constexpr size_t HASH_SIZE = 32u;

        /// @brief 생성자
        HTS_Secure_Boot_Verify() noexcept;

        /// @brief 소멸자 — 해시 버퍼 보안 소거
        ~HTS_Secure_Boot_Verify() noexcept;

        /// 복사/이동 차단
        HTS_Secure_Boot_Verify(const HTS_Secure_Boot_Verify&) = delete;
        HTS_Secure_Boot_Verify& operator=(const HTS_Secure_Boot_Verify&) = delete;
        HTS_Secure_Boot_Verify(HTS_Secure_Boot_Verify&&) = delete;
        HTS_Secure_Boot_Verify& operator=(HTS_Secure_Boot_Verify&&) = delete;

        /// @brief 펌웨어 무결성 검증 실행
        /// @return BootVerifyResult 결과 코드
        /// @note  1회 실패 시 자동 재시도 (글리치 방어)
        [[nodiscard]]
        BootVerifyResult Verify_Firmware() noexcept;

        /// @brief 검증 성공 여부 조회
        [[nodiscard]] bool Is_Verified() const noexcept;

        /// @brief 안전 모드 여부 조회
        [[nodiscard]] bool Is_Safe_Mode() const noexcept;

        /// @brief OTP에 기대 해시 기록 (공장 프로비저닝 시 1회)
        /// @param hash  LSH-256 해시 (32바이트)
        /// @param len   해시 길이 (HASH_SIZE여야 함)
        /// @return true = 기록 성공
        [[nodiscard]]
        bool Provision_Expected_Hash(
            const uint8_t* hash, size_t len) noexcept;

    private:
        static constexpr size_t IMPL_BUF_SIZE = 512u;
        static constexpr size_t IMPL_BUF_ALIGN = 8u;

        struct Impl;

        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        bool impl_valid_ = false;

        Impl* get_impl() noexcept;
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine

#endif // __cplusplus