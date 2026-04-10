// =========================================================================
// HTS_Key_Provisioning.h
// 공장 출하 키 프로비저닝 엔진 — 공개 인터페이스
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [목적]
//  공장 양산 라인에서 장비당 고유 마스터 키(128비트)를 OTP 영역에
//  안전하게 주입하고, 주입 완료 후 디버그 포트를 영구 잠금합니다.
//  키 전송 중 도청 방지를 위해 AES-KW(Key Wrap, RFC 3394) 사용.
//
//  [Unprovisioned ↔ Sealed FSM]
//  공정·주입·SWD 허용 단계와 Lock_Debug_Port / RDP 봉인 이후 단계를 하드웨어 옵션·
//  부트 플래그로 명시 분리하고, Sealed 이후에만 런타임 JTAG/SWD 핫플러깅 자폭 정책과
//  결합할 것(봉인 전 공정과 모순 방지).
//
//  [사용법]
//   1. 생성: HTS_Key_Provisioning()
//   2. Is_Provisioned(): OTP에 키가 이미 주입되었는지 확인
//   3. Inject_Key(wrapped, 32B): AES-KW 언래핑 → OTP 기록 → 검증
//   4. Lock_Debug_Port(): JTAG/SWD 영구 잠금 (RDP Level 2)
//   5. Destroy_Key(): 키 무효화 (Forward Secrecy 종료)
//
//  [보안 설계]
//   impl_buf_: 소멸자에서 Key_Prov_Secure_Wipe 3중 방어 소거
//   키 버퍼: 사용 즉시 소거 (임시 평문 노출 최소화)
//   OTP Read-Back 검증: HTS_ConstantTimeUtil::compare (K-1 / C-1)
//   복사/이동: = delete (키 소재 복제 경로 원천 차단)
//
//  [메모리 요구량]
//   sizeof(HTS_Key_Provisioning) ≈ IMPL_BUF_SIZE(256B) + bool(1B)
//   Impl 내부: key_buf(16B) + otp_shadow(16B) + state(4B) ≈ 48B
//
//  @warning sizeof ≈ 260B — 전역/정적 배치 권장
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>
#include <atomic>

namespace ProtectedEngine {

    /// @brief 키 프로비저닝 결과 코드
    enum class KeyProvResult : uint8_t {
        OK = 0x00u,   ///< 성공
        ALREADY_DONE = 0x01u,   ///< 이미 프로비저닝 완료
        UNWRAP_FAIL = 0x02u,   ///< AES-KW 언래핑 실패 (래핑키 불일치)
        OTP_WRITE_FAIL = 0x03u,   ///< OTP 기록 실패 (타임아웃/하드웨어)
        VERIFY_FAIL = 0x04u,   ///< OTP Read-Back 검증 실패
        NULL_INPUT = 0x05u,   ///< 입력 포인터 nullptr
        INVALID_LEN = 0x06u,   ///< 입력 길이 불일치
        LOCK_FAIL = 0x07u,   ///< 디버그 포트 잠금 실패
        POWER_UNSTABLE = 0x08u,   ///< PVD/BOR 등 전압 불안정 — OTP·옵션바이트 쓰기 거부
    };

    class HTS_Key_Provisioning {
    public:
        static constexpr uint32_t SECURE_TRUE = 0x5A5A5A5Au;
        static constexpr uint32_t SECURE_FALSE = 0xA5A5A5A5u;

        /// @brief 마스터 키 크기 (256비트 = 32바이트, ARIA-256/AES-256)
        static constexpr size_t MASTER_KEY_SIZE = 32u;

        /// @brief AES-KW 래핑된 키 크기 (256비트 + 8바이트 IV = 40바이트)
        static constexpr size_t WRAPPED_KEY_SIZE = 40u;

        /// @brief 생성자 — Impl 배치, 상태 초기화
        HTS_Key_Provisioning() noexcept;

        /// @brief 소멸자 — p->~Impl() + Key_Prov_Secure_Wipe(impl_buf_)
        ~HTS_Key_Provisioning() noexcept;

        /// 키 소재 복사 경로 원천 차단
        HTS_Key_Provisioning(const HTS_Key_Provisioning&) = delete;
        HTS_Key_Provisioning& operator=(const HTS_Key_Provisioning&) = delete;
        HTS_Key_Provisioning(HTS_Key_Provisioning&&) = delete;
        HTS_Key_Provisioning& operator=(HTS_Key_Provisioning&&) = delete;

        // ─── 프로비저닝 API ─────────────────────────────────

        /// @brief OTP에 마스터 키가 이미 주입되었는지 확인
        /// @return 이미 프로비저닝 완료면 SECURE_TRUE
        [[nodiscard]] uint32_t Is_Provisioned() const noexcept;

        /// @brief 래핑된 마스터 키를 언래핑 → OTP에 기록 → 검증
        /// @param wrapped_key  AES-KW(RFC 3394) 래핑된 키 (WRAPPED_KEY_SIZE=40바이트)
        /// @param wrapped_len  래핑된 키 길이 (WRAPPED_KEY_SIZE여야 함)
        /// @param factory_kek  공장 라인 KEK (Key Encryption Key, 32바이트)
        /// @param kek_len      KEK 길이 (MASTER_KEY_SIZE=32여야 함)
        /// @return KeyProvResult 결과 코드
        /// @post 성공 시 OTP에 키 기록 + 내부 평문 버퍼 즉시 소거
        [[nodiscard]]
        KeyProvResult Inject_Key(
            const uint8_t* wrapped_key, size_t wrapped_len,
            const uint8_t* factory_kek, size_t kek_len) noexcept;

        /// @brief OTP에서 마스터 키를 읽어 외부 버퍼에 복사
        /// @param out_buf  출력 버퍼 (32바이트 (MASTER_KEY_SIZE) 이상)
        /// @param out_len  출력 버퍼 크기
        /// @return 성공 시 SECURE_TRUE
        /// @note 양산 후에는 호출 차단 (Lock_Debug_Port 이후 OTP 읽기만 허용)
        [[nodiscard]]
        uint32_t Read_Master_Key(uint8_t* out_buf, size_t out_len) const noexcept;

        /// @brief JTAG/SWD 디버그 포트 영구 잠금 (RDP Level 2)
        /// @return KeyProvResult 결과 코드
        /// @warning 이 함수 호출 후 JTAG 접속 영구 불가 — 되돌릴 수 없음
        [[nodiscard]]
        KeyProvResult Lock_Debug_Port() noexcept;

        /// @brief 마스터 키 물리적 파기 (장비 폐기/변조 감지 시)
        /// @note OTP 키 영역에 0x00 덮어쓰기 → 비트 물리 소실 (비가역)
        /// @post 이후 Read_Master_Key 호출 시 0x00 반환 → 복호 불가
        /// @note 전압 불안정이면 쓰기 생략. OTP 소각 실패 시 RAM 플래그는 갱신하지 않음(물리·논리 일치).
        void Destroy_Key() noexcept;

        /// @brief 안전 종료 — 내부 상태 소거
        void Shutdown() noexcept;

    private:
        // ── Pimpl In-Place Storage (zero-heap) ──
        static constexpr size_t IMPL_BUF_SIZE = 256u;
        static constexpr size_t IMPL_BUF_ALIGN = 8u;

        struct Impl;

        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        std::atomic<bool> impl_valid_{ false };

        Impl* get_impl() noexcept;
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine