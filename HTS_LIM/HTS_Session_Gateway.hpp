// =========================================================================
// HTS_Session_Gateway.hpp
// 최상위 보안 세션 컨트롤러
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [설계 목적]
//  물리 엔트로피 기반 마스터 시드 + 보안 세션 (Open / Close / 인증 / 긴급 정지)
//  ARM: Physical_Entropy_Engine + AntiDebug + AntiGlitch → 하드웨어 보안 체인
//  마스터 시드는 외부로 원시 복사되지 않음 — 도메인 분리 KDF(SHA-256)로만 파생.
//
//  @note 크로노스 기만(벽시각 비정상 점프) 시 Close_Session + 리플레이 윈도우 리셋 후
//        재동기 권장 — 공용 가드: HTS_TimeSpace_Guard.h (AntiReplayWindow64 등).
//
//  [사용법]
//   Session_Gateway::Open_Session();
//   if (Session_Gateway::Is_Session_Active()) { ... }
//   Session_Gateway::Derive_Session_Material(
//       Session_Gateway::DOMAIN_ANCHOR_HMAC, buf, sizeof(buf));
//   Session_Gateway::Close_Session();
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    /// @brief PUF 시드 최대 크기 (바이트)
    inline constexpr size_t MAX_SEED_SIZE = 64u;

    static_assert(MAX_SEED_SIZE >= 32u, "Seed must be at least 256 bits");
    static_assert(MAX_SEED_SIZE <= 256u, "Seed buffer unreasonably large");

    /// @brief 최상위 보안 세션 컨트롤러 (정적 유틸리티)
    class Session_Gateway {
    public:
        /// KDF 도메인 라벨 — 호출부·상대 단말과 문자열 동일해야 파생값 일치
        static constexpr const char* const DOMAIN_DUAL_FEC =
            "HTS.Session.DualTensor.FEC.v1";
        static constexpr const char* const DOMAIN_DUAL_PRNG =
            "HTS.Session.DualTensor.PRNG.v1";
        static constexpr const char* const DOMAIN_ANCHOR_HMAC =
            "HTS.Session.Anchor.HMAC.v1";

        /// @brief 물리 엔트로피 시드 채움 + 하드웨어 보안 락 가동
        static void Open_Session() noexcept;

        /// @brief 마스터 시드 소거(Clean) 후 g_Session_Active 해제 — 소거 전까지는 Busy 가드 하에 활성 플래그 유지
        static void Close_Session() noexcept;

        /// @brief 세션 유효성 (active ∧ valid ∧ seed_len>0). Session_Busy 락 획득 실패 시 false — 경합 시 fail-closed
        [[nodiscard]]
        static bool Is_Session_Active() noexcept;

        /// @brief 세션 마스터로부터 SHA-256 기반 파생(도메인 분리). 원시 시드는 외부로 노출하지 않음.
        /// @param domain_label  널 종료 ASCII, 내부에서 79바이트까지 사용
        /// @param out_buf       출력 (호출자 소거 권장)
        /// @param out_len       필요 바이트 수 (다중 블록 시 counter||seed||domain 연속 해시)
        /// @return 기록된 바이트 수, 0 = 비활성·락 실패·해시 실패
        [[nodiscard]]
        static size_t Derive_Session_Material(
            const char* domain_label,
            uint8_t* out_buf,
            size_t out_len) noexcept;

        /// @brief 물리적 탬퍼링 감지 시 긴급 정지 — 반환 안 함
        static void Trigger_Hardware_Trap(const char* reason) noexcept;

        // 정적 전용 클래스 — 인스턴스화 차단
        Session_Gateway() = delete;
        ~Session_Gateway() = delete;
        Session_Gateway(const Session_Gateway&) = delete;
        Session_Gateway& operator=(const Session_Gateway&) = delete;
        Session_Gateway(Session_Gateway&&) = delete;
        Session_Gateway& operator=(Session_Gateway&&) = delete;
    };

} // namespace ProtectedEngine
