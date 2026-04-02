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
//  PUF 시드 기반 보안 세션 관리 (Open / Close / 인증 / 긴급 정지)
//  ARM: PUF + AntiDebug + AntiGlitch → 하드웨어 보안 체인
//
//  [사용법]
//   Session_Gateway::Open_Session();
//   if (Session_Gateway::Is_Session_Active()) { ... }
//   uint8_t buf[MAX_SEED_SIZE];
//   size_t n = Session_Gateway::Get_Master_Seed_Raw(buf, sizeof(buf));
//   Session_Gateway::Close_Session();
//
//  [양산 수정 이력 — 32건]
//   BUG-30 [HIGH] #define HTS_PLATFORM_ARM 하드코딩 → 컴파일러 감지 매크로
//   BUG-31 [CRIT] ⑭ PC 코드 물리삭제: mutex/vector/string/socket/try-catch
//   BUG-32 [LOW]  주석 정합: "/ PC / Server" 제거
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
        /// @brief PUF 시드 추출 + 하드웨어 보안 락 가동
        static void Open_Session() noexcept;

        /// @brief 마스터 키 완전 파기 + 세션 종료
        static void Close_Session() noexcept;

        /// @brief 세션 유효성 검사 (복사 없음 — 권장 API)
        [[nodiscard]]
        static bool Is_Session_Active() noexcept;

        /// @brief 마스터 시드 취득 — Zero-Heap
        /// @param out_buf   출력 버퍼 (호출자 제공)
        /// @param buf_size  버퍼 크기 (MAX_SEED_SIZE 이상 권장)
        /// @return 복사된 시드 바이트 수 (0 = 세션 미활성)
        /// @note  사용 후 SecureMemory::secureWipe 필수
        [[nodiscard]]
        static size_t Get_Master_Seed_Raw(
            uint8_t* out_buf, size_t buf_size) noexcept;

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
