// =========================================================================
// HTS_HMAC_Bridge.hpp
// KCMVP 승인 알고리즘 : HMAC-SHA256 (KS X ISO/IEC 9797-2)
// Target: STM32F407 (Cortex-M4)
//
// [Cortex-M4 초경량 최적화]
//  - inner_ctx(256B) 내부에 SHA256_INFO + 64바이트 스마트 큐 은닉
//  - KISA SHA256 부분 블록 누적 버그 우회 (64바이트 정렬 주입)
//  - 스택 사용량 약 320바이트
//
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

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4324)
#endif
    // =====================================================================
    //  HMAC_Context — HMAC-SHA256 스트리밍 컨텍스트
    //
    //  inner_ctx[256]: SHA256_INFO + 64바이트 스마트 큐 버퍼
    //  o_key_pad[64]:  외부 패딩 키 (Final 단계에서 사용)
    //  is_initialized: Init 성공 여부
    //
    //  alignas(4): ARM Cortex-M4 4바이트 정렬 (비정렬 접근 시 HardFault)
    // =====================================================================
    struct alignas(4) HMAC_Context {
        // [C26495 수정] 값 초기화 (= {})
        uint8_t  inner_ctx[256] = {};
        uint8_t  o_key_pad[64] = {};
        bool     is_initialized = false;

        HMAC_Context() noexcept
            : is_initialized(false) {
            // inner_ctx, o_key_pad: = {} 로 이미 0 초기화됨
        }

        // 키 소재 복사 경로 원천 차단
        HMAC_Context(const HMAC_Context&) = delete;
        HMAC_Context& operator=(const HMAC_Context&) = delete;
        HMAC_Context(HMAC_Context&&) = delete;
        HMAC_Context& operator=(HMAC_Context&&) = delete;
    };
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

    class HMAC_Bridge {
    public:
        static constexpr uint32_t SECURE_TRUE = 0x5A5A5A5Au;
        static constexpr uint32_t SECURE_FALSE = 0xA5A5A5A5u;

        /// @note 성공/실패 모두 비영 — if(Generate)/if(Verify) 불가.
        ///       `r == SECURE_TRUE` 로만 성공 판정 (호출 계약)

        HMAC_Bridge() = delete;
        HMAC_Bridge(const HMAC_Bridge&) = delete;
        HMAC_Bridge& operator=(const HMAC_Bridge&) = delete;

        // ── 스트리밍 API (KISA 버그 우회 스마트 큐 내장) ──────────────
        //  Init → Update(반복) → Final 또는 Verify_Final

        // 키 설정 + 내부 해시 시작 (i_key_pad 주입)
        [[nodiscard]] static uint32_t Init(
            HMAC_Context& ctx,
            const uint8_t* key,
            size_t         key_len) noexcept;

        // 메시지 청크 누적 (64바이트 정렬 자동 처리)
        [[nodiscard]] static uint32_t Update(
            HMAC_Context& ctx,
            const uint8_t* data,
            size_t         data_len) noexcept;

        // HMAC 생성 + 컨텍스트 보안 소거
        [[nodiscard]] static uint32_t Final(
            HMAC_Context& ctx,
            uint8_t* output_hmac_32bytes) noexcept;

        // HMAC 검증 (상수시간 비교) + 컨텍스트 보안 소거
        [[nodiscard]] static uint32_t Verify_Final(
            HMAC_Context& ctx,
            const uint8_t* received_hmac_32bytes) noexcept;

        // ── 단일 호출 API (하위 호환) ─────────────────────────────────
        //  내부적으로 Init → Update → Final/Verify_Final 순차 호출

        [[nodiscard]] static uint32_t Generate(
            const uint8_t* message, size_t msg_len,
            const uint8_t* key, size_t key_len,
            uint8_t* output_hmac_32bytes) noexcept;

        [[nodiscard]] static uint32_t Verify(
            const uint8_t* message, size_t msg_len,
            const uint8_t* key, size_t key_len,
            const uint8_t* received_hmac_32bytes) noexcept;
    };

} // namespace ProtectedEngine


