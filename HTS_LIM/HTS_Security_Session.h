// =========================================================================
// HTS_Security_Session.h
// KCMVP 암호/인증 통합 오케스트레이터 — 공개 인터페이스
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [구조] Encrypt-then-MAC (EtM)
//   암호화: ARIA-256-CTR / LEA-256-CTR (KS X 1213-1)
//   MAC:    HMAC-SHA256 (KS X ISO/IEC 9797-2)
//
//  [사용법 — 스트리밍]
//   HTS_Security_Session sess;
//   sess.Initialize(LEA_256_CTR, HMAC_SHA256, enc_key, mac_key, iv);
//   sess.Protect_Begin();
//   sess.Protect_Chunk(pt_chunk, len, ct_out);   // 반복
//   sess.Protect_End(mac_tag);
//
//  [사용법 — 단일 호출]
//   sess.Protect_Payload(pt, len, ct_out, mac_out);
//   sess.Unprotect_Payload(ct, len, mac_tag, pt_out);
//
//  [보안 설계]
//   Pimpl(In-Place): 세션 키, 카운터, HMAC 컨텍스트 전부 헤더 미노출
//     [BUG-18] unique_ptr → 고정 버퍼 placement new (힙 할당 0)
//     헤더에는 불투명 바이트 배열만 노출 → 외부 업체 역공학 차단
//   소멸자: 세션 키 + HMAC o_key_pad + inner_ctx 전부 보안 소거
//   복사/이동: = delete (세션 상태 복제 원천 차단)
//
//  [양산 수정 이력 — 19건]
//   세션5 01~10: HMAC 소거, Pimpl, memset DCE, LEA 절삭, pragma,
//     Doxygen, CTR partial, O(1) counter, header, nothrow
//   세션8 11~19: keystream 소거, partial_len 주석, ARIA_Bridge 주석,
//     static_assert, placement new(힙0), 더티 메모리 0클린,
//     ~15u 제로 확장, 키 확장 캐싱, MAC 실패→세션 종료
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    enum class CipherAlgorithm { ARIA_256_CTR, LEA_256_CTR, AES_256_CTR };
    enum class MacAlgorithm { HMAC_SHA256 };

    class HTS_Security_Session {
    public:
        /// @brief 세션 생성 (비활성 상태)
        HTS_Security_Session() noexcept;

        /// @brief 소멸자 — 세션 키 + HMAC 컨텍스트 전체 보안 소거
        ~HTS_Security_Session() noexcept;

        HTS_Security_Session(const HTS_Security_Session&) = delete;
        HTS_Security_Session& operator=(const HTS_Security_Session&) = delete;
        HTS_Security_Session(HTS_Security_Session&&) = delete;
        HTS_Security_Session& operator=(HTS_Security_Session&&) = delete;

        /// @brief 세션 초기화 (키/IV 주입)
        [[nodiscard]] bool Initialize(
            CipherAlgorithm c_alg,
            MacAlgorithm    m_alg,
            const uint8_t* enc_key,
            const uint8_t* mac_key,
            const uint8_t* iv_16bytes) noexcept;

        // ── 송신 스트리밍 API ─────────────────────────────────────────
        [[nodiscard]] bool Protect_Begin() noexcept;
        [[nodiscard]] bool Protect_Chunk(
            const uint8_t* plaintext_chunk,
            size_t chunk_len,
            uint8_t* ciphertext_out) noexcept;
        [[nodiscard]] bool Protect_End(uint8_t* mac_tag_out) noexcept;

        // ── 수신 스트리밍 API ─────────────────────────────────────────
        [[nodiscard]] bool Unprotect_Begin() noexcept;
        [[nodiscard]] bool Unprotect_Feed(
            const uint8_t* ciphertext_chunk,
            size_t chunk_len) noexcept;
        [[nodiscard]] bool Unprotect_Verify(
            const uint8_t* received_mac_tag) noexcept;
        [[nodiscard]] bool Decrypt_Chunk(
            const uint8_t* ciphertext_chunk,
            size_t chunk_len,
            uint8_t* plaintext_out) noexcept;

        // ── 단일 호출 API (하위 호환) ─────────────────────────────────
        [[nodiscard]] bool Protect_Payload(
            const uint8_t* plaintext, size_t length,
            uint8_t* ciphertext_out, uint8_t* mac_tag_out) noexcept;
        [[nodiscard]] bool Unprotect_Payload(
            const uint8_t* ciphertext, size_t length,
            const uint8_t* received_mac_tag,
            uint8_t* plaintext_out) noexcept;

        void Terminate_Session() noexcept;

        /// @brief 세션 활성 여부
        [[nodiscard]] bool Is_Active() const noexcept;

    private:
        // [BUG-18] Pimpl In-Place: 힙 할당 0, 외부 불투명
        //
        // unique_ptr<Impl> → alignas(4) uint8_t[] 고정 버퍼
        // cpp에서 placement new로 Impl 구축 → 힙 접근 0회
        //
        // IMPL_BUF_SIZE: Impl 구조체 크기 상한
        //   기존 멤버: ~800B
        //   [BUG-21] + ARIA_Bridge(~1KB) + LEA_KEY(~800B) + bool
        //   → 안전 마진 포함 4096B
        //
        // static_assert(sizeof(Impl) <= IMPL_BUF_SIZE)는 cpp에서 검증
        // 빌드 시 초과하면 에러 → 이 값을 올리거나 Impl 최적화
        static constexpr size_t IMPL_BUF_SIZE = 4096u;
        struct Impl;  // 전방 선언 (cpp에서만 정의)
        alignas(8) uint8_t impl_buf_[IMPL_BUF_SIZE];
        bool impl_valid_ = false;  // placement new 성공 여부

        Impl* get_impl() noexcept;
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine