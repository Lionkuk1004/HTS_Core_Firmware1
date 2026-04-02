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

// =========================================================================
// HTS_AES_Bridge.h
// FIPS 197 승인 알고리즘: AES 블록 암호 브릿지
// 규격: FIPS 197 (Advanced Encryption Standard)
// Target: STM32F407 (Cortex-M4) / Cortex-A55 / PC
//
// [FIPS 140-3 인증 범위]
//  AES-128 (10라운드), AES-192 (12라운드), AES-256 (14라운드)
//  블록 크기: 128비트 (16바이트) 고정
//  운용 모드: ECB (단일 블록), CTR은 Security_Session에서 조립
//
// [설계 패턴]
//  ARIA_Bridge와 동일한 인터페이스 (교체 투명성)
//  - Initialize_Encryption / Initialize_Decryption
//  - Process_Block (16바이트 단위)
//  - Reset (키 소재 보안 소거)
//
// [키 관리 요건]
//  - 키 소재 잔존 방지(Zeroization): 소멸자 + Reset()에서 보안 소거
//  - 복사/이동 금지: 키 복제 경로 원천 차단
//
// [제약] try-catch 0, float/double 0, heap 0
// =========================================================================
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

    class AES_Bridge {
    public:
        AES_Bridge() noexcept;
        ~AES_Bridge() noexcept;

        AES_Bridge(const AES_Bridge&) = delete;
        AES_Bridge& operator=(const AES_Bridge&) = delete;
        AES_Bridge(AES_Bridge&&) = delete;
        AES_Bridge& operator=(AES_Bridge&&) = delete;

        /// @brief AES 암호화 키 스케줄
        /// @param master_key  마스터 키 (null 불가)
        /// @param key_bits    128 / 192 / 256
        [[nodiscard]] bool Initialize_Encryption(
            const uint8_t* master_key, int key_bits) noexcept;

        /// @brief AES 복호화 키 스케줄
        [[nodiscard]] bool Initialize_Decryption(
            const uint8_t* master_key, int key_bits) noexcept;

        /// @brief AES 16바이트 블록 암/복호화
        /// @note  실패 시 출력 버퍼 0으로 소거 (정보 누출 방지)
        [[nodiscard]] bool Process_Block(
            const uint8_t* input_16bytes,
            uint8_t* output_16bytes) noexcept;

        /// @brief 키 소재 보안 소거 + 상태 초기화
        void Reset() noexcept;

        /// AES-256 최대: 15 라운드 키 × 16 = 240 바이트
        static constexpr size_t ROUND_KEY_BUF_SIZE = 240u;

    private:
        uint8_t round_keys[ROUND_KEY_BUF_SIZE] = {};
        int     num_rounds = 0;
        bool    is_initialized = false;
        bool    is_encrypt = false;  // true=암호화, false=복호화
    };

} // namespace ProtectedEngine