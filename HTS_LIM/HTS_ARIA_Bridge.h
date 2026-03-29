// =========================================================================
// HTS_ARIA_Bridge.h
// KCMVP 승인 알고리즘: ARIA 블록 암호 브릿지
// 규격: KS X 1213-1 (2009)
// 제공: KISA (한국인터넷진흥원)
// Target: STM32F407 (Cortex-M4)
//
// [KCMVP 인증 범위]
//  ARIA-128 (12라운드), ARIA-192 (14라운드), ARIA-256 (16라운드)
//  블록 크기: 128비트 (16바이트) 고정
//  운용 모드: CTR (Security_Session에서 CTR 모드로 스트림 암호화)
//
// [키 관리 요건]
//  - 키 소재 잔존 방지(Zeroization): 소멸자 + Reset()에서 보안 소거
//  - 복사/이동 금지: 키 복제 경로 원천 차단
//  - 사용 후 Reset() 호출 권장 (소멸자 의존 대신 명시적 소거)
//
// [양산 수정]
//  1. C26495: 모든 멤버 기본값 초기화
//  2. Secure_Zero: pragma O0 보호 추가
//  3. Process_Block: 실패 시 출력 버퍼 소거 (정보 누출 방지)
//  4. 매직 넘버 272 → 명명 상수 ROUND_KEY_BUF_SIZE
//  5. 문서화 보강 (KCMVP 인증 범위, 운용 모드)
// =========================================================================
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    class ARIA_Bridge {
    public:
        ARIA_Bridge() noexcept;
        ~ARIA_Bridge() noexcept;

        // 키 소재 복사 경로 원천 차단
        ARIA_Bridge(const ARIA_Bridge&) = delete;
        ARIA_Bridge& operator=(const ARIA_Bridge&) = delete;
        ARIA_Bridge(ARIA_Bridge&&) = delete;
        ARIA_Bridge& operator=(ARIA_Bridge&&) = delete;

        // =================================================================
        //  Initialize_Encryption — ARIA 암호화 키 스케줄
        //
        //  master_key: 마스터 키 (null 불가)
        //  key_bits:   128 / 192 / 256
        //  반환: true=성공, false=파라미터 오류 또는 키 스케줄 실패
        // =================================================================
        [[nodiscard]] bool Initialize_Encryption(
            const uint8_t* master_key, int key_bits) noexcept;

        // =================================================================
        //  Initialize_Decryption — ARIA 복호화 키 스케줄
        // =================================================================
        [[nodiscard]] bool Initialize_Decryption(
            const uint8_t* master_key, int key_bits) noexcept;

        // =================================================================
        //  Process_Block — ARIA 16바이트 블록 암/복호화
        //
        //  input_16bytes:  입력 블록 (16바이트, null 불가)
        //  output_16bytes: 출력 블록 (16바이트, null 불가, in-place 미지원)
        //  실패 시: 출력 버퍼 0으로 소거 (정보 누출 방지)
        // =================================================================
        [[nodiscard]] bool Process_Block(
            const uint8_t* input_16bytes,
            uint8_t* output_16bytes) noexcept;

        // =================================================================
        //  Reset — 키 소재 보안 소거 + 상태 초기화
        //  암복호화 완료 후 명시적 호출 권장
        // =================================================================
        void Reset() noexcept;

        // ── ARIA 라운드 키 버퍼 크기 (public 상수) ─────────────────
        //  ARIA-256 최대: 17 라운드 키 × 16 바이트 = 272 바이트
        static const size_t ROUND_KEY_BUF_SIZE = 272;

    private:
        // [C26495] 모든 멤버 기본값 초기화
        uint8_t round_keys[ROUND_KEY_BUF_SIZE] = {};  // 값 초기화 (0)
        int     num_rounds = 0;
        bool    is_initialized = false;
    };

} // namespace ProtectedEngine