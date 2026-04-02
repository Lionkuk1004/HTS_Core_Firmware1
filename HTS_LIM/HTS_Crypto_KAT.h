// =========================================================================
// HTS_Crypto_KAT.h
// KCMVP/FIPS 140-3 암호 알고리즘 KAT (Known Answer Test)
// Target: STM32F407 (Cortex-M4) / Cortex-A55 / PC
//
// [설계 목적]
//  전원 투입 시 POST_Manager에서 호출하는 암호 KAT 진입점.
//  모든 함수는 bool 반환 (true=통과, false=실패→모듈 차단).
//  iostream 0, heap 0, try-catch 0, float/double 0 — ARM 베어메탈 안전.
//
// [빌드 프리셋]
//  HTS_CRYPTO_KCMVP  : ARIA + LEA + LSH + HMAC KAT
//  HTS_CRYPTO_FIPS   : AES + SHA-256 KAT (향후 AES 구현 시)
//  HTS_CRYPTO_DUAL   : 전부
//
// [KCMVP 검증기준 v3.0]
//  - 7.4.1 전원 투입 자체시험: 승인된 암호 알고리즘 KAT 필수
//  - 기지 답 벡터로 암호화→복호화 1회 실행, 불일치 시 암호 기능 전면 차단
//
// [FIPS 140-3 / ISO 19790]
//  - AS09.11 Power-On Self-Test: 승인 알고리즘 KAT 필수
//  - AS09.12 KAT: 기지 입력 → 기지 출력 비교
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

namespace ProtectedEngine {

    class Crypto_KAT {
    public:
        // ── KCMVP KAT ──────────────────────────────────────────
        // 각 함수: 암호화 + 복호화 양방향 검증
        // 반환: true=통과, false=실패

        /// @brief ARIA-128/192/256 ECB KAT (KS X 1213-1)
        static bool KAT_ARIA() noexcept;

        /// @brief LEA-128/192/256 ECB KAT (TTAK.KO-12.0223)
        static bool KAT_LEA() noexcept;

        /// @brief HMAC-SHA256 KAT (KS X ISO/IEC 9797-2 / RFC 2104)
        static bool KAT_HMAC_SHA256() noexcept;

        /// @brief LSH-256 해시 KAT (KS X 3262)
        static bool KAT_LSH256() noexcept;

        /// @brief CTR_DRBG 결정론 KAT (SP 800-90A)
        /// 고정 시드 → 고정 출력 비교 (KCMVP/FIPS 공통)
        static bool KAT_DRBG() noexcept;

        // ── FIPS KAT (향후 AES 구현 시 활성화) ──────────────────
#if defined(HTS_CRYPTO_FIPS) || defined(HTS_CRYPTO_DUAL)
        /// @brief AES-256 ECB KAT (FIPS 197)
        static bool KAT_AES() noexcept;

        /// @brief SHA-256 해시 KAT (FIPS 180-4)
        static bool KAT_SHA256() noexcept;
#endif

        // ── 통합 진입점 ─────────────────────────────────────────

        /// @brief 전체 암호 KAT 실행 (빌드 프리셋에 따라 선택)
        /// @return true=전 항목 통과, false=1건이라도 실패
        static bool Run_All_Crypto_KAT() noexcept;

        Crypto_KAT() = delete;
        ~Crypto_KAT() = delete;
        Crypto_KAT(const Crypto_KAT&) = delete;
        Crypto_KAT& operator=(const Crypto_KAT&) = delete;
    };

} // namespace ProtectedEngine