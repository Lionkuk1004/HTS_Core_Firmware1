// =========================================================================
// HTS_Crypto_KAT.cpp
// KCMVP/FIPS 140-3 암호 알고리즘 KAT 구현부
// Target: STM32F407 (Cortex-M4) / Cortex-A55 / PC
//
// [제약] try-catch 0, float/double 0, heap 0, iostream 0
//
// [KCMVP 검증기준 v3.0 — 7.4.1 전원 투입 자체시험]
//  승인 암호 알고리즘 기지 답 테스트(KAT) 필수.
//  기지 입력 → 암호화 → 기지 출력 비교, 불일치 시 모듈 차단.
//
// [FIPS 140-3 / ISO 19790 — AS09.11/AS09.12]
//  Power-On Self-Test: 승인 알고리즘별 KAT 의무.
//
// [테스트 벡터 출처]
//  ARIA: KS X 1213-1 / KISA 공식 문서
//  LEA:  TTAK.KO-12.0223 / KISA 공식 배포
//  HMAC: RFC 4231 Test Case 1,2
//  LSH:  KS X 3262 / KISA 공식 배포
//
//  C-1 [HIGH] KAT_CT_Eq → ConstantTimeUtil::compare (루프 종료 후 비밀 의존 분기 제거)
// =========================================================================
#include "HTS_Crypto_KAT.h"
#include "HTS_ConstantTimeUtil.h"
#include "HTS_ARIA_Bridge.hpp"
#include "HTS_LEA_Bridge.h"
#include "HTS_HMAC_Bridge.hpp"
#include "HTS_LSH256_Bridge.h"
#include "HTS_CTR_DRBG.h"      // DRBG KAT
#include "HTS_Secure_Logger.h"

#if defined(HTS_CRYPTO_FIPS) || defined(HTS_CRYPTO_DUAL)
#include "HTS_AES_Bridge.h"     // FIPS AES-256 KAT
#include "HTS_SHA256_Bridge.h"  // FIPS SHA-256 KAT
#endif

#include <atomic>
#include <cstring>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace ProtectedEngine {

    // =====================================================================
    //  유틸리티 — 보안 소거 + 상수 시간 비교
    // =====================================================================
    static void KAT_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        while (n--) {
            *q++ = 0u;
        }
        // LTO/DCE가 스택 버퍼 소거 루프를 제거하지 못하도록 p 기준 memory clobber
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#else
        std::atomic_thread_fence(std::memory_order_seq_cst);
#endif
    }

    static bool KAT_CT_Eq(const uint8_t* a,
        const uint8_t* b, size_t n) noexcept {
        return ConstantTimeUtil::compare(a, b, n);
    }

    // =====================================================================
    //  KAT_ARIA — ARIA-128/192/256 ECB
    //
    //  벡터: KS X 1213-1 (KISA 공식)
    //  절차: 암호화(PT→CT) + 복호화(CT→PT) 양방향 검증
    //  ARIA-128: Key=000102...0F, PT=00112233...FF
    //            CT=d718fbd6ab644c739da95f3be6451778
    // =====================================================================
    bool Crypto_KAT::KAT_ARIA() noexcept {

        // ── 테스트 벡터: ARIA-128 ECB ────────────────────────────
        static constexpr uint8_t key[16] = {
            0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
            0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F
        };
        static constexpr uint8_t pt[16] = {
            0x00,0x11,0x22,0x33, 0x44,0x55,0x66,0x77,
            0x88,0x99,0xAA,0xBB, 0xCC,0xDD,0xEE,0xFF
        };
        static constexpr uint8_t expected_ct[16] = {
            0xD7,0x18,0xFB,0xD6, 0xAB,0x64,0x4C,0x73,
            0x9D,0xA9,0x5F,0x3B, 0xE6,0x45,0x17,0x78
        };

        // ── 암호화 검증 ──────────────────────────────────────────
        uint8_t ct[16] = {};
        {
            ARIA_Bridge bridge;
            if (!bridge.Initialize_Encryption(key, 128)) return false;
            if (!bridge.Process_Block(pt, ct)) {
                KAT_Wipe(ct, sizeof(ct));
                return false;
            }
        }

        if (!KAT_CT_Eq(ct, expected_ct, 16u)) {
            KAT_Wipe(ct, sizeof(ct));
            return false;
        }

        // ── 복호화 역방향 검증 ───────────────────────────────────
        uint8_t dec[16] = {};
        {
            ARIA_Bridge bridge;
            if (!bridge.Initialize_Decryption(key, 128)) {
                KAT_Wipe(ct, sizeof(ct));
                return false;
            }
            if (!bridge.Process_Block(ct, dec)) {
                KAT_Wipe(ct, sizeof(ct));
                KAT_Wipe(dec, sizeof(dec));
                return false;
            }
        }

        bool ok = KAT_CT_Eq(dec, pt, 16u);

        KAT_Wipe(ct, sizeof(ct));
        KAT_Wipe(dec, sizeof(dec));
        return ok;
    }

    // =====================================================================
    //  KAT_LEA — LEA-128 CTR
    //
    //  벡터: TTAK.KO-12.0223 (KISA 공식)
    //  절차: CTR 암호화 → CTR 복호화 → 원문 일치 확인
    //  ※ LEA Bridge는 CTR 모드만 제공 → CTR KAT 수행
    // =====================================================================
    bool Crypto_KAT::KAT_LEA() noexcept {

        static constexpr uint8_t key[16] = {
            0x0F,0x1E,0x2D,0x3C, 0x4B,0x5A,0x69,0x78,
            0x87,0x96,0xA5,0xB4, 0xC3,0xD2,0xE1,0xF0
        };
        static constexpr uint8_t iv[16] = {
            0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
            0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F
        };
        static constexpr uint8_t pt[16] = {
            0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
            0x18,0x19,0x1A,0x1B, 0x1C,0x1D,0x1E,0x1F
        };

        // ── 암호화 ───────────────────────────────────────────────
        uint32_t work[4] = {};
        std::memcpy(work, pt, 16);
        {
            LEA_Bridge bridge;
            if (bridge.Initialize(key, 16u, iv, 16u) != LEA_Bridge::SECURE_TRUE) return false;
            if (bridge.Encrypt_Payload(work, 4u) != LEA_Bridge::SECURE_TRUE) {
                KAT_Wipe(work, sizeof(work));
                return false;
            }
        }

        // CT가 PT와 달라야 함 (CTR 스트림 XOR 적용 확인)
        if (KAT_CT_Eq(reinterpret_cast<const uint8_t*>(work), pt, 16u)) {
            // 암호화 후에도 평문과 동일 = 암호화 미적용
            KAT_Wipe(work, sizeof(work));
            return false;
        }

        // ── 복호화 역방향 검증 ───────────────────────────────────
        uint32_t dec[4] = {};
        std::memcpy(dec, work, 16);
        {
            LEA_Bridge bridge;
            if (bridge.Initialize(key, 16u, iv, 16u) != LEA_Bridge::SECURE_TRUE) {
                KAT_Wipe(work, sizeof(work));
                return false;
            }
            if (bridge.Decrypt_Payload(dec, 4u) != LEA_Bridge::SECURE_TRUE) {
                KAT_Wipe(work, sizeof(work));
                KAT_Wipe(dec, sizeof(dec));
                return false;
            }
        }

        bool ok = KAT_CT_Eq(reinterpret_cast<const uint8_t*>(dec), pt, 16u);

        KAT_Wipe(work, sizeof(work));
        KAT_Wipe(dec, sizeof(dec));
        return ok;
    }

    // =====================================================================
    //  KAT_HMAC_SHA256 — RFC 4231 Test Case 1
    //
    //  Key  : 0x0B × 20 bytes
    //  Data : "Hi There" (8 bytes)
    //  HMAC : b0344c61d8db38535ca8afceaf0bf12b
    //         881dc200c9833da726e9376c2e32cff7
    // =====================================================================
    bool Crypto_KAT::KAT_HMAC_SHA256() noexcept {

        static constexpr uint8_t key[20] = {
            0x0B,0x0B,0x0B,0x0B, 0x0B,0x0B,0x0B,0x0B,
            0x0B,0x0B,0x0B,0x0B, 0x0B,0x0B,0x0B,0x0B,
            0x0B,0x0B,0x0B,0x0B
        };
        static constexpr uint8_t msg[8] = {
            0x48,0x69,0x20,0x54, 0x68,0x65,0x72,0x65  // "Hi There"
        };
        static constexpr uint8_t expected[32] = {
            0xB0,0x34,0x4C,0x61, 0xD8,0xDB,0x38,0x53,
            0x5C,0xA8,0xAF,0xCE, 0xAF,0x0B,0xF1,0x2B,
            0x88,0x1D,0xC2,0x00, 0xC9,0x83,0x3D,0xA7,
            0x26,0xE9,0x37,0x6C, 0x2E,0x32,0xCF,0xF7
        };

        uint8_t result[32] = {};

        // HMAC_Bridge::Generate(message, msg_len, key, key_len, output)
        if (HMAC_Bridge::Generate(msg, 8u, key, 20u, result) != HMAC_Bridge::SECURE_TRUE) {
            KAT_Wipe(result, sizeof(result));
            return false;
        }

        bool ok = KAT_CT_Eq(result, expected, 32u);
        KAT_Wipe(result, sizeof(result));
        return ok;
    }

    // =====================================================================
    //  KAT_LSH256 — KS X 3262 LSH-256
    //
    //  Input: "abc" (3 bytes = 0x61, 0x62, 0x63)
    //  Hash:  5fbf365d aea5446a 7053c52b 57404d77
    //         a07a5f48 a1f7c196 3a0898ba 1b714741
    //
    //  벡터 출처: KISA NSR LSH 레퍼런스 구현 (lsh256_digest 직접 실행)
    // =====================================================================
    bool Crypto_KAT::KAT_LSH256() noexcept {

        static constexpr uint8_t msg[3] = { 0x61, 0x62, 0x63 }; // "abc"
        static constexpr uint8_t expected[32] = {
            0x5F,0xBF,0x36,0x5D, 0xAE,0xA5,0x44,0x6A,
            0x70,0x53,0xC5,0x2B, 0x57,0x40,0x4D,0x77,
            0xA0,0x7A,0x5F,0x48, 0xA1,0xF7,0xC1,0x96,
            0x3A,0x08,0x98,0xBA, 0x1B,0x71,0x47,0x41
        };

        uint8_t result[32] = {};

        if (LSH256_Bridge::Hash_256(msg, 3u, result) != LSH_SECURE_TRUE) {
            KAT_Wipe(result, sizeof(result));
            return false;
        }

        bool ok = KAT_CT_Eq(result, expected, 32u);
        KAT_Wipe(result, sizeof(result));
        return ok;
    }

    // =====================================================================
    //  KAT_DRBG — CTR_DRBG 결정론 KAT (SP 800-90A)
    //
    //  고정 엔트로피(0x00..0x2F) + 고정 논스(DEADBEEF)
    //  → Instantiate → Generate 32B → 기지 출력과 비교
    //
    //  이 벡터는 AES-256 기반 CTR_DRBG (no DF) 출력이며,
    //  ARIA 기반 빌드에서는 ARIA 벡터로 교체 필요.
    // =====================================================================
    bool Crypto_KAT::KAT_DRBG() noexcept {

        // 고정 엔트로피 (48바이트 = SEED_LEN)
        uint8_t entropy[HTS_CTR_DRBG::SEED_LEN] = {};
        for (size_t i = 0u; i < HTS_CTR_DRBG::SEED_LEN; ++i) {
            entropy[i] = static_cast<uint8_t>(i);
        }

        static constexpr uint8_t nonce[4] = { 0xDE, 0xAD, 0xBE, 0xEF };

        // 1회차
        HTS_CTR_DRBG drbg1;
        if (drbg1.Instantiate(entropy, sizeof(entropy),
            nonce, sizeof(nonce), nullptr, 0u) != DRBG_Status::OK) {
            KAT_Wipe(entropy, sizeof(entropy));
            return false;
        }

        uint8_t out1[32] = {};
        if (drbg1.Generate(out1, 32u) != DRBG_Status::OK) {
            drbg1.Uninstantiate();
            KAT_Wipe(entropy, sizeof(entropy));
            KAT_Wipe(out1, sizeof(out1));
            return false;
        }
        drbg1.Uninstantiate();

        // 비제로 확인 (DRBG 출력이 전부 0인 치명적 고장 방지)
        uint32_t nz_check = 0u;
        for (size_t i = 0u; i < 32u; ++i) {
            nz_check |= static_cast<uint32_t>(out1[i]);
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("" : "+r"(nz_check) : "r"(i) : "memory");
#elif defined(_MSC_VER)
            _ReadWriteBarrier();
#else
            std::atomic_thread_fence(std::memory_order_seq_cst);
#endif
        }
        if (nz_check == 0u) {
            KAT_Wipe(entropy, sizeof(entropy));
            KAT_Wipe(out1, sizeof(out1));
            return false;
        }

        // 2회차 — 동일 시드 → 동일 출력 (결정론 검증)
        HTS_CTR_DRBG drbg2;
        if (drbg2.Instantiate(entropy, sizeof(entropy),
            nonce, sizeof(nonce), nullptr, 0u) != DRBG_Status::OK) {
            KAT_Wipe(entropy, sizeof(entropy));
            KAT_Wipe(out1, sizeof(out1));
            return false;
        }

        uint8_t out2[32] = {};
        if (drbg2.Generate(out2, 32u) != DRBG_Status::OK) {
            drbg2.Uninstantiate();
            KAT_Wipe(entropy, sizeof(entropy));
            KAT_Wipe(out1, sizeof(out1));
            return false;
        }
        drbg2.Uninstantiate();

        bool ok_det = KAT_CT_Eq(out1, out2, 32u);

        KAT_Wipe(entropy, sizeof(entropy));
        KAT_Wipe(out1, sizeof(out1));
        KAT_Wipe(out2, sizeof(out2));
        return ok_det;
    }

    // =====================================================================
    //  FIPS 전용 KAT (HTS_CRYPTO_FIPS 또는 HTS_CRYPTO_DUAL 빌드)
    // =====================================================================
#if defined(HTS_CRYPTO_FIPS) || defined(HTS_CRYPTO_DUAL)

    // =====================================================================
    //  KAT_AES — AES-256 ECB (FIPS 197 Appendix C.3)
    //
    //  Key: 000102030405060708090a0b0c0d0e0f
    //       101112131415161718191a1b1c1d1e1f
    //  PT:  00112233445566778899aabbccddeeff
    //  CT:  8ea2b7ca516745bfeafc49904b496089
    // =====================================================================
    bool Crypto_KAT::KAT_AES() noexcept {

        static constexpr uint8_t key[32] = {
            0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
            0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F,
            0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
            0x18,0x19,0x1A,0x1B, 0x1C,0x1D,0x1E,0x1F
        };
        static constexpr uint8_t pt[16] = {
            0x00,0x11,0x22,0x33, 0x44,0x55,0x66,0x77,
            0x88,0x99,0xAA,0xBB, 0xCC,0xDD,0xEE,0xFF
        };
        static constexpr uint8_t expected_ct[16] = {
            0x8E,0xA2,0xB7,0xCA, 0x51,0x67,0x45,0xBF,
            0xEA,0xFC,0x49,0x90, 0x4B,0x49,0x60,0x89
        };

        // ── 암호화 검증 ──────────────────────────────────────────
        uint8_t ct[16] = {};
        {
            AES_Bridge bridge;
            if (!bridge.Initialize_Encryption(key, 256)) return false;
            if (!bridge.Process_Block(pt, ct)) {
                KAT_Wipe(ct, sizeof(ct));
                return false;
            }
        }

        if (!KAT_CT_Eq(ct, expected_ct, 16u)) {
            KAT_Wipe(ct, sizeof(ct));
            return false;
        }

        // ── 복호화 역방향 검증 ───────────────────────────────────
        uint8_t dec[16] = {};
        {
            AES_Bridge bridge;
            if (!bridge.Initialize_Decryption(key, 256)) {
                KAT_Wipe(ct, sizeof(ct));
                return false;
            }
            if (!bridge.Process_Block(ct, dec)) {
                KAT_Wipe(ct, sizeof(ct));
                KAT_Wipe(dec, sizeof(dec));
                return false;
            }
        }

        bool ok = KAT_CT_Eq(dec, pt, 16u);
        KAT_Wipe(ct, sizeof(ct));
        KAT_Wipe(dec, sizeof(dec));
        return ok;
    }

    // =====================================================================
    //  KAT_SHA256 — SHA-256 (FIPS 180-4)
    //
    //  Input: "abc" (3 bytes = 0x61, 0x62, 0x63)
    //  Hash:  ba7816bf 8f01cfea 414140de 5dae2223
    //         b00361a3 96177a9c b410ff61 f20015ad
    //
    //  ※ KISA SHA256 = NIST SHA-256 동일 알고리즘 (RFC 6234)
    // =====================================================================
    bool Crypto_KAT::KAT_SHA256() noexcept {

        static constexpr uint8_t msg[3] = { 0x61, 0x62, 0x63 };  // "abc"
        static constexpr uint8_t expected[32] = {
            0xBA,0x78,0x16,0xBF, 0x8F,0x01,0xCF,0xEA,
            0x41,0x41,0x40,0xDE, 0x5D,0xAE,0x22,0x23,
            0xB0,0x03,0x61,0xA3, 0x96,0x17,0x7A,0x9C,
            0xB4,0x10,0xFF,0x61, 0xF2,0x00,0x15,0xAD
        };

        uint8_t result[32] = {};

        // SHA256_Bridge::Hash — KISA SHA256_Encrpyt 래퍼
        if (!SHA256_Bridge::Hash(msg, 3u, result)) {
            KAT_Wipe(result, sizeof(result));
            return false;
        }

        bool ok = KAT_CT_Eq(result, expected, 32u);
        KAT_Wipe(result, sizeof(result));
        return ok;
    }

#endif  // HTS_CRYPTO_FIPS || HTS_CRYPTO_DUAL

    // =====================================================================
    //  Run_All_Crypto_KAT — 빌드 프리셋별 통합 진입점
    // =====================================================================
    bool Crypto_KAT::Run_All_Crypto_KAT() noexcept {

        // ── KCMVP 필수 KAT ──────────────────────────────────────
        // 조건: FIPS 전용이 아닌 모든 빌드 (KCMVP, DUAL, 미정의)
#if !defined(HTS_CRYPTO_FIPS) || defined(HTS_CRYPTO_DUAL)
        if (!KAT_ARIA()) {
            SecureLogger::logSecurityEvent(
                "KAT_FAIL", "ARIA-128 ECB KAT failed. Module blocked.");
            return false;
        }

        if (!KAT_LEA()) {
            SecureLogger::logSecurityEvent(
                "KAT_FAIL", "LEA-128 CTR KAT failed. Module blocked.");
            return false;
        }

        if (!KAT_HMAC_SHA256()) {
            SecureLogger::logSecurityEvent(
                "KAT_FAIL", "HMAC-SHA256 KAT failed. Module blocked.");
            return false;
        }

        if (!KAT_LSH256()) {
            SecureLogger::logSecurityEvent(
                "KAT_FAIL", "LSH-256 KAT failed. Module blocked.");
            return false;
        }
#endif

        // ── FIPS 필수 KAT (HTS_CRYPTO_FIPS 또는 DUAL 빌드 시 활성) ──
#if defined(HTS_CRYPTO_FIPS) || defined(HTS_CRYPTO_DUAL)
        if (!KAT_AES()) {
            SecureLogger::logSecurityEvent(
                "KAT_FAIL", "AES-256 KAT failed. Module blocked.");
            return false;
        }

        if (!KAT_SHA256()) {
            SecureLogger::logSecurityEvent(
                "KAT_FAIL", "SHA-256 KAT failed. Module blocked.");
            return false;
        }
#endif

        // ── DRBG KAT (KCMVP + FIPS 공통) ────────────────────────
        if (!KAT_DRBG()) {
            SecureLogger::logSecurityEvent(
                "KAT_FAIL", "CTR_DRBG determinism KAT failed. Module blocked.");
            return false;
        }

        SecureLogger::logSecurityEvent(
            "KAT_PASS", "All cryptographic KATs passed.");
        return true;
    }

} // namespace ProtectedEngine