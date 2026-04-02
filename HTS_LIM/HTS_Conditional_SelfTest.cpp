// =========================================================================
// HTS_Conditional_SelfTest.cpp
// KCMVP/FIPS 140-3 조건부 자가진단 + Boot Verify 구현부
// Target: STM32F407 (Cortex-M4) / Cortex-A55 / PC
//
// [구현 항목]
//  1. Verify_ARIA_Key: ARIA 암호화→복호화 라운드트립 (KCMVP)
//  2. Verify_LEA_Key:  LEA-CTR 암호화→복호화 라운드트립 (KCMVP)
//  3. Verify_AES_Key:  AES 암호화→복호화 라운드트립 (FIPS)
//  4. Verify_Flash_Integrity: Flash HMAC-SHA256 무결성 (FIPS AS09.40)
//
// [제약] try-catch 0, float/double 0, heap 0, iostream 0
// =========================================================================
#include "HTS_Conditional_SelfTest.h"
#include "HTS_ARIA_Bridge.hpp"
#include "HTS_LEA_Bridge.h"
#include "HTS_HMAC_Bridge.hpp"

#if defined(HTS_CRYPTO_FIPS) || defined(HTS_CRYPTO_DUAL)
#include "HTS_AES_Bridge.h"
#endif

#include <atomic>
#include <cstring>

namespace ProtectedEngine {

    // =====================================================================
    //  유틸리티
    // =====================================================================
    static void CST_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) return;
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) q[i] = 0u;
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    static bool CST_CT_Eq(const uint8_t* a,
        const uint8_t* b, size_t n) noexcept {
        volatile uint8_t d = 0u;
        for (size_t i = 0u; i < n; ++i) d |= a[i] ^ b[i];
        return (d == 0u);
    }

    // =====================================================================
    //  Verify_ARIA_Key — ARIA 쌍대 일관성
    //
    //  1. 고정 PT(16B) → Encrypt → CT
    //  2. CT → Decrypt → PT'
    //  3. PT == PT' 확인 (상수 시간)
    // =====================================================================
    bool Conditional_SelfTest::Verify_ARIA_Key(
        const uint8_t* key, int key_bits) noexcept {

        if (key == nullptr) return false;
        if (key_bits != 128 && key_bits != 192 && key_bits != 256) return false;

        // 고정 테스트 평문 (KAT과 동일 — 재사용)
        static constexpr uint8_t pt[16] = {
            0x00,0x11,0x22,0x33, 0x44,0x55,0x66,0x77,
            0x88,0x99,0xAA,0xBB, 0xCC,0xDD,0xEE,0xFF
        };

        uint8_t ct[16] = {};
        uint8_t dec[16] = {};

        // 암호화
        {
            ARIA_Bridge enc;
            if (!enc.Initialize_Encryption(key, key_bits)) return false;
            if (!enc.Process_Block(pt, ct)) {
                CST_Wipe(ct, sizeof(ct));
                return false;
            }
        }

        // 복호화
        {
            ARIA_Bridge dec_bridge;
            if (!dec_bridge.Initialize_Decryption(key, key_bits)) {
                CST_Wipe(ct, sizeof(ct));
                return false;
            }
            if (!dec_bridge.Process_Block(ct, dec)) {
                CST_Wipe(ct, sizeof(ct));
                CST_Wipe(dec, sizeof(dec));
                return false;
            }
        }

        bool ok = CST_CT_Eq(dec, pt, 16);
        CST_Wipe(ct, sizeof(ct));
        CST_Wipe(dec, sizeof(dec));
        return ok;
    }

    // =====================================================================
    //  Verify_LEA_Key — LEA-CTR 쌍대 일관성
    //
    //  CTR 모드: 동일 키+IV로 암호화→복호화 → 원문 일치
    // =====================================================================
    bool Conditional_SelfTest::Verify_LEA_Key(
        const uint8_t* key, uint32_t key_len_bytes,
        const uint8_t* iv_16) noexcept {

        if (key == nullptr || iv_16 == nullptr) return false;
        if (key_len_bytes != 16 && key_len_bytes != 24 &&
            key_len_bytes != 32) return false;

        static constexpr uint8_t pt_raw[16] = {
            0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
            0x18,0x19,0x1A,0x1B, 0x1C,0x1D,0x1E,0x1F
        };

        // 암호화 (in-place)
        alignas(4) uint8_t work[16] = {};
        std::memcpy(work, pt_raw, 16);
        {
            LEA_Bridge enc;
            if (enc.Initialize(key, key_len_bytes, iv_16) != LEA_Bridge::SECURE_TRUE) return false;
            if (enc.Encrypt_Payload(
                reinterpret_cast<uint32_t*>(work), 4u) != LEA_Bridge::SECURE_TRUE) {
                CST_Wipe(work, sizeof(work));
                return false;
            }
        }

        // 복호화 (in-place, 동일 키+IV)
        {
            LEA_Bridge dec;
            if (dec.Initialize(key, key_len_bytes, iv_16) != LEA_Bridge::SECURE_TRUE) {
                CST_Wipe(work, sizeof(work));
                return false;
            }
            if (dec.Decrypt_Payload(
                reinterpret_cast<uint32_t*>(work), 4u) != LEA_Bridge::SECURE_TRUE) {
                CST_Wipe(work, sizeof(work));
                return false;
            }
        }

        bool ok = CST_CT_Eq(work, pt_raw, 16);
        CST_Wipe(work, sizeof(work));
        return ok;
    }

#if defined(HTS_CRYPTO_FIPS) || defined(HTS_CRYPTO_DUAL)
    // =====================================================================
    //  Verify_AES_Key — AES 쌍대 일관성 (FIPS)
    // =====================================================================
    bool Conditional_SelfTest::Verify_AES_Key(
        const uint8_t* key, int key_bits) noexcept {

        if (key == nullptr) return false;
        if (key_bits != 128 && key_bits != 192 && key_bits != 256) return false;

        static constexpr uint8_t pt[16] = {
            0x00,0x11,0x22,0x33, 0x44,0x55,0x66,0x77,
            0x88,0x99,0xAA,0xBB, 0xCC,0xDD,0xEE,0xFF
        };

        uint8_t ct[16] = {};
        uint8_t dec[16] = {};

        {
            AES_Bridge enc;
            if (!enc.Initialize_Encryption(key, key_bits)) return false;
            if (!enc.Process_Block(pt, ct)) {
                CST_Wipe(ct, sizeof(ct));
                return false;
            }
        }
        {
            AES_Bridge dec_bridge;
            if (!dec_bridge.Initialize_Decryption(key, key_bits)) {
                CST_Wipe(ct, sizeof(ct));
                return false;
            }
            if (!dec_bridge.Process_Block(ct, dec)) {
                CST_Wipe(ct, sizeof(ct));
                CST_Wipe(dec, sizeof(dec));
                return false;
            }
        }

        bool ok = CST_CT_Eq(dec, pt, 16);
        CST_Wipe(ct, sizeof(ct));
        CST_Wipe(dec, sizeof(dec));
        return ok;
    }
#endif

    // =====================================================================
    //  Verify_Flash_Integrity — Flash HMAC-SHA256 무결성
    //
    //  [FIPS 140-3 AS09.40] 소프트웨어/펌웨어 무결성 테스트
    //
    //  1. Flash를 CHUNK_SIZE(256B) 단위로 읽기
    //  2. HMAC_Bridge Init → Update(반복) → Final
    //  3. 결과와 expected_hmac 상수 시간 비교
    //
    //  STM32F407: flash_base=0x08000000, flash_size=512KB
    //  콜백 기반: 플랫폼 독립 (STM32/A55/PC 모두 동일 인터페이스)
    // =====================================================================
    bool Conditional_SelfTest::Verify_Flash_Integrity(
        FlashReadFunc flash_read,
        uint32_t flash_base,
        uint32_t flash_size,
        const uint8_t* hmac_key,
        const uint8_t* expected_hmac) noexcept {

        if (flash_read == nullptr || hmac_key == nullptr ||
            expected_hmac == nullptr || flash_size == 0u) {
            return false;
        }

        // HMAC_Bridge 스트리밍 API: Init(ctx, key, len) → Update(ctx, ...) → Final(ctx, ...)
        HMAC_Context ctx;
        if (!HMAC_Bridge::Init(ctx, hmac_key, 32)) return false;

        static constexpr size_t CHUNK_SIZE = 256u;
        uint8_t chunk[CHUNK_SIZE] = {};
        uint32_t offset = 0u;

        while (offset < flash_size) {
            if (flash_base > (0xFFFFFFFFu - offset)) {
                CST_Wipe(chunk, sizeof(chunk));
                return false;
            }
            const size_t remain = static_cast<size_t>(flash_size - offset);
            const size_t read_len = (remain < CHUNK_SIZE) ? remain : CHUNK_SIZE;

            const size_t actual = flash_read(
                flash_base + offset, chunk, read_len);
            if (actual != read_len) {
                CST_Wipe(chunk, sizeof(chunk));
                return false;
            }

            if (!HMAC_Bridge::Update(ctx, chunk, read_len)) {
                CST_Wipe(chunk, sizeof(chunk));
                return false;
            }

            offset += static_cast<uint32_t>(read_len);
        }

        CST_Wipe(chunk, sizeof(chunk));

        uint8_t computed_hmac[32] = {};
        if (!HMAC_Bridge::Final(ctx, computed_hmac)) {
            CST_Wipe(computed_hmac, sizeof(computed_hmac));
            return false;
        }

        bool ok = CST_CT_Eq(computed_hmac, expected_hmac, 32);
        CST_Wipe(computed_hmac, sizeof(computed_hmac));
        return ok;
    }

} // namespace ProtectedEngine