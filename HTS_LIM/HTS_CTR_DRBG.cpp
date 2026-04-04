// =========================================================================
// HTS_CTR_DRBG.cpp
// NIST SP 800-90A CTR_DRBG 구현부
// Target: STM32F407 (Cortex-M4) / Cortex-A55 / PC
//
// [구현 범위]
//  SP 800-90A §10.2.1: CTR_DRBG Using Block Cipher
//  - Instantiate    (§10.2.1.3.2 — derivation function 미사용)
//  - Generate       (§10.2.1.5.2)
//  - Reseed         (§10.2.1.4.2)
//  - Uninstantiate  (§10.2.1.6)
//  - Update         (§10.2.1.2)
//
// [블록 암호 선택]
//  HTS_CRYPTO_KCMVP / DUAL: ARIA-256 (HTS_ARIA_Bridge)
//  HTS_CRYPTO_FIPS:          AES-256  (HTS_AES_Bridge)
//  미정의:                    ARIA-256 (기본값)
//
// [제약] try-catch 0, float/double 0, heap 0, iostream 0
// =========================================================================
#include "HTS_CTR_DRBG.h"
#include "HTS_Arm_Irq_Mask_Guard.h"
#include "HTS_Physical_Entropy_Engine.h"
#include "HTS_Secure_Logger.h"

// ── 블록 암호 선택 (빌드 프리셋) ─────────────────────────────────
#if defined(HTS_CRYPTO_FIPS) && !defined(HTS_CRYPTO_DUAL)
#include "HTS_AES_Bridge.h"
#define DRBG_CIPHER_NAME "AES-256"
#else
#include "HTS_ARIA_Bridge.hpp"
#define DRBG_CIPHER_NAME "ARIA-256"
#endif

#include <atomic>
#include <cstring>

namespace ProtectedEngine {

    // =====================================================================
    //  보안 소거
    // =====================================================================
    static void DRBG_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) return;
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) q[i] = 0u;
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  생성자 / 소멸자
    // =====================================================================
    HTS_CTR_DRBG::HTS_CTR_DRBG() noexcept {
        std::memset(key, 0, sizeof(key));
        std::memset(V, 0, sizeof(V));
    }

    HTS_CTR_DRBG::~HTS_CTR_DRBG() noexcept {
        Uninstantiate();
    }

    // =====================================================================
    //  Uninstantiate — 키 소재 완전 소거
    // =====================================================================
    void HTS_CTR_DRBG::Uninstantiate() noexcept {
        Armv7m_Irq_Mask_Guard irq;
        DRBG_Wipe(key, sizeof(key));
        DRBG_Wipe(V, sizeof(V));
        DRBG_Wipe(prev_block, sizeof(prev_block));
        prev_block_valid = false;
        reseed_counter.store(0u, std::memory_order_release);
        instantiated.store(false, std::memory_order_release);
    }

    // =====================================================================
    //  Increment_V — Big-Endian 16바이트 카운터 +1
    //  SP 800-90A §10.2.1.2 Step 2
    // =====================================================================
    void HTS_CTR_DRBG::Increment_V(uint8_t* v) noexcept {
        // [교정] D-1/D-2. 타이밍 부채널 방어 및 연산 레지스터 파기
        volatile uint16_t carry = 1u;
        for (int i = BLOCK_LEN - 1; i >= 0; --i) {
            uint16_t sum = static_cast<uint16_t>(v[i]) + carry;
            v[i] = static_cast<uint8_t>(sum & 0xFFu);
            carry = sum >> 8u;
        }
        carry = 0u;
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(carry) : "memory");
#endif
    }

    // =====================================================================
    //  Block_Encrypt — 블록 암호 1회 호출
    //  빌드 프리셋에 따라 ARIA-256 또는 AES-256 선택
    // =====================================================================
    uint32_t HTS_CTR_DRBG::Block_Encrypt(const uint8_t* key_32,
        const uint8_t* in_16, uint8_t* out_16) noexcept {

#if defined(HTS_CRYPTO_FIPS) && !defined(HTS_CRYPTO_DUAL)
        AES_Bridge cipher;
        if (!cipher.Initialize_Encryption(key_32, 256)) return SECURE_FALSE;
        return cipher.Process_Block(in_16, out_16) ? SECURE_TRUE : SECURE_FALSE;
#else
        ARIA_Bridge cipher;
        if (!cipher.Initialize_Encryption(key_32, 256)) return SECURE_FALSE;
        return cipher.Process_Block(in_16, out_16) ? SECURE_TRUE : SECURE_FALSE;
#endif
    }

    // =====================================================================
    //  Build_Seed_Material — 엔트로피 || 논스 || 개인화 → SEED_LEN 패딩
    //  SP 800-90A: seed_material = entropy || nonce || personalization
    //  SEED_LEN(48B) 초과 시 절단, 미달 시 0 패딩
    // =====================================================================
    void HTS_CTR_DRBG::Build_Seed_Material(
        uint8_t* seed_out,
        const uint8_t* entropy, size_t e_len,
        const uint8_t* nonce, size_t n_len,
        const uint8_t* pers, size_t p_len) noexcept {

        std::memset(seed_out, 0, SEED_LEN);
        size_t pos = 0u;

        // entropy 복사
        if (entropy != nullptr && e_len > 0u) {
            const size_t copy = (e_len > SEED_LEN) ? SEED_LEN : e_len;
            std::memcpy(seed_out, entropy, copy);
            pos = copy;
        }

        // nonce XOR 혼합 (연접 대신 XOR — 고정 SEED_LEN 유지)
        if (nonce != nullptr && n_len > 0u) {
            size_t idx = pos;
            for (size_t i = 0u; i < n_len && i < SEED_LEN; ++i) {
                seed_out[idx] ^= nonce[i];
                ++idx;
                if (idx >= SEED_LEN) { idx -= SEED_LEN; }
            }
        }

        // personalization XOR 혼합
        if (pers != nullptr && p_len > 0u) {
            for (size_t i = 0u; i < p_len && i < SEED_LEN; ++i) {
                seed_out[i] ^= pers[i];
            }
        }
    }

    // =====================================================================
    //  Update — SP 800-90A §10.2.1.2
    //
    //  temp = empty
    //  while len(temp) < seedlen:
    //      V = (V + 1)
    //      output_block = Encrypt(Key, V)
    //      temp = temp || output_block
    //  temp = temp[0..seedlen-1] XOR provided_data
    //  Key = temp[0..keylen-1]
    //  V   = temp[keylen..seedlen-1]
    // =====================================================================
    uint32_t HTS_CTR_DRBG::Update(const uint8_t* provided_data) noexcept {

        alignas(uint32_t) uint8_t temp[SEED_LEN] = {};  // 48B 스택
        size_t offset = 0u;

        // SEED_LEN / BLOCK_LEN = 48 / 16 = 3 블록
        static constexpr size_t NUM_BLOCKS = SEED_LEN / BLOCK_LEN;

        // Generate()와 동일: PRIMASK 안에서는 스냅샷만 — Block_Encrypt(키확장)는 IRQ 허용 구간
        for (size_t i = 0u; i < NUM_BLOCKS; ++i) {
            alignas(uint32_t) uint8_t block_out[BLOCK_LEN] = {};
            alignas(uint32_t) uint8_t key_snapshot[KEY_LEN] = {};
            alignas(uint32_t) uint8_t v_snapshot[BLOCK_LEN] = {};

            {
                Armv7m_Irq_Mask_Guard irq;
                Increment_V(V);
                std::memcpy(key_snapshot, key, KEY_LEN);
                std::memcpy(v_snapshot, V, BLOCK_LEN);
            }

            if (Block_Encrypt(key_snapshot, v_snapshot, block_out) != SECURE_TRUE) {
                DRBG_Wipe(temp, sizeof(temp));
                DRBG_Wipe(block_out, sizeof(block_out));
                DRBG_Wipe(key_snapshot, sizeof(key_snapshot));
                DRBG_Wipe(v_snapshot, sizeof(v_snapshot));
                return SECURE_FALSE;
            }
            std::memcpy(temp + offset, block_out, BLOCK_LEN);
            offset += BLOCK_LEN;
            DRBG_Wipe(block_out, sizeof(block_out));
            DRBG_Wipe(key_snapshot, sizeof(key_snapshot));
            DRBG_Wipe(v_snapshot, sizeof(v_snapshot));
        }

        // XOR with provided_data
        if (provided_data != nullptr) {
            for (size_t i = 0u; i < SEED_LEN; ++i) {
                temp[i] ^= provided_data[i];
            }
        }

        // 새 Key, V 설정 (원자적 갱신)
        {
            Armv7m_Irq_Mask_Guard irq;
            std::memcpy(key, temp, KEY_LEN);
            std::memcpy(V, temp + KEY_LEN, BLOCK_LEN);
            DRBG_Wipe(temp, sizeof(temp));
        }
        return SECURE_TRUE;
    }

    // =====================================================================
    //  Instantiate — SP 800-90A §10.2.1.3.2
    //  (derivation function 미사용 — entropy ≥ security_strength)
    // =====================================================================
    DRBG_Status HTS_CTR_DRBG::Instantiate(
        const uint8_t* entropy, size_t entropy_len,
        const uint8_t* nonce, size_t nonce_len,
        const uint8_t* pers, size_t pers_len) noexcept {

        if (entropy == nullptr || entropy_len < SEED_LEN) {
            return DRBG_Status::ERROR_ENTROPY_FAIL;
        }

        // Key = 0, V = 0 (초기 상태)
        std::memset(key, 0, sizeof(key));
        std::memset(V, 0, sizeof(V));

        // seed_material 구성
        alignas(uint32_t) uint8_t seed[SEED_LEN] = {};
        Build_Seed_Material(seed, entropy, entropy_len,
            nonce, nonce_len, pers, pers_len);

        // Update(seed_material, Key=0, V=0)
        if (Update(seed) != SECURE_TRUE) {
            DRBG_Wipe(seed, sizeof(seed));
            return DRBG_Status::ERROR_CIPHER_FAIL;
        }
        DRBG_Wipe(seed, sizeof(seed));

        reseed_counter.store(1u, std::memory_order_release);
        instantiated.store(true, std::memory_order_release);

        SecureLogger::logSecurityEvent(
            "DRBG_INIT",
            "CTR_DRBG instantiated (" DRBG_CIPHER_NAME ").");

        return DRBG_Status::OK;
    }

    // =====================================================================
    //  Instantiate_Auto — Physical_Entropy_Engine에서 자동 엔트로피 수집
    // =====================================================================
    DRBG_Status HTS_CTR_DRBG::Instantiate_Auto() noexcept {

        // SEED_LEN(48B) = 12 × 4B(uint32_t)
        alignas(uint32_t) uint8_t entropy[SEED_LEN] = {};
        for (size_t i = 0u; i < SEED_LEN; i += 4u) {
            const uint32_t raw =
                Physical_Entropy_Engine::Extract_Quantum_Seed();
            entropy[i] = static_cast<uint8_t>(raw >> 24u);
            entropy[i + 1] = static_cast<uint8_t>((raw >> 16u) & 0xFFu);
            entropy[i + 2] = static_cast<uint8_t>((raw >> 8u) & 0xFFu);
            entropy[i + 3] = static_cast<uint8_t>(raw & 0xFFu);
        }

        // nonce = 추가 4바이트 엔트로피
        alignas(uint32_t) uint8_t nonce[4] = {};
        {
            const uint32_t n =
                Physical_Entropy_Engine::Extract_Quantum_Seed();
            nonce[0] = static_cast<uint8_t>(n >> 24u);
            nonce[1] = static_cast<uint8_t>((n >> 16u) & 0xFFu);
            nonce[2] = static_cast<uint8_t>((n >> 8u) & 0xFFu);
            nonce[3] = static_cast<uint8_t>(n & 0xFFu);
        }

        const DRBG_Status st = Instantiate(
            entropy, sizeof(entropy), nonce, sizeof(nonce), nullptr, 0u);

        DRBG_Wipe(entropy, sizeof(entropy));
        DRBG_Wipe(nonce, sizeof(nonce));
        return st;
    }

    // =====================================================================
    //  Generate — SP 800-90A §10.2.1.5.2
    //
    //  1. reseed_counter 검사
    //  2. additional_input 있으면 Update
    //  3. temp = 반복 { V++; Encrypt(Key, V) }
    //  4. output = Leftmost(temp, requested_bits)
    //  5. Update(additional_input)
    //  6. reseed_counter++
    // =====================================================================
    DRBG_Status HTS_CTR_DRBG::Generate(
        uint8_t* output, size_t output_len) noexcept {

        if (!instantiated.load(std::memory_order_acquire)) return DRBG_Status::ERROR_UNINSTANTIATED;
        if (output == nullptr || output_len == 0u) return DRBG_Status::OK;
        if (output_len > MAX_OUTPUT) return DRBG_Status::ERROR_INPUT_TOO_LONG;

        // reseed 필요 여부
        if (reseed_counter.load(std::memory_order_relaxed) > RESEED_INTERVAL) {
            return DRBG_Status::ERROR_RESEED_REQUIRED;
        }

        size_t generated = 0u;
        uint8_t crng_failed = 0u;
        while (generated < output_len) {
            alignas(uint32_t) uint8_t key_snapshot[KEY_LEN] = {};
            alignas(uint32_t) uint8_t v_snapshot[BLOCK_LEN] = {};
            alignas(uint32_t) uint8_t prev_snapshot[BLOCK_LEN] = {};
            bool prev_valid_snapshot = false;

            {
                Armv7m_Irq_Mask_Guard irq;
                Increment_V(V);
                std::memcpy(key_snapshot, key, KEY_LEN);
                std::memcpy(v_snapshot, V, BLOCK_LEN);
                prev_valid_snapshot = prev_block_valid;
                if (prev_valid_snapshot) {
                    std::memcpy(prev_snapshot, prev_block, BLOCK_LEN);
                }
            }

            alignas(uint32_t) uint8_t block_out[BLOCK_LEN] = {};
            if (Block_Encrypt(key_snapshot, v_snapshot, block_out) != SECURE_TRUE) {
                DRBG_Wipe(key_snapshot, sizeof(key_snapshot));
                DRBG_Wipe(v_snapshot, sizeof(v_snapshot));
                DRBG_Wipe(prev_snapshot, sizeof(prev_snapshot));
                DRBG_Wipe(block_out, sizeof(block_out));
                return DRBG_Status::ERROR_CIPHER_FAIL;
            }

            // ── CRNG 연속 테스트 (FIPS 140-3 AS09.35) ────────────
            //  연속 2개 출력 블록이 동일 → DRBG 고장 (확률 2^(-128))
            if (prev_valid_snapshot) {
                volatile uint8_t diff = 0u;
                for (size_t j = 0u; j < BLOCK_LEN; ++j) {
                    diff = static_cast<uint8_t>(
                        static_cast<uint8_t>(diff)
                        | (static_cast<uint8_t>(block_out[j])
                            ^ static_cast<uint8_t>(prev_snapshot[j])));
                }
                // DRBG 출력 반복 → 치명적 고장
                // 즉시 리턴하지 않고 플래그 누적 후 고정 흐름으로 종료 지점에서 fail-closed.
                const uint32_t d = static_cast<uint32_t>(diff);
                const uint8_t eq_mask = static_cast<uint8_t>((d - 1u) >> 31u); // diff==0 -> 1, else 0
                crng_failed |= eq_mask;
            }
            // 현재 블록을 이전 블록으로 저장
            {
                Armv7m_Irq_Mask_Guard irq;
                for (size_t j = 0u; j < BLOCK_LEN; ++j) {
                    prev_block[j] = block_out[j];
                }
                prev_block_valid = true;
            }

            const size_t remain = output_len - generated;
            const size_t copy = (remain < BLOCK_LEN) ? remain : BLOCK_LEN;
            const uint32_t cf_acc = static_cast<uint32_t>(crng_failed);
            const uint32_t has_err = (cf_acc | (0u - cf_acc)) >> 31u;
            const uint8_t ok_mask = static_cast<uint8_t>((has_err - 1u) & 0xFFu);
            for (size_t j = 0u; j < copy; ++j) {
                // CRNG 실패 누적 시 output으로의 원본 블록 유출 차단
                output[generated + j] = static_cast<uint8_t>(block_out[j] & ok_mask);
            }

            generated += copy;
            DRBG_Wipe(key_snapshot, sizeof(key_snapshot));
            DRBG_Wipe(v_snapshot, sizeof(v_snapshot));
            DRBG_Wipe(prev_snapshot, sizeof(prev_snapshot));
            DRBG_Wipe(block_out, sizeof(block_out));
        }

        if (crng_failed != 0u) {
            DRBG_Wipe(output, output_len);
            Uninstantiate();
            SecureLogger::logSecurityEvent(
                "DRBG_FAIL",
                "CRNG continuous test failed. DRBG blocked.");
            return DRBG_Status::ERROR_CIPHER_FAIL;
        }

        // Update(additional_input = nullptr)
        if (Update(nullptr) != SECURE_TRUE) {
            Uninstantiate();
            return DRBG_Status::ERROR_CIPHER_FAIL;
        }
        reseed_counter.fetch_add(1u, std::memory_order_release);

        return DRBG_Status::OK;
    }

    // =====================================================================
    //  Reseed — SP 800-90A §10.2.1.4.2
    // =====================================================================
    DRBG_Status HTS_CTR_DRBG::Reseed(
        const uint8_t* entropy, size_t entropy_len,
        const uint8_t* additional, size_t add_len) noexcept {

        if (!instantiated.load(std::memory_order_acquire)) return DRBG_Status::ERROR_UNINSTANTIATED;
        if (entropy == nullptr || entropy_len < SEED_LEN) {
            return DRBG_Status::ERROR_ENTROPY_FAIL;
        }

        alignas(uint32_t) uint8_t seed[SEED_LEN] = {};
        Build_Seed_Material(seed, entropy, entropy_len,
            additional, add_len, nullptr, 0u);

        if (Update(seed) != SECURE_TRUE) {
            DRBG_Wipe(seed, sizeof(seed));
            Uninstantiate();
            return DRBG_Status::ERROR_CIPHER_FAIL;
        }
        DRBG_Wipe(seed, sizeof(seed));

        reseed_counter.store(1u, std::memory_order_release);
        instantiated.store(true, std::memory_order_release);

        SecureLogger::logSecurityEvent(
            "DRBG_RESEED",
            "CTR_DRBG reseeded (" DRBG_CIPHER_NAME ").");

        return DRBG_Status::OK;
    }

    // =====================================================================
    //  Reseed_Auto — Physical_Entropy_Engine 자동 리시드
    // =====================================================================
    DRBG_Status HTS_CTR_DRBG::Reseed_Auto() noexcept {

        alignas(uint32_t) uint8_t entropy[SEED_LEN] = {};
        for (size_t i = 0u; i < SEED_LEN; i += 4u) {
            const uint32_t raw =
                Physical_Entropy_Engine::Extract_Quantum_Seed();
            entropy[i] = static_cast<uint8_t>(raw >> 24u);
            entropy[i + 1] = static_cast<uint8_t>((raw >> 16u) & 0xFFu);
            entropy[i + 2] = static_cast<uint8_t>((raw >> 8u) & 0xFFu);
            entropy[i + 3] = static_cast<uint8_t>(raw & 0xFFu);
        }

        const DRBG_Status st = Reseed(entropy, sizeof(entropy), nullptr, 0u);
        DRBG_Wipe(entropy, sizeof(entropy));
        return st;
    }

} // namespace ProtectedEngine
