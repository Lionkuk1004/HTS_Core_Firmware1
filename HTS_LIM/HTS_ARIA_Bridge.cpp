// =========================================================================
// HTS_ARIA_Bridge.cpp
// KCMVP ARIA 블록 암호 브릿지 구현부
// 규격: KS X 1213-1 (2009)
// Target: STM32F407 (Cortex-M4)
//
#include "HTS_ARIA_Bridge.hpp"
#include "HTS_Secure_Memory.h"
#include <cstring>

// =========================================================================
//  KISA ARIA C 구현체 extern "C" 링크
//  Byte typedef: extern "C" 블록 내부 한정 (전역 오염 방지)
// =========================================================================
extern "C" {
    typedef unsigned char Byte;

    // 성공 시 라운드 수(12/14/16) 반환, 실패 시 음수 또는 0
    int  EncKeySetup(const Byte* mk, Byte* rk, int keyBits);
    int  DecKeySetup(const Byte* mk, Byte* rk, int keyBits);

    // 16바이트 블록 암/복호화
    void Crypt(const Byte* i, int Nr, const Byte* rk, Byte* o);
}

namespace ProtectedEngine {

    // =====================================================================
    //  유효 라운드 수 검증
    //  ARIA-128: 12 / ARIA-192: 14 / ARIA-256: 16
    // =====================================================================
    static bool Is_Valid_Round_Count(int r) noexcept {
        return (r == 12 || r == 14 || r == 16);
    }

    // =====================================================================
    //  보안 메모리 소거 — KCMVP 키 소재 잔존 방지(Key Zeroization)
    // =====================================================================

    // =====================================================================
    //  내부 키 스케줄 공통 로직 — 암호화/복호화 중복 제거
    // =====================================================================
    static bool Do_KeySetup(
        const uint8_t* master_key,
        int            key_bits,
        uint8_t* round_keys,
        int& num_rounds,
        bool& is_initialized,
        bool           is_enc) noexcept {

        if (!master_key ||
            (key_bits != 128 && key_bits != 192 && key_bits != 256)) {
            return false;
        }

        // 이전 키 소재 소거 후 재설정
        is_initialized = false;
        SecureMemory::secureWipe(static_cast<void*>(round_keys),
            ARIA_Bridge::ROUND_KEY_BUF_SIZE);

        alignas(4) uint8_t aligned_mk[32] = {};
        const size_t mk_size = static_cast<size_t>(key_bits / 8);
        std::memcpy(aligned_mk, master_key, mk_size);

        int rounds = is_enc
            ? EncKeySetup(
                reinterpret_cast<const Byte*>(aligned_mk),
                reinterpret_cast<Byte*>(round_keys),
                key_bits)
            : DecKeySetup(
                reinterpret_cast<const Byte*>(aligned_mk),
                reinterpret_cast<Byte*>(round_keys),
                key_bits);

        SecureMemory::secureWipe(static_cast<void*>(aligned_mk), sizeof(aligned_mk));

        if (!Is_Valid_Round_Count(rounds)) {
            SecureMemory::secureWipe(static_cast<void*>(round_keys),
            ARIA_Bridge::ROUND_KEY_BUF_SIZE);
            num_rounds = 0;
            return false;
        }

        num_rounds = rounds;
        is_initialized = true;
        return true;
    }

    // =====================================================================
    //  생성자
    // =====================================================================
    ARIA_Bridge::ARIA_Bridge() noexcept
        : round_keys{}
        , num_rounds(0)
        , is_initialized(false) {
        // round_keys는 = {} 값 초기화로 이미 0이지만,
        // KCMVP 감사 투명성을 위해 명시적 SecureMemory::secureWipe 유지
        SecureMemory::secureWipe(static_cast<void*>(round_keys), ROUND_KEY_BUF_SIZE);
    }

    // =====================================================================
    //  소멸자 — KCMVP 요건: 키 소재 반드시 소거
    // =====================================================================
    ARIA_Bridge::~ARIA_Bridge() noexcept {
        SecureMemory::secureWipe(static_cast<void*>(round_keys), ROUND_KEY_BUF_SIZE);
        num_rounds = 0;
        is_initialized = false;
    }

    // =====================================================================
    //  Reset — 명시적 키 소재 소거
    // =====================================================================
    void ARIA_Bridge::Reset() noexcept {
        SecureMemory::secureWipe(static_cast<void*>(round_keys), ROUND_KEY_BUF_SIZE);
        num_rounds = 0;
        is_initialized = false;
    }

    // =====================================================================
    //  Initialize_Encryption
    // =====================================================================
    bool ARIA_Bridge::Initialize_Encryption(
        const uint8_t* master_key, int key_bits) noexcept {

        return Do_KeySetup(
            master_key, key_bits,
            round_keys, num_rounds, is_initialized, true);
    }

    // =====================================================================
    //  Initialize_Decryption
    // =====================================================================
    bool ARIA_Bridge::Initialize_Decryption(
        const uint8_t* master_key, int key_bits) noexcept {

        return Do_KeySetup(
            master_key, key_bits,
            round_keys, num_rounds, is_initialized, false);
    }

    // =====================================================================
    //  Process_Block — ARIA 16바이트 블록 암/복호화
    //
    //  실패 시 출력 16바이트 소거 — 키스트림·이전 버퍼 잔존 방지
    // =====================================================================
    bool ARIA_Bridge::Process_Block(
        const uint8_t* input_16bytes,
        uint8_t* output_16bytes) noexcept {

        if (!is_initialized ||
            !input_16bytes ||
            !output_16bytes ||
            !Is_Valid_Round_Count(num_rounds)) {
            if (output_16bytes) {
                SecureMemory::secureWipe(static_cast<void*>(output_16bytes), 16u);
            }
            return false;
        }

        // in-place 미지원 (KISA Crypt 함수 제약)
        if (input_16bytes == output_16bytes) {
            SecureMemory::secureWipe(static_cast<void*>(output_16bytes), 16u);
            return false;
        }

        alignas(4) uint8_t aligned_in[16];
        alignas(4) uint8_t aligned_out[16];
        std::memcpy(aligned_in, input_16bytes, sizeof(aligned_in));
        SecureMemory::secureWipe(static_cast<void*>(aligned_out), sizeof(aligned_out));

        Crypt(
            reinterpret_cast<const Byte*>(aligned_in),
            num_rounds,
            reinterpret_cast<const Byte*>(round_keys),
            reinterpret_cast<Byte*>(aligned_out)
        );

        std::memcpy(output_16bytes, aligned_out, sizeof(aligned_out));
        SecureMemory::secureWipe(static_cast<void*>(aligned_in), sizeof(aligned_in));
        SecureMemory::secureWipe(static_cast<void*>(aligned_out), sizeof(aligned_out));

        return true;
    }

} // namespace ProtectedEngine
