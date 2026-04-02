// =========================================================================
// HTS_AES_Bridge.cpp
// FIPS 197 AES 블록 암호 구현부 (자체 구현 — 외부 의존 0)
// Target: STM32F407 (Cortex-M4) / Cortex-A55 / PC
//
// [구현 규격]
//  FIPS 197: Advanced Encryption Standard (AES)
//  블록: 128비트 (Nb=4), 키: 128/192/256비트
//  라운드: AES-128=10, AES-192=12, AES-256=14
//
// [보안 설계]
//  - S-box/InvS-box: constexpr Flash 배치 (SRAM 0B)
//  - MixColumns: xtime 매크로 (LUT 없음 — 타이밍 일정)
//  - 키 스케줄: 로컬 배열 (스택 ≤ 240B)
//  - 소멸자/Reset: 키 소재 3중 보안 소거
//
// [제약] try-catch 0, float/double 0, heap 0, iostream 0
// =========================================================================
#include "HTS_AES_Bridge.h"

#include <atomic>
#include <cstdint>
#include <cstring>

namespace ProtectedEngine {

    // =====================================================================
    //  보안 소거 (asm clobber + release fence)
    // =====================================================================
    static void AES_Secure_Zero(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) return;
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) q[i] = 0u;
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  FIPS 197 S-box / Inverse S-box (constexpr — Flash/.rodata 배치)
    // =====================================================================
    static constexpr uint8_t SBOX[256] = {
        0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
        0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
        0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
        0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
        0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
        0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
        0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
        0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
        0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
        0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
        0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
        0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
        0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
        0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
        0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
        0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
    };

    static constexpr uint8_t INV_SBOX[256] = {
        0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
        0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
        0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
        0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
        0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
        0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
        0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
        0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
        0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
        0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
        0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
        0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
        0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
        0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
        0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
        0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
    };

    // =====================================================================
    //  FIPS 197 Rcon (라운드 상수)
    // =====================================================================
    static constexpr uint8_t RCON[11] = {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1B, 0x36
    };

    // =====================================================================
    //  GF(2^8) xtime — MixColumns 핵심 연산
    // =====================================================================
    static constexpr uint8_t xtime(uint8_t x) noexcept {
        return static_cast<uint8_t>(
            (static_cast<uint8_t>(x << 1u)) ^
            (((x >> 7u) & 1u) * 0x1Bu));
    }

    // =====================================================================
    //  AES 라운드 연산 — 상태 배열 column-major (FIPS 197 §3.4)
    //  state[16] = 4×4 바이트, column-major 순서
    // =====================================================================

    static void SubBytes(uint8_t* s) noexcept {
        for (int i = 0; i < 16; ++i) s[i] = SBOX[s[i]];
    }

    static void InvSubBytes(uint8_t* s) noexcept {
        for (int i = 0; i < 16; ++i) s[i] = INV_SBOX[s[i]];
    }

    // ShiftRows: FIPS 197 §5.1.2
    // state[r + 4*c] = column-major 순서
    // Row r를 r만큼 좌측 순환 시프트
    static void ShiftRows(uint8_t* s) noexcept {
        uint8_t t;
        // Row 1: left shift 1
        t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
        // Row 2: left shift 2
        t = s[2]; s[2] = s[10]; s[10] = t;
        t = s[6]; s[6] = s[14]; s[14] = t;
        // Row 3: left shift 3 = right shift 1
        t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
    }

    static void InvShiftRows(uint8_t* s) noexcept {
        uint8_t t;
        // Row 1: right shift 1
        t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
        // Row 2: right shift 2
        t = s[2]; s[2] = s[10]; s[10] = t;
        t = s[6]; s[6] = s[14]; s[14] = t;
        // Row 3: right shift 3 = left shift 1
        t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
    }

    // MixColumns: 각 열에 대해 GF(2^8) 행렬 곱
    static void MixColumns(uint8_t* s) noexcept {
        for (int c = 0; c < 4; ++c) {
            const int i = c * 4;
            const uint8_t a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
            const uint8_t x0 = xtime(a0), x1 = xtime(a1);
            const uint8_t x2 = xtime(a2), x3 = xtime(a3);
            s[i] = static_cast<uint8_t>(x0 ^ x1 ^ a1 ^ a2 ^ a3);
            s[i + 1] = static_cast<uint8_t>(a0 ^ x1 ^ x2 ^ a2 ^ a3);
            s[i + 2] = static_cast<uint8_t>(a0 ^ a1 ^ x2 ^ x3 ^ a3);
            s[i + 3] = static_cast<uint8_t>(x0 ^ a0 ^ a1 ^ a2 ^ x3);
        }
    }

    // Multiply by x in GF(2^8) — Constant-Time (bitmask, 데이터 의존 분기 없음)
    static constexpr uint8_t gmul(uint8_t a, uint8_t b) noexcept {
        uint8_t p = 0;
        for (int i = 0; i < 8; ++i) {
            // if (b & 1) p ^= a → 상수 시간
            p ^= static_cast<uint8_t>(a & static_cast<uint8_t>(
                0u - static_cast<uint8_t>(b & 1u)));
            const uint8_t hi = static_cast<uint8_t>(a >> 7u);
            a = static_cast<uint8_t>(a << 1u);
            // if (hi) a ^= 0x1B → 상수 시간 (부호 확장 마스크)
            a ^= static_cast<uint8_t>(
                static_cast<uint8_t>(0u - hi) & 0x1Bu);
            b = static_cast<uint8_t>(b >> 1u);
        }
        return p;
    }

    static void InvMixColumns(uint8_t* s) noexcept {
        for (int c = 0; c < 4; ++c) {
            const int i = c * 4;
            const uint8_t a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
            s[i] = static_cast<uint8_t>(
                gmul(a0, 0x0E) ^ gmul(a1, 0x0B) ^ gmul(a2, 0x0D) ^ gmul(a3, 0x09));
            s[i + 1] = static_cast<uint8_t>(
                gmul(a0, 0x09) ^ gmul(a1, 0x0E) ^ gmul(a2, 0x0B) ^ gmul(a3, 0x0D));
            s[i + 2] = static_cast<uint8_t>(
                gmul(a0, 0x0D) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0E) ^ gmul(a3, 0x0B));
            s[i + 3] = static_cast<uint8_t>(
                gmul(a0, 0x0B) ^ gmul(a1, 0x0D) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0E));
        }
    }

    static void AddRoundKey(uint8_t* s, const uint8_t* rk) noexcept {
        for (int i = 0; i < 16; ++i) s[i] ^= rk[i];
    }

    // =====================================================================
    //  키 확장 (FIPS 197 §5.2)
    // =====================================================================
    static bool AES_KeyExpansion(const uint8_t* key, int key_bits,
        uint8_t* expanded, int& nr) noexcept {

        int nk;  // 키 워드 수 (32비트 단위)
        switch (key_bits) {
        case 128: nk = 4; nr = 10; break;
        case 192: nk = 6; nr = 12; break;
        case 256: nk = 8; nr = 14; break;
        default: return false;
        }

        const int total_words = 4 * (nr + 1);  // 라운드 키 총 워드 수

        // W[0..Nk-1] = 키에서 직접 복사
        for (int i = 0; i < nk; ++i) {
            expanded[4 * i] = key[4 * i];
            expanded[4 * i + 1] = key[4 * i + 1];
            expanded[4 * i + 2] = key[4 * i + 2];
            expanded[4 * i + 3] = key[4 * i + 3];
        }

        uint8_t temp[4] = {};  // 루프 밖 선언 (소거 보장)
        for (int i = nk; i < total_words; ++i) {
            temp[0] = expanded[4 * (i - 1)];
            temp[1] = expanded[4 * (i - 1) + 1];
            temp[2] = expanded[4 * (i - 1) + 2];
            temp[3] = expanded[4 * (i - 1) + 3];

            if (i % nk == 0) {
                // RotWord + SubWord + Rcon
                const uint8_t t0 = temp[0];
                temp[0] = SBOX[temp[1]];
                temp[1] = SBOX[temp[2]];
                temp[2] = SBOX[temp[3]];
                temp[3] = SBOX[t0];
                temp[0] ^= RCON[i / nk];
            }
            else if (nk > 6 && (i % nk == 4)) {
                // SubWord only (AES-256 추가 단계)
                temp[0] = SBOX[temp[0]];
                temp[1] = SBOX[temp[1]];
                temp[2] = SBOX[temp[2]];
                temp[3] = SBOX[temp[3]];
            }

            expanded[4 * i] = expanded[4 * (i - nk)] ^ temp[0];
            expanded[4 * i + 1] = expanded[4 * (i - nk) + 1] ^ temp[1];
            expanded[4 * i + 2] = expanded[4 * (i - nk) + 2] ^ temp[2];
            expanded[4 * i + 3] = expanded[4 * (i - nk) + 3] ^ temp[3];
        }

        AES_Secure_Zero(temp, sizeof(temp));
        return true;
    }

    // =====================================================================
    //  AES 암호화 (FIPS 197 §5.1)
    // =====================================================================
    static void AES_Encrypt_Block(const uint8_t* in, uint8_t* out,
        const uint8_t* rk, int nr) noexcept {

        uint8_t state[16];
        std::memcpy(state, in, 16);

        AddRoundKey(state, rk);

        for (int round = 1; round < nr; ++round) {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, rk + round * 16);
        }

        // 최종 라운드 (MixColumns 없음)
        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, rk + nr * 16);

        std::memcpy(out, state, 16);
        AES_Secure_Zero(state, 16);
    }

    // =====================================================================
    //  AES 복호화 (FIPS 197 §5.3)
    // =====================================================================
    static void AES_Decrypt_Block(const uint8_t* in, uint8_t* out,
        const uint8_t* rk, int nr) noexcept {

        uint8_t state[16];
        std::memcpy(state, in, 16);

        AddRoundKey(state, rk + nr * 16);

        for (int round = nr - 1; round >= 1; --round) {
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, rk + round * 16);
            InvMixColumns(state);
        }

        // 최종 라운드 (InvMixColumns 없음)
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, rk);

        std::memcpy(out, state, 16);
        AES_Secure_Zero(state, 16);
    }

    // =====================================================================
    //  Bridge — 생성자/소멸자
    // =====================================================================
    AES_Bridge::AES_Bridge() noexcept
        : num_rounds(0), is_initialized(false), is_encrypt(false) {
        std::memset(round_keys, 0, sizeof(round_keys));
    }

    AES_Bridge::~AES_Bridge() noexcept {
        Reset();
    }

    void AES_Bridge::Reset() noexcept {
        AES_Secure_Zero(round_keys, sizeof(round_keys));
        num_rounds = 0;
        is_initialized = false;
        is_encrypt = false;
    }

    // =====================================================================
    //  Initialize_Encryption
    // =====================================================================
    bool AES_Bridge::Initialize_Encryption(
        const uint8_t* master_key, int key_bits) noexcept {

        Reset();
        if (master_key == nullptr) return false;
        if (key_bits != 128 && key_bits != 192 && key_bits != 256) return false;

        if (!AES_KeyExpansion(master_key, key_bits, round_keys, num_rounds)) {
            Reset();
            return false;
        }

        is_encrypt = true;
        is_initialized = true;
        return true;
    }

    // =====================================================================
    //  Initialize_Decryption
    // =====================================================================
    bool AES_Bridge::Initialize_Decryption(
        const uint8_t* master_key, int key_bits) noexcept {

        Reset();
        if (master_key == nullptr) return false;
        if (key_bits != 128 && key_bits != 192 && key_bits != 256) return false;

        if (!AES_KeyExpansion(master_key, key_bits, round_keys, num_rounds)) {
            Reset();
            return false;
        }

        is_encrypt = false;
        is_initialized = true;
        return true;
    }

    // =====================================================================
    //  Process_Block
    // =====================================================================
    bool AES_Bridge::Process_Block(
        const uint8_t* input_16bytes,
        uint8_t* output_16bytes) noexcept {

        if (!is_initialized || !input_16bytes || !output_16bytes) {
            if (output_16bytes) AES_Secure_Zero(output_16bytes, 16);
            return false;
        }

        //  In-place: AES_Encrypt/Decrypt_Block은 내부 state[16] 사용

        if (is_encrypt) {
            AES_Encrypt_Block(input_16bytes, output_16bytes, round_keys, num_rounds);
        }
        else {
            AES_Decrypt_Block(input_16bytes, output_16bytes, round_keys, num_rounds);
        }

        return true;
    }

} // namespace ProtectedEngine
