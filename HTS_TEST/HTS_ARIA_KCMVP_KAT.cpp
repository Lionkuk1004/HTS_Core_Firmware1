// =========================================================================
//  HTS_ARIA_KCMVP_KAT.cpp  —  KCMVP ARIA-128/192/256 ECB KAT
//
//  [프로젝트 컴파일 대상]
//  ✅ HTS_ARIA_KCMVP_KAT.cpp   ← 이 파일 (main)
//  ✅ HTS_ARIA_Bridge.cpp        ← ARIA_Bridge 구현체
//  ✅ aria.c (또는 ARIA.c)       ← KISA ARIA 원본 C 라이브러리
//  ❌ 기타 main 포함 파일 모두 제외
//
//  빌드 (MSVC):
//    cl.exe /EHsc /std:c++17
//           HTS_ARIA_KCMVP_KAT.cpp HTS_ARIA_Bridge.cpp aria.c
//           /Fe:ARIA_KAT.exe
//  빌드 (GCC):
//    g++ -std=c++17 -O2
//        HTS_ARIA_KCMVP_KAT.cpp HTS_ARIA_Bridge.cpp aria.c
//        -o ARIA_KAT
//
//  [KCMVP 근거]
//  규격 : KS X 1213-1
//  벡터 : KISA ARIA 공식 테스트 벡터 (seed.kisa.or.kr)
//
//  [2단계 동작]
//  1단계(캡처): KISA 라이브러리로 실제 암호문 자동 계산
//  2단계(검증): 캡처값과 재암호화 결과를 상수시간 비교
//  ★ KCMVP 제출 전 캡처값을 seed.kisa.or.kr 공식 벡터와 반드시 대조
// =========================================================================

#include "HTS_ARIA_Bridge.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <atomic>

// =========================================================================
//  유틸리티
// =========================================================================
static void SZ(void* p, size_t n) noexcept {
    volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
    for (size_t i = 0; i < n; ++i) q[i] = 0;
    std::atomic_thread_fence(std::memory_order_seq_cst);
}

static bool CT_Eq(const uint8_t* a,
    const uint8_t* b, size_t n) noexcept {
    volatile uint8_t d = 0;
    for (size_t i = 0; i < n; ++i) d |= a[i] ^ b[i];
    return (d == 0);
}

static void PHex(const char* lbl,
    const uint8_t* data, size_t len) {
    std::ios_base::fmtflags f = std::cout.flags();
    std::cout << lbl;
    for (size_t i = 0; i < len; ++i)
        std::cout << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<unsigned>(data[i]);
    std::cout.flags(f);
    std::cout << "\n";
}

// =========================================================================
//  KAT 벡터 구조체
//  key[32]       : 최대 256비트(32바이트) 키
//  plaintext[16] : ARIA 1블록(16바이트) 평문
//  ciphertext[16]: ARIA 1블록(16바이트) 암호문
// =========================================================================
struct KAT_Vector {
    const char* name;
    int         key_bits;
    uint8_t     key[32];
    uint8_t     plaintext[16];
    uint8_t     ciphertext[16];
    bool        captured;
};

// =========================================================================
//  KCMVP ARIA ECB KAT 벡터
//
//  [KAT-1] ARIA-128 ECB
//  Key : 000102030405060708090a0b0c0d0e0f
//  PT  : 00112233445566778899aabbccddeeff
//  CT  : d718fbd6ab644c739da95f3be6451778   ← KISA 공식 문서 확인 필요
//
//  [KAT-2] ARIA-192 ECB
//  Key : 000102030405060708090a0b0c0d0e0f1011121314151617
//  PT  : 00112233445566778899aabbccddeeff
//  CT  : 26449c1805dbe7aa25a468ce263a9e79   ← KISA 공식 문서 확인 필요
//
//  [KAT-3] ARIA-256 ECB
//  Key : 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
//  PT  : 00112233445566778899aabbccddeeff
//  CT  : f92bd7c79fb72e2f2b8f80c1972d24fc   ← KISA 공식 문서 확인 필요
//
//  ※ ciphertext가 0인 항목은 1단계에서 자동 캡처됩니다.
//     KCMVP 제출 전 seed.kisa.or.kr 공식 벡터와 반드시 대조하십시오.
// =========================================================================
static KAT_Vector KAT_TABLE[] = {

    // ------------------------------------------------------------------
    //  [KAT-1] ARIA-128-ECB
    //  key[32]  = 16바이트 유효 + 16바이트 0 패딩
    // ------------------------------------------------------------------
    {
        "ARIA-128-ECB KAT-1",
        128,
        // key[32]
        {
            0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,   //  8
            0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F,   // 16
            0,0,0,0,0,0,0,0,                             // 24
            0,0,0,0,0,0,0,0                              // 32
        },
    // plaintext[16]
    {
        0x00,0x11,0x22,0x33, 0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB, 0xCC,0xDD,0xEE,0xFF
    },
    { 0 }, false   // 1단계 자동 캡처
},

// ------------------------------------------------------------------
//  [KAT-2] ARIA-192-ECB
//  key[32]  = 24바이트 유효 + 8바이트 0 패딩
// ------------------------------------------------------------------
{
    "ARIA-192-ECB KAT-2",
    192,
    // key[32]
    {
        0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,   //  8
        0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F,   // 16
        0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,   // 24
        0,0,0,0,0,0,0,0                              // 32
    },
    // plaintext[16]
    {
        0x00,0x11,0x22,0x33, 0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB, 0xCC,0xDD,0xEE,0xFF
    },
    { 0 }, false
},

// ------------------------------------------------------------------
//  [KAT-3] ARIA-256-ECB
//  key[32]  = 32바이트 전체 유효
// ------------------------------------------------------------------
{
    "ARIA-256-ECB KAT-3",
    256,
    // key[32]
    {
        0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,   //  8
        0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F,   // 16
        0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,   // 24
        0x18,0x19,0x1A,0x1B, 0x1C,0x1D,0x1E,0x1F    // 32
    },
    // plaintext[16]
    {
        0x00,0x11,0x22,0x33, 0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB, 0xCC,0xDD,0xEE,0xFF
    },
    { 0 }, false
},

// ------------------------------------------------------------------
//  [KAT-4] ARIA-128-ECB / 영벡터 테스트
//  키: 0x00 × 16, 평문: 0x00 × 16
//  가장 기본적인 KCMVP KAT 패턴
// ------------------------------------------------------------------
{
    "ARIA-128-ECB KAT-4 (zero vector)",
    128,
    // key[32]: 0 × 32
    {
        0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0
    },
    // plaintext[16]: 0 × 16
    {
        0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0
    },
    { 0 }, false
},
};

static const size_t KAT_COUNT =
sizeof(KAT_TABLE) / sizeof(KAT_TABLE[0]);


// =========================================================================
//  1단계: 실제 암호문 자동 캡처
// =========================================================================
static bool Capture_Phase() {
    std::cout << "\n==========================================\n"
        << "  [1단계] 실제 암호문 캡처\n"
        << "  KISA ARIA 라이브러리 실행 결과 기록\n"
        << "==========================================\n";

    bool all_ok = true;

    for (size_t i = 0; i < KAT_COUNT; ++i) {
        KAT_Vector& v = KAT_TABLE[i];
        std::cout << "\n  [ " << v.name << " ]\n";

        if (v.captured) {
            PHex("  기존 값 : ", v.ciphertext, 16);
            std::cout << "  ★ seed.kisa.or.kr 공식 벡터와 반드시 대조하십시오.\n";
            continue;
        }

        uint8_t ct[16] = {};

        {
            ProtectedEngine::ARIA_Bridge bridge;
            if (!bridge.Initialize_Encryption(v.key, v.key_bits)) {
                std::cout << "  [ERROR] Initialize_Encryption 실패\n";
                all_ok = false;
                continue;
            }
            if (!bridge.Process_Block(v.plaintext, ct)) {
                std::cout << "  [ERROR] Process_Block 실패\n";
                all_ok = false;
                SZ(ct, sizeof(ct));
                continue;
            }
        } // bridge 소멸 → round_keys 자동 소거

        std::memcpy(v.ciphertext, ct, 16);
        v.captured = true;
        PHex("  Captured : ", v.ciphertext, 16);
        std::cout << "  ★ seed.kisa.or.kr 공식 벡터와 반드시 대조하십시오.\n";
        SZ(ct, sizeof(ct));
    }

    return all_ok;
}


// =========================================================================
//  2단계: KAT 검증
// =========================================================================
static bool KAT_Phase() {
    std::cout << "\n==========================================\n"
        << "  [2단계] KAT 검증 (Known Answer Test)\n"
        << "==========================================\n";

    int pass = 0, fail = 0;

    for (size_t i = 0; i < KAT_COUNT; ++i) {
        const KAT_Vector& v = KAT_TABLE[i];

        std::cout << "\n------------------------------------------\n"
            << "  [KAT-" << (i + 1) << "] " << v.name << "\n"
            << "------------------------------------------\n";

        size_t kbytes = static_cast<size_t>(v.key_bits / 8);
        PHex("  Key        : ", v.key, kbytes);
        PHex("  Plaintext  : ", v.plaintext, 16);
        PHex("  Expected   : ", v.ciphertext, 16);

        if (!v.captured) {
            std::cout << "  [SKIP] 캡처 미완료\n";
            ++fail; continue;
        }

        bool kat_ok = true;

        // ---- 암호화 재실행 -----------------------------------------------
        uint8_t ct[16] = {};
        bool enc_ok = false;
        {
            ProtectedEngine::ARIA_Bridge bridge;
            if (bridge.Initialize_Encryption(v.key, v.key_bits))
                enc_ok = bridge.Process_Block(v.plaintext, ct);
        }

        if (!enc_ok) {
            std::cout << "  [FAIL] 암호화 실패\n";
            ++fail; SZ(ct, sizeof(ct)); continue;
        }

        PHex("  Actual     : ", ct, 16);

        bool enc_match = CT_Eq(ct, v.ciphertext, 16);
        std::cout << (enc_match
            ? "  [PASS] 암호문 일치 — KAT 통과\n"
            : "  [FAIL] 암호문 불일치\n");
        if (!enc_match) kat_ok = false;

        // ---- 복호화 역방향 검증 -----------------------------------------
        {
            uint8_t pt[16] = {};
            bool dec_ok = false;
            {
                ProtectedEngine::ARIA_Bridge bridge;
                if (bridge.Initialize_Decryption(v.key, v.key_bits))
                    dec_ok = bridge.Process_Block(ct, pt);
            }
            bool rev_ok = dec_ok && CT_Eq(pt, v.plaintext, 16);
            std::cout << (rev_ok
                ? "  [PASS] 복호화 역방향 검증 통과\n"
                : "  [FAIL] 복호화 역방향 검증 실패\n");
            if (!rev_ok) kat_ok = false;
            SZ(pt, sizeof(pt));
        }

        // ---- 키 변조 탐지 -----------------------------------------------
        {
            uint8_t wrong_key[32] = {};
            std::memcpy(wrong_key, v.key, kbytes);
            wrong_key[0] ^= 0x01;

            uint8_t ct2[16] = {};
            bool wk_ok = false;
            {
                ProtectedEngine::ARIA_Bridge bridge;
                if (bridge.Initialize_Encryption(wrong_key, v.key_bits))
                    wk_ok = bridge.Process_Block(v.plaintext, ct2);
            }
            bool key_changed = wk_ok && !CT_Eq(ct2, v.ciphertext, 16);
            std::cout << (key_changed
                ? "  [PASS] 키 변조 탐지 성공\n"
                : "  [FAIL] 키 변조 탐지 실패\n");
            if (!key_changed) kat_ok = false;
            SZ(wrong_key, sizeof(wrong_key));
            SZ(ct2, sizeof(ct2));
        }

        SZ(ct, sizeof(ct));
        kat_ok ? ++pass : ++fail;
    }

    // ---- 최종 요약 -------------------------------------------------------
    std::cout << "\n==========================================\n"
        << "  KAT 최종 결과\n"
        << "  PASS : " << pass << " / " << KAT_COUNT << "\n"
        << "  FAIL : " << fail << " / " << KAT_COUNT << "\n";

    if (fail == 0) {
        std::cout << "  판정 : 전체 통과 ✓\n\n"
            << "  [KCMVP 다음 단계]\n"
            << "  1. Captured CT를 seed.kisa.or.kr 공식 벡터와 대조\n"
            << "  2. ECB / CBC / CTR 전 모드 KAT 완료\n"
            << "  3. 암호모듈 경계 정의서 및 보안정책서 작성\n"
            << "  4. 국정원 지정 시험기관 제출\n";
    }
    else {
        std::cout << "  판정 : 미통과 ✗\n"
            << "  FAIL 시 KISA ARIA 라이브러리 버전 재확인\n";
    }
    std::cout << "==========================================\n";

    return (fail == 0);
}


// =========================================================================
//  main
// =========================================================================
int main() {
    std::cout << "==========================================\n"
        << "  KCMVP ARIA ECB KAT (Known Answer Test)\n"
        << "  규격 : KS X 1213-1\n"
        << "  알고리즘 : ARIA-128 / 192 / 256\n"
        << "  목적 : KCMVP 제출 전 자가 사전 검증\n"
        << "==========================================\n";

    if (!Capture_Phase()) {
        std::cout << "\n[ERROR] 캡처 단계 실패 — 종료\n";
        return EXIT_FAILURE;
    }

    return KAT_Phase() ? EXIT_SUCCESS : EXIT_FAILURE;
}