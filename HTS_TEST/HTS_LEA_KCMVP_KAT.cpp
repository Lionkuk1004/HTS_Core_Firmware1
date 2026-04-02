// =========================================================================

//  HTS_LEA_KCMVP_KAT.cpp

//

//  [KCMVP KAT — LEA] Known Answer = 검증된 **정적** 기대암호문만

//  · CTR 기대값: KISA lea_ctr_enc와 동일 구현(MSVC로 1회 산출) 상수 하드코딩

//  · MUT(LEA_Bridge)로 런타임 캡처하여 expected를 채우면 안 됨(자기 참조/Tautology)

//

//  [프로젝트 컴파일 대상 — 정확히 이 3개 파일만 포함]

//  ✅ HTS_LEA_KCMVP_KAT.cpp    ← 이 파일 (main)

//  ✅ HTS_LEA_Bridge.cpp        ← LEA_Bridge 구현체

//  ✅ lea_base.c … lea_t_generic.c  ← KISA LEA (vcxproj와 동일)

//

//  ❌ 반드시 프로젝트에서 제외 (중복 main / 중복 심볼 원인)

//     HTS_LEA_Bridge_Test_Main.cpp

//     HTS_LEA_KCMVP_KAT_Unified.cpp

//

//  빌드 (MSVC) — lea_*.c는 MUT(브릿지) 링크용; KAT 기대값 생성에 사용하지 않음

//    cl.exe /EHsc /std:c++17

//           HTS_LEA_KCMVP_KAT.cpp HTS_LEA_Bridge.cpp lea_base.c lea_core.c ...

//           /Fe:KAT.exe

//  빌드 (GCC):

//    g++ -std=c++17 -O2

//        HTS_LEA_KCMVP_KAT.cpp HTS_LEA_Bridge.cpp lea_*.c -o KAT

// =========================================================================



#include "HTS_LEA_Bridge.h"

#include "HTS_Secure_Memory.h"

#include <iostream>

#include <iomanip>

#include <cstring>

#include <cstdlib>

#include <cstdint>



// =========================================================================

//  유틸리티 — D-2 / X-5-1: SecureMemory::secureWipe

// =========================================================================

static void SZ(void* p, size_t n) noexcept {

    ProtectedEngine::SecureMemory::secureWipe(p, n);

}



static bool CT_Eq(const uint8_t* a, const uint8_t* b, size_t n) noexcept {

    if (a == nullptr || b == nullptr) {

        return false;

    }

    if (n == 0u) {

        return true;

    }

    uint32_t diff = 0u;

    for (size_t i = 0u; i < n; ++i) {

        diff |= static_cast<uint32_t>(a[i] ^ b[i]);

    }

    return diff == 0u;

}



static void PHex(const char* lbl, const uint8_t* data, size_t len) {

    if (lbl == nullptr) {

        return;

    }

    std::ios_base::fmtflags f = std::cout.flags();

    std::cout << lbl;

    if (data != nullptr && len > 0u) {

        for (size_t i = 0u; i < len; ++i) {

            std::cout << std::hex << std::setw(2) << std::setfill('0')

                << static_cast<unsigned>(data[i]);

        }

    }

    std::cout.flags(f);

    std::cout << "\n";

}



// =========================================================================

//  KAT 벡터 — ciphertext[16]: 사전 검증된 정적 정답 (런타임 캡처 금지)

// =========================================================================

struct KAT_Vector {

    const char* name;

    int         key_bits;

    uint8_t     key[32];

    uint8_t     iv[16];

    uint8_t     plaintext[16];

    uint8_t     ciphertext[16];

};



// =========================================================================

//  LEA-CTR — 동일 키·IV·평문에 대한 기대 암호문 (KISA lea_ctr_enc, 16바이트 1블록)

//  LEA-128: 83a66e660b183b9b5030197460dfd061

//  LEA-192: be10c838105493065b870e6bb4562ded

//  LEA-256: 6d49f45095bd1fbb51fe8b3b4cc2f877

// =========================================================================

static KAT_Vector KAT_TABLE[] = {



    {   "LEA-128-CTR",

        128,

        { 0x0F,0x1E,0x2D,0x3C, 0x4B,0x5A,0x69,0x78,

          0x87,0x96,0xA5,0xB4, 0xC3,0xD2,0xE1,0xF0,

          0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0 },

        { 0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,

          0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F },

        { 0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,

          0x18,0x19,0x1A,0x1B, 0x1C,0x1D,0x1E,0x1F },

        {

            0x83,0xA6,0x6E,0x66, 0x0B,0x18,0x3B,0x9B,

            0x50,0x30,0x19,0x74, 0x60,0xDF,0xD0,0x61

        }

    },



    {   "LEA-192-CTR",

        192,

        { 0x0F,0x1E,0x2D,0x3C, 0x4B,0x5A,0x69,0x78,

          0x87,0x96,0xA5,0xB4, 0xC3,0xD2,0xE1,0xF0,

          0xF0,0xE1,0xD2,0xC3, 0xB4,0xA5,0x96,0x87,

          0,0,0,0,0,0,0,0 },

        { 0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,

          0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F },

        { 0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,

          0x18,0x19,0x1A,0x1B, 0x1C,0x1D,0x1E,0x1F },

        {

            0xBE,0x10,0xC8,0x38, 0x10,0x54,0x93,0x06,

            0x5B,0x87,0x0E,0x6B, 0xB4,0x56,0x2D,0xED

        }

    },



    {   "LEA-256-CTR",

        256,

        { 0x0F,0x1E,0x2D,0x3C, 0x4B,0x5A,0x69,0x78,

          0x87,0x96,0xA5,0xB4, 0xC3,0xD2,0xE1,0xF0,

          0xF0,0xE1,0xD2,0xC3, 0xB4,0xA5,0x96,0x87,

          0x78,0x69,0x5A,0x4B, 0x3C,0x2D,0x1E,0x0F },

        { 0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,

          0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F },

        { 0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,

          0x18,0x19,0x1A,0x1B, 0x1C,0x1D,0x1E,0x1F },

        {

            0x6D,0x49,0xF4,0x50, 0x95,0xBD,0x1F,0xBB,

            0x51,0xFE,0x8B,0x3B, 0x4C,0xC2,0xF8,0x77

        }

    },

};



static const size_t KAT_COUNT =

    sizeof(KAT_TABLE) / sizeof(KAT_TABLE[0]);



namespace {

    using ProtectedEngine::LEA_Bridge;



    static bool lea_ok(uint32_t r) noexcept {

        return r == LEA_Bridge::SECURE_TRUE;

    }

}



// =========================================================================

//  KAT 검증 — 정적 Expected vs MUT(LEA_Bridge)

// =========================================================================

static bool KAT_Phase() {

    std::cout << "\n==========================================\n"

        << "  KAT 검증 — 정적 기대암호문 vs MUT [KCMVP KAT — LEA]\n"

        << "  (런타임 캡처/자기 참조 없음)\n"

        << "==========================================\n";



    int pass = 0, fail = 0;



    for (size_t i = 0; i < KAT_COUNT; ++i) {

        const KAT_Vector& v = KAT_TABLE[i];



        std::cout << "\n------------------------------------------\n"

            << "  [KAT] " << v.name << "\n"

            << "------------------------------------------\n";



        const size_t kbytes = static_cast<size_t>(v.key_bits / 8);

        PHex("  Key       : ", v.key, kbytes);

        PHex("  IV        : ", v.iv, 16);

        PHex("  Plaintext : ", v.plaintext, 16);

        PHex("  Expected  : ", v.ciphertext, 16);



        // uint32_t[4]: 4바이트 정렬 보장 — reinterpret_cast(uint8_t*) 비정렬 회피 (B-2)

        uint32_t work[4] = {};

        std::memcpy(work, v.plaintext, 16);



        bool kat_ok = true;

        bool enc_ok = false;

        {

            LEA_Bridge bridge;

            const uint32_t klen = static_cast<uint32_t>(kbytes);

            if (lea_ok(bridge.Initialize(v.key, klen, v.iv))) {

                enc_ok = lea_ok(bridge.Encrypt_Payload(work, 4));

            }

        }



        if (!enc_ok) {

            std::cout << "  [FAIL] Encrypt_Payload 실패\n";

            ++fail;

            SZ(work, sizeof(work));

            continue;

        }



        const uint8_t* const act = reinterpret_cast<const uint8_t*>(work);

        PHex("  Actual    : ", act, 16);



        const bool enc_match = CT_Eq(act, v.ciphertext, 16);

        std::cout << (enc_match

            ? "  [PASS] 암호문 일치 — KAT 통과\n"

            : "  [FAIL] 암호문 불일치\n");

        if (!enc_match) {

            kat_ok = false;

        }



        // 복호화 역방향 검증

        {

            uint32_t dec[4] = {};

            std::memcpy(dec, act, 16);

            bool rev_ok = false;

            {

                LEA_Bridge bridge;

                if (lea_ok(bridge.Initialize(

                    v.key, static_cast<uint32_t>(kbytes), v.iv))) {

                    const bool d = lea_ok(bridge.Decrypt_Payload(dec, 4));

                    rev_ok = d && CT_Eq(

                        reinterpret_cast<const uint8_t*>(dec),

                        v.plaintext, 16);

                }

            }

            std::cout << (rev_ok

                ? "  [PASS] 복호화 역방향 검증 통과\n"

                : "  [FAIL] 복호화 역방향 검증 실패\n");

            if (!rev_ok) {

                kat_ok = false;

            }

            SZ(dec, sizeof(dec));

        }



        SZ(work, sizeof(work));

        kat_ok ? ++pass : ++fail;

    }



    std::cout << "\n==========================================\n"

        << "  KAT 최종 결과\n"

        << "  PASS : " << pass << " / " << KAT_COUNT << "\n"

        << "  FAIL : " << fail << " / " << KAT_COUNT << "\n";



    if (fail == 0) {

        std::cout << "  판정 : 전체 통과 ✓\n\n"

            << "  [KCMVP 다음 단계]\n"

            << "  1. 상수 Expected를 공식 벡터·외부 산출값과 대조 유지\n"

            << "  2. ECB / CBC / CTR 전 모드 KAT 완료\n"

            << "  3. 암호모듈 경계 정의서 및 보안정책서 작성\n"

            << "  4. 국정원 지정 시험기관 제출\n";

    }

    else {

        std::cout << "  판정 : 미통과 ✗\n"

            << "  FAIL 시 MUT(LEA_Bridge) 및 KISA lea 라이브러리 재확인\n";

    }

    std::cout << "==========================================\n";



    return (fail == 0);

}





// =========================================================================

//  main

// =========================================================================

int main() {

    std::cout << "==========================================\n"

        << "  KCMVP LEA-CTR KAT (Known Answer Test)\n"

        << "  근거 : KISA LEA + 정적 CTR 기대암호문\n"

        << "  목적 : KCMVP 제출 전 자가 사전 검증\n"

        << "  기대값 : 외부 산출 상수 (런타임 캡처 없음)\n"

        << "==========================================\n";



    return KAT_Phase() ? EXIT_SUCCESS : EXIT_FAILURE;

}


