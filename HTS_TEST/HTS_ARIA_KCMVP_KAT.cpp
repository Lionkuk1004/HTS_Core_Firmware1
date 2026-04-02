// =========================================================================
//  HTS_ARIA_KCMVP_KAT.cpp  —  KCMVP ARIA-128/192/256 ECB KAT
//
//  [프로젝트 컴파일 대상]
//  ✅ HTS_ARIA_KCMVP_KAT.cpp   ← 이 파일 (main)
//  ✅ HTS_ARIA_Bridge.cpp        ← MUT (aria.c는 브릿지 내부 링크)
//  ✅ HTS_Secure_Memory.cpp
//  ❌ 기타 main 포함 파일 모두 제외
//
//  빌드 (MSVC) — aria.c는 MUT(브릿지) 링크용만; KAT 기대값 생성에 사용하지 않음
//    cl.exe /EHsc /std:c++17
//           HTS_ARIA_KCMVP_KAT.cpp HTS_ARIA_Bridge.cpp HTS_Secure_Memory.cpp aria.c
//           /Fe:ARIA_KAT.exe
//  빌드 (GCC):
//    g++ -std=c++17 -O2
//        HTS_ARIA_KCMVP_KAT.cpp HTS_ARIA_Bridge.cpp HTS_Secure_Memory.cpp aria.c
//        -o ARIA_KAT
//
//  [KCMVP 근거]
//  규격 : KS X 1213-1
//  벡터 : KISA ARIA 공식 테스트 벡터 (seed.kisa.or.kr)
//
//  [KCMVP KAT] Known Answer = 검증된 **정적** 기대값만
//  · 기대 암호문: RFC 5794 Appendix A (또는 seed.kisa.or.kr 공식 하드카피) 상수 하드코딩
//  · 런타임에 aria.c 등으로 정답을 계산(캡처)하면 안 됨 — 동일 툴체인 편향 시 오동작
//    이 참조와 MUT가 동일 오류로 일치하는 블라인드 스팟 + 시험 규격 미달
//  · 검증: MUT(ARIA_Bridge) 암·복호·키변조만 상수 Expected와 교차 검증
// =========================================================================

#include "HTS_ARIA_Bridge.hpp"
#include "HTS_Secure_Memory.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <cstdlib>
#include <cstdint>

// =========================================================================
//  유틸리티 — D-2: 스택 버퍼 소거는 SecureMemory::secureWipe
// =========================================================================
static void SZ(void* p, size_t n) noexcept {
    ProtectedEngine::SecureMemory::secureWipe(p, n);
}

/// @brief 상수 시간 바이트열 동등 비교 (H-1, 타이밍 누출 완화)
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
//  KAT 벡터 구조체
//  ciphertext[16]: **사전 검증된 정적 정답** (런타임 생성 금지)
// =========================================================================
struct KAT_Vector {
    const char* name;
    int         key_bits;
    uint8_t     key[32];
    uint8_t     plaintext[16];
    uint8_t     ciphertext[16];
};

// =========================================================================
//  RFC 5794 Appendix A — Example Data (ECB 1블록, 공식 정적 벡터)
//  출처: https://www.rfc-editor.org/rfc/rfc5794 (동일 벡터는 seed.kisa.or.kr 대조 가능)
//
//  추가 벡터(영벡터 등)는 반드시 공식 문서에서 확인한 16바이트 CT를 **상수로만** 추가할 것.
// =========================================================================
static KAT_Vector KAT_TABLE[] = {

    // A.1  128-Bit Key — CT: d718fbd6ab644c739da95f3be6451778
    {
        "ARIA-128-ECB RFC5794 A.1",
        128,
        {
            0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
            0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0
        },
        {
            0x00,0x11,0x22,0x33, 0x44,0x55,0x66,0x77,
            0x88,0x99,0xAA,0xBB, 0xCC,0xDD,0xEE,0xFF
        },
        {
            0xD7,0x18,0xFB,0xD6, 0xAB,0x64,0x4C,0x73,
            0x9D,0xA9,0x5F,0x3B, 0xE6,0x45,0x17,0x78
        }
    },

    // A.2  192-Bit Key — CT: 26449c1805dbe7aa25a468ce263a9e79
    {
        "ARIA-192-ECB RFC5794 A.2",
        192,
        {
            0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
            0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F,
            0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
            0,0,0,0,0,0,0,0
        },
        {
            0x00,0x11,0x22,0x33, 0x44,0x55,0x66,0x77,
            0x88,0x99,0xAA,0xBB, 0xCC,0xDD,0xEE,0xFF
        },
        {
            0x26,0x44,0x9C,0x18, 0x05,0xDB,0xE7,0xAA,
            0x25,0xA4,0x68,0xCE, 0x26,0x3A,0x9E,0x79
        }
    },

    // A.3  256-Bit Key — CT: f92bd7c79fb72e2f2b8f80c1972d24fc
    {
        "ARIA-256-ECB RFC5794 A.3",
        256,
        {
            0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
            0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F,
            0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
            0x18,0x19,0x1A,0x1B, 0x1C,0x1D,0x1E,0x1F
        },
        {
            0x00,0x11,0x22,0x33, 0x44,0x55,0x66,0x77,
            0x88,0x99,0xAA,0xBB, 0xCC,0xDD,0xEE,0xFF
        },
        {
            0xF9,0x2B,0xD7,0xC7, 0x9F,0xB7,0x2E,0x2F,
            0x2B,0x8F,0x80,0xC1, 0x97,0x2D,0x24,0xFC
        }
    },
};

static const size_t KAT_COUNT =
sizeof(KAT_TABLE) / sizeof(KAT_TABLE[0]);


// =========================================================================
//  KAT 검증 — 정적 Expected(RFC 5794 Appx A) vs MUT(ARIA_Bridge)
// =========================================================================
static bool KAT_Phase() {
    std::cout << "\n==========================================\n"
        << "  KAT 검증 — 정적 기대암호문 vs MUT [KCMVP KAT]\n"
        << "  (런타임 참조 라이브러리로 정답 생성 없음)\n"
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
            << "  1. 상수 Expected를 seed.kisa.or.kr 공식 문서와 대조 유지\n"
            << "  2. ECB / CBC / CTR 전 모드 KAT 완료\n"
            << "  3. 암호모듈 경계 정의서 및 보안정책서 작성\n"
            << "  4. 국정원 지정 시험기관 제출\n";
    }
    else {
        std::cout << "  판정 : 미통과 ✗\n"
            << "  FAIL 시 MUT(ARIA_Bridge) 및 키/모드 설정 재확인\n";
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
        << "  기대값 : RFC 5794 Appendix A 정적 상수\n"
        << "==========================================\n";

    return KAT_Phase() ? EXIT_SUCCESS : EXIT_FAILURE;
}