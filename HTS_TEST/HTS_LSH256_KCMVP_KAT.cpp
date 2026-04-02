// =========================================================================
//  HTS_LSH256_KCMVP_KAT.cpp  —  KCMVP LSH-256 / LSH-224 KAT
//
//  [KCMVP KAT — LSH] Known Answer = 검증된 **정적** 기대 해시만
//  · 기대값: NSR lsh256_digest와 동일 결과를 외부 1회 산출한 상수 (본 TU에서 캡처 금지)
//  · MUT(LSH256_Bridge)로 런타임 캡처하여 expected를 채우면 안 됨(자기 참조/Tautology)
//
//  [프로젝트 컴파일 대상]
//  ✅ HTS_LSH256_KCMVP_KAT.cpp  ← 이 파일 (main)
//  ✅ HTS_LSH256_Bridge.cpp
//  ✅ lsh256.c lsh512.c lsh.c   ← NSR LSH (브릿지 링크용; KAT 정답 생성에 사용하지 않음)
//
//  빌드 (MSVC):
//    cl.exe /EHsc /std:c++17
//           HTS_LSH256_KCMVP_KAT.cpp HTS_LSH256_Bridge.cpp HTS_Secure_Memory.cpp lsh256.c lsh512.c lsh.c
//           /Fe:LSH256_KAT.exe
// =========================================================================

#include "HTS_LSH256_Bridge.h"
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

static bool lsh_ok(uint32_t r) noexcept {
    return r == ProtectedEngine::LSH_SECURE_TRUE;
}

// =========================================================================
//  KAT 벡터 — expected: 사전 검증된 정적 정답 (런타임 캡처 금지)
// =========================================================================
struct KAT_Vector {
    const char* name;
    bool        is_256;
    uint8_t     message[128];
    size_t      msg_len;
    uint8_t     expected[32];
    size_t      out_len;
};

// 정적 기대값 — NSR lsh256_digest(동일 NSR 소스) 1회 산출
static KAT_Vector KAT_TABLE[] = {

    {
        "LSH-256 KAT-1 (empty message)",
        true,
        { 0 }, 0,
        {
            0xF3,0xCD,0x41,0x6A, 0x03,0x81,0x82,0x17,
            0x72,0x6C,0xB4,0x7F, 0x4E,0x4D,0x28,0x81,
            0xC9,0xC2,0x9F,0xD4, 0x45,0xC1,0x8B,0x66,
            0xFB,0x19,0xDE,0xA1, 0xA8,0x10,0x07,0xC1
        },
        32
    },

    {
        "LSH-256 KAT-2 (single 0x00)",
        true,
        {
            0x00,
            0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0
        },
        1,
        {
            0xCF,0x25,0xC4,0x7E, 0xB1,0xEF,0xA7,0x7D,
            0x2F,0x7A,0x1D,0xFC, 0xC0,0x9F,0x4D,0x3A,
            0xCF,0xE9,0x7D,0xC7, 0x7C,0x31,0x7B,0x43,
            0x97,0x6E,0x7B,0x23, 0x8D,0xA3,0xDC,0x71
        },
        32
    },

    {
        "LSH-256 KAT-3 (\"abc\")",
        true,
        {
            0x61,0x62,0x63,
            0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0
        },
        3,
        {
            0x5F,0xBF,0x36,0x5D, 0xAE,0xA5,0x44,0x6A,
            0x70,0x53,0xC5,0x2B, 0x57,0x40,0x4D,0x77,
            0xA0,0x7A,0x5F,0x48, 0xA1,0xF7,0xC1,0x96,
            0x3A,0x08,0x98,0xBA, 0x1B,0x71,0x47,0x41
        },
        32
    },

    {
        "LSH-224 KAT-4 (\"abc\")",
        false,
        {
            0x61,0x62,0x63,
            0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0
        },
        3,
        {
            0xF7,0xC5,0x3B,0xA4, 0x03,0x4E,0x70,0x8E,
            0x74,0xFB,0xA4,0x2E, 0x55,0x99,0x7C,0xA5,
            0x12,0x6B,0xB7,0x62, 0x36,0x88,0xF8,0x53,
            0x42,0xF7,0x37,0x32,
            0,0,0,0
        },
        28
    },

    {
        "LSH-256 KAT-5 (B-CDMA payload)",
        true,
        {
            0xB0,0xCD,0xAB,0x01, 0x00,0x01,0x02,0x03,
            0x04,0x05,0x06,0x07, 0x08,0x09,0x0A,0x0B,
            0x0C,0x0D,0x0E,0x0F, 0x10,0x11,0x12,0x13,
            0x14,0x15,0x16,0x17, 0x18,0x19,0x1A,0x1B,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0
        },
        32,
        {
            0x94,0x1A,0x4A,0xA3, 0xBB,0x26,0xFF,0x8A,
            0x45,0x65,0x29,0x27, 0x79,0xA5,0x1E,0xC1,
            0x1E,0x21,0x88,0xA6, 0x69,0xCF,0x47,0x61,
            0x9C,0xA1,0xFC,0xB2, 0x20,0xA7,0xA8,0x06
        },
        32
    },
};

static const size_t KAT_COUNT =
    sizeof(KAT_TABLE) / sizeof(KAT_TABLE[0]);

// =========================================================================
//  KAT 검증 — 정적 Expected vs MUT(LSH256_Bridge)
// =========================================================================
static bool KAT_Phase() {
    std::cout << "\n==========================================\n"
        << "  KAT 검증 — 정적 기대 해시 vs MUT [KCMVP KAT — LSH]\n"
        << "  (런타임 캡처/자기 참조 없음)\n"
        << "==========================================\n";

    int pass = 0, fail = 0;

    for (size_t i = 0; i < KAT_COUNT; ++i) {
        const KAT_Vector& v = KAT_TABLE[i];

        std::cout << "\n------------------------------------------\n"
            << "  [KAT-" << (i + 1) << "] " << v.name << "\n"
            << "------------------------------------------\n";

        if (v.msg_len > 0u) {
            PHex("  Message  : ", v.message, v.msg_len);
        }
        else {
            std::cout << "  Message  : (empty)\n";
        }

        PHex("  Expected : ", v.expected, v.out_len);

        uint8_t computed[32] = {};
        bool hash_ok = false;
        if (v.is_256) {
            hash_ok = lsh_ok(ProtectedEngine::LSH256_Bridge::Hash_256(
                v.message, v.msg_len, computed));
        }
        else {
            hash_ok = lsh_ok(ProtectedEngine::LSH256_Bridge::Hash_224(
                v.message, v.msg_len, computed));
        }

        if (!hash_ok) {
            std::cout << "  [FAIL] 해시 계산 실패\n";
            ++fail;
            SZ(computed, sizeof(computed));
            continue;
        }

        PHex("  Actual   : ", computed, v.out_len);

        bool kat_ok = CT_Eq(computed, v.expected, v.out_len);
        std::cout << (kat_ok
            ? "  [PASS] 해시 일치 — KAT 통과\n"
            : "  [FAIL] 해시 불일치\n");

        if (v.msg_len > 0u) {
            uint8_t tampered[128] = {};
            std::memcpy(tampered, v.message, v.msg_len);
            tampered[0] = static_cast<uint8_t>(tampered[0] ^ 0xFFu);

            uint8_t tampered_hash[32] = {};
            bool t_ok = false;
            if (v.is_256) {
                t_ok = lsh_ok(ProtectedEngine::LSH256_Bridge::Hash_256(
                    tampered, v.msg_len, tampered_hash));
            }
            else {
                t_ok = lsh_ok(ProtectedEngine::LSH256_Bridge::Hash_224(
                    tampered, v.msg_len, tampered_hash));
            }

            const bool changed = t_ok
                && !CT_Eq(tampered_hash, v.expected, v.out_len);

            std::cout << (changed
                ? "  [PASS] 1바이트 변조 탐지 성공 (해시 변경 확인)\n"
                : "  [FAIL] 변조 탐지 실패\n");

            SZ(tampered, sizeof(tampered));
            SZ(tampered_hash, sizeof(tampered_hash));
            if (!changed) {
                kat_ok = false;
            }
        }

        SZ(computed, sizeof(computed));
        kat_ok ? ++pass : ++fail;
    }

    std::cout << "\n==========================================\n"
        << "  KAT 최종 결과\n"
        << "  PASS : " << pass << " / " << KAT_COUNT << "\n"
        << "  FAIL : " << fail << " / " << KAT_COUNT << "\n";

    if (fail == 0) {
        std::cout << "  판정 : 전체 통과 ✓\n\n"
            << "  [KCMVP 다음 단계]\n"
            << "  1. 상수 Expected를 seed.kisa.or.kr 공식 문서와 대조 유지\n"
            << "  2. LSH-256 / LSH-224 전 모드 KAT 완료\n"
            << "  3. 암호모듈 경계 정의서 및 보안정책서 작성\n"
            << "  4. 국정원 지정 시험기관 제출\n";
    }
    else {
        std::cout << "  판정 : 미통과 ✗\n"
            << "  FAIL 시 MUT(LSH256_Bridge) 및 NSR LSH 소스 재확인\n";
    }
    std::cout << "==========================================\n";

    return (fail == 0);
}


// =========================================================================
//  main
// =========================================================================
int main() {
    std::cout << "==========================================\n"
        << "  KCMVP LSH-256 KAT (Known Answer Test)\n"
        << "  규격 : KS X 3262\n"
        << "  알고리즘 : LSH-256 / LSH-224\n"
        << "  목적 : KCMVP 제출 전 자가 사전 검증\n"
        << "  기대값 : 정적 NSR/외부 산출 상수 (런타임 캡처 없음)\n"
        << "==========================================\n";

    return KAT_Phase() ? EXIT_SUCCESS : EXIT_FAILURE;
}
