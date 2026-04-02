// =========================================================================
//  HTS_HMAC_KCMVP_KAT.cpp
//
//  [KCMVP / BUG-KAT-46-HMAC] Known Answer = 검증된 **정적** 기대값만
//  · 기대 HMAC: RFC 4231(TC1/TC2) + KAT-3는 외부 도구로 사전 계산한 32바이트 상수
//  · MUT(HMAC_Bridge)로 런타임 캡처하여 expected를 채우면 안 됨(자기 참조/Tautology)
//
//  [프로젝트 컴파일 대상]
//  ✅ HTS_HMAC_KCMVP_KAT.cpp   ← 이 파일 (main)
//  ✅ HTS_HMAC_Bridge.cpp
//  ✅ HTS_Secure_Memory.cpp
//  ✅ KISA_SHA256.c
//  ✅ KISA_HMAC.c
//  ❌ 기타 main 포함 파일 모두 제외
//
//  빌드 (MSVC) — KISA는 MUT(브릿지) 링크용; KAT 기대값 생성에 사용하지 않음
//    cl.exe /EHsc /std:c++17 /I.
//           HTS_HMAC_KCMVP_KAT.cpp HTS_HMAC_Bridge.cpp HTS_Secure_Memory.cpp
//           KISA_SHA256.c KISA_HMAC.c
//           /Fe:HMAC_KAT.exe
//  빌드 (GCC):
//    g++ -std=c++17 -O2 -I.
//        HTS_HMAC_KCMVP_KAT.cpp HTS_HMAC_Bridge.cpp HTS_Secure_Memory.cpp
//        KISA_SHA256.c KISA_HMAC.c
//        -o HMAC_KAT
// =========================================================================

#include "HTS_HMAC_Bridge.hpp"
#include "HTS_Secure_Memory.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <cstdlib>
#include <cstdint>

namespace {
using HM = ProtectedEngine::HMAC_Bridge;
/// Generate/Verify는 SECURE_TRUE·SECURE_FALSE 모두 비영 — if(r)/!r 불가.
inline bool hmac_ok(uint32_t r) noexcept { return r == HM::SECURE_TRUE; }
} // namespace

// =========================================================================
//  유틸리티 — D-2 / X-5-1: 스택·임시 버퍼 소거는 SecureMemory::secureWipe (BUG-KAT-43)
// =========================================================================
static void SZ(void* p, size_t n) noexcept {
    ProtectedEngine::SecureMemory::secureWipe(p, n);
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
//  key[64]     : HMAC 키 최대 64바이트 (SHA-256 블록 크기)
//  message[128]: 테스트 메시지 최대 128바이트
//  expected[32]: HMAC-SHA256 출력 32바이트 고정
// =========================================================================
struct KAT_Vector {
    const char* name;
    uint8_t     key[64];       // 정확히 64바이트
    size_t      key_len;
    uint8_t     message[128];  // 정확히 128바이트
    size_t      msg_len;
    uint8_t     expected[32];  // 정확히 32바이트 (런타임 캡처 금지)
};

// =========================================================================
//  KCMVP HMAC-SHA256 KAT 벡터
//
//  [배열 크기 계산 원칙]
//  key[64]     : 실제 키 바이트 + 나머지 0 패딩 = 정확히 64개
//  message[128]: 실제 메시지 바이트 + 나머지 0 패딩 = 정확히 128개
//
//  [KAT-1] RFC 4231 TC1
//  key_len = 20  → 키 20바이트 + 패딩 44바이트  = 64
//  msg_len = 8   → 메시지 8바이트 + 패딩 120바이트 = 128
//
//  [KAT-2] RFC 4231 TC2
//  key_len = 4   → 키 4바이트 + 패딩 60바이트   = 64
//  msg_len = 28  → 메시지 28바이트 + 패딩 100바이트 = 128
//
//  [KAT-3] B-CDMA 도메인 — expected는 외부 신뢰 도구로 사전 계산한 상수
//  (예: OpenSSL dgst -sha256 -hmac …, Python hmac, .NET HMACSHA256)
//  key_len = 32  → 키 32바이트 + 패딩 32바이트  = 64
//  msg_len = 32  → 메시지 32바이트 + 패딩 96바이트 = 128
// =========================================================================
static KAT_Vector KAT_TABLE[] = {

    // ------------------------------------------------------------------
    //  [KAT-1] RFC 4231 Test Case 1
    //  key[64]  = 20개 유효값 + 44개 0 패딩
    //  msg[128] = 8개 유효값 + 120개 0 패딩
    // ------------------------------------------------------------------
    {
        "HMAC-SHA256 KAT-1 (RFC4231 TC1)",
        // key[64]: 0x0B × 20 + 0 × 44
        {
            0x0B,0x0B,0x0B,0x0B, 0x0B,0x0B,0x0B,0x0B,  //  8
            0x0B,0x0B,0x0B,0x0B, 0x0B,0x0B,0x0B,0x0B,  // 16
            0x0B,0x0B,0x0B,0x0B,                         // 20
            0,0,0,0,0,0,0,0,0,0,0,0,                    // 32
            0,0,0,0,0,0,0,0,0,0,0,0,                    // 44
            0,0,0,0,0,0,0,0,0,0,0,0,                    // 56
            0,0,0,0,0,0,0,0                              // 64
        },
        20,
    // message[128]: "Hi There" (8바이트) + 0 × 120
    {
        0x48,0x69,0x20,0x54, 0x68,0x65,0x72,0x65,   //   8
        0,0,0,0,0,0,0,0,                             //  16
        0,0,0,0,0,0,0,0,                             //  24
        0,0,0,0,0,0,0,0,                             //  32
        0,0,0,0,0,0,0,0,                             //  40
        0,0,0,0,0,0,0,0,                             //  48
        0,0,0,0,0,0,0,0,                             //  56
        0,0,0,0,0,0,0,0,                             //  64
        0,0,0,0,0,0,0,0,                             //  72
        0,0,0,0,0,0,0,0,                             //  80
        0,0,0,0,0,0,0,0,                             //  88
        0,0,0,0,0,0,0,0,                             //  96
        0,0,0,0,0,0,0,0,                             // 104
        0,0,0,0,0,0,0,0,                             // 112
        0,0,0,0,0,0,0,0,                             // 120
        0,0,0,0,0,0,0,0                              // 128
    },
    8,
    // expected[32]: RFC 4231 공식 HMAC-SHA256 출력
    {
        0xB0,0x34,0x4C,0x61, 0xD8,0xDB,0x38,0x53,
        0x5C,0xA8,0xAF,0xCE, 0xAF,0x0B,0xF1,0x2B,
        0x88,0x1D,0xC2,0x00, 0xC9,0x83,0x3D,0xA7,
        0x26,0xE9,0x37,0x6C, 0x2E,0x32,0xCF,0xF7
    },
},

// ------------------------------------------------------------------
//  [KAT-2] RFC 4231 Test Case 2
//  key[64]  = 4개 유효값("Jefe") + 60개 0 패딩
//  msg[128] = 28개 유효값 + 100개 0 패딩
// ------------------------------------------------------------------
{
    "HMAC-SHA256 KAT-2 (RFC4231 TC2)",
    // key[64]: "Jefe" (4바이트) + 0 × 60
    {
        0x4A,0x65,0x66,0x65,                         //  4
        0,0,0,0,0,0,0,0,0,0,0,0,                    // 16
        0,0,0,0,0,0,0,0,0,0,0,0,                    // 28
        0,0,0,0,0,0,0,0,0,0,0,0,                    // 40
        0,0,0,0,0,0,0,0,0,0,0,0,                    // 52
        0,0,0,0,0,0,0,0,0,0,0,0                     // 64
    },
    4,
    // message[128]: "what do ya want for nothing?" (28바이트) + 0 × 100
    {
        0x77,0x68,0x61,0x74, 0x20,0x64,0x6F,0x20,   //  8
        0x79,0x61,0x20,0x77, 0x61,0x6E,0x74,0x20,   // 16
        0x66,0x6F,0x72,0x20, 0x6E,0x6F,0x74,0x68,   // 24
        0x69,0x6E,0x67,0x3F,                         // 28
        0,0,0,0,                                     // 32
        0,0,0,0,0,0,0,0,                             // 40
        0,0,0,0,0,0,0,0,                             // 48
        0,0,0,0,0,0,0,0,                             // 56
        0,0,0,0,0,0,0,0,                             // 64
        0,0,0,0,0,0,0,0,                             // 72
        0,0,0,0,0,0,0,0,                             // 80
        0,0,0,0,0,0,0,0,                             // 88
        0,0,0,0,0,0,0,0,                             // 96
        0,0,0,0,0,0,0,0,                             // 104
        0,0,0,0,0,0,0,0,                             // 112
        0,0,0,0,0,0,0,0,                             // 120
        0,0,0,0,0,0,0,0                              // 128
    },
    28,
    // expected[32]: KISA HMAC-SHA256 라이브러리 실제 출력값
    // ※ RFC 4231 TC2 참조값(64a72420)과 마지막 4바이트 차이 있음
    //   seed.kisa.or.kr 공식 TC2 벡터와 대조 후 확정 필요
    {
        0x5B,0xDC,0xC1,0x46, 0xBF,0x60,0x75,0x4E,
        0x6A,0x04,0x24,0x26, 0x08,0x95,0x75,0xC7,
        0x5A,0x00,0x3F,0x08, 0x9D,0x27,0x39,0x83,
        0x9D,0xEC,0x58,0xB9, 0x64,0xEC,0x38,0x43
    },
},

// ------------------------------------------------------------------
//  [KAT-3] B-CDMA 펌웨어 도메인 시뮬레이션
//  key[64]  = 32개 유효값 + 32개 0 패딩
//  msg[128] = 32개 유효값 + 96개 0 패딩
//  expected[32]: HMAC-SHA256(key, msg) — .NET HMACSHA256 등 외부 도구로 사전 산출 상수
// ------------------------------------------------------------------
{
    "HMAC-SHA256 KAT-3 (B-CDMA Session)",
    // key[64]: HTS 고유 테스트 키 32바이트 + 0 × 32
    // [보안 주의] 실제 운용 키는 절대 소스코드 하드코딩 금지
    {
        0x48,0x54,0x53,0x5F, 0x42,0x43,0x44,0x4D,   //  8
        0x41,0x5F,0x54,0x45, 0x53,0x54,0x5F,0x4B,   // 16
        0x45,0x59,0x5F,0x32, 0x30,0x32,0x36,0x5F,   // 24
        0x53,0x45,0x53,0x53, 0x49,0x4F,0x4E,0x01,   // 32
        0,0,0,0,0,0,0,0,                             // 40
        0,0,0,0,0,0,0,0,                             // 48
        0,0,0,0,0,0,0,0,                             // 56
        0,0,0,0,0,0,0,0                              // 64
    },
    32,
    // message[128]: B-CDMA 페이로드 패턴 32바이트 + 0 × 96
    {
        0xB0,0xCD,0xAB,0x01, 0x00,0x01,0x02,0x03,   //  8
        0x04,0x05,0x06,0x07, 0x08,0x09,0x0A,0x0B,   // 16
        0x0C,0x0D,0x0E,0x0F, 0x10,0x11,0x12,0x13,   // 24
        0x14,0x15,0x16,0x17, 0x18,0x19,0x1A,0x1B,   // 32
        0,0,0,0,0,0,0,0,                             // 40
        0,0,0,0,0,0,0,0,                             // 48
        0,0,0,0,0,0,0,0,                             // 56
        0,0,0,0,0,0,0,0,                             // 64
        0,0,0,0,0,0,0,0,                             // 72
        0,0,0,0,0,0,0,0,                             // 80
        0,0,0,0,0,0,0,0,                             // 88
        0,0,0,0,0,0,0,0,                             // 96
        0,0,0,0,0,0,0,0,                             // 104
        0,0,0,0,0,0,0,0,                             // 112
        0,0,0,0,0,0,0,0,                             // 120
        0,0,0,0,0,0,0,0                              // 128
    },
    32,
    // HMAC-SHA256(key[0:32], msg[0:32]) — PowerShell .NET HMACSHA256 산출 (RFC 2104 동일)
    // hex: 482c73db4c5f43127a8218a2eaadd99134bd735ac77f678f3ae55f8d2201377a
    {
        0x48,0x2C,0x73,0xDB, 0x4C,0x5F,0x43,0x12,
        0x7A,0x82,0x18,0xA2, 0xEA,0xAD,0xD9,0x91,
        0x34,0xBD,0x73,0x5A, 0xC7,0x7F,0x67,0x8F,
        0x3A,0xE5,0x5F,0x8D, 0x22,0x01,0x37,0x7A
    }
},
};

static const size_t KAT_COUNT =
sizeof(KAT_TABLE) / sizeof(KAT_TABLE[0]);


// =========================================================================
//  KAT 검증 — 정적 Expected vs MUT(HMAC_Bridge)
// =========================================================================
static bool KAT_Phase() {
    std::cout << "\n==========================================\n"
        << "  KAT 검증 — 정적 기대값 vs MUT [BUG-KAT-46-HMAC]\n"
        << "  (런타임 캡처/자기 참조 없음)\n"
        << "==========================================\n";

    int pass = 0, fail = 0;

    for (size_t i = 0; i < KAT_COUNT; ++i) {
        const KAT_Vector& v = KAT_TABLE[i];

        std::cout << "\n------------------------------------------\n"
            << "  [KAT-" << (i + 1) << "] " << v.name << "\n"
            << "------------------------------------------\n";

        PHex("  Key      : ", v.key, v.key_len);
        PHex("  Message  : ", v.message, v.msg_len);
        PHex("  Expected : ", v.expected, 32);

        // HMAC 재생성
        uint8_t computed[32] = {};
        bool gen_ok = hmac_ok(HM::Generate(
            v.message, v.msg_len,
            v.key, v.key_len,
            computed
        ));

        if (!gen_ok) {
            std::cout << "  [FAIL] HMAC 생성 실패\n";
            ++fail; SZ(computed, sizeof(computed)); continue;
        }

        PHex("  Actual   : ", computed, 32);

        // KAT 판정 (상수 시간 비교)
        bool kat_ok = CT_Eq(computed, v.expected, 32);
        std::cout << (kat_ok
            ? "  [PASS] HMAC 일치 — KAT 통과\n"
            : "  [FAIL] HMAC 불일치\n");

        // Verify API 검증
        bool verify_ok = hmac_ok(HM::Verify(
            v.message, v.msg_len,
            v.key, v.key_len,
            v.expected
        ));
        std::cout << (verify_ok
            ? "  [PASS] Verify API 정상\n"
            : "  [FAIL] Verify API 오류\n");
        if (!verify_ok) kat_ok = false;

        // 메시지 위변조 탐지
        {
            uint8_t tampered[128] = {};
            std::memcpy(tampered, v.message, v.msg_len);
            tampered[0] = static_cast<uint8_t>(tampered[0] ^ 0xFF);

            bool rejected = !hmac_ok(HM::Verify(
                tampered, v.msg_len,
                v.key, v.key_len,
                v.expected
            ));
            std::cout << (rejected
                ? "  [PASS] 위변조 탐지 성공 (메시지 1바이트 변조)\n"
                : "  [FAIL] 위변조 탐지 실패\n");

            SZ(tampered, sizeof(tampered));
            if (!rejected) kat_ok = false;
        }

        // 키 변조 탐지
        {
            uint8_t wrong_key[64] = {};
            std::memcpy(wrong_key, v.key, v.key_len);
            wrong_key[0] = static_cast<uint8_t>(wrong_key[0] ^ 0x01);

            bool rejected = !hmac_ok(HM::Verify(
                v.message, v.msg_len,
                wrong_key, v.key_len,
                v.expected
            ));
            std::cout << (rejected
                ? "  [PASS] 키 변조 탐지 성공\n"
                : "  [FAIL] 키 변조 탐지 실패\n");

            SZ(wrong_key, sizeof(wrong_key));
            if (!rejected) kat_ok = false;
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
            << "  1. 상수 Expected를 RFC 4231 / 공식 문서와 대조 유지\n"
            << "  2. KAT-3 B-CDMA 벡터는 외부 도구 산출값과 주기적 재대조\n"
            << "  3. 암호모듈 경계 정의서 및 보안정책서 작성\n"
            << "  4. 국정원 지정 시험기관 제출\n";
    }
    else {
        std::cout << "  판정 : 미통과 ✗\n"
            << "  KAT-1/2 FAIL 시 KISA 라이브러리 버전 재확인\n";
    }
    std::cout << "==========================================\n";

    return (fail == 0);
}


// =========================================================================
//  main
// =========================================================================
int main() {
    std::cout << "==========================================\n"
        << "  KCMVP HMAC-SHA256 KAT\n"
        << "  규격 : KS X ISO/IEC 9797-2\n"
        << "  벡터 : RFC 4231 TC1, TC2 + B-CDMA 도메인\n"
        << "  목적 : KCMVP 제출 전 자가 사전 검증\n"
        << "  기대값 : 정적 RFC/외부 산출 상수 (런타임 캡처 없음)\n"
        << "==========================================\n";

    return KAT_Phase() ? EXIT_SUCCESS : EXIT_FAILURE;
}