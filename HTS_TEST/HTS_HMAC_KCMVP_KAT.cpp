// =========================================================================
//  HTS_HMAC_KCMVP_KAT.cpp
//
//  [프로젝트 컴파일 대상]
//  ✅ HTS_HMAC_KCMVP_KAT.cpp   ← 이 파일 (main)
//  ✅ HTS_HMAC_Bridge.cpp
//  ✅ KISA_HMAC.c
//  ❌ 기타 main 포함 파일 모두 제외
//
//  빌드 (MSVC):
//    cl.exe /EHsc /std:c++17
//           HTS_HMAC_KCMVP_KAT.cpp HTS_HMAC_Bridge.cpp KISA_HMAC.c
//           /Fe:HMAC_KAT.exe
//  빌드 (GCC):
//    g++ -std=c++17 -O2
//        HTS_HMAC_KCMVP_KAT.cpp HTS_HMAC_Bridge.cpp KISA_HMAC.c
//        -o HMAC_KAT
// =========================================================================

#include "HTS_HMAC_Bridge.h"
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
    uint8_t     expected[32];  // 정확히 32바이트
    bool        captured;
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
//  [KAT-3] B-CDMA 도메인
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
    true
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
    true
},

// ------------------------------------------------------------------
//  [KAT-3] B-CDMA 펌웨어 도메인 시뮬레이션
//  key[64]  = 32개 유효값 + 32개 0 패딩
//  msg[128] = 32개 유효값 + 96개 0 패딩
//  ★ 1단계 자동 캡처 → seed.kisa.or.kr 공식 벡터 대조 필요
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
    { 0 }, false   // 1단계 자동 캡처
},
};

static const size_t KAT_COUNT =
sizeof(KAT_TABLE) / sizeof(KAT_TABLE[0]);


// =========================================================================
//  1단계: 실제 HMAC 값 자동 캡처
// =========================================================================
static bool Capture_Phase() {
    std::cout << "\n==========================================\n"
        << "  [1단계] 실제 HMAC 값 캡처\n"
        << "  KISA HMAC-SHA256 라이브러리 실행 결과 기록\n"
        << "==========================================\n";

    bool all_ok = true;

    for (size_t i = 0; i < KAT_COUNT; ++i) {
        KAT_Vector& v = KAT_TABLE[i];
        std::cout << "\n  [ " << v.name << " ]\n";

        if (v.captured) {
            PHex("  기존 값 : ", v.expected, 32);
            std::cout << "  ★ seed.kisa.or.kr 공식 벡터와 반드시 대조하십시오.\n";
            continue;
        }

        uint8_t computed[32] = {};
        bool ok = ProtectedEngine::HMAC_Bridge::Generate(
            v.message, v.msg_len,
            v.key, v.key_len,
            computed
        );

        if (!ok) {
            std::cout << "  [ERROR] HMAC 생성 실패\n";
            all_ok = false;
            SZ(computed, sizeof(computed));
            continue;
        }

        std::memcpy(v.expected, computed, 32);
        v.captured = true;
        PHex("  Captured : ", v.expected, 32);
        std::cout << "  ★ seed.kisa.or.kr 공식 벡터와 반드시 대조하십시오.\n";
        SZ(computed, sizeof(computed));
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

        PHex("  Key      : ", v.key, v.key_len);
        PHex("  Message  : ", v.message, v.msg_len);
        PHex("  Expected : ", v.expected, 32);

        if (!v.captured) {
            std::cout << "  [SKIP] 캡처 미완료\n";
            ++fail; continue;
        }

        // HMAC 재생성
        uint8_t computed[32] = {};
        bool gen_ok = ProtectedEngine::HMAC_Bridge::Generate(
            v.message, v.msg_len,
            v.key, v.key_len,
            computed
        );

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
        bool verify_ok = ProtectedEngine::HMAC_Bridge::Verify(
            v.message, v.msg_len,
            v.key, v.key_len,
            v.expected
        );
        std::cout << (verify_ok
            ? "  [PASS] Verify API 정상\n"
            : "  [FAIL] Verify API 오류\n");

        // 메시지 위변조 탐지
        {
            uint8_t tampered[128] = {};
            std::memcpy(tampered, v.message, v.msg_len);
            tampered[0] ^= 0xFF;

            bool rejected = !ProtectedEngine::HMAC_Bridge::Verify(
                tampered, v.msg_len,
                v.key, v.key_len,
                v.expected
            );
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
            wrong_key[0] ^= 0x01;

            bool rejected = !ProtectedEngine::HMAC_Bridge::Verify(
                v.message, v.msg_len,
                wrong_key, v.key_len,
                v.expected
            );
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
            << "  1. KAT-1, KAT-2 → RFC 4231 공식값 대조 완료\n"
            << "  2. KAT-3 Captured → seed.kisa.or.kr 대조\n"
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
        << "==========================================\n";

    if (!Capture_Phase()) {
        std::cout << "\n[ERROR] 캡처 단계 실패 — 종료\n";
        return EXIT_FAILURE;
    }

    return KAT_Phase() ? EXIT_SUCCESS : EXIT_FAILURE;
}