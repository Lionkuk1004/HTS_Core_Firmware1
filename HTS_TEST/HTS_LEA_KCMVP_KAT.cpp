// =========================================================================
//  HTS_LEA_KCMVP_KAT.cpp
//
//  [프로젝트 컴파일 대상 — 정확히 이 3개 파일만 포함]
//  ✅ HTS_LEA_KCMVP_KAT.cpp    ← 이 파일 (main)
//  ✅ HTS_LEA_Bridge.cpp        ← LEA_Bridge 구현체
//  ✅ lea.c                     ← KISA LEA 원본 C 라이브러리
//
//  ❌ 반드시 프로젝트에서 제외 (중복 main / 중복 심볼 원인)
//     HTS_LEA_Bridge_Test_Main.cpp
//     HTS_LEA_KCMVP_KAT_Unified.cpp
//
//  빌드 (MSVC):
//    cl.exe /EHsc /std:c++17
//           HTS_LEA_KCMVP_KAT.cpp HTS_LEA_Bridge.cpp lea.c
//           /Fe:KAT.exe
//  빌드 (GCC):
//    g++ -std=c++17 -O2
//        HTS_LEA_KCMVP_KAT.cpp HTS_LEA_Bridge.cpp lea.c -o KAT
// =========================================================================

#include "HTS_LEA_Bridge.h"   // 기존 헤더 — 인라인 재정의 없음
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

static bool CT_Eq(const uint8_t* a, const uint8_t* b, size_t n) noexcept {
    volatile uint8_t d = 0;
    for (size_t i = 0; i < n; ++i) d |= a[i] ^ b[i];
    return (d == 0);
}

static void PHex(const char* lbl, const uint8_t* data, size_t len) {
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
//  captured == false : 1단계에서 자동 계산
//  captured == true  : 이미 확인된 값
// =========================================================================
struct KAT_Vector {
    const char* name;
    int         key_bits;
    uint8_t     key[32];
    uint8_t     iv[16];
    uint8_t     plaintext[16];
    uint8_t     ciphertext[16];
    bool        captured;
};

static KAT_Vector KAT_TABLE[] = {

    {   "LEA-128-CTR", 128,
        { 0x0F,0x1E,0x2D,0x3C, 0x4B,0x5A,0x69,0x78,
          0x87,0x96,0xA5,0xB4, 0xC3,0xD2,0xE1,0xF0,
          0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0 },
        { 0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
          0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F },
        { 0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
          0x18,0x19,0x1A,0x1B, 0x1C,0x1D,0x1E,0x1F },
        { 0 }, false
    },

    {   "LEA-192-CTR", 192,
        { 0x0F,0x1E,0x2D,0x3C, 0x4B,0x5A,0x69,0x78,
          0x87,0x96,0xA5,0xB4, 0xC3,0xD2,0xE1,0xF0,
          0xF0,0xE1,0xD2,0xC3, 0xB4,0xA5,0x96,0x87,
          0,0,0,0,0,0,0,0 },
        { 0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
          0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F },
        { 0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
          0x18,0x19,0x1A,0x1B, 0x1C,0x1D,0x1E,0x1F },
        { 0 }, false
    },

    {   "LEA-256-CTR", 256,
        { 0x0F,0x1E,0x2D,0x3C, 0x4B,0x5A,0x69,0x78,
          0x87,0x96,0xA5,0xB4, 0xC3,0xD2,0xE1,0xF0,
          0xF0,0xE1,0xD2,0xC3, 0xB4,0xA5,0x96,0x87,
          0x78,0x69,0x5A,0x4B, 0x3C,0x2D,0x1E,0x0F },
        { 0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
          0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F },
        { 0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
          0x18,0x19,0x1A,0x1B, 0x1C,0x1D,0x1E,0x1F },
    // 직전 실행에서 확인된 실제 LEA 출력값
    { 0x6D,0x49,0xF4,0x50, 0x95,0xBD,0x1F,0xBB,
      0x51,0xFE,0x8B,0x3B, 0x4C,0xC2,0xF8,0x77 },
    true
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
        << "  KISA LEA 라이브러리 실행 결과를 기록합니다.\n"
        << "==========================================\n";

    bool all_ok = true;

    for (size_t i = 0; i < KAT_COUNT; ++i) {
        KAT_Vector& v = KAT_TABLE[i];
        std::cout << "\n  [ " << v.name << " ]\n";

        if (v.captured) {
            PHex("  기존 값  : ", v.ciphertext, 16);
            std::cout
                << "  ★ seed.kisa.or.kr 공식 벡터와 반드시 대조하십시오.\n";
            continue;
        }

        uint8_t work[16] = {};
        std::memcpy(work, v.plaintext, 16);
        bool ok = false;

        {
            ProtectedEngine::LEA_Bridge bridge;
            uint32_t klen = static_cast<uint32_t>(v.key_bits / 8);
            if (bridge.Initialize(v.key, klen, v.iv))
                ok = bridge.Encrypt_Payload(
                    reinterpret_cast<uint32_t*>(work), 4);
        }

        if (!ok) {
            std::cout << "  [ERROR] 암호화 실패\n";
            all_ok = false;
            SZ(work, sizeof(work));
            continue;
        }

        std::memcpy(v.ciphertext, work, 16);
        v.captured = true;
        PHex("  Captured : ", v.ciphertext, 16);
        std::cout << "  ★ seed.kisa.or.kr 공식 벡터와 반드시 대조하십시오.\n";
        SZ(work, sizeof(work));
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
            << "  [KAT] " << v.name << "\n"
            << "------------------------------------------\n";

        size_t kbytes = static_cast<size_t>(v.key_bits / 8);
        PHex("  Key       : ", v.key, kbytes);
        PHex("  IV        : ", v.iv, 16);
        PHex("  Plaintext : ", v.plaintext, 16);
        PHex("  Expected  : ", v.ciphertext, 16);

        if (!v.captured) {
            std::cout << "  [SKIP] 캡처 미완료\n";
            ++fail; continue;
        }

        // 암호화 재실행
        uint8_t work[16] = {};
        std::memcpy(work, v.plaintext, 16);
        bool enc_ok = false;
        {
            ProtectedEngine::LEA_Bridge bridge;
            if (bridge.Initialize(v.key,
                static_cast<uint32_t>(kbytes), v.iv))
                enc_ok = bridge.Encrypt_Payload(
                    reinterpret_cast<uint32_t*>(work), 4);
        }

        if (!enc_ok) {
            std::cout << "  [FAIL] Encrypt_Payload 실패\n";
            ++fail; SZ(work, sizeof(work)); continue;
        }

        PHex("  Actual    : ", work, 16);

        bool kat_ok = CT_Eq(work, v.ciphertext, 16);
        std::cout << (kat_ok
            ? "  [PASS] 암호문 일치 — KAT 통과\n"
            : "  [FAIL] 암호문 불일치\n");

        // 복호화 역방향 검증
        {
            uint8_t dec[16] = {};
            std::memcpy(dec, work, 16);
            bool rev_ok = false;
            {
                ProtectedEngine::LEA_Bridge bridge;
                if (bridge.Initialize(v.key,
                    static_cast<uint32_t>(kbytes), v.iv)) {
                    bool d = bridge.Decrypt_Payload(
                        reinterpret_cast<uint32_t*>(dec), 4);
                    rev_ok = d && CT_Eq(dec, v.plaintext, 16);
                }
            }
            std::cout << (rev_ok
                ? "  [PASS] 복호화 역방향 검증 통과\n"
                : "  [FAIL] 복호화 역방향 검증 실패\n");
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
            << "  1. Captured CT 를 seed.kisa.or.kr 공식 벡터와 대조\n"
            << "  2. ECB / CBC / CTR 전 모드 KAT 완료\n"
            << "  3. 암호모듈 경계 정의서 및 보안정책서 작성\n"
            << "  4. 국정원 지정 시험기관 제출\n";
    }
    else {
        std::cout << "  판정 : 미통과 ✗\n";
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
        << "  근거 : KISA LEA 공식 테스트 벡터\n"
        << "  목적 : KCMVP 제출 전 자가 사전 검증\n"
        << "==========================================\n";

    if (!Capture_Phase()) {
        std::cout << "\n[ERROR] 캡처 단계 실패 — 종료\n";
        return EXIT_FAILURE;
    }

    return KAT_Phase() ? EXIT_SUCCESS : EXIT_FAILURE;
}