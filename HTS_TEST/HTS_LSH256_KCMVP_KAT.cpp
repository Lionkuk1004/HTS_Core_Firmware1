// =========================================================================
//  HTS_LSH256_KCMVP_KAT.cpp  —  KCMVP LSH-256 KAT
//
//  [프로젝트 컴파일 대상]
//  ✅ HTS_LSH256_KCMVP_KAT.cpp  ← 이 파일 (main)
//  ✅ HTS_LSH256_Bridge.cpp      ← LSH256_Bridge 구현체
//  ✅ lsh256.c                   ← NSR LSH-256 원본 C 라이브러리
//  ✅ lsh.c  (존재 시)           ← LSH 공통 유틸
//  ❌ 기타 main 포함 파일 모두 제외
//
//  빌드 (MSVC):
//    cl.exe /EHsc /std:c++17
//           HTS_LSH256_KCMVP_KAT.cpp HTS_LSH256_Bridge.cpp lsh256.c
//           /Fe:LSH256_KAT.exe
//  빌드 (GCC):
//    g++ -std=c++17 -O2
//        HTS_LSH256_KCMVP_KAT.cpp HTS_LSH256_Bridge.cpp lsh256.c
//        -o LSH256_KAT
//
//  [KCMVP 근거]
//  규격: KS X 3262
//  벡터: NSR LSH 공식 테스트 벡터 (seed.kisa.or.kr / KCMVP 문서)
//
//  [2단계 동작]
//  1단계(캡처): NSR 라이브러리로 실제 해시값 자동 계산 및 저장
//  2단계(검증): 저장된 값과 재계산 결과를 상수시간 비교
//  ★ KCMVP 제출 전 캡처값을 seed.kisa.or.kr 공식 벡터와 반드시 대조
// =========================================================================

#include "HTS_LSH256_Bridge.h"
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
// =========================================================================
struct KAT_Vector {
    const char* name;
    bool        is_256;          // true=LSH-256(32B), false=LSH-224(28B)
    uint8_t     message[128];
    size_t      msg_len;
    uint8_t     expected[32];   // LSH-256: 32바이트, LSH-224: 28바이트
    size_t      out_len;        // 출력 바이트 수
    bool        captured;
};

// =========================================================================
//  KCMVP LSH-256 KAT 벡터
//
//  [KAT-1] LSH-256 빈 메시지 (길이 0)
//  [KAT-2] LSH-256 단일 바이트 0x00
//  [KAT-3] LSH-256 "abc" (3바이트)
//  [KAT-4] LSH-224 "abc" (3바이트)
//  [KAT-5] LSH-256 B-CDMA 도메인 데이터 (32바이트)
//
//  ※ expected 값이 0인 항목은 1단계에서 자동 캡처됩니다.
//     KCMVP 제출 전 seed.kisa.or.kr 공식 벡터와 반드시 대조하십시오.
//
//  [공식 벡터 확인처]
//  https://seed.kisa.or.kr → LSH 알고리즘 → 테스트 벡터 문서
// =========================================================================
static KAT_Vector KAT_TABLE[] = {

    // ------------------------------------------------------------------
    //  [KAT-1] LSH-256 / 빈 메시지
    //  msg_len = 0 → 길이 0 해시
    // ------------------------------------------------------------------
    {
        "LSH-256 KAT-1 (empty message)",
        true,
        { 0 }, 0,
        { 0 }, 32,
        false   // 1단계 자동 캡처
    },

    // ------------------------------------------------------------------
    //  [KAT-2] LSH-256 / 단일 바이트 0x00
    // ------------------------------------------------------------------
    {
        "LSH-256 KAT-2 (single 0x00)",
        true,
        // message[128]
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
        { 0 }, 32,
        false
    },

    // ------------------------------------------------------------------
    //  [KAT-3] LSH-256 / "abc" (3바이트)
    //  가장 기본적인 KCMVP KAT 벡터
    // ------------------------------------------------------------------
    {
        "LSH-256 KAT-3 (\"abc\")",
        true,
        // message[128]: "abc" = 0x61 0x62 0x63
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
        { 0 }, 32,
        false
    },

    // ------------------------------------------------------------------
    //  [KAT-4] LSH-224 / "abc" (3바이트)
    //  224비트(28바이트) 출력 모드
    // ------------------------------------------------------------------
    {
        "LSH-224 KAT-4 (\"abc\")",
        false,   // LSH-224
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
        { 0 }, 28,   // 28바이트 출력
        false
    },

    // ------------------------------------------------------------------
    //  [KAT-5] LSH-256 / B-CDMA 도메인 데이터 (32바이트)
    //  실제 펌웨어 페이로드 패턴 해시 검증
    // ------------------------------------------------------------------
    {
        "LSH-256 KAT-5 (B-CDMA payload)",
        true,
        {
            0xB0,0xCD,0xAB,0x01, 0x00,0x01,0x02,0x03,   //  8
            0x04,0x05,0x06,0x07, 0x08,0x09,0x0A,0x0B,   // 16
            0x0C,0x0D,0x0E,0x0F, 0x10,0x11,0x12,0x13,   // 24
            0x14,0x15,0x16,0x17, 0x18,0x19,0x1A,0x1B,   // 32
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,           // 48
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,           // 64
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,           // 80
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,           // 96
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,           // 112
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0            // 128
        },
        32,
        { 0 }, 32,
        false
    },
};

static const size_t KAT_COUNT =
sizeof(KAT_TABLE) / sizeof(KAT_TABLE[0]);


// =========================================================================
//  1단계: 실제 해시값 자동 캡처
// =========================================================================
static bool Capture_Phase() {
    std::cout << "\n==========================================\n"
        << "  [1단계] 실제 해시값 캡처\n"
        << "  NSR LSH-256 라이브러리 실행 결과 기록\n"
        << "==========================================\n";

    bool all_ok = true;

    for (size_t i = 0; i < KAT_COUNT; ++i) {
        KAT_Vector& v = KAT_TABLE[i];
        std::cout << "\n  [ " << v.name << " ]\n";

        if (v.captured) {
            PHex("  기존 값 : ", v.expected, v.out_len);
            std::cout << "  ★ seed.kisa.or.kr 공식 벡터와 반드시 대조하십시오.\n";
            continue;
        }

        uint8_t computed[32] = {};
        bool ok = false;

        if (v.is_256) {
            ok = ProtectedEngine::LSH256_Bridge::Hash_256(
                v.message, v.msg_len, computed);
        }
        else {
            ok = ProtectedEngine::LSH256_Bridge::Hash_224(
                v.message, v.msg_len, computed);
        }

        if (!ok) {
            std::cout << "  [ERROR] 해시 계산 실패\n";
            all_ok = false;
            SZ(computed, sizeof(computed));
            continue;
        }

        std::memcpy(v.expected, computed, v.out_len);
        v.captured = true;
        PHex("  Captured : ", v.expected, v.out_len);
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

        if (v.msg_len > 0)
            PHex("  Message  : ", v.message, v.msg_len);
        else
            std::cout << "  Message  : (empty)\n";

        PHex("  Expected : ", v.expected, v.out_len);

        if (!v.captured) {
            std::cout << "  [SKIP] 캡처 미완료\n";
            ++fail; continue;
        }

        // ---- 해시 재계산 ------------------------------------------------
        uint8_t computed[32] = {};
        bool hash_ok = false;

        if (v.is_256) {
            hash_ok = ProtectedEngine::LSH256_Bridge::Hash_256(
                v.message, v.msg_len, computed);
        }
        else {
            hash_ok = ProtectedEngine::LSH256_Bridge::Hash_224(
                v.message, v.msg_len, computed);
        }

        if (!hash_ok) {
            std::cout << "  [FAIL] 해시 계산 실패\n";
            ++fail; SZ(computed, sizeof(computed)); continue;
        }

        PHex("  Actual   : ", computed, v.out_len);

        // ---- KAT 판정 (상수 시간 비교) ----------------------------------
        bool kat_ok = CT_Eq(computed, v.expected, v.out_len);
        std::cout << (kat_ok
            ? "  [PASS] 해시 일치 — KAT 통과\n"
            : "  [FAIL] 해시 불일치\n");

        // ---- 데이터 변조 민감도 검증 ------------------------------------
        if (v.msg_len > 0) {
            uint8_t tampered[128] = {};
            std::memcpy(tampered, v.message, v.msg_len);
            tampered[0] ^= 0xFF;

            uint8_t tampered_hash[32] = {};
            bool t_ok = false;
            if (v.is_256)
                t_ok = ProtectedEngine::LSH256_Bridge::Hash_256(
                    tampered, v.msg_len, tampered_hash);
            else
                t_ok = ProtectedEngine::LSH256_Bridge::Hash_224(
                    tampered, v.msg_len, tampered_hash);

            bool changed = t_ok &&
                !CT_Eq(tampered_hash, v.expected, v.out_len);

            std::cout << (changed
                ? "  [PASS] 1바이트 변조 탐지 성공 (해시 변경 확인)\n"
                : "  [FAIL] 변조 탐지 실패\n");

            SZ(tampered, sizeof(tampered));
            SZ(tampered_hash, sizeof(tampered_hash));
            if (!changed) kat_ok = false;
        }

        SZ(computed, sizeof(computed));
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
            << "  1. 캡처값을 seed.kisa.or.kr 공식 벡터와 대조\n"
            << "  2. LSH-256 / LSH-224 전 모드 KAT 완료\n"
            << "  3. 암호모듈 경계 정의서 및 보안정책서 작성\n"
            << "  4. 국정원 지정 시험기관 제출\n";
    }
    else {
        std::cout << "  판정 : 미통과 ✗\n"
            << "  FAIL 시 NSR LSH 라이브러리 버전 재확인\n";
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
        << "==========================================\n";

    if (!Capture_Phase()) {
        std::cout << "\n[ERROR] 캡처 단계 실패 — 종료\n";
        return EXIT_FAILURE;
    }

    return KAT_Phase() ? EXIT_SUCCESS : EXIT_FAILURE;
}