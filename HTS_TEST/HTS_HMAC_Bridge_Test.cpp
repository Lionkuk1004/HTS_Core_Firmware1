// =========================================================================
//  HTS_HMAC_Bridge_Test.cpp
//
//  [컴파일 대상]
//  ✅ HTS_HMAC_Bridge_Test.cpp
//  ✅ HTS_HMAC_Bridge.cpp
//  ✅ KISA_SHA_256.c
//  ✅ KISA_HMAC.c
//  ❌ 기타 main 포함 파일 모두 제외
// =========================================================================

#include "HTS_HMAC_Bridge.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <cstdlib>
#include <atomic>

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

static void Sep(const char* t) {
    std::cout << "\n------------------------------------------\n"
        << "  " << t << "\n"
        << "------------------------------------------\n";
}

// =========================================================================
//  TEST-1: RFC 4231 TC1 — Generate KAT
// =========================================================================
static bool Test_TC1_Generate() {
    Sep("TEST-1: RFC 4231 TC1 KAT (Generate)");

    const uint8_t key[20] = {
        0x0B,0x0B,0x0B,0x0B, 0x0B,0x0B,0x0B,0x0B,
        0x0B,0x0B,0x0B,0x0B, 0x0B,0x0B,0x0B,0x0B,
        0x0B,0x0B,0x0B,0x0B
    };
    const uint8_t msg[8] = {
        0x48,0x69,0x20,0x54, 0x68,0x65,0x72,0x65
    };
    const uint8_t expected[32] = {
        0xB0,0x34,0x4C,0x61, 0xD8,0xDB,0x38,0x53,
        0x5C,0xA8,0xAF,0xCE, 0xAF,0x0B,0xF1,0x2B,
        0x88,0x1D,0xC2,0x00, 0xC9,0x83,0x3D,0xA7,
        0x26,0xE9,0x37,0x6C, 0x2E,0x32,0xCF,0xF7
    };

    PHex("  Expected : ", expected, 32);

    uint8_t out[32] = {};
    if (!ProtectedEngine::HMAC_Bridge::Generate(msg, 8, key, 20, out)) {
        std::cout << "  [FAIL] Generate 실패\n"; return false;
    }
    PHex("  Actual   : ", out, 32);

    bool ok = CT_Eq(out, expected, 32);
    std::cout << (ok ? "  [PASS] KAT 일치\n" : "  [FAIL] KAT 불일치\n");
    SZ(out, 32);
    return ok;
}

// =========================================================================
//  TEST-2: RFC 4231 TC1 — 스트리밍 KAT
//  Init + Update(전체 8바이트) + Final == Generate 결과
// =========================================================================
static bool Test_TC1_Streaming() {
    Sep("TEST-2: RFC 4231 TC1 KAT (스트리밍)");

    const uint8_t key[20] = {
        0x0B,0x0B,0x0B,0x0B, 0x0B,0x0B,0x0B,0x0B,
        0x0B,0x0B,0x0B,0x0B, 0x0B,0x0B,0x0B,0x0B,
        0x0B,0x0B,0x0B,0x0B
    };
    const uint8_t msg[8] = {
        0x48,0x69,0x20,0x54, 0x68,0x65,0x72,0x65
    };
    const uint8_t expected[32] = {
        0xB0,0x34,0x4C,0x61, 0xD8,0xDB,0x38,0x53,
        0x5C,0xA8,0xAF,0xCE, 0xAF,0x0B,0xF1,0x2B,
        0x88,0x1D,0xC2,0x00, 0xC9,0x83,0x3D,0xA7,
        0x26,0xE9,0x37,0x6C, 0x2E,0x32,0xCF,0xF7
    };

    uint8_t out[32] = {};
    {
        ProtectedEngine::HMAC_Context ctx;
        bool ok = true;
        ok = ok && ProtectedEngine::HMAC_Bridge::Init(ctx, key, 20);
        ok = ok && ProtectedEngine::HMAC_Bridge::Update(ctx, msg, 8);
        ok = ok && ProtectedEngine::HMAC_Bridge::Final(ctx, out);
        if (!ok) { std::cout << "  [FAIL] 스트리밍 처리 실패\n"; return false; }
    }
    PHex("  Expected : ", expected, 32);
    PHex("  Actual   : ", out, 32);

    bool ok = CT_Eq(out, expected, 32);
    std::cout << (ok ? "  [PASS] KAT 일치\n" : "  [FAIL] KAT 불일치\n");
    SZ(out, 32);
    return ok;
}

// =========================================================================
//  TEST-3: 스트리밍 일관성 — 청크 분할 vs 단일 호출
//  Init + Update×3 + Final == Generate
// =========================================================================
static bool Test_Streaming_Consistency() {
    Sep("TEST-3: 스트리밍 일관성 (Init/Update×3/Final == Generate)");

    const uint8_t key[32] = {
        0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B, 0x1C,0x1D,0x1E,0x1F
    };
    const uint8_t c1[] = { 0xAA,0xBB,0xCC,0xDD };
    const uint8_t c2[] = { 0xEE,0xFF,0x00,0x11, 0x22,0x33,0x44,0x55 };
    const uint8_t c3[] = { 0x66,0x77,0x88,0x99, 0xAA,0xBB,0xCC };

    uint8_t full[19] = {};
    std::memcpy(full, c1, 4);
    std::memcpy(full + 4, c2, 8);
    std::memcpy(full + 12, c3, 7);

    // 단일 호출
    uint8_t ref[32] = {};
    ProtectedEngine::HMAC_Bridge::Generate(full, 19, key, 32, ref);
    PHex("  Generate  : ", ref, 32);

    // 스트리밍 (3청크)
    uint8_t stream[32] = {};
    {
        ProtectedEngine::HMAC_Context ctx;
        bool ok = true;
        ok = ok && ProtectedEngine::HMAC_Bridge::Init(ctx, key, 32);
        ok = ok && ProtectedEngine::HMAC_Bridge::Update(ctx, c1, 4);
        ok = ok && ProtectedEngine::HMAC_Bridge::Update(ctx, c2, 8);
        ok = ok && ProtectedEngine::HMAC_Bridge::Update(ctx, c3, 7);
        ok = ok && ProtectedEngine::HMAC_Bridge::Final(ctx, stream);
        if (!ok) {
            std::cout << "  [FAIL] 스트리밍 처리 실패\n";
            SZ(ref, 32); return false;
        }
    }
    PHex("  Streaming : ", stream, 32);

    bool match = CT_Eq(ref, stream, 32);
    std::cout << (match
        ? "  [PASS] Generate == Streaming 일치\n"
        : "  [FAIL] 불일치\n");

    SZ(ref, 32); SZ(stream, 32);
    return match;
}

// =========================================================================
//  TEST-4: Verify 3종 (정상 / 메시지 변조 / 키 변조)
// =========================================================================
static bool Test_Verify_Suite() {
    Sep("TEST-4: Verify 정상 + 위변조 탐지 + 키 변조 탐지");

    const uint8_t key[] = "HTS_HMAC_Test_Key_2026";
    const uint8_t msg[] = "B-CDMA Payload Integrity Check";
    const size_t  klen = sizeof(key) - 1;
    const size_t  mlen = sizeof(msg) - 1;

    uint8_t tag[32] = {};
    ProtectedEngine::HMAC_Bridge::Generate(msg, mlen, key, klen, tag);
    PHex("  태그 : ", tag, 32);

    bool all = true;

    bool v1 = ProtectedEngine::HMAC_Bridge::Verify(msg, mlen, key, klen, tag);
    std::cout << (v1 ? "  [PASS] 정상 검증\n" : "  [FAIL] 정상 검증 실패\n");
    if (!v1) all = false;

    uint8_t bad_msg[sizeof(msg)] = {};
    std::memcpy(bad_msg, msg, mlen);
    bad_msg[0] ^= 0xFF;
    bool v2 = !ProtectedEngine::HMAC_Bridge::Verify(bad_msg, mlen, key, klen, tag);
    std::cout << (v2 ? "  [PASS] 메시지 변조 탐지\n" : "  [FAIL] 메시지 변조 탐지 실패\n");
    if (!v2) all = false;

    uint8_t bad_key[sizeof(key)] = {};
    std::memcpy(bad_key, key, klen);
    bad_key[0] ^= 0x01;
    bool v3 = !ProtectedEngine::HMAC_Bridge::Verify(msg, mlen, bad_key, klen, tag);
    std::cout << (v3 ? "  [PASS] 키 변조 탐지\n" : "  [FAIL] 키 변조 탐지 실패\n");
    if (!v3) all = false;

    SZ(tag, 32); SZ(bad_msg, sizeof(bad_msg)); SZ(bad_key, sizeof(bad_key));
    return all;
}

// =========================================================================
//  TEST-5: Verify_Final 스트리밍
// =========================================================================
static bool Test_Streaming_Verify() {
    Sep("TEST-5: 스트리밍 Verify_Final");

    const uint8_t key[32] = {
        0x48,0x54,0x53,0x5F, 0x56,0x45,0x52,0x49,
        0x46,0x59,0x5F,0x4B, 0x45,0x59,0x5F,0x32,
        0x30,0x32,0x36,0x00, 0x01,0x02,0x03,0x04,
        0x05,0x06,0x07,0x08, 0x09,0x0A,0x0B,0x0C
    };
    const uint8_t c1[] = { 0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17 };
    const uint8_t c2[] = { 0x18,0x19,0x1A,0x1B, 0x1C,0x1D,0x1E,0x1F };

    uint8_t tag[32] = {};
    {
        ProtectedEngine::HMAC_Context ctx;
        ProtectedEngine::HMAC_Bridge::Init(ctx, key, 32);
        ProtectedEngine::HMAC_Bridge::Update(ctx, c1, 8);
        ProtectedEngine::HMAC_Bridge::Update(ctx, c2, 8);
        ProtectedEngine::HMAC_Bridge::Final(ctx, tag);
    }
    PHex("  태그 : ", tag, 32);

    bool ok = false;
    {
        ProtectedEngine::HMAC_Context ctx;
        ProtectedEngine::HMAC_Bridge::Init(ctx, key, 32);
        ProtectedEngine::HMAC_Bridge::Update(ctx, c1, 8);
        ProtectedEngine::HMAC_Bridge::Update(ctx, c2, 8);
        ok = ProtectedEngine::HMAC_Bridge::Verify_Final(ctx, tag);
    }
    std::cout << (ok ? "  [PASS] Verify_Final 통과\n" : "  [FAIL] Verify_Final 실패\n");
    SZ(tag, 32);
    return ok;
}

// =========================================================================
//  TEST-6: 65바이트 초과 키 (Init 내부 SHA256_Process 압축 경로)
// =========================================================================
static bool Test_Long_Key() {
    Sep("TEST-6: 65바이트 초과 키 재현성");

    uint8_t long_key[65] = {};
    for (size_t i = 0; i < 65; ++i) long_key[i] = static_cast<uint8_t>(i);

    const uint8_t msg[] = "Long key test message";
    uint8_t t1[32] = {}, t2[32] = {};

    ProtectedEngine::HMAC_Bridge::Generate(msg, sizeof(msg) - 1, long_key, 65, t1);
    ProtectedEngine::HMAC_Bridge::Generate(msg, sizeof(msg) - 1, long_key, 65, t2);

    PHex("  Tag1 : ", t1, 32);
    PHex("  Tag2 : ", t2, 32);

    bool ok = CT_Eq(t1, t2, 32);
    std::cout << (ok ? "  [PASS] 재현성 확인\n" : "  [FAIL] 결과 불일치\n");

    // 스트리밍도 동일 결과인지 확인
    uint8_t t3[32] = {};
    {
        ProtectedEngine::HMAC_Context ctx;
        ProtectedEngine::HMAC_Bridge::Init(ctx, long_key, 65);
        ProtectedEngine::HMAC_Bridge::Update(ctx, msg, sizeof(msg) - 1);
        ProtectedEngine::HMAC_Bridge::Final(ctx, t3);
    }
    PHex("  Tag3 (streaming) : ", t3, 32);
    bool ok2 = CT_Eq(t1, t3, 32);
    std::cout << (ok2 ? "  [PASS] Generate == Streaming (초과 키)\n"
        : "  [FAIL] Generate != Streaming (초과 키)\n");

    SZ(long_key, 65); SZ(t1, 32); SZ(t2, 32); SZ(t3, 32);
    return ok && ok2;
}

// =========================================================================
//  main
// =========================================================================
int main() {
    std::cout << "==========================================\n"
        << "  HTS HMAC-SHA256 Bridge 통합 테스트\n"
        << "  KISA : SHA256_Init / SHA256_Process\n"
        << "         / SHA256_Close + HMAC_SHA256\n"
        << "  스트리밍: 내부 버퍼 누적 → Final 단일 호출\n"
        << "==========================================\n";

    int pass = 0, fail = 0;
    auto run = [&](bool (*fn)(), const char* name) {
        bool r = fn();
        r ? ++pass : ++fail;
        std::cout << "  → " << name << (r ? " [PASS]\n" : " [FAIL]\n");
        };

    run(Test_TC1_Generate, "TEST-1 RFC4231 TC1 Generate KAT");
    run(Test_TC1_Streaming, "TEST-2 RFC4231 TC1 Streaming KAT");
    run(Test_Streaming_Consistency, "TEST-3 스트리밍 일관성");
    run(Test_Verify_Suite, "TEST-4 Verify 3종");
    run(Test_Streaming_Verify, "TEST-5 Verify_Final");
    run(Test_Long_Key, "TEST-6 64바이트 초과 키");

    const int total = pass + fail;
    std::cout << "\n==========================================\n"
        << "  최종 결과\n"
        << "  PASS : " << pass << " / " << total << "\n"
        << "  FAIL : " << fail << " / " << total << "\n";

    if (fail == 0) {
        std::cout << "  판정 : 전체 통과 ✓\n";
    }
    else {
        std::cout << "  판정 : 미통과 ✗\n";
    }
    std::cout << "==========================================\n";
    return (fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}