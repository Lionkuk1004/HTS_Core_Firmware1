// =========================================================================
// HTS_HMAC_Bridge.cpp
// KCMVP HMAC-SHA256 브릿지 구현부 (KISA 부분 블록 버그 우회 내장)
// 규격: KS X ISO/IEC 9797-2 / RFC 2104
// Target: STM32F407 (Cortex-M4)
//
// [양산 수정 — 4건 결함 교정]
//
//  BUG-01 [MEDIUM] Secure_Zero(SZ): pragma O0 보호 누락
//    기존: volatile + atomic_thread_fence만 사용
//    수정: pragma O0 push/pop 추가 (프로젝트 보안 소거 3중 보호 표준)
//
//  BUG-02 [MEDIUM] CT_Eq: pragma O0 보호 누락
//    기존: volatile uint8_t d + 루프 — 최적화 차단 미보장
//          GCC -O2: volatile 로컬 변수를 레지스터에만 유지 가능
//          → 분기 예측기가 d==0 패턴을 학습 → 타이밍 누출
//    수정: pragma O0 + 컴파일러 배리어 추가
//
//  BUG-03 [LOW] C26495 — HMAC_Context 배열 멤버 초기화
//    수정: 헤더에서 inner_ctx[256] = {}, o_key_pad[64] = {} 값 초기화
//
//  BUG-04 [LOW] SZ 함수명 → Secure_Zero_HMAC (가독성)
//
//  BUG-05 [LOW] C6385 — ipad 미초기화 + k[i] 범위 오판
//    수정: ipad = {} 초기화 + k[i] 로컬 복사
//
// [기존 설계 100% 보존]
//  - KISA 부분 블록 버그 우회: 64바이트 스마트 큐 버퍼링
//  - SHA256_INFO 캐스팅: inner_ctx[256] 내부에 Internal_HMAC_State 은닉
//  - KISA 함수명 어댑터: 패턴 A(Process/Close) / 패턴 B(Update/Final) 전환
//  - 스트리밍 API: Init → Update(반복) → Final/Verify_Final
//  - 단일 호출 API: Generate / Verify (내부 스트리밍 래핑)
//
// [STM32F407 성능]
//  Init (키 설정):     ~10K사이클 ≈ 0.06ms @168MHz
//  Update (64B 청크):  ~3K사이클 ≈ 0.018ms @168MHz
//  Final:              ~6K사이클 ≈ 0.036ms @168MHz
//  스택 사용량: ~320바이트 (HMAC_Context 스택 할당 기준)
// =========================================================================
#include "HTS_HMAC_Bridge.h"
#include <cstring>
#include <atomic>
#include <limits>

// =========================================================================
//  KISA SHA-256 원본 C 라이브러리 연결
// =========================================================================
extern "C" {
#include "KISA_SHA256.h"
}

// =========================================================================
//  KISA SHA-256 함수명 어댑터
//  패턴 A (기본): SHA256_Process / SHA256_Close
//  패턴 B:        SHA256_Update / SHA256_Final
//  빌드 플래그: -DHTS_KISA_SHA256_PATTERN_B 로 전환
// =========================================================================
#if defined(HTS_KISA_SHA256_PATTERN_B)
#define HTS_SHA256_UPDATE  SHA256_Update
#define HTS_SHA256_FINAL   SHA256_Final
#else
#define HTS_SHA256_UPDATE  SHA256_Process
#define HTS_SHA256_FINAL   SHA256_Close
#endif

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace ProtectedEngine {

    static constexpr size_t SHA256_BLOCK = 64u;
    static constexpr size_t SHA256_DIGEST = 32u;

    // =====================================================================
    //  KISA 부분 블록 누적 버그 우회용 내부 상태
    //  inner_ctx(256바이트)를 SHA256_INFO + 64바이트 큐로 분할
    // =====================================================================
    struct Internal_HMAC_State {
        SHA256_INFO sha_ctx;
        uint32_t    partial_len;
        uint8_t     partial_buf[SHA256_BLOCK];
    };

    static_assert(
        sizeof(Internal_HMAC_State) <= sizeof(HMAC_Context::inner_ctx),
        "HMAC_Context::inner_ctx too small for Internal_HMAC_State. "
        "Increase inner_ctx size in HTS_HMAC_Bridge.h"
        );

    // inner_ctx → Internal_HMAC_State* 캐스팅 (alignas(4) 보장)
    static inline Internal_HMAC_State* Inner(HMAC_Context& ctx) noexcept {
        return reinterpret_cast<Internal_HMAC_State*>(ctx.inner_ctx);
    }

    // =====================================================================
    //  Secure_Zero_HMAC — 보안 메모리 소거 (KCMVP Key Zeroization)
    //
    //  [BUG-01 수정] pragma O0 추가 — 프로젝트 3중 보호 표준
    //  1. pragma O0: 컴파일러 최적화 차단
    //  2. volatile: 각 쓰기가 부작용 → DCE 차단
    //  3. atomic_thread_fence: 메모리 재배치 차단
    // =====================================================================
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC push_options
#pragma GCC optimize("O0")
#elif defined(_MSC_VER)
#pragma optimize("", off)
#endif

    static void Secure_Zero_HMAC(void* p, size_t n) noexcept {
        if (!p || n == 0) return;
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0; i < n; ++i) q[i] = 0;
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  CT_Eq — 상수시간 바이트 배열 비교 (타이밍 사이드채널 차단)
    //
    //  [BUG-02 수정] pragma O0 + 컴파일러 배리어
    //  분기 예측기의 패턴 학습을 차단하여 HMAC 검증 시
    //  일치/불일치에 따른 타이밍 차이를 원천 제거
    // =====================================================================
    static bool CT_Eq(
        const uint8_t* a, const uint8_t* b, size_t n) noexcept {
        if (!a || !b || n == 0) return false;
        volatile uint8_t d = 0;
        for (size_t i = 0; i < n; ++i) {
            d = static_cast<uint8_t>(d | (a[i] ^ b[i]));
        }

        // 컴파일러 배리어: d 값이 레지스터에만 남는 것을 방지
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : "+r"(d) : : "memory");
#elif defined(_MSC_VER)
        _ReadWriteBarrier();
#endif

        return (d == 0);
    }

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC pop_options
#elif defined(_MSC_VER)
#pragma optimize("", on)
#endif

    // =====================================================================
    //  Init — 키 설정 + 내부 해시 시작
    //
    //  [RFC 2104 키 정규화]
    //  key_len > 64: SHA256(key)로 32바이트 압축
    //  key_len ≤ 64: 0 패딩하여 64바이트로 확장
    //  i_key_pad = key ^ 0x36 (내부 패딩)
    //  o_key_pad = key ^ 0x5C (외부 패딩 — Final에서 사용)
    // =====================================================================
    bool HMAC_Bridge::Init(
        HMAC_Context& ctx,
        const uint8_t* key,
        size_t         key_len) noexcept {

        if (!key || key_len == 0) return false;
        constexpr size_t U32MAX =
            static_cast<size_t>(std::numeric_limits<uint32_t>::max());
        if (key_len > U32MAX) return false;

        Secure_Zero_HMAC(ctx.inner_ctx, sizeof(ctx.inner_ctx));
        Secure_Zero_HMAC(ctx.o_key_pad, sizeof(ctx.o_key_pad));
        ctx.is_initialized = false;

        Inner(ctx)->partial_len = 0;

        // 키 정규화 (64바이트 블록)
        alignas(4) uint8_t k[SHA256_BLOCK] = {};

        if (key_len > SHA256_BLOCK) {
            SHA256_INFO tmp;
            SHA256_Init(&tmp);
            HTS_SHA256_UPDATE(&tmp,
                reinterpret_cast<const unsigned char*>(key),
                static_cast<unsigned int>(key_len));
            HTS_SHA256_FINAL(&tmp,
                reinterpret_cast<unsigned char*>(k));
            Secure_Zero_HMAC(&tmp, sizeof(tmp));
        }
        else {
            std::memcpy(k, key, key_len);
        }

        // i_key_pad / o_key_pad 생성
        // [BUG-05 fix] Split into two ranges to satisfy MSVC C6385 analysis:
        //   Range 1: [0 .. effective_len) — k[i] has valid data from memcpy/SHA256
        //   Range 2: [effective_len .. 64) — k[i] is 0 (from = {} init), so XOR = pad constant
        alignas(4) uint8_t ipad[SHA256_BLOCK] = {};
        const size_t effective_len = (key_len > SHA256_BLOCK)
            ? static_cast<size_t>(SHA256_DIGEST)    // SHA256 compressed to 32 bytes
            : key_len;                               // raw key copied

        // Range 1: key-derived region (k[i] is valid)
        for (size_t i = 0u; i < effective_len; ++i) {
            const uint8_t ki = k[i];
            ipad[i] = static_cast<uint8_t>(ki ^ 0x36u);
            ctx.o_key_pad[i] = static_cast<uint8_t>(ki ^ 0x5Cu);
        }
        // Range 2: zero-padded region (k[i] == 0, so XOR = pad constant)
        for (size_t i = effective_len; i < SHA256_BLOCK; ++i) {
            ipad[i] = 0x36u;
            ctx.o_key_pad[i] = 0x5Cu;
        }
        Secure_Zero_HMAC(k, sizeof(k));

        // 내부 해시 시작: SHA256(i_key_pad || ...)
        SHA256_Init(&Inner(ctx)->sha_ctx);
        HTS_SHA256_UPDATE(&Inner(ctx)->sha_ctx,
            reinterpret_cast<const unsigned char*>(ipad),
            static_cast<unsigned int>(SHA256_BLOCK));
        Secure_Zero_HMAC(ipad, sizeof(ipad));

        ctx.is_initialized = true;
        return true;
    }

    // =====================================================================
    //  Update — 메시지 청크 누적 (KISA 버그 우회 스마트 큐)
    //
    //  [KISA 버그]
    //  SHA256_Process()에 64바이트 미만 데이터를 전달하면
    //  내부 상태가 손상되는 구현 버그 존재 (일부 KISA 배포 버전)
    //
    //  [우회 전략]
    //  64바이트 큐 버퍼(partial_buf)에 누적 → 64바이트 꽉 찼을 때만 주입
    //  잔여 데이터는 Final에서 마지막으로 주입
    // =====================================================================
    bool HMAC_Bridge::Update(
        HMAC_Context& ctx,
        const uint8_t* data,
        size_t         data_len) noexcept {

        if (!ctx.is_initialized) return false;
        if (!data || data_len == 0) return true;  // 빈 청크 허용
        constexpr size_t U32MAX =
            static_cast<size_t>(std::numeric_limits<uint32_t>::max());
        if (data_len > U32MAX) return false;

        Internal_HMAC_State* state = Inner(ctx);
        size_t offset = 0;
        size_t remaining = data_len;

        while (remaining > 0) {
            size_t space_left = SHA256_BLOCK - state->partial_len;
            size_t copy_len = (remaining < space_left) ? remaining : space_left;

            std::memcpy(state->partial_buf + state->partial_len,
                data + offset, copy_len);
            state->partial_len += static_cast<uint32_t>(copy_len);
            offset += copy_len;
            remaining -= copy_len;

            // 64바이트 꽉 찼을 때만 KISA 함수에 주입
            if (state->partial_len == SHA256_BLOCK) {
                HTS_SHA256_UPDATE(&state->sha_ctx,
                    reinterpret_cast<const unsigned char*>(state->partial_buf),
                    static_cast<unsigned int>(SHA256_BLOCK));
                state->partial_len = 0;
            }
        }
        return true;
    }

    // =====================================================================
    //  Final — HMAC 생성 + 키 소재 전체 보안 소거
    //
    //  inner_hash = SHA256(i_key_pad || message)
    //  HMAC = SHA256(o_key_pad || inner_hash)
    // =====================================================================
    bool HMAC_Bridge::Final(
        HMAC_Context& ctx,
        uint8_t* output_hmac_32bytes) noexcept {

        if (!ctx.is_initialized || !output_hmac_32bytes) {
            Secure_Zero_HMAC(ctx.inner_ctx, sizeof(ctx.inner_ctx));
            Secure_Zero_HMAC(ctx.o_key_pad, sizeof(ctx.o_key_pad));
            ctx.is_initialized = false;
            if (output_hmac_32bytes) {
                Secure_Zero_HMAC(output_hmac_32bytes, SHA256_DIGEST);
            }
            return false;
        }

        Internal_HMAC_State* state = Inner(ctx);

        // 잔여 데이터 마지막 주입
        if (state->partial_len > 0) {
            HTS_SHA256_UPDATE(&state->sha_ctx,
                reinterpret_cast<const unsigned char*>(state->partial_buf),
                static_cast<unsigned int>(state->partial_len));
            state->partial_len = 0;
        }

        // inner_hash = SHA256(i_key_pad || data)
        alignas(4) uint8_t inner_hash[SHA256_DIGEST] = {};
        HTS_SHA256_FINAL(&state->sha_ctx,
            reinterpret_cast<unsigned char*>(inner_hash));

        // HMAC = SHA256(o_key_pad || inner_hash)
        SHA256_INFO outer;
        SHA256_Init(&outer);
        HTS_SHA256_UPDATE(&outer,
            reinterpret_cast<const unsigned char*>(ctx.o_key_pad),
            static_cast<unsigned int>(SHA256_BLOCK));
        HTS_SHA256_UPDATE(&outer,
            reinterpret_cast<const unsigned char*>(inner_hash),
            static_cast<unsigned int>(SHA256_DIGEST));

        // 출력 버퍼 사전 소거 (이전 메모리 잔존 방지)
        Secure_Zero_HMAC(output_hmac_32bytes, SHA256_DIGEST);
        HTS_SHA256_FINAL(&outer,
            reinterpret_cast<unsigned char*>(output_hmac_32bytes));

        // KCMVP Key Zeroization: 모든 키 소재 소거
        Secure_Zero_HMAC(inner_hash, sizeof(inner_hash));
        Secure_Zero_HMAC(&outer, sizeof(outer));
        Secure_Zero_HMAC(ctx.inner_ctx, sizeof(ctx.inner_ctx));
        Secure_Zero_HMAC(ctx.o_key_pad, sizeof(ctx.o_key_pad));
        ctx.is_initialized = false;

        return true;
    }

    // =====================================================================
    //  Verify_Final — HMAC 검증 (상수시간 비교) + 컨텍스트 소거
    // =====================================================================
    bool HMAC_Bridge::Verify_Final(
        HMAC_Context& ctx,
        const uint8_t* received_hmac_32bytes) noexcept {

        if (!received_hmac_32bytes) {
            Secure_Zero_HMAC(ctx.inner_ctx, sizeof(ctx.inner_ctx));
            Secure_Zero_HMAC(ctx.o_key_pad, sizeof(ctx.o_key_pad));
            ctx.is_initialized = false;
            return false;
        }

        alignas(4) uint8_t computed[SHA256_DIGEST] = {};
        if (!Final(ctx, computed)) {
            Secure_Zero_HMAC(computed, sizeof(computed));
            return false;
        }

        bool match = CT_Eq(computed, received_hmac_32bytes, SHA256_DIGEST);
        Secure_Zero_HMAC(computed, sizeof(computed));
        return match;
    }

    // =====================================================================
    //  Generate — 단일 호출 HMAC 생성
    // =====================================================================
    bool HMAC_Bridge::Generate(
        const uint8_t* message, size_t msg_len,
        const uint8_t* key, size_t key_len,
        uint8_t* output_hmac_32bytes) noexcept {

        if (!message || msg_len == 0 || !key ||
            key_len == 0 || !output_hmac_32bytes) return false;

        HMAC_Context ctx;
        if (!Init(ctx, key, key_len)) return false;
        if (!Update(ctx, message, msg_len)) {
            Secure_Zero_HMAC(ctx.inner_ctx, sizeof(ctx.inner_ctx));
            Secure_Zero_HMAC(ctx.o_key_pad, sizeof(ctx.o_key_pad));
            return false;
        }
        return Final(ctx, output_hmac_32bytes);
    }

    // =====================================================================
    //  Verify — 단일 호출 HMAC 검증
    // =====================================================================
    bool HMAC_Bridge::Verify(
        const uint8_t* message, size_t msg_len,
        const uint8_t* key, size_t key_len,
        const uint8_t* received_hmac_32bytes) noexcept {

        if (!message || msg_len == 0 || !key ||
            key_len == 0 || !received_hmac_32bytes) return false;

        HMAC_Context ctx;
        if (!Init(ctx, key, key_len)) return false;
        if (!Update(ctx, message, msg_len)) {
            Secure_Zero_HMAC(ctx.inner_ctx, sizeof(ctx.inner_ctx));
            Secure_Zero_HMAC(ctx.o_key_pad, sizeof(ctx.o_key_pad));
            return false;
        }
        return Verify_Final(ctx, received_hmac_32bytes);
    }

} // namespace ProtectedEngine