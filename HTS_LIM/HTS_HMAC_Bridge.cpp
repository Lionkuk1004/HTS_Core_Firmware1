// =========================================================================
// HTS_HMAC_Bridge.cpp
// KCMVP HMAC-SHA256 브릿지 구현부 (KISA 부분 블록 버그 우회 내장)
// 규격: KS X ISO/IEC 9797-2 / RFC 2104
// Target: STM32F407 (Cortex-M4)
//
#include "HTS_HMAC_Bridge.hpp"
#include "HTS_ConstantTimeUtil.h"
#include "HTS_Secure_Memory.h"
#include <cstring>
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
        "Increase inner_ctx size in HTS_HMAC_Bridge.hpp"
        );

    // inner_ctx → Internal_HMAC_State* 캐스팅 (alignas(4) 보장)
    static inline Internal_HMAC_State* Inner(HMAC_Context& ctx) noexcept {
        return reinterpret_cast<Internal_HMAC_State*>(ctx.inner_ctx);
    }

    // =====================================================================
    //  CT_Eq — HMAC 태그 검증 (ConstantTimeUtil + SECURE_* 분기 없는 매핑)
    //  [C-1] 내부 비교는 HTS_ConstantTimeUtil::compare 단일 경로
    // =====================================================================
    static uint32_t CT_Eq(
        const uint8_t* a, const uint8_t* b, size_t n) noexcept {
        if (!a || !b || n == 0) return HMAC_Bridge::SECURE_FALSE;
        const bool same = ConstantTimeUtil::compare(a, b, n);
        const uint32_t mask = 0u - static_cast<uint32_t>(same);
        return (HMAC_Bridge::SECURE_TRUE & mask)
            | (HMAC_Bridge::SECURE_FALSE & ~mask);
    }

    // =====================================================================
    //  Init — 키 설정 + 내부 해시 시작
    //
    //  [RFC 2104 키 정규화]
    //  key_len > 64: SHA256(key)로 32바이트 압축
    //  key_len ≤ 64: 0 패딩하여 64바이트로 확장
    //  i_key_pad = key ^ 0x36 (내부 패딩)
    //  o_key_pad = key ^ 0x5C (외부 패딩 — Final에서 사용)
    // =====================================================================
    uint32_t HMAC_Bridge::Init(
        HMAC_Context& ctx,
        const uint8_t* key,
        size_t         key_len) noexcept {

        if (!key || key_len == 0) return SECURE_FALSE;
        constexpr size_t U32MAX =
            static_cast<size_t>(std::numeric_limits<uint32_t>::max());
        if (key_len > U32MAX) return SECURE_FALSE;

        SecureMemory::secureWipe(static_cast<void*>(ctx.inner_ctx), sizeof(ctx.inner_ctx));
        SecureMemory::secureWipe(static_cast<void*>(ctx.o_key_pad), sizeof(ctx.o_key_pad));
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
            SecureMemory::secureWipe(static_cast<void*>(&tmp), sizeof(tmp));
        }
        else {
            std::memcpy(k, key, key_len);
        }

        // i_key_pad / o_key_pad 생성
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
        SecureMemory::secureWipe(static_cast<void*>(k), sizeof(k));

        // 내부 해시 시작: SHA256(i_key_pad || ...)
        SHA256_Init(&Inner(ctx)->sha_ctx);
        HTS_SHA256_UPDATE(&Inner(ctx)->sha_ctx,
            reinterpret_cast<const unsigned char*>(ipad),
            static_cast<unsigned int>(SHA256_BLOCK));
        SecureMemory::secureWipe(static_cast<void*>(ipad), sizeof(ipad));

        ctx.is_initialized = true;
        return SECURE_TRUE;
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
    uint32_t HMAC_Bridge::Update(
        HMAC_Context& ctx,
        const uint8_t* data,
        size_t         data_len) noexcept {

        if (!ctx.is_initialized) return SECURE_FALSE;
        // 빈 청크(msg_len==0)는 RFC 2104 상 합법 — nullptr 허용
        if (data_len == 0u) return SECURE_TRUE;
        // Fail-closed: 길이>0 인데 포인터 없음 → 조용히 성공 금지
        if (!data) return SECURE_FALSE;
        constexpr size_t U32MAX =
            static_cast<size_t>(std::numeric_limits<uint32_t>::max());
        if (data_len > U32MAX) return SECURE_FALSE;

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
        return SECURE_TRUE;
    }

    // =====================================================================
    //  Final — HMAC 생성 + 키 소재 전체 보안 소거
    //
    //  inner_hash = SHA256(i_key_pad || message)
    //  HMAC = SHA256(o_key_pad || inner_hash)
    // =====================================================================
    uint32_t HMAC_Bridge::Final(
        HMAC_Context& ctx,
        uint8_t* output_hmac_32bytes) noexcept {

        if (!ctx.is_initialized || !output_hmac_32bytes) {
            SecureMemory::secureWipe(static_cast<void*>(ctx.inner_ctx), sizeof(ctx.inner_ctx));
            SecureMemory::secureWipe(static_cast<void*>(ctx.o_key_pad), sizeof(ctx.o_key_pad));
            ctx.is_initialized = false;
            if (output_hmac_32bytes) {
                SecureMemory::secureWipe(static_cast<void*>(output_hmac_32bytes), SHA256_DIGEST);
            }
            return SECURE_FALSE;
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

        // 출력은 HTS_SHA256_FINAL이 전부 덮어씀. 호출 전 소거는 Verify_Final(computed) 등
        // 호출자 수명/오류 경로와 충돌할 수 있어 여기서는 하지 않음.
        HTS_SHA256_FINAL(&outer,
            reinterpret_cast<unsigned char*>(output_hmac_32bytes));

        // KCMVP Key Zeroization: 모든 키 소재 소거
        SecureMemory::secureWipe(static_cast<void*>(inner_hash), sizeof(inner_hash));
        SecureMemory::secureWipe(static_cast<void*>(&outer), sizeof(outer));
        SecureMemory::secureWipe(static_cast<void*>(ctx.inner_ctx), sizeof(ctx.inner_ctx));
        SecureMemory::secureWipe(static_cast<void*>(ctx.o_key_pad), sizeof(ctx.o_key_pad));
        ctx.is_initialized = false;

        return SECURE_TRUE;
    }

    // =====================================================================
    //  Verify_Final — HMAC 검증 (상수시간 비교) + 컨텍스트 소거
    // =====================================================================
    uint32_t HMAC_Bridge::Verify_Final(
        HMAC_Context& ctx,
        const uint8_t* received_hmac_32bytes) noexcept {

        if (!received_hmac_32bytes) {
            SecureMemory::secureWipe(static_cast<void*>(ctx.inner_ctx), sizeof(ctx.inner_ctx));
            SecureMemory::secureWipe(static_cast<void*>(ctx.o_key_pad), sizeof(ctx.o_key_pad));
            ctx.is_initialized = false;
            return SECURE_FALSE;
        }

        alignas(4) uint8_t computed[SHA256_DIGEST] = {};
        if (Final(ctx, computed) != SECURE_TRUE) {
            SecureMemory::secureWipe(static_cast<void*>(computed), sizeof(computed));
            return SECURE_FALSE;
        }

        const uint32_t match = CT_Eq(computed, received_hmac_32bytes, SHA256_DIGEST);
        SecureMemory::secureWipe(static_cast<void*>(computed), sizeof(computed));
        return match;
    }

    // =====================================================================
    //  Generate — 단일 호출 HMAC 생성
    // =====================================================================
    uint32_t HMAC_Bridge::Generate(
        const uint8_t* message, size_t msg_len,
        const uint8_t* key, size_t key_len,
        uint8_t* output_hmac_32bytes) noexcept {

        // 빈 메시지(msg_len==0, header-only 등)는 RFC 2104 상 합법 — msg_len>0일 때만 message 필수
        if (!key || key_len == 0 || !output_hmac_32bytes) return SECURE_FALSE;
        if (msg_len > 0u && !message) return SECURE_FALSE;

        HMAC_Context ctx;
        if (Init(ctx, key, key_len) != SECURE_TRUE) return SECURE_FALSE;
        if (Update(ctx, message, msg_len) != SECURE_TRUE) {
            SecureMemory::secureWipe(static_cast<void*>(ctx.inner_ctx), sizeof(ctx.inner_ctx));
            SecureMemory::secureWipe(static_cast<void*>(ctx.o_key_pad), sizeof(ctx.o_key_pad));
            return SECURE_FALSE;
        }
        return Final(ctx, output_hmac_32bytes);
    }

    // =====================================================================
    //  Verify — 단일 호출 HMAC 검증
    // =====================================================================
    uint32_t HMAC_Bridge::Verify(
        const uint8_t* message, size_t msg_len,
        const uint8_t* key, size_t key_len,
        const uint8_t* received_hmac_32bytes) noexcept {

        if (!key || key_len == 0 || !received_hmac_32bytes) return SECURE_FALSE;
        if (msg_len > 0u && !message) return SECURE_FALSE;

        HMAC_Context ctx;
        if (Init(ctx, key, key_len) != SECURE_TRUE) return SECURE_FALSE;
        if (Update(ctx, message, msg_len) != SECURE_TRUE) {
            SecureMemory::secureWipe(static_cast<void*>(ctx.inner_ctx), sizeof(ctx.inner_ctx));
            SecureMemory::secureWipe(static_cast<void*>(ctx.o_key_pad), sizeof(ctx.o_key_pad));
            return SECURE_FALSE;
        }
        return Verify_Final(ctx, received_hmac_32bytes);
    }

} // namespace ProtectedEngine
