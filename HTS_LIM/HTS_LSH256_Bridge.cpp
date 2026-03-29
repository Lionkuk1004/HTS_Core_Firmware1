// =========================================================================
// HTS_LSH256_Bridge.cpp
// KCMVP LSH-256 / LSH-224 해시 브릿지 구현부
// 규격: KS X 3262
// Target: STM32F407 (Cortex-M4)
//
// [양산 수정 — 4건 결함 교정]
//
//  BUG-01 [MEDIUM] Secure_Zero: pragma O0 보호 누락
//    수정: pragma O0 push/pop 추가 (프로젝트 3중 보호 표준)
//
//  BUG-02 [MEDIUM] Do_Hash: lsh256_final 실패 시 출력 버퍼 미소거
//    기존: final 실패 → ctx만 소거, output에 부분 해시 잔존
//          공격자가 실패 경로를 유도하여 부분 해시 수집 가능
//    수정: 모든 실패 경로에서 output 보안 소거
//
//  BUG-03 [LOW] Do_Hash 호출 시 매직 넘버 32/28 → 명명 상수
//    수정: LSH256_DIGEST_BYTES / LSH224_DIGEST_BYTES 사용
//
//  BUG-04 [LOW] constexpr → static const (MSVC C2131 호환 일관성)
//    수정: 헤더에서 static const size_t로 변경
//
// [NSR LSH-256 API 정리]
//  lsh256_init(&ctx, algtype):      초기화 → LSH_SUCCESS
//  lsh256_update(&ctx, data, bitlen): 데이터 주입 (비트 단위!) → LSH_SUCCESS
//  lsh256_final(&ctx, hashval):      최종 해시 출력 → LSH_SUCCESS
//  lsh256_digest(algtype, data, bitlen, hashval): 단일 호출 (내부에서 init+update+final)
//
// [STM32F407 성능]
//  Hash_256 (1KB 데이터): ~25K사이클 ≈ 0.15ms @168MHz
//  Hash_256 (16B 블록):   ~3K사이클 ≈ 0.018ms @168MHz
//  LSH는 SHA-256 대비 약 1.5배 고속 (ARX 구조 + 워드 병렬)
// =========================================================================
#include "HTS_LSH256_Bridge.h"
#include <cstring>
#include <atomic>
#include <limits>
#include <cstdint>

// =========================================================================
//  NSR LSH-256 원본 C 라이브러리 연결
// =========================================================================
extern "C" {
#include "lsh256.h"
#include "lsh.h"
}

namespace ProtectedEngine {

    // =====================================================================
    //  보안 메모리 소거 — KCMVP 해시 내부 상태 잔존 방지
    //
    //  [BUG-01 수정] pragma O0 추가 — 3중 DCE 방지
    // =====================================================================
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC push_options
#pragma GCC optimize("O0")
#elif defined(_MSC_VER)
#pragma optimize("", off)
#endif

    static void Secure_Zero_LSH(void* ptr, size_t size) noexcept {
        if (!ptr || size == 0) return;
        volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
        for (size_t i = 0; i < size; ++i) p[i] = 0;
        // [BUG] seq_cst → release (소거 배리어 정책 통일)
        std::atomic_thread_fence(std::memory_order_release);
    }

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC pop_options
#elif defined(_MSC_VER)
#pragma optimize("", on)
#endif

    // =====================================================================
    //  내부 공통 해시 계산
    //
    //  [바이트→비트 변환]
    //  NSR lsh256_update는 databitlen을 비트 단위로 받음 (API 설계)
    //  → data_len * 8 에서 SIZE_MAX/8 초과 시 오버플로 → 사전 검증
    //
    //  [BUG-02 수정] 모든 실패 경로에서 output 보안 소거
    //  lsh256_final 실패 시에도 output에 부분 데이터가 남을 수 있음
    //  → Secure_Zero_LSH(output) 후 false 반환
    // =====================================================================
    static bool Do_Hash(
        lsh_type       algtype,
        const uint8_t* data,
        size_t         data_len,
        uint8_t* output,
        size_t         output_len) noexcept {

        // 출력 버퍼 필수 / 데이터 포인터는 길이 0이면 null 허용
        if (!output) return false;
        if (data_len > 0 && !data) {
            Secure_Zero_LSH(output, output_len);
            return false;
        }

        // 바이트 → 비트 변환 오버플로 방어
        constexpr size_t MAX_BYTE_LEN =
            std::numeric_limits<size_t>::max() / 8u;
        if (data_len > MAX_BYTE_LEN) {
            Secure_Zero_LSH(output, output_len);
            return false;
        }

        // LSH-256 컨텍스트 초기화
        struct LSH256_Context ctx;
        Secure_Zero_LSH(&ctx, sizeof(ctx));

        lsh_err err = lsh256_init(&ctx, algtype);
        if (err != LSH_SUCCESS) {
            Secure_Zero_LSH(&ctx, sizeof(ctx));
            Secure_Zero_LSH(output, output_len);
            return false;
        }

        // 데이터 주입 (비트 단위)
        if (data_len > 0) {
            size_t databitlen = data_len * 8u;
            err = lsh256_update(&ctx,
                reinterpret_cast<const lsh_u8*>(data),
                databitlen);
            if (err != LSH_SUCCESS) {
                Secure_Zero_LSH(&ctx, sizeof(ctx));
                Secure_Zero_LSH(output, output_len);
                return false;
            }
        }

        // 최종 해시 계산
        err = lsh256_final(&ctx, reinterpret_cast<lsh_u8*>(output));

        // 내부 상태 보안 소거 (KCMVP Key Zeroization)
        Secure_Zero_LSH(&ctx, sizeof(ctx));

        // [BUG-02] final 실패 시 출력 소거
        if (err != LSH_SUCCESS) {
            Secure_Zero_LSH(output, output_len);
            return false;
        }

        return true;
    }

    // =====================================================================
    //  Hash_256 — LSH-256 (32바이트 출력)
    // =====================================================================
    bool LSH256_Bridge::Hash_256(
        const uint8_t* data,
        size_t         data_len,
        uint8_t* output_32) noexcept {

        if (!output_32) return false;

        return Do_Hash(
            LSH_TYPE_256_256,
            data, data_len,
            output_32, LSH256_DIGEST_BYTES);
    }

    // =====================================================================
    //  Hash_224 — LSH-224 (28바이트 출력)
    // =====================================================================
    bool LSH256_Bridge::Hash_224(
        const uint8_t* data,
        size_t         data_len,
        uint8_t* output_28) noexcept {

        if (!output_28) return false;

        return Do_Hash(
            LSH_TYPE_256_224,
            data, data_len,
            output_28, LSH224_DIGEST_BYTES);
    }

} // namespace ProtectedEngine