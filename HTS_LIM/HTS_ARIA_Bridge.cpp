// =========================================================================
// HTS_ARIA_Bridge.cpp
// KCMVP ARIA 블록 암호 브릿지 구현부
// 규격: KS X 1213-1 (2009)
// Target: STM32F407 (Cortex-M4)
//
// [양산 수정 — 5건 결함 교정]
//
//  BUG-01 [MEDIUM] C26495 — 멤버 기본값 미초기화
//    기존: round_keys[272] → 값 초기화 없음 (생성자에서 Secure_Zero)
//          num_rounds, is_initialized → 기본값 없음
//    수정: 헤더에서 = {} / = 0 / = false 기본값 할당
//
//  BUG-02 [MEDIUM] Secure_Zero: pragma O0 보호 누락
//    기존: volatile + atomic_thread_fence만 사용
//          volatile은 C/C++ 표준상 "동시성 메모리 접근" 용도가 아님
//          일부 컴파일러가 "사용되지 않는 메모리에 volatile 쓰기" 를 최적화할 가능성
//    수정: pragma O0 push/pop 추가 (프로젝트 보안 소거 표준 패턴)
//
//  BUG-03 [MEDIUM] Process_Block: 실패 시 출력 버퍼 미소거
//    기존: false 반환 → output_16bytes에 이전 메모리 데이터 잔존
//          호출자가 반환값 무시 시 키스트림 또는 이전 평문 노출 가능
//    수정: 실패 경로에서 출력 16바이트 보안 소거
//
//  BUG-04 [LOW] 매직 넘버 272 반복 사용
//    수정: ARIA_Bridge::ROUND_KEY_BUF_SIZE 명명 상수 사용
//
//  BUG-05 [LOW] KCMVP 인증 문서화 보강
//
// [KISA ARIA C 구현체 연결]
//  aria.c (KISA 공식 배포) → extern "C" 선언으로 링크
//  EncKeySetup: 암호화 라운드 키 생성 → 라운드 수 반환
//  DecKeySetup: 복호화 라운드 키 생성 → 라운드 수 반환
//  Crypt:       16바이트 블록 암/복호화 (라운드 키 + 라운드 수 기반)
//
// [STM32F407 성능]
//  키 스케줄 (256비트): ~15K사이클 ≈ 0.09ms @168MHz
//  블록 암/복호화 (16B): ~3K사이클 ≈ 0.018ms @168MHz
//  Flash: ~500바이트 (브릿지) + ~2KB (aria.c KISA 원본)
// =========================================================================
#include "HTS_ARIA_Bridge.h"
#include <cstring>
#include <atomic>

// =========================================================================
//  KISA ARIA C 구현체 extern "C" 링크
//  Byte typedef: extern "C" 블록 내부 한정 (전역 오염 방지)
// =========================================================================
extern "C" {
    typedef unsigned char Byte;

    // 성공 시 라운드 수(12/14/16) 반환, 실패 시 음수 또는 0
    int  EncKeySetup(const Byte* mk, Byte* rk, int keyBits);
    int  DecKeySetup(const Byte* mk, Byte* rk, int keyBits);

    // 16바이트 블록 암/복호화
    void Crypt(const Byte* i, int Nr, const Byte* rk, Byte* o);
}

namespace ProtectedEngine {

    // =====================================================================
    //  유효 라운드 수 검증
    //  ARIA-128: 12 / ARIA-192: 14 / ARIA-256: 16
    // =====================================================================
    static bool Is_Valid_Round_Count(int r) noexcept {
        return (r == 12 || r == 14 || r == 16);
    }

    // =====================================================================
    //  보안 메모리 소거 — KCMVP 키 소재 잔존 방지(Key Zeroization)
    //
    //  [BUG-02 수정] pragma O0 추가
    //  3중 DCE 방지: pragma O0 + volatile + atomic_thread_fence
    //  → 가장 공격적인 최적화에서도 소거 코드가 삭제되지 않음 보장
    // =====================================================================
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC push_options
#pragma GCC optimize("O0")
#elif defined(_MSC_VER)
#pragma optimize("", off)
#endif

    static void Secure_Zero(void* ptr, size_t size) noexcept {
        if (!ptr || size == 0) return;
        volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
        for (size_t i = 0; i < size; ++i) {
            p[i] = 0;
        }
        // [BUG] seq_cst → release (소거 배리어 정책 통일)
        std::atomic_thread_fence(std::memory_order_release);
    }

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC pop_options
#elif defined(_MSC_VER)
#pragma optimize("", on)
#endif

    // =====================================================================
    //  내부 키 스케줄 공통 로직 — 암호화/복호화 중복 제거
    // =====================================================================
    static bool Do_KeySetup(
        const uint8_t* master_key,
        int            key_bits,
        uint8_t* round_keys,
        int& num_rounds,
        bool& is_initialized,
        bool           is_enc) noexcept {

        if (!master_key ||
            (key_bits != 128 && key_bits != 192 && key_bits != 256)) {
            return false;
        }

        // 이전 키 소재 소거 후 재설정
        is_initialized = false;
        Secure_Zero(round_keys, ARIA_Bridge::ROUND_KEY_BUF_SIZE);

        int rounds = is_enc
            ? EncKeySetup(
                reinterpret_cast<const Byte*>(master_key),
                reinterpret_cast<Byte*>(round_keys),
                key_bits)
            : DecKeySetup(
                reinterpret_cast<const Byte*>(master_key),
                reinterpret_cast<Byte*>(round_keys),
                key_bits);

        if (!Is_Valid_Round_Count(rounds)) {
            Secure_Zero(round_keys, ARIA_Bridge::ROUND_KEY_BUF_SIZE);
            num_rounds = 0;
            return false;
        }

        num_rounds = rounds;
        is_initialized = true;
        return true;
    }

    // =====================================================================
    //  생성자
    // =====================================================================
    ARIA_Bridge::ARIA_Bridge() noexcept
        : round_keys{}
        , num_rounds(0)
        , is_initialized(false) {
        // round_keys는 = {} 값 초기화로 이미 0이지만,
        // KCMVP 감사 투명성을 위해 명시적 Secure_Zero 호출 유지
        Secure_Zero(round_keys, ROUND_KEY_BUF_SIZE);
    }

    // =====================================================================
    //  소멸자 — KCMVP 요건: 키 소재 반드시 소거
    // =====================================================================
    ARIA_Bridge::~ARIA_Bridge() noexcept {
        Secure_Zero(round_keys, ROUND_KEY_BUF_SIZE);
        num_rounds = 0;
        is_initialized = false;
    }

    // =====================================================================
    //  Reset — 명시적 키 소재 소거
    // =====================================================================
    void ARIA_Bridge::Reset() noexcept {
        Secure_Zero(round_keys, ROUND_KEY_BUF_SIZE);
        num_rounds = 0;
        is_initialized = false;
    }

    // =====================================================================
    //  Initialize_Encryption
    // =====================================================================
    bool ARIA_Bridge::Initialize_Encryption(
        const uint8_t* master_key, int key_bits) noexcept {

        return Do_KeySetup(
            master_key, key_bits,
            round_keys, num_rounds, is_initialized, true);
    }

    // =====================================================================
    //  Initialize_Decryption
    // =====================================================================
    bool ARIA_Bridge::Initialize_Decryption(
        const uint8_t* master_key, int key_bits) noexcept {

        return Do_KeySetup(
            master_key, key_bits,
            round_keys, num_rounds, is_initialized, false);
    }

    // =====================================================================
    //  Process_Block — ARIA 16바이트 블록 암/복호화
    //
    //  [BUG-03 수정] 실패 시 출력 버퍼 보안 소거
    //  기존: false 반환 → output_16bytes에 이전 메모리 데이터 잔존
    //  수정: 모든 실패 경로에서 출력 16바이트를 0으로 소거
    //  → 호출자가 [[nodiscard]] 경고를 무시하더라도 키스트림 미누출
    // =====================================================================
    bool ARIA_Bridge::Process_Block(
        const uint8_t* input_16bytes,
        uint8_t* output_16bytes) noexcept {

        if (!is_initialized ||
            !input_16bytes ||
            !output_16bytes ||
            !Is_Valid_Round_Count(num_rounds)) {
            // [BUG-03] 실패 시 출력 소거 (output이 유효한 경우에만)
            if (output_16bytes) {
                Secure_Zero(output_16bytes, 16);
            }
            return false;
        }

        // in-place 미지원 (KISA Crypt 함수 제약)
        if (input_16bytes == output_16bytes) {
            Secure_Zero(output_16bytes, 16);
            return false;
        }

        Crypt(
            reinterpret_cast<const Byte*>(input_16bytes),
            num_rounds,
            reinterpret_cast<const Byte*>(round_keys),
            reinterpret_cast<Byte*>(output_16bytes)
        );

        return true;
    }

} // namespace ProtectedEngine