// =========================================================================
// HTS_LEA_Bridge.cpp
// KCMVP LEA 블록 암호 CTR 모드 브릿지 구현부
// 규격: TTAS.KO-12.0223 (LEA)
// Target: STM32F407 (Cortex-M4)
//
// [양산 수정 — 6건 결함 교정]
//
//  BUG-01 [CRITICAL] Secure_Zero_Self() 헤더 선언만 존재, .cpp에 미정의
//    기존: void Secure_Zero_Self() noexcept; 선언 → LNK2019
//          현재 아무도 호출하지 않아 발현하지 않았으나, 헤더를 include하는
//          다른 모듈이 호출을 시도하면 즉시 링크 에러
//    수정: 헤더에서 선언 제거 (static Secure_Zero_LEA 내부 함수로 대체)
//
//  BUG-02 [CRITICAL] CTR 카운터 이중 증가 → TX/RX 복호화 실패
//    기존: lea_ctr_enc(byte_ptr, ..., iv_counter, ...) 호출 후
//          수동 Increment_CTR(iv_counter, block_count) 추가 호출
//    분석: KISA lea_ctr_enc 시그니처:
//          void lea_ctr_enc(ct, pt, pt_len, unsigned char *ctr, key)
//          ctr 파라미터가 non-const → 함수 내부에서 CTR을 증가시킴
//          → 수동 증가 시 CTR이 2배 진행 = TX와 RX의 카운터 불일치
//          → RX 복호화가 틀린 키스트림을 생성 → 평문 복원 실패
//    수정: Increment_CTR 함수 및 호출 전부 삭제
//          KISA API가 내부적으로 CTR을 관리하므로 외부 개입 불필요
//
//  BUG-03 [MEDIUM] Secure_Zero: pragma O0 보호 누락
//    수정: pragma O0 push/pop 추가 (프로젝트 3중 보호 표준)
//
//  BUG-04 [MEDIUM] C26495 — session_key(LEA_KEY POD), iv_counter, is_initialized
//    수정: 헤더에서 iv_counter = {}, is_initialized = false
//          session_key는 POD → 생성자 Secure_Zero로 초기화
//
//  BUG-05 [MEDIUM] [[nodiscard]] 누락 — Initialize/Encrypt/Decrypt
//    수정: 헤더에서 [[nodiscard]] 추가
//
//  BUG-06 [LOW] Initialize 내 session_key 이중 Secure_Zero
//    기존: 59행 Secure_Zero, 64행 또 Secure_Zero (동일 대상, 연속 호출)
//    수정: 1회로 통합
//
// [KISA LEA API 동작 확인]
//  lea_set_key(key, mk, mk_len): void — 키 스케줄 수행, 반환값 없음
//  lea_ctr_enc(ct, pt, len, ctr, key): void — CTR 암호화 + ctr 내부 증가
//  lea_ctr_dec(pt, ct, len, ctr, key): void — CTR 복호화 + ctr 내부 증가
//  ctr 파라미터: unsigned char* (non-const) → 함수 내부에서 수정
//
// [STM32F407 성능]
//  키 스케줄 (256비트):    ~5K사이클 ≈ 0.03ms @168MHz
//  CTR 암/복호화 (16B):    ~1.5K사이클 ≈ 0.009ms @168MHz
//  LEA는 ARIA 대비 약 2배 고속 (ARX 구조 — 곱셈 없음)
// =========================================================================
#include "HTS_LEA_Bridge.h"
#include <cstring>
#include <atomic>
#include <limits>

namespace ProtectedEngine {

    // =====================================================================
    //  보안 메모리 소거 — KCMVP Key Zeroization
    //
    //  [BUG-03 수정] pragma O0 추가
    //  3중 DCE 방지: pragma O0 + volatile + atomic_thread_fence
    // =====================================================================
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC push_options
#pragma GCC optimize("O0")
#elif defined(_MSC_VER)
#pragma optimize("", off)
#endif

    static void Secure_Zero_LEA(void* ptr, size_t size) noexcept {
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
    //  생성자
    // =====================================================================
    LEA_Bridge::LEA_Bridge() noexcept
        : iv_counter{}
        , is_initialized(false) {
        Secure_Zero_LEA(&session_key, sizeof(LEA_KEY));
    }

    // =====================================================================
    //  소멸자 — KCMVP 요건: 키 소재 반드시 소거
    // =====================================================================
    LEA_Bridge::~LEA_Bridge() noexcept {
        Secure_Zero_LEA(&session_key, sizeof(LEA_KEY));
        Secure_Zero_LEA(iv_counter, sizeof(iv_counter));
        is_initialized = false;
    }

    // =====================================================================
    //  Initialize — LEA 키 스케줄 + IV 설정
    //
    //  [키 검증 전략]
    //  KISA lea_set_key()는 void 반환 — 직접 성공/실패 판별 불가
    //  → session_key를 사전 0으로 소거
    //  → lea_set_key 호출
    //  → session_key 전체가 여전히 0이면 키 세팅 실패로 간주 (간접 검증)
    //
    //  [BUG-06 수정] 이중 Secure_Zero 제거 → 1회로 통합
    // =====================================================================
    bool LEA_Bridge::Initialize(
        const uint8_t* master_key,
        uint32_t       key_len_bytes,
        const uint8_t* initial_vector) noexcept {

        if (!master_key || !initial_vector) return false;
        if (key_len_bytes != 16u &&
            key_len_bytes != 24u &&
            key_len_bytes != 32u) return false;

        // 이전 상태 완전 소거
        is_initialized = false;
        Secure_Zero_LEA(&session_key, sizeof(LEA_KEY));
        Secure_Zero_LEA(iv_counter, sizeof(iv_counter));

        // KISA LEA 키 스케줄 (void 반환)
        lea_set_key(&session_key, master_key, key_len_bytes);

        // 간접 키 검증: 전체 0이면 실패 간주
        volatile uint8_t key_check = 0;
        const auto* key_bytes = reinterpret_cast<const uint8_t*>(&session_key);
        for (size_t i = 0; i < sizeof(LEA_KEY); ++i) {
            key_check |= key_bytes[i];
        }
        if (key_check == 0) {
            Secure_Zero_LEA(&session_key, sizeof(LEA_KEY));
            return false;
        }

        // CTR 모드 IV 복사 (16바이트 고정)
        std::memcpy(iv_counter, initial_vector, 16u);

        is_initialized = true;
        return true;
    }

    // =====================================================================
    //  Encrypt_Payload — LEA-CTR 암호화 (인플레이스)
    //
    //  [BUG-02 수정] CTR 이중 증가 제거
    //  KISA lea_ctr_enc(ct, pt, len, ctr, key):
    //    ctr 파라미터 = unsigned char* (non-const)
    //    → 함수 내부에서 블록 수만큼 CTR을 증가시킴
    //    → 외부에서 추가 증가 시 TX/RX CTR 불일치 → 복호화 실패
    //  수정: Increment_CTR 호출 삭제 — KISA API 내부 관리에 위임
    // =====================================================================
    bool LEA_Bridge::Encrypt_Payload(
        uint32_t* payload_data, size_t elements) noexcept {

        if (!is_initialized || !payload_data || elements == 0) return false;

        // 곱셈 오버플로 방어
        constexpr size_t UINT32_SIZE = sizeof(uint32_t);
        if (elements > std::numeric_limits<size_t>::max() / UINT32_SIZE) {
            return false;
        }
        size_t total_bytes = elements * UINT32_SIZE;

        // unsigned int 절사 방어 (KISA API 파라미터 타입)
        if (total_bytes > static_cast<size_t>(
            std::numeric_limits<unsigned int>::max())) {
            return false;
        }

        auto* byte_ptr = reinterpret_cast<uint8_t*>(payload_data);

        // KISA LEA CTR 암호화
        // ctr(iv_counter)는 함수 내부에서 블록 수만큼 자동 증가됨
        lea_ctr_enc(
            byte_ptr,                                // ct (출력)
            byte_ptr,                                // pt (입력 = 인플레이스)
            static_cast<unsigned int>(total_bytes),   // 바이트 수
            iv_counter,                              // CTR (내부 증가)
            &session_key                             // 키
        );

        return true;
    }

    // =====================================================================
    //  Decrypt_Payload — LEA-CTR 복호화 (인플레이스)
    //
    //  [BUG-02 수정] CTR 이중 증가 제거 (Encrypt와 동일 근거)
    // =====================================================================
    bool LEA_Bridge::Decrypt_Payload(
        uint32_t* payload_data, size_t elements) noexcept {

        if (!is_initialized || !payload_data || elements == 0) return false;

        constexpr size_t UINT32_SIZE = sizeof(uint32_t);
        if (elements > std::numeric_limits<size_t>::max() / UINT32_SIZE) {
            return false;
        }
        size_t total_bytes = elements * UINT32_SIZE;

        if (total_bytes > static_cast<size_t>(
            std::numeric_limits<unsigned int>::max())) {
            return false;
        }

        auto* byte_ptr = reinterpret_cast<uint8_t*>(payload_data);

        // KISA LEA CTR 복호화
        // ctr(iv_counter)는 함수 내부에서 블록 수만큼 자동 증가됨
        lea_ctr_dec(
            byte_ptr,                                // pt (출력)
            byte_ptr,                                // ct (입력 = 인플레이스)
            static_cast<unsigned int>(total_bytes),   // 바이트 수
            iv_counter,                              // CTR (내부 증가)
            &session_key                             // 키
        );

        return true;
    }

} // namespace ProtectedEngine