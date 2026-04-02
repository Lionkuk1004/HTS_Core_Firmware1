// =========================================================================
// HTS_LEA_Bridge.cpp
// KCMVP LEA 블록 암호 CTR 모드 브릿지 구현부
// 규격: TTAS.KO-12.0223 (LEA)
// Target: STM32F407 (Cortex-M4)
//
#include "HTS_LEA_Bridge.h"
#include <cstring>
#include <atomic>
#include <limits>

namespace ProtectedEngine {
    struct LEA_Busy_Guard {
        std::atomic_flag& f;
        uint32_t locked;
        explicit LEA_Busy_Guard(std::atomic_flag& flag) noexcept
            : f(flag), locked(LEA_Bridge::SECURE_FALSE) {
            if (!f.test_and_set(std::memory_order_acquire)) {
                locked = LEA_Bridge::SECURE_TRUE;
            }
        }
        ~LEA_Busy_Guard() noexcept {
            if (locked == LEA_Bridge::SECURE_TRUE) {
                f.clear(std::memory_order_release);
            }
        }
    };

    // =====================================================================
    //  보안 메모리 소거 — KCMVP Key Zeroization
    //
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
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        // 소거 배리어: memory_order_release
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
        : tx_iv_counter{}
        , rx_iv_counter{}
        , is_initialized(false) {
        Secure_Zero_LEA(&session_key, sizeof(LEA_KEY));
    }

    // =====================================================================
    //  소멸자 — KCMVP 요건: 키 소재 반드시 소거
    // =====================================================================
    LEA_Bridge::~LEA_Bridge() noexcept {
        Secure_Zero_LEA(&session_key, sizeof(LEA_KEY));
        Secure_Zero_LEA(tx_iv_counter, sizeof(tx_iv_counter));
        Secure_Zero_LEA(rx_iv_counter, sizeof(rx_iv_counter));
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
    // =====================================================================
    uint32_t LEA_Bridge::Initialize(
        const uint8_t* master_key,
        uint32_t       key_len_bytes,
        const uint8_t* initial_vector,
        uint32_t       iv_len_bytes) noexcept {
        LEA_Busy_Guard guard(op_busy_);
        if (guard.locked != SECURE_TRUE) { return SECURE_FALSE; }

        if (!master_key || !initial_vector) return SECURE_FALSE;
        if (iv_len_bytes != 16u) return SECURE_FALSE;
        if (key_len_bytes != 16u &&
            key_len_bytes != 24u &&
            key_len_bytes != 32u) return SECURE_FALSE;

        // 이전 상태 완전 소거
        is_initialized = false;
        Secure_Zero_LEA(&session_key, sizeof(LEA_KEY));
        Secure_Zero_LEA(tx_iv_counter, sizeof(tx_iv_counter));
        Secure_Zero_LEA(rx_iv_counter, sizeof(rx_iv_counter));

        // KISA LEA 키 스케줄 (void 반환)
        lea_set_key(&session_key, master_key, key_len_bytes);

        // 간접 키 검증: 전체 0이면 실패 간주 (레지스터 누산 — volatile 불필요)
        uint8_t key_check = 0;
        const auto* key_bytes = reinterpret_cast<const uint8_t*>(&session_key);
        for (size_t i = 0; i < sizeof(LEA_KEY); ++i) {
            key_check = static_cast<uint8_t>(key_check | key_bytes[i]);
        }
        if (key_check == 0) {
            Secure_Zero_LEA(&session_key, sizeof(LEA_KEY));
            return SECURE_FALSE;
        }

        // CTR 모드 IV: 송신/수신 카운터 분리 (동일 세션 기준값으로 양쪽 초기화)
        std::memcpy(tx_iv_counter, initial_vector, 16u);
        std::memcpy(rx_iv_counter, initial_vector, 16u);

        is_initialized = true;
        return SECURE_TRUE;
    }

    // =====================================================================
    //  Encrypt_Payload — LEA-CTR 암호화 (인플레이스)
    //
    //  KISA lea_ctr_enc(ct, pt, len, ctr, key):
    //    len은 16바이트 배수만 허용 (부분 블록 시 키스트림 동기화 붕괴 방지)
    //    tx_iv_counter만 갱신 — 복호화 경로(rx_iv_counter)와 독립
    // =====================================================================
    uint32_t LEA_Bridge::Encrypt_Payload(
        uint32_t* payload_data, size_t elements) noexcept {
        LEA_Busy_Guard guard(op_busy_);
        if (guard.locked != SECURE_TRUE) { return SECURE_FALSE; }

        if (!is_initialized || !payload_data || elements == 0u) return SECURE_FALSE;
        const uintptr_t payload_addr = reinterpret_cast<uintptr_t>(payload_data);
        if ((payload_addr & (alignof(uint32_t) - 1u)) != 0u) { return SECURE_FALSE; }

        // 곱셈 오버플로 방어
        constexpr size_t UINT32_SIZE = sizeof(uint32_t);
        if (elements > std::numeric_limits<size_t>::max() / UINT32_SIZE) {
            return SECURE_FALSE;
        }
        size_t total_bytes = elements * UINT32_SIZE;

        // KISA CTR: 블록(16B) 미만분 키스트림 유실 방지 — 배수만 허용
        if ((total_bytes % 16u) != 0u) { return SECURE_FALSE; }

        // unsigned int 절사 방어 (KISA API 파라미터 타입)
        if (total_bytes > static_cast<size_t>(
            std::numeric_limits<unsigned int>::max())) {
            return SECURE_FALSE;
        }

        auto* byte_ptr = reinterpret_cast<uint8_t*>(payload_data);

        // KISA LEA CTR 암호화 — tx_iv_counter만 갱신 (수신과 독립)
        lea_ctr_enc(
            byte_ptr,                                // ct (출력)
            byte_ptr,                                // pt (입력 = 인플레이스)
            static_cast<unsigned int>(total_bytes),   // 바이트 수
            tx_iv_counter,                           // CTR (내부 증가)
            &session_key                             // 키
        );

        return SECURE_TRUE;
    }

    // =====================================================================
    //  Decrypt_Payload — LEA-CTR 복호화 (인플레이스)
    //  len 16바이트 배수, rx_iv_counter만 갱신
    // =====================================================================
    uint32_t LEA_Bridge::Decrypt_Payload(
        uint32_t* payload_data, size_t elements) noexcept {
        LEA_Busy_Guard guard(op_busy_);
        if (guard.locked != SECURE_TRUE) { return SECURE_FALSE; }

        if (!is_initialized || !payload_data || elements == 0u) return SECURE_FALSE;
        const uintptr_t payload_addr = reinterpret_cast<uintptr_t>(payload_data);
        if ((payload_addr & (alignof(uint32_t) - 1u)) != 0u) { return SECURE_FALSE; }

        constexpr size_t UINT32_SIZE = sizeof(uint32_t);
        if (elements > std::numeric_limits<size_t>::max() / UINT32_SIZE) {
            return SECURE_FALSE;
        }
        size_t total_bytes = elements * UINT32_SIZE;

        if ((total_bytes % 16u) != 0u) { return SECURE_FALSE; }

        if (total_bytes > static_cast<size_t>(
            std::numeric_limits<unsigned int>::max())) {
            return SECURE_FALSE;
        }

        auto* byte_ptr = reinterpret_cast<uint8_t*>(payload_data);

        // KISA LEA CTR 복호화 — rx_iv_counter만 갱신 (송신과 독립)
        lea_ctr_dec(
            byte_ptr,                                // pt (출력)
            byte_ptr,                                // ct (입력 = 인플레이스)
            static_cast<unsigned int>(total_bytes),   // 바이트 수
            rx_iv_counter,                           // CTR (내부 증가)
            &session_key                             // 키
        );

        return SECURE_TRUE;
    }

} // namespace ProtectedEngine
