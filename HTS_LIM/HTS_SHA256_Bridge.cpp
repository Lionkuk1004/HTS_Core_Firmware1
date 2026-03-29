// =========================================================================
// HTS_SHA256_Bridge.cpp
// FIPS 180-4 SHA-256 래퍼 구현부
// Target: STM32F407 (Cortex-M4) / Cortex-A55 / PC
//
// [KISA SHA-256 C 라이브러리 연결]
//  SHA256_Encrpyt(msg, len, digest): 원샷 해시 (Init+Process+Close)
//
// [제약] try-catch 0, float/double 0, heap 0
// =========================================================================
#include "HTS_SHA256_Bridge.h"

#include <atomic>
#include <cstring>

// KISA SHA-256 C 라이브러리 extern "C" 링크
extern "C" {
#include "KISA_SHA256.h"
}

namespace ProtectedEngine {

    // =====================================================================
    //  보안 소거
    // =====================================================================
    static void SHA_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) return;
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) q[i] = 0u;
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  Hash — SHA-256 원샷 해시
    // =====================================================================
    bool SHA256_Bridge::Hash(
        const uint8_t* data, size_t data_len,
        uint8_t* output_32) noexcept {

        if (output_32 == nullptr) return false;
        if (data == nullptr && data_len != 0u) {
            SHA_Wipe(output_32, DIGEST_LEN);
            return false;
        }

        // KISA API: SHA256_Encrpyt(msg, len, digest)
        // data_len → UINT 범위 검사
        if (data_len > 0xFFFFFFFFu) {
            SHA_Wipe(output_32, DIGEST_LEN);
            return false;
        }

        // 빈 메시지 처리
        if (data == nullptr || data_len == 0u) {
            SHA256_INFO info;
            SHA256_Init(&info);
            SHA256_Close(&info, output_32);
            SHA_Wipe(&info, sizeof(info));
            return true;
        }

        SHA256_Encrpyt(data, static_cast<UINT>(data_len), output_32);
        return true;
    }

} // namespace ProtectedEngine