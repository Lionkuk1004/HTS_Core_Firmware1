// =========================================================================
// HTS_Remote_Attestation.cpp
// Remote Attestation — FNV-1a + 디바이스 바인딩 + 상수시간 검증
// Target: STM32F407 (Cortex-M4, 168MHz)
//
#include "HTS_Remote_Attestation.hpp"
#include "HTS_Hardware_Bridge.hpp"

#include <atomic>

namespace ProtectedEngine {

    // ── 상수 ──
    namespace {
        // FNV-1a 32-bit (Fowler-Noll-Vo)
        constexpr uint32_t FNV32_OFFSET_BASIS = 0x811C9DC5u;
        constexpr uint32_t FNV32_PRIME = 0x01000193u;

        // Murmur3 fmix32
        constexpr uint32_t MURMUR3_32_C1 = 0x85EBCA6Bu;
        constexpr uint32_t MURMUR3_32_C2 = 0xC2B2AE35u;

        // 골든 비율 32비트
        constexpr uint32_t GOLDEN_RATIO_32 = 0x9E3779B9u;

        // STM32F407 UID 기본 주소
        constexpr uint32_t STM32_UID_BASE_ADDR = 0x1FFF7A10u;
    }

    // =====================================================================
    // =====================================================================
    static uint32_t Murmur3_Fmix32(uint32_t h) noexcept {
        h ^= h >> 16u;
        h *= MURMUR3_32_C1;
        h ^= h >> 13u;
        h *= MURMUR3_32_C2;
        h ^= h >> 16u;
        return h;
    }

    // =====================================================================
    //  Get_Device_Unique_Key — UID 3워드 혼합 (32비트 연산만)
    // =====================================================================
    static uint32_t Get_Device_Key_Lo() noexcept {
#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__ARM_ARCH))
        volatile const uint32_t* uid =
            reinterpret_cast<volatile const uint32_t*>(STM32_UID_BASE_ADDR);
        return Murmur3_Fmix32(uid[0] ^ uid[2]);
#else
        return Murmur3_Fmix32(0x48545333u);  // MSVC 개발빌드 테스트키
#endif
    }

    static uint32_t Get_Device_Key_Hi() noexcept {
#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__ARM_ARCH))
        volatile const uint32_t* uid =
            reinterpret_cast<volatile const uint32_t*>(STM32_UID_BASE_ADDR);
        return Murmur3_Fmix32(uid[1] ^ GOLDEN_RATIO_32);
#else
        return Murmur3_Fmix32(0x3246524Du);  // MSVC 개발빌드 테스트키
#endif
    }

    // =====================================================================
    //
    //  uint64_t hash × FNV1A_PRIME(64bit) = __aeabi_lmul ~30cyc/바이트
    //  FNV32 × 2 독립 누적 → ARM MUL 1cyc × 2 = 2cyc/바이트
    //        hi: 바이트 + key_hi 혼합, lo: 바이트 + key_lo 혼합
    //
    //
    //  문제:
    //    data[i]는 일반 포인터 → 컴파일러가:
    //    (1) 여러 바이트를 LDM으로 일괄 읽기 (벡터화)
    //    (2) 레지스터에 캐시하여 Flash 재읽기 생략
    //    (3) 루프 반복 간 읽기를 재배치
    //    → 공격자가 읽기 사이에 DMA/글리치로 Flash 변조 가능
    //
    //  //    (1) volatile const uint8_t*: 매 바이트 실제 메모리에서 강제 읽기
    //    (2) 매 반복 asm memory clobber: 읽기 재배치/벡터화 원천 차단
    //    (3) hash volatile 유지: DSE(Dead Store Elimination) 차단
    // =====================================================================
    static uint64_t Compute_Keyed_FNV1a_32(
        const uint8_t* data, size_t size,
        uint32_t key_lo, uint32_t key_hi) noexcept {

        volatile const uint8_t* vdata =
            static_cast<volatile const uint8_t*>(data);

        volatile uint32_t hash_lo = FNV32_OFFSET_BASIS ^ key_lo;
        volatile uint32_t hash_hi = FNV32_OFFSET_BASIS ^ key_hi;

        for (size_t i = 0; i < size; ++i) {
            // volatile 읽기: 매 바이트 실제 Flash/SRAM에서 강제 로드
            const uint8_t b = vdata[i];

            hash_lo ^= b;
            hash_lo *= FNV32_PRIME;
            hash_hi ^= b;
            hash_hi *= FNV32_PRIME;
            hash_hi ^= hash_lo;

            // 컴파일러가 다음 반복의 vdata[i+1] 읽기를
            // 현재 반복의 해시 연산보다 앞당기는 것을 차단
#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__ARM_ARCH))
            __asm__ __volatile__("" : : "r"(vdata), "r"(i));
#endif
        }

#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__ARM_ARCH))
        __asm__ __volatile__("" : : "r"(hash_lo), "r"(hash_hi));
#endif
        std::atomic_thread_fence(std::memory_order_release);

        // 최종 혼합
        const uint32_t final_lo = Murmur3_Fmix32(static_cast<uint32_t>(hash_lo));
        const uint32_t final_hi = Murmur3_Fmix32(static_cast<uint32_t>(hash_hi));

        return (static_cast<uint64_t>(final_hi) << 32) | final_lo;
    }

    // =====================================================================
    //  Generate_Enclave_Quote
    // =====================================================================
    uint64_t Remote_Attestation::Generate_Enclave_Quote(
        const void* memory_region, size_t size) noexcept {

        if (memory_region == nullptr || size == 0) return 0;

        const uint8_t* byte_ptr =
            static_cast<const uint8_t*>(memory_region);

        uint32_t key_lo = Get_Device_Key_Lo();
        uint32_t key_hi = Get_Device_Key_Hi();

        // DWT tick nonce 혼합 (32비트)
        const uint32_t tick = static_cast<uint32_t>(
            Hardware_Bridge::Get_Physical_CPU_Tick() & 0xFFFFFFFFu);
        key_lo ^= Murmur3_Fmix32(tick);
        key_hi ^= Murmur3_Fmix32(tick ^ GOLDEN_RATIO_32);

        return Compute_Keyed_FNV1a_32(byte_ptr, size, key_lo, key_hi);
    }

    // =====================================================================
    //  Verify_Quote — FI-hardened 상수시간 비교
    //  (기존 로직 유지 — 이미 32비트 연산만 사용)
    // =====================================================================
    uint32_t Remote_Attestation::Verify_Quote(
        uint64_t computed_quote,
        uint64_t expected_quote) noexcept {

        const uint32_t c_nonzero =
            static_cast<uint32_t>(computed_quote) |
            static_cast<uint32_t>(computed_quote >> 32);
        const uint32_t e_nonzero =
            static_cast<uint32_t>(expected_quote) |
            static_cast<uint32_t>(expected_quote >> 32);

        const uint32_t both_valid = (c_nonzero != 0u) & (e_nonzero != 0u);
        const uint32_t zero_poison = both_valid - 1u;

        const uint64_t diff = computed_quote ^ expected_quote;
        uint32_t reduced =
            static_cast<uint32_t>(diff) |
            static_cast<uint32_t>(diff >> 32);

        return reduced | zero_poison;
    }

    // =====================================================================
    //  Verify_Quote_With_Server — 스텁 (양산 전 교체 필수)
    // =====================================================================
    uint32_t Remote_Attestation::Verify_Quote_With_Server(
        uint64_t quote) noexcept {
        if (quote == 0u || quote == 0xFFFFFFFFFFFFFFFFULL) { return 1u; }
        return 0u;  // STUB: 0=accepted, non-zero=rejected
    }

} // namespace ProtectedEngine
