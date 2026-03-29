// =========================================================================
// HTS_Config.cpp
// HTS-32 PHY Engine 정적 메모리 스케일링 — 컴파일 검증 유닛
// Target: STM32F407VGT6 (Cortex-M4F, 168MHz)
//
// [양산 수정 이력 — 17건]
//  BUG-01~13 (이전 세션)
//  BUG-14 [HIGH] FINAL_* 체인 파생 (자동 스케일링)
//  BUG-15 [MED]  >= 32u 절사 방어 + __attribute__((used)) LTO 방어
//  BUG-16 [HIGH] 나눗셈/곱셈 → 비트 시프트 100% 대체 (⑨ 컨벤션 일관성)
//  BUG-17 [MED]  1024u/8u/32u 매직넘버 → constexpr 명명 상수 (J-3 MISRA)
// =========================================================================
#include "HTS_Config.h"

namespace ProtectedEngine {

    using C = HTS_Static_Config;

    // ── [BUG-16] 교차 검증: 파생 체인 (시프트 연산 통일) ─────────
    static_assert(C::DMA_RAM_BYTES ==
        (static_cast<size_t>(C::MCU_DMA_SRAM_KB) << 10u),
        "DMA_RAM_BYTES derivation mismatch (KB << 10)");

    static_assert(C::TARGET_HTS_RAM_BYTES == (C::DMA_RAM_BYTES >> 1u),
        "TARGET_HTS_RAM_BYTES derivation mismatch (>> 1)");

    static_assert(C::SINGLE_TENSOR_BUF_BYTES == (C::TARGET_HTS_RAM_BYTES >> 1u),
        "SINGLE_TENSOR_BUF_BYTES derivation mismatch (>> 1)");

    static_assert(C::FINAL_NODE_COUNT == (C::SINGLE_TENSOR_BUF_BYTES << 3u),
        "FINAL_NODE_COUNT derivation mismatch (<< 3)");

    static_assert(C::FINAL_PACKED_SIZE == (C::FINAL_NODE_COUNT >> 5u),
        "FINAL_PACKED_SIZE derivation mismatch (>> 5)");

    static_assert(C::FINAL_RAM_BYTES == C::FINAL_PACKED_SIZE * sizeof(uint32_t),
        "FINAL_RAM_BYTES derivation mismatch");

    // [BUG-15] >= 32u 절사 방어 + 2의 제곱수
    static_assert(C::FINAL_NODE_COUNT >= C::BITS_PER_WORD &&
        (C::FINAL_NODE_COUNT & (C::FINAL_NODE_COUNT - 1u)) == 0u,
        "FINAL_NODE_COUNT must be >= BITS_PER_WORD and a power of two");

    static_assert(C::FINAL_RAM_BYTES <= (C::DMA_RAM_BYTES >> 1u),
        "Single tensor buffer exceeds 50% of DMA SRAM");

    // [BUG-15] LTO 증발 방어 + 빈 번역 단위 방어
    extern "C" {
#if defined(__GNUC__) || defined(__clang__)
        __attribute__((used))
#endif
            [[maybe_unused]] const uint32_t HTS_CONFIG_BUILD_STAMP = 0x407A0001u;
    }

} // namespace ProtectedEngine