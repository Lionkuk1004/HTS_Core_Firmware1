// =========================================================================
// HTS_Config.cpp
// HTS-32 PHY Engine 정적 메모리 스케일링 — 컴파일 검증 유닛
// Target: STM32F407VGT6 (Cortex-M4F, 168MHz)
//
#include "HTS_Config.h"

namespace ProtectedEngine {

    using C = HTS_Static_Config;

    // ── 교차 검증: 파생 체인 (시프트 연산 통일) ─────────────────
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

    static_assert(C::FINAL_NODE_COUNT >= C::BITS_PER_WORD &&
        (C::FINAL_NODE_COUNT & (C::FINAL_NODE_COUNT - 1u)) == 0u,
        "FINAL_NODE_COUNT must be >= BITS_PER_WORD and a power of two");

    static_assert(C::FINAL_RAM_BYTES <= (C::DMA_RAM_BYTES >> 1u),
        "Single tensor buffer exceeds 50% of DMA SRAM");

    extern "C" {
#if defined(__GNUC__) || defined(__clang__)
        __attribute__((used))
#endif
            [[maybe_unused]] const uint32_t HTS_CONFIG_BUILD_STAMP = 0x407A0001u;
    }

} // namespace ProtectedEngine
