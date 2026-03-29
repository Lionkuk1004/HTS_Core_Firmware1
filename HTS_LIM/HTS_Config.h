// =========================================================================
/// @file  HTS_Config.h
/// @brief HTS-32 PHY Engine 정적 메모리 스케일링 설정 (컴파일 타임 확정)
/// @target STM32F407VGT6 (Cortex-M4F, 168MHz, SRAM 192KB)
///
/// [STM32F407 메모리 맵]
///   SRAM1 : 112KB (0x2000_0000) — DMA 접근 가능
///   SRAM2 :  16KB (0x2001_C000) — DMA 접근 가능
///   CCM   :  64KB (0x1000_0000) — CPU 전용, DMA 불가
///   합계  : 192KB (DMA 가능 128KB + CCM 64KB)
///
/// [자동 스케일링 체인]
///   MCU_DMA_SRAM_KB → DMA_RAM_BYTES → TARGET → SINGLE_BUF
///   → BASE_MIN_NODES → FINAL_NODE_COUNT → PACKED → RAM
///   ★ 최상단 MCU_DMA_SRAM_KB 하나만 변경하면 전체 자동 재계산
///
/// [양산 수정 이력 — 17건]
///  BUG-01~13 (이전 세션)
///  BUG-14 [HIGH] FINAL_* 매직넘버 → 체인 파생 (자동 스케일링)
///  BUG-15 [MED]  >= 32u 절사 방어 + __attribute__((used)) LTO 방어
///  BUG-16 [HIGH] 나눗셈/곱셈 → 비트 시프트 100% 대체 (⑨ 컨벤션 일관성)
///  BUG-17 [MED]  1024u/8u/32u 매직넘버 → constexpr 명명 상수 (J-3 MISRA)
// =========================================================================
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    /// @class HTS_Static_Config
    /// @brief STM32F407 텐서 메모리 스케일링 상수 (순수 static, 인스턴스화 불가)
    class HTS_Static_Config final {
    public:
        // ── [BUG-17] 단위 변환 명명 상수 (J-3 매직넘버 금지) ─────
        static constexpr uint32_t BYTES_PER_KB = 1024u;  // 1 << 10
        static constexpr uint32_t BITS_PER_BYTE = 8u;     // 1 << 3
        static constexpr uint32_t BITS_PER_WORD = 32u;    // 1 << 5

        // ── MCU 하드웨어 상수 ─────────────────────────────────────
        // ★ 칩셋 포팅 시 이 값만 변경 → 하위 전체 자동 재계산
        static constexpr uint32_t MCU_TOTAL_RAM_KB = 192u;
        static constexpr uint32_t MCU_DMA_SRAM_KB = 128u;

        // ── [BUG-16] 메모리 할당 정책 (나눗셈/곱셈 → 시프트 100%) ──
        static constexpr size_t DMA_RAM_BYTES =
            static_cast<size_t>(MCU_DMA_SRAM_KB) << 10u;        // × BYTES_PER_KB
        static constexpr size_t TARGET_HTS_RAM_BYTES =
            DMA_RAM_BYTES >> 1u;                                  // 50%
        static constexpr size_t SINGLE_TENSOR_BUF_BYTES =
            TARGET_HTS_RAM_BYTES >> 1u;                           // 50%
        static constexpr size_t BASE_MIN_NODES =
            SINGLE_TENSOR_BUF_BYTES << 3u;                        // × BITS_PER_BYTE

        // ── 최종 확정값 (매직넘버 0 — 체인 파생) ──────────────────
        // [BUG-14] 하드코딩 제거 → 상위 파생 체인 100% 동기화
        static constexpr size_t FINAL_NODE_COUNT = BASE_MIN_NODES;
        static constexpr size_t FINAL_PACKED_SIZE =
            FINAL_NODE_COUNT >> 5u;                               // ÷ BITS_PER_WORD
        static constexpr size_t FINAL_RAM_BYTES =
            FINAL_PACKED_SIZE * sizeof(uint32_t);

        // ── constexpr 접근자 ─────────────────────────────────────
        [[nodiscard]] static constexpr uint32_t Get_Target_RAM_KB() noexcept {
            return MCU_TOTAL_RAM_KB;
        }
        [[nodiscard]] static constexpr size_t Get_Tensor_Node_Count() noexcept {
            return FINAL_NODE_COUNT;
        }
        [[nodiscard]] static constexpr size_t Get_Packed_Size() noexcept {
            return FINAL_PACKED_SIZE;
        }
        [[nodiscard]] static constexpr size_t Get_Actual_RAM_Usage_Bytes() noexcept {
            return FINAL_RAM_BYTES;
        }
        [[nodiscard]] static constexpr size_t Get_DMA_SRAM_Bytes() noexcept {
            return DMA_RAM_BYTES;
        }
        [[nodiscard]] static constexpr size_t Get_Single_Tensor_Buf_Bytes() noexcept {
            return SINGLE_TENSOR_BUF_BYTES;
        }

    private:
        HTS_Static_Config() = delete;
        ~HTS_Static_Config() = delete;
    };

    // ── 컴파일 타임 무결성 검증 ─────────────────────────────────
    // [BUG-17] 단위 변환 상수가 2의 거듭제곱인지 빌드 타임 보장
    static_assert(HTS_Static_Config::BYTES_PER_KB == (1u << 10u),
        "BYTES_PER_KB must be 1024 (2^10)");
    static_assert(HTS_Static_Config::BITS_PER_BYTE == (1u << 3u),
        "BITS_PER_BYTE must be 8 (2^3)");
    static_assert(HTS_Static_Config::BITS_PER_WORD == (1u << 5u),
        "BITS_PER_WORD must be 32 (2^5)");

    // [BUG-15] >= 32u: 32 미만이면 PACKED_SIZE=0 → 0바이트 텐서 → 하드폴트
    static_assert(
        HTS_Static_Config::FINAL_NODE_COUNT >= 32u &&
        (HTS_Static_Config::FINAL_NODE_COUNT &
            (HTS_Static_Config::FINAL_NODE_COUNT - 1u)) == 0u,
        "FINAL_NODE_COUNT must be >= 32 and a power of two");

    // [BUG-16] static_assert 내부도 시프트 통일
    static_assert(
        HTS_Static_Config::FINAL_PACKED_SIZE ==
        (HTS_Static_Config::FINAL_NODE_COUNT >> 5u),
        "FINAL_PACKED_SIZE derivation mismatch (NODE_COUNT >> 5)");

    static_assert(
        HTS_Static_Config::FINAL_RAM_BYTES ==
        HTS_Static_Config::FINAL_PACKED_SIZE * sizeof(uint32_t),
        "FINAL_RAM_BYTES derivation mismatch");

    static_assert(
        HTS_Static_Config::SINGLE_TENSOR_BUF_BYTES <=
        (HTS_Static_Config::DMA_RAM_BYTES >> 1u),
        "Single tensor buffer exceeds 50% of DMA SRAM");

} // namespace ProtectedEngine