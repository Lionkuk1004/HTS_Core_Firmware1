// =========================================================================
// HTS_TRNG_Collector.cpp
// TRNG Raw 데이터 수집기 구현부
// Target: STM32F407 (Cortex-M4)
//
// [STM32F407 RNG 레지스터]
//  RNG_BASE = 0x50060800
//  RNG_CR   = +0x00 (Control: bit2=RNGEN)
//  RNG_SR   = +0x04 (Status: bit0=DRDY, bit1=CECS, bit2=SECS)
//  RNG_DR   = +0x08 (Data: 32비트 난수)
//
// [수집 절차]
//  1. RNG 클럭 활성화 (RCC_AHB2ENR bit6)
//  2. RNG_CR.RNGEN = 1
//  3. RNG_SR.DRDY 대기 → RNG_DR 읽기 → 4바이트 출력
//  4. 반복 (sample_count / 4 회)
//
// [제약] ARM 전용, 힙 0, try-catch 0
// =========================================================================
#include "HTS_TRNG_Collector.h"

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#define HTS_COLLECTOR_ARM
#endif

namespace ProtectedEngine {

#if defined(HTS_COLLECTOR_ARM)

    // ── STM32F407 RNG 레지스터 주소 ──────────────────────────────
    static constexpr uint32_t RNG_BASE = 0x50060800u;
    static constexpr uint32_t RNG_CR_OFF = 0x00u;
    static constexpr uint32_t RNG_SR_OFF = 0x04u;
    static constexpr uint32_t RNG_DR_OFF = 0x08u;

    static constexpr uint32_t RNG_CR_RNGEN = (1u << 2);  // RNG Enable
    static constexpr uint32_t RNG_SR_DRDY = (1u << 0);  // Data Ready
    static constexpr uint32_t RNG_SR_CECS = (1u << 1);  // Clock Error
    static constexpr uint32_t RNG_SR_SECS = (1u << 2);  // Seed Error

    // RCC AHB2 RNG 클럭 활성화
    static constexpr uint32_t RCC_BASE = 0x40023800u;
    static constexpr uint32_t RCC_AHB2ENR_OFF = 0x34u;
    static constexpr uint32_t RCC_AHB2ENR_RNGEN = (1u << 6);

    static volatile uint32_t* reg(uint32_t base, uint32_t off) noexcept {
        return reinterpret_cast<volatile uint32_t*>(base + off);
    }

    static void RNG_Init() noexcept {
        // RCC AHB2 RNG 클럭 활성화
        *reg(RCC_BASE, RCC_AHB2ENR_OFF) |= RCC_AHB2ENR_RNGEN;

        // RNG 활성화
        *reg(RNG_BASE, RNG_CR_OFF) = RNG_CR_RNGEN;
    }

    static bool RNG_Read32(uint32_t* out, uint32_t timeout) noexcept {
        uint32_t count = 0u;
        while ((*reg(RNG_BASE, RNG_SR_OFF) & RNG_SR_DRDY) == 0u) {
            if (++count > timeout) return false;
            // 클럭/시드 에러 확인
            const uint32_t sr = *reg(RNG_BASE, RNG_SR_OFF);
            if (sr & (RNG_SR_CECS | RNG_SR_SECS)) return false;
        }
        *out = *reg(RNG_BASE, RNG_DR_OFF);
        return true;
    }

    // =====================================================================
    //  Collect_And_Output — UART 직접 출력
    // =====================================================================
    uint32_t TRNG_Collector::Collect_And_Output(
        uint32_t sample_count,
        void (*uart_putchar)(uint8_t)) noexcept {

        if (uart_putchar == nullptr || sample_count == 0u) return 0u;

        RNG_Init();

        static constexpr uint32_t RNG_TIMEOUT = 100000u;
        uint32_t collected = 0u;

        while (collected < sample_count) {
            uint32_t raw = 0u;
            if (!RNG_Read32(&raw, RNG_TIMEOUT)) break;

            // 4바이트 출력 (Big-Endian)
            const uint32_t remain = sample_count - collected;
            const uint32_t bytes = (remain >= 4u) ? 4u : remain;

            for (uint32_t i = 0u; i < bytes; ++i) {
                const uint8_t byte = static_cast<uint8_t>(
                    (raw >> (24u - i * 8u)) & 0xFFu);
                uart_putchar(byte);
            }
            collected += bytes;
        }

        return collected;
    }

    // =====================================================================
    //  Collect_To_Buffer — 메모리 버퍼 저장
    // =====================================================================
    uint32_t TRNG_Collector::Collect_To_Buffer(
        uint8_t* buffer, uint32_t buffer_size) noexcept {

        if (buffer == nullptr || buffer_size == 0u) return 0u;

        RNG_Init();

        static constexpr uint32_t RNG_TIMEOUT = 100000u;
        uint32_t collected = 0u;

        while (collected < buffer_size) {
            uint32_t raw = 0u;
            if (!RNG_Read32(&raw, RNG_TIMEOUT)) break;

            const uint32_t remain = buffer_size - collected;
            const uint32_t bytes = (remain >= 4u) ? 4u : remain;

            for (uint32_t i = 0u; i < bytes; ++i) {
                buffer[collected + i] = static_cast<uint8_t>(
                    (raw >> (24u - i * 8u)) & 0xFFu);
            }
            collected += bytes;
        }

        return collected;
    }

#else
    // PC 빌드: 미지원 (보드 전용)
    uint32_t TRNG_Collector::Collect_And_Output(
        uint32_t, void (*)(uint8_t)) noexcept {
        return 0u;
    }
    uint32_t TRNG_Collector::Collect_To_Buffer(
        uint8_t*, uint32_t) noexcept {
        return 0u;
    }
#endif

} // namespace ProtectedEngine