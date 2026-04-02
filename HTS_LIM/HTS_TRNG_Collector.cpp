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
#include "HTS_Secure_Memory.h"

#include <atomic>
#include <cstdint>

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#define HTS_COLLECTOR_ARM
#endif

namespace ProtectedEngine {

#if defined(HTS_COLLECTOR_ARM)

    /// STM32F407 RNG 레지스터 주소 (X-1-1)
    static constexpr uint32_t RNG_BASE = 0x50060800u;
    static constexpr uint32_t RNG_CR_OFF = 0x00u;
    static constexpr uint32_t RNG_SR_OFF = 0x04u;
    static constexpr uint32_t RNG_DR_OFF = 0x08u;

    static constexpr uint32_t RNG_CR_RNGEN = (1u << 2);
    static constexpr uint32_t RNG_SR_DRDY = (1u << 0);
    static constexpr uint32_t RNG_SR_CECS = (1u << 1);
    static constexpr uint32_t RNG_SR_SECS = (1u << 2);
    /// RM0090 RNG_SR — 인터럽트 스테이터스, 소프트웨어 0 쓰기로 클리어
    static constexpr uint32_t RNG_SR_CEIS = (1u << 5u);
    static constexpr uint32_t RNG_SR_SEIS = (1u << 6u);

    static constexpr uint32_t RCC_BASE = 0x40023800u;
    static constexpr uint32_t RCC_AHB2ENR_OFF = 0x34u;
    static constexpr uint32_t RCC_AHB2ENR_RNGEN = (1u << 6);

    static constexpr uint32_t RNG_TIMEOUT = 100000u;

    /// ISR/RTOS 재진입 — RNG 대기 무한 루프와 데드락 전이 방지 (N-1)
    static std::atomic_flag g_trng_busy = ATOMIC_FLAG_INIT;

    /// B-2: 포인터 산술을 uintptr_t로 명시
    static volatile uint32_t* reg(uint32_t base, uint32_t off) noexcept {
        const uintptr_t addr =
            static_cast<uintptr_t>(base) + static_cast<uintptr_t>(off);
        return reinterpret_cast<volatile uint32_t*>(addr);
    }

    static void RNG_Init() noexcept {
        *reg(RCC_BASE, RCC_AHB2ENR_OFF) |= RCC_AHB2ENR_RNGEN;
        *reg(RNG_BASE, RNG_CR_OFF) = RNG_CR_RNGEN;
    }

    /// CECS/SECS/CEIS/SEIS 누적 시 RM0090: RNGEN 해제 → DR 드레인 → SR 클리어 → 재가동
    static void RNG_Clear_Error_Flags() noexcept {
        volatile uint32_t* const cr = reg(RNG_BASE, RNG_CR_OFF);
        volatile uint32_t* const sr = reg(RNG_BASE, RNG_SR_OFF);
        volatile uint32_t* const dr = reg(RNG_BASE, RNG_DR_OFF);

        *cr &= ~RNG_CR_RNGEN;

        if ((*sr & RNG_SR_DRDY) != 0u) {
            (void)*dr;
        }

        uint32_t sr_val = *sr;
        sr_val &= ~(RNG_SR_CEIS | RNG_SR_SEIS);
        *sr = sr_val;

        *cr |= RNG_CR_RNGEN;
    }

    static bool RNG_Read32(uint32_t* out, uint32_t timeout) noexcept {
        if (out == nullptr) {
            return false;
        }
        uint32_t count = 0u;
        while ((*reg(RNG_BASE, RNG_SR_OFF) & RNG_SR_DRDY) == 0u) {
            if (++count > timeout) {
                return false;
            }
            const uint32_t sr = *reg(RNG_BASE, RNG_SR_OFF);
            if ((sr & (RNG_SR_CECS | RNG_SR_SECS)) != 0u) {
                RNG_Clear_Error_Flags();
                return false;
            }
        }
        *out = *reg(RNG_BASE, RNG_DR_OFF);
        return true;
    }

    class Trng_Scope_Guard final {
    private:
        bool locked_;

    public:
        Trng_Scope_Guard() noexcept : locked_(false) {
            if (!g_trng_busy.test_and_set(std::memory_order_acquire)) {
                locked_ = true;
            }
        }

        ~Trng_Scope_Guard() noexcept {
            if (locked_) {
                g_trng_busy.clear(std::memory_order_release);
            }
        }

        Trng_Scope_Guard(const Trng_Scope_Guard&) = delete;
        Trng_Scope_Guard& operator=(const Trng_Scope_Guard&) = delete;

        [[nodiscard]] bool locked() const noexcept { return locked_; }
    };

    // =====================================================================
    //  Collect_And_Output — UART 직접 출력
    // =====================================================================
    uint32_t TRNG_Collector::Collect_And_Output(
        uint32_t sample_count,
        void (*uart_putchar)(uint8_t)) noexcept {

        if (uart_putchar == nullptr || sample_count == 0u) {
            return 0u;
        }

        Trng_Scope_Guard guard;
        if (!guard.locked()) {
            return 0u;
        }

        RNG_Init();

        uint32_t collected = 0u;
        uint32_t raw = 0u;

        while (collected < sample_count) {
            if (!RNG_Read32(&raw, RNG_TIMEOUT)) {
                SecureMemory::secureWipe(&raw, sizeof(raw));
                break;
            }

            const uint32_t remain = sample_count - collected;
            const uint32_t bytes = (remain >= 4u) ? 4u : remain;

            for (uint32_t i = 0u; i < bytes; ++i) {
                const uint8_t byte = static_cast<uint8_t>(
                    (raw >> (24u - i * 8u)) & 0xFFu);
                uart_putchar(byte);
            }
            collected += bytes;

            SecureMemory::secureWipe(&raw, sizeof(raw));
        }

        SecureMemory::secureWipe(&raw, sizeof(raw));
        return collected;
    }

    // =====================================================================
    //  Collect_To_Buffer — 메모리 버퍼 저장
    // =====================================================================
    uint32_t TRNG_Collector::Collect_To_Buffer(
        uint8_t* buffer, uint32_t buffer_size) noexcept {

        if (buffer == nullptr || buffer_size == 0u) {
            return 0u;
        }

        Trng_Scope_Guard guard;
        if (!guard.locked()) {
            return 0u;
        }

        RNG_Init();

        uint32_t collected = 0u;
        uint32_t raw = 0u;

        while (collected < buffer_size) {
            if (!RNG_Read32(&raw, RNG_TIMEOUT)) {
                SecureMemory::secureWipe(&raw, sizeof(raw));
                break;
            }

            const uint32_t remain = buffer_size - collected;
            const uint32_t bytes = (remain >= 4u) ? 4u : remain;

            for (uint32_t i = 0u; i < bytes; ++i) {
                buffer[collected + i] = static_cast<uint8_t>(
                    (raw >> (24u - i * 8u)) & 0xFFu);
            }
            collected += bytes;

            SecureMemory::secureWipe(&raw, sizeof(raw));
        }

        SecureMemory::secureWipe(&raw, sizeof(raw));
        return collected;
    }

#else

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


