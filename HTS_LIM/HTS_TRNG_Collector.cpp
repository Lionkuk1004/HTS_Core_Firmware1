// =========================================================================
// HTS_TRNG_Collector.cpp
// TRNG Raw 데이터 수집기 구현부
// Target: STM32F407 (Cortex-M4)
//
// [STM32F407 RNG] RNG_BASE 0x50060800, CR/SR/DR RM0090
// [제약] 힙 0, try-catch 0, float/double 0
// [버스] 4바이트 청크: 정렬 시 may_alias 32비트 스토어 / 비정렬 memcpy(4)
// [안티포렌식] 수집 실패 시 버퍼 전역 secureWipe 후 0만 반환(All-or-Nothing)
// [물리 신뢰] 루프 매 회전마다 DHCSR·OPTCR(RDP) 재폴링(TOCTOU 축소)
// [락] Trng_Scope_Guard: compiler_memory_fence (Session_Gateway 동일)
// [RNG_Read32] CECS/SECS 시 ok_sample=drdy&(1-err)로 성공 경로 차단 + err·timeout 가속(분기 미의존)
// =========================================================================
#include "HTS_TRNG_Collector.h"
#include "HTS_Secure_Memory.h"
#include <atomic>
#include <cstdint>
#include <cstring>
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#define HTS_COLLECTOR_ARM
#include "HTS_Anti_Debug.h"
#include "HTS_Hardware_Init.h"
#endif
namespace ProtectedEngine {
#if !defined(HTS_TRNG_COLLECTOR_SKIP_PHYS_TRUST)
#if defined(HTS_ALLOW_OPEN_DEBUG) || !defined(NDEBUG)
#define HTS_TRNG_COLLECTOR_SKIP_PHYS_TRUST 1
#else
#define HTS_TRNG_COLLECTOR_SKIP_PHYS_TRUST 0
#endif
#endif
#if HTS_TRNG_COLLECTOR_SKIP_PHYS_TRUST == 0 && defined(HTS_COLLECTOR_ARM)
    [[noreturn]] static void TrngCollector_PhysicalTrust_Fault() noexcept {
        Hardware_Init_Manager::Terminal_Fault_Action();
    }
    static void TrngCollector_AssertPhysicalTrustOrFault() noexcept {
        volatile const uint32_t* const dhcsr =
            reinterpret_cast<volatile const uint32_t*>(ADDR_DHCSR);
        const uint32_t d0 = *dhcsr;
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("dsb sy" ::: "memory");
#endif
        const uint32_t d1 = *dhcsr;
        if (d0 != d1) {
            TrngCollector_PhysicalTrust_Fault();
        }
        if ((d0 & DHCSR_DEBUG_MASK) != 0u) {
            TrngCollector_PhysicalTrust_Fault();
        }
        volatile const uint32_t* const optcr =
            reinterpret_cast<volatile const uint32_t*>(HTS_FLASH_OPTCR_ADDR);
        const uint32_t o0 = *optcr;
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("dsb sy" ::: "memory");
#endif
        const uint32_t o1 = *optcr;
        if (o0 != o1) {
            TrngCollector_PhysicalTrust_Fault();
        }
        const uint32_t rdp = (o0 & HTS_RDP_OPTCR_MASK) >> 8u;
        if (rdp != HTS_RDP_EXPECTED_BYTE_VAL) {
            TrngCollector_PhysicalTrust_Fault();
        }
    }
#else
    // 비-ARM·스킵 구성: 미참조 static 방지(C4505). 호출부는 HTS_COLLECTOR_ARM 가드 안.
#define TrngCollector_AssertPhysicalTrustOrFault() ((void)0)
#endif
#if defined(HTS_COLLECTOR_ARM)
    namespace {
        static inline void compiler_memory_fence() noexcept {
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
            _ReadWriteBarrier();
#else
            std::atomic_thread_fence(std::memory_order_acq_rel);
#endif
        }
#if defined(__GNUC__) || defined(__clang__)
        typedef uint32_t __attribute__((__may_alias__)) trng_u32_alias_t;
#else
        typedef uint32_t trng_u32_alias_t;
#endif
        static uint32_t trng_raw_to_buffer_word(uint32_t raw) noexcept {
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
            return raw;
#elif defined(_MSC_VER)
            return _byteswap_ulong(raw);
#else
            return __builtin_bswap32(raw);
#endif
        }
    } // namespace
    static constexpr uint32_t RNG_BASE = 0x50060800u;
    static constexpr uint32_t RNG_CR_OFF = 0x00u;
    static constexpr uint32_t RNG_SR_OFF = 0x04u;
    static constexpr uint32_t RNG_DR_OFF = 0x08u;
    static constexpr uint32_t RNG_CR_RNGEN = (1u << 2);
    static constexpr uint32_t RNG_SR_DRDY = (1u << 0);
    static constexpr uint32_t RNG_SR_CECS = (1u << 1);
    static constexpr uint32_t RNG_SR_SECS = (1u << 2);
    static constexpr uint32_t RNG_SR_CEIS = (1u << 5u);
    static constexpr uint32_t RNG_SR_SEIS = (1u << 6u);
    static constexpr uint32_t RCC_BASE = 0x40023800u;
    static constexpr uint32_t RCC_AHB2ENR_OFF = 0x34u;
    static constexpr uint32_t RCC_AHB2ENR_RNGEN = (1u << 6);
    static constexpr uint32_t RNG_TIMEOUT = 100000u;
    static std::atomic_flag g_trng_busy = ATOMIC_FLAG_INIT;
    static volatile uint32_t* reg(uint32_t base, uint32_t off) noexcept {
        const uintptr_t addr =
            static_cast<uintptr_t>(base) + static_cast<uintptr_t>(off);
        return reinterpret_cast<volatile uint32_t*>(addr);
    }
    static void RNG_Init() noexcept {
        *reg(RCC_BASE, RCC_AHB2ENR_OFF) |= RCC_AHB2ENR_RNGEN;
        *reg(RNG_BASE, RNG_CR_OFF) = RNG_CR_RNGEN;
    }
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
    static void trng_err_side_effect_noop() noexcept {}
    static void trng_err_side_effect_clear() noexcept {
        RNG_Clear_Error_Flags();
    }
    static void (*const k_trng_err_side[2])() noexcept = {
        trng_err_side_effect_noop,
        trng_err_side_effect_clear,
    };
    static bool RNG_Read32(uint32_t* out, uint32_t timeout) noexcept {
        const uint32_t bad = static_cast<uint32_t>(out == nullptr);
        if (bad != 0u) {
            return false;
        }
        *out = 0u;
        uint32_t count = 0u;
        for (;;) {
            const uint32_t sr = *reg(RNG_BASE, RNG_SR_OFF);
            const uint32_t err = static_cast<uint32_t>(
                (sr & (RNG_SR_CECS | RNG_SR_SECS)) != 0u);
            k_trng_err_side[err]();
            const uint32_t drdy = (sr & RNG_SR_DRDY) >> 0u;
            // err==1 이면 ok_sample==0 — fail_hw 분기를 글리치로 건너뛰어도
            // DR 성공 경로로는 절대 들어가지 않음(동일 SR 스냅샷).
            const uint32_t ok_sample = drdy & (1u - err);
            uint32_t dr_val = 0u;
            if (ok_sample != 0u) {
                dr_val = *reg(RNG_BASE, RNG_DR_OFF);
            }
            *out = dr_val * ok_sample + (*out) * (1u - ok_sample);
            if (ok_sample != 0u) {
                return true;
            }
            ++count;
            count += err * timeout;
            const uint32_t expired = static_cast<uint32_t>(count > timeout);
            if (expired != 0u) {
                return false;
            }
        }
    }
    static void trng_uart_drop(void (*fn)(uint8_t), uint8_t b) noexcept {
        (void)fn;
        (void)b;
    }
    static void trng_uart_fire(void (*fn)(uint8_t), uint8_t b) noexcept {
        fn(b);
    }
    using TrngUartSinkFn = void(*)(void (*)(uint8_t), uint8_t) noexcept;
    static TrngUartSinkFn const k_trng_uart_sink[2] = {
        trng_uart_drop,
        trng_uart_fire,
    };
    static void trng_emit_uart_chunk(
        void (*uart_putchar)(uint8_t),
        uint32_t raw,
        uint32_t valid_bytes) noexcept
    {
        const uint32_t m0 = static_cast<uint32_t>(valid_bytes > 0u);
        const uint32_t m1 = static_cast<uint32_t>(valid_bytes > 1u);
        const uint32_t m2 = static_cast<uint32_t>(valid_bytes > 2u);
        const uint32_t m3 = static_cast<uint32_t>(valid_bytes > 3u);
        k_trng_uart_sink[m0](uart_putchar,
            static_cast<uint8_t>((raw >> 24) & 0xFFu));
        k_trng_uart_sink[m1](uart_putchar,
            static_cast<uint8_t>((raw >> 16) & 0xFFu));
        k_trng_uart_sink[m2](uart_putchar,
            static_cast<uint8_t>((raw >> 8) & 0xFFu));
        k_trng_uart_sink[m3](uart_putchar,
            static_cast<uint8_t>(raw & 0xFFu));
    }
    static void trng_store_buffer_chunk(
        uint8_t* base,
        uint32_t collected,
        uint32_t raw,
        uint32_t bytes) noexcept
    {
        uint8_t* const p = base + collected;
        const uint32_t full4 = static_cast<uint32_t>(bytes == 4u);
        if (full4 != 0u) {
            const uint32_t wstore = trng_raw_to_buffer_word(raw);
            const uintptr_t dst = reinterpret_cast<uintptr_t>(p);
            const uint32_t aligned = static_cast<uint32_t>((dst & 3u) == 0u);
            if (aligned != 0u) {
                *reinterpret_cast<trng_u32_alias_t*>(p) = wstore;
            } else {
                std::memcpy(p, &wstore, 4u);
            }
            return;
        }
        uint8_t tmp[4];
        tmp[0] = static_cast<uint8_t>((raw >> 24) & 0xFFu);
        tmp[1] = static_cast<uint8_t>((raw >> 16) & 0xFFu);
        tmp[2] = static_cast<uint8_t>((raw >> 8) & 0xFFu);
        tmp[3] = static_cast<uint8_t>(raw & 0xFFu);
        std::memcpy(p, tmp, static_cast<size_t>(bytes));
        SecureMemory::secureWipe(static_cast<void*>(tmp), sizeof(tmp));
    }
    class Trng_Scope_Guard final {
    private:
        bool locked_;
    public:
        Trng_Scope_Guard() noexcept : locked_(false) {
            const bool prev =
                g_trng_busy.test_and_set(std::memory_order_acquire);
            locked_ = !prev;
            if (locked_) {
                compiler_memory_fence();
            }
        }
        ~Trng_Scope_Guard() noexcept {
            const uint32_t do_clear = static_cast<uint32_t>(locked_);
            if (do_clear != 0u) {
                compiler_memory_fence();
                g_trng_busy.clear(std::memory_order_release);
            }
        }
        Trng_Scope_Guard(const Trng_Scope_Guard&) = delete;
        Trng_Scope_Guard& operator=(const Trng_Scope_Guard&) = delete;
        [[nodiscard]] bool locked() const noexcept { return locked_; }
    };
    uint32_t TRNG_Collector::Collect_And_Output(
        uint32_t sample_count,
        void (*uart_putchar)(uint8_t)) noexcept
    {
        const uint32_t bad =
            static_cast<uint32_t>(uart_putchar == nullptr)
            | static_cast<uint32_t>(sample_count == 0u);
        if (bad != 0u) {
            return 0u;
        }
        Trng_Scope_Guard guard;
        const uint32_t ok_guard = static_cast<uint32_t>(guard.locked());
        if (ok_guard == 0u) {
            return 0u;
        }
        RNG_Init();
        uint32_t collected = 0u;
        uint32_t raw = 0u;
        while (collected < sample_count) {
            TrngCollector_AssertPhysicalTrustOrFault();
            const uint32_t success =
                static_cast<uint32_t>(RNG_Read32(&raw, RNG_TIMEOUT));
            const uint32_t remain = sample_count - collected;
            const uint32_t ge4 = static_cast<uint32_t>(remain >= 4u);
            const uint32_t bytes = ge4 * 4u + remain * (1u - ge4);
            const uint32_t valid_bytes = bytes * success;
            trng_emit_uart_chunk(uart_putchar, raw, valid_bytes);
            collected += valid_bytes;
            SecureMemory::secureWipe(&raw, sizeof(raw));
            raw = 0u;
            const uint32_t stop = 1u - success;
            if (stop != 0u) {
                return 0u;
            }
        }
        SecureMemory::secureWipe(&raw, sizeof(raw));
        return sample_count;
    }
    uint32_t TRNG_Collector::Collect_To_Buffer(
        uint8_t* buffer, uint32_t buffer_size) noexcept
    {
        const uint32_t bad =
            static_cast<uint32_t>(buffer == nullptr)
            | static_cast<uint32_t>(buffer_size == 0u);
        if (bad != 0u) {
            return 0u;
        }
        Trng_Scope_Guard guard;
        const uint32_t ok_guard = static_cast<uint32_t>(guard.locked());
        if (ok_guard == 0u) {
            return 0u;
        }
        RNG_Init();
        uint32_t collected = 0u;
        uint32_t raw = 0u;
        while (collected < buffer_size) {
            TrngCollector_AssertPhysicalTrustOrFault();
            const uint32_t success =
                static_cast<uint32_t>(RNG_Read32(&raw, RNG_TIMEOUT));
            const uint32_t remain = buffer_size - collected;
            const uint32_t ge4 = static_cast<uint32_t>(remain >= 4u);
            const uint32_t bytes = ge4 * 4u + remain * (1u - ge4);
            const uint32_t valid_bytes = bytes * success;
            trng_store_buffer_chunk(buffer, collected, raw, valid_bytes);
            collected += valid_bytes;
            SecureMemory::secureWipe(&raw, sizeof(raw));
            raw = 0u;
            const uint32_t stop = 1u - success;
            if (stop != 0u) {
                SecureMemory::secureWipe(
                    buffer, static_cast<size_t>(buffer_size));
                return 0u;
            }
        }
        SecureMemory::secureWipe(&raw, sizeof(raw));
        return buffer_size;
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
