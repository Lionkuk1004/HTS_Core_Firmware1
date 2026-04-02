// =========================================================================
// HTS_Physical_Entropy_Engine.cpp
// 물리적 엔트로피 엔진 구현부 — Murmur3 다중 혼합 PRNG
// Target: STM32F407 (Cortex-M4, 168MHz)
//
#include "HTS_Physical_Entropy_Engine.h"

#include <atomic>
#include <cstddef>
#include <cstdint>

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#define HTS_PLATFORM_ARM_BAREMETAL
#endif

#if defined(HTS_PLATFORM_ARM_BAREMETAL) && (defined(__GNUC__) || defined(__clang__))
#define HTS_ENTROPY_ARM_GNUC 1
#else
#define HTS_ENTROPY_ARM_GNUC 0
#endif

namespace ProtectedEngine {

    // =====================================================================
    //  전역 암호 카운터 (모든 스레드/ISR 공유)
    // =====================================================================
    std::atomic<uint32_t> Physical_Entropy_Engine::ctr_nonce_state{ 1 };

#if defined(HTS_PLATFORM_ARM_BAREMETAL)

    static std::atomic<uint32_t> hw_trng_seeded{ 0u };

    // =====================================================================
    //  DWT CYCCNT 읽기
    //
    //  Cortex-M4: DEMCR.TRCENA(bit24)만 켜면 DWT 쓰기 권한 활성화
    //  DWT LAR 레지스터는 M4에 물리적 미존재 (M7/M33 전용)
    // =====================================================================
    static uint32_t Read_DWT_CYCCNT() noexcept {
        // J-3: DWT CYCCNT 주소 constexpr (CoreSight)
        static constexpr uintptr_t ADDR_DWT_CYCCNT = 0xE0001004u;  ///< DWT Cycle Count Register

        //  DWT는 Hardware_Init::Initialize_System()에서 활성화 — 여기서는 읽기만
        volatile uint32_t* const DWT_CYCCNT =
            reinterpret_cast<volatile uint32_t*>(ADDR_DWT_CYCCNT);
        return *DWT_CYCCNT;
    }

    // =====================================================================
    //  STM32F407 하드웨어 TRNG 읽기
    //  타임아웃/에러 시 DWT 폴백 (TRNG 고장 대비)
    // =====================================================================
    static uint32_t Read_STM32_RNG() noexcept {
        // ISR/예외 컨텍스트: RCC/RNG 장시간 폴링·클럭 토글 금지 → DWT만 (기아 방지)
#if HTS_ENTROPY_ARM_GNUC
        uint32_t ipsr_val = 0u;
        __asm__ volatile ("mrs %0, ipsr" : "=r"(ipsr_val) : : "memory");
        if (ipsr_val != 0u) {
            return Read_DWT_CYCCNT();
        }
#endif
        // J-3: RNG/RCC 레지스터 constexpr
        static constexpr uintptr_t ADDR_RNG_CR = 0x50060800u;  ///< RNG Control
        static constexpr uintptr_t ADDR_RNG_SR = 0x50060804u;  ///< RNG Status
        static constexpr uintptr_t ADDR_RNG_DR = 0x50060808u;  ///< RNG Data
        static constexpr uintptr_t ADDR_RCC_AHB2ENR = 0x40023834u;  ///< RCC AHB2 Enable
        static constexpr uint32_t  RNG_CR_RNGEN = (1u << 2);    ///< RNG Enable
        static constexpr uint32_t  RCC_RNG_EN = (1u << 6);    ///< RNG Clock Enable

        volatile uint32_t* const RNG_CR =
            reinterpret_cast<volatile uint32_t*>(ADDR_RNG_CR);
        volatile uint32_t* const RNG_SR =
            reinterpret_cast<volatile uint32_t*>(ADDR_RNG_SR);
        volatile uint32_t* const RNG_DR =
            reinterpret_cast<volatile uint32_t*>(ADDR_RNG_DR);
        volatile uint32_t* const RCC_AHB2ENR =
            reinterpret_cast<volatile uint32_t*>(ADDR_RCC_AHB2ENR);

        *RCC_AHB2ENR |= RCC_RNG_EN;
        // AHB 매트릭스 클럭 안정화: 쓰기 직후 RNG 버스 접근 시 Bus Fault 방지 (RM read-back + DSB)
        (void)*RCC_AHB2ENR;
#if HTS_ENTROPY_ARM_GNUC
        __asm__ volatile ("dsb sy" ::: "memory");
#endif
        *RNG_CR |= RNG_CR_RNGEN;
#if HTS_ENTROPY_ARM_GNUC
        __asm__ volatile ("dsb sy" ::: "memory");
#endif

        uint32_t timeout = 1000;
        while (((*RNG_SR) & 1u) == 0 && timeout > 0) {
            if ((*RNG_SR) & 0x60u) { timeout = 0; break; }
            --timeout;
        }

        if (timeout == 0) return Read_DWT_CYCCNT();
        return *RNG_DR;
    }

#endif

    // =====================================================================
    //  Murmur3 변형 단방향 혼합
    // =====================================================================
    uint32_t Physical_Entropy_Engine::PRNG_Mix_Block(
        uint32_t entropy_seed, uint32_t counter) noexcept {
        uint32_t state = entropy_seed ^ counter;
        state = (state << 13u) | (state >> 19u);
        state *= 0x85EBCA6Bu;
        state ^= (state >> 16u);
        state *= 0xC2B2AE35u;
        state ^= (state >> 16u);
        return state;
    }

    // =====================================================================
    //  Extract_Quantum_Seed — 물리적 엔트로피 추출
    //
    //  [동시성 안전]
    //  ctr_nonce_state: fetch_add + fetch_xor (하드웨어 원자적 RMW)
    //  hw_trng_seeded: compare_exchange_strong (3상 상태 머신)
    //  ISR/멀티스레드 동시 호출 안전
    // =====================================================================
    uint32_t Physical_Entropy_Engine::Extract_Quantum_Seed() noexcept {
        uint32_t dynamic_entropy = 0u;

#if defined(HTS_PLATFORM_ARM_BAREMETAL)
        static constexpr uint32_t TRNG_BOOT_WAIT_MAX = 200000u;

        uint32_t expected = 0u;
        if (hw_trng_seeded.compare_exchange_strong(
            expected, 1u, std::memory_order_acq_rel)) {
            uint32_t hw_seed = Read_STM32_RNG();
            ctr_nonce_state.fetch_xor(hw_seed, std::memory_order_release);
            hw_trng_seeded.store(2u, std::memory_order_release);
        }
        else {
            const uint32_t seed_state =
                hw_trng_seeded.load(std::memory_order_acquire);
            if (seed_state == 1u) {
                // 승자가 Read_STM32_RNG 중 — XOR·상태 2 전에 진행하면 시드 혼합 순서 깨짐
                uint32_t spin = 0u;
                while (hw_trng_seeded.load(std::memory_order_acquire) == 1u
                    && spin < TRNG_BOOT_WAIT_MAX) {
                    ++spin;
                }
                // 선발 스레드 정지·TRNG 고착 시 무한 스핀 방지 — 후속 진입 차단용 bust
                if (hw_trng_seeded.load(std::memory_order_acquire) == 1u) {
                    hw_trng_seeded.store(2u, std::memory_order_release);
                }
            }
        }

        dynamic_entropy = Read_DWT_CYCCNT();

#endif

        uint32_t counter = ctr_nonce_state.fetch_add(
            1u, std::memory_order_relaxed);
        counter ^= dynamic_entropy;

        // Murmur3 3단 비가역 혼합
        uint32_t mixed_a = PRNG_Mix_Block(
            counter ^ 0x3D485453u, counter);
        uint32_t mixed_b = PRNG_Mix_Block(
            mixed_a ^ static_cast<uint32_t>(counter * 0x9E3779B9u),
            ~counter);
        uint32_t mixed_c = PRNG_Mix_Block(
            mixed_b ^ static_cast<uint32_t>(counter * 0x6C62272Eu),
            counter ^ mixed_a);

        return mixed_a ^ mixed_b ^ mixed_c;
    }

    // =====================================================================
    //  앵커 노드 판별 (5% 비율: 20칩당 1개)
    // =====================================================================
    bool Physical_Entropy_Engine::Is_Anchor_Node(size_t index) noexcept {
        // ASIC 규약: 런타임 나눗셈/모듈로 제거
        // index % 20 == 0  <=>  (index/4) % 5 == 0
        // /4는 시프트, /5는 reciprocal multiply로 판정
        if (index > static_cast<size_t>(0xFFFFFFFFu)) { return false; }
        const uint32_t idx32 = static_cast<uint32_t>(index);
        if ((idx32 & 3u) != 0u) { return false; }
        const uint32_t div4 = idx32 >> 2u;
        const uint32_t q5 = static_cast<uint32_t>(
            (static_cast<uint64_t>(div4) * 0xCCCCCCCDull) >> 34u);
        return (q5 * 5u) == div4;
    }

} // namespace ProtectedEngine
