// =========================================================================
// HTS_Physical_Entropy_Engine.cpp
// 물리적 엔트로피 엔진 구현부 — Murmur3 다중 혼합 PRNG
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// [양산 수정 — 총 18건]
//  FIX-01~08 (초기), BUG-01~11 (세션 2~5)
//  BUG-12 [CRIT] Spin-Wait 데드락 → Non-blocking DWT 폴백
//  BUG-13 [CRIT] PC 고정 시드 → 시간 기반 초기 시드 주입
//  BUG-14 [HIGH] TRNG 고장 시 고정 시드 → DWT 지속 혼합
//  BUG-15 [MED]  DWT 활성화 파이프라인 지연 → DSB+ISB 배리어
//  BUG-17 [CRIT] TOCTOU 레이스 → 원자적 3상 상태 머신
//  BUG-18 [CRIT] load+store Lost Update → fetch_xor 원자적 RMW
//
// [Cortex-M4 DWT 참고]
//  M4에는 DWT LAR 레지스터 미존재 (M7/M33 전용)
//  DEMCR.TRCENA(bit24) 단독으로 DWT 활성화 충분
// =========================================================================
#include "HTS_Physical_Entropy_Engine.h"

#include <atomic>
#include <cstddef>
#include <cstdint>

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#define HTS_PLATFORM_ARM_BAREMETAL
#elif defined(__aarch64__)
#define HTS_PLATFORM_AARCH64
#include <chrono>
#else
#define HTS_PLATFORM_PC
#include <chrono>
#endif

namespace ProtectedEngine {

    // =====================================================================
    //  전역 암호 카운터 (모든 스레드/ISR 공유)
    // =====================================================================
    std::atomic<uint32_t> Physical_Entropy_Engine::ctr_nonce_state{ 1 };

#if defined(HTS_PLATFORM_ARM_BAREMETAL)

    // [BUG-17] 3상 원자적 상태 머신: 0=미초기화, 1=초기화 중, 2=완료
    static std::atomic<uint32_t> hw_trng_seeded{ 0u };

    // =====================================================================
    //  DWT CYCCNT 읽기
    //
    //  Cortex-M4: DEMCR.TRCENA(bit24)만 켜면 DWT 쓰기 권한 활성화
    //  DWT LAR 레지스터는 M4에 물리적 미존재 (M7/M33 전용)
    // =====================================================================
    static uint32_t Read_DWT_CYCCNT() noexcept {
        volatile uint32_t* const DEMCR =
            reinterpret_cast<volatile uint32_t*>(0xE000EDFCu);
        volatile uint32_t* const DWT_CTRL =
            reinterpret_cast<volatile uint32_t*>(0xE0001000u);
        volatile uint32_t* const DWT_CYCCNT =
            reinterpret_cast<volatile uint32_t*>(0xE0001004u);

        if ((*DWT_CTRL & 1u) != 0) return *DWT_CYCCNT;

        *DEMCR |= (1u << 24);
        *DWT_CTRL |= (1u << 0);
        // [BUG-15] 파이프라인 동기화 배리어
        __asm__ __volatile__("dsb" ::: "memory");
        __asm__ __volatile__("isb" ::: "memory");

        return *DWT_CYCCNT;
    }

    // =====================================================================
    //  STM32F407 하드웨어 TRNG 읽기
    //  타임아웃/에러 시 DWT 폴백 (TRNG 고장 대비)
    // =====================================================================
    static uint32_t Read_STM32_RNG() noexcept {
        volatile uint32_t* const RNG_CR =
            reinterpret_cast<volatile uint32_t*>(0x50060800u);
        volatile uint32_t* const RNG_SR =
            reinterpret_cast<volatile uint32_t*>(0x50060804u);
        volatile uint32_t* const RNG_DR =
            reinterpret_cast<volatile uint32_t*>(0x50060808u);
        volatile uint32_t* const RCC_AHB2ENR =
            reinterpret_cast<volatile uint32_t*>(0x40023834u);

        *RCC_AHB2ENR |= (1u << 6);
        *RNG_CR |= (1u << 2);

        // [BUG-12] 타임아웃 폴링 (Spin-Wait 데드락 방지)
        uint32_t timeout = 1000;
        while (((*RNG_SR) & 1u) == 0 && timeout > 0) {
            if ((*RNG_SR) & 0x60u) { timeout = 0; break; }
            --timeout;
        }

        if (timeout == 0) return Read_DWT_CYCCNT();
        return *RNG_DR;
    }

#elif defined(HTS_PLATFORM_AARCH64)
    static std::atomic<bool> a55_seeded{ false };

    // 통합콘솔 (A55 Linux): CNTVCT_EL0 동적 엔트로피
    static uint32_t Read_CNTVCT_Entropy() noexcept {
        uint64_t cntvct;
        __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(cntvct));
        // 하위 32비트: 타이밍 지터 포함 (호출 시점마다 상이)
        return static_cast<uint32_t>(cntvct);
    }
#else
    static std::atomic<bool> pc_seeded{ false };
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

#if defined(HTS_PLATFORM_ARM_BAREMETAL)
        // [BUG-17] 원자적 3상 상태 머신: TOCTOU 레이스 차단
        uint32_t expected = 0u;
        if (hw_trng_seeded.compare_exchange_strong(
            expected, 1u, std::memory_order_acq_rel)) {
            uint32_t hw_seed = Read_STM32_RNG();
            // [BUG-18] fetch_xor: 원자적 RMW (Lost Update 차단)
            ctr_nonce_state.fetch_xor(hw_seed, std::memory_order_release);
            hw_trng_seeded.store(2u, std::memory_order_release);
        }

        // [BUG-14] 매 호출마다 DWT 지속 혼합 (TRNG 고장 대비)
        uint32_t dynamic_entropy = Read_DWT_CYCCNT();

#elif defined(HTS_PLATFORM_AARCH64)
        // [BUG-20] 통합콘솔 (A55 Linux): CNTVCT_EL0 + chrono 초기 시드
        //
        // A55는 STM32 TRNG 하드웨어에 직접 접근 불가 (PUF와 동일)
        // → CNTVCT_EL0 타이밍 지터를 매 호출 동적 엔트로피로 사용
        // → STM32의 DWT CYCCNT 역할을 CNTVCT_EL0가 대체
        //
        // 초기 시드: chrono nanoseconds (프로세스 시작 시점 1회)
        // 동적 엔트로피: CNTVCT_EL0 (매 호출 타이밍 지터)
        if (!a55_seeded.exchange(true, std::memory_order_relaxed)) {
            auto now = std::chrono::steady_clock::now().time_since_epoch();
            uint32_t time_seed = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    now).count());
            ctr_nonce_state.fetch_xor(time_seed,
                std::memory_order_release);
        }
        uint32_t dynamic_entropy = Read_CNTVCT_Entropy();

#else
        // PC 개발빌드: 시간 기반 초기 시드 (매 실행 고유)
        if (!pc_seeded.exchange(true, std::memory_order_relaxed)) {
            auto now = std::chrono::steady_clock::now().time_since_epoch();
            uint32_t time_seed = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    now).count());
            ctr_nonce_state.fetch_xor(time_seed,
                std::memory_order_release);
        }
        uint32_t dynamic_entropy = 0;
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
        return (index % 20u == 0u);
    }

} // namespace ProtectedEngine