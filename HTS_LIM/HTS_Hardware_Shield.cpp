// =========================================================================
// HTS_Hardware_Shield.cpp
// B-CDMA 하드웨어 보안 실드 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
//
#include "HTS_Hardware_Shield.h"
#include "HTS_Hardware_Bridge.hpp"
#include "HTS_Physical_Entropy_Engine.h"
#include <atomic>

#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
#include <bit>
#endif
#if defined(_MSC_VER)
#include <intrin.h>  // _ReadWriteBarrier (Execute_Tensor_Decoherence_Shredding)
#endif

// =========================================================================
//  3단 플랫폼 분기
// =========================================================================
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#define HTS_SHIELD_ARM
#elif defined(_WIN32)
#define HTS_SHIELD_WIN
#else
#define HTS_SHIELD_LINUX
#endif

namespace ProtectedEngine {

    // =====================================================================
    //  Lock — B-CDMA PHY 레지스터 쓰기 잠금
    //
    //  [동작]
    //  세션 설립 완료 후 호출 → PHY 주파수/코드/출력 등 설정 변경 차단
    //  → 런타임 중 적군의 PHY 파라미터 변조 공격 방어
    //
    //  [파트너사 구현 가이드]
    //  AMI 보드의 PHY 잠금 레지스터 주소를 아래 ARM 경로에 기입하십시오.
    //  예: *HW_LOCK_REG = 0x01 → PHY 레지스터 쓰기 보호 활성화
    //      잠금 해제는 WDT 리셋 후에만 가능 (소프트웨어 해제 불가)
    // =====================================================================
    void Hardware_Shield::Lock() noexcept {
#if defined(HTS_SHIELD_ARM)
        // TODO: 파트너사 AMI 보드 PHY 잠금 레지스터
        // 예:
        // volatile uint32_t* HW_LOCK_REG =
        //     reinterpret_cast<volatile uint32_t*>(0x80005000u);
        // *HW_LOCK_REG = 0x01u;
        // __asm__ __volatile__("dmb sy" ::: "memory");
        (void)0;  // 파트너사 구현 전 NOP
#else
        // PC 시뮬레이션: no-op
        (void)0;
#endif
    }

    // =====================================================================
    //  Execute_Tensor_Decoherence_Shredding — 텐서 요소 물리적 파쇄
    //
    //  [호출 시점]
    //  BB1_Core_Engine: Secure_Gate 실패 시 텐서 데이터 파쇄
    //  → 공격자가 미인가 세션으로 텐서를 읽어도 무의미한 데이터만 잔존
    //
    //  [3단계 DOD 5220.22-M 스타일 덮어쓰기]
    //  Pass 1: 런타임 엔트로피 기반 랜덤 패턴 쓰기
    //          → SRAM 셀의 이전 비트 상태를 무작위 패턴으로 덮음
    //  Pass 2: Pass 1의 비트 보수(~) 쓰기
    //          → 매 셀이 0→1, 1→0 양방향 전이를 경험
    //          → 데이터 잔류(Data Remanence) 패턴 소멸
    //  Pass 3: 0x00000000 최종 소거
    //          → 확인 가능한 깨끗한 상태로 마무리
    //
    //  각 패스 사이 atomic_thread_fence(release): 패스 순서 가시성
    //
    //  단일 워드 API: TRNG + DWT 틱 1회.
    //  범위 API Execute_Tensor_Decoherence_Shredding_Range: TRNG 1회만 —
    //  워드마다 TRNG를 반복 호출하지 않음 (B-CDMA MAC/PHY ISR 기아 방지).
    //
    // =====================================================================
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC push_options
#pragma GCC optimize("O0")
#elif defined(_MSC_VER)
#pragma optimize("", off)
#endif

namespace {

    /// 버퍼 내 워드별 시드 — TRNG 없이 주소·인덱스로 분기 (빠른 경로)
    uint32_t Mix_Per_Word(uint32_t base, size_t index, const uint32_t* addr) noexcept {
        uint32_t x = base;
        x ^= static_cast<uint32_t>(static_cast<uint32_t>(index) * 0x9E3779B9u);
        x ^= static_cast<uint32_t>(reinterpret_cast<uintptr_t>(addr));
        x ^= x >> 16u;
        x *= 0x85EBCA6Bu;
        if (x == 0u) {
            x = 0x5C4E3D2Fu;
        }
        return x;
    }

    void Shred_Single_Volatile_Word(volatile uint32_t* vp, uint32_t word_seed) noexcept {
        uint32_t seed = word_seed;
        if (seed == 0u) {
            seed = 0x5C4E3D2Fu;
        }

        // ── Pass 1: 런타임 랜덤 패턴 ─────────────────────────────────
        uint32_t pattern = *vp ^ seed;
#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
        pattern = std::rotl(pattern, 13);
#else
        pattern = (pattern << 13u) | (pattern >> 19u);
#endif
        pattern ^= 0x3D504F57u;
        *vp = pattern;
        std::atomic_thread_fence(std::memory_order_release);

        // ── Pass 2: 비트 보수 (0→1, 1→0 전이 강제) ──────────────────
        *vp = ~pattern;
        std::atomic_thread_fence(std::memory_order_release);

        // ── Pass 3: 최종 0 소거 ──────────────────────────────────────
        *vp = 0x00000000u;
        std::atomic_thread_fence(std::memory_order_release);
#if defined(_MSC_VER)
        _ReadWriteBarrier();
#elif defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(vp) : "memory");
#endif
    }

} // namespace

    void Hardware_Shield::Execute_Tensor_Decoherence_Shredding(
        uint32_t* node) noexcept {

        if (!node) return;

        uint32_t base = Physical_Entropy_Engine::Extract_Quantum_Seed();
        base ^= static_cast<uint32_t>(
            Hardware_Bridge::Get_Physical_CPU_Tick() & 0xFFFFFFFFULL);
        if (base == 0u) {
            base = 0x5C4E3D2Fu;
        }

        Shred_Single_Volatile_Word(reinterpret_cast<volatile uint32_t*>(node), base);
    }

    void Hardware_Shield::Execute_Tensor_Decoherence_Shredding_Range(
        uint32_t* first, size_t word_count) noexcept {

        if (!first || word_count == 0u) return;

        uint32_t base = Physical_Entropy_Engine::Extract_Quantum_Seed();
        base ^= static_cast<uint32_t>(
            Hardware_Bridge::Get_Physical_CPU_Tick() & 0xFFFFFFFFULL);
        if (base == 0u) {
            base = 0x5C4E3D2Fu;
        }

        if (word_count == 1u) {
            Shred_Single_Volatile_Word(reinterpret_cast<volatile uint32_t*>(first), base);
            return;
        }

        for (size_t i = 0u; i < word_count; ++i) {
            const uint32_t word_seed = Mix_Per_Word(base, i, &first[i]);
            Shred_Single_Volatile_Word(
                reinterpret_cast<volatile uint32_t*>(&first[i]), word_seed);
        }
    }

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC pop_options
#elif defined(_MSC_VER)
#pragma optimize("", on)
#endif

    // =====================================================================
    //  Get_Hardware_Clock — CPU 물리 사이클 카운터
    //
    //  Hardware_Bridge::Get_Physical_CPU_Tick() — ARM DWT / PC TSC
    //
    //  [API 유지 이유]
    //  BB1_Core_Engine 등 호출자가 Hardware_Shield 경유로 틱을 사용할 수 있음
    //  Hardware_Bridge 직접 호출과 동일하나, 모듈 간 의존성 캡슐화 목적
    // =====================================================================
    uint64_t Hardware_Shield::Get_Hardware_Clock() noexcept {
        return Hardware_Bridge::Get_Physical_CPU_Tick();
    }

} // namespace ProtectedEngine
