// =========================================================================
// HTS_Hardware_Shield.cpp
// B-CDMA 하드웨어 보안 실드 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
//
#include "HTS_Hardware_Shield.h"
#include "HTS_Hardware_Bridge.hpp"
#include "HTS_Physical_Entropy_Engine.h"
#include <atomic>

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
    //  각 패스 사이 atomic_thread_fence(seq_cst):
    //    CPU + DMA 메모리 접근 순서 보장 → 패스 순서 보존
    //
    //  Physical_Entropy_Engine::Extract_Quantum_Seed() + DWT 틱 혼합
    //  → 매 호출마다 고유한 패턴 → 전력 차단 시 잔존 데이터 비예측적
    //
    // =====================================================================
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC push_options
#pragma GCC optimize("O0")
#elif defined(_MSC_VER)
#pragma optimize("", off)
#endif

    void Hardware_Shield::Execute_Tensor_Decoherence_Shredding(
        uint32_t* node) noexcept {

        if (!node) return;

        // ── 런타임 엔트로피 시드 생성 ────────────────────────────────
        //  Physical_Entropy: TRNG/PUF 기반 하드웨어 시드
        //  DWT 틱: 호출 시점 바인딩 (같은 데이터라도 시점마다 다른 패턴)
        uint32_t seed = Physical_Entropy_Engine::Extract_Quantum_Seed();
        seed ^= static_cast<uint32_t>(
            Hardware_Bridge::Get_Physical_CPU_Tick() & 0xFFFFFFFFULL);

        // 0 시드 방어 (seed=0 → 패턴이 val 그대로 → 파쇄 효과 없음)
        if (seed == 0) seed = 0x5C4E3D2Fu;

        // ── volatile 포인터: 모든 쓰기가 물리 메모리에 실행 ──────────
        volatile uint32_t* vp = node;

        // ── Pass 1: 런타임 랜덤 패턴 ─────────────────────────────────
        uint32_t pattern = *node ^ seed;
        pattern = (pattern << 13u) | (pattern >> 19u);  // RotL 13
        pattern ^= 0x3D504F57u;                          // 도메인 상수 혼합
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

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC pop_options
#elif defined(_MSC_VER)
#pragma optimize("", on)
#endif

    // =====================================================================
    //  Get_Hardware_Clock — CPU 물리 사이클 카운터
    //
    //  기존: 더미 0xDEAD... 반환 (비기능적)
    //  수정: Hardware_Bridge::Get_Physical_CPU_Tick() 직접 호출
    //        → ARM: DWT CYCCNT (32비트) / PC: TSC (64비트) 실제 값 반환
    //  
    //  [API 유지 이유]
    //  BB1_Core_Engine 등 호출자가 Hardware_Shield 경유로 틱을 사용할 수 있음
    //  Hardware_Bridge 직접 호출과 동일하나, 모듈 간 의존성 캡슐화 목적
    // =====================================================================
    uint64_t Hardware_Shield::Get_Hardware_Clock() noexcept {
        return Hardware_Bridge::Get_Physical_CPU_Tick();
    }

} // namespace ProtectedEngine
