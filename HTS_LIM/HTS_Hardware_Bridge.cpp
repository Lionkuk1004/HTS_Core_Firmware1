// =========================================================================
// HTS_Hardware_Bridge.cpp
// CPU 물리 틱 추출 및 보안 메모리 소거 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
//
#include "HTS_Hardware_Bridge.hpp"

// ── Self-Contained 표준 헤더 (<cstddef>, <cstdint>) ──────────────────
#include <atomic>
#include <cstddef>      // size_t
#include <cstdint>      // uint8_t, uint64_t
#include <cstdlib>      // std::abort — AArch64 틱 실패 시 엔트로피 0 주입 방지

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#define HTS_HWBRIDGE_ARM
#endif

#ifndef HTS_HWBRIDGE_ARM
#include <vector>
#endif

// =========================================================================
//  플랫폼별 틱 카운터 헤더
// =========================================================================
#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
    // MSVC x86/x64: __rdtsc
#include <intrin.h>
#define HTS_TICK_MSVC_X86
#elif (defined(__GNUC__) || defined(__clang__)) && (defined(__i386__) || defined(__x86_64__))
    // GCC/Clang x86/x64: __rdtsc
#include <x86intrin.h>
#define HTS_TICK_GCC_X86
#elif defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
    // ARM Cortex-M4: DWT CYCCNT
#define HTS_TICK_ARM_DWT
#elif defined(__aarch64__)
    // ARM Cortex-A55 (통합콘솔 INNOVID CORE-X Pro): POSIX vDSO 타이머
    //  Linux 4.12+ 보안 커널: CNTKCTL_EL1.EL0VCTEN=0 → EL0에서
    //  mrs cntvct_el0 트랩 → SIGILL(Illegal Instruction) 프로세스 즉사
    //  EL0: clock_gettime(CLOCK_MONOTONIC) — vDSO, 커널 안전 타이머
    //  성능: vDSO는 syscall 아님 → 컨텍스트 스위칭 0, ~20ns (cntvct 대비 +5ns)
#define HTS_TICK_AARCH64_VDSO
#include <time.h>
#else
    // 미지원 플랫폼 — 컴파일 차단
    // 타이밍 방어가 0 반환으로 무력화되는 것을 방지
#error "[HTS_FATAL] HTS_Hardware_Bridge: 지원되지 않는 CPU 아키텍처입니다. x86/x64, ARM Cortex-M, 또는 AArch64를 사용하십시오."
#endif

// MSVC 컴파일러 배리어 — <intrin.h>는 위에서 이미 포함됨

namespace ProtectedEngine {

    // =====================================================================
    //  Get_Physical_CPU_Tick — CPU 물리 사이클 카운터 읽기
    //
    //  [x86/x64] TSC (Time Stamp Counter)
    //    64비트, GHz 클럭 → 수백 년 래핑 → 실질 무한
    //
    //  [ARM Cortex-M4] DWT CYCCNT
    //    32비트, 168MHz → 2^32 / 168,000,000 ≈ 25.56초 래핑
    //    Initialize_System()에서 DEMCR TRCENA + DWT CYCCNTENA 활성화 필수
    //    미활성 시 0 고정 → 타이밍 방어 무력화 (디버그 시 주의)
    //
    //  [반환값]
    //    x86: 64비트 TSC 전체
    //    ARM: 하위 32비트만 유효 (상위 32비트 = 0)
    // =====================================================================
    uint64_t Hardware_Bridge::Get_Physical_CPU_Tick() noexcept {
#if defined(HTS_TICK_MSVC_X86)
        return __rdtsc();

#elif defined(HTS_TICK_GCC_X86)
        return __rdtsc();

#elif defined(HTS_TICK_ARM_DWT)
        // STM32F407 DWT CYCCNT (CMSIS 비의존 직접 접근)
        // J-3: DWT CYCCNT 주소 constexpr (CoreSight)
        static constexpr uintptr_t ADDR_DWT_CYCCNT = 0xE0001004u;
        volatile uint32_t* DWT_CYCCNT =
            reinterpret_cast<volatile uint32_t*>(ADDR_DWT_CYCCNT);
        return static_cast<uint64_t>(*DWT_CYCCNT);

#elif defined(HTS_TICK_AARCH64_VDSO)
        // 통합콘솔 (Cortex-A55 Linux): POSIX clock_gettime vDSO
        //  clock_gettime(CLOCK_MONOTONIC)은 Linux vDSO를 통해 커널 타이머를
        //  유저스페이스에서 안전하게 읽음 (syscall 오버헤드 0, ~20ns)
        //  나노초 해상도: 엔트로피 수집/타이밍 방어에 충분
        //
        //  MONOTONIC 실패 시 0 반환 금지(엔트로피/리플레이 방어 무력화) —
        //  CLOCK_REALTIME 재시도 후에도 실패하면 프로세스 중단(fail-hard).
        struct timespec ts{};
        if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
            if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
                std::abort();
            }
        }
        return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL
            + static_cast<uint64_t>(ts.tv_nsec);
#endif
        // #else는 위에서 #error로 차단됨 → 이 지점에 도달 불가
    }

    // =====================================================================
    //  보안 소거 공통 구현 (pragma O0 보호)
    //
    //  3중 DCE 방지:
    //    1. pragma O0: 컴파일러 최적화 전체 차단
    //    2. volatile: 각 쓰기가 부작용 → 삭제 불가
    //    3. atomic_thread_fence: 소거 이후 메모리 접근 재배치 금지
    //       + 컴파일러 배리어: 포인터 주소를 참조하여 분석 회피
    // =====================================================================
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC push_options
#pragma GCC optimize("O0")
#elif defined(_MSC_VER)
#pragma optimize("", off)
#endif

    // =====================================================================
    //  Secure_Erase_Raw — raw 포인터 보안 소거
    //
    //  용도: 키 소재, HMAC 컨텍스트, 세션 상태 등 비벡터 메모리
    //  nullptr 또는 0바이트 시 무동작 (안전)
    // =====================================================================
    void Hardware_Bridge::Secure_Erase_Raw(
        void* ptr, size_t size_bytes) noexcept {

        if (!ptr || size_bytes == 0) return;

        volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
        for (size_t i = 0; i < size_bytes; ++i) {
            p[i] = static_cast<uint8_t>(0u);
        }

        std::atomic_thread_fence(std::memory_order_release);

        // 컴파일러 배리어: 포인터 주소 참조로 분석 회피
#if defined(_MSC_VER)
        _ReadWriteBarrier();
#elif defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
    }

    // =====================================================================
    //  Secure_Erase_Memory — vector<uint8_t> 보안 소거
    //
    //  내부적으로 Secure_Erase_Raw 호출 (코드 중복 제거)
    //  벡터 크기/capacity 유지 — 내용만 0으로 소거
    // =====================================================================
#ifndef HTS_HWBRIDGE_ARM
    void Hardware_Bridge::Secure_Erase_Memory(
        std::vector<uint8_t>& buffer) noexcept {
        if (buffer.empty()) return;
        Secure_Erase_Raw(buffer.data(), buffer.size());
    }
#endif

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC pop_options
#elif defined(_MSC_VER)
#pragma optimize("", on)
#endif

} // namespace ProtectedEngine

#undef HTS_HWBRIDGE_ARM
