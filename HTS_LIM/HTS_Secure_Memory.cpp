// =========================================================================
// HTS_Secure_Memory.cpp
// 보안 메모리 잠금 + 안티포렌식 소거 구현부
// Target: STM32F407 (Cortex-M4)
//
#include "HTS_Secure_Memory.h"
#include <atomic>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

// =========================================================================
//  Force_Secure_Wipe — volatile 소거 + asm clobber + release fence
//
//    1. volatile unsigned char*: 매 바이트 쓰기를 컴파일러가 제거 불가
//    2. 컴파일러 전체 메모리 clobber (GCC/Clang: asm; MSVC: _ReadWriteBarrier)
//    3. atomic_thread_fence(release): 가시성 보장
// =========================================================================
static void Force_Secure_Wipe(void* ptr, size_t size) noexcept {
    if (ptr == nullptr || size == 0u) { return; }

    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    for (size_t i = 0; i < size; ++i) {
        p[i] = 0x00u;
    }

#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif

    std::atomic_thread_fence(std::memory_order_release);
}

namespace ProtectedEngine {

    // =====================================================================
    //  lockMemory — ARM: no-op
    //
    //  STM32F407에는 가상 메모리, 스왑 파티션, 코어 덤프가 없음
    //  SRAM은 항상 물리 RAM에 존재 -> mlock 불필요
    //  보안 효과: secureWipe()가 콜드 부트 공격을 방어
    // =====================================================================
    void SecureMemory::lockMemory(void* ptr, size_t size) noexcept {
        (void)ptr;
        (void)size;
    }

    // =====================================================================
    //  secureWipe — 안티포렌식 데이터 파쇄
    //
    //  ARM 물리 소거만 수행 (잠금 해제 불필요 — lockMemory가 no-op)
    // =====================================================================
    void SecureMemory::secureWipe(void* ptr, size_t size) noexcept {
        if (ptr == nullptr || size == 0u) { return; }
        Force_Secure_Wipe(ptr, size);
    }

} // namespace ProtectedEngine
