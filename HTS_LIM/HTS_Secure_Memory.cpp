// =========================================================================
// HTS_Secure_Memory.cpp
// 보안 메모리 잠금 + 안티포렌식 소거 구현부
// Target: STM32F407 (Cortex-M4)
//
// [양산 수정 — 14건]
//  기존 01~10: (이전 이력 참조)
//  BUG-11 [LOW]  주석 정합: "/ Windows / Linux" 제거
//  BUG-12 [MED]  pragma GCC optimize("O0") → volatile+asm+fence (표준 통일)
//  BUG-13 [CRIT] PC 코드 물리삭제: windows.h/iostream/mutex/cerr/abort/
//                mlock/madvise/VirtualLock 전량 제거
//  BUG-14 [LOW]  HTS_PLATFORM_ARM_BAREMETAL → 불필요 (ARM 전용 파일)
//
// [제약] try-catch 0, float/double 0, 힙 0
// =========================================================================
#include "HTS_Secure_Memory.h"
#include <atomic>

// =========================================================================
//  Force_Secure_Wipe — volatile 소거 + asm clobber + release fence
//
//  [BUG-12] pragma O0 제거 — 3중 방어로 DCE 완전 차단
//    1. volatile unsigned char*: 매 바이트 쓰기를 컴파일러가 제거 불가
//    2. asm volatile memory clobber: 재배치/삭제 원천 봉쇄
//    3. atomic_thread_fence(release): 가시성 보장
// =========================================================================
static void Force_Secure_Wipe(void* ptr, size_t size) noexcept {
    if (ptr == nullptr || size == 0) return;

    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    for (size_t i = 0; i < size; ++i) {
        p[i] = 0x00u;
    }

#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__ARM_ARCH))
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
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
        if (ptr == nullptr || size == 0) return;
        Force_Secure_Wipe(ptr, size);
    }

} // namespace ProtectedEngine