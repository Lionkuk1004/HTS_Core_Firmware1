// =========================================================================
/// @file  HTS_Types.h
/// @brief 프로젝트 공통 타입 정의 (PC/서버 전용)
/// @target PC / Server (ARM 빌드 제외)
///
/// @note SecureVector는 소멸 시 메모리를 자동 0 소거하는 보안 벡터.
///       FOTA 패킷 등 임시 평문 데이터 처리에 사용.
///       BB1 텐서 버퍼에는 사용 금지 (부팅 시 Impl 내부 resize 전용).
///
/// @warning allocate()는 nothrow 반환. OOM 시 nullptr → std::vector 내부에서
///          미정의 동작 가능. PC 전용 모듈이므로 OOM 가능성 극히 낮으나,
///          대용량 할당 전 시스템 메모리 검사를 권장.
///
/// [양산 수정 이력 — 12건]
///  BUG-01~05 (이전 세션)
///  BUG-06 [CRIT] MSVC 환경 DSE 방어 추가
///  BUG-07 [HIGH] <new> 필수 표준 헤더 누락 교정
///  BUG-08 [MED]  MSVC volatile cast → void* 경유 static_cast
///  BUG-09 [HIGH] ⑭ ARM 빌드 차단 가드 추가
///  BUG-10 [HIGH] C-2: ::operator new → nothrow (-fno-exceptions 준수)
///  BUG-11 [MED]  D-2: release fence 누락 → delete 직전 배리어 추가
///  BUG-12 [LOW]  M-14: DRY TODO 잔류 제거 (HTS_Secure_Memory.h BUG-02에서 이미 해소)
// =========================================================================
#pragma once

// [BUG-09] ARM 빌드 차단 — <vector>/::operator new 힙 인프라 금지
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#error "[HTS_FATAL] HTS_Types.h(SecureVector)는 PC/서버 전용입니다. ARM 빌드에서 제외하십시오."
#endif

#include <vector>
#include <cstdint>
#include <cstring>
#include <new>
#include <atomic>  // [BUG-11] std::atomic_thread_fence

namespace ProtectedEngine {

    template <typename T>
    struct Secure_Allocator {
        using value_type = T;

        Secure_Allocator() noexcept = default;

        template <typename U>
        Secure_Allocator(const Secure_Allocator<U>&) noexcept {}

        // [BUG-10] nothrow: -fno-exceptions에서 OOM 시 std::terminate 방지
        //  nullptr 반환 → std::vector 내부 미정의 동작 가능성 있으나
        //  PC 전용 모듈이므로 OOM 확률 극히 낮음
        [[nodiscard]] T* allocate(std::size_t n) noexcept {
            return static_cast<T*>(
                ::operator new(n * sizeof(T), std::nothrow));
        }

        void deallocate(T* ptr, std::size_t n) noexcept {
            if (ptr && n > 0u) {
                const std::size_t bytes = n * sizeof(T);

#if defined(__GNUC__) || defined(__clang__)
                std::memset(static_cast<void*>(ptr), 0, bytes);
                __asm__ __volatile__("" : : "r"(ptr) : "memory");
#elif defined(_MSC_VER)
                // [BUG-08] T* → void* → volatile uint8_t* (⑫ static_cast 경유)
                // Secure_Wipe_BB1(BB1_Core_Engine.cpp) 패턴과 통일
                volatile uint8_t* vptr = static_cast<volatile uint8_t*>(
                    static_cast<void*>(ptr));
                for (std::size_t i = 0; i < bytes; ++i) {
                    vptr[i] = 0u;
                }
#else
                std::memset(static_cast<void*>(ptr), 0, bytes);
#endif
                // [BUG-11] release fence: 소거 완료를 delete 전에 가시화
                // BB1_Core_Engine Secure_Wipe_BB1 / HTS_Universal_API
                // Absolute_Trace_Erasure 보안 소거 정책 통일
                std::atomic_thread_fence(std::memory_order_release);
            }
            ::operator delete(ptr);
        }
    };

    template <typename T, typename U>
    bool operator==(const Secure_Allocator<T>&,
        const Secure_Allocator<U>&) noexcept {
        return true;
    }

    template <typename T, typename U>
    bool operator!=(const Secure_Allocator<T>&,
        const Secure_Allocator<U>&) noexcept {
        return false;
    }

    using SecureVector = std::vector<uint8_t, Secure_Allocator<uint8_t>>;

} // namespace ProtectedEngine