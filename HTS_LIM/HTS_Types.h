// =========================================================================
/// @file  HTS_Types.h
/// @brief 프로젝트 공통 타입 정의 (PC/서버 전용)
/// @target PC / Server (ARM 빌드 제외)
///
/// @note SecureVector는 소멸 시 메모리를 자동 0 소거하는 보안 벡터.
///       FOTA 패킷 등 임시 평문 데이터 처리에 사용.
///       BB1 텐서 버퍼에는 사용 금지 (부팅 시 Impl 내부 resize 전용).
///
/// @warning allocate()는 ::operator new(nothrow) 사용. nullptr을 vector에 넘기면
///          표준 컨테이너가 역참조하여 UB — 오버플로·OOM 시 std::abort()로 Fail-Safe 종료.
///
/// [양산 수정 이력 — 12건]
///  BUG-06 [CRIT] MSVC 환경 DSE 방어 추가
///  BUG-07 [HIGH] <new> 필수 표준 헤더 누락 교정
///  BUG-08 [MED]  MSVC volatile cast → void* 경유 static_cast
///  BUG-09 [HIGH] ⑭ ARM 빌드 차단 가드 추가
///  BUG-10 [HIGH] C-2: ::operator new → nothrow (-fno-exceptions 준수)
///  BUG-11 [MED]  D-2: release fence 누락 → delete 직전 배리어 추가
///  BUG-12 [LOW]  M-14: DRY TODO 잔류 제거 (HTS_Secure_Memory.h BUG-02에서 이미 해소)
///  BUG-13 [CRIT] allocate nullptr → vector UB 방지: 오버플로/OOM 시 std::abort()
// =========================================================================
#pragma once
// ─────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────
//  [사용법] 기본 사용 예시를 여기에 기재하세요.
//  [메모리] sizeof(클래스명) 확인 후 전역/정적 배치 필수.
//  [보안]   복사/이동 연산자 = delete (키 소재 복제 차단).
//
//  ⚠ [파트너사 필수 확인]
//    HW 레지스터 주소(UART/WDT 등)는 보드 설계에 맞게 교체.
//    IRQ 번호는 STM32F407 RM0090 벡터 테이블 기준으로 교체.
// ─────────────────────────────────────────────────────────

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#error "[HTS_FATAL] HTS_Types.h(SecureVector)는 PC/서버 전용입니다. ARM 빌드에서 제외하십시오."
#endif

#include "HTS_Secure_Memory.h"
#include <vector>
#include <cstdint>
#include <cstdlib>
#include <new>

namespace ProtectedEngine {

    template <typename T>
    struct Secure_Allocator {
        using value_type = T;

        Secure_Allocator() noexcept = default;

        template <typename U>
        Secure_Allocator(const Secure_Allocator<U>&) noexcept {}

        [[nodiscard]] T* allocate(std::size_t n) noexcept {
            if (n != 0u && n > (SIZE_MAX / sizeof(T))) {
                std::abort();
            }
            T* const p = static_cast<T*>(
                ::operator new(n * sizeof(T), std::nothrow));
            if (p == nullptr && n != 0u) {
                std::abort();
            }
            return p;
        }

        void deallocate(T* ptr, std::size_t n) noexcept {
            if (ptr != nullptr && n > 0u) {
                const std::size_t bytes = n * sizeof(T);
                SecureMemory::secureWipe(static_cast<void*>(ptr), bytes);
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
