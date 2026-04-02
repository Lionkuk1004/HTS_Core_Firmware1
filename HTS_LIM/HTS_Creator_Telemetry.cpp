// =========================================================================
// HTS_Creator_Telemetry.cpp
// 개발 모드 텔레메트리 구현부
// Target: STM32F407 (Cortex-M4)
//
#include "HTS_Creator_Telemetry.h"

// =========================================================================
//  _HTS_CREATOR_MODE 활성 시에만 개발 도구 헤더 포함
//  STM32 + A55 양산 빌드에서 실수로 켜지는 것을 컴파일 타임에 즉시 차단
//  A55 디버그 빌드에서 사용하려면 HTS_ALLOW_TELEMETRY_AARCH64도 함께 정의
// =========================================================================
#ifdef _HTS_CREATOR_MODE
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#error "[HTS_FATAL] _HTS_CREATOR_MODE는 ARM 양산 빌드에서 사용할 수 없습니다. 전처리기 정의를 제거하십시오."
#elif defined(__aarch64__) && !defined(HTS_ALLOW_TELEMETRY_AARCH64)
#error "[HTS_FATAL] _HTS_CREATOR_MODE는 A55 양산 빌드에서 사용할 수 없습니다. 디버그용이면 HTS_ALLOW_TELEMETRY_AARCH64를 함께 정의하십시오."
#endif
#include <iostream>
#include <iomanip>
#endif

namespace ProtectedEngine {

    void HTS_Telemetry::Log(
        const char* module_name,
        const char* action,
        uint32_t value) noexcept {

        // 릴리즈 빌드: (void) 캐스트만 남음 → LTO가 함수 자체를 소거
        (void)module_name;
        (void)action;
        (void)value;

#ifdef _HTS_CREATOR_MODE
        const char* safe_module = module_name ? module_name : "(null)";
        const char* safe_action = action ? action : "(null)";

        struct IosFormatGuard {
            std::ios_base::fmtflags flags;
            char fill;
            IosFormatGuard() : flags(std::cout.flags()), fill(std::cout.fill()) {}
            ~IosFormatGuard() {
                std::cout.flags(flags);
                std::cout.fill(fill);
            }
        } format_guard;

        // 모듈명 고정폭 15자 좌측 정렬
        std::cout << "[HTS-32] ["
            << std::setw(15) << std::left << safe_module
            << "] " << safe_action;

        // 0이 아닌 값만 hex 출력 (0은 "값 없음" 의미)
        if (value != 0u) {
            std::cout << " -> 0x"
                << std::hex << std::uppercase
                << std::setfill('0') << std::setw(8)
                << value;
        }

        std::cout << "\n";
#endif
    }

} // namespace ProtectedEngine
