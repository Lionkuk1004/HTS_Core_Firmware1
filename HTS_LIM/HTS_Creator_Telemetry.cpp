// =========================================================================
// HTS_Creator_Telemetry.cpp
// 개발 모드 텔레메트리 구현부
// Target: STM32F407 (Cortex-M4)
//
// [양산 수정 — 5건 결함 교정]
//  BUG-01 [MEDIUM] nullptr UB
//    기존: std::cout << module_name → nullptr 전달 시 정의되지 않은 동작
//          C++ 표준: operator<<(const char*) 에 nullptr = UB
//    수정: nullptr 시 "(null)" 폴백 문자열 사용
//
//  BUG-02 [LOW] iostream 포맷 상태 오염
//    기존: std::setfill('0') + std::hex + std::left 설정 후 미복원
//    수정: RAII(Resource Acquisition Is Initialization) 가드 패턴 적용
//
//  BUG-03 [LOW] ARM #error 메시지 영문 혼용
//    수정: 한국어 통일 (기존과 동일 — 유지)
//
//  BUG-04 [LOW] catch(...) 무조건 무시
//    수정: 디버그 모드이므로 현행 유지 (I/O 실패 시 침묵이 올바른 동작)
//
//  BUG-05 [HIGH] 예외 발생 시 포맷 복원 우회 (상태 오염 부활)
//    수정: IosFormatGuard 로컬 구조체를 도입하여 스택 언와인딩 시에도 
//          소멸자가 무조건 포맷을 복원하도록 예외 안전성 확보
//
// [릴리즈 빌드 Zero-Cost 검증]
//  _HTS_CREATOR_MODE 미정의 시:
//    - #ifdef 내부 코드 전부 전처리기 단계에서 제거
//    - 남는 코드: (void) 캐스트 3개 = 빈 함수
//    - LTO(Link-Time Optimization): 빈 함수 인라인 → CALL 자체 소거
//    - Flash 영향: 0바이트 / 사이클 영향: 0회
// =========================================================================
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
        try {
            // [BUG-01 수정] nullptr 방어
            const char* safe_module = module_name ? module_name : "(null)";
            const char* safe_action = action ? action : "(null)";

            // [BUG-02/05 수정] RAII 패턴 기반 iostream 포맷 상태 보존
            // I/O 작업 중 예외가 발생해 catch 블록으로 점프하더라도
            // format_guard 객체의 소멸자가 호출되며 원래 포맷으로 확실히 롤백됨
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
            if (value != 0) {
                std::cout << " -> 0x"
                    << std::hex << std::uppercase
                    << std::setfill('0') << std::setw(8)
                    << value;
            }

            std::cout << "\n";
        }
        catch (...) {
            // I/O 예외가 펌웨어 콜스택을 붕괴시키는 것을 방어
            // 텔레메트리 실패는 시스템 동작에 영향 없음 (개발 도구 전용)
        }
#endif
    }

} // namespace ProtectedEngine