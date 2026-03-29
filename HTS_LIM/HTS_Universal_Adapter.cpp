// =========================================================================
// HTS_Universal_Adapter.cpp
// 장치 체급별 텐서 자동 최적화 어댑터 구현부
// Target: STM32F407VGT6 (Cortex-M4F, 168MHz)
//
// [양산 수정 이력 — 37건]
//  BUG-01~28 (이전 세션)
//  BUG-29 [HIGH] 핫 패스 acquire → relaxed (DMB 제거)
//  BUG-30 [MED]  PC 빌드 AIRCR Segfault → std::abort 분기
//  BUG-31 [MED]  always_inline 속성 복구
//  BUG-32 [HIGH] sizeof ≈ 82KB 스택 배치 경고 추가
//  BUG-33 [MED]  static_assert SRAM 예산 검증 추가
//  BUG-34 [MED]  Initialize_Device CAS 원자적 전환 (PC 이중 진입 방어)
//  BUG-35 [LOW]  [[likely]] C++20 가드 매크로 (C++14/17 호환)
//  BUG-36 [CRIT] <cstdlib>/std::abort PC코드 물리적 삭제 (아키텍처 원칙3+⑭)
//  BUG-37 [MED]  AIRCR 매직넘버 → constexpr 상수화 (J-3)
// =========================================================================
#include "HTS_Universal_Adapter.h"

namespace ProtectedEngine {

    // =====================================================================
    //  [BUG-37] ARM Cortex-M4 시스템 제어 레지스터 상수 (매직넘버 제거)
    //  출처: ARM Cortex-M4 TRM (DDI0439B) §4.3.4 AIRCR
    //  AIRCR 주소  : 0xE000ED0C (SCB→AIRCR, Cortex-M3/M4/M7 공통)
    //  VECTKEY     : 0x05FA0000 (쓰기 시 필수 인증 키, 읽기 시 0xFA05)
    //  SYSRESETREQ : bit[2] = 0x04 (시스템 리셋 요청)
    // =====================================================================
    namespace {
        constexpr uintptr_t AIRCR_ADDR = 0xE000ED0Cu;
        constexpr uint32_t  AIRCR_VECTKEY = 0x05FA0000u;
        constexpr uint32_t  AIRCR_SYSRESETREQ = 0x04u;
    } // anonymous namespace

    void HTS_Adapter::Initialize_Device(DeviceType type) noexcept {
        // [BUG-34] CAS: 정확히 1컨텍스트만 초기화 실행
        //  기존: load(acquire) → 작업 → store(release)
        //    → PC 테스트 환경: 2스레드 동시 load(false) → 양쪽 모두 초기화 실행
        //    → ARM 단일코어: 무해하나 설계 결함
        //  수정: compare_exchange_strong(acq_rel) — 원자적 false→true 전환
        //    → 선발 1컨텍스트만 통과, 후발은 즉시 반환
        bool expected = false;
        if (!m_is_initialized.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel))
            HTS_ADAPTER_UNLIKELY return;

        switch (type) {
        case DeviceType::SERVER_STORAGE:
            m_active_profile = HTS_Sys_Config_Factory::Get_Tier_Profile(
                HTS_Sys_Tier::HYPER_SERVER);
            break;

            // [BUG-35] [[likely]] → HTS_ADAPTER_LIKELY (C++14/17 호환)
        HTS_ADAPTER_LIKELY case DeviceType::AMI_ENDPOINT:
            [[fallthrough]];
        case DeviceType::ROUTER_AP:
            m_active_profile = HTS_Sys_Config_Factory::Get_Tier_Profile(
                HTS_Sys_Tier::STANDARD_CHIP);
            break;

        case DeviceType::CONSOLE_SWITCH:
            m_active_profile = HTS_Sys_Config_Factory::Get_Tier_Profile(
                HTS_Sys_Tier::WORKSTATION);
            break;

        default:
            // [BUG-36] PC 코드 물리적 삭제 (아키텍처 원칙 3)
            //  기존: #if defined(_MSC_VER) std::abort() #else ARM리셋 #endif
            //  → <cstdlib>/std::abort가 양산 ARM 소스에 물리적 존재 = ⑭ FAIL
            //  수정: PC 분기 전면 삭제, ARM AIRCR 리셋만 존재
            //  PC 테스트: 이 default는 enum class 4가지 외 도달 불가
            //             컴파일러 경고(-Wswitch)가 누락 case를 잡아줌
            // [BUG-37] AIRCR 매직넘버 → constexpr 상수
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("cpsid i" ::: "memory");
            __asm__ __volatile__("dsb" ::: "memory");
#endif
            * reinterpret_cast<volatile uint32_t*>(
                static_cast<uintptr_t>(AIRCR_ADDR)) =
                (AIRCR_VECTKEY | AIRCR_SYSRESETREQ);
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("dsb" ::: "memory");
            __asm__ __volatile__("isb");
#endif
            while (true) {
#if defined(__GNUC__) || defined(__clang__)
                __asm__ __volatile__("wfi");
#endif
            }
        }

        // [BUG-34] CAS에서 이미 true로 설정 완료
        // 추가 store 불필요 — acq_rel이 Reader 가시성 보장
    }

} // namespace ProtectedEngine