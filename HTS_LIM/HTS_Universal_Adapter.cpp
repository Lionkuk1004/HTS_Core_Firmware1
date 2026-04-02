// =========================================================================
// HTS_Universal_Adapter.cpp
// 장치 체급별 텐서 자동 최적화 어댑터 구현부
// Target: STM32F407VGT6 (Cortex-M4F, 168MHz)
//
#include "HTS_Universal_Adapter.h"

#if defined(_MSC_VER)
#include <intrin.h>
#endif
#include <cstdint>

namespace ProtectedEngine {

    // =====================================================================
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
        //   → m_is_initialized 는 프로필 완료 후에만 release (조기 true 금지)
        if (m_is_initialized.load(std::memory_order_acquire)) {
            return;
        }

        while (m_init_spin.test_and_set(std::memory_order_acquire)) {
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("" ::: "memory");
#endif
        }

        if (m_is_initialized.load(std::memory_order_acquire)) {
            m_init_spin.clear(std::memory_order_release);
            return;
        }

        switch (type) {
        case DeviceType::SERVER_STORAGE:
            m_active_profile = HTS_Sys_Config_Factory::Get_Tier_Profile(
                HTS_Sys_Tier::HYPER_SERVER);
            break;

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
            // 대기 중인 다른 진입이 영구 정지하지 않도록 스핀 해제 후 치명 경로
            m_init_spin.clear(std::memory_order_release);
            // 손상/비정상 DeviceType — ARM만 SCB AIRCR 물리 주소 접근 (X-1-1)
            //  PC/호스트: 0xE000ED0C 역참조는 무효 → 메모리 손상(H-1) — 분기 차단
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("cpsid i" ::: "memory");
            __asm__ __volatile__("dsb" ::: "memory");
#endif
            {
                volatile uint32_t* const aircr = reinterpret_cast<volatile uint32_t*>(
                    reinterpret_cast<void*>(static_cast<uintptr_t>(AIRCR_ADDR)));
                *aircr = (AIRCR_VECTKEY | AIRCR_SYSRESETREQ);
            }
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("dsb" ::: "memory");
            __asm__ __volatile__("isb");
#endif
            while (true) {
#if defined(__GNUC__) || defined(__clang__)
                __asm__ __volatile__("wfi");
#endif
            }
#else
            volatile uint32_t hts_fatal_spin = 1u;
            while (hts_fatal_spin != 0u) {
#if defined(__GNUC__) || defined(__clang__)
                __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
                _ReadWriteBarrier();
#endif
            }
#endif
            return;
        }

        m_is_initialized.store(true, std::memory_order_release);
        m_init_spin.clear(std::memory_order_release);
    }

} // namespace ProtectedEngine
