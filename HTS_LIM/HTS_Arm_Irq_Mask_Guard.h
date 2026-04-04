#pragma once
// =========================================================================
// HTS_Arm_Irq_Mask_Guard.h
// Cortex-M 단일코어: PRIMASK 저장 → IRQ 마스크 → 스코프 종료 또는 release() 시 복원
// STAGE 3: 수동 enter/exit 대신 RAII(조기 return·release로 기존 임계구간 길이 보존)
// Target: STM32F407 (Cortex-M4) 등 ARMv7-M / Thumb — AArch64·PC는 no-op
// =========================================================================
#include <cstdint>

namespace ProtectedEngine {

#if (defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
     defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)) && \
    !defined(__aarch64__)

class Armv7m_Irq_Mask_Guard {
    uint32_t saved_primask_;
    bool active_;

    static uint32_t enter_isr_mask() noexcept
    {
        uint32_t primask = 0u;
        __asm volatile ("MRS %0, PRIMASK\n CPSID I"
            : "=r"(primask) :: "memory");
        return primask;
    }

    static void restore_primask(uint32_t pm) noexcept
    {
        __asm volatile ("MSR PRIMASK, %0" :: "r"(pm) : "memory");
    }

public:
    Armv7m_Irq_Mask_Guard() noexcept
        : saved_primask_(enter_isr_mask())
        , active_(true)
    {
    }

    /// 기존 critical_exit(pm) 직전과 동일 시점에 IRQ 복원(이후 memcpy 등은 마스크 해제 후)
    void release() noexcept
    {
        if (!active_) {
            return;
        }
        restore_primask(saved_primask_);
        active_ = false;
    }

    ~Armv7m_Irq_Mask_Guard() noexcept
    {
        if (active_) {
            restore_primask(saved_primask_);
        }
    }

    Armv7m_Irq_Mask_Guard(const Armv7m_Irq_Mask_Guard&) = delete;
    Armv7m_Irq_Mask_Guard& operator=(const Armv7m_Irq_Mask_Guard&) = delete;
};

#else

class Armv7m_Irq_Mask_Guard {
public:
    Armv7m_Irq_Mask_Guard() noexcept = default;
    void release() noexcept {}
    ~Armv7m_Irq_Mask_Guard() noexcept = default;
};

#endif

} // namespace ProtectedEngine
