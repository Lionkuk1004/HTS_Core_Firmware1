/// @file  HTS_Power_Manager.cpp
/// @brief HTS Power Manager -- IoT Low-Power Sleep Management Implementation
/// @note  ARM only. Pure ASCII. No PC/server code.
/// @author Lim Young-jun
/// @copyright INNOViD 2026. All rights reserved.
//
//  B-CDMA 검수 요약 (본 TU)
//   ① LTO/TBAA: Pimpl 버퍼는 uint8_t[] + placement Impl; 소거는 SecureMemory::secureWipe 단일화(D-2).
//   ② ISR: PRIMASK는 HAL disable_irq/enable_irq 쌍으로 캡슐화; 구간 길이는 HAL·on_pre_sleep 구현에 의존 [요검토].
//      Handle_PVD_Event는 ISR 경로 — 콜백은 최소 유지 권장.
//   ③ Flash/BOR: 본 모듈은 Flash 프로그램 없음. STOP 복귀·클럭은 HAL. BOR/전원 붕괴는 보드·PVD 정책.
//   ④ RDP/퓨즈: HTS_Hardware_Init::Initialize_System 부트 검사; 본 파일에서는 미수행.

#include "HTS_Power_Manager.h"
#include "HTS_Hardware_Init.h"
#include "HTS_Secure_Memory.h"
#include <new>
#include <atomic>

namespace ProtectedEngine {

    namespace {
        /// HAL disable_irq/enable_irq 쌍 — 조기 return·예외 경로에서도 enable 보장 (Lost Wakeup 방지 패턴)
        struct Power_Hal_Irq_Pair_Guard {
            const Power_HAL_Callbacks& hal_;
            explicit Power_Hal_Irq_Pair_Guard(const Power_HAL_Callbacks& h) noexcept
                : hal_(h)
            {
                if (hal_.disable_irq != nullptr) {
                    hal_.disable_irq();
                }
            }
            ~Power_Hal_Irq_Pair_Guard() noexcept
            {
                if (hal_.enable_irq != nullptr) {
                    hal_.enable_irq();
                }
            }
            Power_Hal_Irq_Pair_Guard(const Power_Hal_Irq_Pair_Guard&) = delete;
            Power_Hal_Irq_Pair_Guard& operator=(const Power_Hal_Irq_Pair_Guard&) = delete;
        };
    } // namespace

    // 공개 API / Shutdown 교차 시 UAF 방지 — 스핀락 (ISR은 Handle_PVD_Event에서 별도 논블로킹)
    struct Power_Busy_Guard {
        std::atomic_flag& f;
        explicit Power_Busy_Guard(std::atomic_flag& flag) noexcept
            : f(flag)
        {
            while (f.test_and_set(std::memory_order_acquire)) {
                // spin — Request_Sleep·Shutdown 교차 시 완료까지 대기
            }
        }
        ~Power_Busy_Guard() noexcept
        {
            f.clear(std::memory_order_release);
        }
        Power_Busy_Guard(const Power_Busy_Guard&) = delete;
        Power_Busy_Guard& operator=(const Power_Busy_Guard&) = delete;
    };

    // ============================================================
    //  Impl Structure
    // ============================================================

    struct HTS_Power_Manager::Impl {
        // --- HAL Callbacks ---
        Power_HAL_Callbacks    hal_cb;
        Power_Notify_Callbacks notify_cb;

        // --- CFI State ---
        PowerState state;
        uint8_t    cfi_violation_count;
        uint8_t    pad_[2];

        // --- Current Configuration ---
        PowerMode current_mode;
        PVD_Level pvd_level;
        uint16_t  last_wake_source;
        uint32_t  active_clock_mask;

        // --- Statistics ---
        uint32_t sleep_count;
        uint16_t last_battery_mv;
        uint16_t pad2_;

        // ============================================================
        //  CFI Transition
        // ============================================================
        bool Transition_State(PowerState target) noexcept
        {
            if (!Power_Is_Legal_Transition(state, target)) {
                if (Power_Is_Legal_Transition(state, PowerState::ERROR)) {
                    state = PowerState::ERROR;
                }
                else {
                    state = PowerState::UNINITIALIZED;
                }
                cfi_violation_count++;
                return false;
            }
            state = target;
            return true;
        }

        // ============================================================
        //  Execute Sleep Sequence
        // ============================================================
        bool Execute_Sleep(PowerMode mode, uint32_t wakeup_sec) noexcept
        {
            // Validate mode range
            const uint8_t mi = static_cast<uint8_t>(mode);
            if (mi < static_cast<uint8_t>(PowerMode::SLEEP) ||
                mi > static_cast<uint8_t>(PowerMode::STANDBY))
            {
                return false;
            }

            // CFI: ACTIVE -> SLEEPING
            if (!Transition_State(PowerState::SLEEPING)) { return false; }

            // IRQ masking pair must be consistent.
            // If disable only is provided, CPU can remain masked -> ISR deadlock.
            const bool has_disable = (hal_cb.disable_irq != nullptr);
            const bool has_enable = (hal_cb.enable_irq != nullptr);
            if (has_disable != has_enable) {
                Transition_State(PowerState::ERROR);
                return false;
            }

            // Pre-sleep notification (external modules save state)
            if (notify_cb.on_pre_sleep != nullptr) {
                notify_cb.on_pre_sleep(mode);
            }

            // [H-4] 저전력 진입 직전 WDT 킥 — 슬립 구성·클럭 게이팅 지연 중 타임아웃 방지
            Hardware_Init_Manager::Kick_Watchdog();

            // Configure RTC wakeup if requested
            if (wakeup_sec > 0u && hal_cb.configure_rtc_wakeup != nullptr) {
                hal_cb.configure_rtc_wakeup(wakeup_sec);
            }

            // Apply clock gating for target mode
            const PowerPreset& preset =
                k_power_presets[static_cast<size_t>(mi)];
            if (hal_cb.set_clock_gates != nullptr) {
                hal_cb.set_clock_gates(preset.clock_gate_mask);
            }
            active_clock_mask = preset.clock_gate_mask;

            // Enter low-power mode
            // ============================================================
            //  CRITICAL: Lost Wakeup Prevention (PRIMASK atomic pattern)
            // ============================================================
            //  Race condition without PRIMASK:
            //
            //    on_pre_sleep()          <-- external modules save state
            //    configure_rtc_wakeup()  <-- RTC armed
            //    set_clock_gates()       <-- clocks gated
            //       *** INTERRUPT FIRES HERE (sensor GPIO, timer, etc.) ***
            //       *** ISR executes, clears pending flag ***
            //    enter_sleep_wfi()       <-- WFI executes, but wakeup already consumed!
            //       *** DEADLOCK: CPU sleeps forever waiting for next IRQ ***
            //
            //  Fix: ARM Cortex-M PRIMASK pattern
            //    1. __disable_irq()       PRIMASK=1: mask all configurable interrupts
            //    2. Check NVIC pending    If IRQ already fired, skip WFI
            //    3. __WFI()               Still wakes on pending IRQ (ARM guarantee),
            //                             but ISR won't execute until PRIMASK cleared
            //    4. __enable_irq()        PRIMASK=0: pending ISR executes immediately
            //
            //  Key ARM guarantee: WFI wakes on ANY pending interrupt regardless
            //  of PRIMASK state. The interrupt just stays pending until unmasked.
            // ============================================================

            bool woke_ok = false;
            switch (mode) {
            case PowerMode::SLEEP:
                if (hal_cb.enter_sleep_wfi != nullptr) {
                    // Atomic sleep entry: disable IRQ -> check pending -> WFI -> enable IRQ (RAII)
                    {
                        Power_Hal_Irq_Pair_Guard irq_scope(hal_cb);
                        bool skip_wfi = false;
                        if (hal_cb.is_interrupt_pending != nullptr) {
                            skip_wfi = hal_cb.is_interrupt_pending();
                        }
                        if (!skip_wfi) {
                            hal_cb.enter_sleep_wfi();
                            // CPU wakes here. IRQ is pending but masked until scope exit.
                        }
                    }
                    woke_ok = true;
                }
                break;

            case PowerMode::STOP:
                if (hal_cb.enter_stop_mode != nullptr) {
                    {
                        Power_Hal_Irq_Pair_Guard irq_scope(hal_cb);
                        bool skip_stop = false;
                        if (hal_cb.is_interrupt_pending != nullptr) {
                            skip_stop = hal_cb.is_interrupt_pending();
                        }
                        if (!skip_stop) {
                            hal_cb.enter_stop_mode();
                            if (hal_cb.restore_clocks_from_stop != nullptr) {
                                hal_cb.restore_clocks_from_stop();
                            }
                        }
                    }
                    woke_ok = true;
                }
                break;

            case PowerMode::STANDBY:
                if (hal_cb.enter_standby_mode != nullptr) {
                    // STANDBY: no PRIMASK needed (system resets on wakeup,
                    // no race condition possible -- any pending IRQ prevents
                    // STANDBY entry per ARM spec)
                    hal_cb.enter_standby_mode();
                    // [[noreturn]] -- should never reach here
                }
                // Fallthrough: STANDBY entry failed
                Transition_State(PowerState::ERROR);
                return false;

            default:
                Transition_State(PowerState::ERROR);
                return false;
            }

            if (!woke_ok) {
                Transition_State(PowerState::ERROR);
                return false;
            }

            // --- Post-wakeup recovery ---
            // CFI: SLEEPING -> WAKING
            if (!Transition_State(PowerState::WAKING)) { return false; }

            // Read wakeup source
            if (hal_cb.get_wake_source != nullptr) {
                last_wake_source = hal_cb.get_wake_source();
            }

            // Restore full clock tree for RUN mode
            if (hal_cb.set_clock_gates != nullptr) {
                hal_cb.set_clock_gates(ClockGate::ALL);
            }
            active_clock_mask = ClockGate::ALL;

            if (hal_cb.set_cpu_clock != nullptr) {
                hal_cb.set_cpu_clock(168u);
            }
            current_mode = PowerMode::RUN;

            // Read battery voltage
            if (hal_cb.get_battery_mv != nullptr) {
                last_battery_mv = hal_cb.get_battery_mv();
            }

            // Post-wake notification (external modules restore state)
            if (notify_cb.on_post_wake != nullptr) {
                notify_cb.on_post_wake(mode, last_wake_source);
            }

            sleep_count++;

            // CFI: WAKING -> ACTIVE
            Transition_State(PowerState::ACTIVE);
            return true;
        }

        // ============================================================
        //  Clock Mode Switch (RUN <-> LOW_RUN)
        // ============================================================
        bool Execute_Clock_Switch(PowerMode mode) noexcept
        {
            if (static_cast<uint8_t>(mode) > static_cast<uint8_t>(PowerMode::LOW_RUN)) {
                return false;  // Only RUN/LOW_RUN allowed here
            }

            const PowerPreset& preset = k_power_presets[static_cast<size_t>(
                static_cast<uint8_t>(mode))];

            if (hal_cb.set_cpu_clock != nullptr) {
                hal_cb.set_cpu_clock(preset.cpu_freq_mhz);
            }
            if (hal_cb.set_clock_gates != nullptr) {
                hal_cb.set_clock_gates(preset.clock_gate_mask);
            }
            active_clock_mask = preset.clock_gate_mask;
            current_mode = mode;
            return true;
        }
    };

    // ============================================================
    //  Public API
    // ============================================================

    HTS_Power_Manager::HTS_Power_Manager() noexcept
        : initialized_{ false }
    {
        // B-CDMA ⑧/M-20: Impl 정의 이후·완전 형식에서만 alignof 적법 (클래스 본문 안 alignof(Impl)는 C2027)
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "HTS_Power_Manager::Impl exceeds IMPL_BUF_SIZE");
        static_assert(alignof(Impl) <= 8u,
            "HTS_Power_Manager::Impl alignment exceeds alignas(8) impl_buf_ — raise alignas in .h");

        for (uint32_t i = 0u; i < IMPL_BUF_SIZE; ++i) {
            impl_buf_[i] = 0u;
        }
    }

    HTS_Power_Manager::~HTS_Power_Manager() noexcept
    {
        Shutdown();
    }

    bool HTS_Power_Manager::Initialize() noexcept
    {
        Power_Busy_Guard guard(op_busy_);
        bool expected = false;
        if (!initialized_.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel))
        {
            return true;  // Already initialized
        }

        Impl* impl = ::new (static_cast<void*>(impl_buf_)) Impl{};

        impl->state = PowerState::UNINITIALIZED;
        impl->cfi_violation_count = 0u;
        impl->current_mode = PowerMode::RUN;
        impl->pvd_level = PVD_Level::V_2_5;
        impl->last_wake_source = 0u;
        impl->active_clock_mask = ClockGate::ALL;
        impl->sleep_count = 0u;
        impl->last_battery_mv = 0u;

        // Zero HAL callbacks
        impl->hal_cb.set_cpu_clock = nullptr;
        impl->hal_cb.set_clock_gates = nullptr;
        impl->hal_cb.enter_sleep_wfi = nullptr;
        impl->hal_cb.enter_stop_mode = nullptr;
        impl->hal_cb.enter_standby_mode = nullptr;
        impl->hal_cb.restore_clocks_from_stop = nullptr;
        impl->hal_cb.configure_pvd = nullptr;
        impl->hal_cb.configure_rtc_wakeup = nullptr;
        impl->hal_cb.get_battery_mv = nullptr;
        impl->hal_cb.get_wake_source = nullptr;
        impl->hal_cb.disable_irq = nullptr;
        impl->hal_cb.enable_irq = nullptr;
        impl->hal_cb.is_interrupt_pending = nullptr;

        impl->notify_cb.on_pre_sleep = nullptr;
        impl->notify_cb.on_post_wake = nullptr;
        impl->notify_cb.on_pvd_warning = nullptr;

        // CFI: UNINITIALIZED -> ACTIVE
        impl->Transition_State(PowerState::ACTIVE);
        return true;
    }

    void HTS_Power_Manager::Shutdown() noexcept
    {
        Power_Busy_Guard guard(op_busy_);
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        impl->state = PowerState::UNINITIALIZED;
        impl->~Impl();

        SecureMemory::secureWipe(static_cast<void*>(impl_buf_), IMPL_BUF_SIZE);

        initialized_.store(false, std::memory_order_release);
    }

    void HTS_Power_Manager::Register_HAL_Callbacks(const Power_HAL_Callbacks& cb) noexcept
    {
        Power_Busy_Guard guard(op_busy_);
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        std::launder(reinterpret_cast<Impl*>(impl_buf_))->hal_cb = cb;
    }

    void HTS_Power_Manager::Register_Notify_Callbacks(const Power_Notify_Callbacks& cb) noexcept
    {
        Power_Busy_Guard guard(op_busy_);
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        std::launder(reinterpret_cast<Impl*>(impl_buf_))->notify_cb = cb;
    }

    bool HTS_Power_Manager::Request_Sleep(PowerMode mode, uint32_t wakeup_sec) noexcept
    {
        Power_Busy_Guard guard(op_busy_);
        if (!initialized_.load(std::memory_order_acquire)) { return false; }
        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));

        // Must be ACTIVE to enter sleep
        if ((static_cast<uint8_t>(impl->state) &
            static_cast<uint8_t>(PowerState::ACTIVE)) == 0u)
        {
            return false;
        }

        return impl->Execute_Sleep(mode, wakeup_sec);
    }

    bool HTS_Power_Manager::Set_Clock_Mode(PowerMode mode) noexcept
    {
        Power_Busy_Guard guard(op_busy_);
        if (!initialized_.load(std::memory_order_acquire)) { return false; }
        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));

        // Must be ACTIVE
        if ((static_cast<uint8_t>(impl->state) &
            static_cast<uint8_t>(PowerState::ACTIVE)) == 0u)
        {
            return false;
        }

        // Idempotency: already in target mode -> no-op
        if (static_cast<uint8_t>(impl->current_mode) == static_cast<uint8_t>(mode)) {
            return true;
        }

        // PVD V_2_3 이하: RUN <-> LOW_RUN 클럭 전환 거부(동일 모드는 위에서 이미 허용)
        {
            const uint8_t pl = static_cast<uint8_t>(impl->pvd_level);
            if (pl <= static_cast<uint8_t>(PVD_Level::V_2_3)) {
                return false;
            }
        }

        return impl->Execute_Clock_Switch(mode);
    }

    void HTS_Power_Manager::Set_PVD_Level(PVD_Level level) noexcept
    {
        Power_Busy_Guard guard(op_busy_);
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        impl->pvd_level = level;
        if (impl->hal_cb.configure_pvd != nullptr) {
            impl->hal_cb.configure_pvd(static_cast<uint8_t>(level));
        }
    }

    void HTS_Power_Manager::Handle_PVD_Event() noexcept
    {
        // ISR: 스핀 금지 — 락이 잡혀 있으면 이번 샘플 생략(논블로킹)
        if (!initialized_.load(std::memory_order_relaxed)) { return; }
        if (op_busy_.test_and_set(std::memory_order_acquire)) {
            return;
        }
        struct Pvd_Isr_Unlock {
            std::atomic_flag& fl;
            ~Pvd_Isr_Unlock() noexcept
            {
                fl.clear(std::memory_order_release);
            }
        } unlock{op_busy_};

        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        if (impl->hal_cb.get_battery_mv != nullptr) {
            impl->last_battery_mv = impl->hal_cb.get_battery_mv();
        }
        if (impl->notify_cb.on_pvd_warning != nullptr) {
            impl->notify_cb.on_pvd_warning(impl->last_battery_mv);
        }
    }

    void HTS_Power_Manager::Set_Peripheral_Clocks(uint32_t enable_mask) noexcept
    {
        Power_Busy_Guard guard(op_busy_);
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));

        // Mask to valid bits only
        const uint32_t safe_mask = enable_mask & ClockGate::ALL;
        if (impl->hal_cb.set_clock_gates != nullptr) {
            impl->hal_cb.set_clock_gates(safe_mask);
        }
        impl->active_clock_mask = safe_mask;
    }

    PowerState HTS_Power_Manager::Get_State() const noexcept
    {
        Power_Busy_Guard guard(op_busy_);
        if (!initialized_.load(std::memory_order_acquire)) { return PowerState::UNINITIALIZED; }
        return reinterpret_cast<const Impl*>(impl_buf_)->state;
    }

    PowerMode HTS_Power_Manager::Get_Current_Mode() const noexcept
    {
        Power_Busy_Guard guard(op_busy_);
        if (!initialized_.load(std::memory_order_acquire)) { return PowerMode::RUN; }
        return reinterpret_cast<const Impl*>(impl_buf_)->current_mode;
    }

    uint16_t HTS_Power_Manager::Get_Battery_MV() const noexcept
    {
        Power_Busy_Guard guard(op_busy_);
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        return reinterpret_cast<const Impl*>(impl_buf_)->last_battery_mv;
    }

    uint16_t HTS_Power_Manager::Get_Last_Wake_Source() const noexcept
    {
        Power_Busy_Guard guard(op_busy_);
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        return reinterpret_cast<const Impl*>(impl_buf_)->last_wake_source;
    }

    uint32_t HTS_Power_Manager::Get_Sleep_Count() const noexcept
    {
        Power_Busy_Guard guard(op_busy_);
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        return reinterpret_cast<const Impl*>(impl_buf_)->sleep_count;
    }

} // namespace ProtectedEngine
