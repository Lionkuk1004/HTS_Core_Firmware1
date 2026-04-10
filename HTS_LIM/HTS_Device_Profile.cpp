/// @file  HTS_Device_Profile.cpp
/// @brief HTS Device Profile Engine -- STM32 Implementation
/// @note  ARM only. Pure ASCII. No PC/server code.
/// @author Lim Young-jun
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_Device_Profile.h"
#include "HTS_Console_Manager.h"
#include <new>
#include <atomic>

namespace ProtectedEngine {
    static constexpr uint32_t PROFILE_INIT_NONE = 0u;
    static constexpr uint32_t PROFILE_INIT_BUSY = 1u;
    static constexpr uint32_t PROFILE_INIT_READY = 2u;

    static void Profile_Secure_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) { q[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // ============================================================
    //  Impl Structure
    // ============================================================

    struct HTS_Device_Profile::Impl {
        // --- Dependencies ---
        HTS_Console_Manager* console;

        // --- State ---
        std::atomic<ProfileState> state{ ProfileState::UNCONFIGURED };
        DeviceMode    current_mode;
        uint8_t       active_periph_mask;
        uint8_t       cfi_violation_count;  ///< CFI violation counter (security audit)

        // --- Current Preset Cache ---
        DevicePreset  current_preset;

        // --- Peripheral Callbacks ---
        PeriphCallbacks periph_cb;

        // ============================================================
        //  CFI State Transition (validated)
        // ============================================================

        /// @brief CFI-validated state transition
        /// @param target  Target state
        /// @return true if transition succeeded
        /// @note  On illegal transition: state forced to ERROR, counter incremented.
        ///        Attack scenario blocked:
        ///          ERROR -> ACTIVE (must go through SWITCHING)
        ///          SWITCHING -> ACTIVE via glitch (must complete Execute_Switch)
        bool Transition_State(ProfileState target) noexcept
        {
            const ProfileState current = state.load(std::memory_order_acquire);
            if (!Profile_Is_Legal_Transition(current, target)) {
                // Illegal transition detected -- force ERROR state
                // Do NOT blindly overwrite: verify ERROR is reachable from current
                if (Profile_Is_Legal_Transition(current, ProfileState::ERROR)) {
                    state.store(ProfileState::ERROR, std::memory_order_release);
                }
                // If even ERROR is unreachable (e.g., glitched state=0xFF),
                // force to UNCONFIGURED as absolute fallback
                else {
                    state.store(ProfileState::UNCONFIGURED, std::memory_order_release);
                }
                cfi_violation_count++;
                return false;
            }
            state.store(target, std::memory_order_release);
            return true;
        }

        // ============================================================
        //  Apply Peripheral Enable/Disable from Bitmask
        // ============================================================
        void Apply_Periph_Mask(uint8_t new_mask) noexcept
        {
            // XOR detects changed bits; iterate only changed peripherals.
            // Cortex-M4: 8 conditional calls max, each bounded.
            // ASIC: 8-bit XOR -> 8 enable lines, 1-cycle combinational.
            const uint8_t changed = active_periph_mask ^ new_mask;

            if ((changed & PeriphBit::UART_SENSOR) != 0u) {
                if (periph_cb.enable_uart_sensor != nullptr) {
                    periph_cb.enable_uart_sensor((new_mask & PeriphBit::UART_SENSOR) != 0u);
                }
            }
            if ((changed & PeriphBit::SPI_RF) != 0u) {
                if (periph_cb.enable_spi_rf != nullptr) {
                    periph_cb.enable_spi_rf((new_mask & PeriphBit::SPI_RF) != 0u);
                }
            }
            if ((changed & PeriphBit::I2C_SENSOR) != 0u) {
                if (periph_cb.enable_i2c_sensor != nullptr) {
                    periph_cb.enable_i2c_sensor((new_mask & PeriphBit::I2C_SENSOR) != 0u);
                }
            }
            if ((changed & PeriphBit::BLE_NFC) != 0u) {
                if (periph_cb.enable_ble_nfc != nullptr) {
                    periph_cb.enable_ble_nfc((new_mask & PeriphBit::BLE_NFC) != 0u);
                }
            }
            if ((changed & PeriphBit::VOCODER) != 0u) {
                if (periph_cb.enable_vocoder != nullptr) {
                    periph_cb.enable_vocoder((new_mask & PeriphBit::VOCODER) != 0u);
                }
            }
            if ((changed & PeriphBit::ETHERNET) != 0u) {
                if (periph_cb.enable_ethernet != nullptr) {
                    periph_cb.enable_ethernet((new_mask & PeriphBit::ETHERNET) != 0u);
                }
            }
            if ((changed & PeriphBit::MODBUS) != 0u) {
                if (periph_cb.enable_modbus != nullptr) {
                    periph_cb.enable_modbus((new_mask & PeriphBit::MODBUS) != 0u);
                }
            }
            if ((changed & PeriphBit::CCTV_CAM) != 0u) {
                if (periph_cb.enable_cctv_cam != nullptr) {
                    periph_cb.enable_cctv_cam((new_mask & PeriphBit::CCTV_CAM) != 0u);
                }
            }

            active_periph_mask = new_mask;
        }

        // ============================================================
        //  Execute Mode Switch (CFI-protected)
        // ============================================================
        IPC_Error Execute_Switch(DeviceMode mode) noexcept
        {
            // --- Input validation: mode index bounds ---
            const uint8_t idx = static_cast<uint8_t>(mode);
            if (idx >= static_cast<uint8_t>(DeviceMode::MODE_COUNT)) {
                return IPC_Error::INVALID_CMD;
            }

            // --- CFI Gate 1: current state -> SWITCHING ---
            // Legal sources: UNCONFIGURED, ACTIVE, ERROR
            // Blocked: SWITCHING -> SWITCHING (re-entrancy)
            //          Glitched state (0xFF etc) -> caught by Transition_State
            if (!Transition_State(ProfileState::SWITCHING)) {
                return IPC_Error::CFI_VIOLATION;
            }

            // --- Load preset from constexpr ROM table ---
            current_preset = k_device_presets[idx];

            // --- Apply peripheral changes (delta-based) ---
            Apply_Periph_Mask(current_preset.periph_enable_mask);

            // --- Push channel config to Console Manager ---
            if (console != nullptr) {
                const IPC_Error err = console->Set_Channel_Config(current_preset.channel);
                if (err != IPC_Error::OK) {
                    // CFI Gate 2a: SWITCHING -> ERROR (transition failure)
                    Transition_State(ProfileState::ERROR);
                    return err;
                }
            }

            // --- CFI Gate 2b: SWITCHING -> ACTIVE (transition success) ---
            if (!Transition_State(ProfileState::ACTIVE)) {
                // Should never happen (SWITCHING->ACTIVE is legal),
                // but defend against bit-flip on 'state' variable during execution
                return IPC_Error::CFI_VIOLATION;
            }

            current_mode = mode;
            return IPC_Error::OK;
        }
    };

    // ============================================================
    //  Public API
    // ============================================================

    HTS_Device_Profile::HTS_Device_Profile() noexcept
        : init_state_{ PROFILE_INIT_NONE }
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "HTS_Device_Profile::Impl exceeds IMPL_BUF_SIZE");

        for (uint32_t i = 0u; i < IMPL_BUF_SIZE; ++i) {
            impl_buf_[i] = 0u;
        }
    }

    HTS_Device_Profile::~HTS_Device_Profile() noexcept
    {
        Shutdown();
    }

    IPC_Error HTS_Device_Profile::Initialize(HTS_Console_Manager* console) noexcept
    {
        uint32_t expected = PROFILE_INIT_NONE;
        if (!init_state_.compare_exchange_strong(
            expected, PROFILE_INIT_BUSY, std::memory_order_acq_rel))
        {
            return (expected == PROFILE_INIT_READY)
                ? IPC_Error::OK
                : IPC_Error::NOT_INITIALIZED;
        }

        if (console == nullptr) {
            init_state_.store(PROFILE_INIT_NONE, std::memory_order_release);
            return IPC_Error::NOT_INITIALIZED;
        }

        Impl* impl = new (impl_buf_) Impl{};

        impl->console = console;
        impl->state.store(ProfileState::UNCONFIGURED, std::memory_order_release);
        impl->current_mode = DeviceMode::SENSOR_GATEWAY;
        impl->active_periph_mask = 0u;
        impl->cfi_violation_count = 0u;
        impl->current_preset = k_device_presets[0];

        // Zero callbacks
        impl->periph_cb.enable_uart_sensor = nullptr;
        impl->periph_cb.enable_spi_rf = nullptr;
        impl->periph_cb.enable_i2c_sensor = nullptr;
        impl->periph_cb.enable_ble_nfc = nullptr;
        impl->periph_cb.enable_vocoder = nullptr;
        impl->periph_cb.enable_ethernet = nullptr;
        impl->periph_cb.enable_modbus = nullptr;
        impl->periph_cb.enable_cctv_cam = nullptr;

        init_state_.store(PROFILE_INIT_READY, std::memory_order_release);
        return IPC_Error::OK;
    }

    void HTS_Device_Profile::Shutdown() noexcept
    {
        if (init_state_.load(std::memory_order_acquire) != PROFILE_INIT_READY) { return; }

        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));

        // Disable all peripherals
        impl->Apply_Periph_Mask(0u);
        impl->state.store(ProfileState::UNCONFIGURED, std::memory_order_release);
        impl->console = nullptr;

        impl->~Impl();

        Profile_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);

        init_state_.store(PROFILE_INIT_NONE, std::memory_order_release);
    }

    void HTS_Device_Profile::Register_Periph_Callbacks(const PeriphCallbacks& cb) noexcept
    {
        if (init_state_.load(std::memory_order_acquire) != PROFILE_INIT_READY) { return; }
        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        impl->periph_cb = cb;
    }

    IPC_Error HTS_Device_Profile::Switch_Mode(DeviceMode mode) noexcept
    {
        if (init_state_.load(std::memory_order_acquire) != PROFILE_INIT_READY) {
            return IPC_Error::NOT_INITIALIZED;
        }
        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        return impl->Execute_Switch(mode);
    }

    DeviceMode HTS_Device_Profile::Get_Current_Mode() const noexcept
    {
        if (init_state_.load(std::memory_order_acquire) != PROFILE_INIT_READY) {
            return DeviceMode::SENSOR_GATEWAY;
        }
        const Impl* impl = std::launder(reinterpret_cast<const Impl*>(impl_buf_));
        return impl->current_mode;
    }

    void HTS_Device_Profile::Get_Current_Preset(DevicePreset& out_preset) const noexcept
    {
        if (init_state_.load(std::memory_order_acquire) != PROFILE_INIT_READY) {
            out_preset = k_device_presets[0];
            return;
        }
        const Impl* impl = std::launder(reinterpret_cast<const Impl*>(impl_buf_));
        out_preset = impl->current_preset;
    }

    bool HTS_Device_Profile::Get_Preset_For_Mode(DeviceMode mode, DevicePreset& out_preset) const noexcept
    {
        const uint8_t idx = static_cast<uint8_t>(mode);
        if (idx >= static_cast<uint8_t>(DeviceMode::MODE_COUNT)) {
            return false;
        }
        out_preset = k_device_presets[idx];
        return true;
    }

    ProfileState HTS_Device_Profile::Get_State() const noexcept
    {
        if (init_state_.load(std::memory_order_acquire) != PROFILE_INIT_READY) {
            return ProfileState::UNCONFIGURED;
        }
        const Impl* impl = std::launder(reinterpret_cast<const Impl*>(impl_buf_));
        return impl->state.load(std::memory_order_acquire);
    }

    uint8_t HTS_Device_Profile::Get_Active_Periph_Mask() const noexcept
    {
        if (init_state_.load(std::memory_order_acquire) != PROFILE_INIT_READY) { return 0u; }
        const Impl* impl = std::launder(reinterpret_cast<const Impl*>(impl_buf_));
        return impl->active_periph_mask;
    }

} // namespace ProtectedEngine


