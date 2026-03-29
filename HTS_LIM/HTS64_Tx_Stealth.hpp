// =========================================================================
/// @file  HTS64_Tx_Stealth.hpp
/// @brief 64-ary Stealth TX Engine — paired with ECCM_Core(Rx)
/// @target STM32F407 (Cortex-M4, 168MHz) / PC
///
///  [Revision — 17 fixes]
///  BUG-01~15 (previous sessions)
///  BUG-16 [HIGH] comment correction
///  BUG-17 [CRIT] unique_ptr -> placement new (zero-heap)
// =========================================================================
#pragma once
#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    class HTS64_Tx_Stealth_Engine {
    public:
        struct TxMaryData {
            uint32_t chip_HI;
            uint32_t chip_LO;
        };

        explicit HTS64_Tx_Stealth_Engine(uint32_t master_seed) noexcept;
        ~HTS64_Tx_Stealth_Engine() noexcept;

        HTS64_Tx_Stealth_Engine(const HTS64_Tx_Stealth_Engine&) = delete;
        HTS64_Tx_Stealth_Engine& operator=(const HTS64_Tx_Stealth_Engine&) = delete;
        HTS64_Tx_Stealth_Engine(HTS64_Tx_Stealth_Engine&&) = delete;
        HTS64_Tx_Stealth_Engine& operator=(HTS64_Tx_Stealth_Engine&&) = delete;

        void Reseed(uint32_t epoch_seed) noexcept;

        [[nodiscard]]
        TxMaryData Encode_64Ary_With_Tensor(uint8_t input_6bit) noexcept;

    private:
        // [BUG-17] Pimpl In-Place: zero-heap
        // Impl: atomic<uint32_t>(4B) + padding ≈ 8B
        static constexpr size_t IMPL_BUF_SIZE = 64u;
        struct Impl;
        alignas(8) uint8_t impl_buf_[IMPL_BUF_SIZE];
        bool impl_valid_ = false;

        Impl* get_impl() noexcept;
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine