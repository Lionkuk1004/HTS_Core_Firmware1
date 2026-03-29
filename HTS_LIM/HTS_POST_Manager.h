// =========================================================================
// HTS_POST_Manager.h
// FIPS 140-3 Power-On Self-Test (POST) - KAT Validation Manager
// Target: STM32F407 (Cortex-M4)
//
// [Revision - 10 fixes]
//  01~05: iostream removal, namespace, while barrier, noexcept
//  06~10: Self_Healing sig, dead code, vector->fixed array,
//         try-catch removal, magic numbers, Doxygen, delete 6
// =========================================================================
#pragma once

#include <cstdint>

namespace ProtectedEngine {

    class POST_Manager {
    private:
        // [BUG-12] isOperational -> cpp 파일 스코프 atomic<bool>
        // (헤더에서 제거 — ISR/스레드 가시성을 위해 atomic 사용)

        static bool KAT_Parity_Recovery_Engine() noexcept;
        static bool KAT_Gravity_Interpolation_Engine() noexcept;

    public:
        static void executePowerOnSelfTest() noexcept;
        static void verifyOperationalState() noexcept;

        POST_Manager() = delete;
        ~POST_Manager() = delete;
        POST_Manager(const POST_Manager&) = delete;
        POST_Manager& operator=(const POST_Manager&) = delete;
        POST_Manager(POST_Manager&&) = delete;
        POST_Manager& operator=(POST_Manager&&) = delete;
    };

} // namespace ProtectedEngine