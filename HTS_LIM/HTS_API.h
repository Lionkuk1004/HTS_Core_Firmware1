// =========================================================================
// [하드웨어 보안 락] ARM Cortex-M 전용
// =========================================================================
#if !defined(__arm__) && !defined(__TARGET_ARCH_ARM) && !defined(STM32F407xx) && !defined(_MSC_VER)
#error "SECURITY: This firmware is licensed for Embedded ARM only."
#endif

// =========================================================================
/// @file  HTS_API.h
/// @brief 외부 파트너사 연동 API 인터페이스
/// @target STM32F407VGT6 (Cortex-M4F)
///
/// [양산 수정 이력 — 19건]
///  BUG-01~17 (이전 세션)
///  BUG-18 [HIGH] DCLP Fast-Path 추가 (CAS 병목 제거)
///  BUG-19 [CRIT] extern "C" + enum class ABI 불일치 → extern "C" 삭제
// =========================================================================
#pragma once
#include <cstdint>
#include <cstddef>

// ARM GCC/Clang 가시성 매크로
#if defined(__GNUC__) || defined(__clang__)
#define HTS_API_EXPORT __attribute__((visibility("default")))
#else
#define HTS_API_EXPORT
#endif

namespace HTS_API {

    enum class HTS_Status : uint32_t {
        OK = 0x00u,
        ERR_ALREADY_INITIALIZED = 0x01u,
        ERR_NULL_POINTER = 0x02u,
        ERR_POST_FAILED = 0x03u,
        ERR_BUFFER_UNDERFLOW = 0x04u,
        ERR_RECOVERY_FAILED = 0x05u,
        ERR_TAMPERED = 0x06u,
        ERR_NOT_INITIALIZED = 0x07u,
        ERR_UNSUPPORTED_MEDIUM = 0x08u
    };

    enum class HTS_CommMedium : uint32_t {
        B_CDMA_RAW_RF = 0x01u,
        DIGITAL_5G_LTE = 0x02u,
        WIRED_ETHERNET = 0x03u,
        SATELLITE_LINK = 0x04u
    };

    // [BUG-19] extern "C" 삭제: enum class는 C++ 전용 타입
    // C++ namespace 스코프 + HTS_API_EXPORT로 가시성 보장
    [[nodiscard]] HTS_API_EXPORT
        HTS_Status Initialize_Core(
            volatile uint32_t* hw_irq_status_reg,
            volatile uint32_t* hw_irq_clear_reg,
            volatile int16_t* hw_rx_fifo_addr,
            HTS_CommMedium     target_medium) noexcept;

    [[nodiscard]] HTS_API_EXPORT
        HTS_Status Fetch_And_Heal_Rx_Payload(
            uint32_t* out_buffer,
            size_t    required_size) noexcept;

    [[nodiscard]] HTS_API_EXPORT
        HTS_Status Is_System_Operational() noexcept;

} // namespace HTS_API