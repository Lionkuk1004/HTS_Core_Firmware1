// =========================================================================
// HTS_PUF_Adapter.cpp
// PUF 하드웨어 시드 추출 어댑터 구현부
// Target: STM32F407 (Cortex-M4)
//
#include "HTS_PUF_Adapter.h"
#include <atomic>
#include <cstring>

// 플랫폼 감지
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#define HTS_PLATFORM_ARM
#endif

namespace ProtectedEngine {

    // PUF 출력 크기 (AES-256 호환 32바이트)
    static constexpr size_t PUF_KEY_SIZE = 32;

    // =====================================================================
    //  getHardwareSeed_Fixed — 고정 배열 API (ARM Zero-Heap)
    // =====================================================================
    bool PUF_Adapter::getHardwareSeed_Fixed(
        const uint8_t* challenge, size_t challenge_len,
        uint8_t* out_buf, size_t buf_size,
        size_t* out_len) noexcept {

        if (out_buf == nullptr || buf_size == 0u || out_len == nullptr) {
            return false;
        }
        *out_len = 0;

        // 인터페이스 교차 검증:
        // challenge는 nullptr 허용(무챌린지 모드)이나, 길이가 있으면 반드시 유효 포인터여야 함.
        if (challenge == nullptr && challenge_len != 0u) {
            std::memset(out_buf, 0, buf_size);
            std::atomic_thread_fence(std::memory_order_release);
            return false;
        }

        if (buf_size < PUF_KEY_SIZE) {
            std::memset(out_buf, 0, buf_size);
            std::atomic_thread_fence(std::memory_order_release);
            return false;
        }

        std::atomic_thread_fence(std::memory_order_acquire);

#if defined(HTS_PLATFORM_ARM)
        // ARM 양산: PUF 하드웨어 레지스터 직접 읽기
        // J-3: RNG 레지스터 주소 constexpr (STM32F407)
        static constexpr uintptr_t ADDR_PUF_CTRL = 0x50060800u;    ///< RNG_CR
        static constexpr uintptr_t ADDR_PUF_STATUS = 0x50060804u;  ///< RNG_SR
        static constexpr uintptr_t ADDR_PUF_DATA = 0x50060808u;    ///< RNG_DR
        volatile uint32_t* PUF_CTRL =
            reinterpret_cast<volatile uint32_t*>(ADDR_PUF_CTRL);
        volatile uint32_t* PUF_DATA =
            reinterpret_cast<volatile uint32_t*>(ADDR_PUF_DATA);
        volatile uint32_t* PUF_STATUS =
            reinterpret_cast<volatile uint32_t*>(ADDR_PUF_STATUS);

        if (challenge != nullptr && challenge_len >= 4u) {
            *PUF_CTRL = (static_cast<uint32_t>(challenge[0]) << 24u)
                | (static_cast<uint32_t>(challenge[1]) << 16u)
                | (static_cast<uint32_t>(challenge[2]) << 8u)
                | static_cast<uint32_t>(challenge[3]);
        }
        else {
            *PUF_CTRL = 0x01u;
        }

        static constexpr uint32_t PUF_POLL_TIMEOUT = 10000u;

        for (size_t i = 0; i < PUF_KEY_SIZE; i += 4u) {
            bool puf_ready = false;
            for (volatile uint32_t wait = 0u; wait < PUF_POLL_TIMEOUT; ++wait) {
                if (((*PUF_STATUS) & 0x01u) != 0u) {
                    puf_ready = true;
                    break;
                }
            }
            if (!puf_ready) {
                // 워드 단위 DRDY 미충족 — 부분 시드 잔류 차단
                std::memset(out_buf, 0, buf_size);
                std::atomic_thread_fence(std::memory_order_release);
                return false;
            }
            const uint32_t word = *PUF_DATA;
            out_buf[i + 0u] = static_cast<uint8_t>((word >> 24u) & 0xFFu);
            out_buf[i + 1u] = static_cast<uint8_t>((word >> 16u) & 0xFFu);
            out_buf[i + 2u] = static_cast<uint8_t>((word >> 8u) & 0xFFu);
            out_buf[i + 3u] = static_cast<uint8_t>(word & 0xFFu);
        }
#elif defined(__aarch64__)
        // 통합콘솔 (A55 Linux): 목업 (PUF는 STM32 측 하드웨어)
        (void)challenge; (void)challenge_len;
        static constexpr uint8_t console_mock[PUF_KEY_SIZE] = {
            0x1F, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x80,
            0x91, 0xA2, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7, 0x08,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
        };
        std::memcpy(out_buf, console_mock, PUF_KEY_SIZE);
#else
        // PC 개발빌드 (MSVC x86): 동일 목업
        (void)challenge; (void)challenge_len;
        static constexpr uint8_t pc_mock[PUF_KEY_SIZE] = {
            0x1F, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x80,
            0x91, 0xA2, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7, 0x08,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
        };
        std::memcpy(out_buf, pc_mock, PUF_KEY_SIZE);
#endif

        * out_len = PUF_KEY_SIZE;
        std::atomic_thread_fence(std::memory_order_release);
        return true;
    }

} // namespace ProtectedEngine
