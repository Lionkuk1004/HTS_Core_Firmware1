// =========================================================================
// HTS_Secure_Logger.cpp
// 보안 감사 로거 구현부 — ARM 전용, 힙 할당 0회
// Target: STM32F407 (Cortex-M4)
//
// [양산 수정 — 12건]
//  FIX-01~03, BUG-01~08: (이전 이력 참조)
//  BUG-09 [CRIT] D-2: 스택 버퍼(buf, crc_buf) 3중 방어 소거
//  BUG-10 [LOW]  Target "/ Windows / Linux" 제거
//  BUG-11 [CRIT] std::string/std::vector → const char* (B-1 힙금지 준수)
//  BUG-12 [CRIT] PC 코드 물리삭제: iostream/Log_PC/3단분기/BAREMETAL 매크로
//
// [제약] try-catch 0, float/double 0, 힙 0, std::string 0, std::vector 0
// =========================================================================
#include "HTS_Secure_Logger.h"
#include "HTS_Crc32Util.h"
#include "HTS_Hardware_Bridge.hpp"

#include <atomic>
#include <cstdio>
#include <cstring>

namespace ProtectedEngine {

    // =====================================================================
    //  [BUG-09] D-2 스택 소거 헬퍼 — 3중 방어
    //  volatile + asm clobber + release fence
    // =====================================================================
    static void Wipe_Stack_Buffer(void* ptr, size_t size) noexcept {
        if (!ptr || size == 0) return;
        volatile unsigned char* p =
            static_cast<volatile unsigned char*>(ptr);
        for (size_t i = 0; i < size; ++i) p[i] = 0;
#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__ARM_ARCH))
        __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  CRC32 로그 무결성 지문
    // =====================================================================
    static uint32_t Compute_Log_CRC(
        const char* data, size_t len) noexcept {
        if (!data || len == 0) return 0;
        return Crc32Util::calculate(
            reinterpret_cast<const uint8_t*>(data), len);
    }

    // =====================================================================
    //  logSecurityEvent — ARM 전용 (UART 스텁 출력)
    //
    //  [BUG-11] const char* 파라미터 — std::string 힙 할당 원천 제거
    //  [BUG-09] 함수 반환 전 buf + crc_buf 3중 방어 소거
    // =====================================================================
    void SecureLogger::logSecurityEvent(
        const char* eventType,
        const char* details) noexcept {

        if (!eventType) eventType = "UNKNOWN";
        if (!details)   details = "";

        const uint32_t tick = static_cast<uint32_t>(
            Hardware_Bridge::Get_Physical_CPU_Tick() & 0xFFFFFFFFu);

        // CRC 결합 버퍼
        char crc_buf[256];
        const int crc_len = snprintf(crc_buf, sizeof(crc_buf),
            "%s|%s", eventType, details);
        const size_t safe_crc_len =
            (crc_len < 0) ? 0u :
            (static_cast<size_t>(crc_len) >= sizeof(crc_buf))
            ? sizeof(crc_buf) - 1u
            : static_cast<size_t>(crc_len);

        const uint32_t logCrc = Compute_Log_CRC(crc_buf, safe_crc_len);

        // 출력 버퍼
        char buf[256];
        const int written = snprintf(buf, sizeof(buf),
            "[AUDIT@%08lX] %s | %s | CRC:0x%08lX\n",
            static_cast<unsigned long>(tick),
            eventType,
            details,
            static_cast<unsigned long>(logCrc));

        if (written > 0) {
            const size_t out_len =
                (static_cast<size_t>(written) >= sizeof(buf))
                ? sizeof(buf) - 1u
                : static_cast<size_t>(written);
            buf[out_len] = '\0';

            const char* p = buf;
            while (*p) {
                fputc(*p, stdout);
                ++p;
            }
        }

        // [BUG-09] D-2: 스택 버퍼 3중 방어 소거
        Wipe_Stack_Buffer(buf, sizeof(buf));
        Wipe_Stack_Buffer(crc_buf, sizeof(crc_buf));
    }

} // namespace ProtectedEngine