// =========================================================================
// HTS_Secure_Logger.cpp
// 보안 감사 로거 구현부 — ARM 전용, 힙 할당 0회
// Target: STM32F407 (Cortex-M4)
//
#include "HTS_Secure_Logger.h"
#include "HTS_Crc32Util.h"
#include "HTS_Hardware_Bridge.hpp"
#include "HTS_Secure_Memory.h"

#include <atomic>
#include <cstring>

namespace ProtectedEngine {

    static char g_last_audit_line[256] = {};

    static size_t Append_Lit(char* dst, size_t cap, size_t pos, const char* s) noexcept {
        if (dst == nullptr || s == nullptr || cap == 0u) { return pos; }
        while (*s != '\0' && pos + 1u < cap) {
            dst[pos++] = *s++;
        }
        dst[pos] = '\0';
        return pos;
    }

    static size_t Append_Hex32(char* dst, size_t cap, size_t pos, uint32_t v) noexcept {
        static constexpr char k_hex[] = "0123456789ABCDEF";
        if (dst == nullptr || cap == 0u) { return pos; }
        for (int i = 7; i >= 0; --i) {
            if (pos + 1u >= cap) { break; }
            const uint8_t nib = static_cast<uint8_t>((v >> (static_cast<uint32_t>(i) * 4u)) & 0x0Fu);
            dst[pos++] = k_hex[nib];
        }
        dst[pos] = '\0';
        return pos;
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
    // =====================================================================
    void SecureLogger::logSecurityEvent(
        const char* eventType,
        const char* details) noexcept {

#ifdef HTS_MILITARY_GRADE_EW
        (void)eventType;
        (void)details;
        return;
#endif

        if (!eventType) eventType = "UNKNOWN";
        if (!details)   details = "";

        const uint32_t tick = static_cast<uint32_t>(
            Hardware_Bridge::Get_Physical_CPU_Tick() & 0xFFFFFFFFu);

        // CRC 결합 버퍼
        char crc_buf[256];
        size_t crc_pos = 0u;
        crc_pos = Append_Lit(crc_buf, sizeof(crc_buf), crc_pos, eventType);
        crc_pos = Append_Lit(crc_buf, sizeof(crc_buf), crc_pos, "|");
        crc_pos = Append_Lit(crc_buf, sizeof(crc_buf), crc_pos, details);

        const uint32_t logCrc = Compute_Log_CRC(crc_buf, crc_pos);

        // 출력 버퍼
        char buf[256];
        size_t pos = 0u;
        pos = Append_Lit(buf, sizeof(buf), pos, "[AUDIT@");
        pos = Append_Hex32(buf, sizeof(buf), pos, tick);
        pos = Append_Lit(buf, sizeof(buf), pos, "] ");
        pos = Append_Lit(buf, sizeof(buf), pos, eventType);
        pos = Append_Lit(buf, sizeof(buf), pos, " | ");
        pos = Append_Lit(buf, sizeof(buf), pos, details);
        pos = Append_Lit(buf, sizeof(buf), pos, " | CRC:0x");
        pos = Append_Hex32(buf, sizeof(buf), pos, logCrc);
        pos = Append_Lit(buf, sizeof(buf), pos, "\n");
        (void)pos;

        // 베어메탈 안전 경로: stdout/semihosting 대신 내부 고정 버퍼에 기록
        std::memcpy(g_last_audit_line, buf, sizeof(g_last_audit_line));

        SecureMemory::secureWipe(buf, sizeof(buf));
        SecureMemory::secureWipe(crc_buf, sizeof(crc_buf));
    }

} // namespace ProtectedEngine
