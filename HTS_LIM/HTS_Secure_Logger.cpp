// =========================================================================
// HTS_Secure_Logger.cpp
// 보안 감사 로거 구현부 — ARM 전용, 힙 할당 0회
// Target: STM32F407 (Cortex-M4)
//
#include "HTS_Secure_Logger.h"
#include "HTS_Anti_Debug.h"
#include "HTS_Crc32Util.h"
#include "HTS_Hardware_Bridge.hpp"
#include "HTS_Hardware_Init.h"
#include "HTS_Secure_Memory.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

extern "C" void HTS_AuditLog_SyncDrainLine(const char* line, size_t len) noexcept;

namespace {

constexpr size_t kAuditRingSlots = 16u;
/// 슬롯 상태: 0=Empty, 1=Writing(생산자 독점), 2=Ready(소비자 처리 가능)
constexpr uint8_t kAuditEmpty = 0u;
constexpr uint8_t kAuditWriting = 1u;
constexpr uint8_t kAuditReady = 2u;

static_assert((kAuditRingSlots & (kAuditRingSlots - 1u)) == 0u && kAuditRingSlots >= 1u,
    "kAuditRingSlots must be a power of two");

#if defined(__GNUC__) || defined(__clang__)
__attribute__((used))
#endif
alignas(4) static char g_audit_ring[kAuditRingSlots][256] = {};

std::atomic<uint8_t> g_audit_ready[kAuditRingSlots] = {};

std::atomic<uint32_t> g_audit_seq{0u};
std::atomic<uint32_t> g_audit_event_drop_count{0u};

/// 레이트 리밋: 단일 atomic<uint32_t>. enc==0 미기록. raw=(tick>>16)_16 | crc_16, 저장값= XOR(오버플로+1 회피).
std::atomic<uint32_t> s_audit_rate_packed{0u};

/// 접두+페이로드 상한 — 접미(| CRC:0x + 8 hex + \n 등) 여유
static constexpr size_t kAuditCrcPrefixCap = 220u;

/// tick>>16 단위 간격(~65536 CPU cycles ≈ 390µs @168MHz). 윈도우 25 ≈ 약 10ms.
static constexpr uint32_t kAuditRateWindowScaled = 25u;

static constexpr uint32_t kRateXorMask = 0x5A5A5A5Au;

static uint32_t MakeRateRaw(uint32_t crc32, uint32_t tick32) noexcept {
    const uint32_t tick_sc = (tick32 >> 16) & 0xFFFFu;
    const uint32_t c = crc32 & 0xFFFFu;
    return (tick_sc << 16) | c;
}

static uint32_t EncodeRateRaw(uint32_t raw) noexcept {
    if (raw == kRateXorMask) {
        return 0xFFFFFFFFu;
    }
    return raw ^ kRateXorMask;
}

static bool DecodeRateRaw(uint32_t enc, uint32_t& raw_out) noexcept {
    if (enc == 0u) {
        return false;
    }
    if (enc == 0xFFFFFFFFu) {
        raw_out = kRateXorMask;
        return true;
    }
    raw_out = enc ^ kRateXorMask;
    return true;
}

static void AuditRateCommit(uint32_t crc32, uint32_t tick32) noexcept {
    const uint32_t raw_new = MakeRateRaw(crc32, tick32);
    const uint32_t enc_new = EncodeRateRaw(raw_new);
    const uint16_t tick_sc_new = static_cast<uint16_t>((tick32 >> 16) & 0xFFFFu);

    uint32_t expected = s_audit_rate_packed.load(std::memory_order_relaxed);
    for (uint32_t spin = 0u; spin < 100000u; ++spin) {
        if (expected == 0u) {
            if (s_audit_rate_packed.compare_exchange_weak(
                    expected,
                    enc_new,
                    std::memory_order_release,
                    std::memory_order_relaxed)) {
                return;
            }
            continue;
        }
        uint32_t raw_old = 0u;
        (void)DecodeRateRaw(expected, raw_old);
        const uint16_t old_tick_sc = static_cast<uint16_t>((raw_old >> 16) & 0xFFFFu);
        const uint32_t fwd = static_cast<uint32_t>(
            static_cast<uint16_t>(tick_sc_new - old_tick_sc));
        if (fwd > 32767u) {
            return;
        }
        if (s_audit_rate_packed.compare_exchange_weak(
                expected,
                enc_new,
                std::memory_order_release,
                std::memory_order_relaxed)) {
            return;
        }
    }
    ProtectedEngine::Hardware_Init_Manager::Terminal_Fault_Action();
}

static void AuditDropReleaseBarrier(char* slot, size_t idx) noexcept {
    ProtectedEngine::SecureMemory::secureWipe(static_cast<void*>(slot), 256u);
    std::atomic_thread_fence(std::memory_order_release);
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
    g_audit_ready[idx].store(kAuditEmpty, std::memory_order_release);
}

static void FlushAuditRingForTrapImpl() noexcept {
#ifndef HTS_MILITARY_GRADE_EW
    for (size_t i = 0u; i < kAuditRingSlots; ++i) {
        if (g_audit_ready[i].load(std::memory_order_acquire) != kAuditReady) {
            continue;
        }
        const char* const slot = g_audit_ring[i];
        size_t len = 0u;
        while (len < 255u && slot[len] != '\0') {
            ++len;
        }
        HTS_AuditLog_SyncDrainLine(slot, len);
    }
    std::atomic_thread_fence(std::memory_order_release);
#endif
}

} // namespace

#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
extern "C" void HTS_AuditLog_SyncDrainLine(const char* line, size_t len) noexcept {
    (void)line;
    (void)len;
}

// 소거·자폭은 본 함수 단일 경로(내부 정적 복제 금지).
// LTO: noinline+used로 인라인 흡수·DCE 경로 축소, secureWipe 직후 컴파일러 배리어로 데드스토어 판정 방지.
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noreturn, noinline, used))
#elif defined(_MSC_VER)
__declspec(noreturn) __declspec(noinline)
#endif
extern "C" void SecureLogger_WipeRingAndFault(void) {
    ProtectedEngine::SecureMemory::secureWipe(
        static_cast<void*>(g_audit_ring), sizeof(g_audit_ring));
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
    ProtectedEngine::Hardware_Init_Manager::Terminal_Fault_Action();
}

extern "C" const char* SecureLogger_GetAuditRingBase(void) {
    return &g_audit_ring[0][0];
}

extern "C" size_t SecureLogger_GetAuditRingSlotCount(void) {
    return kAuditRingSlots;
}

extern "C" size_t SecureLogger_GetAuditLineBytes(void) {
    return 256u;
}

extern "C" uint32_t SecureLogger_GetAuditDropCount(void) {
    return g_audit_event_drop_count.load(std::memory_order_relaxed);
}

extern "C" uint8_t SecureLogger_GetAuditSlotReady(size_t slot_index) {
    if (slot_index >= kAuditRingSlots) {
        return 0u;
    }
    return g_audit_ready[slot_index].load(std::memory_order_acquire);
}

extern "C" void SecureLogger_ClearAuditSlotReady(size_t slot_index) {
    if (slot_index >= kAuditRingSlots) {
        return;
    }
    g_audit_ready[slot_index].store(0u, std::memory_order_release);
}

namespace ProtectedEngine {

static void Append_NullTerminate(char* dst, size_t cap, size_t pos) noexcept {
    if (dst == nullptr || cap == 0u) { return; }
    if (pos < cap) {
        dst[pos] = '\0';
    } else {
        dst[cap - 1u] = '\0';
    }
}

static size_t Append_Lit(char* dst, size_t cap, size_t pos, const char* s) noexcept {
    if (dst == nullptr || s == nullptr || cap == 0u) { return pos; }
    constexpr size_t kMaxSeg = 256u;
    for (size_t n = 0u; n < kMaxSeg && pos + 1u < cap; ++n) {
        const char c = s[n];
        if (c == '\0') {
            break;
        }
        dst[pos++] = c;
    }
    Append_NullTerminate(dst, cap, pos);
    return pos;
}

static size_t Append_Hex32(char* dst, size_t cap, size_t pos, uint32_t v) noexcept {
    static constexpr char k_hex[] = "0123456789ABCDEF";
    if (dst == nullptr || cap == 0u) { return pos; }
    for (int i = 7; i >= 0; --i) {
        if (pos + 1u >= cap) { break; }
        const uint8_t nib = static_cast<uint8_t>((v >> (static_cast<uint32_t>(i) * 4u)) & 0x0Fu);
        dst[pos++] = k_hex[static_cast<size_t>(nib)];
    }
    Append_NullTerminate(dst, cap, pos);
    return pos;
}

void SecureLogger::pollDebuggerHardwareOrFault() noexcept {
    AntiDebugManager::pollHardwareOrFault();
}

void SecureLogger::flushAuditRingForTrap() noexcept {
    FlushAuditRingForTrapImpl();
}

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

    const uint32_t seq = g_audit_seq.fetch_add(1u, std::memory_order_relaxed);
    const size_t idx = static_cast<size_t>(seq & static_cast<uint32_t>(kAuditRingSlots - 1u));
    char* const slot = g_audit_ring[idx];

    uint8_t expected_empty = kAuditEmpty;
    if (!g_audit_ready[idx].compare_exchange_strong(
            expected_empty,
            kAuditWriting,
            std::memory_order_acquire,
            std::memory_order_relaxed)) {
        g_audit_event_drop_count.fetch_add(1u, std::memory_order_relaxed);
        return;
    }

    // 단일 패스: 동적 접두 [AUDIT@tick] 후 payload_start — CRC는 eventType|details만(레이트·플러딩 방어).
    size_t pos = 0u;
    pos = Append_Lit(slot, kAuditCrcPrefixCap, pos, "[AUDIT@");
    pos = Append_Hex32(slot, kAuditCrcPrefixCap, pos, tick);
    pos = Append_Lit(slot, kAuditCrcPrefixCap, pos, "] ");
    const size_t payload_start = pos;
    pos = Append_Lit(slot, kAuditCrcPrefixCap, pos, eventType);
    pos = Append_Lit(slot, kAuditCrcPrefixCap, pos, " | ");
    pos = Append_Lit(slot, kAuditCrcPrefixCap, pos, details);

    const size_t payload_len = pos - payload_start;
    const uint32_t logCrc = Crc32Util::calculate(
        reinterpret_cast<const uint8_t*>(slot + payload_start), payload_len);

    const uint16_t tick_sc = static_cast<uint16_t>((tick >> 16) & 0xFFFFu);
    const uint32_t enc = s_audit_rate_packed.load(std::memory_order_acquire);
    if (enc != 0u) {
        uint32_t raw_prev = 0u;
        if (DecodeRateRaw(enc, raw_prev)) {
            const uint32_t last_crc16 = raw_prev & 0xFFFFu;
            const uint16_t last_tick_sc = static_cast<uint16_t>((raw_prev >> 16) & 0xFFFFu);
            const uint32_t dt_sc = static_cast<uint32_t>(
                static_cast<uint16_t>(tick_sc - last_tick_sc));
            if ((logCrc & 0xFFFFu) == last_crc16 && dt_sc < kAuditRateWindowScaled) {
                g_audit_event_drop_count.fetch_add(1u, std::memory_order_relaxed);
                AuditDropReleaseBarrier(slot, idx);
                return;
            }
        }
    }

    pos = Append_Lit(slot, 256u, pos, " | CRC:0x");
    pos = Append_Hex32(slot, 256u, pos, logCrc);
    pos = Append_Lit(slot, 256u, pos, "\n");

    const size_t ncopy = (pos < 256u) ? (pos + 1u) : 256u;
    if (ncopy < 256u) {
        std::memset(slot + ncopy, 0, 256u - ncopy);
    }
    std::atomic_thread_fence(std::memory_order_release);
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#endif
    g_audit_ready[idx].store(kAuditReady, std::memory_order_release);

    AuditRateCommit(logCrc, tick);
}

} // namespace ProtectedEngine
