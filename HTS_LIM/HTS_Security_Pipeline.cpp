// =========================================================================
// HTS_Security_Pipeline.cpp
// 최상위 보안 파이프라인 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
//
#include "HTS_Security_Pipeline.h"

#include "HTS_Universal_API.h"
#include "HTS_Gyro_Engine.h"
#include "HTS_Sparse_Recovery.h"
#include "HTS_AntiAnalysis_Shield.h"
#include "HTS_Secure_Memory.h"
#include "HTS_Hardware_Init.h"

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace ProtectedEngine {

    // ── 파일 스코프 상수 (내부 링키지) ──
    namespace {
        constexpr uint64_t PIPELINE_SESSION_ID = 0x550e8400e29b41d4ULL;

        constexpr uint32_t DEFAULT_ANCHOR_INTERVAL = 20u;
        constexpr bool     DEFAULT_TEST_MODE = false;

        constexpr size_t   SECURITY_CHECK_MASK = 0x1FFFu;

        constexpr uint32_t SPARSE_PERIOD = 20u;

        constexpr uint32_t FNV32_PRIME = 0x01000193u;  // FNV-1a 32비트 표준 소수

        // CFI: 상위 16비트 = 상태, 하위 16비트 = 동일 모드 활성 워커 수
        constexpr uint32_t CFI_IDLE = 0xC100u;
        constexpr uint32_t CFI_WORKER = 0xC101u;
        constexpr uint32_t CFI_AEAD = 0xC102u;

        constexpr uint32_t cfi_pack(uint32_t state16, uint32_t count16) noexcept {
            return (state16 << 16) | (count16 & 0xFFFFu);
        }

        std::atomic<uint32_t> g_pipeline_cfi{ cfi_pack(CFI_IDLE, 0u) };

        [[noreturn]] static void pipeline_security_terminal_fault(
            uint32_t* data, size_t start, size_t end,
            size_t buffer_total_words) noexcept;

        static bool cfi_enter(uint32_t target) noexcept {
            for (uint32_t spin = 0u; spin < 100000u; ++spin) {
                const uint32_t cur = g_pipeline_cfi.load(std::memory_order_acquire);
                const uint32_t st = cur >> 16;
                const uint32_t cnt = cur & 0xFFFFu;
                uint32_t next = 0u;
                if (cnt == 0u) {
                    if (st != CFI_IDLE) {
                        return false;
                    }
                    next = cfi_pack(target, 1u);
                } else {
                    if (st != target) {
                        return false;
                    }
                    if (cnt >= 0xFFFFu) {
                        return false;
                    }
                    next = cfi_pack(st, cnt + 1u);
                }
                uint32_t expected = cur;
                if (g_pipeline_cfi.compare_exchange_weak(
                        expected, next,
                        std::memory_order_acq_rel,
                        std::memory_order_acquire)) {
                    return true;
                }
            }
            Hardware_Init_Manager::Terminal_Fault_Action();
        }

        static void cfi_leave(uint32_t from) noexcept {
            for (uint32_t spin = 0u; spin < 100000u; ++spin) {
                const uint32_t cur = g_pipeline_cfi.load(std::memory_order_acquire);
                const uint32_t st = cur >> 16;
                const uint32_t cnt = cur & 0xFFFFu;
                if (st != from || cnt == 0u) {
                    Hardware_Init_Manager::Terminal_Fault_Action();
                }
                const uint32_t next =
                    (cnt == 1u) ? cfi_pack(CFI_IDLE, 0u) : cfi_pack(st, cnt - 1u);
                uint32_t expected = cur;
                if (g_pipeline_cfi.compare_exchange_weak(
                        expected, next,
                        std::memory_order_acq_rel,
                        std::memory_order_acquire)) {
                    return;
                }
            }
            Hardware_Init_Manager::Terminal_Fault_Action();
        }

        // 0 = 정상, 0xFFFFFFFF = 실패 (비트 OR·감산으로 마스크 생성)
        static uint32_t security_fail_mask(uint64_t session_id) noexcept {
            volatile bool obs = AntiAnalysis_Shield::Is_Under_Observation();
            const uint32_t gate_ok =
                Universal_API::Continuous_Session_Verification(session_id);
            const uint32_t ses_fail =
                static_cast<uint32_t>((~gate_ok) >> 31) & 1u;
            const uint32_t bits =
                static_cast<uint32_t>(obs) | ses_fail;
            return static_cast<uint32_t>(0u - bits);
        }

        static void wipe_pipeline_buffer_on_fault(
            uint32_t* data, size_t start, size_t end,
            size_t buffer_total_words) noexcept {
            if (buffer_total_words != 0u) {
                SecureMemory::secureWipe(
                    data, buffer_total_words * sizeof(uint32_t));
            } else {
                SecureMemory::secureWipe(
                    data + start, (end - start) * sizeof(uint32_t));
            }
        }

        [[noreturn]] static void pipeline_security_terminal_fault(
            uint32_t* data, size_t start, size_t end,
            size_t buffer_total_words) noexcept {
            wipe_pipeline_buffer_on_fault(data, start, end, buffer_total_words);
            Hardware_Init_Manager::Terminal_Fault_Action();
        }

        // division-free start % 20 (Cortex-M4 friendly)
        static uint32_t fast_mod20_u32(uint32_t x) noexcept {
            // Mul-shift 근사: static_cast<uint64_t>(x) 기반 /20 스케일 (UDIV 회피)
            const uint32_t q = static_cast<uint32_t>(
                (static_cast<uint64_t>(x) * 0xCCCCCCCDull) >> 36u);
            return static_cast<uint32_t>(x - q * SPARSE_PERIOD);
        }
    }

    static_assert(PIPELINE_SESSION_ID != 0u,
        "PIPELINE_SESSION_ID must be non-zero");
    static_assert(DEFAULT_ANCHOR_INTERVAL > 0u,
        "DEFAULT_ANCHOR_INTERVAL must be positive");
    static_assert(SECURITY_CHECK_MASK == 8191u,
        "SECURITY_CHECK_MASK must be 8192-1 for bit-mask optimization");
    static_assert(SPARSE_PERIOD > 0u,
        "SPARSE_PERIOD must be positive");
    static_assert(FNV32_PRIME != 0u,
        "FNV32_PRIME must be non-zero");

    // =====================================================================
    //  Secure_Master_Worker — 기본 파이프라인 (AEAD 없음)
    // =====================================================================
    void Security_Pipeline::Secure_Master_Worker(
        uint32_t* data, size_t start, size_t end,
        std::atomic<bool>& abort_signal,
        size_t buffer_total_words) noexcept {

        uint32_t ok = 1u; // TPE:
        ok &= static_cast<uint32_t>(data != nullptr); // TPE:
        ok &= static_cast<uint32_t>(start < end); // TPE:
        ok &= static_cast<uint32_t>(
            buffer_total_words == 0u || end <= buffer_total_words); // TPE:
        ok &= static_cast<uint32_t>(
            !abort_signal.load(std::memory_order_relaxed)); // TPE:

        bool cfi_entered = false;
        if (ok != 0u) {
            cfi_entered = cfi_enter(CFI_WORKER);
            ok &= static_cast<uint32_t>(cfi_entered); // TPE:
            if (!cfi_entered) {
                abort_signal.store(true, std::memory_order_release);
            }
        }

        const size_t m_ok = static_cast<size_t>(0u - ok); // TPE:
        const size_t safe_end = end & m_ok; // TPE:

        if (ok != 0u) {
            const uint32_t m_entry = security_fail_mask(PIPELINE_SESSION_ID);
            if (m_entry != 0u) {
                pipeline_security_terminal_fault(data, start, end, buffer_total_words);
            }
        }

        uint32_t sparse_cnt = fast_mod20_u32(static_cast<uint32_t>(start));

        for (size_t i = start; i < safe_end; ++i) {
            Gyro_Engine::Apply_Dynamic_Phase_Stabilization(data[i]);

            if (sparse_cnt == 0u) {
                Sparse_Recovery_Engine::Generate_Interference_Pattern(
                    &data[i], 1, PIPELINE_SESSION_ID,
                    DEFAULT_ANCHOR_INTERVAL, DEFAULT_TEST_MODE);
            }
            if (++sparse_cnt >= SPARSE_PERIOD) sparse_cnt = 0u;

            if ((i & SECURITY_CHECK_MASK) == 0u) {
                const uint32_t m = security_fail_mask(PIPELINE_SESSION_ID);
                data[i] |= m;
                if (m != 0u) {
                    pipeline_security_terminal_fault(
                        data, start, end, buffer_total_words);
                }
            }

            data[i] = ~data[i];
        }
        if (cfi_entered) {
            cfi_leave(CFI_WORKER);
        }
    }

    // =====================================================================
    //  Secure_Master_Worker_AEAD — AEAD 태그 포함 파이프라인
    //
    //  요소별 기여: (data[i], 인덱스 i)만으로 h_lo/h_hi 계산 후 XOR 누적.
    //  XOR는 가환·결합 → 청크 경계(start,end)와 처리 순서에 무관하게 global_tag 일치.
    //
    //  ARM Cortex-M4: 64비트 원자적 연산 미지원
    //  fetch_xor(__atomic_fetch_xor_8) → libatomic 소프트웨어 락
    //        → Tearing + 링커 에러 + HardFault
    //  hi/lo 32비트 분할 → LDREX/STREX 단일 사이클 lock-free
    // =====================================================================
    void Security_Pipeline::Secure_Master_Worker_AEAD(
        uint32_t* data, size_t start, size_t end,
        std::atomic<bool>& abort_signal,
        std::atomic<uint32_t>& global_tag_hi,
        std::atomic<uint32_t>& global_tag_lo,
        size_t buffer_total_words) noexcept {

        uint32_t ok = 1u; // TPE:
        ok &= static_cast<uint32_t>(data != nullptr); // TPE:
        ok &= static_cast<uint32_t>(start < end); // TPE:
        ok &= static_cast<uint32_t>(
            buffer_total_words == 0u || end <= buffer_total_words); // TPE:
        ok &= static_cast<uint32_t>(
            !abort_signal.load(std::memory_order_relaxed)); // TPE:

        bool cfi_entered = false;
        if (ok != 0u) {
            cfi_entered = cfi_enter(CFI_AEAD);
            ok &= static_cast<uint32_t>(cfi_entered); // TPE:
            if (!cfi_entered) {
                abort_signal.store(true, std::memory_order_release);
            }
        }

        const size_t m_ok = static_cast<size_t>(0u - ok); // TPE:
        const size_t safe_end = end & m_ok; // TPE:

        if (ok != 0u) {
            const uint32_t m_entry = security_fail_mask(PIPELINE_SESSION_ID);
            if (m_entry != 0u) {
                pipeline_security_terminal_fault(data, start, end, buffer_total_words);
            }
        }

        uint32_t tag_hi = 0u;
        uint32_t tag_lo = 0u;
        const uint32_t tag_key =
            static_cast<uint32_t>(PIPELINE_SESSION_ID & 0xFFFFFFFFu);
        const uint32_t tag_key_hi =
            static_cast<uint32_t>(PIPELINE_SESSION_ID >> 32u);

        uint32_t sparse_cnt = fast_mod20_u32(static_cast<uint32_t>(start));

        for (size_t i = start; i < safe_end; ++i) {
            Gyro_Engine::Apply_Dynamic_Phase_Stabilization(data[i]);

            if (sparse_cnt == 0u) {
                Sparse_Recovery_Engine::Generate_Interference_Pattern(
                    &data[i], 1, PIPELINE_SESSION_ID,
                    DEFAULT_ANCHOR_INTERVAL, DEFAULT_TEST_MODE);
            }
            if (++sparse_cnt >= SPARSE_PERIOD) sparse_cnt = 0u;

            if ((i & SECURITY_CHECK_MASK) == 0u) {
                const uint32_t m = security_fail_mask(PIPELINE_SESSION_ID);
                data[i] |= m;
                if (m != 0u) {
                    pipeline_security_terminal_fault(
                        data, start, end, buffer_total_words);
                }
            }

            data[i] = ~data[i];

            const uint32_t data_word = static_cast<uint32_t>(data[i]);
            const uint64_t i64 = static_cast<uint64_t>(i);
            const uint32_t i_lo = static_cast<uint32_t>(i64);
            const uint32_t i_hi = static_cast<uint32_t>(i64 >> 32u);

            uint32_t h_lo = data_word ^ tag_key ^ i_lo;
            h_lo *= FNV32_PRIME;
            h_lo = static_cast<uint32_t>((h_lo << 13u) | (h_lo >> 19u));

            uint32_t h_hi = data_word ^ tag_key_hi ^ i_hi ^ (i_lo * 0xB5297A4Du);
            h_hi *= FNV32_PRIME;
            h_hi = static_cast<uint32_t>((h_hi << 7u) | (h_hi >> 25u));

            tag_lo ^= h_lo;
            tag_hi ^= h_hi;
        }

        if (cfi_entered) {
            global_tag_hi.fetch_xor(tag_hi, std::memory_order_relaxed);
            global_tag_lo.fetch_xor(tag_lo, std::memory_order_relaxed);

            SecureMemory::secureWipe(&tag_hi, sizeof(tag_hi));
            SecureMemory::secureWipe(&tag_lo, sizeof(tag_lo));
            cfi_leave(CFI_AEAD);
        }
    }

} // namespace ProtectedEngine
