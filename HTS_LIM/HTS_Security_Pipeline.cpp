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

        // CFI 상태 (초경량 32비트 원자 상태머신)
        constexpr uint32_t CFI_IDLE = 0xC100u;
        constexpr uint32_t CFI_WORKER = 0xC101u;
        constexpr uint32_t CFI_AEAD = 0xC102u;
        constexpr uint32_t CFI_ABORT = 0xC1FFu;

        std::atomic<uint32_t> g_pipeline_cfi{ CFI_IDLE };

        static bool cfi_enter(uint32_t target) noexcept {
            const uint32_t cur = g_pipeline_cfi.load(std::memory_order_acquire);
            if (cur != CFI_IDLE) { return false; }
            g_pipeline_cfi.store(target, std::memory_order_release);
            return true;
        }

        static void cfi_leave(uint32_t from) noexcept {
            const uint32_t cur = g_pipeline_cfi.load(std::memory_order_acquire);
            if (cur == from) {
                g_pipeline_cfi.store(CFI_IDLE, std::memory_order_release);
            }
            else {
                g_pipeline_cfi.store(CFI_ABORT, std::memory_order_release);
            }
        }

        // division-free start % 20 (Cortex-M4 friendly)
        static uint32_t fast_mod20_u32(uint32_t x) noexcept {
            const uint32_t q = static_cast<uint32_t>(
                (static_cast<uint64_t>(x) * 0xCCCCCCCDull) >> 36u); // floor(x/20)
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
    //
    //  if (Is_Under_Observation() || !Continuous_Session_Verification())
    //  → 글리치로 첫 번째 BNE 스킵 시 두 번째 검사 건너뜀!
    //
    //  각 검사를 volatile bool에 개별 저장 → 비트 OR 합산
    //  → 단일 분기로 축소 (Anti_Glitch와 동일 원리)
    // =====================================================================
    static bool security_check_failed(uint64_t session_id) noexcept {
        // 각 검사 결과를 volatile에 개별 저장
        // → 컴파일러가 검사를 생략하거나 재배치 불가
        volatile bool obs = AntiAnalysis_Shield::Is_Under_Observation();
        volatile bool ses = !Universal_API::Continuous_Session_Verification(
            session_id);

        // 비트 OR → 단일 분기 (단축평가 제거)
        // 정상: obs=false, ses=false → 0|0=0 → return false
        // 이상: 어느 하나라도 true → return true
        uint32_t fail = 0u;
        fail |= (obs ? 1u : 0u);
        fail |= (ses ? 1u : 0u);
        return (fail != 0u);
    }

    // =====================================================================
    //  Secure_Master_Worker — 기본 파이프라인 (AEAD 없음)
    // =====================================================================
    void Security_Pipeline::Secure_Master_Worker(
        uint32_t* data, size_t start, size_t end,
        std::atomic<bool>& abort_signal) noexcept {

        if (data == nullptr || start >= end) return;
        if (abort_signal.load(std::memory_order_relaxed)) return;
        if (!cfi_enter(CFI_WORKER)) {
            abort_signal.store(true, std::memory_order_release);
            return;
        }

        if (security_check_failed(PIPELINE_SESSION_ID)) {
            abort_signal.store(true, std::memory_order_release);
            cfi_leave(CFI_WORKER);
            return;
        }

        // [개선] start % 20의 UDIV 제거 (division-free reciprocal)
        uint32_t sparse_cnt = fast_mod20_u32(static_cast<uint32_t>(start));

        for (size_t i = start; i < end; ++i) {
            Gyro_Engine::Apply_Dynamic_Phase_Stabilization(data[i]);

            if (sparse_cnt == 0u) {
                Sparse_Recovery_Engine::Generate_Interference_Pattern(
                    &data[i], 1, PIPELINE_SESSION_ID,
                    DEFAULT_ANCHOR_INTERVAL, DEFAULT_TEST_MODE);
            }
            if (++sparse_cnt >= SPARSE_PERIOD) sparse_cnt = 0u;

            if ((i & SECURITY_CHECK_MASK) == 0u) {
                if (abort_signal.load(std::memory_order_relaxed)) {
                    cfi_leave(CFI_WORKER);
                    return;
                }

                if (security_check_failed(PIPELINE_SESSION_ID)) {
                    abort_signal.store(true, std::memory_order_release);
                    cfi_leave(CFI_WORKER);
                    return;
                }
            }

            data[i] = ~data[i];
        }
        cfi_leave(CFI_WORKER);
    }

    // =====================================================================
    //  Secure_Master_Worker_AEAD — AEAD 태그 포함 파이프라인
    //
    //  비트 회전(RotL13)이 XOR 결합법칙을 파괴하므로,
    //  스레드 분할 단위(start, end)가 달라지면 global_tag 변동.
    //  이 태그는 엄밀한 MAC 검증이 아닌
    //  '청크 단위 훼손 탐지용 체크섬'으로만 사용하십시오.
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
        std::atomic<uint32_t>& global_tag_lo) noexcept {

        if (data == nullptr || start >= end) return;
        if (abort_signal.load(std::memory_order_relaxed)) return;
        if (!cfi_enter(CFI_AEAD)) {
            abort_signal.store(true, std::memory_order_release);
            return;
        }

        if (security_check_failed(PIPELINE_SESSION_ID)) {
            abort_signal.store(true, std::memory_order_release);
            cfi_leave(CFI_AEAD);
            return;
        }

        // uint64_t local_tag × FNV_PRIME(64bit) + rotl64(13)
        //  → __aeabi_lmul(30cyc) + 64bit shift(8cyc) = 요소당 ~50cyc
        // tag_hi/tag_lo 독립 FNV-1a 32비트 × FNV32_PRIME
        //  → UMULL(1cyc) + ROR(1cyc) = 요소당 ~6cyc (8× 가속)
        // 출력 호환: global_tag_hi/lo에 직접 XOR 병합 (분할 불필요)
        uint32_t tag_hi = 0u;
        uint32_t tag_lo = 0u;
        const uint32_t tag_key =
            static_cast<uint32_t>(PIPELINE_SESSION_ID & 0xFFFFFFFFu);
        const uint32_t tag_key_hi =
            static_cast<uint32_t>(PIPELINE_SESSION_ID >> 32u);

        uint32_t sparse_cnt = fast_mod20_u32(static_cast<uint32_t>(start));

        for (size_t i = start; i < end; ++i) {
            Gyro_Engine::Apply_Dynamic_Phase_Stabilization(data[i]);

            if (sparse_cnt == 0u) {
                Sparse_Recovery_Engine::Generate_Interference_Pattern(
                    &data[i], 1, PIPELINE_SESSION_ID,
                    DEFAULT_ANCHOR_INTERVAL, DEFAULT_TEST_MODE);
            }
            if (++sparse_cnt >= SPARSE_PERIOD) sparse_cnt = 0u;

            if ((i & SECURITY_CHECK_MASK) == 0u) {
                if (abort_signal.load(std::memory_order_relaxed)) {
                    cfi_leave(CFI_AEAD);
                    return;
                }

                if (security_check_failed(PIPELINE_SESSION_ID)) {
                    abort_signal.store(true, std::memory_order_release);
                    cfi_leave(CFI_AEAD);
                    return;
                }
            }

            data[i] = ~data[i];

            // hi: data^tag_key_hi 혼합, lo: data^tag_key 혼합
            // 독립 누적 → 크로스 XOR로 엔트로피 확산
            const uint32_t data_word = static_cast<uint32_t>(data[i]);
            const uint32_t mixed = static_cast<uint32_t>(data_word ^ tag_key);
            tag_lo ^= mixed;
            tag_lo *= FNV32_PRIME;     // ARM UMULL 1cyc
            tag_lo = static_cast<uint32_t>((tag_lo << 13u) | (tag_lo >> 19u));  // ROR 1cyc

            const uint32_t mixed_hi = static_cast<uint32_t>(data_word ^ tag_key_hi);
            tag_hi ^= mixed_hi;
            tag_hi *= FNV32_PRIME;
            tag_hi = static_cast<uint32_t>((tag_hi << 7u) | (tag_hi >> 25u));  // 다른 회전량 → 독립성

            // 크로스 XOR: hi↔lo 상호 의존성 주입
            tag_hi ^= tag_lo;
        }

        global_tag_hi.fetch_xor(tag_hi, std::memory_order_relaxed);
        global_tag_lo.fetch_xor(tag_lo, std::memory_order_relaxed);

        SecureMemory::secureWipe(&tag_hi, sizeof(tag_hi));
        SecureMemory::secureWipe(&tag_lo, sizeof(tag_lo));
        cfi_leave(CFI_AEAD);
    }

} // namespace ProtectedEngine
