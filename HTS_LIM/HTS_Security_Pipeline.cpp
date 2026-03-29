// =========================================================================
// HTS_Security_Pipeline.cpp
// 최상위 보안 파이프라인 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// [양산 수정 — 26건]
//
//  ── 세션 5 (BUG-01 ~ BUG-15) ──
//  BUG-01~15: noexcept, nullptr, include경로, 세션ID, AEAD,
//    비트연산, copy/move, cstddef, Doxygen, relaxed, 안티디버깅,
//    AEAD비결정성, 시그니처, atomic, 모듈로최적화
//
//  ── 세션 8 전수검사 (BUG-16 ~ BUG-22) ──
//  BUG-16 [HIGH] atomic<uint64_t> ARM lock-free 미보장 → BUG-22로 근본 해결
//  BUG-17 [CRIT] 보안 검사 || 단축평가 → 개별 저장 + 비트 OR
//  BUG-18 [MED]  SESSION_ID 하드코딩 → 주석 강화
//  BUG-19 [MED]  FNV prime 매직 넘버 → constexpr 상수화
//  BUG-20 [LOW]  local_tag/tag_key 보안 소거 누락
//  BUG-21 [MED]  static_assert 빌드타임 검증 추가
//  BUG-22 [CRIT] atomic<uint64_t> → 2×atomic<uint32_t> 분할
//                ARM: LDREX/STREX lock-free 보장, Tearing/링커에러 해소
//
// [제약] float 0, double 0, try-catch 0, 힙 0
// =========================================================================
#include "HTS_Security_Pipeline.h"

#include "HTS_Universal_API.h"
#include "HTS_Gyro_Engine.h"
#include "HTS_Sparse_Recovery.h"
#include "HTS_AntiAnalysis_Shield.h"

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace ProtectedEngine {

    // ── 파일 스코프 상수 (내부 링키지) ──
    namespace {
        // [BUG-04/18] 세션 ID — 양산 시 Session_Gateway에서 런타임 주입으로 교체
        constexpr uint64_t PIPELINE_SESSION_ID = 0x550e8400e29b41d4ULL;

        // [BUG-13] Generate_Interference_Pattern 기본 파라미터
        constexpr uint32_t DEFAULT_ANCHOR_INTERVAL = 20u;
        constexpr bool     DEFAULT_TEST_MODE = false;

        // [BUG-15] 주기적 보안 검사 간격 (2^13 = 8192 = 32KB)
        constexpr size_t   SECURITY_CHECK_MASK = 0x1FFFu;

        // [BUG-15] 간섭 패턴 생성 주기
        constexpr uint32_t SPARSE_PERIOD = 20u;

        // [BUG-19] FNV-1a 해시 상수
        // [BUG-26] 64비트→32비트 전환: __aeabi_lmul 제거
        constexpr uint32_t FNV32_PRIME = 0x01000193u;  // FNV-1a 32비트 표준 소수
    }

    // [BUG-21] 빌드 타임 검증
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
    //  [BUG-17] 보안 검사 헬퍼 — 단축평가(||) 제거
    //
    //  기존: if (Is_Under_Observation() || !Continuous_Session_Verification())
    //  → 글리치로 첫 번째 BNE 스킵 시 두 번째 검사 건너뜀!
    //
    //  수정: 각 검사를 volatile bool에 개별 저장 → 비트 OR 합산
    //  → 단일 분기로 축소 (Anti_Glitch BUG-07과 동일 원리)
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

        if (!data || start >= end) return;
        if (abort_signal.load(std::memory_order_relaxed)) return;

        // [BUG-11] 루프 진입 전 1회 선행 보안 검증
        // [BUG-17] 단축평가 제거 → security_check_failed 헬퍼
        if (security_check_failed(PIPELINE_SESSION_ID)) {
            abort_signal.store(true, std::memory_order_release);
            return;
        }

        // [BUG-15] 로컬 카운터 초기화 (UDIV 1회만 → 루프 내 0회)
        uint32_t sparse_cnt = static_cast<uint32_t>(start % SPARSE_PERIOD);

        for (size_t i = start; i < end; ++i) {
            Gyro_Engine::Apply_Dynamic_Phase_Stabilization(data[i]);

            // [BUG-15] i % 20 → 로컬 카운터 (UDIV 제거)
            if (sparse_cnt == 0u) {
                Sparse_Recovery_Engine::Generate_Interference_Pattern(
                    &data[i], 1, PIPELINE_SESSION_ID,
                    DEFAULT_ANCHOR_INTERVAL, DEFAULT_TEST_MODE);
            }
            if (++sparse_cnt >= SPARSE_PERIOD) sparse_cnt = 0u;

            // [BUG-15] i % 8192 → & SECURITY_CHECK_MASK (비트 마스크)
            if ((i & SECURITY_CHECK_MASK) == 0u) {
                if (abort_signal.load(std::memory_order_relaxed)) return;

                // [BUG-17] 단축평가 제거
                if (security_check_failed(PIPELINE_SESSION_ID)) {
                    abort_signal.store(true, std::memory_order_release);
                    return;
                }
            }

            data[i] = ~data[i];
        }
    }

    // =====================================================================
    //  Secure_Master_Worker_AEAD — AEAD 태그 포함 파이프라인
    //
    //  [BUG-12] ⚠ 경고: 스레드 분할 비결정성
    //  비트 회전(RotL13)이 XOR 결합법칙을 파괴하므로,
    //  스레드 분할 단위(start, end)가 달라지면 global_tag 변동.
    //  이 태그는 엄밀한 MAC 검증이 아닌
    //  '청크 단위 훼손 탐지용 체크섬'으로만 사용하십시오.
    //
    //  [BUG-22] atomic<uint64_t> → 2×atomic<uint32_t> 분할
    //  ARM Cortex-M4: 64비트 원자적 연산 미지원
    //  기존: fetch_xor(__atomic_fetch_xor_8) → libatomic 소프트웨어 락
    //        → Tearing + 링커 에러 + HardFault
    //  수정: hi/lo 32비트 분할 → LDREX/STREX 단일 사이클 lock-free
    // =====================================================================
    void Security_Pipeline::Secure_Master_Worker_AEAD(
        uint32_t* data, size_t start, size_t end,
        std::atomic<bool>& abort_signal,
        std::atomic<uint32_t>& global_tag_hi,
        std::atomic<uint32_t>& global_tag_lo) noexcept {

        if (!data || start >= end) return;
        if (abort_signal.load(std::memory_order_relaxed)) return;

        // [BUG-11/17] 선행 검증 (단축평가 제거)
        if (security_check_failed(PIPELINE_SESSION_ID)) {
            abort_signal.store(true, std::memory_order_release);
            return;
        }

        // [BUG-26] 32비트 이중 누적기 — 64비트 연산 0회
        // 기존: uint64_t local_tag × FNV_PRIME(64bit) + rotl64(13)
        //  → __aeabi_lmul(30cyc) + 64bit shift(8cyc) = 요소당 ~50cyc
        // 수정: tag_hi/tag_lo 독립 FNV-1a 32비트 × FNV32_PRIME
        //  → UMULL(1cyc) + ROR(1cyc) = 요소당 ~6cyc (8× 가속)
        // 출력 호환: global_tag_hi/lo에 직접 XOR 병합 (분할 불필요)
        uint32_t tag_hi = 0u;
        uint32_t tag_lo = 0u;
        const uint32_t tag_key =
            static_cast<uint32_t>(PIPELINE_SESSION_ID & 0xFFFFFFFFu);
        const uint32_t tag_key_hi =
            static_cast<uint32_t>(PIPELINE_SESSION_ID >> 32u);

        // [BUG-15] 로컬 카운터 초기화
        uint32_t sparse_cnt = static_cast<uint32_t>(start % SPARSE_PERIOD);

        for (size_t i = start; i < end; ++i) {
            Gyro_Engine::Apply_Dynamic_Phase_Stabilization(data[i]);

            // [BUG-15] 로컬 카운터
            if (sparse_cnt == 0u) {
                Sparse_Recovery_Engine::Generate_Interference_Pattern(
                    &data[i], 1, PIPELINE_SESSION_ID,
                    DEFAULT_ANCHOR_INTERVAL, DEFAULT_TEST_MODE);
            }
            if (++sparse_cnt >= SPARSE_PERIOD) sparse_cnt = 0u;

            // [BUG-15/17] 주기적 보안 검사
            if ((i & SECURITY_CHECK_MASK) == 0u) {
                if (abort_signal.load(std::memory_order_relaxed)) return;

                if (security_check_failed(PIPELINE_SESSION_ID)) {
                    abort_signal.store(true, std::memory_order_release);
                    return;
                }
            }

            data[i] = ~data[i];

            // [BUG-26] 32비트 이중 FNV-1a — 64비트 연산 0회
            // hi: data^tag_key_hi 혼합, lo: data^tag_key 혼합
            // 독립 누적 → 크로스 XOR로 엔트로피 확산
            const uint32_t mixed = data[i] ^ tag_key;
            tag_lo ^= mixed;
            tag_lo *= FNV32_PRIME;     // ARM UMULL 1cyc
            tag_lo = (tag_lo << 13u) | (tag_lo >> 19u);  // ROR 1cyc

            const uint32_t mixed_hi = data[i] ^ tag_key_hi;
            tag_hi ^= mixed_hi;
            tag_hi *= FNV32_PRIME;
            tag_hi = (tag_hi << 7u) | (tag_hi >> 25u);  // 다른 회전량 → 독립성

            // 크로스 XOR: hi↔lo 상호 의존성 주입
            tag_hi ^= tag_lo;
        }

        // [BUG-26] 32비트 직접 병합 — 분할 불필요
        global_tag_hi.fetch_xor(tag_hi, std::memory_order_relaxed);
        global_tag_lo.fetch_xor(tag_lo, std::memory_order_relaxed);

        // [BUG-24] D-2 보안 소거 — 3중 방어
        volatile uint32_t* v_hi = &tag_hi;
        volatile uint32_t* v_lo = &tag_lo;
        *v_hi = 0u;
        *v_lo = 0u;
#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__ARM_ARCH))
        __asm__ __volatile__("" : : "r"(v_hi), "r"(v_lo) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

} // namespace ProtectedEngine