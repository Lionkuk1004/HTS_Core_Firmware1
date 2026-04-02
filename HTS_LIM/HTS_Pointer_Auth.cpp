// =========================================================================
// HTS_Pointer_Auth.cpp
// 포인터 인증 코드(PAC) 구현부 — Murmur3 비가역 해시 + 런타임 키
// Target: STM32F407 (Cortex-M4)
//
#include "HTS_Pointer_Auth.hpp"
#include "HTS_Auto_Rollback_Manager.hpp"
#include "HTS_Secure_Logger.h"
#include "HTS_Secure_Memory.h"
#include <atomic>

namespace ProtectedEngine {

    // ── 매직 넘버 상수화 (J-3) ───────────────────────────────────
    namespace {
        /// 0 키 방어용 도메인 분리 상수 ("HTS_PAC!" ASCII)
        constexpr uint64_t PAC_FALLBACK_KEY = 0x4854535F50414321ULL;

        /// Murmur3 fmix — 32비트 경로 사용

        /// 자가 치유 코드
        constexpr uint32_t HEAL_PAC_TAMPER = 0xDEAD0BA0u;  ///< PAC 변조 코드

        constexpr uint32_t PAC_UNINIT = 0u;
        constexpr uint32_t PAC_IN_PROGRESS = 1u;
        constexpr uint32_t PAC_DONE = 2u;
    }

    // =====================================================================
    //  PAC 키: 64비트 tearing 방지 — hi/lo를 atomic<uint32_t>로 분리
    // =====================================================================
    static std::atomic<uint32_t> g_pac_init_state{ PAC_UNINIT };
    static std::atomic<uint32_t> g_pac_key_hi{ 0u };
    static std::atomic<uint32_t> g_pac_key_lo{ 0u };

    // =====================================================================
    //  키 읽기: seqlock(g_pac_key_ver)로 hi/lo 일관성
    // =====================================================================
    static std::atomic<uint32_t> g_pac_key_ver{ 0u };  // 짝수=안정, 홀수=쓰기중

    // 키 쓰기 — seqlock 보호
    static void Store_Runtime_Key(uint64_t key) noexcept {
        // ver → 홀수 (쓰기 시작)
        g_pac_key_ver.fetch_add(1u, std::memory_order_release);
        g_pac_key_hi.store(static_cast<uint32_t>(key >> 32),
            std::memory_order_relaxed);
        g_pac_key_lo.store(static_cast<uint32_t>(key & 0xFFFFFFFFu),
            std::memory_order_relaxed);
        // ver → 짝수 (쓰기 완료)
        g_pac_key_ver.fetch_add(1u, std::memory_order_release);
    }

    // 키 읽기 — seqlock 보호 (최대 4회 재시도 후 폴백)
    static uint64_t Load_Runtime_Key() noexcept {
        for (int retry = 0; retry < 4; ++retry) {
            const uint32_t v1 = g_pac_key_ver.load(std::memory_order_acquire);
            if ((v1 & 1u) != 0u) continue;  // 홀수 = 쓰기 진행중 → 재시도

            const uint32_t hi = g_pac_key_hi.load(std::memory_order_relaxed);
            const uint32_t lo = g_pac_key_lo.load(std::memory_order_relaxed);

            const uint32_t v2 = g_pac_key_ver.load(std::memory_order_acquire);
            if (v1 == v2) {
                return (static_cast<uint64_t>(hi) << 32) | lo;
            }
            // v1 != v2: 읽기 도중 쓰기 발생 → 재시도
        }
        // 4회 실패 (비정상) — 폴백 키 반환
        return PAC_FALLBACK_KEY;
    }

    // ── Murmur3 상수 ──
    namespace {
        /// Murmur3 fmix32 표준 상수
        constexpr uint32_t MURMUR3_32_C1 = 0x85EBCA6Bu;
        constexpr uint32_t MURMUR3_32_C2 = 0xC2B2AE35u;
    }

    // =====================================================================
    //  Murmur3 fmix32를 lo/hi에 각각 적용 — 64비트 곱셈·lmul 회피
    // =====================================================================
    static uint32_t Murmur3_Fmix32(uint32_t lo_half,
        uint32_t hi_half) noexcept {
        // lo 해시
        lo_half ^= lo_half >> 16u;
        lo_half *= MURMUR3_32_C1;
        lo_half ^= lo_half >> 13u;
        lo_half *= MURMUR3_32_C2;
        lo_half ^= lo_half >> 16u;

        // hi 해시
        hi_half ^= hi_half >> 16u;
        hi_half *= MURMUR3_32_C1;
        hi_half ^= hi_half >> 13u;
        hi_half *= MURMUR3_32_C2;
        hi_half ^= hi_half >> 16u;

        return lo_half ^ hi_half;
    }

    static uint64_t Mix_Key_64(uint64_t input) noexcept {
        const uint32_t lo = static_cast<uint32_t>(input);
        const uint32_t hi = static_cast<uint32_t>(input >> 32);
        const uint32_t mixed_lo = Murmur3_Fmix32(lo, hi ^ 0x9E3779B9u);
        const uint32_t mixed_hi = Murmur3_Fmix32(hi, lo ^ 0x6A09E667u);
        return (static_cast<uint64_t>(mixed_hi) << 32) | mixed_lo;
    }

    // =====================================================================
    //  위반 시 로그 후 Self_Healing → WFI 루프
    // =====================================================================
    [[noreturn]] void PAC_Manager::Halt_PAC_Violation(
        const char* reason) noexcept {

        SecureLogger::logSecurityEvent(
            "PAC_VIOLATION",
            reason ? reason : "UNKNOWN");

        Auto_Rollback_Manager::Execute_Self_Healing(
            HEAL_PAC_TAMPER);

        while (true) {
#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__ARM_ARCH))
            __asm__ __volatile__("wfi");
#endif
        }
    }

    // =====================================================================
    //  Initialize_Runtime_Key — 부팅 시 명시적 PUF 엔트로피 주입
    //
    //
    //  IN_PROGRESS → 키 교체(seqlock) → DONE. 호출자는 초기화 순서 계약 준수.
    //
    //  [⚠ 호출 계약]
    //    이 함수 호출 전에 서명된 포인터는 새 키로 재서명 필수
    //    부팅 시 Sign_Pointer보다 먼저 호출하는 것을 강력 권장
    // =====================================================================
    void PAC_Manager::Initialize_Runtime_Key(uint64_t entropy_seed) noexcept {
        if (entropy_seed == 0) {
            entropy_seed = PAC_FALLBACK_KEY;
        }

        // 상태를 IN_PROGRESS로 전환 (어떤 상태에서든)
        // → Load_Runtime_Key 호출자가 seqlock으로 대기/재시도
        // → Ensure_Key_Initialized 호출자가 spin-wait
        uint32_t prev = g_pac_init_state.exchange(
            PAC_IN_PROGRESS, std::memory_order_acq_rel);
        (void)prev;

        // seqlock 보호 키 쓰기
        Store_Runtime_Key(Mix_Key_64(entropy_seed));

        // DONE 전환 — 이후 Sign/Auth가 새 키 사용
        g_pac_init_state.store(PAC_DONE, std::memory_order_release);
    }

    // =====================================================================
    // =====================================================================
    void PAC_Manager::Wipe_Runtime_Key() noexcept {
        g_pac_key_ver.fetch_add(1u, std::memory_order_release);  // 홀수
        g_pac_key_hi.store(0u, std::memory_order_relaxed);
        g_pac_key_lo.store(0u, std::memory_order_relaxed);
        g_pac_key_ver.fetch_add(1u, std::memory_order_release);  // 짝수

        // 상태를 미초기화로 → 다음 Sign/Auth 시 Halt (재초기화 필요)
        g_pac_init_state.store(PAC_UNINIT, std::memory_order_release);
    }

    // =====================================================================
    //  자동 키 생성 없음 — DONE 전이는 Initialize_Runtime_Key만
    // =====================================================================
    void PAC_Manager::Ensure_Key_Initialized() noexcept {
        // Fast path: 이미 초기화 완료
        const uint32_t state = g_pac_init_state.load(std::memory_order_acquire);
        if (state == PAC_DONE) return;

        // IN_PROGRESS: Initialize_Runtime_Key가 진행 중 → 짧은 대기
        if (state == PAC_IN_PROGRESS) {
            constexpr uint32_t MAX_SPIN = 100u;
            for (uint32_t spin = 0; spin < MAX_SPIN; ++spin) {
                if (g_pac_init_state.load(std::memory_order_acquire) == PAC_DONE) {
                    return;
                }
#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__ARM_ARCH))
                __asm__ __volatile__("yield");
#endif
            }
        }

        // UNINIT 또는 spin 타임아웃:
        // Initialize_Runtime_Key가 호출되지 않음 → 보안 위반
        Halt_PAC_Violation(
            "PAC key not initialized — call Initialize_Runtime_Key before Sign/Auth");
    }

    // =====================================================================
    //  Compute_PAC — Murmur3 기반 비가역 포인터 인증 코드 생성
    //
    //  [알고리즘]
    //  1. 주소 ⊕ 키 기본 혼합
    //  2. 키 17비트 회전값 추가 혼합 (관련 키 공격 방어)
    //  3. Murmur3 fmix64 통과
    //  4. 64→32비트 XOR 접기 (정보 손실 = 추가 비가역성)
    // =====================================================================
    uint32_t PAC_Manager::Compute_PAC(uint64_t raw_addr) noexcept {
        const uint64_t key64 = Load_Runtime_Key();
        const uint32_t key_hi = static_cast<uint32_t>(key64 >> 32);
        const uint32_t key_lo = static_cast<uint32_t>(key64 & 0xFFFFFFFFu);
        const uint32_t addr32 = static_cast<uint32_t>(raw_addr);

        // 주소 ⊕ 키 혼합 (32비트 독립)
        volatile uint32_t mix_lo = addr32 ^ key_lo;
        volatile uint32_t mix_hi = addr32 ^ key_hi;

        // 키 회전 혼합 (관련 키 공격 방어) — 32비트 연산만
        mix_lo += (key_lo >> 17u) | (key_hi << 15u);
        mix_hi += (key_hi >> 17u) | (key_lo << 15u);

        // Murmur3 fmix32 이중 해시
        volatile uint32_t hash = Murmur3_Fmix32(mix_lo, mix_hi);

#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__ARM_ARCH))
        __asm__ __volatile__("" : : "r"(static_cast<uint32_t>(hash)));
#endif

        return static_cast<uint32_t>(hash);
    }

} // namespace ProtectedEngine
