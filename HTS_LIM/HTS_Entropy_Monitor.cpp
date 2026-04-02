// =========================================================================
// HTS_Entropy_Monitor.cpp
// TRNG 건강성 감시 구현부 — NIST SP 800-90B RCT + APT
// Target: STM32F407 (Cortex-M4)
//
#include "HTS_Entropy_Monitor.h"
#include "HTS_Auto_Rollback_Manager.hpp"

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#define HTS_ENTROPY_ARM
#elif defined(__aarch64__)
#define HTS_ENTROPY_AARCH64
#else
#define HTS_ENTROPY_PC
#endif

#if defined(HTS_ENTROPY_PC)
#include <cstdlib>
#endif

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace ProtectedEngine {

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
    static inline uint32_t ent_critical_enter() noexcept {
        uint32_t primask;
        __asm volatile ("MRS %0, PRIMASK\n CPSID I"
            : "=r"(primask) :: "memory");
        return primask;
    }
    static inline void ent_critical_exit(uint32_t pm) noexcept {
        __asm volatile ("MSR PRIMASK, %0" :: "r"(pm) : "memory");
    }
#else
    static inline uint32_t ent_critical_enter() noexcept { return 0u; }
    static inline void ent_critical_exit(uint32_t) noexcept {}
#endif

    // =====================================================================
    //  Entropy Fault 처리 — RCT/APT 공통
    // =====================================================================
    // Execute_Self_Healing 은 [[noreturn]] — 진입 후 반환 없음.
    // PC/ARM 공통: 엔트로피 Fault 는 중앙 집행점으로 위임만 수행.
    [[noreturn]] static void Entropy_Fault_Handler(uint32_t fault_code) noexcept {
        Auto_Rollback_Manager::Execute_Self_Healing(fault_code);
    }

    // =====================================================================
    //  생성자
    // =====================================================================
    EntropyMonitor::EntropyMonitor() noexcept
        : last_byte(0u)
        , repeat_count(1u)
        , is_initialized(false)
        , apt_sample(0u)
        , apt_count(0u)
        , apt_window_pos(0u) {
    }

    // =====================================================================
    //  healthCheck — TRNG 출력 1바이트 건강성 검사
    //
    //  [1] RCT (Repetition Count Test) — §4.4.1
    //      동일 바이트 연속 NIST_RCT_CUTOFF(16)회 → Stuck-at Fault
    //
    //  [2] APT (Adaptive Proportion Test) — §4.4.2
    //      윈도우(512바이트) 내 특정 값이 APT_CUTOFF(41)회 이상 → Bias Fault
    //      윈도우 첫 바이트를 기준값으로 설정, 이후 W-1개에서 동일 값 카운트
    // =====================================================================
    void EntropyMonitor::healthCheck(uint8_t generatedByte) noexcept {
        uint32_t fault_code = 0u;
        const uint32_t pm = ent_critical_enter();
        // ── 첫 호출: 참조 바이트 + APT 윈도우 시작 ────────────────
        if (!is_initialized) {
            last_byte = generatedByte;
            repeat_count = 1u;
            is_initialized = true;

            // APT 윈도우 초기화
            apt_sample = generatedByte;
            apt_count = 1u;
            apt_window_pos = 1u;
            ent_critical_exit(pm);
            return;
        }

        // ══════════════════════════════════════════════════════════
        //  [1] RCT — 브랜치리스 카운터
        // ══════════════════════════════════════════════════════════
        const uint32_t is_same = static_cast<uint32_t>(
            generatedByte == last_byte);
        repeat_count = (repeat_count * is_same) + 1u;

        if (repeat_count >= NIST_RCT_CUTOFF) {
            // TRNG Stuck-at Fault → 0xEEEEEEEE
            fault_code = 0xEEEEEEEEu;
        }
        last_byte = generatedByte;

        // ══════════════════════════════════════════════════════════
        //  [2] APT — 윈도우 내 편향 감지
        // ══════════════════════════════════════════════════════════
        if (apt_window_pos == 0u) {
            // 새 윈도우 시작: 첫 샘플 기록
            apt_sample = generatedByte;
            apt_count = 1u;
            apt_window_pos = 1u;
        }
        else {
            // 윈도우 진행: 기준값과 비교
            if (generatedByte == apt_sample) {
                apt_count++;
            }
            apt_window_pos++;

            // 임계치 초과 → Bias Fault (윈도우 완료 전이라도 즉시 판정)
            if (apt_count >= APT_CUTOFF) {
                // TRNG Bias Fault → 0xEEEEAAAA
                fault_code = 0xEEEEAAAAu;
            }

            // 윈도우 완료 → 리셋 (다음 호출에서 새 윈도우 시작)
            if (apt_window_pos >= APT_WINDOW_SIZE) {
                apt_window_pos = 0u;
                apt_count = 0u;
            }
        }
        ent_critical_exit(pm);
        if (fault_code != 0u) {
            Entropy_Fault_Handler(fault_code);
        }
    }

} // namespace ProtectedEngine
