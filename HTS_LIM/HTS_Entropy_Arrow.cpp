#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
#define HTS_LIKELY   [[likely]]
#define HTS_UNLIKELY [[unlikely]]
#else
#define HTS_LIKELY
#define HTS_UNLIKELY
#endif
// =========================================================================
// HTS_Entropy_Arrow.cpp
// 엔트로피 시간 화살 구현부 — DWT 틱 타이머(ARM) / steady_clock(PC)
// Target: STM32F407 (Cortex-M4, 168MHz)
//
#include "HTS_Entropy_Arrow.hpp"
#include <atomic>

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#define HTS_PLATFORM_ARM
#endif

#ifdef HTS_PLATFORM_ARM
#include "HTS_Hardware_Bridge.hpp"
#else
#include <chrono>
#endif

// C++20 비트 회전
#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
#include <bit>
#endif

namespace ProtectedEngine {

    // =====================================================================
    //  Fast_RotL64 — 비트 좌회전 (시프트 가드)
    // =====================================================================
    static inline uint64_t Fast_RotL64(uint64_t x, unsigned k) noexcept {
        k &= 63u;
        if (k == 0u) return x;
#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
        return std::rotl(x, static_cast<int>(k));
#else
        return (x << k) | (x >> (64u - k));
#endif
    }

#ifdef HTS_PLATFORM_ARM
    // =====================================================================
    //  ARM 전용 상수
    //  168MHz → 1ms = 168,000 틱
    //  최대 수명: 2^64 / 168,000,000 ≈ 1.1 × 10^11 초 (무한에 가까움)
    // =====================================================================
    static const uint64_t TICKS_PER_MS = 168000ULL;  // 168MHz / 1000

    // DWT CYCCNT 읽기 (32비트)
    static inline uint32_t Read_DWT_Tick() noexcept {
        return static_cast<uint32_t>(
            Hardware_Bridge::Get_Physical_CPU_Tick() & 0xFFFFFFFFu);
    }

    struct Entropy_Primask_Guard {
        uint32_t saved_;
        Entropy_Primask_Guard() noexcept {
            __asm__ __volatile__("mrs %0, primask\n\tcpsid i" : "=r"(saved_) :: "memory");
        }
        ~Entropy_Primask_Guard() noexcept {
            __asm__ __volatile__("msr primask, %0" :: "r"(saved_) : "memory");
        }
        Entropy_Primask_Guard(const Entropy_Primask_Guard&) = delete;
        Entropy_Primask_Guard& operator=(const Entropy_Primask_Guard&) = delete;
    };
#endif

    // =====================================================================
    //  생성자 — uint32_t(밀리초) 정수 기반
    //  최대 수명: 30일(2,592,000,000ms)
    // =====================================================================
    Entropy_Time_Arrow::Entropy_Time_Arrow(uint32_t lifespan_ms) noexcept {

        if (lifespan_ms == 0u) {
            lifespan_ms = 1000u;  // 최소 1초
        }
        else if (lifespan_ms > 2592000000u) {
            lifespan_ms = 2592000000u;  // 최대 30일
        }

#ifdef HTS_PLATFORM_ARM
        max_lifespan_ticks = static_cast<uint64_t>(lifespan_ms) * TICKS_PER_MS;
        last_tick = Read_DWT_Tick();
        total_elapsed_ticks = 0;
#else
        // A55 Linux / PC: steady_clock 기반
        max_lifespan_ms = static_cast<uint64_t>(lifespan_ms);
        creation_time = std::chrono::steady_clock::now();
#endif
    }

    // =====================================================================
    //  Validate_Or_Destroy — 수명 검증 + 만료 시 키 파쇄
    //
    //   미호출 시 틱 래핑만으로는 수명이 줄지 않을 수 있음 → MAX_SILENT_TICKS
    //   초과 시 즉시 파쇄(fail-safe). 정상·지연 호출은 아래 분기 참고.
    //
    //   Cortex-M: uint64_t 누적은 torn RMW 위험 → PRIMASK로 원자 갱신
    //
    //  [아키텍처 전제] 호출 간격 < 15초 필수 (BB1_Core_Engine: 매 프레임)
    // =====================================================================
    uint64_t Entropy_Time_Arrow::Validate_Or_Destroy(
        uint64_t current_session_id) noexcept {

        // 이미 붕괴 상태
        if (is_collapsed.load(std::memory_order_acquire)) HTS_UNLIKELY {
            return Generate_Chaos_Seed(current_session_id);
        }

#ifdef HTS_PLATFORM_ARM
            //  uint32_t 최대 = 4,294,967,295 → 25.5초 래핑
            //  15초 임계 → 래핑 공격 윈도우를 40.5초 이상으로 밀어냄
        static constexpr uint32_t MAX_SILENT_TICKS = 2520000000u;  // 15초 @168MHz

        bool collapse_now = false;
        bool expired = false;
        {
            Entropy_Primask_Guard irq_guard;
            const uint32_t now_tick = Read_DWT_Tick();
            const uint32_t delta = now_tick - last_tick;
            last_tick = now_tick;

            collapse_now = (delta > MAX_SILENT_TICKS);
            total_elapsed_ticks += static_cast<uint64_t>(delta);
            expired = (total_elapsed_ticks > max_lifespan_ticks);
        }

        if (collapse_now) HTS_UNLIKELY {
            is_collapsed.store(true, std::memory_order_release);
            return Generate_Chaos_Seed(current_session_id);
        }
        if (expired) HTS_UNLIKELY {
            is_collapsed.store(true, std::memory_order_release);
            return Generate_Chaos_Seed(current_session_id);
        }
#else
            // ── A55 Linux / PC: steady_clock 기반 경과 시간 계산 ─────────────────────
        auto now = std::chrono::steady_clock::now();
        uint64_t elapsed_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                now - creation_time).count());

        if (elapsed_ms > max_lifespan_ms) HTS_UNLIKELY {
            is_collapsed.store(true, std::memory_order_release);
            return Generate_Chaos_Seed(current_session_id);
        }
#endif

        // Force_Collapse()와의 경합 창구 차단:
        // 함수 진입 후 붕괴 플래그가 set된 경우라도 정상 세션 ID가
        // 1회 반환되지 않도록 반환 직전 재확인한다.
        if (is_collapsed.load(std::memory_order_acquire)) HTS_UNLIKELY {
            return Generate_Chaos_Seed(current_session_id);
        }
        return current_session_id;
    }

    // =====================================================================
    //  Force_Collapse — 즉시 자폭
    // =====================================================================
    void Entropy_Time_Arrow::Force_Collapse() noexcept {
        is_collapsed.store(true, std::memory_order_release);
    }

    // =====================================================================
    //  Generate_Chaos_Seed — 비가역 ARX 해시 키 파쇄
    //
    //  [보안 모델]
    //  입력: session_id + 시점 엔트로피 (DWT 틱 또는 steady_clock)
    //  → SplitMix64 변형 (Murmur3 계열 곱셈 + 우측 시프트)
    //  → Fast_RotL64 최종 비트 회전
    //  → 출력에서 원본 session_id 역산 수학적 불가
    //
    // =====================================================================
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC push_options
#pragma GCC optimize("O0")
#elif defined(_MSC_VER)
#pragma optimize("", off)
#endif

    uint64_t Entropy_Time_Arrow::Generate_Chaos_Seed(uint64_t input) const noexcept {
        // 시점 엔트로피 혼합 (플랫폼별)
#ifdef HTS_PLATFORM_ARM
        uint64_t time_entropy = static_cast<uint64_t>(Read_DWT_Tick());
#else
        uint64_t time_entropy = static_cast<uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count());
#endif

        uint64_t z = input + time_entropy;

        // SplitMix64 변형 — 비가역 혼합
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        z ^= (z >> 31);

        // 최종 비트 회전 (위치 고정화 방지)
        return Fast_RotL64(z, 13);
    }

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC pop_options
#elif defined(_MSC_VER)
#pragma optimize("", on)
#endif

} // namespace ProtectedEngine
