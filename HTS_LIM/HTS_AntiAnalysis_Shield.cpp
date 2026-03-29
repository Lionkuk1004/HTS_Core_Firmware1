// =========================================================================
// HTS_AntiAnalysis_Shield.cpp
// 실행 속도 기반 디버거/에뮬레이터 탐지 + 기만적 붕괴 구현부
// Target: STM32F407 (Cortex-M4, 168MHz) / PC
//
// [양산 수정 — 10건]
//
//  ── 기존 (3건) ──
//  01: DWT CYCCNT 직접 사용 (std::chrono 제거)
//  02: 변수명 baseline_execution_us → ticks
//  03: 임계치 배수 10x 유지
//
//  ── 세션 8 전수검사 (BUG-04 ~ BUG-10) ──
//  BUG-04 [HIGH] atomic<uint64_t> → atomic<uint32_t> (ARM lock-free)
//  BUG-05 [MED]  Deploy() 빈 함수체 → SecureLogger 호출
//  BUG-06 [MED]  매직 넘버 상수화 (CHAOS_MASK, GOLDEN_RATIO 등)
//  BUG-07 [MED]  chaos_seed 보안 소거 누락
//  BUG-08 [LOW]  프로브 루프 횟수 PROBE_ITERATIONS 상수화
//  BUG-09 [MED]  static_assert 빌드타임 검증 추가
//  BUG-10 [HIGH] uint64_t → uint32_t 타이밍 통일 (ARM 단일 사이클)
//
// [제약] float 0, double 0, try-catch 0, 힙 0
// =========================================================================
#include "HTS_AntiAnalysis_Shield.h"
#include "HTS_Hardware_Bridge.hpp"
#include "HTS_Universal_API.h"
#include "HTS_Physical_Entropy_Engine.h"
#include "HTS_Secure_Logger.h"
#include <type_traits>
#include <limits>

#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
#include <bit>
#endif

namespace ProtectedEngine {

    // =====================================================================
    //  [BUG-06] 매직 넘버 상수화 (내부 링키지)
    // =====================================================================
    namespace {
        constexpr int      PROBE_ITERATIONS = 1000;    ///< 타이밍 프로브 루프 횟수
        constexpr int      CALIBRATION_ROUNDS = 5;       ///< 캘리브레이션 시행 횟수
        constexpr uint32_t TIMING_MULTIPLIER = 10u;     ///< 탐지 임계치 배수
        constexpr uint32_t DEFAULT_BASELINE = 5000u;   ///< DWT 미초기화 시 기본값
        constexpr uint32_t CHAOS_MASK = 0xAAAAAAAAu;  ///< 기만 붕괴 XOR 마스크
        constexpr uint32_t GOLDEN_RATIO = 0x9E3779B9u;  ///< 요소별 인덱스 혼합
    }

    // [BUG-09] 빌드 타임 검증
    static_assert(PROBE_ITERATIONS > 0,
        "PROBE_ITERATIONS must be positive");
    static_assert(TIMING_MULTIPLIER > 1u,
        "TIMING_MULTIPLIER must exceed 1");
    static_assert(DEFAULT_BASELINE > 0u,
        "DEFAULT_BASELINE must be non-zero");

    // =====================================================================
    //  정적 변수 초기화
    //  [BUG-04] uint64_t → uint32_t (ARM lock-free 보장)
    // =====================================================================
    std::atomic<uint32_t> AntiAnalysis_Shield::baseline_execution_ticks{ DEFAULT_BASELINE };
    std::atomic<uint32_t> AntiAnalysis_Shield::cal_state{ AntiAnalysis_Shield::CAL_UNINIT };

    // =====================================================================
    //  타이밍 프로브 — 고정 연산량 실행 후 소요 틱 측정
    //  [BUG-10] uint64_t → uint32_t (ARM 32비트 DWT CYCCNT 직접 사용)
    // =====================================================================
    static uint32_t Run_Timing_Probe() noexcept {
        const uint32_t start = static_cast<uint32_t>(
            Hardware_Bridge::Get_Physical_CPU_Tick());

        // 고정 연산량 (volatile → 컴파일러 최적화 제거 차단)
        volatile uint32_t dummy = 0;
        for (int i = 0; i < PROBE_ITERATIONS; ++i) {
            dummy ^= static_cast<uint32_t>(i);
        }

        // [BUG-13] 루프 삭제(DCE) 완전 차단
        // volatile만으로는 공격적 최적화기(-O3)가 "결과 미사용 dead store"로
        // 루프를 통째로 증발시킬 위험 있음.
        // asm volatile + memory clobber로 컴파일러가 dummy에 대해
        // "외부에서 관측 가능한 사이드 이펙트"가 있다고 강제 인식.
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(static_cast<uint32_t>(dummy)) : "memory");
#elif defined(_MSC_VER)
        // MSVC: volatile 읽기 자체가 side effect — 추가 방어
        volatile uint32_t sink = dummy;
        (void)sink;
#endif

        const uint32_t end = static_cast<uint32_t>(
            Hardware_Bridge::Get_Physical_CPU_Tick());

        if (end == start) return 0u;
        return end - start;
    }

    // =====================================================================
    //  [1] 캘리브레이션 — 부팅 직후 정상 속도 측정
    //
    //  [BUG-11] 3상 상태 머신으로 초기화 레이스 해소
    //
    //  기존: is_calibrated(bool) CAS(false→true) 후 측정 시작
    //    → 후발 스레드가 true를 보고 baseline을 읽지만, 아직 쓰레기값!
    //
    //  수정: cal_state 3상 (UNINIT → IN_PROGRESS → DONE)
    //    선발: CAS(0→1) 성공 → 측정 → store(baseline) → store(2)
    //    후발: CAS(0→1) 실패 → 상태가 2(DONE)일 때까지 spin-wait
    //          50회 spin 후에도 미완료 → DEFAULT_BASELINE 폴백 (안전)
    // =====================================================================
    void AntiAnalysis_Shield::Calibrate_Baseline() noexcept {
        // 선발 스레드: UNINIT → IN_PROGRESS 전환 시도
        uint32_t expected = CAL_UNINIT;
        if (!cal_state.compare_exchange_strong(expected, CAL_IN_PROGRESS,
            std::memory_order_acq_rel, std::memory_order_acquire)) {

            // 후발 스레드: 선발이 완료할 때까지 대기
            // spin-wait 최대 50회 (프로브 ~수백μs × 5회 ≈ ~2ms)
            if (expected == CAL_IN_PROGRESS) {
                for (int spin = 0; spin < 50; ++spin) {
                    if (cal_state.load(std::memory_order_acquire) == CAL_DONE) {
                        return;  // 선발 완료 → baseline 유효
                    }
                    // ARM: yield, x86: pause — 스핀 대기 전력 절감
#if defined(__GNUC__) || defined(__clang__)
#if defined(__arm__) || defined(__aarch64__)
                    __asm__ __volatile__("yield");
#else
                    __asm__ __volatile__("pause");
#endif
#elif defined(_MSC_VER)
                    _mm_pause();
#endif
                }
                // 타임아웃: 선발이 비정상 지연 → 기본값으로 안전 폴백
                // (baseline이 DEFAULT_BASELINE 그대로이므로 오탐보다는 안전)
            }
            return;  // 이미 DONE이거나 폴백 완료
        }

        // ── 선발 스레드 전용 구간 ──
        uint32_t min_ticks = std::numeric_limits<uint32_t>::max();

        for (int attempt = 0; attempt < CALIBRATION_ROUNDS; ++attempt) {
            uint32_t ticks = Run_Timing_Probe();
            if (ticks > 0u && ticks < min_ticks) {
                min_ticks = ticks;
            }
        }

        if (min_ticks == std::numeric_limits<uint32_t>::max()) {
            min_ticks = DEFAULT_BASELINE;
        }
        if (min_ticks == 0u) {
            min_ticks = 1u;
        }

        // baseline 먼저 쓰기 (release) → 후발이 읽을 때 유효값 보장
        baseline_execution_ticks.store(min_ticks, std::memory_order_release);

        // 상태 DONE 전환 (release) → 후발 spin-wait 해제
        cal_state.store(CAL_DONE, std::memory_order_release);
    }

    // =====================================================================
    //  [2] Deploy — 관측 탐지 시 감사 로그 + 기만 상태 돌입
    //  [BUG-05] 빈 함수체 → 최소한 감사 로그 기록
    // =====================================================================
    void AntiAnalysis_Shield::Deploy() noexcept {
        SecureLogger::logSecurityEvent(
            "ANTI_ANALYSIS_DEPLOY",
            "Observation detected — deceptive mode");
    }

    // =====================================================================
    //  [3] 관측 탐지 — 타이밍 프로브 기반
    //
    //  임계치 = baseline × TIMING_MULTIPLIER(10)
    //  디버거/에뮬레이터: 실행 속도 10~100배 저하 → 즉시 탐지
    //  포화 곱셈으로 uint32_t 래핑 오버플로 방어
    // =====================================================================
    bool AntiAnalysis_Shield::Is_Under_Observation() noexcept {
        if (cal_state.load(std::memory_order_acquire) != CAL_DONE) {
            Calibrate_Baseline();
        }

        uint32_t elapsed_ticks = Run_Timing_Probe();
        if (elapsed_ticks == 0u) return false;  // DWT 미초기화 → 오탐 방지

        uint32_t baseline = baseline_execution_ticks.load(std::memory_order_acquire);

        // 포화 곱셈 (오버플로 방어)
        constexpr uint32_t MAX_U32 = std::numeric_limits<uint32_t>::max();
        uint32_t threshold;

        if (baseline > MAX_U32 / TIMING_MULTIPLIER) {
            threshold = MAX_U32;
        }
        else {
            threshold = baseline * TIMING_MULTIPLIER;
        }

        if (elapsed_ticks > threshold) {
            Deploy();
            return true;
        }

        return false;
    }

    // =====================================================================
    //  [4] 기만적 붕괴 — 패턴 분석 무력화
    //
    //  요소별 인덱스 혼합 마스크 + 비트 회전 + 최종 흔적 소각
    //  unsigned 타입만 허용 (비트 연산 안전)
    //  [BUG-07] chaos_seed 보안 소거 추가
    // =====================================================================
    template <typename T>
    void AntiAnalysis_Shield::Trigger_Deceptive_Collapse(
        T* tensor_data, size_t elements) noexcept {

        static_assert(std::is_unsigned<T>::value,
            "T must be an unsigned integer type for safe bitwise operations.");

        if (!tensor_data || elements == 0) return;

        uint32_t chaos_seed = Physical_Entropy_Engine::Extract_Quantum_Seed();

#if !(__cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L))
        constexpr unsigned int bit_width = static_cast<unsigned int>(sizeof(T) * 8u);
        constexpr unsigned int shift_left = 3u;
        constexpr unsigned int shift_right = bit_width - shift_left;
#endif

        for (size_t i = 0; i < elements; ++i) {
            // [BUG-06] 매직 넘버 → 상수 사용
            uint32_t per_element_mask = chaos_seed
                ^ CHAOS_MASK
                ^ static_cast<uint32_t>(i * GOLDEN_RATIO);

            tensor_data[i] ^= static_cast<T>(per_element_mask);

#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
            tensor_data[i] = std::rotl(tensor_data[i], 3);
#else
            // [BUG-12+14] 정수 승격 UB 방어 + 64비트 타입 시프트 안전
            //
            // T=uint64_t일 때 shift_right=61 → unsigned int(32비트) >> 61 = UB
            // 수정: T 자체 너비의 정수형으로 연산
            constexpr T type_mask = static_cast<T>(~T(0));
            const T val = tensor_data[i] & type_mask;
            tensor_data[i] = static_cast<T>(
                ((val << shift_left) | (val >> shift_right)) & type_mask);
#endif
        }

        // 최종 흔적 소각
        Universal_API::Absolute_Trace_Erasure(tensor_data, elements * sizeof(T));

        // [BUG-07] chaos_seed 보안 소거 — 스택 잔류 방지
        // volatile 포인터로 컴파일러 최적화 차단
        volatile uint32_t* vp = &chaos_seed;
        *vp = 0u;
    }

    // 명시적 템플릿 인스턴스화
    template void AntiAnalysis_Shield::Trigger_Deceptive_Collapse<uint8_t>(uint8_t*, size_t) noexcept;
    template void AntiAnalysis_Shield::Trigger_Deceptive_Collapse<uint16_t>(uint16_t*, size_t) noexcept;
    template void AntiAnalysis_Shield::Trigger_Deceptive_Collapse<uint32_t>(uint32_t*, size_t) noexcept;
    template void AntiAnalysis_Shield::Trigger_Deceptive_Collapse<uint64_t>(uint64_t*, size_t) noexcept;

} // namespace ProtectedEngine