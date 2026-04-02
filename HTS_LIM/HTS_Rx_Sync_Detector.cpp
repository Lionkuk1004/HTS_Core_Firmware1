// =========================================================================
// HTS_Rx_Sync_Detector.cpp
// B-CDMA CFAR 기반 동기화 피크 검출기 구현부 (Pimpl 은닉)
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
#include "HTS_Rx_Sync_Detector.h"

// 내부 전용 includes (헤더에 미노출)
#include "HTS_Dynamic_Config.h"
#include "HTS_RF_Metrics.h"     // SNR 프록시 기록용 (선택적)

// ── Self-Contained 표준 헤더 [BUG-07] ───────────────────────────────
#include <atomic>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#if defined(_MSC_VER)
#include <intrin.h>             // _BitScanReverse (CLZ 등가)
#endif

// ── 플랫폼 검증 (BUG-03: 헤더→.cpp 이동) ──────────────────────────
static_assert(sizeof(int32_t) == 4,
    "[HTS_Sync] int32_t != 4 bytes: CFAR accumulator arithmetic will break");
static_assert(sizeof(size_t) >= 2,
    "[HTS_Sync] size_t too narrow for expected buffer sizes");

namespace ProtectedEngine {
    static void Rx_Sync_Detector_Secure_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) { q[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(q) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }


    // =====================================================================
    //  보안 소거 (volatile + asm clobber + seq_cst)
    //  상태 없는 검출기이지만 impl_buf_ 이중 소거를 위해 유지
    // =====================================================================
    static void SecWipe_Sync(void* ptr, size_t size) noexcept {
        if (ptr == nullptr || size == 0u) { return; }
        volatile unsigned char* p =
            static_cast<volatile unsigned char*>(ptr);
        for (size_t i = 0u; i < size; ++i) { p[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // ── CFAR 상수 ───────────────────────────────────────────────────────
    static constexpr int32_t MIN_CFAR_MULTIPLIER = 1;

    // =====================================================================
    //  Pimpl 구현 구조체
    // =====================================================================
    struct HTS_Rx_Sync_Detector::Impl {
        HTS_Phy_Config current_config = {};
        int32_t        threshold_multiplier = MIN_CFAR_MULTIPLIER;

        explicit Impl(HTS_Phy_Tier tier) noexcept
            : current_config(HTS_Phy_Config_Factory::make(tier))
            , threshold_multiplier(current_config.cfar_default_mult)
        {
            if (threshold_multiplier < MIN_CFAR_MULTIPLIER) {
                threshold_multiplier = MIN_CFAR_MULTIPLIER;
            }
        }

        ~Impl() noexcept = default;
    };

    // =====================================================================
    // =====================================================================
    HTS_Rx_Sync_Detector::Impl*
        HTS_Rx_Sync_Detector::get_impl() noexcept {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE(256B)를 초과합니다 — 버퍼 크기를 늘려주세요");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 요구가 impl_buf_ alignas(8)을 초과합니다");
        return impl_valid_.load(std::memory_order_acquire)
            ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }

    const HTS_Rx_Sync_Detector::Impl*
        HTS_Rx_Sync_Detector::get_impl() const noexcept {
        return impl_valid_.load(std::memory_order_acquire)
            ? reinterpret_cast<const Impl*>(impl_buf_)
            : nullptr;
    }

    // =====================================================================
    // =====================================================================
    HTS_Rx_Sync_Detector::HTS_Rx_Sync_Detector(
        HTS_Phy_Tier tier) noexcept
        : impl_valid_(false)
    {
        SecWipe_Sync(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl(tier);
        impl_valid_.store(true, std::memory_order_release);
    }

    // =====================================================================
    // =====================================================================
    HTS_Rx_Sync_Detector::~HTS_Rx_Sync_Detector() noexcept {
        Impl* p = get_impl();
        if (p != nullptr) {
            p->~Impl();
            Rx_Sync_Detector_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
        }
        SecWipe_Sync(impl_buf_, sizeof(impl_buf_));
        impl_valid_.store(false, std::memory_order_release);
    }

    // =====================================================================
    //  Set_CFAR_Multiplier — CFAR 배수 동적 조정 [FIX-04]
    // =====================================================================
    void HTS_Rx_Sync_Detector::Set_CFAR_Multiplier(
        int32_t multiplier) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        p->threshold_multiplier =
            (multiplier < MIN_CFAR_MULTIPLIER)
            ? MIN_CFAR_MULTIPLIER : multiplier;
    }

    int32_t HTS_Rx_Sync_Detector::Get_CFAR_Multiplier() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? p->threshold_multiplier : MIN_CFAR_MULTIPLIER;
    }

    // =====================================================================
    //  uint8_t → uint32_t (향후 256+ 칩 확장 대비)
    // =====================================================================
    uint32_t HTS_Rx_Sync_Detector::Get_Chip_Count() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) { return 0u; }
        return static_cast<uint32_t>(p->current_config.chip_count);
    }

    int32_t HTS_Rx_Sync_Detector::Get_Default_CFAR_Mult() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr)
            ? p->current_config.cfar_default_mult
            : MIN_CFAR_MULTIPLIER;
    }

    // =====================================================================
    //  Detect_Sync_Peak — CFAR 피크 검출
    //
    //    energy_sum(양수) / buffer_size(전체) → 과소평가
    //    → 음수 50% 시 noise_floor가 절반 → 임계치 절반 → 오탐 폭증
    //    수정: energy_sum(양수) / positive_count(양수만) → 정확한 평균
    //
    //    기존: O(2N) 두 번 순회 → SRAM 이중 로드 → 대역폭 50% 낭비
    //    수정: 1회 순회로 energy_sum + max_value/max_index 동시 추적
    //
    // =====================================================================
    int32_t HTS_Rx_Sync_Detector::Detect_Sync_Peak(
        const int32_t* correlation_buffer,
        size_t         buffer_size,
        HTS_RF_Metrics* p_metrics) noexcept
    {
        if (correlation_buffer == nullptr) { return -1; }
        if (buffer_size == 0u) { return -1; }

        Impl* p = get_impl();
        if (p == nullptr) { return -1; }

        // ── 단일 O(N) 패스: 노이즈 + 피크 동시 추적 ─────────────────
        int64_t energy_sum = 0;
        size_t  positive_count = 0u;
        int64_t max_value = 0;
        int32_t max_index = -1;

        for (size_t i = 0u; i < buffer_size; ++i) {
            const int64_t val =
                static_cast<int64_t>(correlation_buffer[i]);

            // 양수 누산: 삼항 → ARM IT 블록 조건부 이동 (1사이클)
            energy_sum += (val > 0) ? val : 0;
            positive_count += (val > 0) ? 1u : 0u;

            // 피크 추적
            if (val > max_value) {
                max_value = val;
                max_index = static_cast<int32_t>(i);
            }
        }

        // 양수 0개: 신호 소실 → 즉시 동기 실패
        // p_metrics가 있으면 snr_proxy = 0 기록 (컨트롤러가 NOISY로 판단)
        if (positive_count == 0u) {
            if (p_metrics != nullptr) {
                p_metrics->snr_proxy.store(0, std::memory_order_release);
            }
            return -1;
        }

        //
        //  [문제]
        //   energy_sum: 양수 int32_t 누적 → 최대 buffer_size × INT32_MAX ≈ 2^43
        //   → int64_t / int64_t = __aeabi_ldivmod (~200cyc)
        //   → 나눗셈 결과(양수 평균)는 INT32_MAX 이내이므로 32비트 축소 가능
        //
        //  [기존] while(nf_num > INT32_MAX) { nf_num >>= 1; nf_den >>= 1; }
        //   → 순차 상태 머신: worst 13~14회 순회 ≈ 40~50cyc
        //
        //  [수정] __builtin_clz(hi) 1사이클로 시프트량 직접 산출 → 루프 0회
        //
        //  [유도]
        //   상위 32비트 hi = nf_num >> 32
        //   nf_num 유효 비트 수 = 64 - CLZ(hi)
        //   INT32_MAX = 31비트 → shift = max(0, 33 - CLZ(hi))
        //   hi == 0 → nf_num ≤ 0xFFFFFFFF → bit31 추출 (브랜치리스, 1cyc)
        //
        //  [검증]
        //   hi=1(CLZ=31): shift=2, 0x1FFFFFFFF>>2 = 0x7FFFFFFF ≤ INT32_MAX ✓
        //   hi=2(CLZ=30): shift=3, 0x2FFFFFFFF>>3 = 0x5FFFFFFF ≤ INT32_MAX ✓
        //   hi=0x800(2^43,CLZ=20): shift=13 → while 13회와 동일 결과 ✓
        //
        //  [성능] CLZ(1) + CMP(1) + LSR×2(2) + UDIV(12) = 고정 ~17cyc
        //         기존 while worst ~52cyc → 3× 가속
        //
        //  [정밀도] while 루프와 동일 — 동일 shift량 적용
        //    worst = buffer_size 4096 → shift=13 → 오차 ≤ 1 LSB (CFAR 무시 가능)
        int64_t  nf_num = energy_sum;
        uint32_t nf_den = static_cast<uint32_t>(positive_count);

        const uint32_t hi = static_cast<uint32_t>(
            static_cast<uint64_t>(nf_num) >> 32u);

        uint32_t shift = 0u;
        if (hi != 0u) {
            // hi > 0: nf_num > 0xFFFFFFFF
            // CLZ(hi) = 상위 32비트의 선행 제로 수 (0~31)
            // shift = 33 - CLZ(hi) → nf_num >> shift ≤ INT32_MAX
#if defined(__GNUC__) || defined(__clang__)
            // ARM Cortex-M4: CLZ = 1사이클 하드웨어 명령어
            shift = 33u - static_cast<uint32_t>(__builtin_clz(hi));
#elif defined(_MSC_VER)
            //  idx = MSB 위치 (0~31), CLZ = 31 - idx
            //  shift = 33 - (31 - idx) = idx + 2
            unsigned long idx = 0;
            const unsigned char bsr_ok =
                _BitScanReverse(&idx, static_cast<unsigned long>(hi));
            if (bsr_ok != 0u) {
                shift = static_cast<uint32_t>(idx) + 2u;
            }
            else {
                // hi!=0 조건에서 이 경로는 이론상 도달 불가.
                // 정적분석기 경고(C6031)와 방어 코딩을 위해 유지.
                shift = 1u;
            }
#else
            // 범용 폴백 (시뮬레이션 전용)
            uint32_t tmp = hi;
            uint32_t bits = 0u;
            while (tmp != 0u) { tmp >>= 1u; ++bits; }
            shift = bits + 1u;
#endif
        }
        else {
            // hi == 0: nf_num ≤ 0xFFFFFFFF
            // bit31 = 1 → nf_num > INT32_MAX → shift 1
            // bit31 = 0 → nf_num ≤ INT32_MAX → shift 0
            shift = static_cast<uint32_t>(nf_num) >> 31u;
        }

        nf_num >>= shift;
        //  기존: nf_den >>= shift → nf_den=1,shift=1 → nf_den=0 → 가드=1 → 2배 왜곡
        //  수정: nf_den가 shift를 수용 가능할 때만 시프트
        //  불가 시: nf_den 유지 → 결과는 noise_floor 과소추정 (보수적 CFAR, 안전)
        if (shift > 0u && nf_den >= (1u << shift)) {
            nf_den >>= shift;
        }
        if (nf_den == 0u) { nf_den = 1u; }

        // HW UDIV: 2~12사이클 (기존 __aeabi_ldivmod ~200사이클)
        const int32_t noise_floor_32 = static_cast<int32_t>(
            static_cast<uint32_t>(nf_num) / nf_den);
        // int64_t 승격: cfar_threshold 곱셈 및 max_value 비교용 (나눗셈 아님)
        const int64_t noise_floor = static_cast<int64_t>(noise_floor_32);

        const int64_t cfar_threshold =
            noise_floor *
            static_cast<int64_t>(p->threshold_multiplier);

        // ── SNR 프록시 계산 + metrics 기록 ───────────────────────────
        //   max_value: correlation_buffer[i]의 최대 → ≤ INT32_MAX (int32_t 원소)
        //   noise_floor_32: 양수 평균 → ≤ INT32_MAX
        //   snr_raw: max_value / noise_floor → ≤ INT32_MAX → 클램핑 불필요
        //   HW SDIV: 2~12사이클 (기존 __aeabi_ldivmod ~200사이클)
        if (p_metrics != nullptr) {
            const int32_t max_val_32 = static_cast<int32_t>(max_value);
            const int32_t snr_raw = (noise_floor_32 > 0)
                ? (max_val_32 / noise_floor_32)
                : 0;
            p_metrics->snr_proxy.store(snr_raw, std::memory_order_release);
        }

        return (max_value > cfar_threshold) ? max_index : -1;
    }

} // namespace ProtectedEngine
