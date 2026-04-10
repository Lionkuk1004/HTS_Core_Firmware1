// =========================================================================
// HTS_Sensor_Aggregator.cpp
// 센서 HAL + 샘플링 스케줄러 구현부
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// [설계]
//  · ADC DMA ISR → On_ADC_DMA_Complete (4채널 일괄)
//  · I2C ISR → On_Accel_Read (가속도)
//  · Tick: 주기 샘플링 + Fusion 전달 + 건강 감시
//  · 센서 고착: 동일값 카운터(산술) + ADC 레일 0/4095 → STUCK/STALE; EMA 이탈 누적 → FAIL
//  · Tick 상단: ARM Release 시 DHCSR·OPTCR(RDP) 폴링(디버그/퓨즈 이완 시 자폭)
// =========================================================================
#include "HTS_Sensor_Aggregator.h"
#include "HTS_Sensor_Fusion.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <new>

#if defined(_MSC_VER)
#include <intrin.h>
#endif
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#include "HTS_Anti_Debug.h"
#include "HTS_Hardware_Init.h"
#endif

namespace ProtectedEngine {

#if !defined(HTS_SENSOR_AGG_SKIP_PHYS_TRUST)
#if defined(HTS_ALLOW_OPEN_DEBUG) || !defined(NDEBUG)
#define HTS_SENSOR_AGG_SKIP_PHYS_TRUST 1
#else
#define HTS_SENSOR_AGG_SKIP_PHYS_TRUST 0
#endif
#endif

#if HTS_SENSOR_AGG_SKIP_PHYS_TRUST == 0 && \
    (defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH))
    [[noreturn]] static void SensorAgg_PhysicalTrust_Fault() noexcept {
        Hardware_Init_Manager::Terminal_Fault_Action();
    }

    static void SensorAgg_AssertPhysicalTrustOrFault() noexcept {
        volatile const uint32_t* const dhcsr =
            reinterpret_cast<volatile const uint32_t*>(ADDR_DHCSR);
        const uint32_t d0 = *dhcsr;
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("dsb sy" ::: "memory");
#endif
        const uint32_t d1 = *dhcsr;
        if (d0 != d1) {
            SensorAgg_PhysicalTrust_Fault();
        }
        if ((d0 & DHCSR_DEBUG_MASK) != 0u) {
            SensorAgg_PhysicalTrust_Fault();
        }
        volatile const uint32_t* const optcr =
            reinterpret_cast<volatile const uint32_t*>(HTS_FLASH_OPTCR_ADDR);
        const uint32_t o0 = *optcr;
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("dsb sy" ::: "memory");
#endif
        const uint32_t o1 = *optcr;
        if (o0 != o1) {
            SensorAgg_PhysicalTrust_Fault();
        }
        const uint32_t rdp = (o0 & HTS_RDP_OPTCR_MASK) >> 8u;
        if (rdp != HTS_RDP_EXPECTED_BYTE_VAL) {
            SensorAgg_PhysicalTrust_Fault();
        }
    }
#else
    static void SensorAgg_AssertPhysicalTrustOrFault() noexcept {}
#endif

    // =====================================================================
    //  보안 소거 (PRIMASK 미사용 — ADC/가속도는 atomic<uint16_t> lock-free)
    // =====================================================================
    static void Agg_Secure_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) { q[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(q) : "memory");
#elif defined(_MSC_VER)
        _ReadWriteBarrier();
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  ADC → 물리값 변환 (NTC 서미스터 근사)
    //
    //  NTC 10K@25°C, B=3950:
    //   ADC 12비트 (0-4095) → 전압 비 → 온도
    //   간소화: 선형 근사 (0°C=ADC2048, 100°C=ADC512)
    //   temp_x10 = (2048 - adc) × 650 / 1536
    //   MISRA: 음수 비트 시프트 금지 → 상수 나눗셈(/1024)으로 근사(컴파일러가 안전 시프트로 치환)
    // =====================================================================
    static int16_t adc_to_temp_x10(uint16_t adc) noexcept {
        const int32_t diff = 2048 - static_cast<int32_t>(adc);
        return static_cast<int16_t>((diff * 650) / 1024);
    }

    // 풍속: 열선 풍속계 선형 근사
    // ADC 0=0m/s, ADC 4095=50m/s → wind_x10 = adc × 500 / 4095
    // 근사: adc × 500 >> 12 (÷4096)
    static uint16_t adc_to_wind_x10(uint16_t adc) noexcept {
        return static_cast<uint16_t>(
            (static_cast<uint32_t>(adc) * 500u) >> 12u);
    }

    // 습도: 저항형 습도센서 선형 근사
    // ADC 0=0%, ADC 4095=100% → pct = adc × 100 / 4095
    // 근사: adc × 100 >> 12
    static uint8_t adc_to_humid_pct(uint16_t adc) noexcept {
        const uint32_t pct = (static_cast<uint32_t>(adc) * 100u) >> 12u;
        return static_cast<uint8_t>(pct);
    }

    // =====================================================================
    //  센서 채널 상태
    // =====================================================================
    struct ChannelState {
        uint16_t     last_raw;
        uint16_t     ema;           // IIR 저역 (EMA) — 진동/단선 노이즈 대비 기준
        uint8_t      stuck_count;   // 동일값 연속 (산술 갱신, 분기 최소화)
        uint8_t      noise_count;   // EMA 대비 과도 편차 연속
        SensorHealth health;
        uint8_t      flags;         // bit0: ema 시드 완료
    };

    static_assert(sizeof(ChannelState) == 8u, "ChannelState size");

    // (센서 고착 임계는 Impl::STALE_THRESHOLD / STUCK_EXT_THRESHOLD에서 정의)

    // =====================================================================
    //  Pimpl 구현 구조체
    // =====================================================================
    struct HTS_Sensor_Aggregator::Impl {
        // ADC/가속도: ISR·Tick lock-free (aligned 16-bit atomic)
        std::atomic<uint16_t> adc_raw[NUM_ADC_CH] = {};   // temp, smoke, humid, wind
        std::atomic<uint16_t> accel_raw{ 0u };
        std::atomic<bool>     accel_ok{ false };

        // 채널 건강
        ChannelState ch[NUM_ADC_CH + 1u] = {};  // +1 = 가속도

        // 샘플링
        uint32_t last_sample_ms = 0u;
        bool     fast_mode = false;
        bool     first_tick = true;

        explicit Impl() noexcept = default;
        ~Impl() noexcept = default;

        uint32_t get_period() const noexcept {
            return fast_mode ? FAST_PERIOD_MS : NORMAL_PERIOD_MS;
        }

        // ──────────────────────────────────────────────────
        //  센서 건강 상태 머신 (3단계 판정)
        //
        //  3단계 에스컬레이션 + 명확한 복구 경로
        //
        //  상태 전이:
        //   OK ──(동일값 10회)──→ STALE ──(+0/4095)──→ STUCK
        //    ↑                      ↑                     │
        //    └──(값 변경)───────────┘──(값 변경)──────────┘
        //
        //  STALE: 값이 변하지 않음 (고착 의심, 정상일 수도)
        //  STUCK: 극단값(0/4095) 고착 (센서 단선/단락 확정)
        // ──────────────────────────────────────────────────
        static constexpr uint8_t STALE_THRESHOLD = 10u;
        static constexpr uint8_t STUCK_EXT_THRESHOLD = 20u;
        static constexpr uint32_t OUTLIER_DEV = 320u;       // 12비트 풀스케일 대비 ~8%
        static constexpr uint8_t NOISE_FAIL_THRESHOLD = 8u;

        void check_stuck(size_t idx, uint16_t raw) noexcept {
            if (idx > NUM_ADC_CH) { return; }
            ChannelState& c = ch[idx];

            if ((c.flags & 1u) == 0u) {
                c.ema = raw;
                c.flags |= 1u;
            }
            else {
                if (idx < NUM_ADC_CH) {
                    const int32_t d_prev =
                        static_cast<int32_t>(raw) - static_cast<int32_t>(c.ema);
                    const uint32_t absd =
                        static_cast<uint32_t>(d_prev < 0 ? -d_prev : d_prev);
                    const uint32_t outlier = (absd > OUTLIER_DEV) ? 1u : 0u;
                    c.noise_count = static_cast<uint8_t>(
                        (static_cast<uint32_t>(c.noise_count) + 1u) * outlier);
                }
                c.ema = static_cast<uint16_t>(
                    (static_cast<uint32_t>(c.ema) * 15u + static_cast<uint32_t>(raw)) / 16u);
            }

            const uint32_t is_same = (raw == c.last_raw) ? 1u : 0u;
            c.stuck_count = static_cast<uint8_t>(
                (static_cast<uint32_t>(c.stuck_count) + 1u) * is_same);
            const uint32_t is_diff = 1u - is_same;

            const uint32_t is_ext_adc =
                (idx < NUM_ADC_CH)
                ? (static_cast<uint32_t>(raw == 0u) | static_cast<uint32_t>(raw == 4095u))
                : 0u;

            uint8_t h = static_cast<uint8_t>(
                static_cast<uint8_t>(c.health) * is_same
                + static_cast<uint8_t>(SensorHealth::OK) * is_diff);

            if (c.noise_count >= NOISE_FAIL_THRESHOLD) {
                h = static_cast<uint8_t>(SensorHealth::FAIL);
            }
            else if (is_same != 0u) {
                if (is_ext_adc != 0u && c.stuck_count >= STALE_THRESHOLD) {
                    h = static_cast<uint8_t>(SensorHealth::STUCK);
                }
                else if (is_ext_adc == 0u && c.stuck_count >= STUCK_EXT_THRESHOLD) {
                    h = static_cast<uint8_t>(SensorHealth::STALE);
                }
            }

            c.health = static_cast<SensorHealth>(h);
            c.last_raw = raw;
        }
    };

    // =====================================================================
    //  get_impl
    // =====================================================================
    HTS_Sensor_Aggregator::Impl*
        HTS_Sensor_Aggregator::get_impl() noexcept
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE를 초과합니다");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 초과");
        if (!impl_valid_.load(std::memory_order_acquire)) {
            return nullptr;
        }
        return std::launder(reinterpret_cast<Impl*>(impl_buf_));
    }

    const HTS_Sensor_Aggregator::Impl*
        HTS_Sensor_Aggregator::get_impl() const noexcept
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE를 초과합니다");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 초과");
        if (!impl_valid_.load(std::memory_order_acquire)) {
            return nullptr;
        }
        return std::launder(reinterpret_cast<const Impl*>(impl_buf_));
    }

    // =====================================================================
    //  생성자 / 소멸자
    // =====================================================================
    HTS_Sensor_Aggregator::HTS_Sensor_Aggregator() noexcept
        : impl_valid_(false)
    {
        Agg_Secure_Wipe(impl_buf_, sizeof(impl_buf_));
        // LTO: placement new 직전 소거 DCE 방지 + 패딩 0 유지
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(impl_buf_) : "memory");
#elif defined(_MSC_VER)
        _ReadWriteBarrier();
#endif
        ::new (static_cast<void*>(impl_buf_)) Impl();
        impl_valid_.store(true, std::memory_order_release);
    }

    HTS_Sensor_Aggregator::~HTS_Sensor_Aggregator() noexcept {
        Impl* const p = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        const bool was_valid = impl_valid_.exchange(false, std::memory_order_acq_rel);
        if (was_valid) { p->~Impl(); }
        Agg_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
    }

    // =====================================================================
    //  ISR 콜백
    // =====================================================================
    void HTS_Sensor_Aggregator::On_ADC_DMA_Complete(
        const uint16_t* adc_buf) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr || adc_buf == nullptr) { return; }

        // ISR 콜백에서 호출되므로 PRIMASK 재조작 없이 즉시 스냅샷 반영
        for (size_t i = 0u; i < NUM_ADC_CH; ++i) {
            p->adc_raw[i].store(adc_buf[i], std::memory_order_relaxed);
        }
    }

    void HTS_Sensor_Aggregator::On_Accel_Read(
        uint16_t accel_mg, bool success) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        // ISR: 원시값·통신 성공 플래그만 갱신 — health는 Tick 단일 컨텍스트에서만 갱신
        if (success) {
            p->accel_raw.store(accel_mg, std::memory_order_relaxed);
            p->accel_ok.store(true, std::memory_order_relaxed);
        }
        else {
            p->accel_ok.store(false, std::memory_order_relaxed);
        }
    }

    // =====================================================================
    //  샘플링 제어 / 건강 조회
    // =====================================================================
    void HTS_Sensor_Aggregator::Set_Fast_Mode(bool fast) noexcept {
        Impl* p = get_impl();
        if (p != nullptr) { p->fast_mode = fast; }
    }

    SensorHealth HTS_Sensor_Aggregator::Get_Health(
        uint8_t channel) const noexcept
    {
        const Impl* p = get_impl();
        if (p == nullptr || channel > NUM_ADC_CH) {
            return SensorHealth::FAIL;
        }
        return p->ch[channel].health;
    }

    bool HTS_Sensor_Aggregator::All_Healthy() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) { return false; }
        for (size_t i = 0u; i <= NUM_ADC_CH; ++i) {
            if (p->ch[i].health != SensorHealth::OK) {
                return false;
            }
        }
        return true;
    }

    // =====================================================================
    //  Tick — 주기 샘플링 + Fusion 전달 + 건강 감시
    // =====================================================================
    void HTS_Sensor_Aggregator::Tick(
        uint32_t systick_ms,
        HTS_Sensor_Fusion& fusion) noexcept
    {
        SensorAgg_AssertPhysicalTrustOrFault();

        Impl* p = get_impl();
        if (p == nullptr) { return; }

        if (p->first_tick) {
            p->last_sample_ms = systick_ms - p->get_period();
            p->first_tick = false;
        }

        const uint32_t period = p->get_period();
        const uint32_t elapsed = systick_ms - p->last_sample_ms;
        if (elapsed < period) { return; }

        //  last = systick_ms → 지연 누적 → IIR 시정수 왜곡
        //  last += period → 정확한 샘플링 주파수 유지
        //  안전 장치: 2주기 이상 밀린 경우 → 현재 시각으로 리셋 (폭주 방지)
        if (elapsed >= period * 2u) {
            p->last_sample_ms = systick_ms;  // 과도 지연: 리셋
        }
        else {
            p->last_sample_ms += period;     // 정상: 주기 누적
        }

        uint16_t snap_adc[NUM_ADC_CH] = {};
        for (size_t i = 0u; i < NUM_ADC_CH; ++i) {
            snap_adc[i] = p->adc_raw[i].load(std::memory_order_relaxed);
        }
        const uint16_t snap_accel =
            p->accel_raw.load(std::memory_order_relaxed);

        for (size_t i = 0u; i < NUM_ADC_CH; ++i) {
            p->check_stuck(i, snap_adc[i]);
        }

        if (!p->accel_ok.load(std::memory_order_relaxed)) {
            ChannelState& ac = p->ch[NUM_ADC_CH];
            ac.health = SensorHealth::FAIL;
            ac.stuck_count = 0u;
            ac.noise_count = 0u;
            ac.flags = 0u;
            ac.last_raw = 0xFFFFu;
            ac.ema = 0u;
        }
        else {
            p->check_stuck(NUM_ADC_CH, snap_accel);
        }

        // ADC → 물리값 변환 + Fusion 전달
        fusion.Feed_Temperature(adc_to_temp_x10(snap_adc[0]));
        fusion.Feed_Smoke(snap_adc[1]);  // 연기: ADC 직접 전달
        fusion.Feed_Humidity(adc_to_humid_pct(snap_adc[2]));
        fusion.Feed_Wind(adc_to_wind_x10(snap_adc[3]));
        fusion.Feed_Accel(snap_accel);
    }

    // =====================================================================
    //  Shutdown — 객체가 살아 있는 채 종료 시에도 ADC/채널 이력 잔류 방지
    // =====================================================================
    void HTS_Sensor_Aggregator::Shutdown() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        for (size_t i = 0u; i < NUM_ADC_CH; ++i) {
            p->adc_raw[i].store(0u, std::memory_order_relaxed);
        }
        p->accel_raw.store(0u, std::memory_order_relaxed);
        p->accel_ok.store(false, std::memory_order_relaxed);
        Agg_Secure_Wipe(p->ch, sizeof(p->ch));
        p->last_sample_ms = 0u;
        p->fast_mode = false;
        p->first_tick = true;
    }

} // namespace ProtectedEngine
