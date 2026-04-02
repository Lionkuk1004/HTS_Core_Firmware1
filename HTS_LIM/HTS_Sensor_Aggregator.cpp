// =========================================================================
// HTS_Sensor_Aggregator.cpp
// 센서 HAL + 샘플링 스케줄러 구현부
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// [설계]
//  · ADC DMA ISR → On_ADC_DMA_Complete (4채널 일괄)
//  · I2C ISR → On_Accel_Read (가속도)
//  · Tick: 주기 샘플링 + Fusion 전달 + 건강 감시
//  · 센서 고착: 동일값 10회 연속 → STUCK 판정
// =========================================================================
#include "HTS_Sensor_Aggregator.h"
#include "HTS_Sensor_Fusion.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <new>

namespace ProtectedEngine {

    // =====================================================================
    //  보안 소거 / PRIMASK
    // =====================================================================
    static void Agg_Secure_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) { q[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(q) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
    static inline uint32_t agg_critical_enter() noexcept {
        uint32_t primask;
        __asm volatile ("MRS %0, PRIMASK\n CPSID I"
        : "=r"(primask) :: "memory");
        return primask;
    }
    static inline void agg_critical_exit(uint32_t pm) noexcept {
        __asm volatile ("MSR PRIMASK, %0" :: "r"(pm) : "memory");
    }
#else
    static inline uint32_t agg_critical_enter() noexcept { return 0u; }
    static inline void agg_critical_exit(uint32_t) noexcept {}
#endif

    // =====================================================================
    //  ADC → 물리값 변환 (NTC 서미스터 근사)
    //
    //  NTC 10K@25°C, B=3950:
    //   ADC 12비트 (0-4095) → 전압 비 → 온도
    //   간소화: 선형 근사 (0°C=ADC2048, 100°C=ADC512)
    //   temp_x10 = (2048 - adc) × 650 / 1536
    //   → (2048 - adc) × 650 >> 10 (근사, ÷1024)
    // =====================================================================
    static int16_t adc_to_temp_x10(uint16_t adc) noexcept {
        const int32_t diff = 2048 - static_cast<int32_t>(adc);
        return static_cast<int16_t>((diff * 650) >> 10);
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
        return (pct > 100u) ? 100u : static_cast<uint8_t>(pct);
    }

    // =====================================================================
    //  센서 채널 상태
    // =====================================================================
    struct ChannelState {
        uint16_t     last_raw;
        uint8_t      stuck_count;   // 동일값 연속 횟수
        SensorHealth health;
        uint8_t      pad;
    };

    static_assert(sizeof(ChannelState) == 6u, "ChannelState size");

    // (센서 고착 임계는 Impl::STALE_THRESHOLD / STUCK_EXT_THRESHOLD에서 정의)

    // =====================================================================
    //  Pimpl 구현 구조체
    // =====================================================================
    struct HTS_Sensor_Aggregator::Impl {
        // ADC 원시값 (DMA ISR에서 기록)
        uint16_t adc_raw[NUM_ADC_CH] = {};   // temp, smoke, humid, wind
        uint16_t accel_raw = 0u;
        bool     accel_ok = false;

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
        //  수정: 3단계 에스컬레이션 + 명확한 복구 경로
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

        void check_stuck(size_t idx, uint16_t raw) noexcept {
            if (idx > NUM_ADC_CH) { return; }
            ChannelState& c = ch[idx];

            if (raw == c.last_raw) {
                // 동일값 연속
                if (c.stuck_count < 255u) { c.stuck_count++; }

                if (raw == 0u || raw == 4095u) {
                    // 극단값 고착: STALE_THRESHOLD 이상 → STUCK (확정)
                    if (c.stuck_count >= STALE_THRESHOLD) {
                        c.health = SensorHealth::STUCK;
                    }
                }
                else {
                    // 일반값 고착: 더 긴 임계 → STALE (의심)
                    if (c.stuck_count >= STUCK_EXT_THRESHOLD) {
                        c.health = SensorHealth::STALE;
                    }
                }
            }
            else {
                // 값 변경 → 무조건 OK 복귀 (어떤 상태에서든)
                c.stuck_count = 0u;
                c.health = SensorHealth::OK;
            }
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
        return impl_valid_.load(std::memory_order_acquire)
            ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }

    const HTS_Sensor_Aggregator::Impl*
        HTS_Sensor_Aggregator::get_impl() const noexcept
    {
        return impl_valid_.load(std::memory_order_acquire)
            ? reinterpret_cast<const Impl*>(impl_buf_) : nullptr;
    }

    // =====================================================================
    //  생성자 / 소멸자
    // =====================================================================
    HTS_Sensor_Aggregator::HTS_Sensor_Aggregator() noexcept
        : impl_valid_(false)
    {
        Agg_Secure_Wipe(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl();
        impl_valid_.store(true, std::memory_order_release);
    }

    HTS_Sensor_Aggregator::~HTS_Sensor_Aggregator() noexcept {
        Impl* const p = reinterpret_cast<Impl*>(impl_buf_);
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
            p->adc_raw[i] = adc_buf[i];
        }
    }

    void HTS_Sensor_Aggregator::On_Accel_Read(
        uint16_t accel_mg, bool success) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        // ISR 콜백에서 호출되므로 PRIMASK 재조작 없이 즉시 갱신
        if (success) {
            p->accel_raw = accel_mg;
            p->accel_ok = true;
            p->ch[NUM_ADC_CH].health = SensorHealth::OK;
        }
        else {
            p->accel_ok = false;
            p->ch[NUM_ADC_CH].health = SensorHealth::FAIL;
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
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        if (p->first_tick) {
            p->last_sample_ms = systick_ms - p->get_period();
            p->first_tick = false;
        }

        const uint32_t period = p->get_period();
        const uint32_t elapsed = systick_ms - p->last_sample_ms;
        if (elapsed < period) { return; }

        //  기존: last = systick_ms → 지연 누적 → IIR 시정수 왜곡
        //  수정: last += period → 정확한 샘플링 주파수 유지
        //  안전 장치: 2주기 이상 밀린 경우 → 현재 시각으로 리셋 (폭주 방지)
        if (elapsed >= period * 2u) {
            p->last_sample_ms = systick_ms;  // 과도 지연: 리셋
        }
        else {
            p->last_sample_ms += period;     // 정상: 주기 누적
        }

        // 원시값 스냅샷 (크리티컬 보호)
        uint16_t snap_adc[NUM_ADC_CH] = {};
        uint16_t snap_accel = 0u;

        const uint32_t pm = agg_critical_enter();
        for (size_t i = 0u; i < NUM_ADC_CH; ++i) {
            snap_adc[i] = p->adc_raw[i];
        }
        snap_accel = p->accel_raw;
        agg_critical_exit(pm);

        // 건강 감시 (고착 검사)
        for (size_t i = 0u; i < NUM_ADC_CH; ++i) {
            p->check_stuck(i, snap_adc[i]);
        }
        p->check_stuck(NUM_ADC_CH, snap_accel);

        // ADC → 물리값 변환 + Fusion 전달
        fusion.Feed_Temperature(adc_to_temp_x10(snap_adc[0]));
        fusion.Feed_Smoke(snap_adc[1]);  // 연기: ADC 직접 전달
        fusion.Feed_Humidity(adc_to_humid_pct(snap_adc[2]));
        fusion.Feed_Wind(adc_to_wind_x10(snap_adc[3]));
        fusion.Feed_Accel(snap_accel);
    }

    // =====================================================================
    //  Shutdown
    // =====================================================================
    void HTS_Sensor_Aggregator::Shutdown() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        Agg_Secure_Wipe(p->adc_raw, sizeof(p->adc_raw));
        p->accel_raw = 0u;
    }

} // namespace ProtectedEngine
