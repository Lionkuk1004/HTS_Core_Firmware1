// =========================================================================
// HTS_Rx_Sync_Detector.cpp
// B-CDMA CFAR 기반 동기화 피크 검출기 구현부 (Pimpl 은닉)
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
#include "HTS_Rx_Sync_Detector.h"

// 내부 전용 includes (헤더에 미노출)
#include "HTS_Dynamic_Config.h"
#include "HTS_RF_Metrics.h"
#include "HTS_Secure_Memory.h"

// ── Self-Contained 표준 헤더 (<atomic>, <cstdint> 등) ────────────────
#include <atomic>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

namespace {
/// 소멸자 op_busy_ 스핀 상한 — 무한 대기(WDT/프리징) 방지. 초과 시 강제 파쇄(타 스레드·ISR 동시 접근 시 UAF 위험).
constexpr uint32_t kDestructorSpinLimit = 10000000u;
} // namespace

// ── 플랫폼 검증 (int32_t/size_t) ───────────────────────────────────
static_assert(sizeof(int32_t) == 4,
    "[HTS_Sync] int32_t != 4 bytes: CFAR accumulator arithmetic will break");
static_assert(sizeof(size_t) >= 2,
    "[HTS_Sync] size_t too narrow for expected buffer sizes");

namespace ProtectedEngine {

    namespace {

        struct OpBusyGuard final {
            std::atomic_flag* f_;
            explicit OpBusyGuard(std::atomic_flag& fl) noexcept : f_(&fl) {
                while (f_->test_and_set(std::memory_order_acquire)) {
                }
            }
            ~OpBusyGuard() noexcept { f_->clear(std::memory_order_release); }
            OpBusyGuard(const OpBusyGuard&) = delete;
            OpBusyGuard& operator=(const OpBusyGuard&) = delete;
        };
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
            ? std::launder(reinterpret_cast<Impl*>(impl_buf_)) : nullptr;
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
        SecureMemory::secureWipe(static_cast<void*>(impl_buf_), sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl(tier);
        impl_valid_.store(true, std::memory_order_release);
    }

    // =====================================================================
    // =====================================================================
    HTS_Rx_Sync_Detector::~HTS_Rx_Sync_Detector() noexcept {
        uint32_t spins = 0;
        while (op_busy_.test_and_set(std::memory_order_acquire)) {
            if (++spins >= kDestructorSpinLimit) {
                break;
            }
        }
        Impl* const p = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        const bool was_valid = impl_valid_.exchange(false, std::memory_order_acq_rel);
        if (was_valid) { p->~Impl(); }
        SecureMemory::secureWipe(static_cast<void*>(impl_buf_), sizeof(impl_buf_));
        op_busy_.clear(std::memory_order_release);
    }

    // =====================================================================
    //  Set_CFAR_Multiplier — CFAR 배수 동적 조정
    // =====================================================================
    void HTS_Rx_Sync_Detector::Set_CFAR_Multiplier(
        int32_t multiplier) noexcept
    {
        OpBusyGuard guard(op_busy_);
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        p->threshold_multiplier =
            (multiplier < MIN_CFAR_MULTIPLIER)
            ? MIN_CFAR_MULTIPLIER : multiplier;
    }

    int32_t HTS_Rx_Sync_Detector::Get_CFAR_Multiplier() const noexcept {
        OpBusyGuard guard(op_busy_);
        const Impl* p = get_impl();
        return (p != nullptr) ? p->threshold_multiplier : MIN_CFAR_MULTIPLIER;
    }

    // =====================================================================
    //  uint8_t → uint32_t (향후 256+ 칩 확장 대비)
    // =====================================================================
    uint32_t HTS_Rx_Sync_Detector::Get_Chip_Count() const noexcept {
        OpBusyGuard guard(op_busy_);
        const Impl* p = get_impl();
        if (p == nullptr) { return 0u; }
        return static_cast<uint32_t>(p->current_config.chip_count);
    }

    int32_t HTS_Rx_Sync_Detector::Get_Default_CFAR_Mult() const noexcept {
        OpBusyGuard guard(op_busy_);
        const Impl* p = get_impl();
        return (p != nullptr)
            ? p->current_config.cfar_default_mult
            : MIN_CFAR_MULTIPLIER;
    }

    // =====================================================================
    //  Detect_Sync_Peak — CFAR 피크 검출
    //
    //  임계 판별(무 나눗셈): max_value * N_pos > energy_sum * k
    //   ⇔ max_value > (energy_sum / N_pos) * k  (N_pos > 0)
    //
    //  SNR 프록시(metrics 전용): energy_sum/N_pos, max/NF — 32비트 나눗셈 격리
    // =====================================================================
    int32_t HTS_Rx_Sync_Detector::Detect_Sync_Peak(
        const int32_t* correlation_buffer,
        size_t         buffer_size,
        HTS_RF_Metrics* p_metrics) noexcept
    {
        if (correlation_buffer == nullptr) { return -1; }
        if (buffer_size == 0u) { return -1; }

        OpBusyGuard guard(op_busy_);

        Impl* p = get_impl();
        if (p == nullptr) { return -1; }

        int64_t energy_sum = 0LL;
        size_t  positive_count = 0u;
        int64_t max_value = 0LL;
        int32_t max_index = -1;

        for (size_t i = 0u; i < buffer_size; ++i) {
            const int64_t val =
                static_cast<int64_t>(
                    correlation_buffer[static_cast<size_t>(i)]);

            energy_sum += (val > 0) ? val : 0;
            positive_count += (val > 0) ? 1u : 0u;

            if (val > max_value) {
                max_value = val;
                max_index = static_cast<int32_t>(i);
            }
        }

        if (positive_count == 0u) {
            if (p_metrics != nullptr) {
                p_metrics->snr_proxy.store(0, std::memory_order_release);
            }
            return -1;
        }

        const int64_t mult =
            static_cast<int64_t>(p->threshold_multiplier);
        const int64_t lhs =
            max_value * static_cast<int64_t>(positive_count);
        const int64_t rhs = energy_sum * mult;

        const bool peak_ok = (lhs > rhs);

        if (p_metrics != nullptr) {
            const int32_t max_val_32 = static_cast<int32_t>(max_value);
            int32_t noise_floor_32 = 0;
            if (positive_count > 0u) {
                noise_floor_32 = static_cast<int32_t>(
                    energy_sum / static_cast<int64_t>(positive_count));
            }
            if (noise_floor_32 <= 0) {
                p_metrics->snr_proxy.store(0, std::memory_order_release);
            }
            else {
                const int32_t snr_raw = max_val_32 / noise_floor_32;
                p_metrics->snr_proxy.store(snr_raw, std::memory_order_release);
            }
        }

        return peak_ok ? max_index : -1;
    }

} // namespace ProtectedEngine
