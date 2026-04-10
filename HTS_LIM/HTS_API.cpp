#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
#define HTS_LIKELY   [[likely]]
#define HTS_UNLIKELY [[unlikely]]
#else
#define HTS_LIKELY
#define HTS_UNLIKELY
#endif
// =========================================================================
// HTS_API.cpp
// 외부 파트너사 연동 API 구현부
// Target: STM32F407VGT6 (Cortex-M4F) / PC
//

// 이 파일이 라이브러리 구현부이므로 반드시 BUILD 매크로 선행 정의
#if !defined(HTS_API_BUILD)
#define HTS_API_BUILD
#endif

#include "HTS_API.h"
#include "HTS_POST_Manager.h"
#include "HTS_Secure_Boot_Verify.h"
// PHY RX: V400/Sparse 경로 — HTS_PHY_Receiver 헤더 미사용
#include "HTS_Sparse_Recovery.h"

#include "HTS_Dual_Tensor_16bit.h"
#include "HTS_Dynamic_Config.h"
#include "HTS_Tx_Scheduler.hpp"
#include "HTS_Unified_Scheduler.hpp"

#include <atomic>
#include <cstring>

#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
#define HTS_API_LIKELY   HTS_LIKELY
#define HTS_API_UNLIKELY HTS_UNLIKELY
#else
#define HTS_API_LIKELY
#define HTS_API_UNLIKELY
#endif

namespace HTS_API {

    namespace {
        //  초기화 상태: NONE→BUSY→READY (BUSY 동안 외부는 ERR_NOT_INITIALIZED)
        //        READY는 모든 포인터 할당 + release 배리어 후에만 설정
        static constexpr uint32_t INIT_NONE = 0u;  ///< 미초기화
        static constexpr uint32_t INIT_BUSY = 1u;  ///< 초기화 진행 중 (포인터 미완성)
        static constexpr uint32_t INIT_READY = 2u;  ///< 초기화 완료 (포인터 유효)

        std::atomic<uint32_t>     g_init_state{ INIT_NONE };
        std::atomic<uint32_t> g_active_medium{
            static_cast<uint32_t>(HTS_CommMedium::B_CDMA_RAW_RF) };

        volatile uint32_t* g_hw_irq_status;
        volatile uint32_t* g_hw_irq_clear;
        volatile int16_t* g_hw_rx_fifo;

        // ── TX: Dual_Tensor → Unified_Scheduler(DMA) → HTS_Tx_Scheduler ──
        //  EMBEDDED_MINI temporal_slice_chunk(16)과 Push 정렬 일치 — tier 변경 시 동기화
        static constexpr size_t kTxPushChunk = 16u;
        static constexpr uint32_t kTensorBtQ16 = 19661u; ///< ~0.3 × 65536
        static constexpr size_t kTensorTaps = 31u;

        ProtectedEngine::Dual_Tensor_Pipeline g_tensor_pipe(
            kTensorBtQ16, kTensorTaps);
        ProtectedEngine::Unified_Scheduler g_unified_sched(&g_tensor_pipe);
        ProtectedEngine::HTS_Tx_Scheduler g_tx_sched(
            ProtectedEngine::HTS_Sys_Tier::EMBEDDED_MINI);

        std::atomic<bool> g_pipeline_abort{ false };
        bool g_tx_ring_ready{ false };

        // 메인 틱 주기 게이트(기본 23ms = 보코더 프레임). 0 = 매 틱 실행.
        std::atomic<uint32_t> g_unified_tx_period_ms{
            kDefaultUnifiedTxServicePeriodMs };
        std::atomic<uint32_t> g_last_unified_tx_service_ms{ 0u };
        std::atomic<uint32_t> g_unified_tx_service_run_count{ 0u };
        std::atomic<uint32_t> g_unified_tx_service_skip_count{ 0u };

        // Service_Unified_Tx_Main_Tick_Default 전용 — Dual_Tensor 입력 상한(ARM)과 여유
        static constexpr size_t kUnifiedTxScratchUint16 = 1024u;
        static uint16_t g_unified_tx_scratch[kUnifiedTxScratchUint16];
    }

    static bool Is_Valid_Medium(HTS_CommMedium m) noexcept {
        switch (m) {
        case HTS_CommMedium::B_CDMA_RAW_RF:
        case HTS_CommMedium::DIGITAL_5G_LTE:
        case HTS_CommMedium::WIRED_ETHERNET:
        case HTS_CommMedium::SATELLITE_LINK:
            return true;
        default:
            return false;
        }
    }

    HTS_Status Initialize_Core(
        volatile uint32_t* hw_irq_status_reg,
        volatile uint32_t* hw_irq_clear_reg,
        volatile int16_t* hw_rx_fifo_addr,
        HTS_CommMedium     target_medium) noexcept {

        // Secure Boot 미검증 시 초기화 거부
        if (HTS_Secure_Boot_Is_Verified() != 1) {
            return HTS_Status::ERR_TAMPERED;
        }

        //  CAS(NONE→BUSY): 단일 컨텍스트만 초기화 진입
        //  BUSY 상태: 외부 스레드가 포인터 접근 불가 (READY가 아니므로)
        //  READY 설정: 모든 포인터 할당 + release 배리어 후에만
        uint32_t expected = INIT_NONE;
        if (!g_init_state.compare_exchange_strong(
            expected, INIT_BUSY, std::memory_order_acq_rel)) {
            // BUSY: 다른 컨텍스트가 초기화 진행 중 (아직 포인터 미완성)
            // READY: 이미 초기화 완료
            return (expected == INIT_READY)
                ? HTS_Status::ERR_ALREADY_INITIALIZED
                : HTS_Status::ERR_NOT_INITIALIZED;
        }

        if (!hw_irq_status_reg || !hw_irq_clear_reg || !hw_rx_fifo_addr) {
            g_init_state.store(INIT_NONE, std::memory_order_release);
            return HTS_Status::ERR_NULL_POINTER;
        }

        if (!Is_Valid_Medium(target_medium)) HTS_API_UNLIKELY {
            g_init_state.store(INIT_NONE, std::memory_order_release);
            return HTS_Status::ERR_UNSUPPORTED_MEDIUM;
        }

        ProtectedEngine::POST_Manager::executePowerOnSelfTest();

        g_hw_irq_status = hw_irq_status_reg;
        g_hw_irq_clear = hw_irq_clear_reg;
        g_hw_rx_fifo = hw_rx_fifo_addr;

        g_active_medium.store(
            static_cast<uint32_t>(target_medium),
            std::memory_order_relaxed);

        g_tx_ring_ready = false;
        if (!g_tx_sched.Initialize()) {
            g_hw_irq_status = nullptr;
            g_hw_irq_clear = nullptr;
            g_hw_rx_fifo = nullptr;
            g_init_state.store(INIT_NONE, std::memory_order_release);
            return HTS_Status::ERR_POST_FAILED;
        }
        g_tx_ring_ready = true;

        //  release 배리어 → 다른 스레드에서 READY를 보면 포인터도 반드시 가시
        g_init_state.store(INIT_READY, std::memory_order_release);
        return HTS_Status::OK;
    }

    HTS_Status Fetch_And_Heal_Rx_Payload(
        uint32_t* out_buffer, size_t required_size) noexcept {

        if (g_init_state.load(std::memory_order_acquire) != INIT_READY) {
            return HTS_Status::ERR_NOT_INITIALIZED;
        }
        if (!out_buffer || required_size == 0u) {
            return HTS_Status::ERR_NULL_POINTER;
        }

        // 방어: READY 상태여도 HW 포인터가 비정상 오염되면 즉시 차단
        if (g_hw_irq_status == nullptr || g_hw_irq_clear == nullptr || g_hw_rx_fifo == nullptr) {
            return HTS_Status::ERR_NOT_INITIALIZED;
        }

        // RX→복구: HW 폴링 → FIFO → uint32 패킹 → IRQ ACK → L1 힐링
        static constexpr size_t RX_MAX_WORDS = 512u;    // uint32 슬롯 상한 (= required_size max)

        // required_size 초과는 버퍼 상한 위반 — HTS_Status에 전용 코드 없음.
        //  ERR_BUFFER_UNDERFLOW로 임시 매핑(의미: 요청 거부). 향후 ERR_INVALID_SIZE 권고.
        if (required_size > RX_MAX_WORDS) HTS_API_UNLIKELY {
            return HTS_Status::ERR_BUFFER_UNDERFLOW;
        }

        // STEP 1 — IRQ status: bit[0] set = RX 준비, 최대 1024회 폴링 (무한 루프 금지)
        bool rx_ready = false;
        for (uint32_t poll = 0u; poll < 1024u; ++poll) {
            const uint32_t st = *g_hw_irq_status;
            if ((st & 1u) != 0u) {
                rx_ready = true;
                break;
            }
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
            __asm__ volatile("nop" ::: "memory");
#endif
        }
        if (!rx_ready) HTS_API_UNLIKELY {
            return HTS_Status::ERR_BUFFER_UNDERFLOW;
        }

        // STEP 2 — FIFO → out_buffer 패킹 (스택 사용량 최소화)
        {
            volatile int16_t* const fifo = g_hw_rx_fifo;
            for (size_t i = 0u; i < required_size; ++i) {
                const uint16_t lo =
                    static_cast<uint16_t>(fifo[i << 1u]);
                const uint16_t hi =
                    static_cast<uint16_t>(fifo[(i << 1u) + 1u]);
                out_buffer[i] =
                    (static_cast<uint32_t>(hi) << 16) | static_cast<uint32_t>(lo);
            }
        }

        // STEP 3 — session_id 스냅샷 (IRQ 클리어 전, 레지스터 소거 전 상태)
        const uint64_t session_id =
            static_cast<uint64_t>(*g_hw_irq_status)
            ^ 0xB0CDABCD00000000ULL;

        // STEP 4 — IRQ 클리어 + release fence
        *g_hw_irq_clear = 1u;
        std::atomic_thread_fence(std::memory_order_release);

        // STEP 5 — L1 스파스 복구 (in-place)
        ProtectedEngine::RecoveryStats stats{};
        const bool healed =
            ProtectedEngine::Sparse_Recovery_Engine::Execute_L1_Reconstruction<uint32_t>(
                out_buffer,
                required_size,
                session_id,
                4u,
                false,
                false,
                stats);

        if (!healed) HTS_API_UNLIKELY {
            return HTS_Status::ERR_RECOVERY_FAILED;
        }

        return HTS_Status::OK;
    }

    uint32_t Is_System_Operational() noexcept {
        const bool ok =
            (g_init_state.load(std::memory_order_acquire) == INIT_READY);
        return ok ? SECURE_TRUE : SECURE_FALSE;
    }

    void Set_Unified_Tx_Service_Period_Ms(uint32_t period_ms) noexcept {
        g_unified_tx_period_ms.store(period_ms, std::memory_order_relaxed);
    }

    uint32_t Get_Unified_Tx_Service_Period_Ms() noexcept {
        return g_unified_tx_period_ms.load(std::memory_order_relaxed);
    }

    uint32_t Get_Unified_Tx_Service_Run_Count() noexcept {
        return g_unified_tx_service_run_count.load(std::memory_order_relaxed);
    }

    uint32_t Get_Unified_Tx_Service_Skip_Count() noexcept {
        return g_unified_tx_service_skip_count.load(std::memory_order_relaxed);
    }

    HTS_Status Service_Unified_Tx_If_Due(
        uint32_t  monotonic_ms,
        uint16_t* sensor_samples,
        size_t    sample_count) noexcept
    {
        if (g_init_state.load(std::memory_order_acquire) != INIT_READY) {
            return HTS_Status::ERR_NOT_INITIALIZED;
        }
        if (!sensor_samples || sample_count == 0u) {
            return HTS_Status::ERR_NULL_POINTER;
        }

        const uint32_t period =
            g_unified_tx_period_ms.load(std::memory_order_relaxed);
        const uint32_t last =
            g_last_unified_tx_service_ms.load(std::memory_order_relaxed);
        const uint32_t elapsed = monotonic_ms - last;
        const uint32_t first_u = static_cast<uint32_t>(last == 0u);
        const uint32_t period_zero_u = static_cast<uint32_t>(period == 0u);
        const uint32_t elapsed_ge =
            static_cast<uint32_t>(elapsed >= period);
        const uint32_t due_u =
            period_zero_u | first_u | elapsed_ge;
        if (due_u == 0u) {
            g_unified_tx_service_skip_count.fetch_add(
                1u, std::memory_order_relaxed);
            return HTS_Status::OK;
        }

        const HTS_Status st =
            Schedule_Unified_Tx_And_Queue(sensor_samples, sample_count);
        if (st == HTS_Status::OK) {
            g_last_unified_tx_service_ms.store(
                monotonic_ms, std::memory_order_relaxed);
            g_unified_tx_service_run_count.fetch_add(
                1u, std::memory_order_relaxed);
        }
        return st;
    }

    HTS_Status Service_Unified_Tx_Main_Tick_Default(
        uint32_t monotonic_ms) noexcept
    {
        return Service_Unified_Tx_If_Due(
            monotonic_ms,
            g_unified_tx_scratch,
            kUnifiedTxScratchUint16);
    }

    HTS_Status Schedule_Unified_Tx_And_Queue(
        uint16_t* sensor_samples,
        size_t sample_count) noexcept
    {
        if (g_init_state.load(std::memory_order_acquire) != INIT_READY) {
            return HTS_Status::ERR_NOT_INITIALIZED;
        }
        if (!g_tx_ring_ready) {
            return HTS_Status::ERR_NOT_INITIALIZED;
        }
        if (!sensor_samples || sample_count == 0u) {
            return HTS_Status::ERR_NULL_POINTER;
        }

        if (!g_unified_sched.Schedule_Next_Transfer(
            sensor_samples, sample_count, g_pipeline_abort)) {
            return HTS_Status::ERR_TX_PIPELINE_FAILED;
        }

        const uint32_t* lane = g_tensor_pipe.Get_Dual_Lane_Data();
        const size_t lane_words = g_tensor_pipe.Get_Dual_Lane_Size();
        if (!lane || lane_words == 0u) {
            return HTS_Status::ERR_TX_PIPELINE_FAILED;
        }

        const size_t push_words =
            (lane_words / kTxPushChunk) * kTxPushChunk;
        if (push_words == 0u) {
            return HTS_Status::OK;
        }

        // C-07 strict aliasing: uint32_t* 레인을 int32_t*로 reinterpret 금지 → memcpy만 사용
        static_assert(sizeof(uint32_t) == sizeof(int32_t),
            "lane word size must match waveform sample word");
        // Push_Waveform_Chunk가 const int32_t*를 받으므로 memcpy로 복사
        // push_words ≤ lane_words ≤ kUnifiedTxScratchUint16 (1024) → 4KB 이하
        static int32_t g_tx_lane_i32[1024];
        const size_t copy_bytes = push_words * sizeof(int32_t);
        std::memcpy(
            static_cast<void*>(g_tx_lane_i32),
            static_cast<const void*>(lane),
            copy_bytes);
        if (!g_tx_sched.Push_Waveform_Chunk(g_tx_lane_i32, push_words)) {
            return HTS_Status::ERR_TX_PIPELINE_FAILED;
        }

        return HTS_Status::OK;
    }

} // namespace HTS_API
