// =========================================================================
// HTS_Pipeline_V2_Dispatcher.cpp
// =========================================================================
#include "HTS_Pipeline_V2_Dispatcher.h"

#include <atomic>
#include <cstdint>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace ProtectedEngine {

namespace {

inline void PipelineV2_ScatterGather_Fence() noexcept
{
#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
     defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH))
    __asm volatile("dmb sy" ::: "memory");
#endif
    std::atomic_thread_fence(std::memory_order_release);
#if defined(__GNUC__) || defined(__clang__)
    __asm volatile("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
}

inline uint32_t Branchless_Clamp_U32(uint32_t n, uint32_t cap) noexcept
{
    const uint32_t over = 0u - static_cast<uint32_t>(n > cap);
    return (n & ~over) | (cap & over);
}

} // namespace

HTS_Pipeline_V2_Dispatcher::HTS_Pipeline_V2_Dispatcher(
    HTS_RF_Metrics& metrics,
    HTS_Adaptive_BPS_Controller& bps_controller) noexcept
    : metrics_(metrics)
    , bps_controller_(bps_controller)
    , mapper_()
    , last_session_id_(0u)
    , last_frame_counter_(0u)
    , cached_bps_(HTS_Adaptive_BPS_Controller::BPS_MIN)
{
}

void HTS_Pipeline_V2_Dispatcher::Begin_Frame(
    uint64_t session_id,
    uint32_t frame_counter,
    uint32_t harq_round) noexcept
{
    // 논리 프레임 번호(디버깅·계약) — HARQ 슬롯과 분리
    last_session_id_ = session_id;
    last_frame_counter_ = frame_counter;

    // HARQ 슬롯 클램프: 분기 없음(비트마스크), 가변 /·% 없음
    const uint32_t hr_slot =
        Branchless_Clamp_U32(harq_round, kMapperHarqSlotStride - 1u);

    // 가상 프레임 카운터: (frame << 4) | slot — kMapperHarqSlotStride == 16
    const uint32_t mapper_fc =
        (frame_counter << 4u) + hr_slot;

    mapper_.Update_Frame(session_id, mapper_fc);

    bps_controller_.Update();
    cached_bps_ =
        metrics_.current_bps.load(std::memory_order_relaxed);
}

void HTS_Pipeline_V2_Dispatcher::Fractal_Scatter_Tx(
    uint8_t* dst_wire,
    uint32_t dst_wire_cap,
    const uint8_t* src_fec,
    uint32_t src_fec_cap,
    uint32_t fec_symbol_count) const noexcept
{
    uint32_t run = Branchless_Clamp_U32(fec_symbol_count, kMapperDomain);
    run = Branchless_Clamp_U32(run, src_fec_cap);

    const uint32_t p_ok = static_cast<uint32_t>(
        (dst_wire != nullptr) & (src_fec != nullptr)
        & static_cast<uint32_t>(dst_wire_cap >= kMapperDomain));
    run *= p_ok;

    for (uint32_t i = 0u; i < run; ++i) {
        const uint32_t j = mapper_.Forward(i);
        dst_wire[j] = src_fec[i];
    }

    if (run != 0u) {
        PipelineV2_ScatterGather_Fence();
    }
}

void HTS_Pipeline_V2_Dispatcher::Fractal_Gather_Rx(
    uint8_t* dst_fec,
    uint32_t dst_fec_cap,
    const uint8_t* src_wire,
    uint32_t src_wire_cap,
    uint32_t wire_iter_count) const noexcept
{
    uint32_t run = Branchless_Clamp_U32(wire_iter_count, kMapperDomain);
    run = Branchless_Clamp_U32(run, dst_fec_cap);

    const uint32_t p_ok = static_cast<uint32_t>(
        (dst_fec != nullptr) & (src_wire != nullptr)
        & static_cast<uint32_t>(dst_fec_cap > 0u)
        & static_cast<uint32_t>(src_wire_cap >= kMapperDomain));
    run *= p_ok;

    for (uint32_t i = 0u; i < run; ++i) {
        const uint32_t j = mapper_.Forward(i);
        dst_fec[i] = src_wire[j];
    }

    PipelineV2_ScatterGather_Fence();
}

} // namespace ProtectedEngine
