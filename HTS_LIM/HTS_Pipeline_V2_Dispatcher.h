// =========================================================================
// HTS_Pipeline_V2_Dispatcher.h
// HTS V2 파이프라인 래퍼 — 프랙탈 와이어 매핑 + Adaptive_BPS 동기화 (TX/RX)
// Target: STM32F407 (Cortex-M4F, 168MHz, 192KB SRAM)
//
// [계약]
//  · Begin_Frame: 전송(또는 HARQ 라운드) 시작 시 mapper.Update_Frame +
//    bps_controller.Update 만 수행 — TX/RX가 별도 Update_Frame 호출 금지.
//  · HARQ 시간 다양성: 동일 frame_counter 에서 harq_round 가 바뀌면 매퍼 내부 키가
//    달라져 라운드별 Forward 순열이 분리됨(TX/RX 동일 harq_round 필수).
//  · kMapperHarqSlotStride 는 외부 LTE/FEC 헤더에 의존하지 않는 독립 상수(16).
//  · TX: FEC → Fractal_Scatter_Tx → RF / RX: RF → Fractal_Gather_Rx → FEC
//  · BPS: Begin_Frame 직후 Cached_Bps() → FEC/변조 파라미터 주입
//
// [12비트 전단사 / 핫패스]
//  kMapperDomain = FULL_MASK+1. dst_wire_cap·src_wire_cap >= kMapperDomain 일 때만
//  Scatter/Gather 수행(p_ok). 루프 내 인덱스 클램프는 생략(계약 위반 시 run=0).
//
// [Scatter/Gather — i 는 FEC 인덱스]
//  TX: dst_wire[Forward(i)] = src_fec[i]
//  RX: dst_fec[i] = src_wire[Forward(i)]
//
// [제약] 힙 금지, 핫패스 가변 /·%·float 금지
// =========================================================================
#ifndef HTS_PIPELINE_V2_DISPATCHER_H
#define HTS_PIPELINE_V2_DISPATCHER_H

#include <cstddef>
#include <cstdint>

#include "HTS_Dynamic_Fractal_Mapper.h"
#include "HTS_Adaptive_BPS_Controller.h"
#include "HTS_RF_Metrics.h"

namespace ProtectedEngine {

// Pimpl impl_buf_ 없음 — 멤버(Dynamic_Fractal_Mapper 등)가 직접 내장됨.

class HTS_Pipeline_V2_Dispatcher {
public:
    static constexpr uint32_t kMapperDomain =
        Dynamic_Fractal_Mapper::FULL_MASK + 1u;

    /// 프레임당 HARQ 슬롯 폭(2^4). 슬롯 0..15 — 일반적 재전송 최대 12회와 정합.
    /// 외부 HARQ 컨트롤러 헤더 비의존.
    static constexpr uint32_t kMapperHarqSlotStride = 16u;
    static_assert(kMapperHarqSlotStride == 16u,
        "Begin_Frame mapper_fc uses <<4; stride must remain 16");

    explicit HTS_Pipeline_V2_Dispatcher(
        HTS_RF_Metrics& metrics,
        HTS_Adaptive_BPS_Controller& bps_controller) noexcept;

    HTS_Pipeline_V2_Dispatcher(const HTS_Pipeline_V2_Dispatcher&) = delete;
    HTS_Pipeline_V2_Dispatcher& operator=(const HTS_Pipeline_V2_Dispatcher&) =
        delete;

    /// @brief 단일 동기화 진입점 — 매퍼 키 + BPS 갱신
    /// @param harq_round 시간 다양성 슬롯. 0=최초 시도, 재전송마다 +1 권장.
    ///        (HARQ 루프 k=1..K_max 이면 harq_round=(uint32_t)(k-1) 전달)
    ///        (kMapperHarqSlotStride-1) 초과 시 상한으로 클램프. 기본 0u → 구 2인자 호환.
    void Begin_Frame(uint64_t session_id, uint32_t frame_counter,
        uint32_t harq_round = 0u) noexcept;

    [[nodiscard]] uint64_t Last_Session_Id() const noexcept {
        return last_session_id_;
    }
    [[nodiscard]] uint32_t Last_Frame_Counter() const noexcept {
        return last_frame_counter_;
    }

    [[nodiscard]] uint8_t Cached_Bps() const noexcept {
        return cached_bps_;
    }

    [[nodiscard]] HTS_RF_Metrics& Metrics() noexcept { return metrics_; }
    [[nodiscard]] const HTS_RF_Metrics& Metrics() const noexcept {
        return metrics_;
    }

    [[nodiscard]] Dynamic_Fractal_Mapper& Mapper() noexcept { return mapper_; }
    [[nodiscard]] const Dynamic_Fractal_Mapper& Mapper() const noexcept {
        return mapper_;
    }

    [[nodiscard]] HTS_Adaptive_BPS_Controller& Bps_Controller() noexcept {
        return bps_controller_;
    }

    /// TX: dst_wire[j]=src_fec[i], j=Forward(i). dst_wire_cap >= kMapperDomain 필수.
    void Fractal_Scatter_Tx(uint8_t* dst_wire,
        uint32_t dst_wire_cap,
        const uint8_t* src_fec,
        uint32_t src_fec_cap,
        uint32_t fec_symbol_count) const noexcept;

    /// RX: dst_fec[i]=src_wire[j], j=Forward(i). src_wire_cap >= kMapperDomain 필수.
    void Fractal_Gather_Rx(uint8_t* dst_fec,
        uint32_t dst_fec_cap,
        const uint8_t* src_wire,
        uint32_t src_wire_cap,
        uint32_t wire_iter_count) const noexcept;

private:
    HTS_RF_Metrics& metrics_;
    HTS_Adaptive_BPS_Controller& bps_controller_;
    Dynamic_Fractal_Mapper mapper_;

    uint64_t last_session_id_ = 0u;
    uint32_t last_frame_counter_ = 0u;
    uint8_t  cached_bps_ = HTS_Adaptive_BPS_Controller::BPS_MIN;
};

} // namespace ProtectedEngine

#endif // HTS_PIPELINE_V2_DISPATCHER_H
