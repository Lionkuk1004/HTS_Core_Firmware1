// =========================================================================
// HTS_Unified_Scheduler.hpp
// DMA 핑퐁 이중 버퍼 기반 통합 송신 스케줄러
// Target: STM32F407 (Cortex-M4)
//
#pragma once
// ─────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────
//  [사용법] 기본 사용 예시를 여기에 기재하세요.
//  [메모리] sizeof(클래스명) 확인 후 전역/정적 배치 필수.
//  [보안]   복사/이동 연산자 = delete (키 소재 복제 차단).
//
//  ⚠ [파트너사 필수 확인]
//    HW 레지스터 주소(UART/WDT 등)는 보드 설계에 맞게 교체.
//    IRQ 번호는 STM32F407 RM0090 벡터 테이블 기준으로 교체.
// ─────────────────────────────────────────────────────────

#include <cstdint>
#include <cstddef>
#include <atomic>
#include "HTS_Dual_Tensor_16bit.h"

namespace ProtectedEngine {

    // DMA 레지스터 주소 매핑 구조체
    struct Hardware_DMA_Registers {
        volatile uint32_t* source_address;
        volatile uint32_t* transfer_length;
        volatile uint32_t* control_status;
        volatile uint32_t* dest_address;
    };

    class Unified_Scheduler {
    public:
        /// @brief DMA 핑퐁 프레임 최대 크기 (BB1 MAX_TENSOR_ELEMENTS 일치)
        /// 핑퐁 2개 × MAX_DMA_FRAME × 4B = 32KB
        static constexpr size_t MAX_DMA_FRAME = 4096u;

        static_assert(MAX_DMA_FRAME * sizeof(uint32_t) * 2u < 40u * 1024u,
            "Ping-Pong buffers exceed 40KB SRAM budget");

        explicit Unified_Scheduler(Dual_Tensor_Pipeline* pipeline) noexcept;

        /// @brief 소멸자 — 핑퐁 버퍼 + 넌스 보안 소거
        /// 32KB 텐서 데이터 잔존 방지 (콜드부트/힙 스캔 방어)
        ~Unified_Scheduler() noexcept;

        // 복사/이동 금지 (DMA 레지스터 포인터 + atomic 멤버)
        Unified_Scheduler(const Unified_Scheduler&) = delete;
        Unified_Scheduler& operator=(const Unified_Scheduler&) = delete;
        Unified_Scheduler(Unified_Scheduler&&) = delete;
        Unified_Scheduler& operator=(Unified_Scheduler&&) = delete;

        /// @brief 센서 데이터 → 듀얼 텐서 처리 → 빈 버퍼에 채움 → DMA 트리거
        /// @note DMA 레지스터 장전·START 실패(BUSY 타임아웃 등) 시 false — 이때
        ///       current_dma_buffer 는 갱신하지 않음 (핑퐁 소유권 일관성).
        ///
        /// @pre raw_sensor_data: uint16_t 배열, data_len개 원소
        ///      data_len이 충분하지 않으면 듀얼 텐서 파이프라인이 생성한
        ///      generated_len이 축소되며, Schedule_Next_Transfer는
        ///      generated_len만큼만 ping/pong에 복사 후 DMA를 수행함
        [[nodiscard]]
        bool Schedule_Next_Transfer(
            uint16_t* raw_sensor_data, size_t data_len,
            std::atomic<bool>& abort_signal) noexcept;

        /// @brief DMA 전송 완료 ISR (다음 스왑 준비)
        void DMA_Transfer_Complete_ISR() noexcept;

    private:
        Dual_Tensor_Pipeline* core_pipeline;
        // Output buffer capacity in uint32_t elements (ping/pong length).
        size_t buffer_size;

        uint32_t ping_buffer[MAX_DMA_FRAME];
        uint32_t pong_buffer[MAX_DMA_FRAME];

        // 현재 DMA 활성 버퍼 (0: Ping, 1: Pong)
        std::atomic<int> current_dma_buffer;

        // 패킷 시퀀스 넌스 (리플레이 공격 방어)
        uint32_t packet_sequence_nonce;

        // DMA 하드웨어 제어 블록
        Hardware_DMA_Registers dma_hw;

        /// @return true=레지스터 장전 및 START 완료, false=BUSY 타임아웃/검증 실패
        [[nodiscard]] bool Trigger_DMA_Hardware(
            uint32_t* buffer_ptr, size_t length) noexcept;
    };

} // namespace ProtectedEngine


