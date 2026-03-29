// =========================================================================
// HTS_Unified_Scheduler.h
// DMA 핑퐁 이중 버퍼 기반 통합 송신 스케줄러
// Target: STM32F407 (Cortex-M4)
//
// [양산 수정 이력]
//  BUG-64 [CRIT] unique_ptr Pimpl → placement new (zero-heap)
//  BUG-65 [CRIT] 생성자 try-catch 완전 제거 (-fno-exceptions)
//  BUG-66 [CRIT] vector ping/pong → 정적 배열 (Zero-Heap 원칙 확립)
//  BUG-68 [HIGH] DMA_START_BIT 매직넘버 → constexpr 상수화
//  BUG-69 [MED]  current_dma_buffer relaxed 읽기 → acquire
//  BUG-70 [MED]  소멸자 보안 소거 추가 (핑퐁 32KB 잔존 방지)
//  BUG-71 [MED]  core_pipeline nullptr → AIRCR 즉시 리셋
//  BUG-72 [MED]  Schedule_Next_Transfer data_len @pre 단위 문서화
//  BUG-73 [CRIT] FPGA DMA BUSY 폴링 — 레지스터 장전 전 IDLE 확인 필수
//         · BUSY 상태에서 source_address 쓰기 → FPGA 락업/HardFault
//         · 타임아웃 초과 시 레지스터 쓰기 전면 차단 (프레임 유실 허용)
//
// [메모리 요구량]
//  sizeof(Unified_Scheduler) ≈ 32KB + 48B (DMA 레지스터+atomic+포인터)
//  ⚠ 반드시 전역/정적 변수로 배치 (스택 배치 시 32KB 스택 소모)
// =========================================================================
#pragma once

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

        // [BUG-66] SRAM 예산 빌드 타임 검증
        static_assert(MAX_DMA_FRAME * sizeof(uint32_t) * 2u < 40u * 1024u,
            "Ping-Pong buffers exceed 40KB SRAM budget");

        explicit Unified_Scheduler(Dual_Tensor_Pipeline* pipeline) noexcept;

        /// @brief 소멸자 — 핑퐁 버퍼 + 넌스 보안 소거
        /// [BUG-70] 32KB 텐서 데이터 잔존 방지 (콜드부트/힙 스캔 방어)
        ~Unified_Scheduler() noexcept;

        // 복사/이동 금지 (DMA 레지스터 포인터 + atomic 멤버)
        Unified_Scheduler(const Unified_Scheduler&) = delete;
        Unified_Scheduler& operator=(const Unified_Scheduler&) = delete;
        Unified_Scheduler(Unified_Scheduler&&) = delete;
        Unified_Scheduler& operator=(Unified_Scheduler&&) = delete;

        /// @brief 센서 데이터 → 듀얼 텐서 처리 → 빈 버퍼에 채움 → DMA 트리거
        ///
        /// @pre raw_sensor_data: uint16_t 배열, data_len개 원소
        ///      data_len >= buffer_size × 2 권장 (16비트 2개 → 32비트 1개 패킹)
        ///      듀얼 텐서 파이프라인이 16→32비트 패킹을 내부 수행하므로
        ///      safe_len 계산은 32비트 단위 출력 기준으로 수렴
        [[nodiscard]]
        bool Schedule_Next_Transfer(
            uint16_t* raw_sensor_data, size_t data_len,
            std::atomic<bool>& abort_signal) noexcept;

        /// @brief DMA 전송 완료 ISR (다음 스왑 준비)
        void DMA_Transfer_Complete_ISR() noexcept;

    private:
        Dual_Tensor_Pipeline* core_pipeline;
        size_t buffer_size;  // min(active_tensor_count, MAX_DMA_FRAME)

        // [BUG-66] 핑퐁 이중 버퍼 — 정적 배열 (힙 할당 0회)
        uint32_t ping_buffer[MAX_DMA_FRAME];
        uint32_t pong_buffer[MAX_DMA_FRAME];

        // 현재 DMA 활성 버퍼 (0: Ping, 1: Pong)
        std::atomic<int> current_dma_buffer;

        // 패킷 시퀀스 넌스 (리플레이 공격 방어)
        uint32_t packet_sequence_nonce;

        // DMA 하드웨어 제어 블록
        Hardware_DMA_Registers dma_hw;

        // DMA 레지스터에 주소/길이 장전 + 전송 시작
        void Trigger_DMA_Hardware(uint32_t* buffer_ptr, size_t length) noexcept;
    };

} // namespace ProtectedEngine