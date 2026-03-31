// =========================================================================
// HTS_Priority_Scheduler.h
// 3단계 패킷 우선순위 큐 스케줄러 — 공개 인터페이스
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [목적]
//  재밍 환경에서 대역폭이 축소될 때 SOS > VOICE > DATA 우선순위를
//  코드로 강제하여 음성 통화 QoS를 보장합니다.
//
//  [우선순위 체계]
//   P0 (최긴급): SOS 비콘         — 큐 깊이 4, 재밍 시에도 전송
//   P1 (긴급):   VOICE 음성       — 큐 깊이 8, 재밍 시 DATA 억제
//   P2 (일반):   DATA 일반        — 큐 깊이 8, 재밍 시 전송 보류
//
//  [사용법]
//   1. 생성: HTS_Priority_Scheduler()
//   2. Enqueue(priority, data, len): 패킷을 우선순위 큐에 삽입
//   3. Dequeue(out_data, out_len, out_priority): 최고 우선순위 패킷 추출
//   4. Tick(systick_ms): 에이징 처리 + NF 기반 정책 갱신
//
//  [디큐 정책]
//   항상 P0 → P1 → P2 순서로 비어있을 때까지 추출.
//   NF > 재밍 임계 시 P2 전송 보류 → P0/P1 대역폭 100% 보장.
//   P2 큐 체류 2초 초과 시 우선순위 P1로 에이징 승격.
//
//  [메모리]
//   sizeof ≈ IMPL_BUF_SIZE(512B) + bool(1B)
//   Impl: 3큐 × 항목(16B) × (4+8+8) = 320B + 상태 48B ≈ 368B
//
//  @warning sizeof ≈ 516B — 전역/정적 배치 권장
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    /// @brief 패킷 우선순위
    enum class PacketPriority : uint8_t {
        SOS = 0u,   ///< P0: 긴급 비콘 (최우선)
        VOICE = 1u,   ///< P1: 음성 통화
        DATA = 2u,   ///< P2: 일반 데이터 (센서/검침/메쉬)
    };

    /// @brief 큐 삽입 결과
    enum class EnqueueResult : uint8_t {
        OK = 0x00u,
        QUEUE_FULL = 0x01u,
        NULL_INPUT = 0x02u,
        OVER_SIZE = 0x03u,
    };

    class HTS_Priority_Scheduler {
    public:
        /// @brief 패킷 최대 데이터 크기 (FEC_HARQ MAX_INFO = 8바이트)
        static constexpr size_t MAX_PACKET_DATA = 8u;

        /// @brief 큐 깊이
        static constexpr size_t SOS_QUEUE_DEPTH = 4u;
        static constexpr size_t VOICE_QUEUE_DEPTH = 8u;
        static constexpr size_t DATA_QUEUE_DEPTH = 8u;

        /// @brief 생성자
        HTS_Priority_Scheduler() noexcept;

        /// @brief 소멸자 — Secure_Wipe
        ~HTS_Priority_Scheduler() noexcept;

        /// 복사/이동 차단
        HTS_Priority_Scheduler(const HTS_Priority_Scheduler&) = delete;
        HTS_Priority_Scheduler& operator=(const HTS_Priority_Scheduler&) = delete;
        HTS_Priority_Scheduler(HTS_Priority_Scheduler&&) = delete;
        HTS_Priority_Scheduler& operator=(HTS_Priority_Scheduler&&) = delete;

        // ─── 큐 API ─────────────────────────────────────────

        /// @brief 패킷을 우선순위 큐에 삽입
        /// @param priority  우선순위 (SOS/VOICE/DATA)
        /// @param data      패킷 데이터 (최대 MAX_PACKET_DATA)
        /// @param len       데이터 길이
        /// @param timestamp 삽입 시점 systick_ms (에이징 기준)
        [[nodiscard]]
        EnqueueResult Enqueue(
            PacketPriority priority,
            const uint8_t* data, size_t len,
            uint32_t timestamp) noexcept;

        /// @brief 최고 우선순위 패킷 추출
        /// @param out_data     출력 버퍼 (MAX_PACKET_DATA 이상)
        /// @param out_len      출력 데이터 길이
        /// @param out_priority 출력 우선순위
        /// @return true = 패킷 존재, false = 전 큐 비어있음
        [[nodiscard]]
        bool Dequeue(
            uint8_t* out_data, size_t& out_len,
            PacketPriority& out_priority) noexcept;

        /// @brief 주기 처리 (에이징 + NF 정책 갱신)
        /// @param systick_ms  현재 시스템 시각 (ms)
        /// @param current_nf  현재 노이즈 플로어 (RF_Metrics에서)
        void Tick(uint32_t systick_ms, uint32_t current_nf) noexcept;

        /// @brief 전체 큐 비우기
        void Flush() noexcept;

        /// @brief 큐별 사용량 조회
        [[nodiscard]] size_t Get_SOS_Count()   const noexcept;
        [[nodiscard]] size_t Get_VOICE_Count() const noexcept;
        [[nodiscard]] size_t Get_DATA_Count()  const noexcept;

        /// @brief 재밍 억제 상태 조회
        [[nodiscard]] bool Is_DATA_Suppressed() const noexcept;

    private:
        static constexpr size_t IMPL_BUF_SIZE = 512u;
        static constexpr size_t IMPL_BUF_ALIGN = 8u;

        struct Impl;

        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        bool impl_valid_ = false;

        Impl* get_impl() noexcept;
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine