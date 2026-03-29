// =========================================================================
// HTS_Tx_Scheduler.h
// B-CDMA TX 전송 스케줄러 — 공개 인터페이스
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  이 모듈은 B-CDMA TX 파이프라인의 전송 스케줄러입니다.
//  Q16 고정소수점 파형 데이터를 링 버퍼에 적재하고,
//  RF 전송단(ISR/모뎀)이 팝하여 DMA로 전송합니다.
//
//  [운용 모드 — SPSC (Single Producer, Single Consumer)]
//   프로듀서: Unified_Scheduler / 메인 루프 → Push_Waveform_Chunk()
//   컨슈머:  DMA ISR / RF 전송단 → Pop_Tx_Payload()
//   ⚠ 단일 프로듀서 + 단일 컨슈머 전용 — 다중 스레드에서 동시 Push 불가
//
//  [사용법]
//   1. 생성: HTS_Tx_Scheduler(tier)
//      → 시스템 체급(IOT, MOBILE, SERVER)에 따라 버퍼 크기 자동 결정
//      → 초기화 실패 시 impl_valid_=false → 모든 함수 false 반환
//
//   2. Initialize():
//      → 링 버퍼 메모리 할당 (2의 제곱수 정렬 — 비트 마스킹)
//      → 실패 시 false 반환 (OOM)
//
//   3. Push_Waveform_Chunk(q16_data, size):
//      → Q16 파형 데이터 적재 (size는 temporal_slice_chunk의 배수)
//      → 버퍼 부족 시 false (데이터 손실 → 상위에서 재전송)
//      → ISR 안전: 힙 할당 0회, memcpy만 사용
//
//   4. Pop_Tx_Payload(out_buffer, requested_size):
//      → RF 전송단으로 데이터 추출
//      → 데이터 부족 시 false
//      → ISR 안전: 힙 할당 0회, memcpy만 사용
//
//  [메모리 요구량]
//   ARM (EMBEDDED_MINI):
//     Impl(SRAM In-Place): impl_buf_[8704] — placement new, 힙 할당 0회
//       tx_ring_buffer[2048] × 4B = 8KB (EMBEDDED ring_size=1024 수용)
//     sizeof(HTS_Tx_Scheduler) ≈ 8.5KB
//   PC (STANDARD+):
//     Impl: impl_buf_[67584] — tx_ring_buffer[16384] × 4B = 64KB
//     sizeof(HTS_Tx_Scheduler) ≈ 66KB
//   ⚠ 반드시 전역/정적 변수로 배치 (스택 배치 금지)
//
//  [보안 설계]
//   tx_ring_buffer: 소멸자에서 보안 소거 (Q16 파형 잔존 방지)
//   impl_buf_: 소멸자에서 SecWipe — Impl 전체 보안 소거
//   current_config: 시스템 구성 — Impl 소멸자에서 함께 소거
//   복사/이동: = delete (링 버퍼 + atomic 복제 방지)
//
//  [STM32F407 성능]
//   Push/Pop (256 words): ~300사이클 ≈ 1.8µs @168MHz
//   비트 마스크 교체로 기존 모듈러 % 대비 ~40% 가속
//
//  [양산 수정 이력]
//   BUG-01~08 (DCE소거, chunk=0방어, 전방선언, 비트마스크,
//             SPSC문서, C26495, available분기제거, copy/move)
//   BUG-09~12 (Self-Contained, dead include, Free-running, chunk정렬)
//   BUG-59~63 (SRAM 한계, SecWipe, Dead Branch, 배리어, Flush/Used/Avail)
//   BUG-64 [CRIT] unique_ptr Pimpl → placement new (zero-heap)
//          힙 단편화 및 런타임 OOM 원천 제거
//          AlignedIndex alignas(64) 요구 → impl_buf_ alignas(64) 적용
//   BUG-67 [CRIT] MAX_RING_POW2/CACHELINE 플랫폼 분리
//          ARM: ring[2048](8KB) + alignas(8) — 60KB SRAM 절감 (94%)
//          PC:  ring[16384](64KB) + alignas(64) — 기존 유지
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    // 전방 선언 (HTS_Dynamic_Config.h include 제거)
    enum class HTS_Sys_Tier : uint8_t;

    class HTS_Tx_Scheduler {
    public:
        /// @brief TX 스케줄러 생성
        /// @param tier  시스템 체급 (IOT/MOBILE/SERVER)
        /// @note  초기화 실패(OOM) 시 impl_valid_=false → 모든 함수 false 반환
        explicit HTS_Tx_Scheduler(HTS_Sys_Tier tier) noexcept;

        /// @brief 소멸자 — Impl 보안 소거 후 impl_buf_ SecWipe
        ~HTS_Tx_Scheduler() noexcept;

        /// 링 버퍼 + atomic 상태 복제 방지
        HTS_Tx_Scheduler(const HTS_Tx_Scheduler&) = delete;
        HTS_Tx_Scheduler& operator=(const HTS_Tx_Scheduler&) = delete;
        HTS_Tx_Scheduler(HTS_Tx_Scheduler&&) = delete;
        HTS_Tx_Scheduler& operator=(HTS_Tx_Scheduler&&) = delete;

        /// @brief 링 버퍼 메모리 할당 (2의 제곱수 정렬)
        /// @return true=성공, false=OOM 또는 설정 오류
        /// @note  생성 후 반드시 호출 — 미호출 시 Push/Pop이 false 반환
        [[nodiscard]] bool Initialize() noexcept;

        /// @brief 링 버퍼 강제 초기화 (Flush)
        /// @note  재밍, 통신 단절, 모드 전환 시 잔여 파형을 즉시 폐기하고 인덱스 리셋
        void Flush() noexcept;

        /// @brief 현재 링 버퍼에 적재된(전송 대기 중인) 데이터 크기 확인
        /// @return 적재된 Q16 파형 요소 수
        [[nodiscard]] size_t Get_Used_Space() const noexcept;

        /// @brief 현재 링 버퍼에 추가로 적재 가능한 잔여 공간 확인
        /// @return 적재 가능한 여유 요소 수
        [[nodiscard]] size_t Get_Available_Space() const noexcept;

        /// @brief Q16 파형 데이터 적재 (프로듀서 — 메인 루프)
        /// @param q16_data  Q16 고정소수점 파형 배열 (nullptr 불가)
        /// @param size      요소 수 (temporal_slice_chunk의 배수, 0 불가)
        /// @return true=적재 성공, false=버퍼 부족/정렬 오류
        /// @note  ISR 안전: 힙 0회, 잠금 0회
        [[nodiscard]] bool Push_Waveform_Chunk(
            const int32_t* q16_data, size_t size) noexcept;

        /// @brief RF 전송단으로 데이터 추출 (컨슈머 — ISR/모뎀)
        /// @param out_buffer      출력 버퍼 (nullptr 불가)
        /// @param requested_size  요청 요소 수 (0 불가)
        /// @return true=추출 성공, false=데이터 부족
        /// @note  ISR 안전: 힙 0회, 잠금 0회
        [[nodiscard]] bool Pop_Tx_Payload(
            int32_t* out_buffer, size_t requested_size) noexcept;

    private:
        // ── [BUG-64+66+67] Pimpl In-Place Storage (zero-heap) ────────────
        //
        // [BUG-67] 플랫폼별 IMPL_BUF_SIZE/ALIGN 분리
        //
        //  ARM (EMBEDDED_MINI): node_count=256 → ring_size=1024
        //    tx_ring_buffer[2048] × 4B = 8KB + metadata ≈ 8.5KB
        //    AlignedIndex alignas(8) — Cortex-M4 단일 코어, False Sharing 불가
        //
        //  PC (STANDARD+): node_count=1024+ → ring_size ≤ 16384
        //    tx_ring_buffer[16384] × 4B = 64KB + metadata ≈ 66KB
        //    AlignedIndex alignas(64) — 멀티 코어 False Sharing 방어
        //
#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
        static constexpr size_t IMPL_BUF_SIZE = 8704u;   // 8.5KB (ring[2048]+meta)
        static constexpr size_t IMPL_BUF_ALIGN = 8u;     // Cortex-M4: 단일 코어
#else
        static constexpr size_t IMPL_BUF_SIZE = 67584u;  // 66KB (ring[16384]+meta)
        static constexpr size_t IMPL_BUF_ALIGN = 64u;    // PC: False Sharing 방어
#endif

        struct Impl;  ///< 링 버퍼 + SPSC 인덱스 완전 은닉 (ABI 안정성 보장)

        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        bool impl_valid_ = false;  ///< placement new 성공 여부

        /// @brief impl_buf_에서 Impl 포인터 반환 (컴파일 타임 크기·정렬 검증 포함)
        Impl* get_impl() noexcept;
        /// @overload
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine