// =========================================================================
// HTS_Mesh_Sync.h
// 메쉬 시간 동기화 + ToA 거리 추정 엔진 — 공개 인터페이스
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  [목적]
//  1. B-CDMA Walsh 직교성 유지 — 노드 간 ±1μs 동기화
//  2. 다중 홉 동기 전파 — 루트(GPS앵커)→말단 계층적 타이밍 배포
//  3. ToA 거리 추정 — 비콘 왕복/편도 시간차 → 노드 간 거리(cm)
//  4. 동기 품질 지표 — 수색 위치 추정 신뢰도 판단
//
//  [위치 추적 아키텍처]
//   Mesh_Sync: 각 이웃까지 ToA 거리(cm) 측정
//   Location_Engine: 3+ 앵커 거리 → 삼각측량 → 위치(lat/lon)
//   Emergency_Beacon: 위치 포함 SOS 패킷 → 상황실 지도 표시
//
//  [거리 정밀도]
//   B-CDMA 칩 해상도:     ~5μs (200kc/s) = 1500m
//   10x 오버샘플링:        ~0.5μs = 150m
//   상관 피크 보간:         ~0.1μs = 30m
//   삼각측량 (3+ 앵커):    ±50m (산악 환경)
//
//  @warning sizeof ≈ 520B — 전역/정적 배치 권장
// ─────────────────────────────────────────────────────────────────────────
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

namespace ProtectedEngine {

    enum class SyncState : uint8_t {
        UNSYNC = 0u,
        ACQUIRING = 1u,
        LOCKED = 2u,
        SUSPENDED = 3u,
    };

    /// @brief 이웃 동기/거리 정보 (Location_Engine 입력용)
    struct PeerRanging {
        uint16_t peer_id;
        int32_t  offset_q16;        ///< Q16 클럭 오프셋 (μs)
        uint32_t distance_cm;       ///< 추정 거리 (cm, 0=미측정)
        uint8_t  sync_quality;      ///< 동기 품질 (0-100%)
        uint8_t  hop_level;         ///< 상대방 동기 계층
        uint8_t  valid;
        uint8_t  pad;
    };

    class HTS_Mesh_Sync {
    public:
        static constexpr size_t   MAX_SYNC_PEERS = 16u;
        static constexpr uint32_t SLOT_DURATION_US = 10000u;
        static constexpr uint32_t GUARD_TIME_US = 500u;
        static constexpr uint8_t  MAX_SLOTS = 8u;

        explicit HTS_Mesh_Sync(uint16_t my_id) noexcept;
        ~HTS_Mesh_Sync() noexcept;

        HTS_Mesh_Sync(const HTS_Mesh_Sync&) = delete;
        HTS_Mesh_Sync& operator=(const HTS_Mesh_Sync&) = delete;
        HTS_Mesh_Sync(HTS_Mesh_Sync&&) = delete;
        HTS_Mesh_Sync& operator=(HTS_Mesh_Sync&&) = delete;

        // ─── 비콘 타이밍 입력 ────────────────────────────
        /// @brief 비콘 타이밍 입력 (① 포물선 보간 포함)
        /// @param corr_prev/peak/next  상관 피크 3샘플 (0=보간 생략)
        void On_Beacon_Timing(
            uint16_t peer_id,
            uint32_t rx_capture_us,
            uint32_t expected_us,
            uint8_t  peer_hop,
            uint32_t systick_ms,
            int32_t  corr_prev = 0,
            int32_t  corr_peak = 0,
            int32_t  corr_next = 0) noexcept;

        // ─── 다중 홉 동기 ───────────────────────────────
        void    Set_As_Root() noexcept;
        [[nodiscard]] uint8_t Get_My_Hop_Level() const noexcept;

        // ─── 상태/품질 ──────────────────────────────────
        [[nodiscard]] SyncState Get_State() const noexcept;
        [[nodiscard]] int32_t   Get_Offset_Q16() const noexcept;
        [[nodiscard]] bool      Is_Locked() const noexcept;
        [[nodiscard]] uint8_t   Get_Sync_Quality() const noexcept;

        // ─── ToA 거리 (Location_Engine 입력) ────────────
        [[nodiscard]] uint32_t Get_Distance_cm(uint16_t peer_id) const noexcept;
        [[nodiscard]] size_t   Get_All_Ranging(PeerRanging* out, size_t cap) const noexcept;

        // ─── TDMA 슬롯 ─────────────────────────────────
        void Set_My_Slot(uint8_t slot) noexcept;
        [[nodiscard]] uint8_t Get_My_Slot() const noexcept;
        [[nodiscard]] bool Is_My_TX_Slot(uint32_t systick_us) const noexcept;

        // ─── 전력 모드 ─────────────────────────────────
        void Suspend() noexcept;
        void Resume() noexcept;
        void Shutdown() noexcept;

    private:
        static constexpr size_t IMPL_BUF_SIZE = 512u;
        static constexpr size_t IMPL_BUF_ALIGN = 8u;
        struct Impl;
        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        std::atomic<bool> impl_valid_{ false };
        Impl* get_impl() noexcept;
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine