// =========================================================================
// HTS_Mesh_Router.h
// 자가치유 메쉬 라우터 — 공개 인터페이스
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  [자가치유 프로세스]
//   1. Neighbor_Discovery Link_Down 콜백 수신 (15초)
//   2. 해당 next_hop 경유 경로 전부 즉시 무효화
//   3. Poison Reverse: metric=∞ 브로드캐스트 (루프 방지)
//   4. 이웃 경로 정보 기반 대체 경로 자동 탐색
//   5. 복구 시간: 15~30초 (비콘 3~6회)
//
//  [라우팅 알고리즘]
//   거리 벡터 (Bellman-Ford 변형)
//   메트릭: hop_count × 4 + (100 - min_lqi) → 낮을수록 좋음
//   루프 방지: Split Horizon + Poison Reverse
//   경로 노화: 60초 미갱신 → 자동 삭제
//
//  @warning sizeof ≈ 516B — 전역/정적 배치 권장
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    class HTS_Priority_Scheduler;

    /// @brief 라우팅 항목
    struct RouteEntry {
        uint16_t dest_id;       ///< 목적지 ID
        uint16_t next_hop;      ///< 다음 홉 ID
        uint8_t  hop_count;     ///< 홉 수
        uint8_t  metric;        ///< 종합 메트릭 (0=최적)
        uint8_t  lqi;           ///< 경로 최소 LQI
        uint8_t  valid;
    };

    /// @brief 포워딩 결과
    enum class FwdResult : uint8_t {
        OK = 0u,
        NO_ROUTE = 1u,
        QUEUE_FULL = 2u,
        TTL_EXPIRED = 3u,
        SELF_DEST = 4u,
    };

    class HTS_Mesh_Router {
    public:
        static constexpr size_t  MAX_ROUTES = 32u;
        static constexpr uint8_t MAX_HOP = 8u;
        static constexpr uint8_t DEFAULT_TTL = 8u;
        static constexpr uint8_t METRIC_INF = 255u;
        static constexpr uint32_t ROUTE_AGE_MS = 60000u;  // 60초 노화

        explicit HTS_Mesh_Router(uint16_t my_id) noexcept;
        ~HTS_Mesh_Router() noexcept;

        HTS_Mesh_Router(const HTS_Mesh_Router&) = delete;
        HTS_Mesh_Router& operator=(const HTS_Mesh_Router&) = delete;
        HTS_Mesh_Router(HTS_Mesh_Router&&) = delete;
        HTS_Mesh_Router& operator=(HTS_Mesh_Router&&) = delete;

        // ─── 자가치유 이벤트 ─────────────────────────────

        /// @brief 이웃 경로 정보 수신 (비콘 내 라우팅 벡터)
        void On_Route_Update(
            uint16_t neighbor_id,
            const RouteEntry* routes, size_t route_count,
            uint8_t neighbor_lqi) noexcept;

        /// @brief 링크 단절 → 경로 무효화 + Hold-down 설정
        void On_Link_Down(uint16_t neighbor_id, uint32_t systick_ms) noexcept;

        /// @brief 링크 복구 → 직접 경로 추가
        void On_Link_Up(uint16_t neighbor_id, uint8_t lqi) noexcept;

        // ─── 메쉬 헤더 (6바이트, 페이로드 앞에 부착) ─────
        //  [0-1] next_hop      MAC 전송 대상
        //  [2-3] final_dest    최종 목적지
        //  [4]   ttl           잔여 홉 수
        //  [5]   src_id_lo     원본 송신자 하위 바이트
        static constexpr size_t MESH_HDR_SIZE = 6u;
        static constexpr size_t MAX_RELAY_PKT = 64u;  // 헤더+페이로드 최대

        /// @brief 로컬 수신 콜백 (목적지가 자신인 패킷 전달)
        using LocalDeliverCallback = void(*)(
            const uint8_t* payload, size_t len, uint16_t src_id);

        // ─── 패킷 수신 (메쉬 중계 핵심) ─────────────────

        /// @brief 수신 패킷 처리: 로컬 전달 또는 다음 홉 중계
        /// @param src_neighbor  직전 홉 이웃 ID
        /// @param pkt           메쉬 헤더 포함 패킷
        /// @param pkt_len       전체 길이
        /// @param systick_ms    현재 시각
        /// @param scheduler     Priority_Scheduler
        /// @return SELF_DEST=로컬 전달, OK=중계 성공, 기타=오류
        [[nodiscard]]
        FwdResult On_Packet_Received(
            uint16_t src_neighbor,
            const uint8_t* pkt, size_t pkt_len,
            uint32_t systick_ms,
            HTS_Priority_Scheduler& scheduler) noexcept;

        /// @brief 로컬 전달 콜백 등록
        void Register_Local_Deliver(LocalDeliverCallback cb) noexcept;

        // ─── 패킷 송신 (자신이 원본 송신자) ─────────────

        /// @brief 메쉬 헤더 부착 + 다음 홉 결정 + 인큐
        [[nodiscard]]
        FwdResult Forward(
            uint16_t dest_id,
            const uint8_t* payload, size_t len,
            uint8_t ttl, uint32_t systick_ms,
            HTS_Priority_Scheduler& scheduler) noexcept;

        // ─── 라우팅 테이블 조회 ──────────────────────────

        [[nodiscard]] bool   Get_Route(uint16_t dest_id, RouteEntry& out) const noexcept;
        [[nodiscard]] size_t Get_All_Routes(RouteEntry* out, size_t cap) const noexcept;
        [[nodiscard]] size_t Get_Route_Count() const noexcept;

        // ─── 주기 처리 ──────────────────────────────────

        /// @brief 경로 노화 + 주기적 라우팅 벡터 브로드캐스트
        void Tick(uint32_t systick_ms,
            HTS_Priority_Scheduler& scheduler) noexcept;

        void Shutdown() noexcept;

    private:
        static constexpr size_t IMPL_BUF_SIZE = 640u;
        static constexpr size_t IMPL_BUF_ALIGN = 8u;
        struct Impl;
        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        bool impl_valid_ = false;
        Impl* get_impl() noexcept;
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine