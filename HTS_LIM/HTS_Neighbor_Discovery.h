// =========================================================================
// HTS_Neighbor_Discovery.h
// 메쉬 이웃 탐색/토폴로지 관리 — 공개 인터페이스
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [목적]
//  B-CDMA 메쉬 네트워크에서 "내 주변에 누가 있고, 각각의 링크 품질이
//  얼마인지" 실시간 파악. Mesh_Router 경로 계산의 입력 데이터 공급.
//
//  [비콘 프로토콜]
//   5초 주기 비콘 송출 (P2 DATA 큐)
//   비콘 패킷 (8바이트):
//     [0-1] src_id          장비 ID
//     [2]   seq             시퀀스 (0-255 순환)
//     [3]   hop_from_root   루트까지 홉 수
//     [4]   tx_power_dbm    송신 전력 (dBm, 부호 있음)
//     [5]   neighbor_count  이웃 수
//     [6]   capability      기능 플래그
//     [7]   reserved
//
//  [이웃 테이블]
//   최대 32개 이웃 × 16바이트 = 512B
//   15초(비콘 3회) 미수신 → 자동 제거 + 콜백 통보
//
//  @warning sizeof ≈ 1028B — 전역/정적 배치 권장
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>
#include <atomic>

namespace ProtectedEngine {

    class HTS_Priority_Scheduler;

    /// @brief 이웃 탐색 전력 모드 (4단계 적응형)
    ///
    ///  DEEP_SLEEP: 비콘 5분, RX 2초 윈도우, 타임아웃 20분
    ///  WATCH:      비콘 30초, RX 50%, 타임아웃 2분
    ///  ALERT:      비콘 5초, RX 100%, 타임아웃 15초
    ///  REALTIME:   비콘 1초, RX 100%, 타임아웃 3초 (상시 전원)
    ///
    ///  REALTIME: 태양광/상시전원 장비 전용
    ///   AMI 전력계량기, 국가지점번호판, 산불감시탑
    ///   장애 감지 3초 → 경로 복구 5초
    enum class DiscoveryMode : uint8_t {
        DEEP_SLEEP = 0u,   ///< 정상 대기 (5분 주기, 최소 전력)
        WATCH = 1u,   ///< 주의 상태 (30초 주기, 센서 이상)
        ALERT = 2u,   ///< 긴급 모드 (5초 주기, SOS/화재)
        REALTIME = 3u,   ///< 상시 전원 (1초 주기, 즉각 복구)
    };

    /// @brief 이웃 항목 (외부 조회용, 읽기 전용 복사)
    struct NeighborInfo {
        uint16_t node_id;           ///< 이웃 장비 ID
        uint8_t  rssi;              ///< 수신 신호 강도 (0-255, Q8)
        uint8_t  lqi;               ///< 링크 품질 (0-100%)
        uint32_t last_seen_ms;      ///< 마지막 수신 시각
        uint8_t  hop_from_root;     ///< 루트까지 홉 수
        uint8_t  capability;        ///< 기능 플래그
        int8_t   tx_power_dbm;      ///< 상대방 송신 전력
        uint8_t  valid;             ///< 1=유효, 0=빈 슬롯
    };

    /// @brief 링크 단절 콜백 타입
    /// @param node_id  단절된 이웃의 ID
    using LinkDownCallback = void(*)(uint16_t node_id);

    class HTS_Neighbor_Discovery {
    public:
        static constexpr size_t MAX_NEIGHBORS = 32u;
        static constexpr size_t BEACON_PKT_SIZE = 8u;

        // ── 모드별 파라미터 ──────────────────────────────
        // DEEP_SLEEP: 산불감시탑 10년 배터리 최적화
        static constexpr uint32_t INTERVAL_DEEP_MS = 300000u;  // 5분
        static constexpr uint32_t TIMEOUT_DEEP_MS = 1200000u; // 20분
        static constexpr uint32_t RX_WINDOW_DEEP_MS = 2000u;    // TX 후 2초

        // WATCH: 센서 이상 감지 → 이웃 감시 강화
        static constexpr uint32_t INTERVAL_WATCH_MS = 30000u;   // 30초
        static constexpr uint32_t TIMEOUT_WATCH_MS = 120000u;  // 2분

        // ALERT: 긴급 모드 → 최대 응답성
        static constexpr uint32_t INTERVAL_ALERT_MS = 5000u;    // 5초
        static constexpr uint32_t TIMEOUT_ALERT_MS = 15000u;   // 15초

        // REALTIME: 상시 전원 → 즉각 장애 감지 (태양광/AMI/감시탑)
        static constexpr uint32_t INTERVAL_RT_MS = 1000u;    // 1초
        static constexpr uint32_t TIMEOUT_RT_MS = 3000u;    // 3초

        /// @brief 생성자
        /// @param my_id  자신의 장비 ID
        explicit HTS_Neighbor_Discovery(uint16_t my_id) noexcept;

        /// @brief 소멸자
        ~HTS_Neighbor_Discovery() noexcept;

        /// 복사/이동 차단
        HTS_Neighbor_Discovery(const HTS_Neighbor_Discovery&) = delete;
        HTS_Neighbor_Discovery& operator=(const HTS_Neighbor_Discovery&) = delete;
        HTS_Neighbor_Discovery(HTS_Neighbor_Discovery&&) = delete;
        HTS_Neighbor_Discovery& operator=(HTS_Neighbor_Discovery&&) = delete;

        // ─── 설정 ───────────────────────────────────────────

        /// @brief 전력 모드 전환
        /// @param mode        DEEP_SLEEP / WATCH / ALERT / REALTIME
        /// @param systick_ms  현재 틱 — 주기 단축 전환 시 이웃 last_seen_ms 그레이스 부여에 사용
        /// @note  Emergency_Beacon 연동: SOS 발동 시 ALERT 자동 전환
        void Set_Mode(DiscoveryMode mode, uint32_t systick_ms) noexcept;

        /// @brief 현재 전력 모드 조회
        [[nodiscard]] DiscoveryMode Get_Mode() const noexcept;

        /// @brief RX 수신 윈도우 활성 여부 (Power_Manager 연동)
        ///
        /// DEEP_SLEEP: TX 후 2초만 true → 이후 RF OFF 가능
        /// WATCH:      50% 듀티 → 비콘 주기 절반 true
        /// ALERT:      항상 true (100% 수신)
        ///
        /// @param systick_ms 현재 시각
        /// @return true = RF 수신기 ON 유지, false = 슬립 가능
        [[nodiscard]]
        bool Is_RX_Window(uint32_t systick_ms) const noexcept;

        /// @brief 링크 단절 콜백 등록 (Mesh_Router 통보용)
        void Register_Link_Down(LinkDownCallback cb) noexcept;

        /// @brief 자신의 홉 수 설정 (루트=0, 1홉=1, ...)
        void Set_My_Hop(uint8_t hop) noexcept;

        /// @brief 자신의 TX 전력 설정 (dBm)
        void Set_My_TX_Power(int8_t dbm) noexcept;

        // ─── 비콘 수신 ──────────────────────────────────────

        /// @brief 수신된 비콘 패킷 처리 → 이웃 테이블 갱신
        /// @param pkt       비콘 패킷 (8바이트)
        /// @param pkt_len   패킷 길이
        /// @param rx_rssi   수신 시 RSSI (snr_proxy 기반)
        /// @param systick_ms 현재 시각
        /// @note  Network_Bridge와 연동 시 Bridge 계열 보안 반환값은
        ///        bool로 암묵 변환하지 말고
        ///        (ret == BRIDGE_SECURE_TRUE)로 명시 비교할 것.
        void On_Beacon_Received(
            const uint8_t* pkt, size_t pkt_len,
            uint8_t rx_rssi, uint32_t systick_ms) noexcept;

        // ─── 주기 처리 ──────────────────────────────────────

        /// @brief 주기 호출 — 비콘 송출 + 타임아웃 검사
        /// @param systick_ms  현재 시각
        /// @param scheduler   Priority_Scheduler (P2 DATA)
        /// @note  동기화 자원(락/CAS/크리티컬 섹션)의 획득·해제는 각 모듈
        ///        내부 구현이 단독 책임을 가지며, 외부 호출자가 중첩 획득하지 않는다.
        void Tick(uint32_t systick_ms,
            HTS_Priority_Scheduler& scheduler) noexcept;

        // ─── 이웃 테이블 조회 ────────────────────────────────

        /// @brief 현재 이웃 수
        [[nodiscard]] size_t Get_Neighbor_Count() const noexcept;

        /// @brief 이웃 정보 조회 (인덱스 기반)
        /// @param idx   테이블 인덱스 (0 ~ MAX_NEIGHBORS-1)
        /// @param out   출력 구조체
        /// @return true = 유효한 이웃
        [[nodiscard]]
        bool Get_Neighbor(size_t idx, NeighborInfo& out) const noexcept;

        /// @brief 특정 node_id 이웃 검색
        /// @return true = 발견
        [[nodiscard]]
        bool Find_Neighbor(uint16_t node_id, NeighborInfo& out) const noexcept;

        /// @brief 안전 종료
        void Shutdown() noexcept;

    private:
        static constexpr size_t IMPL_BUF_SIZE = 1024u;
        static constexpr size_t IMPL_BUF_ALIGN = 8u;

        struct Impl;

        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        std::atomic<bool> impl_valid_{ false };

        Impl* get_impl() noexcept;
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine