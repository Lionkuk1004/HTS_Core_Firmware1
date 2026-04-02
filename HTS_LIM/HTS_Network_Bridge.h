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

/// @file  HTS_Network_Bridge.h
/// @brief HTS 네트워크 브릿지 -- Ethernet <-> B-CDMA 양방향 변환
/// @details
///   이더넷 MAC 프레임을 B-CDMA 페이로드 크기로 분할하여 송신하고,
///   수신된 B-CDMA 분할 프레임을 재조립하여 이더넷 프레임으로 복원한다.
///
///   기능:
///   - ETH->B-CDMA: Fragment_And_Send() -- 1518B 이더넷 -> 최대 7분할
///   - B-CDMA->ETH: Feed_Fragment() -- 분할 수신 -> 재조립 완료 시 콜백
///   - Tick() -- 재조립 타임아웃 관리 (500ms 제한)
///   - CFI 검증 상태 머신 (글리치 방어)
///
///   사용 예시:
///   @code
///   static ProtectedEngine::HTS_Network_Bridge g_bridge;
///   g_bridge.Initialize(&g_ipc);
///   g_bridge.Register_ETH_Callback(on_eth_frame_reassembled);
///
///   // ETH -> B-CDMA
///   g_bridge.Fragment_And_Send(eth_frame, eth_len);
///
///   // B-CDMA -> ETH (IPC 수신 루프에서)
///   const uint32_t reassembled =
///       g_bridge.Feed_Fragment(frag_payload, frag_len, systick_ms);
///   if (reassembled == ProtectedEngine::BRIDGE_SECURE_TRUE) {
///       // 콜백 경로에서 ETH 프레임 처리
///   }
///
///   // 주기적
///   g_bridge.Tick(systick_ms);
///   @endcode
///
/// @warning sizeof(HTS_Network_Bridge) ~ 8KB (재조립 슬롯 4개 x 1.5KB).
///          반드시 전역/정적 변수로 배치할 것.
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_Network_Bridge_Defs.h"
#include "HTS_IPC_Protocol_Defs.h"
#include <cstdint>
#include <atomic>

namespace ProtectedEngine {

    class HTS_IPC_Protocol;

    /// @brief 재조립 완료 콜백 타입
    /// @param data  재조립된 이더넷 프레임
    /// @param len   프레임 길이
    typedef void (*Bridge_ETH_Callback)(const uint8_t* data, uint16_t len);

    /// @brief HTS 네트워크 브릿지 -- Ethernet <-> B-CDMA
    ///
    /// @warning sizeof ~ 8KB. 전역/정적 배치 필수.
    ///          Cortex-M4 스택에 절대 선언 금지.
    class HTS_Network_Bridge final {
    public:
        HTS_Network_Bridge() noexcept;
        ~HTS_Network_Bridge() noexcept;

        /// @name 수명 주기
        /// @{

        /// @brief 브릿지 초기화
        /// @param ipc  IPC 프로토콜 엔진 (B-CDMA 송수신용)
        /// @return 성공 시 IPC_Error::OK
        IPC_Error Initialize(HTS_IPC_Protocol* ipc) noexcept;

        /// @brief 종료 및 보안 소거
        void Shutdown() noexcept;

        /// @brief 재조립 완료 콜백 등록
        /// @param cb  이더넷 프레임 재조립 완료 시 호출할 함수
        void Register_ETH_Callback(Bridge_ETH_Callback cb) noexcept;

        /// @}

        /// @name ETH -> B-CDMA (분할 송신)
        /// @{

        /// @brief 이더넷 프레임을 분할하여 B-CDMA로 송신
        /// @param eth_frame  이더넷 프레임 데이터
        /// @param eth_len    프레임 길이 (14~1518 바이트)
        /// @return 성공 시 IPC_Error::OK
        IPC_Error Fragment_And_Send(const uint8_t* eth_frame,
            uint16_t eth_len) noexcept;

        /// @}

        /// @name B-CDMA -> ETH (분할 수신/재조립)
        /// @{

        /// @brief 수신된 B-CDMA 분할 프레임을 재조립 엔진에 투입
        /// @param frag_payload  분할 페이로드 (분할 헤더 포함)
        /// @param frag_len      페이로드 길이
        /// @param systick_ms    현재 시스템 틱
        /// @return 재조립 완료 시 BRIDGE_SECURE_TRUE (콜백 호출됨)
        /// @note  호출자는 bool 캐스팅을 금지하고 반드시
        ///        (ret == BRIDGE_SECURE_TRUE)로 명시 비교할 것.
        /// @note  내부 CAS 가드(op_busy_)는 본 객체가 단독 소유/해제하며,
        ///        외부에서 동기화 객체를 획득/해제하지 않는다.
        uint32_t Feed_Fragment(const uint8_t* frag_payload, uint16_t frag_len,
            uint32_t systick_ms) noexcept;

        /// @}

        /// @name 주기적 관리
        /// @{

        /// @brief 타임아웃 관리 -- 메인 루프에서 호출
        /// @param systick_ms  현재 시스템 틱
        void Tick(uint32_t systick_ms) noexcept;

        /// @}

        /// @name 상태
        /// @{
        BridgeState Get_State() const noexcept;
        uint32_t Get_TX_Fragment_Count() const noexcept;
        uint32_t Get_RX_Reassembled_Count() const noexcept;
        uint32_t Get_Timeout_Count() const noexcept;
        /// @}

        // -- 복사/이동 금지 --
        HTS_Network_Bridge(const HTS_Network_Bridge&) = delete;
        HTS_Network_Bridge& operator=(const HTS_Network_Bridge&) = delete;
        HTS_Network_Bridge(HTS_Network_Bridge&&) = delete;
        HTS_Network_Bridge& operator=(HTS_Network_Bridge&&) = delete;

        /// @brief Pimpl 버퍼 크기
        /// @details 4 슬롯 x 1528B + IPC ptr + 상태 + 통계 + 콜백 + 여유
        ///          = ~6200B, 여유 포함 8192B
        static constexpr uint32_t IMPL_BUF_SIZE = 8192u;

    private:
        struct Impl;
        alignas(4) uint8_t impl_buf_[IMPL_BUF_SIZE];
        std::atomic<bool>  initialized_{ false };
        mutable std::atomic_flag op_busy_ = ATOMIC_FLAG_INIT;
    };

    /// @warning sizeof ~ 8KB (재조립 슬롯 4 x 1528B 내장).
    ///          반드시 전역/정적 변수로 배치할 것 -- 스택 선언 시 즉시 오버플로우.
    static_assert(sizeof(HTS_Network_Bridge) <= 10240u,
        "HTS_Network_Bridge exceeds 10KB SRAM budget");

} // namespace ProtectedEngine