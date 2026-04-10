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

/// @file  HTS_BLE_NFC_Gateway.h
/// @brief HTS BLE/NFC 게이트웨이 -- 스마트폰 연결 (국가지점번호 안내판)
/// @details
///   BLE/NFC 모듈(UART)을 통해 사용자 스마트폰과 연결하고,
///   텍스트/음성/위치/긴급호출 데이터를 B-CDMA 망으로 중계한다.
///
///   기능:
///   - BLE 세션 관리 (연결/해제/타임아웃)
///   - NFC 태그 읽기 (국가지점번호 자동 식별)
///   - 텍스트 메시지 양방향 전달 (안내 문구, 긴급 알림)
///   - 음성 안내 트리거 (보코더 인덱스 전달)
///   - 위치 정보 요청/응답 (국가지점번호 조회)
///   - 긴급 호출 중계 (119/112)
///
///   사용 예시:
///   @code
///   static ProtectedEngine::HTS_BLE_NFC_Gateway g_ble;
///   g_ble.Initialize(&g_ipc, location_code);
///   g_ble.Register_UART_Callbacks(uart_cbs);
///
///   void main_loop() {
///       g_ble.Tick(HAL_GetTick());
///   }
///
///   // UART RX 인터럽트에서:
///   g_ble.Feed_UART_Byte(byte);
///   @endcode
///
/// @warning sizeof(HTS_BLE_NFC_Gateway) ~ 1KB. 전역/정적 배치 권장.
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_BLE_NFC_Gateway_Defs.h"
#include "HTS_IPC_Protocol_Defs.h"
#include <cstdint>
#include <atomic>

namespace ProtectedEngine {

    class HTS_IPC_Protocol;

    /// @brief UART 송신 콜백 (BLE/NFC 모듈로 AT 명령 전송)
    /// @param data  송신 바이트
    /// @param len   길이
    typedef void (*BLE_UART_TX_Callback)(const uint8_t* data, uint16_t len);

    /// @brief BLE/NFC 수신 데이터 콜백 (스마트폰 -> 안내판)
    /// @param msg_type  메시지 타입
    /// @param payload   페이로드
    /// @param len       길이
    /// @param session   세션 정보
    typedef void (*BLE_RX_Data_Callback)(BLE_MsgType msg_type,
        const uint8_t* payload, uint16_t len, const BLE_Session* session);

    /// @brief HTS BLE/NFC 게이트웨이
    ///
    /// @warning sizeof ~ 1KB. 전역/정적 배치 권장.
    class HTS_BLE_NFC_Gateway final {
    public:
        HTS_BLE_NFC_Gateway() noexcept;
        ~HTS_BLE_NFC_Gateway() noexcept;

        /// @brief 초기화
        /// @param ipc           IPC 프로토콜 엔진
        /// @param location_code 이 안내판의 국가지점번호
        /// @return 성공 시 IPC_Error::OK
        IPC_Error Initialize(HTS_IPC_Protocol* ipc,
            LocationCode location_code) noexcept;

        /// @brief 종료 및 보안 소거
        void Shutdown() noexcept;

        /// @brief UART 송신 콜백 등록 (BLE/NFC 모듈로 명령 전송)
        void Register_UART_TX(BLE_UART_TX_Callback cb) noexcept;

        /// @brief 수신 데이터 콜백 등록 (앱 레이어 처리)
        void Register_RX_Callback(BLE_RX_Data_Callback cb) noexcept;

        /// @brief 주기적 틱 -- 메인 루프에서 호출
        /// @param systick_ms  현재 시스템 틱
        /// @note  세션 타임아웃 관리 + UART RX 버퍼 처리.
        void Tick(uint32_t systick_ms) noexcept;

        /// @brief UART RX 바이트 투입 (ISR 또는 DMA 콜백에서 호출)
        /// @param byte  수신된 1바이트
        /// @note  Lock-free 링 버퍼에 적재. ISR 안전.
        void Feed_UART_Byte(uint8_t byte) noexcept;

        /// @brief B-CDMA 망에서 수신된 메시지를 BLE/NFC로 전달
        /// @param payload  수신 페이로드 (게이트웨이 프레임)
        /// @param len      길이
        void Relay_From_BCDMA(const uint8_t* payload, uint16_t len) noexcept;

        /// @brief 텍스트 메시지를 B-CDMA 망으로 송신
        /// @param text     텍스트 바이트 (UTF-8)
        /// @param text_len 길이
        /// @param session_id 대상 세션 ID
        /// @return 성공 시 IPC_Error::OK
        IPC_Error Send_Text(const uint8_t* text, uint16_t text_len,
            uint16_t session_id) noexcept;

        /// @brief 음성 안내 트리거 전송
        /// @param voice_index 보코더 음성 인덱스
        /// @param session_id  대상 세션 ID
        /// @return 성공 시 IPC_Error::OK
        IPC_Error Send_Voice_Trigger(uint16_t voice_index,
            uint16_t session_id) noexcept;

        /// @brief 긴급 호출 중계
        /// @param session_id  발신 세션 ID
        /// @return 성공 시 IPC_Error::OK
        IPC_Error Send_Emergency(uint16_t session_id) noexcept;

        /// @name 상태
        /// @{
        BLE_GW_State Get_State() const noexcept;
        uint32_t Get_Active_Session_Count() const noexcept;
        /// @}

        // -- 복사/이동 금지 --
        HTS_BLE_NFC_Gateway(const HTS_BLE_NFC_Gateway&) = delete;
        HTS_BLE_NFC_Gateway& operator=(const HTS_BLE_NFC_Gateway&) = delete;
        HTS_BLE_NFC_Gateway(HTS_BLE_NFC_Gateway&&) = delete;
        HTS_BLE_NFC_Gateway& operator=(HTS_BLE_NFC_Gateway&&) = delete;

        static constexpr uint32_t IMPL_BUF_SIZE = 1024u;
        static constexpr unsigned IMPL_BUF_ALIGN = 8u;

    private:
        struct Impl;
        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        std::atomic<uint32_t> init_state_{ 0u };  ///< 0=NONE, 1=BUSY, 2=READY
    };

    static_assert(sizeof(HTS_BLE_NFC_Gateway) <= 2048u,
        "HTS_BLE_NFC_Gateway exceeds 2KB SRAM budget");

} // namespace ProtectedEngine