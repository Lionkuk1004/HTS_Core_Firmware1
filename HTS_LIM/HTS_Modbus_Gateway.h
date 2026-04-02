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

/// @file  HTS_Modbus_Gateway.h
/// @brief HTS Modbus 게이트웨이 -- 산업용 다중 인터페이스 변환
/// @details
///   RS-485/RS-232/RS-422/Modbus TCP/4-20mA 산업 디바이스를 B-CDMA 무선망에
///   연결하는 프로토콜 변환 게이트웨이. 원격 SCADA/모니터링 시스템 구현.
///
///   사용 예시:
///   @code
///   static ProtectedEngine::HTS_Modbus_Gateway g_modbus;
///   g_modbus.Initialize(&g_ipc);
///   g_modbus.Register_PHY_Callbacks(phy_cbs);
///   g_modbus.Configure_UART(Modbus_PHY::RS485, uart_cfg);
///   g_modbus.Add_Poll_Item(item);  // 자동 폴링 등록
///
///   void main_loop() {
///       g_modbus.Tick(HAL_GetTick());
///   }
///
///   // B-CDMA에서 Modbus 요청 수신 시:
///   g_modbus.Process_GW_Command(payload, len);
///   @endcode
///
/// @warning sizeof(HTS_Modbus_Gateway) ~ 512B. 전역/정적 배치 권장.
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_Modbus_Gateway_Defs.h"
#include "HTS_IPC_Protocol_Defs.h"
#include <cstdint>
#include <atomic>

namespace ProtectedEngine {

    class HTS_IPC_Protocol;

    /// @brief HTS Modbus 게이트웨이
    ///
    /// @warning sizeof ~ 512B. 전역/정적 배치 권장.
    class HTS_Modbus_Gateway final {
    public:
        static constexpr uint32_t SECURE_TRUE = 0x5A5A5A5Au;
        static constexpr uint32_t SECURE_FALSE = 0xA5A5A5A5u;

        HTS_Modbus_Gateway() noexcept;
        ~HTS_Modbus_Gateway() noexcept;

        /// @brief 초기화
        IPC_Error Initialize(HTS_IPC_Protocol* ipc) noexcept;

        /// @brief 종료
        void Shutdown() noexcept;

        /// @brief PHY 콜백 등록
        void Register_PHY_Callbacks(const Modbus_PHY_Callbacks& cb) noexcept;

        /// @brief UART 설정 (RS-485/232/422)
        void Configure_UART(Modbus_PHY phy, const Modbus_UART_Config& cfg) noexcept;

        /// @brief B-CDMA에서 수신된 GW 명령 처리
        /// @param payload [GW_CMD][PHY][SLAVE][FC][LEN][DATA...] 형식의 프레임
        /// @param len payload 총 길이 (최소 MODBUS_GW_HEADER_SIZE)
        /// @note  내부 검증 규칙:
        ///        - PHY: 1..(PHY_COUNT-1)
        ///        - SLAVE_ADDR: 1..247
        ///        - FUNC_CODE: ModbusFC 화이트리스트만 허용
        void Process_GW_Command(const uint8_t* payload, uint16_t len) noexcept;

        /// @brief 자동 폴링 항목 추가
        /// @return 슬롯 인덱스 (0~7), 실패 시 0xFF
        /// @note  item 입력 계약:
        ///        - active=1, interval_sec>0
        ///        - slave_addr: 1..247
        ///        - reg_count: 1..125
        ///        - func_code: ModbusFC 화이트리스트
        ///        - phy_type: 1..(PHY_COUNT-1)
        uint8_t Add_Poll_Item(const Modbus_PollItem& item) noexcept;

        /// @brief 자동 폴링 항목 제거
        void Remove_Poll_Item(uint8_t slot_idx) noexcept;

        /// @brief 주기적 틱 -- 메인 루프에서 호출
        void Tick(uint32_t systick_ms) noexcept;

        /// @brief Modbus 슬레이브에 직접 요청 (내부 모듈용)
        /// @return 응답 데이터 길이, 실패 시 0
        /// @note  입력 계약:
        ///        - phy: 1..(PHY_COUNT-1)
        ///        - slave_addr: 1..247
        ///        - func_code: ModbusFC 화이트리스트
        ///        - data_len>0 이면 data!=nullptr
        ///        - rsp_buf_size>0 이면 rsp_buf!=nullptr
        uint16_t Send_Request(Modbus_PHY phy, uint8_t slave_addr,
            uint8_t func_code, const uint8_t* data,
            uint8_t data_len, uint8_t* rsp_buf,
            uint16_t rsp_buf_size) noexcept;

        /// @name 상태
        /// @{
        Modbus_State Get_State() const noexcept;
        uint32_t Get_Request_Count() const noexcept;
        uint32_t Get_Error_Count() const noexcept;
        /// @}

        // -- 복사/이동 금지 --
        HTS_Modbus_Gateway(const HTS_Modbus_Gateway&) = delete;
        HTS_Modbus_Gateway& operator=(const HTS_Modbus_Gateway&) = delete;
        HTS_Modbus_Gateway(HTS_Modbus_Gateway&&) = delete;
        HTS_Modbus_Gateway& operator=(HTS_Modbus_Gateway&&) = delete;

        static constexpr uint32_t IMPL_BUF_SIZE = 768u;

    private:
        struct Impl;
        alignas(4) uint8_t impl_buf_[IMPL_BUF_SIZE];
        std::atomic<bool>  initialized_{ false };
        mutable std::atomic_flag op_busy_ = ATOMIC_FLAG_INIT;
    };

    static_assert(sizeof(HTS_Modbus_Gateway) <= 1024u,
        "HTS_Modbus_Gateway exceeds 1KB SRAM budget");

} // namespace ProtectedEngine