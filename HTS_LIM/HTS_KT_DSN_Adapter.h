#pragma once
/// @file  HTS_KT_DSN_Adapter.h
/// @brief HTS KT 재난안전망 어댑터 -- CBS/CMAS 재난 경보 중계
/// @details
///   KT 재난안전망(DSN)에서 수신한 CBS/CMAS 재난 경보를 B-CDMA 채널로
///   중계하고, 재난 시 자동 BPS 하향으로 최대 도달거리를 확보한다.
///
///   사용 예시:
///   @code
///   static ProtectedEngine::HTS_KT_DSN_Adapter g_dsn;
///   g_dsn.Initialize(&g_ipc, my_area_code);
///   g_dsn.Register_Receive_Callbacks(rx_cbs);
///   g_dsn.Register_Channel_Callbacks(ch_cbs);
///
///   void main_loop() {
///       g_dsn.Tick(HAL_GetTick());
///   }
///
///   // KT 수신 데이터 도착 시:
///   g_dsn.Feed_DSN_Message(data, len);
///   @endcode
///
/// @warning sizeof(HTS_KT_DSN_Adapter) ~ 512B. 전역/정적 배치 권장.
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_KT_DSN_Adapter_Defs.h"
#include "HTS_IPC_Protocol_Defs.h"
#include <cstdint>
#include <atomic>

namespace ProtectedEngine {

    class HTS_IPC_Protocol;

    /// @brief HTS KT 재난안전망 어댑터
    ///
    /// @warning sizeof ~ 512B. 전역/정적 배치 권장.
    class HTS_KT_DSN_Adapter final {
    public:
        HTS_KT_DSN_Adapter() noexcept;
        ~HTS_KT_DSN_Adapter() noexcept;

        /// @brief 초기화
        /// @param ipc        IPC 프로토콜 엔진
        /// @param area_code  이 장비의 행정구역 코드
        /// @return 성공 시 IPC_Error::OK
        IPC_Error Initialize(HTS_IPC_Protocol* ipc, uint32_t area_code) noexcept;

        /// @brief 종료
        void Shutdown() noexcept;

        /// @brief 재난 수신 콜백 등록
        void Register_Receive_Callbacks(const DSN_Receive_Callbacks& cb) noexcept;

        /// @brief 채널 오버라이드 콜백 등록
        void Register_Channel_Callbacks(const DSN_Channel_Callbacks& cb) noexcept;

        /// @brief KT에서 수신된 DSN 메시지 투입
        /// @param data  메시지 바이트
        /// @param len   길이
        void Feed_DSN_Message(const uint8_t* data, uint16_t len) noexcept;

        /// @brief 주기적 틱 -- 메인 루프에서 호출
        /// @param systick_ms  현재 시스템 틱
        /// @note  재전송 관리 + 경보 만료 체크 + 하트비트.
        void Tick(uint32_t systick_ms) noexcept;

        /// @name 상태
        /// @{
        DSN_State Get_State() const noexcept;
        uint32_t Get_Active_Alert_Count() const noexcept;
        uint32_t Get_Total_Alerts_Received() const noexcept;
        /// @}

        // -- 복사/이동 금지 --
        HTS_KT_DSN_Adapter(const HTS_KT_DSN_Adapter&) = delete;
        HTS_KT_DSN_Adapter& operator=(const HTS_KT_DSN_Adapter&) = delete;
        HTS_KT_DSN_Adapter(HTS_KT_DSN_Adapter&&) = delete;
        HTS_KT_DSN_Adapter& operator=(HTS_KT_DSN_Adapter&&) = delete;

        static constexpr uint32_t IMPL_BUF_SIZE = 512u;

    private:
        struct Impl;
        alignas(4) uint8_t impl_buf_[IMPL_BUF_SIZE];
        std::atomic<bool>  initialized_{ false };
    };

    static_assert(sizeof(HTS_KT_DSN_Adapter) <= 1024u,
        "HTS_KT_DSN_Adapter exceeds 1KB SRAM budget");

} // namespace ProtectedEngine