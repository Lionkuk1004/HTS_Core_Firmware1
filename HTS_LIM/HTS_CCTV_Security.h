#pragma once
/// @file  HTS_CCTV_Security.h
/// @brief HTS CCTV 보안 코프로세서 -- 카메라 해킹 방지
/// @details
///   CCTV 카메라에 내장되는 HTS B-CDMA 보안 칩.
///   영상 전송이 아닌 보안 감시를 전담하며, 해킹 시도를
///   실시간 탐지하여 B-CDMA 망으로 보안 이벤트를 보고한다.
///
///   방어 기능:
///   - 영상 스트림 HMAC 인증 (위변조/replay 공격 방지)
///   - 펌웨어 CRC 주기 검증 (백도어 삽입 탐지)
///   - 네트워크 침입 감시 (브루트포스/포트스캔/RTSP 하이재킹)
///   - 물리적 탬퍼 감지 (케이스/렌즈/케이블/방향/JTAG)
///   - 비상 잠금 (LOCKDOWN): 위험 이벤트 시 RTSP 차단, 알림 집중
///   - 보안 이벤트 B-CDMA 실시간 전송 (HMAC 인증 태그 부착)
///
///   사용 예시:
///   @code
///   static ProtectedEngine::HTS_CCTV_Security g_cctv_sec;
///   g_cctv_sec.Initialize(&g_ipc, camera_id);
///   g_cctv_sec.Register_Monitor_Callbacks(mon_cbs);
///   g_cctv_sec.Register_Auth_Callbacks(auth_cbs);
///   g_cctv_sec.Set_HMAC_Key(key, 32);
///
///   void main_loop() {
///       g_cctv_sec.Tick(HAL_GetTick());
///   }
///   @endcode
///
/// @warning sizeof(HTS_CCTV_Security) ~ 1KB. 전역/정적 배치 권장.
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_CCTV_Security_Defs.h"
#include "HTS_IPC_Protocol_Defs.h"
#include <cstdint>
#include <atomic>

namespace ProtectedEngine {

    class HTS_IPC_Protocol;

    /// @brief HTS CCTV 보안 코프로세서
    ///
    /// @warning sizeof ~ 1KB. 전역/정적 배치 권장.
    class HTS_CCTV_Security final {
    public:
        HTS_CCTV_Security() noexcept;
        ~HTS_CCTV_Security() noexcept;

        /// @brief 초기화
        /// @param ipc        IPC 프로토콜 엔진
        /// @param camera_id  카메라 고유 ID
        /// @return 성공 시 IPC_Error::OK
        IPC_Error Initialize(HTS_IPC_Protocol* ipc, uint32_t camera_id) noexcept;

        /// @brief 종료 및 보안 소거 (HMAC 키 포함)
        void Shutdown() noexcept;

        /// @brief 모니터링 콜백 등록
        void Register_Monitor_Callbacks(const CCTV_Monitor_Callbacks& cb) noexcept;

        /// @brief 스트림 인증 콜백 등록
        void Register_Auth_Callbacks(const CCTV_Auth_Callbacks& cb) noexcept;

        /// @brief HMAC 키 설정 (KCMVP SHA-256용)
        /// @param key      키 바이트 (32바이트 권장)
        /// @param key_len  키 길이 (최대 32)
        /// @return 성공 시 IPC_Error::OK
        IPC_Error Set_HMAC_Key(const uint8_t* key, uint8_t key_len) noexcept;

        /// @brief 주기적 틱 -- 메인 루프에서 호출
        /// @param systick_ms  현재 시스템 틱
        /// @note  펌웨어 CRC 검증 / 스트림 HMAC 검증 / 탬퍼 감지 /
        ///        네트워크 감시 / 하트비트 보고 주기 실행.
        void Tick(uint32_t systick_ms) noexcept;

        /// @brief 수동 보안 이벤트 발생
        /// @param evt       이벤트 타입
        /// @param severity  심각도
        /// @param detail    상세 바이트 (nullable)
        /// @param detail_len 상세 길이
        void Report_Event(CCTV_EventType evt, CCTV_Severity severity,
            const uint8_t* detail, uint8_t detail_len) noexcept;

        /// @brief 비상 잠금 수동 발동
        IPC_Error Enter_Lockdown() noexcept;

        /// @brief 비상 잠금 해제 (인증 후)
        IPC_Error Exit_Lockdown() noexcept;

        /// @name 상태
        /// @{
        CCTV_SecState Get_State() const noexcept;
        uint32_t Get_Event_Count() const noexcept;
        uint32_t Get_Critical_Count() const noexcept;

        /// @brief 최근 이벤트 로그 조회
        /// @param[out] out_log   로그 배열 (호출자 제공)
        /// @param      max_count 배열 최대 크기
        /// @param[out] out_count 실제 반환된 항목 수
        void Get_Recent_Events(CCTV_EventLog* out_log, uint8_t max_count,
            uint8_t& out_count) const noexcept;
        /// @}

        // -- 복사/이동 금지 --
        HTS_CCTV_Security(const HTS_CCTV_Security&) = delete;
        HTS_CCTV_Security& operator=(const HTS_CCTV_Security&) = delete;
        HTS_CCTV_Security(HTS_CCTV_Security&&) = delete;
        HTS_CCTV_Security& operator=(HTS_CCTV_Security&&) = delete;

        static constexpr uint32_t IMPL_BUF_SIZE = 1024u;

    private:
        struct Impl;
        alignas(4) uint8_t impl_buf_[IMPL_BUF_SIZE];
        std::atomic<bool>  initialized_{ false };
    };

    static_assert(sizeof(HTS_CCTV_Security) <= 2048u,
        "HTS_CCTV_Security exceeds 2KB SRAM budget");

} // namespace ProtectedEngine