#pragma once
/// @file  HTS_Console_Manager.h
/// @brief HTS 콘솔 매니저 -- STM32 보안 코프로세서 측
/// @details
///   INNOVID CORE-X Pro 통합콘솔의 A55(Linux)에서 IPC로 전달되는
///   CLI/설정/상태/진단 명령을 STM32 보안 코프로세서에서 처리한다.
///
///   기능:
///   - CONFIG_SET/GET: 채널(BPS/RF/확산), 보안(암호/키/세션), 디바이스 프로파일 설정
///   - STATUS_REQ/RSP: 시스템 상태 스냅샷 보고
///   - DIAG_REQ/RSP: 상세 진단 보고서 (SNR/재밍/온도/SRAM/Flash CRC)
///   - BPS_NOTIFY: 적응형 BPS 변경 시 A55에 자동 알림
///   - JAMMING_ALERT: 재밍 탐지 시 A55에 경보
///
///   아키텍처:
///   - HTS_IPC_Protocol과 연동 (Receive_Frame으로 명령 수신, Send_Frame으로 응답)
///   - constexpr 파라미터 디스패치 테이블 (ASIC ROM 합성 가능)
///   - CFI 검증 상태 머신
///   - 완전 Pimpl 은닉
///   - 힙 할당 제로, float/double 제로, 나눗셈 제로
///
///   사용 예시:
///   @code
///   static ProtectedEngine::HTS_Console_Manager g_console;
///
///   void main_init() {
///       g_console.Initialize(&g_ipc);  // IPC 엔진 포인터 연결
///   }
///
///   void main_loop() {
///       g_ipc.Tick(HAL_GetTick());
///       g_console.Tick(HAL_GetTick());  // IPC에서 명령 수신 및 처리
///   }
///   @endcode
///
/// @warning sizeof(HTS_Console_Manager) ~ 1KB (impl_buf_[1024] 내장).
///          반드시 전역/정적 변수로 배치할 것.
///
/// @note  ARM 전용 모듈. PC/서버 코드 없음.
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_Console_Manager_Defs.h"
#include "HTS_IPC_Protocol_Defs.h"
#include <cstdint>
#include <atomic>

namespace ProtectedEngine {

    // 전방 선언 (Pimpl, 순환 포함 방지)
    class HTS_IPC_Protocol;

    /// @brief HTS 콘솔 매니저 -- STM32 보안 코프로세서
    ///
    /// @warning sizeof ~ 1KB. 전역/정적 배치 필수.
    ///
    /// @par 스레드 안전성
    ///   모든 API는 메인 루프 컨텍스트 전용. ISR에서 호출 금지.
    ///
    /// @par 콜백 인터페이스
    ///   외부 모듈(PHY/FEC/보안 등)의 실시간 데이터를 주입받기 위해
    ///   콜백 함수 포인터 구조체를 사용한다.
    ///   콜백은 Initialize 후 Register_Callbacks()로 등록.
    class HTS_Console_Manager final {
    public:
        /// @brief 외부 모듈 데이터 콜백 (진단 보고서 생성용)
        /// @note  각 함수 포인터는 nullptr이면 해당 필드 0으로 보고.
        ///        ASIC: 함수 포인터 -> 하드와이어 MUX 신호.
        struct DiagCallbacks {
            uint16_t(*get_current_bps)(void);      ///< 현재 BPS 값 조회
            uint16_t(*get_snr_proxy_q8)(void);     ///< SNR 프록시 (Q8)
            uint16_t(*get_jamming_level)(void);    ///< 재밍 레벨
            uint16_t(*get_temperature_q8)(void);   ///< 칩 온도 (Q8 섭씨)
            uint32_t(*get_crc_error_count)(void);  ///< 누적 CRC 에러
            uint32_t(*get_harq_retx_count)(void);  ///< HARQ 재전송 횟수
            uint32_t(*get_sram_usage)(void);       ///< SRAM 사용량 (바이트)
            uint32_t(*get_flash_crc)(void);        ///< 펌웨어 Flash CRC-32
        };

        HTS_Console_Manager() noexcept;
        ~HTS_Console_Manager() noexcept;

        /// @name 수명 주기
        /// @{

        /// @brief 콘솔 매니저 초기화
        /// @param ipc  IPC 프로토콜 엔진 포인터 (수명 동안 유효 필수)
        /// @return 성공 시 IPC_Error::OK
        /// @note  IPC가 이미 초기화된 상태여야 한다.
        ///        compare_exchange_strong으로 멱등성 보장.
        IPC_Error Initialize(HTS_IPC_Protocol* ipc) noexcept;

        /// @brief 종료 및 보안 소거
        void Shutdown() noexcept;

        /// @brief 진단 콜백 등록
        /// @param cb  콜백 구조체 (nullptr 멤버는 0 보고)
        void Register_Callbacks(const DiagCallbacks& cb) noexcept;

        /// @}

        /// @name 메인 루프
        /// @{

        /// @brief 주기적 틱 -- 메인 루프에서 호출
        /// @param systick_ms  현재 시스템 틱 (밀리초)
        /// @note  IPC RX 링에서 명령 프레임을 디큐하여 처리하고
        ///        응답 프레임을 IPC TX 링에 큐잉한다.
        void Tick(uint32_t systick_ms) noexcept;

        /// @}

        /// @name 채널 설정 접근
        /// @{

        /// @brief 현재 채널 설정 조회 (스냅샷 복사)
        /// @param[out] out_config  설정 출력
        void Get_Channel_Config(ChannelConfig& out_config) const noexcept;

        /// @brief 채널 설정 직접 변경 (내부 모듈용, IPC 경유 아님)
        /// @param config  새 설정
        /// @return 성공 시 IPC_Error::OK
        IPC_Error Set_Channel_Config(const ChannelConfig& config) noexcept;

        /// @}

        /// @name 상태
        /// @{

        /// @brief 현재 콘솔 상태 조회
        ConsoleState Get_State() const noexcept;

        /// @brief 진단 보고서 생성 (즉시)
        /// @param[out] out_report  보고서 출력
        void Build_Diag_Report(DiagReport& out_report) const noexcept;

        /// @}

        /// @name 알림 (STM32 -> A55)
        /// @{

        /// @brief BPS 변경 알림 전송
        /// @param new_bps  새 BPS 값
        void Notify_BPS_Change(uint16_t new_bps) noexcept;

        /// @brief 재밍 경보 전송
        /// @param level  재밍 레벨
        void Alert_Jamming(uint16_t level) noexcept;

        /// @}

        // -- 복사/이동 금지 --
        HTS_Console_Manager(const HTS_Console_Manager&) = delete;
        HTS_Console_Manager& operator=(const HTS_Console_Manager&) = delete;
        HTS_Console_Manager(HTS_Console_Manager&&) = delete;
        HTS_Console_Manager& operator=(HTS_Console_Manager&&) = delete;

        /// @brief Pimpl 버퍼 크기 (빌드 시점 sizeof 검증용)
        /// @details 내역:
        ///   - ChannelConfig: 28 바이트
        ///   - DiagCallbacks: 32 바이트 (8 포인터 x 4B on ARM32)
        ///   - DiagReport 캐시: 40 바이트
        ///   - IPC 포인터 + 상태 + tick + 응답 버퍼(264B) + 여유
        ///   - 합계: ~512 바이트, 여유 포함 1024
        static constexpr uint32_t IMPL_BUF_SIZE = 1024u;

    private:
        struct Impl;

        alignas(4) uint8_t impl_buf_[IMPL_BUF_SIZE];
        std::atomic<bool>  initialized_{ false };
    };

    // SRAM 예산: 192KB, Console Manager <= 2KB (1.0%)
    static_assert(sizeof(HTS_Console_Manager) <= 2048u,
        "HTS_Console_Manager exceeds 2KB SRAM budget -- "
        "reduce IMPL_BUF_SIZE");

} // namespace ProtectedEngine