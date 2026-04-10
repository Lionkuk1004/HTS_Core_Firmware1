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

/// @file  HTS_Device_Profile.h
/// @brief HTS 디바이스 프로파일 엔진 -- STM32 보안 코프로세서
/// @details
///   6종 운용 시나리오(재난안전망/스마트안내판/AMI/CCTV/IoT/브릿지) 간
///   런타임 모드 전환을 관리한다. 모드 전환 시:
///   - constexpr 프리셋 테이블에서 채널 설정 로드
///   - 주변장치 활성화/비활성화 (비트맵 기반 콜백)
///   - Console_Manager에 새 채널 설정 적용
///   - CFI 검증 전환 상태 머신
///
///   사용 예시:
///   @code
///   static ProtectedEngine::HTS_Device_Profile g_profile;
///
///   void main_init() {
///       g_profile.Initialize(&g_console);
///       g_profile.Register_Periph_Callbacks(periph_cbs);
///       g_profile.Switch_Mode(DeviceMode::SENSOR_GATEWAY);
///   }
///   @endcode
///
/// @warning sizeof(HTS_Device_Profile) ~ 256B (impl_buf_[256] 내장).
///          전역/정적 배치 권장 (스택 허용 가능하나 비권장).
///
/// @note  ARM 전용. PC/서버 코드 없음.
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_Device_Profile_Defs.h"
#include "HTS_IPC_Protocol_Defs.h"
#include <cstdint>
#include <atomic>

namespace ProtectedEngine {

    // 전방 선언
    class HTS_Console_Manager;

    /// @brief HTS 디바이스 프로파일 엔진
    ///
    /// @warning sizeof ~ 256B. 전역/정적 배치 권장.
    ///
    /// @par 스레드 안전성
    ///   모든 API는 메인 루프 컨텍스트 전용.
    class HTS_Device_Profile final {
    public:
        HTS_Device_Profile() noexcept;
        ~HTS_Device_Profile() noexcept;

        /// @name 수명 주기
        /// @{

        /// @brief 프로파일 엔진 초기화
        /// @param console  콘솔 매니저 포인터 (수명 동안 유효 필수)
        /// @return 성공 시 IPC_Error::OK
        IPC_Error Initialize(HTS_Console_Manager* console) noexcept;

        /// @brief 종료
        void Shutdown() noexcept;

        /// @brief 주변장치 제어 콜백 등록
        /// @param cb  콜백 구조체 (nullptr 멤버는 해당 주변장치 무시)
        void Register_Periph_Callbacks(const PeriphCallbacks& cb) noexcept;

        /// @}

        /// @name 모드 전환
        /// @{

        /// @brief 운용 모드 전환 (프리셋 자동 적용)
        /// @param mode  목표 모드 (DeviceMode 열거형)
        /// @return 성공 시 IPC_Error::OK, 잘못된 모드이면 INVALID_CMD
        /// @note  프리셋 테이블에서 채널 설정 로드 -> 주변장치 재설정 ->
        ///        Console_Manager에 설정 적용. 원자적 전환 보장.
        IPC_Error Switch_Mode(DeviceMode mode) noexcept;

        /// @brief 현재 활성 모드 조회
        DeviceMode Get_Current_Mode() const noexcept;

        /// @brief 현재 모드의 프리셋 조회 (const 참조)
        /// @param[out] out_preset  프리셋 출력
        void Get_Current_Preset(DevicePreset& out_preset) const noexcept;

        /// @brief 특정 모드의 프리셋 조회 (테이블 참조)
        /// @param mode  조회할 모드
        /// @param[out] out_preset  프리셋 출력
        /// @return 유효한 모드이면 true
        bool Get_Preset_For_Mode(DeviceMode mode, DevicePreset& out_preset) const noexcept;

        /// @}

        /// @name 상태
        /// @{

        /// @brief 현재 프로파일 전환 상태 조회
        ProfileState Get_State() const noexcept;

        /// @brief 주변장치 활성화 비트맵 조회
        uint8_t Get_Active_Periph_Mask() const noexcept;

        /// @}

        // -- 복사/이동 금지 --
        HTS_Device_Profile(const HTS_Device_Profile&) = delete;
        HTS_Device_Profile& operator=(const HTS_Device_Profile&) = delete;
        HTS_Device_Profile(HTS_Device_Profile&&) = delete;
        HTS_Device_Profile& operator=(HTS_Device_Profile&&) = delete;

        /// @brief Pimpl 버퍼 크기
        /// @details 내역:
        ///   - Console_Manager 포인터: 4B
        ///   - PeriphCallbacks: 32B (8 포인터 x 4B on ARM32)
        ///   - DevicePreset 캐시: 28B
        ///   - 상태/모드/마스크/패딩: ~16B
        ///   - 합계: ~80B, 여유 포함 256B
        static constexpr uint32_t IMPL_BUF_SIZE = 256u;
        static constexpr unsigned IMPL_BUF_ALIGN = 8u;

    private:
        struct Impl;

        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        std::atomic<uint32_t> init_state_{ 0u };  ///< 0=NONE, 1=BUSY, 2=READY
    };

    // SRAM 예산: 192KB, Device Profile <= 512B (0.3%)
    static_assert(sizeof(HTS_Device_Profile) <= 512u,
        "HTS_Device_Profile exceeds 512B SRAM budget");

} // namespace ProtectedEngine