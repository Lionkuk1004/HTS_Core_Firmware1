#pragma once
/// @file  HTS_AMI_Protocol.h
/// @brief HTS AMI 프로토콜 엔진 -- DLMS/COSEM 전력량계 (국제 수출 대응)
/// @details
///   [A1] OBIS 딕셔너리: 국가별 ROM 테이블 주입 (KEPCO/IDIS/ANSI C12)
///   [A2] Security Suite: ARIA-GCM(한국) / AES-GCM(글로벌) 콜백 훅
///   [A3] Block Transfer: 48B 초과 응답 자동 청킹
///
///   사용 예시 (한국 KEPCO):
///   @code
///   static const OBIS_DictEntry kepco_dict[] = { ... };
///   static const OBIS_Dictionary kepco_obis = { kepco_dict, 14 };
///
///   g_ami.Initialize(&g_ipc, device_id);
///   g_ami.Register_OBIS_Dictionary(&kepco_obis);
///   g_ami.Register_Security_Suite(&aria_gcm_suite);
///   g_ami.Register_Meter_Callbacks(meter_cbs);
///   g_ami.Set_Report_Interval(60000u);
///   @endcode
///
/// @warning sizeof(HTS_AMI_Protocol) ~ 640B. 전역/정적 배치 권장.
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_AMI_Protocol_Defs.h"
#include "HTS_IPC_Protocol_Defs.h"
#include <cstdint>
#include <atomic>

namespace ProtectedEngine {

    class HTS_IPC_Protocol;

    /// @brief 미터 계측값 콜백 (외부 하드웨어 ADC 연결)
    /// @note  각 함수 반환값: Q16/Q8 또는 raw uint32_t. nullptr이면 0 보고.
    struct MeterCallbacks {
        uint32_t(*get_energy_import_wh)(void);
        uint32_t(*get_energy_export_wh)(void);
        uint16_t(*get_voltage_l1_q8)(void);
        uint16_t(*get_voltage_l2_q8)(void);
        uint16_t(*get_voltage_l3_q8)(void);
        uint16_t(*get_current_l1_q8)(void);
        uint16_t(*get_current_l2_q8)(void);
        uint16_t(*get_current_l3_q8)(void);
        uint32_t(*get_active_power_w)(void);
        uint16_t(*get_power_factor_q16)(void);
        uint16_t(*get_frequency_q8)(void);
        uint32_t(*get_demand_max_w)(void);
        uint32_t(*get_meter_datetime)(void);
        uint32_t(*get_meter_uptime)(void);     ///< [AMI-6] 추가 — 가동 시간 (초)
    };

    /// @brief HTS AMI 프로토콜 엔진 (국제 수출 대응)
    class HTS_AMI_Protocol final {
    public:
        HTS_AMI_Protocol() noexcept;
        ~HTS_AMI_Protocol() noexcept;

        /// @brief 초기화
        IPC_Error Initialize(HTS_IPC_Protocol* ipc, uint32_t device_id) noexcept;

        /// @brief 종료 및 보안 소거 [AMI-1] impl_buf_ 전체 소거
        void Shutdown() noexcept;

        /// @brief [A1] 국가별 OBIS 딕셔너리 주입
        /// @param dict  OBIS 딕셔너리 (ROM 상주, 수명 ≥ AMI 인스턴스)
        /// @note  미등록 시 내부 기본 테이블 사용 (IEC 62056 표준)
        void Register_OBIS_Dictionary(const OBIS_Dictionary* dict) noexcept;

        /// @brief [A2] 보안 Suite 등록 (ARIA-GCM / AES-GCM)
        /// @param suite  보안 콜백 (nullptr = 평문 모드)
        void Register_Security_Suite(const AMI_SecuritySuite* suite) noexcept;

        /// @brief 미터 콜백 등록
        void Register_Meter_Callbacks(const MeterCallbacks& cb) noexcept;

        /// @brief 주기 보고 간격 설정 (ms, 0=비활성)
        void Set_Report_Interval(uint32_t interval_ms) noexcept;

        /// @brief 주기적 틱 -- 메인 루프에서 호출
        void Tick(uint32_t systick_ms) noexcept;

        /// @brief 즉시 계측 보고서 전송
        IPC_Error Send_Periodic_Report() noexcept;

        /// @brief 수신된 DLMS 요청 처리
        void Process_Request(const uint8_t* apdu, uint16_t apdu_len) noexcept;

        /// @brief 현재 상태 조회
        AMI_State Get_State() const noexcept;

        // -- 복사/이동 금지 --
        HTS_AMI_Protocol(const HTS_AMI_Protocol&) = delete;
        HTS_AMI_Protocol& operator=(const HTS_AMI_Protocol&) = delete;
        HTS_AMI_Protocol(HTS_AMI_Protocol&&) = delete;
        HTS_AMI_Protocol& operator=(HTS_AMI_Protocol&&) = delete;

        // [A2] 보안 버퍼 포함으로 확장
        static constexpr uint32_t IMPL_BUF_SIZE = 640u;

    private:
        struct Impl;
        // [AMI-4] alignas(4) → alignas(8) 프로젝트 Pimpl 표준
        alignas(8) uint8_t impl_buf_[IMPL_BUF_SIZE];
        std::atomic<bool>  initialized_{ false };
    };

    static_assert(sizeof(HTS_AMI_Protocol) <= 1024u,
        "HTS_AMI_Protocol exceeds 1KB SRAM budget");

} // namespace ProtectedEngine