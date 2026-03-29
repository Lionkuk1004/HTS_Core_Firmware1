#pragma once
/// @file  HTS_OTA_Manager.h
/// @brief HTS OTA 매니저 -- 원격 펌웨어 업데이트
/// @details
///   A55(Linux)에서 IPC로 전달받은 펌웨어 이미지를 STM32 Flash Bank B에
///   기록하고, CRC-32 + 버전 검증 후 듀얼 뱅크 스왑으로 안전하게 업데이트.
///
///   업데이트 흐름:
///   1. BEGIN: 이미지 메타 수신 (크기/버전/CRC/청크수)
///   2. CHUNK_DATA: 분할 청크 순차 수신 -> Bank B Flash 기록
///   3. VERIFY: 전체 이미지 CRC-32 검증 + 롤백 방지 버전 검사
///   4. COMMIT: 뱅크 스왑 실행 -> 시스템 리부팅
///
///   안전 장치:
///   - 듀얼 뱅크: 실패 시 원래 Bank A 유지 (벽돌 방지)
///   - 롤백 방지: 현재 버전 이하 거부
///   - CRC-32 전체 검증 후에만 커밋 허용
///   - ABORT: 수신 중 언제든 중단 가능
///
/// [양산 수정 이력]
///  OTA-1 [HIGH] Get_Progress_Percent 나눗셈 → Q16 역수 사전 계산
///  OTA-2 [HIGH] Shutdown 보안 소거 추가
///  OTA-3 [MED]  생성자 memset 표준 통일
///  OTA-4 [MED]  alignas(4) → alignas(8) 프로젝트 Pimpl 표준
///  OTA-5 [LOW]  Verify 256B 청크 읽기
///
/// @warning sizeof(HTS_OTA_Manager) ~ 512B. 전역/정적 배치 권장.
///
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_OTA_Manager_Defs.h"
#include "HTS_IPC_Protocol_Defs.h"
#include <cstdint>
#include <atomic>

namespace ProtectedEngine {

    class HTS_IPC_Protocol;

    /// @brief HTS OTA 매니저
    ///
    /// @warning sizeof ~ 512B. 전역/정적 배치 권장.
    class HTS_OTA_Manager final {
    public:
        HTS_OTA_Manager() noexcept;
        ~HTS_OTA_Manager() noexcept;

        /// @brief 초기화
        /// @param ipc  IPC 프로토콜 엔진
        /// @return 성공 시 IPC_Error::OK
        IPC_Error Initialize(HTS_IPC_Protocol* ipc) noexcept;

        /// @brief 종료 — impl_buf_ 보안 소거 포함 [OTA-2]
        void Shutdown() noexcept;

        /// @brief Flash HAL 콜백 등록
        void Register_Flash_Callbacks(const OTA_Flash_Callbacks& cb) noexcept;

        /// @brief OTA 명령 처리 (IPC 수신 프레임에서 호출)
        /// @param payload  OTA 프레임 페이로드
        /// @param len      길이
        void Process_OTA_Command(const uint8_t* payload, uint16_t len) noexcept;

        /// @brief 현재 OTA 상태
        OTA_State Get_State() const noexcept;

        /// @brief 수신 진행률 (0~100)
        /// [OTA-1] Q16 역수 곱셈 — hot path 나눗셈 0회
        uint8_t Get_Progress_Percent() const noexcept;

        /// @brief 마지막 결과 코드
        OTA_Result Get_Last_Result() const noexcept;

        /// @brief 수신된 청크 수
        uint16_t Get_Received_Chunks() const noexcept;

        // -- 복사/이동 금지 --
        HTS_OTA_Manager(const HTS_OTA_Manager&) = delete;
        HTS_OTA_Manager& operator=(const HTS_OTA_Manager&) = delete;
        HTS_OTA_Manager(HTS_OTA_Manager&&) = delete;
        HTS_OTA_Manager& operator=(HTS_OTA_Manager&&) = delete;

        static constexpr uint32_t IMPL_BUF_SIZE = 512u;

    private:
        struct Impl;
        // [OTA-4] alignas(4) → alignas(8): BB1/TensorCodec/ECCM Pimpl 표준 통일
        alignas(8) uint8_t impl_buf_[IMPL_BUF_SIZE];
        std::atomic<bool>  initialized_{ false };
    };

    static_assert(sizeof(HTS_OTA_Manager) <= 1024u,
        "HTS_OTA_Manager exceeds 1KB SRAM budget");

} // namespace ProtectedEngine