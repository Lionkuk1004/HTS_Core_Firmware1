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

/// @file  HTS_IPC_Protocol.h
/// @brief HTS IPC 프로토콜 엔진 -- STM32 SPI 슬레이브 측
/// @details
///   STM32F407VGT6(Cortex-M4F)에서 동작하는 SPI 슬레이브 IPC 엔진.
///   통합콘솔 Cortex-A55(SPI 마스터)와 양방향 프레임 통신을 수행한다.
///
///   아키텍처:
///   - SPI 슬레이브 모드, DMA 기반 TX/RX (데이터 경로 CPU 폴링 제로)
///   - Lock-free 링 버퍼로 TX/RX 프레임 큐잉 (ISR 안전, atomic CAS)
///   - DRDY GPIO: STM32 -> A55 데이터 준비 인터럽트 신호
///   - 모든 프레임에 CRC-16 CCITT (512B constexpr LUT)
///   - CFI 검증 상태 머신 (다중 비트 글리치 방어)
///   - 완전 Pimpl 은닉 (헤더에 구현 세부사항 노출 없음)
///
///   사용 예시:
///   @code
///   static ProtectedEngine::HTS_IPC_Protocol g_ipc;  // 전역/정적만 허용!
///
///   void main_init() {
///       ProtectedEngine::IPC_Config cfg{};
///       cfg.spi_base_addr    = 0x40013000u;  // SPI1
///       cfg.dma_base_addr    = 0x40026400u;  // DMA2
///       cfg.dma_stream_rx    = 0u;           // Stream0
///       cfg.dma_stream_tx    = 3u;           // Stream3
///       cfg.dma_channel      = 3u;           // Channel3
///       cfg.drdy_port_index  = 0u;           // GPIOA
///       cfg.drdy_pin         = 8u;           // PA8
///       cfg.frame_timeout_ms = 100u;
///       cfg.ping_interval_ms = 1000u;
///       g_ipc.Initialize(cfg);
///   }
///
///   void main_loop() {
///       g_ipc.Tick(HAL_GetTick());  // systick ms 전달
///   }
///
///   // DMA2_Stream0_IRQHandler (SPI1 RX 완료):
///   extern "C" void DMA2_Stream0_IRQHandler() { g_ipc.ISR_SPI_RX_Complete(); }
///   @endcode
///
/// @warning sizeof(HTS_IPC_Protocol) ~ 6KB (impl_buf_[6144] 내장).
///          반드시 전역/정적 변수로 배치할 것.
///          Cortex-M4 스택(2~8KB)에 선언 시 즉시 오버플로우.
///
/// @note  ARM 전용 모듈. PC/서버 코드 없음.
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

// ARM Cortex-M (STM32) 전용 모듈: A55/리눅스 서버 빌드 차단
// Visual Studio Windows 정적 라이브러리(HTS_LIM.vcxproj)는 _WIN32 로 호스트 단위검증 빌드 허용.
#if (((!defined(__arm__) && !defined(__TARGET_ARCH_ARM) && \
      !defined(__TARGET_ARCH_THUMB) && !defined(__ARM_ARCH)) || \
     defined(__aarch64__)) && !defined(_WIN32))
#error "[HTS_FATAL] HTS_IPC_Protocol은 STM32 전용입니다. A55/서버 빌드에서 제외하십시오."
#endif

#include "HTS_IPC_Protocol_Defs.h"
#include <cstdint>
#include <cstddef>
#include <atomic>

namespace ProtectedEngine {

    /// @brief HTS IPC 프로토콜 엔진 -- STM32 SPI 슬레이브
    ///
    /// @warning sizeof ~ 6KB. 전역/정적 배치 필수.
    ///          스택 선언 시 Cortex-M4 즉시 오버플로우.
    ///
    /// @par 스레드 안전성
    ///   - Tick(), Send_Frame(), Receive_Frame(), Get_*() : 메인 루프 컨텍스트만
    ///   - ISR_SPI_RX_Complete(), ISR_SPI_TX_Complete() : ISR 컨텍스트만
    ///   - 링 버퍼 head/tail은 atomic (ISR<->메인 lock-free 통신)
    ///
    /// @par Pimpl
    ///   구현부는 Impl 구조체에 완전 은닉 (HTS_IPC_Protocol.cpp).
    ///   공개 헤더는 API 표면만 노출.
    class HTS_IPC_Protocol final {
    public:
        static constexpr uint32_t SECURE_TRUE = 0x5A5A5A5Au;
        static constexpr uint32_t SECURE_FALSE = 0xA5A5A5A5u;

        HTS_IPC_Protocol() noexcept;
        ~HTS_IPC_Protocol() noexcept;

        /// @name 수명 주기
        /// @{

        /// @brief 하드웨어 설정으로 IPC 엔진 초기화
        /// @param config  하드웨어 설정 (SPI 베이스, DMA, GPIO)
        /// @return 성공 시 IPC_Error::OK
        /// @note  다른 메서드 호출 전 정확히 1회 호출 필수.
        ///        compare_exchange_strong으로 멱등성 보장.
        IPC_Error Initialize(const IPC_Config& config) noexcept;

        /// @brief 종료 및 모든 내부 상태 보안 소거
        void Shutdown() noexcept;

        /// @brief 프로토콜 상태 리셋 (에러 복구 후 재동기)
        /// @return 성공 시 IPC_Error::OK
        IPC_Error Reset() noexcept;

        /// @}

        /// @name 메인 루프
        /// @{

        /// @brief 주기적 틱 -- 메인 루프에서 1 kHz 이상으로 호출
        /// @param systick_ms  현재 시스템 틱 (밀리초)
        /// @note  수신 프레임 처리, 타임아웃 관리, 하트비트 처리.
        ///        ISR 컨텍스트에서 호출 금지.
        void Tick(uint32_t systick_ms) noexcept;

        /// @}

        /// @name 데이터 전송
        /// @{

        /// @brief A55로 전송할 프레임을 TX 링에 큐잉
        /// @param cmd         명령 코드
        /// @param payload     페이로드 (payload_len == 0이면 nullptr 가능)
        /// @param payload_len 페이로드 길이 (0 ~ IPC_MAX_PAYLOAD)
        /// @return 성공 시 IPC_Error::OK, TX 링 가득 차면 QUEUE_FULL
        IPC_Error Send_Frame(IPC_Command cmd,
            const uint8_t* payload,
            uint16_t payload_len) noexcept;

        /// @brief A55에서 수신된 프레임을 RX 링에서 디큐
        /// @param[out] out_cmd         수신된 명령
        /// @param[out] out_payload     페이로드 복사 대상 버퍼
        /// @param      out_buf_size    out_payload 버퍼 크기
        /// @param[out] out_payload_len 실제 페이로드 길이
        /// @return 성공 시 IPC_Error::OK, RX 링 비어있으면 QUEUE_FULL.
        ///         페이로드가 out_buf_size를 초과하면 BUFFER_OVERFLOW (fail-closed).
        IPC_Error Receive_Frame(IPC_Command& out_cmd,
            uint8_t* out_payload,
            uint16_t      out_buf_size,
            uint16_t& out_payload_len) noexcept;

        /// @}

        /// @name 상태 및 진단
        /// @{

        /// @brief 현재 프로토콜 상태 조회
        IPC_State Get_State() const noexcept;

        /// @brief 누적 통계 스냅샷 조회
        /// @param[out] out_stats  통계 출력
        void Get_Statistics(IPC_Statistics& out_stats) const noexcept;

        /// @brief A55 링크 생존 여부 확인 (하트비트 정상 여부)
        /// @return 마지막 하트비트가 3배 핑 주기 이내이면 SECURE_TRUE
        uint32_t Is_Link_Alive() const noexcept;

        /// @brief TX 링 대기 프레임 수
        uint32_t Get_TX_Pending() const noexcept;

        /// @brief RX 링 대기 프레임 수
        uint32_t Get_RX_Pending() const noexcept;

        /// @}

        /// @name ISR 콜백
        /// @{
        /// @note 대응하는 ISR 핸들러에서 반드시 호출할 것.
        ///       Lock-free이며 ISR 안전.

        /// @brief SPI RX DMA 전송 완료 콜백
        void ISR_SPI_RX_Complete() noexcept;

        /// @brief SPI TX DMA 전송 완료 콜백
        void ISR_SPI_TX_Complete() noexcept;

        /// @brief SPI 에러 인터럽트 콜백
        void ISR_SPI_Error() noexcept;

        /// @}

        // -- 복사/이동 금지 --
        HTS_IPC_Protocol(const HTS_IPC_Protocol&) = delete;
        HTS_IPC_Protocol& operator=(const HTS_IPC_Protocol&) = delete;
        HTS_IPC_Protocol(HTS_IPC_Protocol&&) = delete;
        HTS_IPC_Protocol& operator=(HTS_IPC_Protocol&&) = delete;

        /// @brief Pimpl 버퍼 크기 (빌드 시점 sizeof 검증용 공개)
        /// @details 내역:
        ///   - RX 링: 8 x 268 = 2144 바이트
        ///   - TX 링: 8 x 268 = 2144 바이트
        ///   - SPI DMA RX/TX 버퍼: 2 x 264 = 528 바이트
        ///   - Idle 버퍼: 264 바이트
        ///   - Atomic + 상태 + 설정 + 통계 + 기타: ~256 바이트
        ///   - 합계: ~5336 바이트, 여유 포함 6144로 상향
        static constexpr uint32_t IMPL_BUF_SIZE = 6144u;

    private:
        struct Impl;

        alignas(8) uint8_t impl_buf_[IMPL_BUF_SIZE];
        std::atomic<bool>  initialized_{ false };
    };

    // SRAM 예산: 192KB 중 IPC <= 8KB (4.2%)
    static_assert(sizeof(HTS_IPC_Protocol) <= 8192u,
        "HTS_IPC_Protocol exceeds 8KB SRAM budget -- "
        "reduce IMPL_BUF_SIZE or ring buffer depth");

} // namespace ProtectedEngine