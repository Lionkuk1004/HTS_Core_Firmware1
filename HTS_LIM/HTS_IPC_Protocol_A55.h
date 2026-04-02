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

/// @file  HTS_IPC_Protocol_A55.h
/// @brief HTS IPC 프로토콜 엔진 -- A55 SPI 마스터 측 (Linux aarch64)
/// @details
///   Cortex-A55 (INNOVID CORE-X Pro, Linux aarch64) SPI 마스터 IPC 엔진.
///   STM32F407 보안 코프로세서(SPI 슬레이브)와 spidev를 통해 통신한다.
///
///   아키텍처:
///   - Linux spidev를 통한 SPI 마스터 모드 (/dev/spidevX.Y)
///   - Linux GPIO chardev/sysfs를 통한 DRDY 입력 (상승 에지 트리거)
///   - 백그라운드 RX 스레드: DRDY를 poll하여 상승 에지 시 SPI 전송 수행
///   - TX/RX 프레임 큐잉용 lock-free 링 버퍼
///     TX 링: MPSC (Send_Frame + Tick_Heartbeat 다중 생산자, spinlock 보호)
///     RX 링: SPSC (RX 스레드 생산, 메인 스레드 소비)
///   - CRC-16 CCITT 검증 프레이밍 (STM32 측과 공유 프로토콜)
///   - CFI 검증 상태 머신
///   - 완전 Pimpl 은닉
///
///   사용 예시:
///   @code
///   ProtectedEngine::HTS_IPC_Protocol_A55 ipc;
///   ProtectedEngine::IPC_A55_Config cfg{};
///   cfg.spidev_path = "/dev/spidev0.0";
///   cfg.spi_speed_hz = 8000000;        // 8 MHz
///   cfg.gpio_drdy_chip = 0;            // gpiochip0
///   cfg.gpio_drdy_line = 24;           // GPIO 24
///   cfg.frame_timeout_ms = 100;
///   cfg.ping_interval_ms = 1000;
///   ipc.Initialize(cfg);
///
///   // STM32로 B-CDMA TX 데이터 전송
///   uint8_t payload[64] = { ... };
///   ipc.Send_Frame(IPC_Command::DATA_TX, payload, 64);
///
///   // STM32에서 처리된 데이터 수신
///   IPC_Command cmd;
///   uint8_t rx_buf[256];
///   uint16_t rx_len = 0;
///   if (ipc.Receive_Frame(cmd, rx_buf, sizeof(rx_buf), rx_len) == IPC_Error::OK) {
///       // rx_buf[0..rx_len-1] 처리
///   }
///
///   ipc.Tick(get_monotonic_ms());  // 하트비트/타임아웃 관리
///   ipc.Shutdown();
///   @endcode
///
/// @warning sizeof(HTS_IPC_Protocol_A55) ~ 8KB (impl_buf_[8192] 내장).
///          A55 Linux에서 힙 할당 가능하나, STM32 측 Pimpl 패턴과
///          일관성을 위해 placement new 사용.
///
/// @note  AArch64 Linux 전용. HTS_PLATFORM_AARCH64 가드.
///        STM32 레지스터 레벨 코드 없음.
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#ifdef HTS_PLATFORM_AARCH64

#include "HTS_IPC_Protocol_Defs.h"
#include <cstdint>
#include <cstddef>
#include <atomic>

namespace ProtectedEngine {

    // ============================================================
    //  A55 전용 설정
    // ============================================================

    /// @brief A55 IPC 모듈 설정
    struct IPC_A55_Config {
        char     spidev_path[64];       ///< spidev 디바이스 경로 (예: "/dev/spidev0.0")
        uint32_t spi_speed_hz;          ///< SPI 클럭 주파수 (Hz), 통상 1~16 MHz
        uint8_t  spi_mode;              ///< SPI 모드 (0~3), STM32 슬레이브와 일치 필수
        uint8_t  spi_bits_per_word;     ///< 워드당 비트 (기본 8)
        uint8_t  gpio_drdy_chip;        ///< gpiochip 인덱스 (예: /dev/gpiochip0이면 0)
        uint8_t  gpio_drdy_line;        ///< DRDY 입력 GPIO 라인 번호
        uint32_t frame_timeout_ms;      ///< 프레임 수신 타임아웃
        uint32_t ping_interval_ms;      ///< 하트비트 주기 (0=비활성)
        uint32_t poll_timeout_ms;       ///< DRDY poll() 타임아웃 (기본 50ms)
        uint8_t  reserved[4];           ///< 정렬 패딩
    };
    static_assert(sizeof(IPC_A55_Config) == 88u, "IPC_A55_Config size check");

    /// @brief HTS IPC 프로토콜 엔진 -- A55 SPI 마스터
    ///
    /// @warning sizeof ~ 8KB. 내부 placement new Pimpl 버퍼 사용.
    ///
    /// @par 스레드 안전성
    ///   - Initialize(), Shutdown() : 단일 스레드 초기화/해제만
    ///   - Tick(), Send_Frame(), Receive_Frame(), Get_*() : 메인 스레드만
    ///   - 내부 RX 스레드가 DRDY 폴링 및 SPI 전송 처리
    ///   - TX 링: MPSC (메인+Tick 컨텍스트 생산, spinlock 직렬화)
    ///   - RX 링: SPSC (RX 스레드 생산, 메인 소비)
    class HTS_IPC_Protocol_A55 final {
    public:
        HTS_IPC_Protocol_A55() noexcept;
        ~HTS_IPC_Protocol_A55() noexcept;

        /// @name 수명 주기
        /// @{

        /// @brief A55 IPC 엔진 초기화
        /// @param config  설정 (spidev 경로, GPIO, 타이밍)
        /// @return 성공 시 IPC_Error::OK
        /// @note  spidev 열기, GPIO DRDY 설정, RX 스레드 생성.
        ///        CAS 가드로 멱등성 보장.
        IPC_Error Initialize(const IPC_A55_Config& config) noexcept;

        /// @brief 종료: RX 스레드 정지, spidev/GPIO 닫기, 보안 소거
        void Shutdown() noexcept;

        /// @brief 프로토콜 상태 리셋 (에러 복구 후 재동기)
        /// @return 성공 시 IPC_Error::OK
        IPC_Error Reset() noexcept;

        /// @}

        /// @name 메인 루프
        /// @{

        /// @brief 주기적 틱 -- 메인 루프에서 호출
        /// @param monotonic_ms  단조 클럭 밀리초
        /// @note  대기 TX 프레임 전송, 하트비트 관리, 타임아웃 점검.
        void Tick(uint32_t monotonic_ms) noexcept;

        /// @}

        /// @name 데이터 전송
        /// @{

        /// @brief STM32로 전송할 프레임을 TX 링에 큐잉
        /// @param cmd         명령 코드
        /// @param payload     페이로드 (payload_len == 0이면 nullptr 가능)
        /// @param payload_len 페이로드 길이 (0 ~ IPC_MAX_PAYLOAD)
        /// @return 성공 시 IPC_Error::OK, TX 링 가득 차면 QUEUE_FULL
        IPC_Error Send_Frame(IPC_Command cmd,
            const uint8_t* payload,
            uint16_t payload_len) noexcept;

        /// @brief STM32에서 수신된 프레임을 RX 링에서 디큐
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

        /// @brief 누적 통계 조회
        void Get_Statistics(IPC_Statistics& out_stats) const noexcept;

        /// @brief STM32 링크 생존 여부 확인 (하트비트 정상)
        bool Is_Link_Alive() const noexcept;

        /// @brief TX 링 대기 프레임 수
        uint32_t Get_TX_Pending() const noexcept;

        /// @brief RX 링 대기 프레임 수
        uint32_t Get_RX_Pending() const noexcept;

        /// @}

        // -- 복사/이동 금지 --
        HTS_IPC_Protocol_A55(const HTS_IPC_Protocol_A55&) = delete;
        HTS_IPC_Protocol_A55& operator=(const HTS_IPC_Protocol_A55&) = delete;
        HTS_IPC_Protocol_A55(HTS_IPC_Protocol_A55&&) = delete;
        HTS_IPC_Protocol_A55& operator=(HTS_IPC_Protocol_A55&&) = delete;

        /// @brief Pimpl 버퍼 크기 (빌드 시점 sizeof 검증용 공개)
        /// @details 내역:
        ///   - RX 링: 8 x 268 = 2144 바이트
        ///   - TX 링: 8 x 268 = 2144 바이트
        ///   - SPI TX/RX 버퍼: 2 x 264 = 528 바이트
        ///   - 설정 + 상태 + 통계 + FD + Atomic: ~512 바이트
        ///   - pthread 객체: ~256 바이트
        ///   - 여유: ~2608 바이트
        ///   - 합계: ~8192 바이트
        static constexpr uint32_t IMPL_BUF_SIZE = 8192u;

    private:
        struct Impl;

        alignas(8) uint8_t impl_buf_[IMPL_BUF_SIZE];
        std::atomic<bool>  initialized_{ false };
    };

    // A55는 8GB RAM -- 여유롭지만 규율을 위해 16KB로 제한
    static_assert(sizeof(HTS_IPC_Protocol_A55) <= 16384u,
        "HTS_IPC_Protocol_A55 exceeds 16KB budget -- "
        "reduce IMPL_BUF_SIZE or ring buffer depth");

} // namespace ProtectedEngine

#endif // HTS_PLATFORM_AARCH64