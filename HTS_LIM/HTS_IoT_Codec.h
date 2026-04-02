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

/// @file  HTS_IoT_Codec.h
/// @brief HTS IoT 코덱 -- 범용 센서 데이터 TLV 직렬화/역직렬화
/// @details
///   센서/액추에이터 데이터를 B-CDMA 페이로드에 직렬화하는 범용 코덱.
///   힙 할당 제로, 정적 버퍼 기반, TLV 체인 구조.
///
///   사용 예시 (송신 측):
///   @code
///   ProtectedEngine::HTS_IoT_Codec codec;
///   codec.Begin_Frame(IoT_MsgType::SENSOR_REPORT, device_id, uptime_sec);
///   codec.Add_U16(SensorType::TEMPERATURE, temp_q8);
///   codec.Add_U16(SensorType::HUMIDITY, hum_q8);
///   codec.Add_U32(SensorType::ENERGY_WH, energy_wh);
///   uint8_t wire[256];
///   uint16_t wire_len = 0;
///   codec.Finalize(wire, sizeof(wire), wire_len);
///   ipc.Send_Frame(IPC_Command::DATA_TX, wire, wire_len);
///   @endcode
///
///   사용 예시 (수신 측):
///   @code
///   IoT_Frame_Header hdr;
///   IoT_TLV_Item items[32];
///   uint8_t item_count = 0;
///   codec.Parse(rx_buf, rx_len, hdr, items, 32, item_count);
///   @endcode
///
/// @warning sizeof(HTS_IoT_Codec) ~ 512B. 전역/정적 배치 권장.
///
/// @note  ARM 전용. PC/서버 코드 없음.
///        Stateless 설계: Begin_Frame -> Add_* -> Finalize 1사이클.
///        스레드 안전하지 않음 (단일 컨텍스트 전용).
/// @warning ISR 내부에서 Begin_Frame/Parse/Finalize 직접 호출 금지 — op_busy_
///          Busy_Guard와 경합. 비상/인터럽트 경로는 메인 루프에 디스패치 후 처리.
/// @author 임영준 (Lim Young-jun)
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_IoT_Codec_Defs.h"
#include "HTS_IPC_Protocol_Defs.h"
#include <cstdint>
#include <atomic>

namespace ProtectedEngine {

    /// @brief HTS IoT 코덱 -- 범용 센서 TLV 직렬화/역직렬화
    ///
    /// @warning sizeof ~ 512B. 전역/정적 배치 권장.
    ///
    /// @par 설계 원칙
    ///   - 힙 0: 내부 직렬화 버퍼는 정적 멤버
    ///   - Begin/Add/Finalize 패턴: 프레임 빌드 후 와이어 버퍼에 출력
    ///   - Parse: 와이어 버퍼에서 TLV 항목 배열로 역직렬화
    ///   - CRC-16 무결성 (IPC_Compute_CRC16 공유)
    class HTS_IoT_Codec final {
    public:
        static constexpr uint32_t SECURE_TRUE = 0x5A5A5A5Au;
        static constexpr uint32_t SECURE_FALSE = 0xA5A5A5A5u;

        HTS_IoT_Codec() noexcept;

        /// @name 프레임 빌드 (송신 측)
        /// @{

        /// @brief 새 IoT 프레임 시작
        /// @param type       메시지 타입
        /// @param device_id  디바이스 고유 ID
        /// @param timestamp  타임스탬프 (에포크 초 또는 가동 초)
        void Begin_Frame(IoT_MsgType type, uint32_t device_id,
            uint32_t timestamp) noexcept;

        /// @brief uint8_t 값 TLV 추가
        /// @param sensor  센서 타입
        /// @param value   값
        /// @return 성공 시 SECURE_TRUE, 실패 시 SECURE_FALSE
        uint32_t Add_U8(SensorType sensor, uint8_t value) noexcept;

        /// @brief uint16_t / int16_t 값 TLV 추가 (빅엔디안 직렬화)
        /// @param sensor  센서 타입
        /// @param value   값
        /// @return 성공 시 SECURE_TRUE, 실패 시 SECURE_FALSE
        uint32_t Add_U16(SensorType sensor, uint16_t value) noexcept;

        /// @brief uint32_t / int32_t 값 TLV 추가 (빅엔디안 직렬화)
        /// @param sensor  센서 타입
        /// @param value   값
        /// @return 성공 시 SECURE_TRUE, 실패 시 SECURE_FALSE
        uint32_t Add_U32(SensorType sensor, uint32_t value) noexcept;

        /// @brief 원시 바이트 배열 TLV 추가
        /// @param sensor    센서 타입
        /// @param data      값 바이트
        /// @param data_len  값 길이 (1~8)
        /// @return 성공 시 SECURE_TRUE, 실패 시 SECURE_FALSE
        uint32_t Add_Raw(SensorType sensor, const uint8_t* data,
            uint8_t data_len) noexcept;

        /// @brief 프레임 완성: CRC 부착 및 와이어 버퍼 출력
        /// @param[out] out_buf     출력 와이어 버퍼
        /// @param      out_buf_size 출력 버퍼 크기
        /// @param[out] out_len     실제 기록된 바이트
        /// @return 성공 시 SECURE_TRUE, 실패 시 SECURE_FALSE
        uint32_t Finalize(uint8_t* out_buf, uint16_t out_buf_size,
            uint16_t& out_len) noexcept;

        /// @}

        /// @name 프레임 파싱 (수신 측)
        /// @{

        /// @brief 와이어 버퍼에서 IoT 프레임 파싱
        /// @param[in]  wire_buf    입력 와이어 버퍼
        /// @param      wire_len    입력 길이
        /// @param[out] out_header  프레임 헤더
        /// @param[out] out_items   TLV 항목 배열 (호출자 제공)
        /// @param      max_items   배열 최대 크기
        /// @param[out] out_item_count 실제 파싱된 항목 수
        /// @return 성공 시 SECURE_TRUE, 실패 시 SECURE_FALSE
        uint32_t Parse(const uint8_t* wire_buf, uint16_t wire_len,
            IoT_Frame_Header& out_header,
            IoT_TLV_Item* out_items, uint8_t max_items,
            uint8_t& out_item_count) const noexcept;

        /// @}

        /// @brief 현재 빌드 중인 프레임의 TLV 항목 수
        uint8_t Get_TLV_Count() const noexcept;

        /// @brief 현재 빌드 중인 프레임의 사용된 바이트
        uint16_t Get_Used_Bytes() const noexcept;

        // -- 복사 허용 (경량 구조체, Pimpl 불필요) --

    private:
        /// 내부 직렬화 버퍼 (정적, 프레임 1개분)
        uint8_t  build_buf_[IOT_MAX_FRAME_SIZE];
        uint16_t build_pos_;     ///< 현재 기록 위치
        uint8_t  tlv_count_;     ///< 추가된 TLV 항목 수
        bool     frame_active_;  ///< Begin_Frame 호출 여부
        mutable std::atomic_flag op_busy_ = ATOMIC_FLAG_INIT;

        /// @brief 엔디안 독립 직렬화 헬퍼 (인라인)
        static void Write_U16(uint8_t* b, uint16_t v) noexcept
        {
            b[0] = static_cast<uint8_t>(v >> 8u);
            b[1] = static_cast<uint8_t>(v & 0xFFu);
        }
        static void Write_U32(uint8_t* b, uint32_t v) noexcept
        {
            b[0] = static_cast<uint8_t>(v >> 24u);
            b[1] = static_cast<uint8_t>((v >> 16u) & 0xFFu);
            b[2] = static_cast<uint8_t>((v >> 8u) & 0xFFu);
            b[3] = static_cast<uint8_t>(v & 0xFFu);
        }
        static uint16_t Read_U16(const uint8_t* b) noexcept
        {
            return static_cast<uint16_t>(
                (static_cast<uint16_t>(b[0]) << 8u) | static_cast<uint16_t>(b[1]));
        }
        static uint32_t Read_U32(const uint8_t* b) noexcept
        {
            return (static_cast<uint32_t>(b[0]) << 24u) |
                (static_cast<uint32_t>(b[1]) << 16u) |
                (static_cast<uint32_t>(b[2]) << 8u) |
                static_cast<uint32_t>(b[3]);
        }
    };

    // sizeof: 256(buf) + 2 + 1 + 1 + padding ~ 264B
    static_assert(sizeof(HTS_IoT_Codec) <= 512u,
        "HTS_IoT_Codec exceeds 512B SRAM budget");

} // namespace ProtectedEngine