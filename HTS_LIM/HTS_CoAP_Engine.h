// =========================================================================
// HTS_CoAP_Engine.h
// 경량 CoAP 메시징 엔진 (RFC 7252 간소화)
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  [패킷 구조]  dest_id(2B) + CoAP헤더(6B) + payload(≤48B) = ≤56B
//
//  [0-1]  dest_id    목적지 장비 ID (메쉬 라우팅용, LE)
//  [2]    ver(2b)|type(2b)|tkl(4b)
//  [3]    code       메서드 또는 응답코드
//  [4-5]  message_id 메시지 ID (BE)
//  [6-7]  token      2바이트 토큰 (BE)
//  [8..]  payload    URI + 데이터
//
//  [T-1] On_Message_Received: msg_len > MAX_PKT_SIZE 구간은 구현부에서 폐기
//        (payload 길이 > MAX_PAYLOAD 시 핸들러 주입 길이 폭주 방지)
//  [RF-비대칭] 동일 (src_id, MID) CON 재전송은 8슬롯 윈도로 중복 억제 — ACK 유실 시 상위 중복 인입 방지
//
//  @warning sizeof ≈ 768B — 전역/정적 배치 필수
// ─────────────────────────────────────────────────────────────────────────
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

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    class HTS_Priority_Scheduler;

    namespace CoapCode {
        static constexpr uint8_t GET = 0x01u;
        static constexpr uint8_t POST = 0x02u;
        static constexpr uint8_t PUT = 0x03u;
        static constexpr uint8_t OK_200 = 0x44u;
        static constexpr uint8_t CONTENT_205 = 0x45u;
        static constexpr uint8_t BAD_REQ_400 = 0x80u;
        static constexpr uint8_t NOT_FOUND = 0x84u;
    }

    enum class CoapType : uint8_t {
        CON = 0u, NON = 1u, ACK = 2u, RST = 3u,
    };

    using ResourceHandler = size_t(*)(
        uint8_t method,
        const uint8_t* payload, size_t pay_len,
        uint8_t* resp_buf, size_t resp_cap);

    class HTS_CoAP_Engine {
    public:
        static constexpr size_t MAX_RESOURCES = 8u;
        static constexpr size_t MAX_URI_LEN = 24u;
        static constexpr size_t DEST_PREFIX = 2u;    // dest_id (2B LE)
        static constexpr size_t COAP_HDR_SIZE = 6u;    // 4B hdr + 2B token
        static constexpr size_t MAX_PAYLOAD = 48u;
        // 전체 패킷 상한: dest(2) + hdr(6) + payload(48) = 56
        static constexpr size_t MAX_PKT_SIZE = DEST_PREFIX + COAP_HDR_SIZE + MAX_PAYLOAD;
        static constexpr uint8_t MAX_RETRANSMIT = 3u;
        static constexpr uint32_t ACK_TIMEOUT_MS = 2000u;

        explicit HTS_CoAP_Engine(uint16_t my_id) noexcept;
        ~HTS_CoAP_Engine() noexcept;

        HTS_CoAP_Engine(const HTS_CoAP_Engine&) = delete;
        HTS_CoAP_Engine& operator=(const HTS_CoAP_Engine&) = delete;
        HTS_CoAP_Engine(HTS_CoAP_Engine&&) = delete;
        HTS_CoAP_Engine& operator=(HTS_CoAP_Engine&&) = delete;

        [[nodiscard]]
        bool Register_Resource(const char* uri, ResourceHandler handler) noexcept;

        void On_Message_Received(
            const uint8_t* msg, size_t msg_len,
            uint16_t src_id, uint32_t systick_ms,
            HTS_Priority_Scheduler& scheduler) noexcept;

        [[nodiscard]]
        uint16_t Send_GET(
            uint16_t dest_id, const char* uri,
            uint32_t systick_ms,
            HTS_Priority_Scheduler& scheduler) noexcept;

        void Tick(uint32_t systick_ms,
            HTS_Priority_Scheduler& scheduler) noexcept;

        void Shutdown() noexcept;

    private:
        static constexpr size_t IMPL_BUF_SIZE = 768u;
        static constexpr size_t IMPL_BUF_ALIGN = 8u;
        struct Impl;
        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        bool impl_valid_ = false;
        Impl* get_impl() noexcept;
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine