// =========================================================================
// HTS_CoAP_Engine.cpp
// 경량 CoAP 메시징 엔진 구현부
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// [수정 이력]
//  FIX-1: resp 버퍼 상수화 (MAX_PKT_SIZE 기반, 하드코딩 제거)
//  FIX-2: dest_id 2B 프리픽스 캡슐화 (메쉬 라우팅 연동)
//  FIX-3: IMPL_BUF_SIZE 768B (x64 포인터/패딩 안전)
// =========================================================================
#include "HTS_CoAP_Engine.h"
#include "HTS_Priority_Scheduler.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <new>

namespace ProtectedEngine {

    static void Coap_Secure_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) { q[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // CoAP: 빅엔디안 (MID, Token)
    static void ser_u16_be(uint8_t* dst, uint16_t v) noexcept {
        dst[0] = static_cast<uint8_t>((v >> 8u) & 0xFFu);
        dst[1] = static_cast<uint8_t>(v & 0xFFu);
    }
    static uint16_t deser_u16_be(const uint8_t* src) noexcept {
        return (static_cast<uint16_t>(src[0]) << 8u)
            | static_cast<uint16_t>(src[1]);
    }

    // dest_id: 리틀엔디안 (메쉬 계층 호환)
    static void ser_u16_le(uint8_t* dst, uint16_t v) noexcept {
        dst[0] = static_cast<uint8_t>(v & 0xFFu);
        dst[1] = static_cast<uint8_t>((v >> 8u) & 0xFFu);
    }

    static size_t safe_strlen(const char* s, size_t max) noexcept {
        if (s == nullptr) { return 0u; }
        size_t len = 0u;
        while (len < max && s[len] != '\0') { ++len; }
        return len;
    }

    static bool safe_streq(const char* a, const char* b, size_t max) noexcept {
        for (size_t i = 0u; i < max; ++i) {
            if (a[i] != b[i]) { return false; }
            if (a[i] == '\0') { return true; }
        }
        return true;
    }

    // =====================================================================
    //  상수 별칭 (파일 스코프)
    // =====================================================================
    static constexpr size_t DST = HTS_CoAP_Engine::DEST_PREFIX;     // 2
    static constexpr size_t HDR = HTS_CoAP_Engine::COAP_HDR_SIZE;   // 6
    static constexpr size_t MPAY = HTS_CoAP_Engine::MAX_PAYLOAD;     // 48
    static constexpr size_t MPKT = HTS_CoAP_Engine::MAX_PKT_SIZE;    // 56

    // =====================================================================
    //  내부 구조체
    // =====================================================================
    struct ResourceEntry {
        char             uri[24];
        ResourceHandler  handler;
        uint8_t          valid;
        uint8_t          pad[3];
    };

    static constexpr size_t MAX_PENDING = 4u;

    struct PendingMsg {
        uint16_t msg_id;
        uint16_t dest_id;
        uint32_t send_ms;
        uint8_t  retries;
        uint8_t  valid;
        uint8_t  pad[2];
        uint8_t  msg[MPKT];    // [FIX-1] 상수 기반 (56B)
        size_t   msg_len;
    };

    struct HTS_CoAP_Engine::Impl {
        ResourceEntry resources[HTS_CoAP_Engine::MAX_RESOURCES] = {};
        PendingMsg    pending[MAX_PENDING] = {};

        uint16_t my_id = 0u;
        uint16_t next_mid = 1u;
        uint16_t next_token = 0x0100u;
        uint8_t  pad[2] = {};

        explicit Impl(uint16_t id) noexcept : my_id(id) {}
        ~Impl() noexcept = default;

        int32_t find_resource(const char* uri) const noexcept {
            for (size_t i = 0u; i < HTS_CoAP_Engine::MAX_RESOURCES; ++i) {
                if (resources[i].valid != 0u &&
                    safe_streq(resources[i].uri, uri, 24u))
                {
                    return static_cast<int32_t>(i);
                }
            }
            return -1;
        }

        int32_t find_pending(uint16_t mid) const noexcept {
            for (size_t i = 0u; i < MAX_PENDING; ++i) {
                if (pending[i].valid != 0u && pending[i].msg_id == mid) {
                    return static_cast<int32_t>(i);
                }
            }
            return -1;
        }

        int32_t find_free_pending() const noexcept {
            for (size_t i = 0u; i < MAX_PENDING; ++i) {
                if (pending[i].valid == 0u) {
                    return static_cast<int32_t>(i);
                }
            }
            return -1;
        }

        uint16_t alloc_mid() noexcept {
            const uint16_t mid = next_mid;
            next_mid++;
            if (next_mid == 0u) { next_mid = 1u; }
            return mid;
        }

        // CoAP 헤더 조립 (오프셋: dest_prefix 뒤)
        // buf[offset]: ver=1(2b), type(2b), tkl=2(4b)
        static void build_header(uint8_t* buf, size_t offset,
            CoapType type, uint8_t code,
            uint16_t mid, uint16_t token) noexcept
        {
            buf[offset + 0u] = static_cast<uint8_t>(
                0x42u | (static_cast<uint8_t>(type) << 4u));
            buf[offset + 1u] = code;
            ser_u16_be(&buf[offset + 2u], mid);
            ser_u16_be(&buf[offset + 4u], token);
        }
    };

    // =====================================================================
    //  get_impl
    // =====================================================================
    HTS_CoAP_Engine::Impl*
        HTS_CoAP_Engine::get_impl() noexcept
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE(768B)를 초과합니다");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 초과");
        return impl_valid_
            ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }

    const HTS_CoAP_Engine::Impl*
        HTS_CoAP_Engine::get_impl() const noexcept
    {
        return impl_valid_
            ? reinterpret_cast<const Impl*>(impl_buf_) : nullptr;
    }

    HTS_CoAP_Engine::HTS_CoAP_Engine(uint16_t my_id) noexcept
        : impl_valid_(false)
    {
        Coap_Secure_Wipe(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl(my_id);
        impl_valid_ = true;
    }

    HTS_CoAP_Engine::~HTS_CoAP_Engine() noexcept {
        Impl* p = get_impl();
        if (p != nullptr) { p->~Impl(); }
        Coap_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
        impl_valid_ = false;
    }

    // =====================================================================
    //  Register_Resource
    // =====================================================================
    bool HTS_CoAP_Engine::Register_Resource(
        const char* uri, ResourceHandler handler) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr || uri == nullptr || handler == nullptr) {
            return false;
        }
        if (p->find_resource(uri) >= 0) { return false; }

        for (size_t i = 0u; i < MAX_RESOURCES; ++i) {
            if (p->resources[i].valid == 0u) {
                const size_t len = safe_strlen(uri, MAX_URI_LEN - 1u);
                for (size_t c = 0u; c < len; ++c) {
                    p->resources[i].uri[c] = uri[c];
                }
                p->resources[i].uri[len] = '\0';
                p->resources[i].handler = handler;
                p->resources[i].valid = 1u;
                return true;
            }
        }
        return false;
    }

    // =====================================================================
    //  On_Message_Received — 수신 파싱 + 응답
    //
    //  수신 패킷:  [dest(2)] [coap_hdr(6)] [payload(≤48)]
    //  응답 패킷:  [src_id(2)] [coap_ack(6)] [resp_payload(≤48)]
    // =====================================================================
    void HTS_CoAP_Engine::On_Message_Received(
        const uint8_t* msg, size_t msg_len,
        uint16_t src_id, uint32_t systick_ms,
        HTS_Priority_Scheduler& scheduler) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr || msg == nullptr) { return; }
        if (msg_len < DST + HDR) { return; }  // dest(2) + hdr(6) 최소

        // [FIX-2] dest_id 프리픽스 스킵 → CoAP 헤더 파싱
        const uint8_t  type_raw = (msg[DST + 0u] >> 4u) & 0x03u;
        const uint8_t  code = msg[DST + 1u];
        const uint16_t mid = deser_u16_be(&msg[DST + 2u]);
        const uint16_t token = deser_u16_be(&msg[DST + 4u]);
        const CoapType type = static_cast<CoapType>(type_raw);

        // ACK → 재전송 해제
        if (type == CoapType::ACK) {
            const int32_t slot = p->find_pending(mid);
            if (slot >= 0) {
                Coap_Secure_Wipe(
                    &p->pending[static_cast<size_t>(slot)],
                    sizeof(PendingMsg));
            }
            return;
        }

        if (code != CoapCode::GET && code != CoapCode::PUT &&
            code != CoapCode::POST)
        {
            return;
        }

        // 페이로드: dest(2) + hdr(6) 이후
        const uint8_t* payload = &msg[DST + HDR];
        const size_t   pay_len = msg_len - DST - HDR;

        // URI 추출
        char uri_buf[24] = {};
        size_t uri_len = 0u;
        for (size_t i = 0u; i < pay_len && i < 23u; ++i) {
            if (payload[i] == 0u || payload[i] == 0xFFu) { break; }
            uri_buf[uri_len++] = static_cast<char>(payload[i]);
        }
        uri_buf[uri_len] = '\0';

        // 리소스 매칭 + 핸들러 호출
        const int32_t res_slot = p->find_resource(uri_buf);

        // [FIX-1] 응답 버퍼: 상수 기반 (MAX_PKT_SIZE = 56B)
        uint8_t resp[MPKT] = {};
        uint8_t resp_code = CoapCode::NOT_FOUND;
        size_t  resp_pay_len = 0u;

        if (res_slot >= 0) {
            uint8_t resp_payload[MPAY] = {};
            const ResourceEntry& re =
                p->resources[static_cast<size_t>(res_slot)];

            const size_t data_off = uri_len + 1u;
            const uint8_t* req_data =
                (data_off < pay_len) ? (payload + data_off) : nullptr;
            const size_t req_len =
                (data_off < pay_len) ? (pay_len - data_off) : 0u;

            resp_pay_len = re.handler(
                code, req_data, req_len,
                resp_payload, MPAY);

            // 응답 페이로드 상한 클램프
            if (resp_pay_len > MPAY) { resp_pay_len = MPAY; }
            resp_code = CoapCode::CONTENT_205;

            // [FIX-2] 응답 dest = 요청 src (역방향)
            ser_u16_le(&resp[0], src_id);
            Impl::build_header(resp, DST, CoapType::ACK,
                resp_code, mid, token);

            for (size_t i = 0u; i < resp_pay_len; ++i) {
                resp[DST + HDR + i] = resp_payload[i];
            }
        }
        else {
            ser_u16_le(&resp[0], src_id);
            Impl::build_header(resp, DST, CoapType::ACK,
                resp_code, mid, token);
        }

        const size_t resp_total = DST + HDR + resp_pay_len;
        static_assert(MPKT == DST + HDR + MPAY,
            "MAX_PKT_SIZE 불일치");

        const EnqueueResult enq = scheduler.Enqueue(
            PacketPriority::DATA,
            resp, resp_total, systick_ms);
        (void)enq;

        Coap_Secure_Wipe(resp, sizeof(resp));
    }

    // =====================================================================
    //  Send_GET — CON GET + 재전송 등록
    //  [FIX-2] dest_id를 패킷 [0-1]에 캡슐화
    // =====================================================================
    uint16_t HTS_CoAP_Engine::Send_GET(
        uint16_t dest_id, const char* uri,
        uint32_t systick_ms,
        HTS_Priority_Scheduler& scheduler) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr || uri == nullptr) { return 0u; }

        const uint16_t mid = p->alloc_mid();
        const uint16_t tok = p->next_token++;

        uint8_t pkt[MPKT] = {};

        // [FIX-2] dest_id 프리픽스 캡슐화
        ser_u16_le(&pkt[0], dest_id);
        Impl::build_header(pkt, DST, CoapType::CON, CoapCode::GET, mid, tok);

        // URI 삽입
        const size_t uri_len = safe_strlen(uri, MAX_URI_LEN - 1u);
        for (size_t i = 0u; i < uri_len; ++i) {
            pkt[DST + HDR + i] = static_cast<uint8_t>(uri[i]);
        }
        pkt[DST + HDR + uri_len] = 0u;

        const size_t pkt_total = DST + HDR + uri_len + 1u;

        // 재전송 슬롯
        const int32_t slot = p->find_free_pending();
        if (slot >= 0) {
            PendingMsg& pm = p->pending[static_cast<size_t>(slot)];
            pm.msg_id = mid;
            pm.dest_id = dest_id;
            pm.send_ms = systick_ms;
            pm.retries = 0u;
            pm.valid = 1u;
            pm.msg_len = pkt_total;
            for (size_t i = 0u; i < pkt_total; ++i) {
                pm.msg[i] = pkt[i];
            }
        }

        const EnqueueResult enq = scheduler.Enqueue(
            PacketPriority::DATA,
            pkt, pkt_total, systick_ms);
        (void)enq;

        Coap_Secure_Wipe(pkt, sizeof(pkt));
        return mid;
    }

    // =====================================================================
    //  Tick — 재전송 (지수 백오프 2s→4s→8s)
    // =====================================================================
    void HTS_CoAP_Engine::Tick(
        uint32_t systick_ms,
        HTS_Priority_Scheduler& scheduler) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        for (size_t i = 0u; i < MAX_PENDING; ++i) {
            PendingMsg& pm = p->pending[i];
            if (pm.valid == 0u) { continue; }

            const uint32_t timeout = ACK_TIMEOUT_MS << pm.retries;
            const uint32_t elapsed = systick_ms - pm.send_ms;
            if (elapsed < timeout) { continue; }

            if (pm.retries >= MAX_RETRANSMIT) {
                Coap_Secure_Wipe(&pm, sizeof(PendingMsg));
                continue;
            }

            const EnqueueResult enq = scheduler.Enqueue(
                PacketPriority::DATA,
                pm.msg, pm.msg_len, systick_ms);
            (void)enq;

            pm.send_ms = systick_ms;
            pm.retries++;
        }
    }

    void HTS_CoAP_Engine::Shutdown() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        Coap_Secure_Wipe(p->pending, sizeof(p->pending));
    }

} // namespace ProtectedEngine