// =========================================================================
// HTS_CoAP_Engine.cpp
// 경량 CoAP 메시징 엔진 구현부
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// resp: MAX_PKT_SIZE 기반, dest_id 2B 프리픽스, IMPL_BUF_SIZE 768B(x64 패딩 안전).
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

    /// H-16/O-13: 짧은 문자열 리터럴 URI도 24B 0패딩으로 정규화 후 safe_streq와 결합
    static void coap_uri_normalize_24(const char* uri, char out[24]) noexcept {
        Coap_Secure_Wipe(out, 24u);
        if (uri == nullptr) { return; }
        const size_t len = safe_strlen(uri, 23u);
        for (size_t i = 0u; i < len; ++i) {
            out[i] = uri[i];
        }
        out[len] = '\0';
    }

    //  a[i]!=b[i] → return false (단축 평가)
    //        → 공격자가 타이밍 계측으로 은닉 API URI를 바이트 단위 유추
    //  전체 max 길이를 무조건 XOR → 고정 사이클
    static bool safe_streq(const char* a, const char* b, size_t max) noexcept {
        uint8_t diff = 0u;
        for (size_t i = 0u; i < max; ++i) {
            diff |= (static_cast<uint8_t>(a[i]) ^ static_cast<uint8_t>(b[i]));
        }
        return (diff == 0u);
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
        //  0=FREE, 1=ALLOCATING(복사 중), 2=READY(전송 가능)
        //  uint8_t valid → Send_GET에서 valid=1 직후 ISR Tick이
        //        덜 쓰인 msg를 읽어 쓰레기 패킷 송출
        //  ALLOCATING(1) 동안 Tick이 건너뜀 → 복사 완료 후 READY(2)
        std::atomic<uint8_t> alloc_state{ 0u };
        uint8_t  pad[2];
        uint8_t  msg[MPKT];    // 상수 기반 (56B)
        size_t   msg_len;
    };

    struct HTS_CoAP_Engine::Impl {
        ResourceEntry resources[HTS_CoAP_Engine::MAX_RESOURCES] = {};
        PendingMsg    pending[MAX_PENDING] = {};

        uint16_t my_id = 0u;
        std::atomic<uint16_t> next_mid{ 1u };
        std::atomic<uint16_t> next_token{ 0x0100u };
        uint8_t  pad[2] = {};

        explicit Impl(uint16_t id) noexcept : my_id(id) {}
        ~Impl() noexcept = default;

        int32_t find_resource(const char* uri) const noexcept {
            char uri_norm[24];
            coap_uri_normalize_24(uri, uri_norm);
            for (size_t i = 0u; i < HTS_CoAP_Engine::MAX_RESOURCES; ++i) {
                if (resources[i].valid != 0u &&
                    safe_streq(resources[i].uri, uri_norm, 24u))
                {
                    Coap_Secure_Wipe(uri_norm, sizeof(uri_norm));
                    return static_cast<int32_t>(i);
                }
            }
            Coap_Secure_Wipe(uri_norm, sizeof(uri_norm));
            return -1;
        }

        int32_t find_pending(uint16_t mid) const noexcept {
            for (size_t i = 0u; i < MAX_PENDING; ++i) {
                if (pending[i].alloc_state.load(std::memory_order_acquire) == 2u &&
                    pending[i].msg_id == mid) {
                    return static_cast<int32_t>(i);
                }
            }
            return -1;
        }

        int32_t find_free_pending() noexcept {
            for (size_t i = 0u; i < MAX_PENDING; ++i) {
                uint8_t expected = 0u;
                if (pending[i].alloc_state.compare_exchange_strong(
                    expected, 1u, std::memory_order_acq_rel)) {
                    return static_cast<int32_t>(i);
                }
            }
            return -1;
        }

        uint16_t alloc_mid() noexcept {
            uint16_t mid = next_mid.fetch_add(1u, std::memory_order_acq_rel);
            if (mid == 0u) {
                mid = next_mid.fetch_add(1u, std::memory_order_acq_rel);
            }
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
                //  uri_len 이후 꼬리 영역에 쓰레기 잔류
                //        → safe_streq가 24바이트 전체 XOR → 꼬리 불일치 → 항상 NOT_FOUND
                //  쓰기 전 전체 소거 → 꼬리 0x00 보장
                Coap_Secure_Wipe(p->resources[i].uri, sizeof(p->resources[i].uri));

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

        //  TKL 무시 → 고정 HDR(6) 오프셋으로 페이로드 파싱
        //        → TKL≠2 패킷 시 페이로드 오프셋 틀어짐 → URI 오정렬
        //  TKL==2 아니면 즉각 폐기 (설계 규격 엄격 준수)
        const uint8_t  type_raw = (msg[DST + 0u] >> 4u) & 0x03u;
        const uint8_t  tkl = msg[DST + 0u] & 0x0Fu;
        if (tkl != 2u) { return; }  // 허용 TKL: 2 only

        const uint8_t  code = msg[DST + 1u];
        const uint16_t mid = deser_u16_be(&msg[DST + 2u]);
        const uint16_t token = deser_u16_be(&msg[DST + 4u]);
        const CoapType type = static_cast<CoapType>(type_raw);

        // ACK → 재전송 해제
        if (type == CoapType::ACK) {
            const int32_t slot = p->find_pending(mid);
            if (slot >= 0) {
                PendingMsg& apm = p->pending[static_cast<size_t>(slot)];
                //  무조건 Wipe → Tick이 동시에 msg 읽기 가능 → 쓰레기 패킷
                //  CAS로 소유권 확보 후에만 Wipe (Tick은 state≠2 → skip)
                uint8_t expected = 2u;
                if (apm.alloc_state.compare_exchange_strong(
                    expected, 3u, std::memory_order_acq_rel)) {
                    Coap_Secure_Wipe(apm.msg, MPKT);
                    apm.msg_id = 0u;
                    apm.msg_len = 0u;
                    apm.retries = 0u;
                    apm.alloc_state.store(0u, std::memory_order_release);
                }
            }

            //  바이너리 응답 페이로드를 URI로 파싱 → 서버 핸들러 강제 호출
            //  순수 페이로드로 보존 → 향후 클라이언트 콜백 연동 지점
            if (code == CoapCode::CONTENT_205) {
                if (msg_len > DST + HDR) {
                    // 향후: 클라이언트 응답 콜백으로 페이로드 전달
                    // const uint8_t* ack_payload = &msg[DST + HDR];
                    // const size_t   ack_pay_len = msg_len - DST - HDR;
                    (void)0;
                }
                return;
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
        if (pay_len > MPAY) { return; }

        //  i < 23u 하드코딩 → MAX_URI_LEN(24) 변경 시 불일치 가능
        //  MAX_URI_LEN - 1u로 상수 연동 → 마지막 바이트 항상 '\0' 보장
        char uri_buf[MAX_URI_LEN] = {};
        size_t uri_len = 0u;
        for (size_t i = 0u; i < pay_len && i < (MAX_URI_LEN - 1u); ++i) {
            if (payload[i] == 0u || payload[i] == 0xFFu) { break; }
            uri_buf[uri_len++] = static_cast<char>(payload[i]);
        }
        uri_buf[uri_len] = '\0';

        // 리소스 매칭 + 핸들러 호출
        const int32_t res_slot = p->find_resource(uri_buf);

        uint8_t resp[MPKT] = {};
        uint8_t resp_code = CoapCode::NOT_FOUND;
        size_t  resp_pay_len = 0u;

        if (res_slot >= 0) {
            uint8_t resp_payload[MPAY] = {};
            const ResourceEntry& re =
                p->resources[static_cast<size_t>(res_slot)];

            //  data_off = uri_len + 1u → 맹목적 건너뛰기
            //        → 공격자가 MAX_URI_LEN 긴 URI 전송 시 24번째 바이트를
            //          0xFF 마커로 오인 → 악성 데이터가 핸들러로 주입
            //  payload[uri_len]이 실제 0xFF인지 엄격 검증
            const size_t data_off = uri_len + 1u;
            const uint8_t* req_data = nullptr;
            size_t req_len = 0u;

            if (data_off <= pay_len && payload[uri_len] == 0xFFu) {
                req_data = payload + data_off;
                req_len = pay_len - data_off;
            }

            resp_pay_len = re.handler(
                code, req_data, req_len,
                resp_payload, MPAY);

            // 응답 페이로드 상한 클램프
            if (resp_pay_len > (MPAY - 1u)) { resp_pay_len = MPAY - 1u; }
            resp_code = CoapCode::CONTENT_205;

            ser_u16_le(&resp[0], src_id);
            Impl::build_header(resp, DST, CoapType::ACK,
                resp_code, mid, token);

            //  헤더 바로 뒤에 페이로드 직결 → 수신측 옵션 델타 오인 → 패킷 폐기
            //  페이로드 존재 시 0xFF 마커 삽입 (RFC 7252 §3)
            size_t marker_offset = 0u;
            if (resp_pay_len > 0u) {
                resp[DST + HDR] = 0xFFu;
                marker_offset = 1u;
            }

            for (size_t i = 0u; i < resp_pay_len; ++i) {
                resp[DST + HDR + marker_offset + i] = resp_payload[i];
            }
            // resp_total 계산 시 마커 포함
            resp_pay_len += marker_offset;

            //  핸들러 응답에 키/토큰 등 극비 데이터 포함 가능
            //  resp로 복사 완료 후 원본 즉시 파기
            Coap_Secure_Wipe(resp_payload, sizeof(resp_payload));
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
    // =====================================================================
    uint16_t HTS_CoAP_Engine::Send_GET(
        uint16_t dest_id, const char* uri,
        uint32_t systick_ms,
        HTS_Priority_Scheduler& scheduler) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr || uri == nullptr) { return 0u; }

        const uint16_t mid = p->alloc_mid();
        const uint16_t tok = p->next_token.fetch_add(1u, std::memory_order_acq_rel);

        uint8_t pkt[MPKT] = {};

        ser_u16_le(&pkt[0], dest_id);
        Impl::build_header(pkt, DST, CoapType::CON, CoapCode::GET, mid, tok);

        //  pkt_total = DST+HDR+uri_len+1u → uri_len=MPAY(48) 시 57B > MPKT(56) 오버플로
        //  CoAP 규격상 URI 길이는 옵션 헤더로 식별 → nullptr 불필요
        //        uri_len을 MPAY로 클램프하여 원천 차단
        size_t uri_len = safe_strlen(uri, MAX_URI_LEN - 1u);
        if (uri_len > MPAY) { uri_len = MPAY; }

        for (size_t i = 0u; i < uri_len; ++i) {
            pkt[DST + HDR + i] = static_cast<uint8_t>(uri[i]);
        }

        const size_t pkt_total = DST + HDR + uri_len;

        // 재전송 슬롯
        const int32_t slot = p->find_free_pending();
        if (slot >= 0) {
            PendingMsg& pm = p->pending[static_cast<size_t>(slot)];
            pm.msg_id = mid;
            pm.dest_id = dest_id;
            pm.send_ms = systick_ms;
            pm.retries = 0u;
            pm.msg_len = pkt_total;
            for (size_t i = 0u; i < pkt_total; ++i) {
                pm.msg[i] = pkt[i];
            }
            //  ALLOCATING(1) 동안 Tick이 이 슬롯을 건너뜀
            pm.alloc_state.store(2u, std::memory_order_release);
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
            if (pm.alloc_state.load(std::memory_order_acquire) != 2u) {
                continue;
            }

            //  PRIMASK 안에서 Enqueue → 수천 사이클 ISR 블로킹 → MCU 마비
            //  PRIMASK 안에서 로컬 복사(~50cyc)만 수행 → 즉시 락 해제
            //        락 밖에서 Enqueue → ISR 지연 0
            bool need_enqueue = false;
            uint8_t local_msg[MPKT];
            size_t  local_msg_len = 0u;

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
            uint32_t primask;
            __asm__ __volatile__("mrs %0, primask\n\tcpsid i"
                : "=r"(primask) : : "memory");
#endif

            // 선행 검사와 IRQ 차단 사이 경합 가능성 방어: 잠금 후 상태 재확인
            if (pm.alloc_state.load(std::memory_order_acquire) == 2u) {
                const uint8_t safe_shift =
                    (pm.retries <= 21u) ? pm.retries : 21u;
                const uint32_t timeout = ACK_TIMEOUT_MS << safe_shift;
                const uint32_t elapsed = systick_ms - pm.send_ms;

                if (elapsed >= timeout) {
                    if (pm.retries >= MAX_RETRANSMIT) {
                        Coap_Secure_Wipe(pm.msg, MPKT);
                        pm.msg_id = 0u;
                        pm.msg_len = 0u;
                        pm.alloc_state.store(0u, std::memory_order_release);
                    }
                    else {
                        // 로컬 복사 (~50cyc, PRIMASK 내부)
                        for (size_t j = 0u; j < pm.msg_len && j < MPKT; ++j) {
                            local_msg[j] = pm.msg[j];
                        }
                        local_msg_len = pm.msg_len;
                        need_enqueue = true;
                        pm.send_ms = systick_ms;
                        pm.retries++;
                    }
                }
            }

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
            __asm__ __volatile__("msr primask, %0" : : "r"(primask) : "memory");
#endif

            // PRIMASK 외부: 스케줄러 호출 (ISR 정상 동작)
            if (need_enqueue) {
                const EnqueueResult enq = scheduler.Enqueue(
                    PacketPriority::DATA, local_msg, local_msg_len, systick_ms);
                (void)enq;
                Coap_Secure_Wipe(local_msg, sizeof(local_msg));
            }
        }
    }

    void HTS_CoAP_Engine::Shutdown() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        //  atomic 객체 생존 보장 (파괴자 호출 전까지 라이브 상태)
        for (size_t i = 0u; i < MAX_PENDING; ++i) {
            Coap_Secure_Wipe(p->pending[i].msg, MPKT);
            p->pending[i].alloc_state.store(0u, std::memory_order_release);
        }
    }

} // namespace ProtectedEngine
