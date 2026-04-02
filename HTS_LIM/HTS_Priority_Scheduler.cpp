// =========================================================================
// HTS_Priority_Scheduler.cpp
// 3단계 패킷 우선순위 큐 스케줄러 구현부 (Pimpl 은닉)
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// [설계]
//  · P0(SOS) > P1(VOICE) > P2(DATA) 엄격 우선순위
//  · 정적 링버퍼 (힙 0회)
//  · 재밍 감지 시 P2 전송 억제 → P0/P1 대역폭 보장
//  · P2 에이징: 2초 초과 → P1 승격 (기아 방지)
//  · 3중 보안 소거 (패킷 데이터 잔류 방지)
// =========================================================================
#include "HTS_Priority_Scheduler.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

static_assert(sizeof(uint8_t) == 1, "uint8_t must be 1 byte");
static_assert(sizeof(uint32_t) == 4, "uint32_t must be 4 bytes");

namespace ProtectedEngine {

    // =====================================================================
    //  3중 보안 소거
    // =====================================================================
    static void PriSched_Secure_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) { q[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(q) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  큐 항목 (16바이트 고정)
    // =====================================================================
    struct QueueItem {
        uint8_t  data[8];       // 패킷 데이터 (MAX_PACKET_DATA)
        uint32_t timestamp;     // 삽입 시점 (systick_ms)
        uint8_t  len;           // 유효 데이터 길이
        uint8_t  orig_priority; // 원본 우선순위
        uint8_t  pad[2];        // 정렬 패딩
    };

    static_assert(sizeof(QueueItem) == 16u,
        "QueueItem must be exactly 16 bytes");

    // =====================================================================
    //  정적 링버퍼 (템플릿 없이 매크로 없이 — MISRA 준수)
    //
    //  head: 다음 읽기 위치
    //  tail: 다음 쓰기 위치
    //  count: 현재 항목 수
    //  비어있음: count == 0
    //  가득 참:  count == capacity
    // =====================================================================
    static constexpr size_t SOS_CAP = 4u;
    static constexpr size_t VOICE_CAP = 8u;
    static constexpr size_t DATA_CAP = 8u;

    struct RingQ_SOS {
        QueueItem items[SOS_CAP] = {};
        uint8_t head = 0u;
        uint8_t tail = 0u;
        uint8_t count = 0u;
    };

    struct RingQ_Voice {
        QueueItem items[VOICE_CAP] = {};
        uint8_t head = 0u;
        uint8_t tail = 0u;
        uint8_t count = 0u;
    };

    struct RingQ_Data {
        QueueItem items[DATA_CAP] = {};
        uint8_t head = 0u;
        uint8_t tail = 0u;
        uint8_t count = 0u;
    };

    // ── 링버퍼 공통 연산 (인라인, 타입 안전) ──

    static bool ring_push(QueueItem* items, uint8_t cap,
        uint8_t& tail, uint8_t& count,
        const QueueItem& item) noexcept
    {
        if (count >= cap) { return false; }
        items[tail] = item;
        tail = static_cast<uint8_t>((tail + 1u) % cap);
        ++count;
        return true;
    }

    static bool ring_pop(QueueItem* items, uint8_t cap,
        uint8_t& head, uint8_t& count,
        QueueItem& out) noexcept
    {
        if (count == 0u) { return false; }
        out = items[head];
        PriSched_Secure_Wipe(&items[head], sizeof(QueueItem));
        head = static_cast<uint8_t>((head + 1u) % cap);
        --count;
        return true;
    }

    static const QueueItem* ring_peek(
        const QueueItem* items, uint8_t head, uint8_t count) noexcept
    {
        if (count == 0u) { return nullptr; }
        return &items[head];
    }

    static void ring_flush(QueueItem* items, size_t total_bytes,
        uint8_t& head, uint8_t& tail, uint8_t& count) noexcept
    {
        PriSched_Secure_Wipe(items, total_bytes);
        head = 0u;
        tail = 0u;
        count = 0u;
    }

    // =====================================================================
    //
    //  Enqueue: 메인 루프 또는 APP 콜백에서 호출
    //  Dequeue: TX 타이머 ISR에서 호출 가능
    //  Tick:    SysTick ISR에서 호출
    //  → 3곳의 인터럽트 우선순위가 다를 수 있음 → PRIMASK 필수
    // =====================================================================
#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
    static inline uint32_t critical_enter() noexcept {
        uint32_t primask;
        __asm volatile ("MRS %0, PRIMASK\n CPSID I"
        : "=r"(primask) :: "memory");
        return primask;
    }
    static inline void critical_exit(uint32_t primask) noexcept {
        __asm volatile ("MSR PRIMASK, %0"
        :: "r"(primask) : "memory");
    }
#else
    static inline uint32_t critical_enter() noexcept { return 0u; }
    static inline void critical_exit(uint32_t) noexcept {}
#endif

    // =====================================================================
    //  NF 임계값 (FEC_HARQ와 동일 기준)
    // =====================================================================
    static constexpr uint32_t NF_SUPPRESS_TH = 500u;   // NF > 500 → DATA 억제
    static constexpr uint32_t AGING_MS = 2000u;   // 2초 에이징

    // =====================================================================
    //  Pimpl 구현 구조체
    //
    //  sizeof(Impl):
    //    SOS:   4×16 + 3 = 67B
    //    VOICE: 8×16 + 3 = 131B
    //    DATA:  8×16 + 3 = 131B
    //    State: 8B
    //    Total: ≈ 337B (< 512B IMPL_BUF_SIZE)
    // =====================================================================
    struct HTS_Priority_Scheduler::Impl {
        RingQ_SOS    q_sos;
        RingQ_Voice  q_voice;
        RingQ_Data   q_data;

        bool     data_suppressed = false;
        uint32_t last_nf = 0u;

        Impl() noexcept = default;

        ~Impl() noexcept {
            ring_flush(q_sos.items, sizeof(q_sos.items),
                q_sos.head, q_sos.tail, q_sos.count);
            ring_flush(q_voice.items, sizeof(q_voice.items),
                q_voice.head, q_voice.tail, q_voice.count);
            ring_flush(q_data.items, sizeof(q_data.items),
                q_data.head, q_data.tail, q_data.count);
            data_suppressed = false;
            last_nf = 0u;
        }
    };

    // =====================================================================
    //  get_impl
    // =====================================================================
    HTS_Priority_Scheduler::Impl*
        HTS_Priority_Scheduler::get_impl() noexcept
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE(512B)를 초과합니다");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 요구가 impl_buf_ alignas를 초과합니다");
        return impl_valid_
            .load(std::memory_order_acquire)
            ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }

    const HTS_Priority_Scheduler::Impl*
        HTS_Priority_Scheduler::get_impl() const noexcept
    {
        return impl_valid_.load(std::memory_order_acquire)
            ? reinterpret_cast<const Impl*>(impl_buf_) : nullptr;
    }

    // =====================================================================
    //  생성자 / 소멸자
    // =====================================================================
    HTS_Priority_Scheduler::HTS_Priority_Scheduler() noexcept
        : impl_valid_(false)
    {
        PriSched_Secure_Wipe(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl();
        impl_valid_.store(true, std::memory_order_release);
    }

    HTS_Priority_Scheduler::~HTS_Priority_Scheduler() noexcept {
        Impl* p = get_impl();
        if (p != nullptr) { p->~Impl(); }
        PriSched_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
        impl_valid_.store(false, std::memory_order_release);
    }

    // =====================================================================
    //  Enqueue — 우선순위별 큐 삽입
    // =====================================================================
    EnqueueResult HTS_Priority_Scheduler::Enqueue(
        PacketPriority priority,
        const uint8_t* data, size_t len,
        uint32_t timestamp) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr || data == nullptr) {
            return EnqueueResult::NULL_INPUT;
        }
        if (len == 0u || len > MAX_PACKET_DATA) {
            return EnqueueResult::OVER_SIZE;
        }

        QueueItem item = {};
        std::memcpy(item.data, data, len);
        item.timestamp = timestamp;
        item.len = static_cast<uint8_t>(len);
        item.orig_priority = static_cast<uint8_t>(priority);

        const uint32_t pm = critical_enter();
        bool ok = false;

        switch (priority) {
        case PacketPriority::SOS:
            ok = ring_push(p->q_sos.items, static_cast<uint8_t>(SOS_CAP),
                p->q_sos.tail, p->q_sos.count, item);
            break;
        case PacketPriority::VOICE:
            ok = ring_push(p->q_voice.items, static_cast<uint8_t>(VOICE_CAP),
                p->q_voice.tail, p->q_voice.count, item);
            break;
        case PacketPriority::DATA:
            ok = ring_push(p->q_data.items, static_cast<uint8_t>(DATA_CAP),
                p->q_data.tail, p->q_data.count, item);
            break;
        default:
            critical_exit(pm);
            return EnqueueResult::NULL_INPUT;
        }

        critical_exit(pm);
        return ok ? EnqueueResult::OK : EnqueueResult::QUEUE_FULL;
    }

    // =====================================================================
    //  Dequeue — 최고 우선순위 패킷 추출
    //
    //  정책: P0(SOS) → P1(VOICE) → P2(DATA) 엄격 우선
    //  재밍 시: P2 억제 (data_suppressed == true → P2 건너뜀)
    // =====================================================================
    bool HTS_Priority_Scheduler::Dequeue(
        uint8_t* out_data, size_t& out_len,
        PacketPriority& out_priority) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr || out_data == nullptr) { return false; }

        QueueItem item = {};

        const uint32_t pm = critical_enter();

        // P0: SOS (항상 최우선)
        if (ring_pop(p->q_sos.items, static_cast<uint8_t>(SOS_CAP),
            p->q_sos.head, p->q_sos.count, item))
        {
            critical_exit(pm);
            std::memcpy(out_data, item.data, item.len);
            out_len = static_cast<size_t>(item.len);
            out_priority = PacketPriority::SOS;
            PriSched_Secure_Wipe(&item, sizeof(item));
            return true;
        }

        // P1: VOICE
        if (ring_pop(p->q_voice.items, static_cast<uint8_t>(VOICE_CAP),
            p->q_voice.head, p->q_voice.count, item))
        {
            critical_exit(pm);
            std::memcpy(out_data, item.data, item.len);
            out_len = static_cast<size_t>(item.len);
            out_priority = PacketPriority::VOICE;
            PriSched_Secure_Wipe(&item, sizeof(item));
            return true;
        }

        // P2: DATA (재밍 억제 시 건너뜀)
        if (!p->data_suppressed) {
            if (ring_pop(p->q_data.items, static_cast<uint8_t>(DATA_CAP),
                p->q_data.head, p->q_data.count, item))
            {
                critical_exit(pm);
                std::memcpy(out_data, item.data, item.len);
                out_len = static_cast<size_t>(item.len);
                out_priority = PacketPriority::DATA;
                PriSched_Secure_Wipe(&item, sizeof(item));
                return true;
            }
        }

        critical_exit(pm);
        return false;
    }

    // =====================================================================
    //  Tick — 에이징 + NF 정책 갱신
    //
    //  [에이징] DATA 큐의 head 항목이 AGING_MS 초과 체류 시
    //          → VOICE 큐로 승격 (기아 방지)
    //  [NF 정책] NF > NF_SUPPRESS_TH → DATA 억제
    //            NF ≤ NF_SUPPRESS_TH → DATA 허용
    // =====================================================================
    void HTS_Priority_Scheduler::Tick(
        uint32_t systick_ms, uint32_t current_nf) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        const uint32_t pm = critical_enter();

        // NF 기반 DATA 억제 정책
        p->last_nf = current_nf;
        p->data_suppressed = (current_nf > NF_SUPPRESS_TH);

        //  기존: pop 먼저 → VOICE 풀 시 tail 재삽입 → FIFO 역전
        //  수정: peek으로 조건 확인 → VOICE 빈칸 있을 때만 pop+push
        const QueueItem* peek =
            ring_peek(p->q_data.items, p->q_data.head, p->q_data.count);

        if (peek != nullptr) {
            const uint32_t elapsed = systick_ms - peek->timestamp;

            if (elapsed >= AGING_MS &&
                p->q_voice.count < static_cast<uint8_t>(VOICE_CAP))
            {
                QueueItem aged = {};
                ring_pop(p->q_data.items, static_cast<uint8_t>(DATA_CAP),
                    p->q_data.head, p->q_data.count, aged);

                aged.orig_priority =
                    static_cast<uint8_t>(PacketPriority::DATA);

                ring_push(p->q_voice.items, static_cast<uint8_t>(VOICE_CAP),
                    p->q_voice.tail, p->q_voice.count, aged);

                critical_exit(pm);
                PriSched_Secure_Wipe(&aged, sizeof(aged));
                return;  // pm 이미 해제됨 → 아래 exit 건너뜀
            }
            // 조건 미충족 시: pop 하지 않음 → FIFO 순서 보존
        }

        critical_exit(pm);
    }

    // =====================================================================
    //  Flush — 전체 큐 비우기
    // =====================================================================
    void HTS_Priority_Scheduler::Flush() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        const uint32_t pm = critical_enter();
        ring_flush(p->q_sos.items, sizeof(p->q_sos.items),
            p->q_sos.head, p->q_sos.tail, p->q_sos.count);
        ring_flush(p->q_voice.items, sizeof(p->q_voice.items),
            p->q_voice.head, p->q_voice.tail, p->q_voice.count);
        ring_flush(p->q_data.items, sizeof(p->q_data.items),
            p->q_data.head, p->q_data.tail, p->q_data.count);
        critical_exit(pm);
    }

    // =====================================================================
    //  조회 API
    // =====================================================================
    size_t HTS_Priority_Scheduler::Get_SOS_Count() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? static_cast<size_t>(p->q_sos.count) : 0u;
    }

    size_t HTS_Priority_Scheduler::Get_VOICE_Count() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? static_cast<size_t>(p->q_voice.count) : 0u;
    }

    size_t HTS_Priority_Scheduler::Get_DATA_Count() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? static_cast<size_t>(p->q_data.count) : 0u;
    }

    bool HTS_Priority_Scheduler::Is_DATA_Suppressed() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) && p->data_suppressed;
    }

} // namespace ProtectedEngine
