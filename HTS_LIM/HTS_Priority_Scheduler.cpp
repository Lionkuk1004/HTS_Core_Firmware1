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
//  · 패킷 소거: SecureMemory::secureWipe (B-CDMA D-2 단일화)
//
//  B-CDMA 검수 요약 (본 TU)
//   ① LTO/TBAA: 소거는 HTS_Secure_Memory D-2; Pimpl은 impl_buf_+placement Impl.
//   ② ISR: Enqueue/Dequeue/Tick/Get_* 는 PRIMASK critical_enter/exit로 큐와 정합.
//      Tick 본문은 잠금 구간이 길 수 있음 — SysTick 주기·우선순위 [요검토].
//   ③ Flash/BOR: 본 모듈 Flash 쓰기 없음.
//   ④ RDP: HTS_Hardware_Init 부트 검사.
// =========================================================================
#include "HTS_Priority_Scheduler.h"
#include "HTS_Arm_Irq_Mask_Guard.h"
#include "HTS_Anti_Debug.h"
#include "HTS_Secure_Memory.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#if defined(HTS_ALLOW_HOST_BUILD)
#include <mutex>
#endif

static_assert(sizeof(uint8_t) == 1, "uint8_t must be 1 byte");
static_assert(sizeof(uint32_t) == 4, "uint32_t must be 4 bytes");

namespace ProtectedEngine {

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
    static_assert((SOS_CAP & (SOS_CAP - 1u)) == 0u && SOS_CAP >= 1u, "SOS_CAP must be power of 2");
    static_assert((VOICE_CAP & (VOICE_CAP - 1u)) == 0u && VOICE_CAP >= 1u, "VOICE_CAP must be power of 2");
    static_assert((DATA_CAP & (DATA_CAP - 1u)) == 0u && DATA_CAP >= 1u, "DATA_CAP must be power of 2");

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
        // cap은 2의 거듭제곱 — % 대신 마스크 (B-CDMA 가변 분모 나눗셈 회피)
        items[static_cast<size_t>(tail)] = item;
        tail = static_cast<uint8_t>(
            (static_cast<uint32_t>(tail) + 1u) & static_cast<uint32_t>(cap - 1u));
        ++count;
        return true;
    }

    static bool ring_pop(QueueItem* items, uint8_t cap,
        uint8_t& head, uint8_t& count,
        QueueItem& out) noexcept
    {
        if (count == 0u) { return false; }
        const size_t hi = static_cast<size_t>(head);
        out = items[hi];
        SecureMemory::secureWipe(static_cast<void*>(&items[hi]), sizeof(QueueItem));
        head = static_cast<uint8_t>(
            (static_cast<uint32_t>(head) + 1u) & static_cast<uint32_t>(cap - 1u));
        --count;
        return true;
    }

    /// out_buf_cap 미만이면 pop 하지 않음 — memcpy OOB(H-1) 방지
    static bool ring_pop_if_fits(QueueItem* items, uint8_t cap,
        uint8_t& head, uint8_t& count,
        QueueItem& out, size_t out_buf_cap) noexcept
    {
        if (count == 0u) { return false; }
        const size_t hi = static_cast<size_t>(head);
        const uint8_t need = items[hi].len;
        if (static_cast<size_t>(need) > out_buf_cap) { return false; }
        out = items[hi];
        SecureMemory::secureWipe(static_cast<void*>(&items[hi]), sizeof(QueueItem));
        head = static_cast<uint8_t>(
            (static_cast<uint32_t>(head) + 1u) & static_cast<uint32_t>(cap - 1u));
        --count;
        return true;
    }

    static const QueueItem* ring_peek(
        const QueueItem* items, uint8_t head, uint8_t count) noexcept
    {
        if (count == 0u) { return nullptr; }
        return &items[static_cast<size_t>(head)];
    }

    static void ring_flush(QueueItem* items, size_t total_bytes,
        uint8_t& head, uint8_t& tail, uint8_t& count) noexcept
    {
        SecureMemory::secureWipe(static_cast<void*>(items), total_bytes);
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
    //     (STAGE 3: Armv7m_Irq_Mask_Guard + release()로 기존 exit 시점 보존)
    // =====================================================================

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
#if defined(HTS_ALLOW_HOST_BUILD)
        /// 호스트 멀티스레드 스트레스: PRIMASK 가드가 no-op이므로 큐 정합용 상호배제
        mutable std::mutex host_concurrency_mu;
#endif
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
            ? std::launder(reinterpret_cast<Impl*>(impl_buf_)) : nullptr;
    }

    const HTS_Priority_Scheduler::Impl*
        HTS_Priority_Scheduler::get_impl() const noexcept
    {
        return impl_valid_.load(std::memory_order_acquire)
            ? std::launder(reinterpret_cast<const Impl*>(impl_buf_)) : nullptr;
    }

    // =====================================================================
    //  생성자 / 소멸자
    // =====================================================================
    HTS_Priority_Scheduler::HTS_Priority_Scheduler() noexcept
        : impl_valid_(false)
    {
        SecureMemory::secureWipe(static_cast<void*>(impl_buf_), sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl();
        impl_valid_.store(true, std::memory_order_release);
    }

    HTS_Priority_Scheduler::~HTS_Priority_Scheduler() noexcept {
        Impl* const p = get_impl();
        if (p == nullptr) { return; }
        // ISR/TX 콜백의 UAF 방지: 유효 플래그를 먼저 내린 뒤 파괴·소거
        impl_valid_.store(false, std::memory_order_release);
        p->~Impl();
        SecureMemory::secureWipe(static_cast<void*>(impl_buf_), IMPL_BUF_SIZE);
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

#if defined(HTS_ALLOW_HOST_BUILD)
        std::lock_guard<std::mutex> host_lock(p->host_concurrency_mu);
#endif
        Armv7m_Irq_Mask_Guard irq;
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
            irq.release();
            return EnqueueResult::NULL_INPUT;
        }

        irq.release();
        return ok ? EnqueueResult::OK : EnqueueResult::QUEUE_FULL;
    }

    // =====================================================================
    //  Dequeue — 최고 우선순위 패킷 추출
    //
    //  정책: P0(SOS) → P1(VOICE) → P2(DATA) 엄격 우선
    //  재밍 시: P2 억제 (data_suppressed == true → P2 건너뜀)
    // =====================================================================
    bool HTS_Priority_Scheduler::Dequeue(
        uint8_t* out_data, size_t out_buf_cap, size_t& out_len,
        PacketPriority& out_priority) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr || out_data == nullptr) { return false; }

        QueueItem item = {};

#if defined(HTS_ALLOW_HOST_BUILD)
        std::lock_guard<std::mutex> host_lock(p->host_concurrency_mu);
#endif
        Armv7m_Irq_Mask_Guard irq;

        // P0: SOS (항상 최우선)
        if (ring_pop_if_fits(p->q_sos.items, static_cast<uint8_t>(SOS_CAP),
            p->q_sos.head, p->q_sos.count, item, out_buf_cap))
        {
            irq.release();
            std::memcpy(out_data, item.data, item.len);
            out_len = static_cast<size_t>(item.len);
            out_priority = PacketPriority::SOS;
            SecureMemory::secureWipe(static_cast<void*>(&item), sizeof(item));
            return true;
        }

        // P1: VOICE
        if (ring_pop_if_fits(p->q_voice.items, static_cast<uint8_t>(VOICE_CAP),
            p->q_voice.head, p->q_voice.count, item, out_buf_cap))
        {
            irq.release();
            std::memcpy(out_data, item.data, item.len);
            out_len = static_cast<size_t>(item.len);
            out_priority = PacketPriority::VOICE;
            SecureMemory::secureWipe(static_cast<void*>(&item), sizeof(item));
            return true;
        }

        // P2: DATA (재밍 억제 시 건너뜀)
        if (!p->data_suppressed) {
            if (ring_pop_if_fits(p->q_data.items, static_cast<uint8_t>(DATA_CAP),
                p->q_data.head, p->q_data.count, item, out_buf_cap))
            {
                irq.release();
                std::memcpy(out_data, item.data, item.len);
                out_len = static_cast<size_t>(item.len);
                out_priority = PacketPriority::DATA;
                SecureMemory::secureWipe(static_cast<void*>(&item), sizeof(item));
                return true;
            }
        }

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
        AntiDebugManager::pollHardwareOrFault();
        Impl* p = get_impl();
        if (p == nullptr) { return; }

#if defined(HTS_ALLOW_HOST_BUILD)
        std::lock_guard<std::mutex> host_lock(p->host_concurrency_mu);
#endif
        Armv7m_Irq_Mask_Guard irq;

        // NF 기반 DATA 억제 정책
        p->last_nf = current_nf;
        p->data_suppressed = (current_nf > NF_SUPPRESS_TH);

        //  pop 먼저 → VOICE 풀 시 tail 재삽입 → FIFO 역전
        //  peek으로 조건 확인 → VOICE 빈칸 있을 때만 pop+push
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

                // VOICE 삽입 실패 시(이론상 ISR 단일 맥락 밖 경합 등) DATA에서 이미 pop된
                // 항목이 증발하지 않도록 DATA tail로 복귀(FIFO 순서는 끝으로 밀림).
                const bool pushed_voice = ring_push(
                    p->q_voice.items, static_cast<uint8_t>(VOICE_CAP),
                    p->q_voice.tail, p->q_voice.count, aged);
                if (!pushed_voice) {
                    (void)ring_push(
                        p->q_data.items, static_cast<uint8_t>(DATA_CAP),
                        p->q_data.tail, p->q_data.count, aged);
                }

                irq.release();
                SecureMemory::secureWipe(static_cast<void*>(&aged), sizeof(aged));
                return;
            }
            // 조건 미충족 시: pop 하지 않음 → FIFO 순서 보존
        }
    }

    // =====================================================================
    //  Flush — 전체 큐 비우기
    // =====================================================================
    void HTS_Priority_Scheduler::Flush() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

#if defined(HTS_ALLOW_HOST_BUILD)
        std::lock_guard<std::mutex> host_lock(p->host_concurrency_mu);
#endif
        Armv7m_Irq_Mask_Guard irq;
        ring_flush(p->q_sos.items, sizeof(p->q_sos.items),
            p->q_sos.head, p->q_sos.tail, p->q_sos.count);
        ring_flush(p->q_voice.items, sizeof(p->q_voice.items),
            p->q_voice.head, p->q_voice.tail, p->q_voice.count);
        ring_flush(p->q_data.items, sizeof(p->q_data.items),
            p->q_data.head, p->q_data.tail, p->q_data.count);
    }

    // =====================================================================
    //  조회 API
    // =====================================================================
    size_t HTS_Priority_Scheduler::Get_SOS_Count() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) { return 0u; }
        size_t n = 0u;
        {
#if defined(HTS_ALLOW_HOST_BUILD)
            std::lock_guard<std::mutex> host_lock(p->host_concurrency_mu);
#endif
            Armv7m_Irq_Mask_Guard irq;
            n = static_cast<size_t>(p->q_sos.count);
        }
        return n;
    }

    size_t HTS_Priority_Scheduler::Get_VOICE_Count() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) { return 0u; }
        size_t n = 0u;
        {
#if defined(HTS_ALLOW_HOST_BUILD)
            std::lock_guard<std::mutex> host_lock(p->host_concurrency_mu);
#endif
            Armv7m_Irq_Mask_Guard irq;
            n = static_cast<size_t>(p->q_voice.count);
        }
        return n;
    }

    size_t HTS_Priority_Scheduler::Get_DATA_Count() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) { return 0u; }
        size_t n = 0u;
        {
#if defined(HTS_ALLOW_HOST_BUILD)
            std::lock_guard<std::mutex> host_lock(p->host_concurrency_mu);
#endif
            Armv7m_Irq_Mask_Guard irq;
            n = static_cast<size_t>(p->q_data.count);
        }
        return n;
    }

    bool HTS_Priority_Scheduler::Is_DATA_Suppressed() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) { return false; }
        bool s = false;
        {
#if defined(HTS_ALLOW_HOST_BUILD)
            std::lock_guard<std::mutex> host_lock(p->host_concurrency_mu);
#endif
            Armv7m_Irq_Mask_Guard irq;
            s = p->data_suppressed;
        }
        return s;
    }

} // namespace ProtectedEngine
