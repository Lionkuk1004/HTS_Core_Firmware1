// =========================================================================
// HTS_Unified_Scheduler.cpp
// DMA 핑퐁 이중 버퍼 기반 통합 송신 스케줄러 구현부
// Target: STM32F407 (Cortex-M4)
//
// [양산 수정]
//  1. Trigger_DMA_Hardware: 3단 플랫폼 분기
//  2. iostream/cerr ARM 가드
//  3. 생성자: resize() OOM → [BUG-65] try-catch 제거 → [BUG-66] resize 자체 제거
//  4. static packet_sequence_nonce → 멤버 변수
//  5. DMA 주소: 0x80000000 (보드별 커스텀 B-CDMA 모뎀)
//
//  [BUG-65] try-catch 완전 제거 (-fno-exceptions)
//  [BUG-66] vector ping/pong → 정적 배열 (Zero-Heap 원칙)
//  [BUG-68] DMA_START_BIT 매직넘버 → constexpr 상수화 (프로젝트 표준 J-3)
//  [BUG-69] current_dma_buffer 읽기 relaxed → acquire (ISR 확장 안전)
//  [BUG-70] 소멸자 보안 소거 추가 (핑퐁 32KB 텐서 데이터 잔존 방지)
//  [BUG-71] core_pipeline nullptr → AIRCR 즉시 리셋 (BB1 표준 통일)
//  [BUG-72] Schedule_Next_Transfer data_len @pre 단위 문서화
//  [BUG-73] [CRIT] FPGA DMA BUSY 폴링 + 타임아웃 추가
//           · FPGA 커스텀 DMA는 BUSY 상태에서 레지스터 덮어쓰기 시
//             내부 낸드 게이트 꼬임 → 하드웨어 락업/HardFault
//           · Trigger_DMA_Hardware: 레지스터 장전 전 BUSY 비트 폴링
//           · 타임아웃 100,000 루프(≈600us @168MHz) — 초과 시 쓰기 차단
//           · 데이터 1프레임 유실 > FPGA 락업 (안전 우선)
// =========================================================================
#include "HTS_Unified_Scheduler.h"
#include "HTS_Hardware_Init.h"

#include <atomic>
#include <cstdint>
#include <cstddef>
#include <cstring>

// 플랫폼 감지
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#define HTS_PLATFORM_ARM
#endif

namespace ProtectedEngine {

    // =====================================================================
    //  보안 메모리 소거 (프로젝트 표준 — volatile + asm clobber + release)
    // =====================================================================
    static void Secure_Wipe_Sched(void* ptr, size_t size) noexcept {
        if (ptr == nullptr || size == 0u) { return; }
        volatile unsigned char* p =
            static_cast<volatile unsigned char*>(ptr);
        for (size_t i = 0u; i < size; ++i) { p[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  DMA 레지스터 절대 주소 (보드별 커스텀 B-CDMA 모뎀)
    //  [주의] STM32F407 내장 DMA(0x4002_6000)와는 별개
    //         외부 B-CDMA 모뎀 FPGA 맵드 주소 — 보드 설계서 참조
    // =====================================================================
    static constexpr uint32_t DMA_BASE_ADDR = 0x80000000u;
    static constexpr uint32_t DMA_SRC_ADDR_REG = DMA_BASE_ADDR + 0x100u;
    static constexpr uint32_t DMA_TRANS_LEN_REG = DMA_BASE_ADDR + 0x104u;
    static constexpr uint32_t DMA_CTRL_STAT_REG = DMA_BASE_ADDR + 0x108u;
    static constexpr uint32_t DMA_DEST_ADDR_REG = DMA_BASE_ADDR + 0x10Cu;
    static constexpr uint32_t BCDMA_TX_FIFO_ADDR = 0x90000000u;

    // [BUG-68] DMA 제어 비트 상수화 (J-3 매직넘버 상수화 — BB1 BUG-56 표준)
    static constexpr uint32_t DMA_START_BIT = 0x01u;  ///< bit[0] DMA 전송 시작
    // [BUG-73] FPGA DMA BUSY 비트 + 폴링 타임아웃
    //  FPGA 커스텀 DMA 컨트롤러 control_status 레지스터 비트맵:
    //    bit[0] = START (W: 전송 시작, R: 0)
    //    bit[1] = BUSY  (R: 1=전송 중, 0=IDLE)
    //  ⚠ BUSY=1 상태에서 source_address/transfer_length 쓰기 금지
    //    → FPGA 내부 낸드 게이트 꼬임 → 시스템 락업/HardFault
    //  보드별 비트맵이 다를 수 있음 — FPGA RTL 또는 보드 설계서 참조
    static constexpr uint32_t DMA_BUSY_BIT = 0x02u;   ///< bit[1] FPGA DMA 전송 중
    // 타임아웃: 168MHz × ~600us ≈ 100,000 루프
    //  MAX_DMA_FRAME(4096) × 32bit = 16KB, FSMC 8비트 모드 최악
    //  16KB ÷ 30MB/s(FSMC) ≈ 530us → 100,000 루프로 충분
    static constexpr uint32_t DMA_BUSY_TIMEOUT = 100000u;

    // [BUG-71] ARM Cortex-M AIRCR 리셋 상수 (BB1 BUG-56과 통일)
    static constexpr uintptr_t AIRCR_ADDR = 0xE000ED0Cu;
    static constexpr uint32_t  AIRCR_VECTKEY = 0x05FA0000u;
    static constexpr uint32_t  AIRCR_SYSRST = 0x04u;

    // =====================================================================
    //  생성자
    //
    //  [BUG-66] vector::resize() 완전 제거 → 정적 배열 + memset
    //  [BUG-71] core_pipeline nullptr → AIRCR 즉시 하드 리셋
    //   기존: while(true) 무한 루프 — 워치독 만료까지 CPU 점유
    //   수정: AIRCR SYSRESETREQ → 즉시 하드웨어 리셋 (BB1 표준)
    //         while(true)는 AIRCR 실패 시 폴백으로 유지
    // =====================================================================
    Unified_Scheduler::Unified_Scheduler(Dual_Tensor_Pipeline* pipeline) noexcept
        : core_pipeline(pipeline)
        , buffer_size(0)
        , ping_buffer{}
        , pong_buffer{}
        , current_dma_buffer(0)
        , packet_sequence_nonce(0)
        , dma_hw{} {

        if (!core_pipeline) {
            // [BUG-71] AIRCR 즉시 리셋 → while(true)는 도달 불가 폴백
#if defined(HTS_PLATFORM_ARM)
            * reinterpret_cast<volatile uint32_t*>(
                static_cast<uintptr_t>(AIRCR_ADDR)) =
                (AIRCR_VECTKEY | AIRCR_SYSRST);
#endif
            while (true) {
#if defined(__GNUC__) || defined(__clang__)
                __asm__ __volatile__("" ::: "memory");
#endif
            }
        }

        // [BUG-66] 정적 배열 상한 클램프 — 배열 OOB 원천 차단
        const size_t requested = core_pipeline->Get_Active_Tensor_Count();
        buffer_size = (requested < MAX_DMA_FRAME) ? requested : MAX_DMA_FRAME;

        // DMA 레지스터 매핑 — ARM에서만 유효
#if defined(HTS_PLATFORM_ARM)
        dma_hw.source_address = reinterpret_cast<volatile uint32_t*>(static_cast<uintptr_t>(DMA_SRC_ADDR_REG));
        dma_hw.transfer_length = reinterpret_cast<volatile uint32_t*>(static_cast<uintptr_t>(DMA_TRANS_LEN_REG));
        dma_hw.control_status = reinterpret_cast<volatile uint32_t*>(static_cast<uintptr_t>(DMA_CTRL_STAT_REG));
        dma_hw.dest_address = reinterpret_cast<volatile uint32_t*>(static_cast<uintptr_t>(DMA_DEST_ADDR_REG));
#else
        // PC 시뮬레이션: DMA 레지스터 = nullptr (Trigger_DMA_Hardware에서 no-op)
        dma_hw.source_address = nullptr;
        dma_hw.transfer_length = nullptr;
        dma_hw.control_status = nullptr;
        dma_hw.dest_address = nullptr;
#endif
    }

    // =====================================================================
    //  [BUG-70] 소멸자 — 핑퐁 버퍼 + 넌스 보안 소거
    //
    //  기존: 소멸자 미정의 (= default 암시)
    //   → 32KB 핑퐁 버퍼에 텐서 데이터 평문 잔존
    //   → 콜드부트/힙 스캔 공격으로 직전 송신 데이터 복원 가능
    //
    //  수정: volatile 소거 + asm clobber + release fence
    //   → BB1, TensorCodec, Anchor_Vault 소멸자 보안 소거 표준과 통일
    // =====================================================================
    Unified_Scheduler::~Unified_Scheduler() noexcept {
        Secure_Wipe_Sched(ping_buffer, sizeof(ping_buffer));
        Secure_Wipe_Sched(pong_buffer, sizeof(pong_buffer));
        Secure_Wipe_Sched(&packet_sequence_nonce, sizeof(packet_sequence_nonce));
        current_dma_buffer.store(0, std::memory_order_relaxed);
        buffer_size = 0u;
        core_pipeline = nullptr;
    }

    // =====================================================================
    //  Schedule_Next_Transfer — 센서 → 듀얼 텐서 → 핑퐁 버퍼 → DMA
    //
    //  [BUG-69] current_dma_buffer 읽기: relaxed → acquire
    //   기존: relaxed — ISR/다른 컨텍스트에서 stale 값 가능
    //   수정: acquire — store(release)와 쌍을 이루어 가시성 보장
    //         현재 ISR이 비어있어 실질 영향 없으나, 향후 ISR에서
    //         버퍼 스왑 로직 추가 시 데이터 레이스 예방
    //
    //  [BUG-72] @pre data_len 단위 문서화
    //   data_len: raw_sensor_data의 uint16_t 원소 개수
    //   buffer_size/generated_len: uint32_t 원소 개수
    //   듀얼 텐서 파이프라인이 16→32비트 패킹을 내부 수행하므로
    //   safe_len 계산은 32비트 단위 출력 기준으로 수렴함
    //   호출자는 data_len >= buffer_size × 2 를 보장해야 파이프라인
    //   입력이 부족하지 않음 (16비트 2개 → 32비트 1개 패킹)
    // =====================================================================
    bool Unified_Scheduler::Schedule_Next_Transfer(
        uint16_t* raw_sensor_data, size_t data_len,
        std::atomic<bool>& abort_signal) noexcept {

        // [BUG-69] acquire 읽기 — store(release)와 쌍
        const int active_dma = current_dma_buffer.load(std::memory_order_acquire);
        const int target_cpu_buffer = (active_dma == 0) ? 1 : 0;

        // 듀얼 텐서 파이프라인 실행 (16비트 보안 + 16비트 스텔스 동시 생성)
        bool success = core_pipeline->Execute_Dual_Processing(
            raw_sensor_data, data_len, packet_sequence_nonce++, abort_signal);
        if (!success) return false;

        // 파이프라인 출력을 타겟 버퍼에 복사
        const uint32_t* generated_data = core_pipeline->Get_Dual_Lane_Data();
        const size_t generated_len = core_pipeline->Get_Dual_Lane_Size();
        if (generated_data == nullptr || generated_len == 0u) return false;

        uint32_t* active_cpu_buffer =
            (target_cpu_buffer == 0) ? ping_buffer : pong_buffer;

        // [BUG-72] safe_len: 32비트 단위 출력 기준 (파이프라인 출력 크기)
        size_t safe_len = (data_len < buffer_size) ? data_len : buffer_size;
        if (safe_len > generated_len) safe_len = generated_len;

        for (size_t i = 0; i < safe_len; ++i) {
            active_cpu_buffer[i] = generated_data[i];
        }

        // 버퍼 스왑 (Ping ↔ Pong)
        current_dma_buffer.store(target_cpu_buffer, std::memory_order_release);

        // DMA 전송 시작
        Trigger_DMA_Hardware(active_cpu_buffer, safe_len);

        return true;
    }

    // =====================================================================
    //  DMA 전송 완료 ISR
    //  TODO: 향후 버퍼 스왑 알림, 세마포어 시그널 등 추가
    // =====================================================================
    void Unified_Scheduler::DMA_Transfer_Complete_ISR() noexcept {
        // 실제 환경: 다음 스왑 준비 또는 슬립 해제
    }

    // =====================================================================
    //  Trigger_DMA_Hardware — DMA 레지스터 장전 + 전송 시작
    //
    //  [양산 수정] 3단 플랫폼 분기
    //  [BUG-68] 0x01u → DMA_START_BIT constexpr 상수
    //  [BUG-73] FPGA DMA BUSY 폴링 — 레지스터 장전 전 반드시 IDLE 확인
    //
    //  ⚠ CRITICAL: FPGA 커스텀 DMA 컨트롤러는 BUSY=1 상태에서
    //     source_address / dest_address / transfer_length 레지스터를
    //     덮어쓰면 FPGA 내부 낸드 게이트가 꼬이면서 하드웨어 락업 발생.
    //     (STM32 내장 DMA는 EN=0으로 비활성화 후 쓰기 가능하지만,
    //      외부 FPGA는 이 보호 메커니즘이 없음)
    //
    //  동작 순서:
    //   ① BUSY 비트 폴링 (타임아웃 100,000 루프 ≈ 600us @168MHz)
    //   ② BUSY 해제 확인 후에만 레지스터 장전
    //   ③ 캐시 플러시
    //   ④ START 비트 설정
    //   타임아웃 시: 레지스터 쓰기 전면 차단 → return (데이터 유실이
    //   하드웨어 락업보다 안전)
    // =====================================================================
    void Unified_Scheduler::Trigger_DMA_Hardware(
        uint32_t* buffer_ptr, size_t length) noexcept {

        (void)buffer_ptr;
        (void)length;

#if defined(HTS_PLATFORM_ARM)
        // ARM 베어메탈: 실제 DMA 하드웨어 접근
        if (!dma_hw.source_address || !dma_hw.transfer_length ||
            !dma_hw.control_status || !dma_hw.dest_address) {
            return;
        }

        // ── [BUG-73] Step 0: FPGA DMA BUSY 해제 대기 ──────────────
        //  이전 전송이 완료될 때까지 레지스터 쓰기를 절대 하지 않음.
        //  BUSY=1 상태에서 source_address 쓰기 → FPGA 락업 → HardFault.
        //
        //  타임아웃: 168MHz에서 단순 루프 1회 ≈ 6ns (분기+읽기+감산)
        //  100,000회 × 6ns ≈ 600us
        //  MAX_DMA_FRAME(4096) × 4B = 16KB, FSMC 8비트 모드 최악
        //  16KB ÷ 30MB/s(FSMC) ≈ 530us → 100,000 루프로 충분
        {
            uint32_t timeout = DMA_BUSY_TIMEOUT;
            while ((*dma_hw.control_status & DMA_BUSY_BIT) != 0u) {
                if (--timeout == 0u) {
                    // DMA 행(Hang) — 레지스터 쓰기 전면 차단
                    // 데이터 1프레임 유실이 FPGA 락업보다 안전
                    // 호출자(Schedule_Next_Transfer)는 다음 주기에 재시도
                    return;
                }
            }
        }

        // ── Step 1: DMA 레지스터 장전 (BUSY=0 확인 후에만 도달) ────
        *dma_hw.source_address = static_cast<uint32_t>(
            reinterpret_cast<uintptr_t>(buffer_ptr));
        *dma_hw.dest_address = static_cast<uint32_t>(BCDMA_TX_FIFO_ADDR);
        *dma_hw.transfer_length = static_cast<uint32_t>(length);

        // ── Step 2: CPU 캐시 → RAM 플러시 ─────────────────────────
        //  DMA가 읽기 전에 최신 데이터 보장
        Hardware_Init_Manager::Cache_Clean_Tx(buffer_ptr, length);

        // ── Step 3: DMA 전송 시작 ─────────────────────────────────
        //  [BUG-68] constexpr 상수
        *dma_hw.control_status |= DMA_START_BIT;
#else
        // PC 시뮬레이션: DMA 없음 — 데이터는 이미 버퍼에 준비됨
#endif
    }

} // namespace ProtectedEngine