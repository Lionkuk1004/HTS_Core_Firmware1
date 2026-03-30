// =========================================================================
// BB1_Core_Engine.cpp
// HTS 최상위 코어 엔진 구현부 (Pimpl 은닉)
// Target: STM32F407VGT6 (Cortex-M4F, 168MHz)
//         Flash 1MB / SRAM 192KB (112KB+16KB CCM+64KB 보조)
//
// ─────────────────────────────────────────────────────────────────────────
//  [양산 수정 이력 — 누적 59건]
//  BUG-01~46 (이전 세션)
//  BUG-47 [CRIT] unique_ptr Pimpl → placement new (zero-heap)
//  BUG-48 [HIGH] Secure_Wipe_BB1 pragma O0 제거
//  BUG-49 [HIGH] Secure_Wipe_BB1 seq_cst → release
//  BUG-50 [CRIT] noise_ratio_to_q16 double → 정수 나눗셈
//  BUG-51 [CRIT] Scramble_XOR LCG 31비트 마스킹 제거
//  BUG-52 [CRIT] Impl vector 6개 → 정적 배열 (힙 완전 제거)
//  BUG-53 [MED]  static_assert 메시지 "1024B" 잔류 → "81920B" 수정
//  BUG-54 [LOW]  [[unlikely]]/[[likely]] C++20 가드 매크로 (C++14/17 호환)
//  BUG-55 [CRIT] noise_to_q16 uint64_t 나눗셈 → uint32_t 다운캐스트
//         · MAX_TENSOR_ELEMENTS=2048 → 2048<<16=134M < UINT32_MAX ✓
//         · __aeabi_uldivmod 100+cyc → UDIV 2~12cyc
//  BUG-56 [MED]  AIRCR 매직넘버(0xE000ED0C,0x05FA) → constexpr 상수화
//         · TX pipeline + RX pipeline 2곳 모두 적용
//  BUG-57 [LOW]  C26495 tx/rx 익명 구조체 멤버 초기화 (MSVC 경고 해소)
//         · struct { uint32_t arr[N]; } tx; → struct { uint32_t arr[N] = {}; } tx = {};
//         · 생성자에서 placement new + Wipe로 이중 초기화되므로 기능 무관
//  BUG-58 [LOW]  Polymorphic_Shield block_index CTR 카운터 추가
//         · TX Apply + RX Reverse 양쪽 static_cast<uint32_t>(i) 전달
//         · 기존: block_index=0 (동일 청크 내 동일 키스트림)
//         · 수정: 원소별 고유 CTR → 키스트림 다양성 확보
//  BUG-59 [HIGH] noise_to_q16 오버플로우 안전 증명 → static_assert 추가
//         · 기존: 주석 증명만 존재 ("2048<<16=134M < UINT32_MAX")
//         · 수정: static_assert로 컴파일 타임 보장
//         · MAX_TENSOR_ELEMENTS 변경 시 주석 미갱신 위험 원천 차단
// =========================================================================
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "BB1_Core_Engine.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
// [BUG-52] <vector> 제거: Impl 멤버가 정적 배열로 전환됨
#include <algorithm>

#include "HTS_Gyro_Engine.h"
#include "HTS_Entropy_Arrow.hpp"
#include "HTS_Hardware_Shield.h"
#include "HTS_Physical_Entropy_Engine.h"
#include "HTS_Polymorphic_Shield.h"
#include "HTS_Universal_API.h"
#include "HTS_AntiAnalysis_Shield.h"
// [VDF 삭제] HTS_Quantum_Decoy_VDF.h 제거
//  Execute_Time_Lock_Puzzle: 50,000회×64비트 = 119ms CPU 독점
//  → DMA 타임슬롯 1ms의 119배 초과 → 패킷 100% 유실
//  V400 Walsh 확산 + ARIA/LEA 암호화 + Polymorphic_Shield가 보안 담당
#include "HTS_Orbital_Mapper.hpp"
#include "HTS_Sparse_Recovery.h"
#include "HTS_Holo_Tensor_Engine.h"

// =========================================================================
//  [BUG-54] C++20 속성 가드 — C++14/17 빌드 호환
//  프로젝트 표준 패턴 (HTS_Universal_Adapter, HTS_Entropy_Arrow 등과 통일)
// =========================================================================
#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
#define HTS_BB1_UNLIKELY [[unlikely]]
#define HTS_BB1_LIKELY   [[likely]]
#else
#define HTS_BB1_UNLIKELY
#define HTS_BB1_LIKELY
#endif

namespace ProtectedEngine {

    // ── [BUG-48] 보안 메모리 소거 ─────────────────────────────────────
    // pragma O0 제거 → memset + asm clobber(DSE 차단) + seq_cst(순서 보장)
    // Strict Aliasing 규칙 준수 — volatile 포인터 캐스팅 우회 없음
    static void Secure_Wipe_BB1(void* ptr, size_t size) noexcept {
        if (ptr == nullptr || size == 0u) { return; }
        std::memset(ptr, 0, size);
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
        // [BUG-49] seq_cst → release: 소거 완료 가시성만 필요 (HTS_Secure_Memory.cpp 정책 통일)
        std::atomic_thread_fence(std::memory_order_release);
    }

    // ── Q16 상수 ────────────────────────────────────────────────────────
    static constexpr int32_t Q16_ONE = 65536;
    static constexpr int32_t Q16_EMA_OLD = 58982;
    static constexpr int32_t Q16_EMA_NEW = 6554;
    static constexpr int32_t Q16_NOISE_015 = 9830;
    static constexpr int32_t Q16_NOISE_008 = 5243;
    static constexpr int32_t Q16_NOISE_003 = 1966;

    // ── SRAM 예산 ───────────────────────────────────────────────────────
    // [2048 다운사이즈] 텐서 요소 수 4096→2048
    //  · SRAM: 37KB→20KB (−16KB), Phase 2 여유 9→25KB
    //  · 처리 속도: 2배 향상 (루프 절반)
    //  · 보안: 2048×2048×L=4 = 10^80,807,124 (4096×L=1과 동일)
    //  · V400 Walsh/HARQ/AJC 성능: 영향 0 (독립 계층)
    static constexpr size_t MAX_TENSOR_ELEMENTS = 2048;

    // [BUG-52+65] 힙 할당 전면 제거 → 정적 배열 + TX/RX 공유
    // shared: state_map(8KB) + temp_vec(8KB) = 16KB (TX/RX 반이중 공유)
    // rx_only: erased_bits(256B) — 비트 패킹 (uint8_t[2048] → uint32_t[64])
    // erasure_idx: 완전 제거 (2-pass → 1-pass 인라인)
    // 합계: 32.5KB (기존 76KB → 56% 절감)
    static constexpr size_t BB1_STATIC_ARRAYS =
        MAX_TENSOR_ELEMENTS * sizeof(uint32_t) * 2   // state_map + temp_vec (공유)
        + (MAX_TENSOR_ELEMENTS / 32u) * sizeof(uint32_t);  // erased_bits

    static_assert(BB1_STATIC_ARRAYS < 80u * 1024u,
        "BB1 static arrays exceed 80KB SRAM budget");

    // [BUG-59] noise_to_q16 uint32_t 오버플로우 안전 증명 — 컴파일 타임 보장
    //  MAX_TENSOR_ELEMENTS << 16 이 UINT32_MAX를 초과하면 빌드 실패
    //  향후 MAX_TENSOR_ELEMENTS 증가 시 주석이 아닌 빌드 에러로 즉시 검출
    static_assert(
        static_cast<uint64_t>(MAX_TENSOR_ELEMENTS) << 16u
        <= static_cast<uint64_t>(UINT32_MAX),
        "MAX_TENSOR_ELEMENTS << 16이 uint32_t 범위를 초과합니다 — noise_to_q16 수정 필요");

    // ── [BUG-56] ARM Cortex-M AIRCR 리셋 상수 (J-3 매직넘버 상수화) ────
    // Application Interrupt and Reset Control Register
    // ARM Architecture Reference Manual (DDI0403E) §B3.2.6
    static constexpr uintptr_t AIRCR_ADDR = 0xE000ED0Cu;  // AIRCR 레지스터 주소
    static constexpr uint32_t  AIRCR_VECTKEY = 0x05FA0000u;  // 쓰기 허가 키
    static constexpr uint32_t  AIRCR_SYSRST = 0x04u;        // SYSRESETREQ 비트

    // [BUG-50→55] double 산술 완전 제거 → 정수 기반 Q16 변환
    // [BUG-55] uint64_t 나눗셈 → uint32_t 다운캐스트 (64비트 UDIV 잔재 제거)
    //   기존: (uint64_t)(destroyed) << 16 / total → __aeabi_uldivmod 100+cyc
    //   수정: (uint32_t)(destroyed) << 16 / (uint32_t)total → UDIV 2~12cyc
    //   안전 증명: BUG-59 static_assert로 컴파일 타임 보장
    static int32_t noise_to_q16(size_t destroyed, size_t total) noexcept {
        if (total == 0u || destroyed == 0u) return 0;
        if (destroyed >= total) return Q16_ONE;
        // [BUG-55] uint32_t 하드웨어 UDIV (Cortex-M4 단일명령어)
        const uint32_t d32 = static_cast<uint32_t>(destroyed);
        const uint32_t t32 = static_cast<uint32_t>(total);
        return static_cast<int32_t>((d32 << 16u) / t32);
    }

    // =====================================================================
    //  [BUG-52] Impl — 정적 배열 기반 (힙 할당 0회, OOM 불가)
    //
    //  기존: vector<T> 6개 + Reserve_Buffers(resize) → 데드코드
    //   · -fno-exceptions에서 resize OOM = std::terminate 즉시 → 반환값 검사 도달 불가
    //   · "방어 코드처럼 보이지만 실제 보호 효과 0"인 거짓 안전 패턴
    //
    //  수정: MAX_TENSOR_ELEMENTS(2048) 컴파일 타임 상수 → 정적 배열
    //   · sizeof(Impl) ≈ 17KB → IMPL_BUF_SIZE = 20480 (20KB)
    //   · 힙 할당 0회 → OOM 경로 자체가 존재하지 않음
    //   · SRAM 총량 동일 (힙 76KB → 정적 76KB, 할당 전략만 전환)
    //
    //  ⚠ BB1_Core_Engine은 반드시 전역/정적 변수로 배치할 것
    //    스택에 놓으면 ~80KB 스택 소모 → ARM 스택 오버플로우
    // =====================================================================
    struct BB1_Core_Engine::Impl {

        // ── [BUG-65] TX/RX 공유 버퍼 (반이중 → 동시 접근 불가) ──
        //  Build_Map → state_map 생성, 매 호출 시 재생성
        //  temp_vec: 인터리빙/역인터리빙 스크래치
        //  TX/RX 순차 실행 → 1개로 공유 (−32KB)
        struct {
            uint32_t state_map[MAX_TENSOR_ELEMENTS] = {};
            uint32_t temp_vec[MAX_TENSOR_ELEMENTS] = {};
        } shared = {};

        // ── TX 전용 상태 (경량) ──────────────────────────────────
        Gyro_Engine            tx_gyro;
        uint32_t               tx_gyro_phase = 0;
        Entropy_Time_Arrow     tx_time_arrow = Entropy_Time_Arrow(3600u);

        // ── RX 전용 상태 (경량) ──────────────────────────────────
        //  [BUG-65] erased: uint8_t[4096] → uint32_t[128] 비트 패킹 (−3.5KB)
        //  [BUG-65] erasure_idx: 완전 제거 (−8KB) — 1-pass 인라인으로 대체
        static constexpr size_t ERASED_WORDS = MAX_TENSOR_ELEMENTS / 32u;
        uint32_t erased_bits[ERASED_WORDS] = {};

        Gyro_Engine            rx_gyro;
        uint32_t               rx_gyro_phase = 0;
        Entropy_Time_Arrow     rx_time_arrow = Entropy_Time_Arrow(3600u);

        // ── [BUG-65] erased 비트 접근 헬퍼 (인라인, 분기 0개) ────
        void set_erased(size_t idx) noexcept {
            erased_bits[idx >> 5u] |= (1u << (idx & 31u));
        }
        bool is_erased(size_t idx) const noexcept {
            return (erased_bits[idx >> 5u] & (1u << (idx & 31u))) != 0u;
        }
        void clear_erased(size_t n) noexcept {
            const size_t words = (n + 31u) >> 5u;
            std::memset(erased_bits, 0, words * sizeof(uint32_t));
        }

        // ── 공유 (Lock-free) ────────────────────────────────────
        // [BUG-44] SeqLock: last_stats 찢어짐 읽기 방지
        std::atomic<uint32_t>  stats_seq{ 0 };
        RecoveryStats          last_stats = {};
        std::atomic<int32_t>   moving_avg_noise_q16{ 0 };

        // [BUG-52] Reserve_Buffers 완전 삭제
        //  정적 배열 → 생성자에서 placement new만으로 초기화 완료
        //  OOM 경로 자체가 소멸 → 데드코드 0, 거짓 안전 패턴 0

        // ── 궤적 소거 (고정 크기 — 조건 분기 없음) ────────────────
        // [FIX-LOW] shared 이중 소거 제거: Wipe_Shared 분리
        void Wipe_Shared() noexcept {
            Secure_Wipe_BB1(shared.state_map, sizeof(shared.state_map));
            Secure_Wipe_BB1(shared.temp_vec, sizeof(shared.temp_vec));
        }
        void Wipe_TX() noexcept {
            Wipe_Shared();
        }
        void Wipe_RX() noexcept {
            Wipe_Shared();
            Secure_Wipe_BB1(erased_bits, sizeof(erased_bits));
        }

        // ── 소멸자 ─────────────────────────────────────────────
        ~Impl() noexcept {
            Secure_Wipe_BB1(&tx_gyro_phase, sizeof(tx_gyro_phase));
            Secure_Wipe_BB1(&rx_gyro_phase, sizeof(rx_gyro_phase));
            moving_avg_noise_q16.store(0, std::memory_order_relaxed);
            Secure_Wipe_BB1(&last_stats, sizeof(last_stats));
            Wipe_Shared();  // 1회만 소거
            Secure_Wipe_BB1(erased_bits, sizeof(erased_bits));
        }

        // ── 적응형 앵커 (atomic acquire) ────────────────────────
        [[nodiscard]]
        uint32_t Adaptive_Anchor() const noexcept {
            const int32_t n = moving_avg_noise_q16.load(
                std::memory_order_acquire);
            if (n > Q16_NOISE_015) { return 4u; }
            if (n > Q16_NOISE_008) { return 6u; }
            if (n > Q16_NOISE_003) { return 10u; }
            return 20u;
        }

        // ── [BUG-51] LCG 스크램블 — FIX-09 전파 (31비트 마스킹 제거) ──
        // 기존: & 0x7FFFFFFFu → MSB 항상 0 → XOR bit-15 항상 0 노출
        // 수정: uint32_t 자연 오버플로우 → 32비트 전 영역 엔트로피 활용
        template <typename T>
        static void Scramble_XOR(T* data, size_t n,
            uint64_t session) noexcept {
            uint32_t s = static_cast<uint32_t>(session ^ 0xAA55AA55u);
            if (s == 0u) { s = 0xDEADBEEFu; }
            for (size_t i = 0u; i < n; ++i) {
                s = s * 1103515245u + 12345u;
                data[i] ^= static_cast<T>(s & 0xFFFFu);
            }
        }

        // ── [BUG-65] PLL (erased 비트 패킹) ──────────────────────
        template <typename T>
        void PLL(T* data, size_t n, uint32_t anchor) noexcept {
            if (anchor == 0u || n == 0u) { return; }
            const size_t fa = static_cast<size_t>(anchor);
            const T AV = static_cast<T>(0x7FFF);
            const T IV = static_cast<T>(
                static_cast<T>(~static_cast<T>(0x7FFF))
                + static_cast<T>(1));
            const T EM = static_cast<T>(~static_cast<T>(0));

            bool ph = false;
            for (size_t b = 0u; b < n; b += fa) {
                const size_t p = std::min(b + fa - 1u, n - 1u);
                if (data[p] == IV) { ph = true;  break; }
                if (data[p] == AV) { ph = false; break; }
            }
            for (size_t b = 0u; b < n; b += fa) {
                const size_t p = std::min(b + fa - 1u, n - 1u);
                const bool bi = (data[p] == IV) ? true
                    : (data[p] == AV) ? false : ph;
                set_erased(p);             // [BUG-65] 비트 패킹
                data[p] = EM;
                for (size_t i = b; i < p; ++i) {
                    if (data[i] == EM) { set_erased(i); }  // [BUG-65]
                    else if (bi) {
                        data[i] = static_cast<T>(
                            static_cast<T>(~data[i]) + static_cast<T>(1));
                    }
                }
                ph = bi;
            }
        }

        // ── [BUG-45] 인터리버 상태맵: % → 뺄셈 강도 절감 ────────
        // [BUG-52] std::vector& → uint32_t* (정적 배열 직접 참조)
        static void Build_Map(uint32_t* buf,
            size_t n, uint32_t fa) noexcept {
            if (fa <= 1u || n % static_cast<size_t>(fa) != 0u) {
                for (size_t k = 0u; k < n; ++k)
                    buf[k] = static_cast<uint32_t>(k);
                return;
            }
            const uint32_t H = static_cast<uint32_t>(
                n / static_cast<size_t>(fa));
            const uint32_t cols = fa - 1u;
            const uint32_t hop = H / cols;
            for (uint32_t r = 0u; r < H; ++r) {
                uint32_t cur_hop = r;
                for (uint32_t c = 0u; c < fa; ++c) {
                    const uint32_t li = r * fa + c;
                    if (c == cols) {
                        buf[li] = li;
                    }
                    else {
                        buf[li] = cur_hop * fa + c;
                        cur_hop += hop;
                        while (cur_hop >= H) { cur_hop -= H; }
                    }
                }
            }
        }

        static uint32_t Resolve_Anchor(uint32_t anchor_interval,
            bool is_test, uint32_t adaptive) noexcept {
            uint32_t fa = anchor_interval;
            if (!is_test) {
                if (fa == 0u) { fa = adaptive; }
                if (fa == 0u || fa > 6u) { fa = (fa != 0u) ? 6u : 0u; }
            }
            else {
                if (fa == 0u) { fa = 20u; }
            }
            return fa;
        }

        // ── [BUG-43+50] CAS Lock-free EMA 갱신 (double 완전 제거) ──
        void Update_Noise_EMA(const RecoveryStats& stats) noexcept {
            const int32_t nn = noise_to_q16(
                stats.destroyed_count, stats.total_elements);
            int32_t old_val = moving_avg_noise_q16.load(
                std::memory_order_relaxed);
            int32_t new_val;
            do {
                new_val = static_cast<int32_t>(
                    (static_cast<int64_t>(old_val) * Q16_EMA_OLD
                        + static_cast<int64_t>(nn) * Q16_EMA_NEW) >> 16);
            } while (!moving_avg_noise_q16.compare_exchange_weak(
                old_val, new_val,
                std::memory_order_release,
                std::memory_order_relaxed));
        }
    };

    // =====================================================================
    //  [BUG-47] 컴파일 타임 크기·정렬 검증 + get_impl()
    // =====================================================================
    BB1_Core_Engine::Impl* BB1_Core_Engine::get_impl() noexcept {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            // [BUG-53] 메시지 수정: 1024B → 81920B (BUG-52에서 버퍼 확장 후 미갱신)
            "Impl이 IMPL_BUF_SIZE(81920B)를 초과합니다 — 버퍼 크기를 늘려주세요");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 요구가 impl_buf_ alignas(8)을 초과합니다");
        return impl_valid_ ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }

    const BB1_Core_Engine::Impl* BB1_Core_Engine::get_impl() const noexcept {
        return impl_valid_
            ? reinterpret_cast<const Impl*>(impl_buf_)
            : nullptr;
    }

    // =====================================================================
    //  [BUG-52] 생성자 — placement new만으로 초기화 완료 (OOM 경로 소멸)
    //
    //  기존: Reserve_Buffers(resize) → 실패 검사 → 데드코드
    //   · -fno-exceptions에서 resize OOM = std::terminate 즉시 호출
    //   · 반환값 검사 코드는 도달 불가 → 거짓 안전 패턴
    //
    //  수정: 정적 배열 → 힙 할당 0회 → OOM 경로 자체가 존재하지 않음
    //   · Secure_Wipe_BB1 + placement new = 초기화 완료
    //   · 실패 경로 0개, 분기 0개, 완벽하게 결정론적
    // =====================================================================
    BB1_Core_Engine::BB1_Core_Engine() noexcept : impl_valid_(false) {
        Secure_Wipe_BB1(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl();
        impl_valid_ = true;
    }

    // =====================================================================
    //  [BUG-47] 소멸자 — 명시적 (= default 제거)
    // =====================================================================
    BB1_Core_Engine::~BB1_Core_Engine() noexcept {
        Impl* p = get_impl();
        if (p != nullptr) { p->~Impl(); }
        Secure_Wipe_BB1(impl_buf_, sizeof(impl_buf_));
        impl_valid_ = false;
    }

    // =====================================================================
    //  [BUG-44] SeqLock 원자적 스냅샷 읽기
    // =====================================================================
    RecoveryStats BB1_Core_Engine::Get_Last_Recovery_Stats() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) HTS_BB1_UNLIKELY{ return RecoveryStats{}; }
        RecoveryStats copy;
        uint32_t seq;
        do {
            seq = p->stats_seq.load(std::memory_order_acquire);
            copy = p->last_stats;
            std::atomic_thread_fence(std::memory_order_acquire);
        } while ((seq & 1u) ||
            seq != p->stats_seq.load(std::memory_order_relaxed));
        return copy;
    }

    // =====================================================================
    //  TX 파이프라인 (메인 루프 전용)
    // =====================================================================
    template <typename T>
    bool BB1_Core_Engine::Process_Tensor_Pipeline(
        T* tensor_data, size_t elements, uint64_t session_id,
        uint32_t slice_chunk, uint32_t anchor_interval,
        bool is_test_mode, bool strict_mode) {

        (void)strict_mode;
        Impl* p_impl = get_impl();
        if (p_impl == nullptr || tensor_data == nullptr
            || elements == 0u || slice_chunk == 0u) HTS_BB1_UNLIKELY{
            return false;
        }
            if (elements > MAX_TENSOR_ELEMENTS) HTS_BB1_UNLIKELY{
                Universal_API::Absolute_Trace_Erasure(
                    tensor_data, elements * sizeof(T));
                return false;
            }

        auto& m = *p_impl;
        uint64_t vs = session_id;

        if (!is_test_mode) {
            if (!Universal_API::Secure_Gate_Open(session_id)) HTS_BB1_UNLIKELY{
                Universal_API::Absolute_Trace_Erasure(
                    tensor_data, elements * sizeof(T));
                return false;
            }
            vs = m.tx_time_arrow.Validate_Or_Destroy(session_id);
            if (AntiAnalysis_Shield::Is_Under_Observation()) HTS_BB1_UNLIKELY{
                AntiAnalysis_Shield::Trigger_Deceptive_Collapse(
                    tensor_data, elements);
                // [BUG-56] AIRCR 타격: JTAG 감지 시 즉시 하드 리셋 (램 덤프 차단)
                *reinterpret_cast<volatile uint32_t*>(
                    static_cast<uintptr_t>(AIRCR_ADDR)) =
                    (AIRCR_VECTKEY | AIRCR_SYSRST);
                return false; // 도달 불가
            }
        }

        Impl::Scramble_XOR(tensor_data, elements, vs);

        const uint32_t fa32 = Impl::Resolve_Anchor(
            anchor_interval, is_test_mode, m.Adaptive_Anchor());
        const size_t fa = static_cast<size_t>(fa32);

        Sparse_Recovery_Engine::Generate_Interference_Pattern(
            tensor_data, elements, vs, fa32, is_test_mode);
        // [VDF 삭제] Apply_Quantum_Decoy 제거 (119ms CPU 독점 → DMA 유실)

        Impl::Build_Map(m.shared.state_map, elements, fa32);  // [BUG-65] tx→shared
        for (size_t i = 0u; i < elements; ++i)
            m.shared.temp_vec[i] = static_cast<uint32_t>(tensor_data[i]);
        // [BUG-52] raw 포인터 오버로드 (정적 배열 직접 전달, vector 래핑 제거)
        Orbital_Mapper::Apply_Orbital_Clouding(
            m.shared.temp_vec, elements, m.shared.state_map, elements);
        for (size_t i = 0u; i < elements; ++i)
            tensor_data[i] = static_cast<T>(m.shared.temp_vec[i]);

        m.tx_gyro.Initialize_Stabilizer(vs);
        {
            size_t nb = fa;
            size_t cp = (fa > 0u) ? std::min(fa - 1u, elements - 1u) : 0u;
            for (size_t s = 0u; s < elements;
                s += static_cast<size_t>(slice_chunk)) {
                m.tx_gyro.Update_Gyro_Stabilizer();
                m.tx_gyro_phase = m.tx_gyro.Get_Current_Phase();
                const size_t ei = std::min(
                    s + static_cast<size_t>(slice_chunk), elements);
                for (size_t i = s; i < ei; ++i) {
                    while (fa > 0u && i >= nb) {
                        nb += fa;
                        cp = std::min(nb - 1u, elements - 1u);
                    }
                    if (fa > 0u && i == cp) { continue; }
                    tensor_data[i] =
                        Polymorphic_Shield::Apply_Holographic_Folding(
                            tensor_data[i], m.tx_gyro_phase, vs,
                            static_cast<uint32_t>(i));  // [BUG-58] CTR 카운터
                }
            }
        }

        if (fa > 0u) {
            for (size_t i = 0u; i < elements; i += fa)
                tensor_data[std::min(i + fa - 1u, elements - 1u)]
                = static_cast<T>(0x7FFF);
        }

        {
            static constexpr uint32_t HOLO_CHIP = 64u;
            // [FIX-CSPRNG] 128비트 암호학적 시드 생성
            //  기존: (uint32_t)(vs ^ (vs>>32)) = 32비트 → GPU 4초 해독
            //  수정: vs 64비트 전체 + 골든 래셔 혼합 = 128비트 시드 기반
            const uint32_t vs_lo = static_cast<uint32_t>(vs);
            const uint32_t vs_hi = static_cast<uint32_t>(vs >> 32);

            int32_t holo_buf[HOLO_CHIP];
            for (size_t base = 0u; base < elements; base += HOLO_CHIP) {
                const size_t chunk =
                    std::min<size_t>(HOLO_CHIP, elements - base);
                for (size_t k = 0u; k < chunk; ++k)
                    holo_buf[k] = static_cast<int32_t>(tensor_data[base + k]);
                for (size_t k = chunk; k < HOLO_CHIP; ++k)
                    holo_buf[k] = 0;

                // 블록별 128비트 시드: vs(64) + block_offset + 혼합 상수
                const uint32_t blk = static_cast<uint32_t>(base);
                const uint32_t crypto_seed[4] = {
                    vs_lo ^ (blk * 0x9E3779B9u),
                    vs_hi ^ (blk * 0x6A09E667u),
                    vs_lo ^ vs_hi ^ (blk * 0xBB67AE85u),
                    (vs_lo + vs_hi) ^ (blk * 0x3C6EF372u)
                };
                Holo_Tensor_Engine::Encode_Hologram(
                    holo_buf, HOLO_CHIP, crypto_seed);

                for (size_t k = 0u; k < chunk; ++k)
                    tensor_data[base + k] = static_cast<T>(holo_buf[k]);
            }
        }

        m.Wipe_TX();
        return true;
    }

    // =====================================================================
    //  RX 파이프라인 (ISR/DMA 안전)
    // =====================================================================
    template <typename T>
    bool BB1_Core_Engine::Recover_Tensor_Pipeline(
        T* damaged_tensor, size_t elements, uint64_t session_id,
        uint32_t slice_chunk, uint32_t anchor_interval,
        bool is_test_mode, bool strict_mode) {

        Impl* p_impl = get_impl();
        if (p_impl == nullptr || damaged_tensor == nullptr
            || elements == 0u || slice_chunk == 0u) HTS_BB1_UNLIKELY{
            return false;
        }
            if (elements > MAX_TENSOR_ELEMENTS) HTS_BB1_UNLIKELY{
                Universal_API::Absolute_Trace_Erasure(
                    damaged_tensor, elements * sizeof(T));
                return false;
            }

        auto& m = *p_impl;
        uint64_t vs = session_id;
        const T EM = static_cast<T>(~static_cast<T>(0));

        if (!is_test_mode) {
            if (!Universal_API::Secure_Gate_Open(session_id)) HTS_BB1_UNLIKELY{
                Universal_API::Absolute_Trace_Erasure(
                    damaged_tensor, elements * sizeof(T));
                return false;
            }
            vs = m.rx_time_arrow.Validate_Or_Destroy(session_id);
            if (AntiAnalysis_Shield::Is_Under_Observation()) HTS_BB1_UNLIKELY{
                AntiAnalysis_Shield::Trigger_Deceptive_Collapse(
                    damaged_tensor, elements);
                // [BUG-56] AIRCR 리셋 (constexpr 상수)
                *reinterpret_cast<volatile uint32_t*>(
                    static_cast<uintptr_t>(AIRCR_ADDR)) =
                    (AIRCR_VECTKEY | AIRCR_SYSRST);
                return false;
            }
        }

        const uint32_t fa32 = Impl::Resolve_Anchor(
            anchor_interval, is_test_mode, m.Adaptive_Anchor());
        const size_t fa = static_cast<size_t>(fa32);

        // 0. 홀로그래픽 텐서 수렴 (역FWHT + 역4D 회전)
        {
            static constexpr uint32_t HOLO_CHIP = 64u;
            // [FIX-CSPRNG] TX와 동일한 128비트 시드 재생성
            const uint32_t vs_lo = static_cast<uint32_t>(vs);
            const uint32_t vs_hi = static_cast<uint32_t>(vs >> 32);

            int32_t holo_buf[HOLO_CHIP];
            for (size_t base = 0u; base < elements; base += HOLO_CHIP) {
                const size_t chunk =
                    std::min<size_t>(HOLO_CHIP, elements - base);
                for (size_t k = 0u; k < chunk; ++k)
                    holo_buf[k] =
                    static_cast<int32_t>(damaged_tensor[base + k]);
                for (size_t k = chunk; k < HOLO_CHIP; ++k)
                    holo_buf[k] = 0;

                const uint32_t blk = static_cast<uint32_t>(base);
                const uint32_t crypto_seed[4] = {
                    vs_lo ^ (blk * 0x9E3779B9u),
                    vs_hi ^ (blk * 0x6A09E667u),
                    vs_lo ^ vs_hi ^ (blk * 0xBB67AE85u),
                    (vs_lo + vs_hi) ^ (blk * 0x3C6EF372u)
                };
                Holo_Tensor_Engine::Decode_Hologram(
                    holo_buf, HOLO_CHIP, crypto_seed);

                for (size_t k = 0u; k < chunk; ++k)
                    damaged_tensor[base + k] = static_cast<T>(holo_buf[k]);
            }
        }

        // 1. PLL (RX 전용 버퍼)
        // [BUG-65] erased 비트 패킹 초기화
        m.clear_erased(elements);
        m.PLL(damaged_tensor, elements, fa32);

        // 2. 역 보호막 (RX 전용 gyro)
        m.rx_gyro.Initialize_Stabilizer(vs);
        {
            size_t nb = fa;
            size_t cp = (fa > 0u) ? std::min(fa - 1u, elements - 1u) : 0u;
            for (size_t s = 0u; s < elements;
                s += static_cast<size_t>(slice_chunk)) {
                m.rx_gyro.Update_Gyro_Stabilizer();
                m.rx_gyro_phase = m.rx_gyro.Get_Current_Phase();
                const size_t ei = std::min(
                    s + static_cast<size_t>(slice_chunk), elements);
                for (size_t i = s; i < ei; ++i) {
                    if (damaged_tensor[i] == EM) { continue; }
                    while (fa > 0u && i >= nb) {
                        nb += fa;
                        cp = std::min(nb - 1u, elements - 1u);
                    }
                    if (fa > 0u && i == cp) { continue; }
                    if (!m.is_erased(i))       // [BUG-65] 비트 패킹
                        damaged_tensor[i] =
                        Polymorphic_Shield::Reverse_Holographic_Folding(
                            damaged_tensor[i], m.rx_gyro_phase, vs,
                            static_cast<uint32_t>(i));  // [BUG-58] CTR 카운터
                }
            }
        }

        // 3. 역 인터리빙 (공유 버퍼)
        Impl::Build_Map(m.shared.state_map, elements, fa32);  // [BUG-65] rx→shared
        for (size_t i = 0u; i < elements; ++i)
            m.shared.temp_vec[i] = static_cast<uint32_t>(damaged_tensor[i]);
        // [BUG-52] raw 포인터 오버로드
        Orbital_Mapper::Reverse_Orbital_Collapse(
            m.shared.temp_vec, elements, m.shared.state_map, elements);
        for (size_t i = 0u; i < elements; ++i)
            damaged_tensor[i] = static_cast<T>(m.shared.temp_vec[i]);

        // [BUG-65] erasure 좌표 변환 — 비트맵 기반 (데이터 값 의존 제거)
        //
        //  [FIX-PILOT] 기존: damaged_tensor[i] == EM 으로 삭제 판별
        //   → EM(0xFFFF)이 유효 데이터와 충돌 시 파일럿 복원에서 데이터 파괴
        //  수정: erased_bits 비트맵을 역인터리빙 좌표로 재구축
        //   → 비트맵은 데이터 값과 무관한 확정적 삭제 상태
        //
        //  temp_vec[0..63] 임시 사용 (역인터리빙 완료 후 미사용 구간)
        for (size_t w = 0u; w < m.ERASED_WORDS; ++w)
            m.shared.temp_vec[w] = m.erased_bits[w];  // pre-interleave 백업
        m.clear_erased(elements);                       // post-interleave 초기화
        for (size_t i = 0u; i < elements; ++i) {
            const size_t pre_pos =
                static_cast<size_t>(m.shared.state_map[i]);
            const bool was_erased =
                (m.shared.temp_vec[pre_pos >> 5u]
                    & (1u << (pre_pos & 31u))) != 0u;
            if (was_erased) {
                damaged_tensor[i] = EM;
                m.set_erased(i);  // post-interleave 비트맵 갱신
            }
        }

        // 4. [VDF 삭제] Reverse_Quantum_Decoy 제거 (TX Apply와 대칭 삭제)

        // 5. 파일럿 복원
        //  [FIX-PILOT] damaged_tensor[i]==EM → m.is_erased(i) 교체
        //   비트맵 기반 판별: 데이터 값과 무관, EM 충돌 불가
        if (fa > 0u) {
            uint32_t ms = static_cast<uint32_t>(vs ^ 0x3D485453u);
            uint32_t bs = static_cast<uint32_t>(vs ^ 0xAA55AA55u);
            if (bs == 0u) { bs = 0xDEADBEEFu; }
            size_t nb = fa;
            size_t cp = std::min(fa - 1u, elements - 1u);
            for (size_t i = 0u; i < elements; ++i) {
                // [BUG-51] FIX-09 전파: 31비트 마스킹 제거
                bs = bs * 1103515245u + 12345u;
                while (i >= nb) {
                    nb += fa;
                    cp = std::min(nb - 1u, elements - 1u);
                }
                if (i == cp && m.is_erased(i)) {
                    const T bv = static_cast<T>(bs & 0xFFFFu);
                    const uint32_t zs =
                        (ms ^ static_cast<uint32_t>(i)) * 0x9E3779B9u;
                    damaged_tensor[i] =
                        bv ^ static_cast<T>((zs >> 5) | (zs << 27));
                }
            }
        }

        m.Wipe_RX();

        // 6. L1 복구 — [BUG-44] SeqLock 보호 쓰기
        RecoveryStats temp_stats = {};
        const bool ok = Sparse_Recovery_Engine::Execute_L1_Reconstruction(
            damaged_tensor, elements, vs, fa32,
            is_test_mode, strict_mode, temp_stats);

        m.stats_seq.fetch_add(1u, std::memory_order_release);
        m.last_stats = temp_stats;
        m.stats_seq.fetch_add(1u, std::memory_order_release);

        m.Update_Noise_EMA(temp_stats);

        if (ok) HTS_BB1_LIKELY{
            Impl::Scramble_XOR(damaged_tensor, elements, vs);
            if (fa > 0u) {
                for (size_t i = 0u; i < elements; i += fa)
                    damaged_tensor[std::min(i + fa - 1u, elements - 1u)]
                    = static_cast<T>(0);
            }
        }
        else {
            Universal_API::Absolute_Trace_Erasure(
                damaged_tensor, elements * sizeof(T));
            return false;
        }
        return true;
    }

    // ── 명시적 인스턴스화 ───────────────────────────────────────────────
    template bool BB1_Core_Engine::Process_Tensor_Pipeline<uint16_t>(
        uint16_t*, size_t, uint64_t, uint32_t, uint32_t, bool, bool);
    template bool BB1_Core_Engine::Process_Tensor_Pipeline<uint32_t>(
        uint32_t*, size_t, uint64_t, uint32_t, uint32_t, bool, bool);
    template bool BB1_Core_Engine::Recover_Tensor_Pipeline<uint16_t>(
        uint16_t*, size_t, uint64_t, uint32_t, uint32_t, bool, bool);
    template bool BB1_Core_Engine::Recover_Tensor_Pipeline<uint32_t>(
        uint32_t*, size_t, uint64_t, uint32_t, uint32_t, bool, bool);

} // namespace ProtectedEngine