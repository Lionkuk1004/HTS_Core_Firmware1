#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
#define HTS_LIKELY   [[likely]]
#define HTS_UNLIKELY [[unlikely]]
#else
#define HTS_LIKELY
#define HTS_UNLIKELY
#endif
// =========================================================================
// BB1_Core_Engine.cpp
// HTS 최상위 코어 엔진 구현부 (Pimpl 은닉)
// Target: STM32F407VGT6 (Cortex-M4F, 168MHz)
//         Flash 1MB / SRAM 192KB (112KB+16KB CCM+64KB 보조)
//
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
#include <algorithm>
#include <type_traits>

#include "HTS_Gyro_Engine.h"
#include "HTS_Entropy_Arrow.hpp"
#include "HTS_Hardware_Shield.h"
#include "HTS_Physical_Entropy_Engine.h"
#include "HTS_Polymorphic_Shield.h"
#include "HTS_Universal_API.h"
#include "HTS_AntiAnalysis_Shield.h"
// Quantum Decoy VDF 미연동 — BB1은 Walsh·암호·Polymorphic_Shield 경로
#include "HTS_Orbital_Mapper.hpp"
#include "HTS_Sparse_Recovery.h"
#include "HTS_Holo_Tensor_Engine.h"
#include "HTS_Secure_Memory.h"

// =========================================================================
//  프로젝트 표준 패턴 (HTS_Universal_Adapter, HTS_Entropy_Arrow 등과 통일)
// =========================================================================
#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
#define HTS_BB1_UNLIKELY HTS_UNLIKELY
#define HTS_BB1_LIKELY   HTS_LIKELY
#else
#define HTS_BB1_UNLIKELY
#define HTS_BB1_LIKELY
#endif

namespace ProtectedEngine {

    // ── 보안 메모리 소거 ─────────────────────────────────────────────
    // SecureMemory::secureWipe — volatile 바이트 스토어 + 배리어 (LTO/DCE 안전)
    static void Secure_Wipe_BB1(void* ptr, size_t size) noexcept {
        SecureMemory::secureWipe(ptr, size);
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

    // shared: state_map(8KB) + temp_vec(8KB) = 16KB (TX/RX 반이중 공유)
    // rx_only: erased_bits(256B) — 비트 패킹 (uint8_t[2048] → uint32_t[64])
    // erasure_idx: 완전 제거 (2-pass → 1-pass 인라인)
    // 합계: 32.5KB 정적 배열
    static constexpr size_t BB1_STATIC_ARRAYS =
        MAX_TENSOR_ELEMENTS * sizeof(uint32_t) * 2   // state_map + temp_vec (공유)
        + (MAX_TENSOR_ELEMENTS / 32u) * sizeof(uint32_t);  // erased_bits

    static_assert(BB1_STATIC_ARRAYS < 37u * 1024u,
        "BB1 static arrays exceed 37KB SRAM budget");

    //  MAX_TENSOR_ELEMENTS << 16 이 UINT32_MAX를 초과하면 빌드 실패
    //  향후 MAX_TENSOR_ELEMENTS 증가 시 주석이 아닌 빌드 에러로 즉시 검출
    static_assert(
        static_cast<uint64_t>(MAX_TENSOR_ELEMENTS) << 16u
        <= static_cast<uint64_t>(UINT32_MAX),
        "MAX_TENSOR_ELEMENTS << 16이 uint32_t 범위를 초과합니다 — noise_to_q16 수정 필요");

    // ── ARM Cortex-M AIRCR 리셋 상수 (J-3 매직넘버 상수화) ─────────────
    // Application Interrupt and Reset Control Register
    // ARM Architecture Reference Manual (DDI0403E) §B3.2.6
    static constexpr uintptr_t AIRCR_ADDR = 0xE000ED0Cu;  // AIRCR 레지스터 주소
    static constexpr uint32_t  AIRCR_VECTKEY = 0x05FA0000u;  // 쓰기 허가 키
    static constexpr uint32_t  AIRCR_SYSRST = 0x04u;        // SYSRESETREQ 비트

    // ── Holo_Tensor_Engine(64): Encode가 입력을 Max_Safe_Amplitude로 클램프 —
    //    uint16_t는 단일 int32 레인으로 무손실(상위 비트 0).
    //    uint32_t→int32_t 단순 캐스트는 상위 값에서 UB/랩어라운드 → Holo 한계로 선클램프.
    // ── 출력: int32_t→T 잘림 대신 [0..max(T)] 명시 클램프(복구율 보존).
    template <typename T>
    static int32_t BB1_Holo_Tensor_To_I32(T v) noexcept {
        static constexpr uint32_t HOLO_N = 64u;
        const int32_t mx = Holo_Tensor_Engine::Max_Safe_Amplitude(HOLO_N);
        if constexpr (std::is_same_v<T, uint16_t>) {
            (void)mx;
            return static_cast<int32_t>(v);
        } else {
            static_assert(std::is_same_v<T, uint32_t>, "BB1 Holo T must be uint16_t or uint32_t");
            const uint64_t w = static_cast<uint64_t>(v);
            const uint64_t mu = static_cast<uint64_t>(static_cast<uint32_t>(mx));
            if (w > mu) {
                return mx;
            }
            return static_cast<int32_t>(static_cast<uint32_t>(w));
        }
    }

    template <typename T>
    static T BB1_I32_To_Holo_Tensor(int32_t v) noexcept {
        if constexpr (std::is_same_v<T, uint16_t>) {
            if (v < 0) {
                return static_cast<uint16_t>(0u);
            }
            if (v > 65535) {
                return static_cast<uint16_t>(65535u);
            }
            return static_cast<uint16_t>(static_cast<uint32_t>(v));
        } else {
            static_assert(std::is_same_v<T, uint32_t>, "BB1 Holo T must be uint16_t or uint32_t");
            if (v < 0) {
                return static_cast<uint32_t>(0u);
            }
            return static_cast<uint32_t>(v);
        }
    }

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
    [[noreturn]] static void BB1_Pipeline_Bad_Context_Reset() noexcept {
        *reinterpret_cast<volatile uint32_t*>(AIRCR_ADDR) =
            AIRCR_VECTKEY | AIRCR_SYSRST;
        for (;;) {
            __asm__ __volatile__("" ::: "memory");
            __asm__ __volatile__("wfi");
        }
    }

    static void BB1_Assert_Pipeline_Call_Context() noexcept {
        uint32_t primask_val = 0u;
        uint32_t ipsr_val = 0u;
        __asm__ __volatile__(
            "mrs %0, primask\n\t"
            "mrs %1, ipsr"
            : "=r"(primask_val), "=r"(ipsr_val)
            :: "memory");
        if (primask_val != 0u || ipsr_val != 0u) {
            BB1_Pipeline_Bad_Context_Reset();
        }
    }
#endif

    //   (uint64_t)(destroyed) << 16 / total → __aeabi_uldivmod 100+cyc
    //   (uint32_t)(destroyed) << 16 / (uint32_t)total → UDIV 2~12cyc
    //   안전 증명: static_assert로 컴파일 타임 보장
    static int32_t noise_to_q16(size_t destroyed, size_t total) noexcept {
        if (total == 0u || destroyed == 0u) return 0;
        if (destroyed >= total) return Q16_ONE;
        const uint32_t d32 = static_cast<uint32_t>(destroyed);
        const uint32_t t32 = static_cast<uint32_t>(total);
        return static_cast<int32_t>((d32 << 16u) / t32);
    }

    // =====================================================================
    //
    //  vector<T> 6개 + Reserve_Buffers(resize) → 데드코드
    //   · -fno-exceptions에서 resize OOM = std::terminate 즉시 → 반환값 검사 도달 불가
    //   · "방어 코드처럼 보이지만 실제 보호 효과 0"인 거짓 안전 패턴
    //
    //  MAX_TENSOR_ELEMENTS(2048) 컴파일 타임 상수 → 정적 배열
    //   · sizeof(Impl) ≈ 17KB → IMPL_BUF_SIZE = 20480 (20KB)
    //   · 힙 할당 0회 → OOM 경로 자체가 존재하지 않음
    //   · SRAM 예산 내 정적 배열 (힙 경로 없음)
    //
    //  ⚠ BB1_Core_Engine은 반드시 전역/정적 변수로 배치할 것
    //    스택에 놓으면 ~80KB 스택 소모 → ARM 스택 오버플로우
    // =====================================================================
    struct BB1_Core_Engine::Impl {

        // ── TX/RX 공유 버퍼 (반이중 → 동시 접근 불가) ───────────────
        //  Build_Map → state_map 생성, 매 호출 시 재생성
        //  temp_vec: 인터리빙/역인터리빙 스크래치
        //  TX/RX 순차 실행 → 1개로 공유 (−32KB)
        struct {
            mutable uint32_t state_map[MAX_TENSOR_ELEMENTS] = {};
            mutable uint32_t temp_vec[MAX_TENSOR_ELEMENTS] = {};
        } shared = {};

        // ── TX 전용 상태 (경량) ──────────────────────────────────
        Gyro_Engine            tx_gyro;
        uint32_t               tx_gyro_phase = 0;
        Entropy_Time_Arrow     tx_time_arrow = Entropy_Time_Arrow(3600000u);  // 1h (ms)

        // ── RX 전용 상태 (경량) ──────────────────────────────────
        static constexpr size_t ERASED_WORDS = MAX_TENSOR_ELEMENTS / 32u;
        mutable uint32_t erased_bits[ERASED_WORDS] = {};

        Gyro_Engine            rx_gyro;
        uint32_t               rx_gyro_phase = 0;
        Entropy_Time_Arrow     rx_time_arrow = Entropy_Time_Arrow(3600000u);  // 1h (ms)

        // ── erased 비트 접근 헬퍼 (인라인, 분기 0개) ───────────────
        void set_erased(size_t idx) noexcept {
            erased_bits[idx >> 5u] |= (1u << (idx & 31u));
        }
        bool is_erased(size_t idx) const noexcept {
            return (erased_bits[idx >> 5u] & (1u << (idx & 31u))) != 0u;
        }
        void clear_erased(size_t n) const noexcept {
            const size_t words = (n + 31u) >> 5u;
            std::memset(erased_bits, 0, words * sizeof(uint32_t));
        }

        // ── 공유 (Lock-free) ────────────────────────────────────
        std::atomic<uint32_t>  stats_seq{ 0 };
        RecoveryStats          last_stats = {};
        std::atomic<int32_t>   moving_avg_noise_q16{ 0 };

        //  정적 배열 → 생성자에서 placement new만으로 초기화 완료
        //  OOM 경로 자체가 소멸 → 데드코드 0, 거짓 안전 패턴 0

        // ── 궤적 소거 (고정 크기 — 조건 분기 없음) ────────────────
        void Wipe_Shared() const noexcept {
            Secure_Wipe_BB1(shared.state_map, sizeof(shared.state_map));
            Secure_Wipe_BB1(shared.temp_vec, sizeof(shared.temp_vec));
        }
        void Wipe_TX() const noexcept {
            Wipe_Shared();
        }
        void Wipe_RX() const noexcept {
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

        // ── LCG 스크램블 (31비트 마스킹 제거) ───────────────────────
        // & 0x7FFFFFFFu → MSB 항상 0 → XOR bit-15 항상 0 노출
        // uint32_t 자연 오버플로우 → 32비트 전 영역 엔트로피 활용
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

        // ── PLL (erased 비트 패킹) ───────────────────────────────
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
                set_erased(p);             // 비트 패킹
                data[p] = EM;
                for (size_t i = b; i < p; ++i) {
                    if (data[i] == EM) { set_erased(i); }  // 비트 패킹
                    else if (bi) {
                        data[i] = static_cast<T>(
                            static_cast<T>(~data[i]) + static_cast<T>(1));
                    }
                }
                ph = bi;
            }
        }

        // ── 인터리버 상태맵: % → 뺄셈 강도 절감 ───────────────────
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

        // ── CAS Lock-free EMA 갱신 (double 완전 제거) ─────────────
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
    // =====================================================================
    BB1_Core_Engine::Impl* BB1_Core_Engine::get_impl() noexcept {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
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
    //
    //  Reserve_Buffers(resize) → 실패 검사 → 데드코드
    //   · -fno-exceptions에서 resize OOM = std::terminate 즉시 호출
    //   · 반환값 검사 코드는 도달 불가 → 거짓 안전 패턴
    //
    //  정적 배열 → 힙 할당 0회 → OOM 경로 자체가 존재하지 않음
    //   · Secure_Wipe_BB1 + placement new = 초기화 완료
    //   · 실패 경로 0개, 분기 0개, 완벽하게 결정론적
    // =====================================================================
    BB1_Core_Engine::BB1_Core_Engine() noexcept : impl_valid_(false) {
        Secure_Wipe_BB1(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl();
        impl_valid_ = true;
    }

    // =====================================================================
    // =====================================================================
    BB1_Core_Engine::~BB1_Core_Engine() noexcept {
        Impl* p = get_impl();
        if (p != nullptr) { p->~Impl(); }
        Secure_Wipe_BB1(impl_buf_, sizeof(impl_buf_));
        impl_valid_ = false;
    }

    // =====================================================================
    // =====================================================================
    RecoveryStats BB1_Core_Engine::Get_Last_Recovery_Stats() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) HTS_BB1_UNLIKELY{ return RecoveryStats{}; }
        RecoveryStats copy;
        uint32_t seq = 0;
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

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
        BB1_Assert_Pipeline_Call_Context();
#endif

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
        // Apply_Quantum_Decoy 미호출 (Sparse/Orbital 경로)

        Impl::Build_Map(m.shared.state_map, elements, fa32);  // tx→shared
        for (size_t i = 0u; i < elements; ++i)
            m.shared.temp_vec[i] = static_cast<uint32_t>(tensor_data[i]);
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
                            static_cast<uint32_t>(i));  // CTR 카운터
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
            //  (uint32_t)(vs ^ (vs>>32)) = 32비트 → GPU 4초 해독
            //  vs 64비트 전체 + 골든 래셔 혼합 = 128비트 시드 기반
            const uint32_t vs_lo = static_cast<uint32_t>(vs);
            const uint32_t vs_hi = static_cast<uint32_t>(vs >> 32);

            int32_t holo_buf[HOLO_CHIP] = {};
            for (size_t base = 0u; base < elements; base += HOLO_CHIP) {
                const size_t chunk =
                    std::min<size_t>(HOLO_CHIP, elements - base);
                for (size_t k = 0u; k < chunk; ++k) {
                    holo_buf[k] = BB1_Holo_Tensor_To_I32(tensor_data[base + k]);
                }
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

                for (size_t k = 0u; k < chunk; ++k) {
                    tensor_data[base + k] = BB1_I32_To_Holo_Tensor<T>(holo_buf[k]);
                }
            }
        }

        m.Wipe_TX();
        return true;
    }

    // =====================================================================
    //  RX 파이프라인 (메인 루프 전용 — PRIMASK/ISR에서 호출 시 AIRCR 리셋)
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

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
        BB1_Assert_Pipeline_Call_Context();
#endif

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
            const uint32_t vs_lo = static_cast<uint32_t>(vs);
            const uint32_t vs_hi = static_cast<uint32_t>(vs >> 32);

            int32_t holo_buf[HOLO_CHIP] = {};
            for (size_t base = 0u; base < elements; base += HOLO_CHIP) {
                const size_t chunk =
                    std::min<size_t>(HOLO_CHIP, elements - base);
                for (size_t k = 0u; k < chunk; ++k) {
                    holo_buf[k] = BB1_Holo_Tensor_To_I32(damaged_tensor[base + k]);
                }
                for (size_t k = chunk; k < HOLO_CHIP; ++k)
                    holo_buf[k] = 0;

                const uint32_t blk = static_cast<uint32_t>(base);
                const uint32_t crypto_seed[4] = {
                    vs_lo ^ (blk * 0x9E3779B9u),
                    vs_hi ^ (blk * 0x6A09E667u),
                    vs_lo ^ vs_hi ^ (blk * 0xBB67AE85u),
                    (vs_lo + vs_hi) ^ (blk * 0x3C6EF372u)
                };
                const uint32_t holo_dec = Holo_Tensor_Engine::Decode_Hologram(
                    holo_buf, HOLO_CHIP, crypto_seed);
                if (holo_dec != Holo_Tensor_Engine::SECURE_TRUE) {
                    SecureMemory::secureWipe(
                        static_cast<void*>(holo_buf), sizeof(holo_buf));
                    Universal_API::Absolute_Trace_Erasure(
                        damaged_tensor, elements * sizeof(T));
                    return false;
                }

                for (size_t k = 0u; k < chunk; ++k) {
                    damaged_tensor[base + k] = BB1_I32_To_Holo_Tensor<T>(holo_buf[k]);
                }
            }
        }

        // 1. PLL (RX 전용 버퍼)
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
                    if (!m.is_erased(i))       // 비트 패킹
                        damaged_tensor[i] =
                        Polymorphic_Shield::Reverse_Holographic_Folding(
                            damaged_tensor[i], m.rx_gyro_phase, vs,
                            static_cast<uint32_t>(i));  // CTR 카운터
                }
            }
        }

        // 3. 역 인터리빙 (공유 버퍼)
        Impl::Build_Map(m.shared.state_map, elements, fa32);  // rx→shared
        for (size_t i = 0u; i < elements; ++i)
            m.shared.temp_vec[i] = static_cast<uint32_t>(damaged_tensor[i]);
        Orbital_Mapper::Reverse_Orbital_Collapse(
            m.shared.temp_vec, elements, m.shared.state_map, elements);
        for (size_t i = 0u; i < elements; ++i)
            damaged_tensor[i] = static_cast<T>(m.shared.temp_vec[i]);

        //
        //   → EM(0xFFFF)이 유효 데이터와 충돌 시 파일럿 복원에서 데이터 파괴
        //  erased_bits 비트맵을 역인터리빙 좌표로 재구축
        //   → 비트맵은 데이터 값과 무관한 확정적 삭제 상태
        //
        //  temp_vec[0..63] 임시 사용 (역인터리빙 완료 후 미사용 구간)
        for (size_t w = 0u; w < m.ERASED_WORDS; ++w)
            m.shared.temp_vec[w] = m.erased_bits[w];  // pre-interleave 백업
        m.clear_erased(elements);                       // post-interleave 초기화
        for (size_t i = 0u; i < elements; ++i) {
            const size_t pre_pos =
                static_cast<size_t>(m.shared.state_map[i]);
            // fail-closed: state_map 오염 시 OOB 접근 차단
            if (pre_pos >= elements) {
                m.Wipe_RX();
                Universal_API::Absolute_Trace_Erasure(
                    damaged_tensor, elements * sizeof(T));
                return false;
            }
            const bool was_erased =
                (m.shared.temp_vec[pre_pos >> 5u]
                    & (1u << (pre_pos & 31u))) != 0u;
            if (was_erased) {
                damaged_tensor[i] = EM;
                m.set_erased(i);  // post-interleave 비트맵 갱신
            }
        }

        // Reverse_Quantum_Decoy 미호출 — Sparse L1 복구만 진행

        m.Wipe_RX();

        // 6. L1 복구 — SeqLock 보호 쓰기
        RecoveryStats temp_stats = {};
        const bool ok = Sparse_Recovery_Engine::Execute_L1_Reconstruction(
            damaged_tensor, elements, vs, fa32,
            is_test_mode, strict_mode, temp_stats);

        //  release만 → 데이터 쓰기(B)가 시퀀스 증가(A) 위로 재배치 가능
        //        → Reader가 짝수 seq 보고 안전 판단 → 반쯤 쓰인 데이터 읽기(Tearing)
        //  acq_rel → acquire가 (B)의 상방 재배치 차단
        //        release가 이전 연산의 하방 재배치 차단 → 완전한 SeqLock 성립
        //
        //  (A) seq++ [acq_rel] — 데이터 쓰기가 여기 위로 올라갈 수 없음
        //  (B) last_stats = temp_stats — 데이터 쓰기
        //  (C) seq++ [release]  — 데이터 쓰기가 여기 아래로 내려갈 수 없음
        m.stats_seq.fetch_add(1u, std::memory_order_acq_rel);
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
