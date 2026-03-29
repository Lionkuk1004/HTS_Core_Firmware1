// =========================================================================
// HTS_Dual_Tensor_16bit.cpp
// B-CDMA 듀얼 레인 텐서 파이프라인 구현부 (Pimpl 은닉)
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// [양산 수정 이력 — 21건]
//  BUG-01~13 (이전 세션)
//  BUG-14 [CRIT] unique_ptr → placement new (zero-heap Pimpl)
//  BUG-15 [CRIT] Impl 생성자 try-catch 제거 (-fno-exceptions)
//         · try { reserve } catch → 완전 삭제
//         · -fno-exceptions에서 reserve OOM = std::terminate (방어 불가)
//  BUG-16 [CRIT] Execute try-catch 래퍼 완전 제거 (-fno-exceptions)
//         · noexcept 함수 내 try-catch = 의미 모순
//         · -fno-exceptions에서 catch 블록 도달 불가 (데드코드)
//  BUG-17 [CRIT] dual_lane_buffer vector → 정적 배열 (Zero-Heap)
//         · MAX_DL_FRAME=4096 (BB1/Unified_Scheduler 일치)
//         · reserve/resize 힙 할당 완전 제거
//         · dl_len_ 멤버로 유효 길이 추적
//  BUG-18 [HIGH] Secure_Wipe seq_cst → release (배리어 정책 통일)
//         · HTS_Secure_Memory.cpp 프로젝트 표준 통일
//  BUG-19 [HIGH] Get_Master_Seed → Get_Master_Seed_Raw (BUG-29 마이그레이션)
//         · vector 힙 할당 2곳 → 고정 배열 memcpy 직접 복사
//         · ARM: 힙 0회, PC: 힙 0회
//  BUG-20 [MED]  Execute 내부 로컬 vector 7개 → [PENDING] 외부 API 의존
//         · raw_bit_stream, fec_tensor, interleaved_tensor: 3D_Tensor_FEC API
//         · temp_sec_buffer, temp_tx_signal: Gaussian_Pulse/Security_Pipeline API
//         · 해당 모듈 API를 raw 포인터로 전환 후 일괄 교체
//         · double 8곳: 3D_Tensor_FEC/Interleaver 고정소수점 전환 후 제거
//
// [PENDING — 외부 API 의존 항목]
//  ④ double 8곳: 3D_Tensor_FEC::Encode(), Interleaver::Interleave() 반환 타입
//  ③ vector 7곳: 위 API + Gaussian_Pulse::Apply_Pulse_Shaping_Tensor_Coupled()
//  → 해당 모듈 전수검사 시 일괄 교체 예정
// =========================================================================
#include "HTS_Dual_Tensor_16bit.h"

// ── 내부 전용 includes (헤더에 미노출 — Pimpl 은닉) ─────────────────
#include "HTS_Security_Pipeline.h"
#include "HTS_Gaussian_Pulse.h"
#include "HTS_Hardware_Auto_Scaler.h"
#include "HTS_3D_Tensor_FEC.h"
#include "HTS_Session_Gateway.hpp"

// ── Self-Contained 표준 헤더 ─────────────────────────────────────────
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
// [BUG-20] <vector> 삭제 — 정적 배열 전환 완료

#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
#include <bit>
#endif

namespace ProtectedEngine {

    // =====================================================================
    //  보안 메모리 소거 (pragma O0 + volatile + fence 3중 보호)
    //
    //  [BUG-18] memory_order_seq_cst → memory_order_release
    //   소거 = "쓰기 완료를 다른 코어에 가시화" → release 의미
    //   seq_cst DMB ISH 풀배리어 → release DMB ST 단방향 (~40cyc 절감)
    //   HTS_Secure_Memory.cpp, BB1_Core_Engine 프로젝트 표준 통일
    // =====================================================================
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC push_options
#pragma GCC optimize("O0")
#elif defined(_MSC_VER)
#pragma optimize("", off)
#endif

    static void Secure_Wipe_Buffer(void* ptr, size_t bytes) noexcept {
        if (ptr == nullptr || bytes == 0u) { return; }
        volatile unsigned char* p =
            static_cast<volatile unsigned char*>(ptr);
        for (size_t i = 0u; i < bytes; ++i) { p[i] = 0u; }
        // [BUG-18] seq_cst → release (소거 배리어 정책 통일)
        std::atomic_thread_fence(std::memory_order_release);
    }

    struct RAII_Secure_Wiper {
        void* ptr;
        size_t size;
        RAII_Secure_Wiper(void* p, size_t s) noexcept : ptr(p), size(s) {}
        ~RAII_Secure_Wiper() noexcept { Secure_Wipe_Buffer(ptr, size); }
        void update(void* p, size_t s) noexcept { ptr = p; size = s; }
        RAII_Secure_Wiper(const RAII_Secure_Wiper&) = delete;
        RAII_Secure_Wiper& operator=(const RAII_Secure_Wiper&) = delete;
        RAII_Secure_Wiper(RAII_Secure_Wiper&&) = delete;
        RAII_Secure_Wiper& operator=(RAII_Secure_Wiper&&) = delete;
    };

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC pop_options
#elif defined(_MSC_VER)
#pragma optimize("", on)
#endif

    // [BUG-05/09] 64비트 좌회전 — k=0 UB 가드 + MISRA uint32_t
    static inline uint64_t RotL64(uint64_t x, uint32_t k) noexcept {
        k &= 63u;
        if (k == 0u) { return x; }
#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
        return std::rotl(x, static_cast<int>(k));
#else
        return (x << k) | (x >> (64u - k));
#endif
    }

    // [BUG-03] C++14 호환 clamp
    static inline int32_t Safe_Clamp(
        int32_t val, int32_t lo, int32_t hi) noexcept {
        if (val < lo) { return lo; }
        if (val > hi) { return hi; }
        return val;
    }

    // =====================================================================
    //  Pimpl 구현 구조체
    //
    //  [BUG-15] try { reserve } catch 완전 삭제
    //  [BUG-17] dual_lane_buffer: vector → 정적 배열
    //  [BUG-20] 로컬 vector 5개 + double 3개 → 정적 int8_t 워킹 버퍼
    //
    //  메모리 배치 (ARM, process_len ≤ 1024):
    //    work_A[16384]:  int8_t raw_bits / interleaved (ping-pong A)
    //    work_B union:   int8_t fec_bits[16384] / int32_t tx_signal[4096] (ping-pong B)
    //    temp_sec[2560]: uint32_t (packed_len ≤ 512 + 여유)
    //    dual_lane[4096]: uint32_t DMA 출력 버퍼
    //
    //  Impl ≈ 52KB (정적, 힙 0회, 런타임 HardFault 0건)
    //  기존 런타임 힙: ~4.2MB (vector<double> × 3 = 즉사) → 완전 제거
    // =====================================================================
    struct Dual_Tensor_Pipeline::Impl {
        size_t active_tensor_count = 0;
        Gaussian_Pulse_Shaper pulse_shaper;
        Security_Pipeline     sec_pipeline;

        // [BUG-17] 출력 DMA 버퍼 (정적)
        static constexpr size_t MAX_DL_FRAME = 4096u;
        uint32_t dual_lane_buffer[MAX_DL_FRAME] = {};
        size_t   dl_len_ = 0;

        HTS_Engine::Soft_Tensor_FEC    tensor_fec_engine;
        HTS_Engine::Tensor_Interleaver tensor_interleaver;

        // ── [BUG-20] 정적 워킹 버퍼 (vector/double 완전 제거) ──
        //
        //  파이프라인 수명 분석:
        //    Stage ③: raw_bits 생성 (work_A)
        //    Stage ④: FEC Encode: work_A(입력) → work_B.fec(출력)
        //    Stage ④: Interleave: work_B.fec(입력) → work_A(출력, 재사용)
        //    Stage ④: intlv→uint32 패킹: work_A → temp_sec
        //    Stage ⑤: Pulse Shaping: temp_sec → work_B.tx_sig(재사용)
        //    Stage ⑥: Dual Lane: work_B.tx_sig + temp_sec → dual_lane_buffer
        //
        //  work_A와 fec_bits: 동시 사용 (Encode 입출력) → 분리 필수
        //  fec_bits와 tx_signal: 순차 사용 → union 가능
        //
#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
        static constexpr size_t MAX_PROCESS_LEN = 1024u;
#else
        static constexpr size_t MAX_PROCESS_LEN = 4096u;
#endif
        static constexpr size_t MAX_PACKED_LEN = (MAX_PROCESS_LEN + 1u) / 2u;

#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
        // [FIX-CRITICAL] ARM dim=26 → dim³=17,576
        //  기존 dim=16(4096) < MAX_PACKED_LEN*32(16384) → 75% 데이터 절삭
        //  dim=26 → 17,576 ≥ 16,384 → 정합 완료
        //  work 버퍼 크기도 dim³에 맞춰 확장 (16384 → 17576, +1.2KB×2)
        static constexpr size_t INTLV_DIM = 26u;
        static constexpr size_t INTLV_TOTAL = INTLV_DIM * INTLV_DIM * INTLV_DIM;  // 17,576
        static constexpr size_t MAX_RAW_BITS = MAX_PACKED_LEN * 32u;                // 16,384
        static constexpr size_t MAX_WORK_BITS =
            (MAX_RAW_BITS > INTLV_TOTAL) ? MAX_RAW_BITS : INTLV_TOTAL;             // 17,576
#else
        static constexpr size_t INTLV_DIM = 64u;
        static constexpr size_t INTLV_TOTAL = INTLV_DIM * INTLV_DIM * INTLV_DIM;  // 262,144
        static constexpr size_t MAX_RAW_BITS = MAX_PACKED_LEN * 32u;                // 65,536
        static constexpr size_t MAX_WORK_BITS =
            (MAX_RAW_BITS > INTLV_TOTAL) ? MAX_RAW_BITS : INTLV_TOTAL;
#endif
        static constexpr size_t MAX_SEC_WORDS = MAX_PACKED_LEN + 1024u;
        static constexpr size_t MAX_TX_SAMPS = MAX_DL_FRAME;

        // Ping-pong A: raw_bits → interleaved_bits (재사용)
        int8_t work_A[MAX_WORK_BITS] = {};

        // Ping-pong B: fec_bits ↔ tx_signal (수명 비중첩 union)
        union {
            int8_t  fec_bits[MAX_WORK_BITS];
            int32_t tx_signal[MAX_TX_SAMPS];
        } work_B = {};

        // Security/패킹 버퍼
        uint32_t temp_sec[MAX_SEC_WORDS] = {};

        Impl(double bt_product, size_t filter_taps) noexcept
            : active_tensor_count(0)
            , pulse_shaper(filter_taps, bt_product)
            , sec_pipeline()
            , tensor_fec_engine()
            , tensor_interleaver(INTLV_DIM)
        {
            active_tensor_count =
                Hardware_Auto_Scaler::Calculate_Optimal_Tensor_Count();
            if (active_tensor_count == 0u) { active_tensor_count = MAX_PROCESS_LEN; }
            if (active_tensor_count > MAX_PROCESS_LEN) {
                active_tensor_count = MAX_PROCESS_LEN;
            }
        }

        ~Impl() noexcept = default;
    };

    // [BUG-17] SRAM 예산 빌드 타임 검증
    //  dual_lane_buffer: 4096 × 4B = 16KB
    //  Impl 전체: 서브모듈 포인터 + 정적 배열 ≈ 17~18KB
    //  IMPL_BUF_SIZE를 증가시켜야 할 수 있음 → static_assert로 자동 검출

    // =====================================================================
    //  [BUG-14] 컴파일 타임 크기·정렬 검증 + get_impl()
    // =====================================================================
    Dual_Tensor_Pipeline::Impl* Dual_Tensor_Pipeline::get_impl() noexcept {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE를 초과합니다 — 헤더에서 IMPL_BUF_SIZE를 늘려주세요");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 요구가 impl_buf_ alignas(8)을 초과합니다");
        return impl_valid_ ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }

    const Dual_Tensor_Pipeline::Impl*
        Dual_Tensor_Pipeline::get_impl() const noexcept {
        return impl_valid_
            ? reinterpret_cast<const Impl*>(impl_buf_)
            : nullptr;
    }

    // =====================================================================
    //  [BUG-14] 생성자 — placement new (zero-heap)
    // =====================================================================
    Dual_Tensor_Pipeline::Dual_Tensor_Pipeline(
        double bt_product, size_t filter_taps) noexcept
        : impl_valid_(false)
    {
        Secure_Wipe_Buffer(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl(bt_product, filter_taps);
        impl_valid_ = true;
    }

    // =====================================================================
    //  [BUG-14] 소멸자 — 명시적 (= default 제거)
    // =====================================================================
    Dual_Tensor_Pipeline::~Dual_Tensor_Pipeline() noexcept {
        Impl* p = get_impl();
        if (p != nullptr) { p->~Impl(); }
        Secure_Wipe_Buffer(impl_buf_, sizeof(impl_buf_));
        impl_valid_ = false;
    }

    // =====================================================================
    //  Execute_Dual_Processing — 핵심 파이프라인
    //
    //  [BUG-20] vector<double> 5개 + double 8곳 → 정적 int8_t 완전 전환
    //   · raw_bit_stream(double) → work_A(int8_t): ±1만 저장, 1/8 메모리
    //   · fec_tensor(double)     → work_B.fec_bits(int8_t): Raw API
    //   · interleaved(double)    → work_A 재사용(int8_t): ping-pong
    //   · temp_sec_buffer(vec)   → temp_sec(정적 uint32_t)
    //   · temp_tx_signal(vec)    → work_B.tx_signal(union 재사용)
    //   · 힙 할당: ∞회 → 0회, double 연산: 0회
    //
    //  [BUG-16/19] try-catch/vector 힙 이전 수정사항 유지
    // =====================================================================
    bool Dual_Tensor_Pipeline::Execute_Dual_Processing(
        const uint16_t* raw_sensor_data, size_t data_len,
        uint32_t packet_nonce,
        std::atomic<bool>& abort_signal) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr || data_len == 0u || raw_sensor_data == nullptr) {
            return false;
        }

        auto& impl = *p;
        const size_t process_len =
            std::min(data_len, impl.active_tensor_count);

        // ── ❶ 민감 데이터 선언 + RAII 바인딩 ──
        uint64_t crypto_state_A = 0u;
        uint64_t crypto_state_B = 0u;
        uint32_t fec_seed = 0u;

        uint8_t fec_master_seed_buf[MAX_SEED_SIZE] = {};
        uint8_t master_seed_buf[MAX_SEED_SIZE] = {};
        size_t  fec_mseed_len = 0;
        size_t  mseed_len = 0;

        // RAII: 로컬 민감값 + Impl 워킹 버퍼 소거
        //  [BUG-20 FIX-2] vector→정적 전환 시 평문 잔류 방어
        //  work_A/B/temp_sec는 Impl 멤버이므로 함수 종료 후에도 생존
        //  → 모든 반환 경로에서 RAII로 즉시 소거 (조기 return 포함)
        RAII_Secure_Wiper wipe_fec_mseed(fec_master_seed_buf, sizeof(fec_master_seed_buf));
        RAII_Secure_Wiper wipe_master(master_seed_buf, sizeof(master_seed_buf));
        RAII_Secure_Wiper wipe_cA(&crypto_state_A, sizeof(crypto_state_A));
        RAII_Secure_Wiper wipe_cB(&crypto_state_B, sizeof(crypto_state_B));
        RAII_Secure_Wiper wipe_fseed(&fec_seed, sizeof(fec_seed));
        RAII_Secure_Wiper wipe_workA(impl.work_A, sizeof(impl.work_A));
        RAII_Secure_Wiper wipe_workB(&impl.work_B, sizeof(impl.work_B));
        RAII_Secure_Wiper wipe_tsec(impl.temp_sec, sizeof(impl.temp_sec));

        // ── ② 16비트 → 32비트 패킹 (정적 temp_sec) ──
        size_t packed_len = (process_len + 1u) / 2u;
        if (packed_len > Impl::MAX_SEC_WORDS) {
            packed_len = Impl::MAX_SEC_WORDS;
        }

        for (size_t i = 0u; i < packed_len; ++i) {
            const uint32_t high = raw_sensor_data[i * 2u];
            const uint32_t low = (i * 2u + 1u < process_len)
                ? raw_sensor_data[i * 2u + 1u] : 0x0000u;
            impl.temp_sec[i] = (high << 16u) | low;
        }

        // ── ③ Security_Pipeline 보안 변환 ──
        impl.sec_pipeline.Secure_Master_Worker(
            impl.temp_sec, 0, packed_len, abort_signal);
        if (abort_signal.load(std::memory_order_acquire)) {
            return false;
        }

        // ── ④ 3D FEC + 인터리빙 (int8_t Raw API) ──
        fec_mseed_len = Session_Gateway::Get_Master_Seed_Raw(
            fec_master_seed_buf, sizeof(fec_master_seed_buf));

        fec_seed = packet_nonce;
        if (fec_mseed_len >= 4u) {
            std::memcpy(&fec_seed, fec_master_seed_buf, 4u);
        }
        fec_seed ^= (packet_nonce << 16u) | (packet_nonce >> 16u);

        // [BUG-20] double push_back → int8_t 직접 기록
        const size_t n_raw_bits = packed_len * 32u;
        if (n_raw_bits > Impl::MAX_WORK_BITS) { return false; }

        for (size_t i = 0u; i < packed_len; ++i) {
            const uint32_t word = impl.temp_sec[i];
            for (int32_t bit = 31; bit >= 0; --bit) {
                impl.work_A[i * 32u + static_cast<size_t>(31 - bit)] =
                    ((word >> static_cast<uint32_t>(bit)) & 1u)
                    ? static_cast<int8_t>(1) : static_cast<int8_t>(-1);
            }
        }

        // [BUG-20] Encode: work_A(raw) → work_B.fec(FEC 출력)
        const size_t fec_out_max =
            (n_raw_bits < Impl::MAX_WORK_BITS) ? n_raw_bits : Impl::MAX_WORK_BITS;
        const size_t fec_len = impl.tensor_fec_engine.Encode_Raw(
            impl.work_A, n_raw_bits,
            impl.work_B.fec_bits, fec_out_max,
            fec_seed);
        if (fec_len == 0u) { return false; }

        // [BUG-20] Interleave: work_B.fec → work_A(재사용, ping-pong)
        const size_t intlv_len = impl.tensor_interleaver.Interleave_Raw(
            impl.work_B.fec_bits, fec_len,
            impl.work_A, Impl::MAX_WORK_BITS);

        // intlv(int8_t) → uint32 패킹 (temp_sec 재사용)
        const size_t interleaved_bits = intlv_len;
        const size_t fec_words = (interleaved_bits + 31u) / 32u;
        if (fec_words > Impl::MAX_SEC_WORDS) { return false; }

        for (size_t i = 0u; i < fec_words; ++i) {
            uint32_t word = 0u;
            for (int32_t bit = 0; bit < 32; ++bit) {
                const size_t idx =
                    i * 32u + static_cast<size_t>(bit);
                if (idx < interleaved_bits &&
                    impl.work_A[idx] > 0) {          // [BUG-20] > 0.0 → > 0
                    word |= (1u << (31u - static_cast<uint32_t>(bit)));
                }
            }
            impl.temp_sec[i] = word;
        }
        packed_len = fec_words;

        // ── ⑤ 펄스 셰이핑 (work_B.tx_signal 재사용) ──
        const size_t ps_out_len = packed_len * 8u + impl.pulse_shaper.Get_Num_Taps() - 1;
        const size_t ps_max =
            (ps_out_len < Impl::MAX_TX_SAMPS) ? ps_out_len : Impl::MAX_TX_SAMPS;
        std::memset(impl.work_B.tx_signal, 0, ps_max * sizeof(int32_t));
        const size_t actual_ps = impl.pulse_shaper.Apply_Pulse_Shaping_Tensor_Raw(
            impl.temp_sec, packed_len,
            impl.work_B.tx_signal, ps_max);

        const size_t tx_len = actual_ps;
        if (tx_len == 0u) { return false; }

        const size_t dl_len = (tx_len < Impl::MAX_DL_FRAME)
            ? tx_len : Impl::MAX_DL_FRAME;
        impl.dl_len_ = dl_len;

        // ── ⑥ 듀얼 레인 패킹 (Xoroshiro128++) ──
        const size_t total_16bit_words = packed_len * 2u;
        if (total_16bit_words == 0u) { return false; }

        const uint64_t PRIME_INTERLEAVER = 1000003ULL;
        const size_t logical_step = static_cast<size_t>(
            PRIME_INTERLEAVER % total_16bit_words);
        size_t logical_idx = 0u;

        mseed_len = Session_Gateway::Get_Master_Seed_Raw(
            master_seed_buf, sizeof(master_seed_buf));

        crypto_state_A = 0x3D4854539E3779B9ULL
            ^ static_cast<uint64_t>(tx_len);
        crypto_state_B = 0xC2B2AE3585EBCA6BULL;

        if (mseed_len >= 16u) {
            std::memcpy(&crypto_state_A, master_seed_buf, 8u);
            std::memcpy(&crypto_state_B, master_seed_buf + 8u, 8u);
        }
        crypto_state_A ^=
            (static_cast<uint64_t>(packet_nonce) << 32u) | packet_nonce;

        for (size_t i = 0u; i < dl_len; ++i) {
            if ((i & 0x3FFu) == 0u &&
                abort_signal.load(std::memory_order_relaxed)) {
                break;
            }

            int32_t normalized_tx = impl.work_B.tx_signal[i] >> 4;
            normalized_tx = Safe_Clamp(normalized_tx, -32768, 32767);
            const uint16_t tx_16bit =
                static_cast<uint16_t>(normalized_tx & 0xFFFF);

            // [BUG-20 FIX-1] 수학적으로 sec_buffer_idx < packed_len 보장
            //  (logical_idx < packed_len*2 → >>1 < packed_len)
            //  EMI 비트플립 방어: 분기 유지, 모듈로(%) → 클램프 대체
            //  [FIX-C6385] MAX_SEC_WORDS 경계 명시 — MSVC 정적 분석기 만족
            size_t sec_buffer_idx = logical_idx >> 1u;
            if (sec_buffer_idx >= packed_len
                || sec_buffer_idx >= Impl::MAX_SEC_WORDS) {
                sec_buffer_idx = packed_len - 1u;
            }
            const bool is_high_part = ((logical_idx & 1u) == 0u);
            const uint32_t encrypted_32bit =
                impl.temp_sec[sec_buffer_idx];

            const uint16_t sec_16bit = is_high_part
                ? static_cast<uint16_t>(encrypted_32bit >> 16u)
                : static_cast<uint16_t>(encrypted_32bit & 0xFFFFu);

            const uint64_t s0 = crypto_state_A;
            uint64_t s1 = crypto_state_B;
            const uint64_t crypto_stream =
                RotL64(s0 + s1, 17u) + s0;

            s1 ^= s0;
            crypto_state_A = RotL64(s0, 49u) ^ s1 ^ (s1 << 21u);
            crypto_state_B = RotL64(s1, 28u);

            const uint16_t stealth_sec = sec_16bit
                ^ static_cast<uint16_t>(crypto_stream >> 48u);

            impl.dual_lane_buffer[i] =
                (static_cast<uint32_t>(tx_16bit) << 16u) | stealth_sec;

            logical_idx += logical_step;
            if (logical_idx >= total_16bit_words) {
                logical_idx -= total_16bit_words;
            }
        }

        return !abort_signal.load(std::memory_order_acquire);
        // RAII_Secure_Wiper가 로컬 민감값 + Impl 워킹 버퍼(work_A/B, temp_sec)
        // 를 스코프 종료 시 자동 소거 — 평문 잔류 0바이트
    }

    // =====================================================================
    //  접근자 (Pimpl 위임)
    // =====================================================================
    size_t Dual_Tensor_Pipeline::Get_Active_Tensor_Count() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? p->active_tensor_count : 0u;
    }

    // [BUG-17] Get_Dual_Lane_Buffer: raw 포인터 + 길이 반환
    //  기존 vector API는 헤더에서 PC 전용으로 분리 (하위 호환)
    const uint32_t* Dual_Tensor_Pipeline::Get_Dual_Lane_Data() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? p->dual_lane_buffer : nullptr;
    }

    size_t Dual_Tensor_Pipeline::Get_Dual_Lane_Size() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? p->dl_len_ : 0u;
    }

} // namespace ProtectedEngine