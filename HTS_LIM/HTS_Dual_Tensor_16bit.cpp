// =========================================================================
// HTS_Dual_Tensor_16bit.cpp
// B-CDMA 듀얼 레인 텐서 파이프라인 구현부 (Pimpl 은닉)
// Target: STM32F407 (Cortex-M4, 168MHz)
//
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
#include <new>
#include <cstddef>
#include <cstdint>
#include <cstring>

#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
#include <bit>
#endif

namespace ProtectedEngine {

    // =====================================================================
    //  보안 메모리 소거 (pragma O0 + volatile + fence 3중 보호)
    //
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
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
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

    static inline uint64_t RotL64(uint64_t x, uint32_t k) noexcept {
        k &= 63u;
        if (k == 0u) { return x; }
#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
        return std::rotl(x, static_cast<int>(k));
#else
        return (x << k) | (x >> (64u - k));
#endif
    }

    static inline int32_t Safe_Clamp(
        int32_t val, int32_t lo, int32_t hi) noexcept {
        if (val < lo) { return lo; }
        if (val > hi) { return hi; }
        return val;
    }

    /// int32_t / (1u << k), k < 32 — C++ 정수 나눗셈(0 방향 절사)과 동일, SDIV/분기 없이 시프트만.
    /// 부호 있는 >> 는 구현 정의이므로, 절댓값을 uint32_t 로 시프트 후 부호 복원.
    static inline int32_t Int32_Div_Pow2_Truncate(
        int32_t x, uint32_t k) noexcept {
        const int32_t sign = x >> 31;
        const uint32_t mag =
            static_cast<uint32_t>(static_cast<uint32_t>(x ^ sign)
                - static_cast<uint32_t>(sign));
        const uint32_t qu = mag >> k;
        const int32_t q = static_cast<int32_t>(qu);
        return static_cast<int32_t>(
            (static_cast<uint32_t>(q) ^ static_cast<uint32_t>(sign))
            - static_cast<uint32_t>(sign));
    }

    /// 분기 없는 min(x, cap) — EMI/인덱스 클램프 (루프 내 예측 실패 제거)
    static inline size_t Min_Size_U(size_t x, size_t cap) noexcept {
        return cap ^ ((x ^ cap) & -static_cast<std::ptrdiff_t>(x < cap));
    }

    // =====================================================================
    //  Pimpl 구현 구조체
    //
    //
    //  메모리 배치 (ARM, process_len ≤ 1024):
    //    work_A[16384]:  int8_t raw_bits / interleaved (ping-pong A)
    //    work_B union:   int8_t fec_bits[16384] / int32_t tx_signal[4096] (ping-pong B)
    //    temp_sec[2560]: uint32_t (packed_len ≤ 512 + 여유)
    //    dual_lane[4096]: uint32_t DMA 출력 버퍼
    //
    //  Impl ≈ 52KB (정적, 힙 0회, 런타임 HardFault 0건)
    //  런타임 힙: ~4.2MB (vector<fp64> × 3 = 즉사) → 완전 제거
    // =====================================================================
    struct Dual_Tensor_Pipeline::Impl {
        size_t active_tensor_count = 0;
        Gaussian_Pulse_Shaper pulse_shaper;
        Security_Pipeline     sec_pipeline;

        static constexpr size_t MAX_DL_FRAME = 4096u;
        static_assert(MAX_DL_FRAME == 4096u,
            "MAX_DL_FRAME must be 4096 for scheduler compatibility");
        uint32_t dual_lane_buffer[MAX_DL_FRAME] = {};
        static_assert(sizeof(dual_lane_buffer) ==
            MAX_DL_FRAME * sizeof(uint32_t),
            "dual_lane_buffer size mismatch");
        size_t   dl_len_ = 0;

        HTS_Engine::Soft_Tensor_FEC    tensor_fec_engine;
        HTS_Engine::Tensor_Interleaver tensor_interleaver;

        // ── 정적 워킹 버퍼 (vector/fp64 제거) ───────────────────────
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
        //  dim=16(4096) < MAX_PACKED_LEN*32(16384) → 75% 데이터 절삭
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

        //  fec_bits / tx_signal 분리 버퍼 — 단계 간 alias·union 패딩 이슈 방지
        int8_t  fec_bits[MAX_WORK_BITS] = {};
        int32_t tx_signal[MAX_TX_SAMPS] = {};

        // Security/패킹 버퍼
        uint32_t temp_sec[MAX_SEC_WORDS] = {};

        Impl(uint32_t bt_q16, size_t filter_taps) noexcept
            : active_tensor_count(0)
            , pulse_shaper(filter_taps, bt_q16)
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

    //  dual_lane_buffer: 4096 × 4B = 16KB
    //  Impl 전체: 서브모듈 포인터 + 정적 배열 ≈ 17~18KB
    //  IMPL_BUF_SIZE를 증가시켜야 할 수 있음 → static_assert로 자동 검출

    // =====================================================================
    // =====================================================================
    Dual_Tensor_Pipeline::Impl* Dual_Tensor_Pipeline::get_impl() noexcept {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE를 초과합니다 — 헤더에서 IMPL_BUF_SIZE를 늘려주세요");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 요구가 impl_buf_ alignas(8)을 초과합니다");
        return impl_valid_.load(std::memory_order_acquire)
            ? std::launder(reinterpret_cast<Impl*>(impl_buf_)) : nullptr;
    }

    const Dual_Tensor_Pipeline::Impl*
        Dual_Tensor_Pipeline::get_impl() const noexcept {
        return impl_valid_.load(std::memory_order_acquire)
            ? std::launder(reinterpret_cast<const Impl*>(impl_buf_))
            : nullptr;
    }

    // =====================================================================
    // =====================================================================
    Dual_Tensor_Pipeline::Dual_Tensor_Pipeline(
        uint32_t bt_q16, size_t filter_taps) noexcept
        : impl_valid_(false)
    {
        Secure_Wipe_Buffer(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl(bt_q16, filter_taps);
        impl_valid_.store(true, std::memory_order_release);
    }

    // =====================================================================
    // =====================================================================
    Dual_Tensor_Pipeline::~Dual_Tensor_Pipeline() noexcept {
        impl_valid_.store(false, std::memory_order_release);
        Impl* p = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        if (p != nullptr) { p->~Impl(); }
        Secure_Wipe_Buffer(impl_buf_, sizeof(impl_buf_));
    }

    // =====================================================================
        //  Execute_Dual_Processing — 핵심 파이프라인
    //
        //   · raw_bit_stream(fp64)  → work_A(int8_t): ±1만 저장, 1/8 메모리
        //   · fec_tensor(fp64)      → work_B.fec_bits(int8_t): Raw API
        //   · interleaved(fp64)     → work_A 재사용(int8_t): ping-pong
    //   · temp_sec_buffer(vec)   → temp_sec(정적 uint32_t)
    //   · temp_tx_signal(vec)    → work_B.tx_signal(union 재사용)
        //   · 힙 할당: ∞회 → 0회, fp64 연산: 0회
    //
    // =====================================================================
    bool Dual_Tensor_Pipeline::Execute_Dual_Processing(
        const uint16_t* raw_sensor_data, size_t data_len,
        uint32_t packet_nonce,
        std::atomic<bool>& abort_signal) noexcept
    {
        uint32_t ok = 1u; // TPE: cumulative validity (0/1)
        Impl* p_chk = get_impl();
        ok &= static_cast<uint32_t>(p_chk != nullptr);
        ok &= static_cast<uint32_t>(raw_sensor_data != nullptr);
        ok &= static_cast<uint32_t>(data_len > 0u);

        Impl& impl = *std::launder(reinterpret_cast<Impl*>(impl_buf_));

        // active_tensor_count는 "uint32(듀얼 텐서) 개수" 단위.
        // Stage①에서 16비트 센서 2개 → 32비트 1개 패킹하므로,
        // 입력 process_len(=uint16 원소 수) 캡은 active_tensor_count×2여야 한다.
        size_t process_len =
            std::min(data_len, impl.active_tensor_count * 2u);
        const uint32_t m_ok0 = 0u - ok; // TPE: mask lengths when invalid
        process_len &= static_cast<size_t>(m_ok0);

        // ── ❶ 민감 데이터 선언 + RAII 바인딩 ──
        uint64_t crypto_state_A = 0u;
        uint64_t crypto_state_B = 0u;
        uint64_t crypto_stream_cache = 0u;   // PRNG 캐시 (4×16비트)
        uint32_t fec_seed = 0u;

        uint8_t fec_master_seed_buf[MAX_SEED_SIZE] = {};
        uint8_t master_seed_buf[MAX_SEED_SIZE] = {};
        size_t  fec_mseed_len = 0;
        size_t  mseed_len = 0;

        // RAII: 로컬 민감값 + Impl 워킹 버퍼 소거
        //  work_A/B/temp_sec는 Impl 멤버이므로 함수 종료 후에도 생존
        //  → 모든 반환 경로에서 RAII로 즉시 소거 (조기 return 포함)
        RAII_Secure_Wiper wipe_fec_mseed(fec_master_seed_buf, sizeof(fec_master_seed_buf));
        RAII_Secure_Wiper wipe_master(master_seed_buf, sizeof(master_seed_buf));
        RAII_Secure_Wiper wipe_cA(&crypto_state_A, sizeof(crypto_state_A));
        RAII_Secure_Wiper wipe_cB(&crypto_state_B, sizeof(crypto_state_B));
        RAII_Secure_Wiper wipe_cache(&crypto_stream_cache, sizeof(crypto_stream_cache));
        RAII_Secure_Wiper wipe_fseed(&fec_seed, sizeof(fec_seed));
        RAII_Secure_Wiper wipe_workA(impl.work_A, sizeof(impl.work_A));
        RAII_Secure_Wiper wipe_fec(impl.fec_bits, sizeof(impl.fec_bits));
        RAII_Secure_Wiper wipe_txsig(impl.tx_signal, sizeof(impl.tx_signal));
        RAII_Secure_Wiper wipe_tsec(impl.temp_sec, sizeof(impl.temp_sec));

        // ── ② 16비트 → 32비트 패킹 (정적 temp_sec) ──
        // ⑨ /2u → >>1u
        size_t packed_len = (process_len + 1u) >> 1u;
        packed_len = Min_Size_U(packed_len, Impl::MAX_SEC_WORDS);

        for (size_t i = 0u; i < packed_len; ++i) {
            const uint32_t high = raw_sensor_data[i * 2u];
            const uint32_t low = (i * 2u + 1u < process_len)
                ? raw_sensor_data[i * 2u + 1u] : 0x0000u;
            impl.temp_sec[i] = (high << 16u) | low;
        }

        // ── ③ Security_Pipeline 보안 변환 ──
        impl.sec_pipeline.Secure_Master_Worker(
            impl.temp_sec, 0, packed_len, abort_signal, packed_len);

        // ── ④ 3D FEC + 인터리빙 (int8_t Raw API) ──
        fec_mseed_len = Session_Gateway::Derive_Session_Material(
            Session_Gateway::DOMAIN_DUAL_FEC,
            fec_master_seed_buf, sizeof(fec_master_seed_buf));

        uint32_t fec_mix = 0u;
        std::memcpy(&fec_mix, fec_master_seed_buf, 4u);
        const uint32_t m_fec4 = 0u - static_cast<uint32_t>(fec_mseed_len >= 4u); // TPE:
        fec_seed = packet_nonce;
        fec_seed = (fec_mix & m_fec4) | (fec_seed & ~m_fec4);
        fec_seed ^= (packet_nonce << 16u) | (packet_nonce >> 16u);

        size_t n_raw_bits = packed_len * 32u;
        ok &= static_cast<uint32_t>(n_raw_bits <= Impl::MAX_WORK_BITS);
        const uint32_t m_ok_bits = 0u - ok; // TPE:
        packed_len &= static_cast<size_t>(m_ok_bits);
        n_raw_bits = packed_len * 32u;

        for (size_t i = 0u; i < packed_len; ++i) {
            const uint32_t word = impl.temp_sec[i];
            for (int32_t bit = 31; bit >= 0; --bit) {
                impl.work_A[i * 32u + static_cast<size_t>(31 - bit)] =
                    ((word >> static_cast<uint32_t>(bit)) & 1u)
                    ? static_cast<int8_t>(1) : static_cast<int8_t>(-1);
            }
        }

        const size_t fec_out_max =
            (n_raw_bits < Impl::MAX_WORK_BITS) ? n_raw_bits : Impl::MAX_WORK_BITS;
        const size_t fec_len = impl.tensor_fec_engine.Encode_Raw(
            impl.work_A, n_raw_bits,
            impl.fec_bits, fec_out_max,
            fec_seed);
        ok &= static_cast<uint32_t>(fec_len > 0u);
        const size_t fec_len_use = fec_len & static_cast<size_t>(0u - ok); // TPE:

        uint64_t fractal_sid =
            static_cast<uint64_t>(fec_seed)
            ^ (static_cast<uint64_t>(packet_nonce) << 32u);
        uint64_t fractal_from_buf = fractal_sid;
        std::memcpy(&fractal_from_buf, fec_master_seed_buf, 8u);
        const uint64_t m_fec8 = static_cast<uint64_t>(0ull)
            - static_cast<uint64_t>(fec_mseed_len >= 8u); // TPE:
        fractal_sid = (fractal_from_buf & m_fec8) | (fractal_sid & ~m_fec8);
        impl.tensor_interleaver.Sync_Fractal_Key(
            fractal_sid, fec_seed ^ packet_nonce);

        const size_t intlv_len = impl.tensor_interleaver.Interleave_Raw(
            impl.fec_bits, fec_len_use,
            impl.work_A, Impl::MAX_WORK_BITS);

        // intlv(int8_t) → uint32 패킹 (temp_sec 재사용)
        const size_t interleaved_bits = intlv_len;
        // ⑨ /32u → >>5u
        size_t fec_words = (interleaved_bits + 31u) >> 5u;
        ok &= static_cast<uint32_t>(fec_words <= Impl::MAX_SEC_WORDS);
        fec_words &= static_cast<size_t>(0u - ok); // TPE:

        for (size_t i = 0u; i < fec_words; ++i) {
            uint32_t word = 0u;
            for (int32_t bit = 0; bit < 32; ++bit) {
                const size_t idx =
                    i * 32u + static_cast<size_t>(bit);
                if (idx < interleaved_bits &&
                    impl.work_A[idx] > 0) {          // 정수 부호 비교
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
        std::memset(impl.tx_signal, 0, ps_max * sizeof(int32_t));
        const size_t actual_ps = impl.pulse_shaper.Apply_Pulse_Shaping_Tensor_Raw(
            impl.temp_sec, packed_len,
            impl.tx_signal, ps_max);

        const size_t tx_len = actual_ps;
        ok &= static_cast<uint32_t>(tx_len > 0u);

        size_t dl_len = (tx_len < Impl::MAX_DL_FRAME)
            ? tx_len : Impl::MAX_DL_FRAME;

        // ── ⑥ 듀얼 레인 패킹 (Xoroshiro128++) ──
        const size_t total_16bit_words = packed_len * 2u;
        ok &= static_cast<uint32_t>(total_16bit_words > 0u);

        // [HT-6] runtime modulo(%) 제거:
        //  logical_step은 [0, total_16bit_words-1] 범위만 만족하면
        //  이후 logical_idx += logical_step; if >= total then -= total
        //  로 정확한 1-step 원형 인덱싱이 성립합니다.
        //  total_16bit_words > 1에서 total_16bit_words-1은 항상 서로소
        //  이므로( gcd(total, total-1)=1 ) 완전 순환(permute cycle)을 보장합니다.
        static constexpr uint32_t PRIME_INTERLEAVER = 1000003u;
        const size_t logical_step = (total_16bit_words <= 1u)
            ? 0u
            : ((PRIME_INTERLEAVER < static_cast<uint32_t>(total_16bit_words))
                ? static_cast<size_t>(PRIME_INTERLEAVER)
                : (total_16bit_words - 1u));
        size_t logical_idx = 0u;

        mseed_len = Session_Gateway::Derive_Session_Material(
            Session_Gateway::DOMAIN_DUAL_PRNG,
            master_seed_buf, sizeof(master_seed_buf));

        // ─────────────────────────────────────────────────────────────
        //
        //  Xoroshiro128++는 128비트 상태 — 마스터 시드 16바이트 미만이면 암호화 거부
        // ─────────────────────────────────────────────────────────────
        ok &= static_cast<uint32_t>(mseed_len >= 16u);
        std::memcpy(&crypto_state_A, master_seed_buf, 8u);
        std::memcpy(&crypto_state_B, master_seed_buf + 8u, 8u);
        crypto_state_A ^=
            (static_cast<uint64_t>(packet_nonce) << 32u) | packet_nonce;

        const uint32_t m_ok_final = 0u - ok; // TPE: dl_len / dual-lane iteration bound
        dl_len &= static_cast<size_t>(m_ok_final);
        impl.dl_len_ = dl_len;

        // ─────────────────────────────────────────────────────────────
        //
        //  ★★★ TX/RX 암호학적 동기화 계약 (절대 변경 금지) ★★★
        //
        //  (1) PRNG: 매 샘플 동일 연산(상태는 ph==0에서만 마스크로 커밋) + 4샘플 블록 언롤
        //  (2) 16비트 추출 순서: MSB-first
        //       phase 0 → [63:48], phase 1 → [47:32],
        //       phase 2 → [31:16], phase 3 → [15:0]
        //  (3) 위상 카운터: 루프 시작 시 0으로 초기화
        //  (4) RX 디코더는 반드시 동일한 (1)~(3) 규약으로 키스트림 재생
        //      이 규약을 위반하면 TX/RX 키스트림 위상이 영구 이탈하여
        //      전체 패킷 디코딩이 100% 실패함
        //
        //  효과:
        //   · PRNG 갱신 횟수: dl_len → dl_len/4 (75% 연산 감소)
        //   · 64비트 전량 활용 → 16비트 편향 없이 균일 분포
        //   · TX/RX 위상 계약 코드-수준 명시 → 독립 최적화 시 파괴 방지
        // ─────────────────────────────────────────────────────────────
        crypto_stream_cache = 0u;
        uint32_t stream_phase = 0u;
        static constexpr uint32_t TX_SIGNAL_ATTEN_SHIFT = 4u;  // ÷16, 나눗셈 연산자 금지

        // 듀얼 레인 1샘플: ph==0일 때만 Xoroshiro 상태 반영 — 64비트 마스크 합성(분기 없음)
        auto dual_lane_one = [&](size_t idx, uint32_t ph) noexcept -> void {
            int32_t normalized_tx = Int32_Div_Pow2_Truncate(
                impl.tx_signal[idx], TX_SIGNAL_ATTEN_SHIFT);
            normalized_tx = Safe_Clamp(normalized_tx, -32768, 32767);
            const uint16_t tx_16bit =
                static_cast<uint16_t>(normalized_tx & 0xFFFF);

            size_t sec_buffer_idx = logical_idx >> 1u;
            sec_buffer_idx = Min_Size_U(sec_buffer_idx, packed_len - 1u);
            sec_buffer_idx = Min_Size_U(
                sec_buffer_idx, Impl::MAX_SEC_WORDS - 1u);
            const uint32_t encrypted_32bit =
                impl.temp_sec[sec_buffer_idx];

            const uint32_t mask_lo =
                0u - (static_cast<uint32_t>(logical_idx) & 1u);
            const uint16_t sec_16bit = static_cast<uint16_t>(
                ((encrypted_32bit >> 16u) & ~mask_lo)
                | ((encrypted_32bit & 0xFFFFu) & mask_lo));

            const uint64_t s0 = crypto_state_A;
            uint64_t s1 = crypto_state_B;
            const uint64_t new_cache = RotL64(s0 + s1, 17u) + s0;
            s1 ^= s0;
            const uint64_t new_a =
                RotL64(s0, 49u) ^ s1 ^ (s1 << 21u);
            const uint64_t new_b = RotL64(s1, 28u);
            const uint64_t m64 = 0ull - static_cast<uint64_t>(ph == 0u);
            crypto_stream_cache =
                (new_cache & m64) | (crypto_stream_cache & ~m64);
            crypto_state_A =
                (new_a & m64) | (crypto_state_A & ~m64);
            crypto_state_B =
                (new_b & m64) | (crypto_state_B & ~m64);
            std::atomic_signal_fence(std::memory_order_acq_rel);

            const uint32_t shift = (3u - ph) << 4u;
            const uint16_t stealth_sec = sec_16bit
                ^ static_cast<uint16_t>(
                    (crypto_stream_cache >> shift) & 0xFFFFu);

            impl.dual_lane_buffer[idx] =
                (static_cast<uint32_t>(tx_16bit) << 16u)
                | static_cast<uint32_t>(stealth_sec);

            logical_idx += logical_step;
            const size_t ovf =
                static_cast<size_t>(logical_idx >= total_16bit_words);
            logical_idx -= ovf * total_16bit_words;
        };

        size_t i = 0u;
        for (; i + 4u <= dl_len; i += 4u) {
            dual_lane_one(i + 0u, 0u);
            dual_lane_one(i + 1u, 1u);
            dual_lane_one(i + 2u, 2u);
            dual_lane_one(i + 3u, 3u);
        }
        for (; i < dl_len; ++i) {
            dual_lane_one(i, stream_phase);
            stream_phase = (stream_phase + 1u) & 3u;
        }

        return (ok != 0u)
            && !abort_signal.load(std::memory_order_acquire);
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

    //  vector API는 헤더에서 PC 전용으로 분리 (하위 호환)
    const uint32_t* Dual_Tensor_Pipeline::Get_Dual_Lane_Data() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? p->dual_lane_buffer : nullptr;
    }

    size_t Dual_Tensor_Pipeline::Get_Dual_Lane_Size() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? p->dl_len_ : 0u;
    }

} // namespace ProtectedEngine
