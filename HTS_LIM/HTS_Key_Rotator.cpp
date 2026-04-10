// =========================================================================
// HTS_Key_Rotator.cpp
// Forward Secrecy 기반 동적 시드 로테이터 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
//
#include "HTS_Key_Rotator.h"
#include "HTS_Arm_Irq_Mask_Guard.h"
#include "HTS_BitOps.h"
#include "HTS_Secure_Memory.h"

// ── Self-Contained 표준 헤더 ───────────────────────────────────────
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
#include <bit>
#endif
#if !defined(__arm__) && !defined(__TARGET_ARCH_ARM) && \
    !defined(__TARGET_ARCH_THUMB) && !defined(__ARM_ARCH)
#include <vector>
#endif

// Cortex-M / 임베디드 ARM 단일코어: atomic_flag 스핀은 ISR 선점 시 데드락 → PRIMASK
// HTS_Key_Rotator.h 의 “ARM” 판별과 동일. AArch64는 멀티코어·모델 상이 → 스핀락 유지
#if (defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
     defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)) && \
    !defined(__aarch64__)
#define HTS_KEY_ROTATOR_PRIMASK_CRIT 1
#else
#define HTS_KEY_ROTATOR_PRIMASK_CRIT 0
#endif

namespace ProtectedEngine {
namespace {

#if HTS_KEY_ROTATOR_PRIMASK_CRIT
    using KeyRotator_Primask_Guard = Armv7m_Irq_Mask_Guard;
#endif

    /// RAII: atomic_flag 획득 실패 시 clear 없음, 성공 시 소멸자에서 release
    struct KeyRotator_Spinlock_Guard {
        std::atomic_flag* flag_;
        bool held_;
        explicit KeyRotator_Spinlock_Guard(std::atomic_flag* f) noexcept
            : flag_(f), held_(false) {
            if (flag_ == nullptr) { return; }
            uint32_t spin_guard = 1000000u;
            while (flag_->test_and_set(std::memory_order_acquire)) {
                if (--spin_guard == 0u) {
                    return;
                }
            }
            held_ = true;
        }
        ~KeyRotator_Spinlock_Guard() noexcept {
            if (held_) {
                flag_->clear(std::memory_order_release);
            }
        }
        bool held() const noexcept { return held_; }
        KeyRotator_Spinlock_Guard(const KeyRotator_Spinlock_Guard&) = delete;
        KeyRotator_Spinlock_Guard& operator=(const KeyRotator_Spinlock_Guard&) = delete;
    };

} // anonymous namespace

    static void Key_Rotator_Secure_Wipe(void* p, size_t n) noexcept {
        SecureMemory::secureWipe(p, n);
    }

    // =====================================================================
    //  Murmur3-32 해시 (시드 파생 전용)
    // =====================================================================
    static inline uint32_t RotL32(uint32_t x, uint32_t r) noexcept {
        r &= 31u;
        if (r == 0u) { return x; }
        //  (32−r) 비트 시프트 UB 회피: C++20 std::rotl 우선
#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
        return std::rotl(x, static_cast<int>(r));
#else
        return (x << r) | (x >> (32u - r));
#endif
    }

    static uint32_t Murmur3_Mix(
        const uint8_t* data, size_t len, uint32_t seed) noexcept {

        uint32_t h = seed;
        // ⑨ 바이트 길이 → 워드 수: >>2 (나눗셈 대신 시프트)
        const size_t nblocks = len >> 2u;

        for (size_t i = 0u; i < nblocks; ++i) {
            const size_t base = i * 4u;
            const uint32_t k =
                static_cast<uint32_t>(data[base])
                | (static_cast<uint32_t>(data[base + 1u]) << 8u)
                | (static_cast<uint32_t>(data[base + 2u]) << 16u)
                | (static_cast<uint32_t>(data[base + 3u]) << 24u);

            uint32_t kx = k;
            kx *= 0xCC9E2D51u;
            kx = RotL32(kx, 15u);
            kx *= 0x1B873593u;

            h ^= kx;
            h = RotL32(h, 13u);
            h = h * 5u + 0xE6546B64u;
        }

        // tail — [[fallthrough]] + C++14 주석 병행
        const uint8_t* tail = data + nblocks * 4u;
        uint32_t k1 = 0u;
        switch (len & 3u) {
        case 3:
            k1 ^= static_cast<uint32_t>(tail[2]) << 16u;
#if __cplusplus >= 201703L || (defined(_MSVC_LANG) && _MSVC_LANG >= 201703L)
            [[fallthrough]];
#endif
            // fallthrough (C++14)
        case 2:
            k1 ^= static_cast<uint32_t>(tail[1]) << 8u;
#if __cplusplus >= 201703L || (defined(_MSVC_LANG) && _MSVC_LANG >= 201703L)
            [[fallthrough]];
#endif
            // fallthrough
        case 1:
            k1 ^= static_cast<uint32_t>(tail[0]);
            k1 *= 0xCC9E2D51u;
            k1 = RotL32(k1, 15u);
            k1 *= 0x1B873593u;
            h ^= k1;
            break;
        default:
            break;
        }

        // fmix32
        h ^= static_cast<uint32_t>(len);
        h ^= h >> 16u;
        h *= 0x85EBCA6Bu;
        h ^= h >> 13u;
        h *= 0xC2B2AE35u;
        h ^= h >> 16u;

        const uint32_t result = h;
        {
            volatile uint32_t* v_h =
                reinterpret_cast<volatile uint32_t*>(&h);
            volatile uint32_t* v_k1 =
                reinterpret_cast<volatile uint32_t*>(&k1);
            *v_h = 0u;
            *v_k1 = 0u;
            std::atomic_thread_fence(std::memory_order_release);
        }

        return result;
    }

    // =====================================================================
    //  Pimpl 구현
    //   시드 크기: 항상 32바이트 (resize(32u) 강제)
    //   try-catch 제거: 정적 배열 → OOM 경로 소멸
    // =====================================================================
    struct DynamicKeyRotator::Impl {
        static constexpr size_t SEED_LEN = 32u;
        static_assert(SEED_LEN >= 1u, "SEED_LEN must be positive");
        static_assert((SEED_LEN & (SEED_LEN - 1u)) == 0u,
            "SEED_LEN must be power of 2 for bitmask offset");
        uint8_t currentSeed[SEED_LEN] = {};
        size_t  seed_len = 0u;

        //  Cortex-M 단일코어에서 본 플래그로 상호배제 시 ISR 재진입 데드락 가능
        std::atomic_flag spin_lock = ATOMIC_FLAG_INIT;

        explicit Impl(const uint8_t* master, size_t master_len) noexcept {
            seed_len = (master_len < SEED_LEN) ? master_len : SEED_LEN;
            if (master != nullptr && seed_len > 0u) {
                std::memcpy(currentSeed, master, seed_len);
            }
            // 32바이트 미만 시 나머지는 이미 0으로 초기화됨
            seed_len = SEED_LEN;  // 항상 32바이트 고정
        }

        ~Impl() noexcept {
            Key_Rotator_Secure_Wipe(currentSeed, sizeof(currentSeed));
        }
    };

    // =====================================================================
    // =====================================================================
    DynamicKeyRotator::Impl* DynamicKeyRotator::get_impl() noexcept {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE(256B)를 초과합니다 — 버퍼 크기를 늘려주세요");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 요구가 impl_buf_ alignas(8)을 초과합니다");
        return impl_valid_.load(std::memory_order_acquire)
            ? std::launder(reinterpret_cast<Impl*>(impl_buf_)) : nullptr;
    }

    const DynamicKeyRotator::Impl*
        DynamicKeyRotator::get_impl() const noexcept {
        return impl_valid_.load(std::memory_order_acquire)
            ? reinterpret_cast<const Impl*>(impl_buf_)
            : nullptr;
    }

    // =====================================================================
    //
    //  placement new(impl_buf_): 선행 SecWipe 후 Impl 구성, impl_valid_로 가시성
    // =====================================================================
#if !defined(__arm__) && !defined(__TARGET_ARCH_ARM) && \
    !defined(__TARGET_ARCH_THUMB) && !defined(__ARM_ARCH)
    DynamicKeyRotator::DynamicKeyRotator(
        const std::vector<uint8_t>& masterSeed) noexcept
        : DynamicKeyRotator(masterSeed.data(), masterSeed.size())
    {
    }
#endif

    DynamicKeyRotator::DynamicKeyRotator(
        const uint8_t* masterSeed, size_t master_len) noexcept
        : impl_valid_(false)
    {
        Key_Rotator_Secure_Wipe(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl(
            masterSeed, master_len);
        impl_valid_.store(true, std::memory_order_release);
    }

    // =====================================================================
    //  Impl 소멸자(currentSeed 보안 소거) → impl_buf_ 전체 SecWipe
    // =====================================================================
    DynamicKeyRotator::~DynamicKeyRotator() noexcept {
        if (impl_valid_.load(std::memory_order_acquire)) {
            impl_valid_.store(false, std::memory_order_release);
            std::launder(reinterpret_cast<Impl*>(impl_buf_))->~Impl();
        }
        Key_Rotator_Secure_Wipe(impl_buf_, sizeof(impl_buf_));
    }

    // =====================================================================
    //  deriveNextSeed — 블록 인덱스 기반 단방향 시드 파생
    //  반환: 호출자 버퍼에 복사 (Raw API)
    //  PC vector 출력 API는 out 매개변수로만 기록 (반환값 복사 없음)
    // =====================================================================
    bool DynamicKeyRotator::deriveNextSeed(
        uint32_t blockIndex,
        uint8_t* out_buf, size_t out_buf_size, size_t& out_len) noexcept {

        out_len = 0u;
        Impl* p = get_impl();
        if (p == nullptr || p->seed_len == 0u ||
            out_buf == nullptr || out_buf_size == 0u) {
            return false;
        }
        const size_t seed_len = p->seed_len;
        if (out_buf_size < seed_len) {
            return false;
        }

        // ─────────────────────────────────────────────────────────────
        //
        //  위협: 단일코어 Cortex-M4에서 atomic_flag spinlock은 데드락 확정
        //    메인루프가 lock 보유 중 ISR 발생 → ISR이 동일 lock spin
        //    → ISR이 CPU 점유 → 메인루프 영원히 복귀 불가 → 즉사(Deadlock)
        //
        //  Cortex-M: PRIMASK (HTS_KEY_ROTATOR_PRIMASK_CRIT)
        //  PC/A55: atomic_flag (멀티스레드)
        // ─────────────────────────────────────────────────────────────
#if HTS_KEY_ROTATOR_PRIMASK_CRIT
        const KeyRotator_Primask_Guard kr_irq_guard{};
#else
        KeyRotator_Spinlock_Guard kr_spin_guard(&p->spin_lock);
        if (!kr_spin_guard.held()) {
            return false;
        }
#endif

        uint8_t* seed = p->currentSeed;

        // 1단계: blockIndex 혼합 (선두 4바이트)
        for (size_t i = 0u; i < 4u && i < seed_len; ++i) {
            seed[i] ^= static_cast<uint8_t>(
                (blockIndex >> (i * 8u)) & 0xFFu);
        }

        // 2단계: Murmur3 기반 전체 시드 비가역 혼합
        uint32_t running_hash = blockIndex ^ 0x5BD1E995u;
        // ⑨ 바이트 길이 → 워드 수: >>2 (나눗셈 대신 시프트); 정렬 패드는 (4-(n&3))&3
        size_t num_passes = align_up_pow2_mask_size(seed_len, 3u) >> 2u;
        if (num_passes == 0u) { num_passes = 1u; }

        for (size_t pass = 0u; pass < num_passes; ++pass) {
            running_hash = Murmur3_Mix(
                seed, seed_len,
                running_hash ^ static_cast<uint32_t>(pass));

            // ⑨ seed_len=2^k → 오프셋 마스크 &(m−1) (static_assert와 일치)
            const size_t offset = (pass * 4u) & (seed_len - 1u);
            for (size_t b = 0u; b < 4u && (offset + b) < seed_len; ++b) {
                seed[offset + b] ^= static_cast<uint8_t>(
                    (running_hash >> (b * 8u)) & 0xFFu);
            }
        }

        // 키 파생 중간값 보안 소거
        {
            volatile uint32_t* v_rh =
                reinterpret_cast<volatile uint32_t*>(&running_hash);
            *v_rh = 0u;
            std::atomic_thread_fence(std::memory_order_release);
        }

        // 3단계: 출력 — 임계 구역 내부에서 복사 완료 후 해제 (경계는 진입 시 검증됨)
        std::memcpy(out_buf, seed, seed_len);
        out_len = seed_len;

        // 범위 탈출 시 kr_irq_guard / kr_spin_guard 소멸자가 PRIMASK 복원 또는 spin_lock 해제
        return true;
    }

#if !defined(__arm__) && !defined(__TARGET_ARCH_ARM) && \
    !defined(__TARGET_ARCH_THUMB) && !defined(__ARM_ARCH)
    bool DynamicKeyRotator::deriveNextSeed(
        uint32_t blockIndex,
        std::vector<uint8_t>& out) noexcept {
        out.clear();
        uint8_t buf[Impl::SEED_LEN];
        size_t nout = 0u;
        if (!deriveNextSeed(blockIndex, buf, sizeof(buf), nout)) {
            SecureMemory::secureWipe(static_cast<void*>(buf), sizeof(buf));
            return false;
        }
        out.assign(buf, buf + nout);
        SecureMemory::secureWipe(static_cast<void*>(buf), sizeof(buf));
        return true;
    }
#endif

} // namespace ProtectedEngine
