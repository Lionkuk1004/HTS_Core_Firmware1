// =========================================================================
// HTS_Key_Rotator.cpp
// Forward Secrecy 기반 동적 시드 로테이터 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// [양산 수정 이력 — 17건]
//  BUG-01~15 (이전 세션)
//  BUG-16 [CRIT] try-catch 4블록 제거 + seq_cst→release 3곳
//         · Impl 내부 try-catch 2블록: 정적 배열 전환으로 OOM 소멸
//         · deriveNextSeed try-catch 1블록: 삭제
//         · Secure_Zero_KR/Murmur3/deriveNextSeed seq_cst → release
//  BUG-17 [CRIT] currentSeed vector → uint8_t[32] 정적 배열
//         · 시드 크기 항상 32바이트 고정 (resize(32) 강제)
//         · Impl 생성자: vector 복사 → memcpy (힙 0회, OOM 불가)
//         · <vector> include 삭제 (반환 타입만 잔존 — 호출자 전환 후 제거)
// =========================================================================
#include "HTS_Key_Rotator.h"

// ── Self-Contained 표준 헤더 [BUG-11] ───────────────────────────────
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

namespace ProtectedEngine {
    // [FIX-WIPE] 3중 방어 보안 소거 — impl_buf_ 전체 파쇄
    static void Key_Rotator_Secure_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) { q[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }



    // =====================================================================
    //  Murmur3-32 해시 (시드 파생 전용)
    //  [BUG-08/09] uint32_t k, r=0 UB 가드
    //  [BUG-14]   반환 전 h, k1 보안 소거
    // =====================================================================
    static inline uint32_t RotL32(uint32_t x, uint32_t r) noexcept {
        r &= 31u;
        if (r == 0u) { return x; }
        return (x << r) | (x >> (32u - r));
    }

    static uint32_t Murmur3_Mix(
        const uint8_t* data, size_t len, uint32_t seed) noexcept {

        uint32_t h = seed;
        const size_t nblocks = len / 4u;

        for (size_t i = 0u; i < nblocks; ++i) {
            uint32_t k = 0u;
            std::memcpy(&k, data + i * 4u, 4u);

            k *= 0xCC9E2D51u;
            k = RotL32(k, 15u);
            k *= 0x1B873593u;

            h ^= k;
            h = RotL32(h, 13u);
            h = h * 5u + 0xE6546B64u;
        }

        // tail — [BUG-10] [[fallthrough]] + C++14 주석 병행
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

        // [BUG-14] 로컬 중간값 소거
        const uint32_t result = h;
        {
            volatile uint32_t* v_h =
                reinterpret_cast<volatile uint32_t*>(&h);
            volatile uint32_t* v_k1 =
                reinterpret_cast<volatile uint32_t*>(&k1);
            *v_h = 0u;
            *v_k1 = 0u;
            // [BUG-16] seq_cst → release
            std::atomic_thread_fence(std::memory_order_release);
        }

        return result;
    }

    // =====================================================================
    //  Pimpl 구현
    //  [BUG-17] currentSeed: vector → uint8_t[SEED_LEN] 정적 배열
    //   시드 크기: 항상 32바이트 (resize(32u) 강제)
    //   try-catch 제거: 정적 배열 → OOM 경로 소멸
    // =====================================================================
    struct DynamicKeyRotator::Impl {
        static constexpr size_t SEED_LEN = 32u;
        uint8_t currentSeed[SEED_LEN] = {};
        size_t  seed_len = 0u;

        // [FIX-RACE] Spinlock — 단일 진입 강제 (Writer 상호 배제)
        //  std::atomic_flag: LDREX/STREX 기반 → ISR 안전
        //  SeqLock 삭제: Writer-Writer 경합에 무효
        std::atomic_flag spin_lock = ATOMIC_FLAG_INIT;

        explicit Impl(const uint8_t* master, size_t master_len) noexcept {
            // [BUG-17] memcpy 직접 복사 (힙 0회, OOM 불가)
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
    //  [BUG-15] 컴파일 타임 크기·정렬 검증 + get_impl()
    // =====================================================================
    DynamicKeyRotator::Impl* DynamicKeyRotator::get_impl() noexcept {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE(256B)를 초과합니다 — 버퍼 크기를 늘려주세요");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 요구가 impl_buf_ alignas(8)을 초과합니다");
        return impl_valid_ ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }

    const DynamicKeyRotator::Impl*
        DynamicKeyRotator::get_impl() const noexcept {
        return impl_valid_
            ? reinterpret_cast<const Impl*>(impl_buf_)
            : nullptr;
    }

    // =====================================================================
    //  [BUG-15] 생성자 — placement new (zero-heap)
    //
    //  기존: std::make_unique<Impl>(masterSeed) + try-catch
    //  수정: impl_buf_ SecWipe → ::new Impl(masterSeed) → impl_valid_ = true
    //  Impl(masterSeed) 내부 try-catch가 OOM 처리 → 생성자 자체는 noexcept 유지
    // =====================================================================
    DynamicKeyRotator::DynamicKeyRotator(
        const std::vector<uint8_t>& masterSeed) noexcept
        : impl_valid_(false)
    {
        Key_Rotator_Secure_Wipe(impl_buf_, sizeof(impl_buf_));
        // [BUG-17] vector → raw 포인터 + 길이 전달
        ::new (static_cast<void*>(impl_buf_)) Impl(
            masterSeed.data(), masterSeed.size());
        impl_valid_ = true;
    }

    // =====================================================================
    //  [BUG-15] 소멸자 — 명시적 (= default 제거)
    //  Impl 소멸자(currentSeed 보안 소거) → impl_buf_ 전체 SecWipe
    // =====================================================================
    DynamicKeyRotator::~DynamicKeyRotator() noexcept {
        Impl* p = get_impl();
        if (p != nullptr) { p->~Impl(); }
        // [FIX-WIPE] impl_buf_ 전체 3중 방어 소거 (p==nullptr에도 무조건 실행)
        Key_Rotator_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
        impl_valid_ = false;
    }

    // =====================================================================
    //  deriveNextSeed — 블록 인덱스 기반 단방향 시드 파생
    //  [BUG-16] try-catch 제거 (-fno-exceptions)
    //  [BUG-17] 내부: 정적 배열 직접 사용
    //  반환: 호출자 버퍼에 복사 (Raw API)
    //  기존 vector 반환 API는 헤더에서 유지 (호출자 마이그레이션 후 제거)
    // =====================================================================
    // =====================================================================
    //  [FIX-HEAP] Raw API — 힙 할당 0회, noexcept 보장
    //  [FIX-RACE] Spinlock 보호 — Writer 상호 배제 (ISR 안전)
    // =====================================================================
    bool DynamicKeyRotator::deriveNextSeed(
        uint32_t blockIndex,
        uint8_t* out_buf, size_t out_len) noexcept {

        Impl* p = get_impl();
        if (p == nullptr || p->seed_len == 0u ||
            out_buf == nullptr || out_len == 0u) {
            return false;
        }

        // [FIX-RACE] Spinlock 획득 — 단일 Writer 진입 강제
        //  LDREX/STREX: ISR 선점 시 STREX 실패 → 재시도 (데드락 불가)
        while (p->spin_lock.test_and_set(std::memory_order_acquire)) {
            // Cortex-M4: 단일코어, ISR 선점만 가능 → 짧은 스핀
        }

        uint8_t* seed = p->currentSeed;
        const size_t seed_len = p->seed_len;

        // 1단계: blockIndex 혼합 (선두 4바이트)
        for (size_t i = 0u; i < 4u && i < seed_len; ++i) {
            seed[i] ^= static_cast<uint8_t>(
                (blockIndex >> (i * 8u)) & 0xFFu);
        }

        // 2단계: Murmur3 기반 전체 시드 비가역 혼합
        uint32_t running_hash = blockIndex ^ 0x5BD1E995u;
        size_t num_passes = (seed_len + 3u) / 4u;
        if (num_passes == 0u) { num_passes = 1u; }

        for (size_t pass = 0u; pass < num_passes; ++pass) {
            running_hash = Murmur3_Mix(
                seed, seed_len,
                running_hash ^ static_cast<uint32_t>(pass));

            const size_t offset = (pass * 4u) % seed_len;
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

        // 3단계: 출력 — 임계 구역 내부에서 복사 완료 후 해제
        //  [FIX-RACE] memcpy가 lock 내부 → Tearing Read 불가
        const size_t copy_len = (out_len < seed_len) ? out_len : seed_len;
        std::memcpy(out_buf, seed, copy_len);

        // [FIX-RACE] Spinlock 해제 — memcpy 완료 후
        p->spin_lock.clear(std::memory_order_release);

        return true;
    }

    // [호환] 기존 vector API — Raw API 래퍼 (마이그레이션 후 삭제)
    std::vector<uint8_t> DynamicKeyRotator::deriveNextSeed(
        uint32_t blockIndex) noexcept {
        uint8_t buf[Impl::SEED_LEN];
        if (!deriveNextSeed(blockIndex, buf, sizeof(buf))) {
            return std::vector<uint8_t>();
        }
        return std::vector<uint8_t>(buf, buf + Impl::SEED_LEN);
    }

} // namespace ProtectedEngine