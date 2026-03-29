// =========================================================================
// HTS64_Tx_Stealth.cpp — 64-ary Stealth TX Engine
// Target: STM32F407 (Cortex-M4, 168MHz) / PC
//
// [Revision — 19 fixes]
//  BUG-01~16 (previous sessions)
//  BUG-17 [CRIT] unique_ptr -> placement new (zero-heap)
//  BUG-18 [LOW]  D-2: SecWipe MSVC volatile char→uint8_t (프로젝트 통일)
//  BUG-19 [HIGH] H-1/S-1: Impl 소멸자 SecWipe(atomic) UB 제거
//                atomic API(store)로만 소거 + release fence
//
// [Constraints] try-catch 0, float/double 0, heap 0
// =========================================================================
#include "HTS64_Tx_Stealth.hpp"
#include <atomic>
#include <cstdint>
#include <cstring>
#include <new>

namespace ProtectedEngine {

    static void SecWipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0) return;
        std::memset(p, 0, n);
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    static constexpr uint32_t popc32(uint32_t x) noexcept {
        x = x - ((x >> 1u) & 0x55555555u);
        x = (x & 0x33333333u) + ((x >> 2u) & 0x33333333u);
        return (((x + (x >> 4u)) & 0x0F0F0F0Fu) * 0x01010101u) >> 24u;
    }

    // =====================================================================
    //  Pimpl
    // =====================================================================
    struct HTS64_Tx_Stealth_Engine::Impl {
        std::atomic<uint32_t> current_state{ 0u };

        uint32_t NextState() noexcept {
            uint32_t o = current_state.load(std::memory_order_relaxed);
            uint32_t nv;
            do {
                nv = o;
                nv ^= nv << 13u;
                nv ^= nv >> 17u;
                nv ^= nv << 5u;
                if (nv == 0u) nv = 0xDEADBEEFu;
            } while (!current_state.compare_exchange_weak(
                o, nv, std::memory_order_relaxed, std::memory_order_relaxed));
            return nv;
        }

        // [BUG-18] Constant-time Walsh encode — branchless
        //
        // 기존: if ((popc32(m & j) & 1u) == 0u) hi |= ...
        //   → 데이터 종속 분기 → DPA/SPA 전력 분석으로 평문 역추적!
        //
        // 수정: mask = parity - 1 → 짝수:0xFFFFFFFF, 홀수:0x00000000
        //   → OR 연산은 항상 실행 → 사이클/전류 100% 동일
        //
        // ARM: SUB + AND + ORR = 3사이클/칩 고정 (분기 0개)
        static void walsh_encode_romless(uint8_t sym,
            uint32_t& out_hi, uint32_t& out_lo) noexcept {
            const uint32_t m = static_cast<uint32_t>(sym & 0x3Fu);
            uint32_t hi = 0u;
            for (uint32_t j = 0u; j < 32u; ++j) {
                const uint32_t parity = popc32(m & j) & 1u;
                const uint32_t mask = parity - 1u;  // 0→0xFFFFFFFF, 1→0x00000000
                hi |= mask & (1u << (31u - j));
            }
            uint32_t lo = 0u;
            for (uint32_t j = 32u; j < 64u; ++j) {
                const uint32_t parity = popc32(m & j) & 1u;
                const uint32_t mask = parity - 1u;
                lo |= mask & (1u << (31u - (j - 32u)));
            }
            out_hi = hi;
            out_lo = lo;
        }

        ~Impl() noexcept {
            // [BUG-19] atomic 객체에 memset(SecWipe) 호출 = UB 제거
            //  std::atomic 내부 바이트 직접 조작 금지 (C++ [atomics.types.generic])
            //  atomic API(store)로만 소거 → release fence로 가시성 보장
            current_state.store(0u, std::memory_order_relaxed);
            std::atomic_thread_fence(std::memory_order_release);
        }
    };

    // [BUG-17] Build-time size validation
    HTS64_Tx_Stealth_Engine::Impl*
        HTS64_Tx_Stealth_Engine::get_impl() noexcept {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl exceeds IMPL_BUF_SIZE");
        static_assert(alignof(Impl) <= 8,
            "Impl alignment exceeds impl_buf_");
        return impl_valid_ ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }

    const HTS64_Tx_Stealth_Engine::Impl*
        HTS64_Tx_Stealth_Engine::get_impl() const noexcept {
        return impl_valid_ ? reinterpret_cast<const Impl*>(impl_buf_) : nullptr;
    }

    // =====================================================================
    //  [BUG-17] Constructor: placement new (zero-heap)
    // =====================================================================
    HTS64_Tx_Stealth_Engine::HTS64_Tx_Stealth_Engine(
        uint32_t master_seed) noexcept
        : impl_valid_(false) {
        SecWipe(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl();
        impl_valid_ = true;

        Impl* p = get_impl();
        if (p) {
            p->current_state.store(
                (master_seed == 0u) ? 0xDEADBEEFu : master_seed,
                std::memory_order_relaxed);
        }
    }

    HTS64_Tx_Stealth_Engine::~HTS64_Tx_Stealth_Engine() noexcept {
        Impl* p = get_impl();
        if (p) {
            p->~Impl();
        }
        SecWipe(impl_buf_, sizeof(impl_buf_));
        impl_valid_ = false;
    }

    // =====================================================================
    //  Reseed
    // =====================================================================
    void HTS64_Tx_Stealth_Engine::Reseed(uint32_t epoch_seed) noexcept {
        Impl* p = get_impl();
        if (!p) return;
        p->current_state.store(
            (epoch_seed == 0u) ? 0xDEADBEEFu : epoch_seed,
            std::memory_order_release);
    }

    // =====================================================================
    //  Encode
    // =====================================================================
    HTS64_Tx_Stealth_Engine::TxMaryData
        HTS64_Tx_Stealth_Engine::Encode_64Ary_With_Tensor(
            uint8_t input_6bit) noexcept {

        TxMaryData out_data = { 0u, 0u };
        Impl* p = get_impl();
        if (!p) return out_data;

        uint32_t base_hi = 0u, base_lo = 0u;
        Impl::walsh_encode_romless(input_6bit, base_hi, base_lo);

        const uint32_t key_hi = p->NextState();
        const uint32_t key_lo = p->NextState();

        out_data.chip_HI = base_hi ^ key_hi;
        out_data.chip_LO = base_lo ^ key_lo;

        return out_data;
    }

} // namespace ProtectedEngine