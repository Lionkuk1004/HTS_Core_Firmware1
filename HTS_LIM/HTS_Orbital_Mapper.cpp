// =========================================================================
// HTS_Orbital_Mapper.cpp
// 파울리 배타 원리 기반 LCM 2D 직교 인터리버 + 오비탈 텐서 폴딩
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
#include "HTS_Orbital_Mapper.hpp"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#if (HTS_ORBITAL_MAPPER_ARM == 0)
#include <vector>
#endif

namespace ProtectedEngine {

    // =====================================================================
    //  보안 소거 — volatile void* + asm clobber (DCE 차단)
    // =====================================================================
    static void Secure_Wipe_Orbital(volatile void* ptr, size_t size) noexcept {
        if (!ptr || size == 0) return;
        volatile unsigned char* p =
            static_cast<volatile unsigned char*>(ptr);
        for (size_t i = 0; i < size; ++i) p[i] = 0;
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#elif defined(_MSC_VER)
        _ReadWriteBarrier();
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  state_map 범위 검증
    // =====================================================================
#if (HTS_ORBITAL_MAPPER_ARM == 0)
    static bool Validate_State_Map(
        const std::vector<uint32_t>& state_map, size_t tensor_size) noexcept {
        for (size_t i = 0; i < state_map.size(); ++i) {
            if (state_map[i] >= static_cast<uint32_t>(tensor_size))
                return false;
        }
        return true;
    }
#endif

    // =====================================================================
    //  크로스 플랫폼 결정적: GCC/MSVC/Clang 동일 출력 보장
    // =====================================================================
    namespace {
        // MAX_H×W = 256×60 = 15360 — scatter/gather 상한과 일치
        static constexpr size_t MAX_PERM_N = 15360u;
        static constexpr size_t BITMAP_WORDS = (MAX_PERM_N + 31u) / 32u;  // 480

        // 스택 1KB+ 방지 — BSS 단일 버퍼(병렬 호출 시 호출부에서 직렬화 필요)
        static uint32_t g_visited_bitmap[BITMAP_WORDS];

        struct SplitMix64 {
            uint64_t state;
            explicit SplitMix64(uint64_t seed) noexcept : state(seed) {}

            uint64_t next() noexcept {
                state += 0x9E3779B97F4A7C15ULL;
                uint64_t z = state;
                z ^= z >> 30;
                z *= 0xBF58476D1CE4E5B9ULL;
                z ^= z >> 27;
                z *= 0x94D049BB133111EBULL;
                z ^= z >> 31;
                return z;
            }

            /// [0, bound) 균등 근사 — Lemire식 (r*bound)>>32, UMULL만 사용
            uint32_t bounded_u32(uint32_t bound) noexcept {
                const uint64_t z = next();
                const uint32_t r =
                    static_cast<uint32_t>(z ^ (z >> 32));
                const uint64_t prod =
                    static_cast<uint64_t>(r) * static_cast<uint64_t>(bound);
                return static_cast<uint32_t>(prod >> 32);
            }

            void fisher_yates(uint32_t* arr, uint32_t n) noexcept {
                if (n <= 1u) { return; }
                for (uint32_t i = n - 1u; i > 0u; --i) {
                    const uint32_t j = bounded_u32(i + 1u);
                    const uint32_t tmp =
                        arr[static_cast<size_t>(i)];
                    arr[static_cast<size_t>(i)] =
                        arr[static_cast<size_t>(j)];
                    arr[static_cast<size_t>(j)] = tmp;
                }
            }
        };

        static inline void bmp_clear(uint32_t* bmp, size_t n_bits) noexcept {
            // ⑨ /32u → >>5u
            const size_t words = (n_bits + 31u) >> 5u;
            std::memset(bmp, 0, words * sizeof(uint32_t));
        }
        static inline bool bmp_test(const uint32_t* bmp, size_t idx) noexcept {
            const size_t wi = static_cast<size_t>(idx >> 5u);
            return (bmp[wi] & (1u << (idx & 31u))) != 0u;
        }
        static inline void bmp_set(uint32_t* bmp, size_t idx) noexcept {
            const size_t wi = static_cast<size_t>(idx >> 5u);
            bmp[wi] |= (1u << (idx & 31u));
        }

        bool inplace_scatter(
            uint32_t* tensor,
            const uint32_t* map,
            size_t n) noexcept {
            if (n > MAX_PERM_N) return false;

            bmp_clear(g_visited_bitmap, n);

            for (size_t i = 0; i < n; ++i) {
                if (bmp_test(g_visited_bitmap, i)) continue;
                if (map[static_cast<size_t>(i)] == static_cast<uint32_t>(i)) {
                    bmp_set(g_visited_bitmap, i);
                    continue;
                }

                uint32_t saved = tensor[static_cast<size_t>(i)];
                size_t dst = static_cast<size_t>(map[static_cast<size_t>(i)]);
                bmp_set(g_visited_bitmap, i);

                size_t steps = 0;
                while (dst != i) {
                    if (++steps > n) return false;
                    uint32_t tmp = tensor[dst];
                    tensor[dst] = saved;
                    saved = tmp;
                    bmp_set(g_visited_bitmap, dst);
                    dst = static_cast<size_t>(map[dst]);
                }
                tensor[static_cast<size_t>(i)] = saved;
            }
            return true;
        }

        bool inplace_gather(
            uint32_t* tensor,
            const uint32_t* map,
            size_t n) noexcept {
            if (n > MAX_PERM_N) return false;

            bmp_clear(g_visited_bitmap, n);

            for (size_t i = 0; i < n; ++i) {
                if (bmp_test(g_visited_bitmap, i)) continue;
                if (map[static_cast<size_t>(i)] == static_cast<uint32_t>(i)) {
                    bmp_set(g_visited_bitmap, i);
                    continue;
                }

                uint32_t saved = tensor[static_cast<size_t>(i)];
                size_t cur = i;
                bmp_set(g_visited_bitmap, cur);

                size_t src = static_cast<size_t>(map[cur]);
                size_t steps = 0;
                while (src != i) {
                    if (++steps > n) return false;
                    tensor[cur] = tensor[src];
                    bmp_set(g_visited_bitmap, src);
                    cur = src;
                    src = static_cast<size_t>(map[cur]);
                }
                tensor[cur] = saved;
            }
            return true;
        }

    } // anonymous namespace

    // =====================================================================
    //  [1] 파울리 배타 원리 기반 양자 상태 지도
    // =====================================================================
#if (HTS_ORBITAL_MAPPER_ARM == 0)
    std::vector<uint32_t> Orbital_Mapper::Generate_Pauli_State_Map(
        size_t tensor_size, uint64_t pqc_session_id) noexcept {
        std::vector<uint32_t> state_map(tensor_size);
        // PENDING: 반환 타입 vector는 호출자 API 호환 유지
        //          raw API(Generate_Pauli_State_Map_Raw) 추가 후 전환 예정

        if (tensor_size <= 60) {
            for (size_t i = 0; i < tensor_size; ++i) {
                state_map[static_cast<size_t>(i)] =
                    static_cast<uint32_t>(i);
            }
            return state_map;
        }

        SplitMix64 rng(pqc_session_id);

        static constexpr uint32_t W = 60u;
        static constexpr uint32_t MAX_H = 256u;
        const uint32_t H = static_cast<uint32_t>(
            (tensor_size + W - 1u) / W);
        if (H > MAX_H) {
            //  state_map은 항등 순열로 채운 뒤 반환 (영벡터 매핑 붕괴 방지)
            for (size_t i = 0u; i < tensor_size; ++i) {
                state_map[i] = static_cast<uint32_t>(i);
            }
            return state_map;
        }

        uint32_t block_shuffle[MAX_H];
        uint32_t offset_shuffle[W];

        for (uint32_t i = 0u; i < H; ++i) {
            block_shuffle[static_cast<size_t>(i)] = i;
        }
        rng.fisher_yates(block_shuffle, H);

        for (uint32_t i = 0u; i < W; ++i) {
            offset_shuffle[static_cast<size_t>(i)] = i;
        }
        rng.fisher_yates(offset_shuffle, W);

        uint32_t physical_pos = 0u;

        for (uint32_t o_idx = 0u; o_idx < W; ++o_idx) {
            const uint32_t offset =
                offset_shuffle[static_cast<size_t>(o_idx)];
            for (uint32_t b_idx = 0u; b_idx < H; ++b_idx) {
                const uint32_t block =
                    block_shuffle[static_cast<size_t>(b_idx)];
                const uint64_t logical_index =
                    static_cast<uint64_t>(block) * static_cast<uint64_t>(W)
                    + static_cast<uint64_t>(offset);

                if (logical_index < static_cast<uint64_t>(tensor_size)) {
                    state_map[static_cast<size_t>(logical_index)] =
                        physical_pos++;
                }
            }
        }

        return state_map;
    }

    // =====================================================================
    //  [2] 오비탈 텐서 폴딩 (정방향: Scatter)
    // =====================================================================
    void Orbital_Mapper::Apply_Orbital_Clouding(
        std::vector<uint32_t>& tensor,
        const std::vector<uint32_t>& state_map) noexcept {

        if (tensor.size() != state_map.size() || tensor.empty()) return;

        if (!Validate_State_Map(state_map, tensor.size())) {
            Secure_Wipe_Orbital(tensor.data(),
                tensor.size() * sizeof(uint32_t));
            tensor.clear();
            return;
        }

        if (!inplace_scatter(tensor.data(), state_map.data(), tensor.size())) {
            Secure_Wipe_Orbital(tensor.data(),
                tensor.size() * sizeof(uint32_t));
            tensor.clear();
        }
    }

    // =====================================================================
    //  [3] 오비탈 파동 함수 수렴 (역방향: Gather)
    // =====================================================================
    void Orbital_Mapper::Reverse_Orbital_Collapse(
        std::vector<uint32_t>& tensor,
        const std::vector<uint32_t>& state_map) noexcept {

        if (tensor.size() != state_map.size() || tensor.empty()) return;

        if (!Validate_State_Map(state_map, tensor.size())) {
            Secure_Wipe_Orbital(tensor.data(),
                tensor.size() * sizeof(uint32_t));
            tensor.clear();
            return;
        }

        if (!inplace_gather(tensor.data(), state_map.data(), tensor.size())) {
            Secure_Wipe_Orbital(tensor.data(),
                tensor.size() * sizeof(uint32_t));
            tensor.clear();
        }
    }
#endif

    // =====================================================================
    //
    //  vector API는 하위 호환을 위해 유지.
    //  raw 포인터 API는 BB1_Core_Engine 정적 배열 경로와 일치
    //  전환에 따라 vector 래핑 없이 inplace_scatter/gather 직접 호출.
    //
    //  Fail-Closed: 실패 시 memset(0) 보안 소거 (vector.clear() 불필요)
    // =====================================================================

    /// @brief state_map 범위 검증 (raw 포인터)
    static bool Validate_State_Map_Raw(
        const uint32_t* state_map, size_t map_size,
        size_t tensor_size) noexcept {
        for (size_t i = 0u; i < map_size; ++i) {
            if (state_map[i] >= static_cast<uint32_t>(tensor_size))
                return false;
        }
        return true;
    }

    void Orbital_Mapper::Apply_Orbital_Clouding(
        uint32_t* tensor, size_t t_size,
        const uint32_t* state_map, size_t m_size) noexcept {

        if (!tensor || !state_map || t_size == 0u || t_size != m_size)
            return;

        if (!Validate_State_Map_Raw(state_map, m_size, t_size)) {
            Secure_Wipe_Orbital(tensor, t_size * sizeof(uint32_t));
            return;
        }

        if (!inplace_scatter(tensor, state_map, t_size)) {
            Secure_Wipe_Orbital(tensor, t_size * sizeof(uint32_t));
        }
    }

    void Orbital_Mapper::Reverse_Orbital_Collapse(
        uint32_t* tensor, size_t t_size,
        const uint32_t* state_map, size_t m_size) noexcept {

        if (!tensor || !state_map || t_size == 0u || t_size != m_size)
            return;

        if (!Validate_State_Map_Raw(state_map, m_size, t_size)) {
            Secure_Wipe_Orbital(tensor, t_size * sizeof(uint32_t));
            return;
        }

        if (!inplace_gather(tensor, state_map, t_size)) {
            Secure_Wipe_Orbital(tensor, t_size * sizeof(uint32_t));
        }
    }

} // namespace ProtectedEngine
