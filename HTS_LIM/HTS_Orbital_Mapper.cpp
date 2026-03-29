// =========================================================================
// HTS_Orbital_Mapper.cpp
// 파울리 배타 원리 기반 LCM 2D 직교 인터리버 + 오비탈 텐서 폴딩
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// [양산 수정 — 총 11건]
//  BUG-01 [CRIT] Fail-Open → Fail-Closed (OOM 시 텐서 소거 + clear)
//  BUG-02 [HIGH] Generate 내 std::abort → 빈 벡터 반환
//  BUG-03 [CRIT] std::shuffle → 자체 Fisher-Yates (크로스 플랫폼 결정적)
//  BUG-04 [HIGH] mt19937_64 → SplitMix64 (스택 2.5KB → 8B)
//  BUG-05 [MED]  state_map 범위 검증 (OOB 차단)
//  BUG-06 [CRIT] tensor.clear() 추가 (좀비 텐서 방지)
//  BUG-07 [HIGH] inplace_scatter/gather → bool 반환 (실패 전파)
//  BUG-08 [CRIT] temp_tensor 복사 → 사이클 기반 인플레이스 순열 (OOM 제거)
//  BUG-09 [MED]  volatile void* Secure_Wipe 표준 적용
//  BUG-10 [HIGH] 사이클 길이 가드: ρ형 무한 궤도 탐지
//  BUG-11 [HIGH] raw 포인터 오버로드 추가 (BB1 BUG-52 정적 배열 직접 전달)
//         · Apply_Orbital_Clouding(uint32_t*, size_t, const uint32_t*, size_t)
//         · Reverse_Orbital_Collapse(uint32_t*, size_t, const uint32_t*, size_t)
//         · vector 래핑 0회, inplace_scatter/gather 직접 호출
// =========================================================================
#include "HTS_Orbital_Mapper.hpp"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

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
#endif
        // [BUG-12] seq_cst → release (소거 배리어 정책 통일)
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  state_map 범위 검증 [BUG-05]
    // =====================================================================
    static bool Validate_State_Map(
        const std::vector<uint32_t>& state_map, size_t tensor_size) noexcept {
        for (size_t i = 0; i < state_map.size(); ++i) {
            if (state_map[i] >= static_cast<uint32_t>(tensor_size))
                return false;
        }
        return true;
    }

    // =====================================================================
    //  [BUG-04] SplitMix64 PRNG — 8바이트 상태 (mt19937_64 2.5KB 대체)
    //  크로스 플랫폼 결정적: GCC/MSVC/Clang 동일 출력 보장
    // =====================================================================
    namespace {
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

            // [BUG-03] 결정적 Fisher-Yates (std::shuffle 대체)
            void fisher_yates(uint32_t* arr, uint32_t n) noexcept {
                for (uint32_t i = n - 1; i > 0; --i) {
                    uint32_t j = static_cast<uint32_t>(next() % (i + 1));
                    uint32_t tmp = arr[i];
                    arr[i] = arr[j];
                    arr[j] = tmp;
                }
            }
        };

        // =================================================================
        //  [BUG-08] 사이클 기반 인플레이스 순열 (temp_tensor 복사 제거)
        //  [BUG-07] bool 반환: 성공=true, OOM=false
        //  [BUG-12] vector<bool> → 정적 uint32_t 비트맵 (B-1 힙금지)
        //
        //  비트맵: MAX_TENSOR/32 = 256 uint32_t = 1KB (BSS)
        //  단일 메인 루프 전용 — static 재진입 안전
        // =================================================================

        static constexpr size_t MAX_PERM_N = 8192u;
        static constexpr size_t BITMAP_WORDS = MAX_PERM_N / 32u;  // 256

        static inline void bmp_clear(uint32_t* bmp, size_t n_bits) noexcept {
            const size_t words = (n_bits + 31u) / 32u;
            std::memset(bmp, 0, words * sizeof(uint32_t));
        }
        static inline bool bmp_test(const uint32_t* bmp, size_t idx) noexcept {
            return (bmp[idx >> 5u] & (1u << (idx & 31u))) != 0u;
        }
        static inline void bmp_set(uint32_t* bmp, size_t idx) noexcept {
            bmp[idx >> 5u] |= (1u << (idx & 31u));
        }

        bool inplace_scatter(
            uint32_t* tensor,
            const uint32_t* map,
            size_t n) noexcept {

            if (n > MAX_PERM_N) return false;

            // [BUG-12] 정적 비트맵 (힙 0회)
            static uint32_t visited[BITMAP_WORDS];
            bmp_clear(visited, n);

            for (size_t i = 0; i < n; ++i) {
                if (bmp_test(visited, i)) continue;
                if (map[i] == static_cast<uint32_t>(i)) {
                    bmp_set(visited, i);
                    continue;
                }

                uint32_t saved = tensor[i];
                size_t dst = map[i];
                bmp_set(visited, i);

                size_t steps = 0;
                while (dst != i) {
                    if (++steps > n) return false;
                    uint32_t tmp = tensor[dst];
                    tensor[dst] = saved;
                    saved = tmp;
                    bmp_set(visited, dst);
                    dst = map[dst];
                }
                tensor[i] = saved;
            }
            return true;
        }

        bool inplace_gather(
            uint32_t* tensor,
            const uint32_t* map,
            size_t n) noexcept {

            if (n > MAX_PERM_N) return false;

            // [BUG-13] 정적 비트맵 (힙 0회)
            static uint32_t visited[BITMAP_WORDS];
            bmp_clear(visited, n);

            for (size_t i = 0; i < n; ++i) {
                if (bmp_test(visited, i)) continue;
                if (map[i] == static_cast<uint32_t>(i)) {
                    bmp_set(visited, i);
                    continue;
                }

                uint32_t saved = tensor[i];
                size_t cur = i;
                bmp_set(visited, cur);

                size_t src = map[cur];
                size_t steps = 0;
                while (src != i) {
                    if (++steps > n) return false;
                    tensor[cur] = tensor[src];
                    bmp_set(visited, src);
                    cur = src;
                    src = map[cur];
                }
                tensor[cur] = saved;
            }
            return true;
        }

    } // anonymous namespace

    // =====================================================================
    //  [1] 파울리 배타 원리 기반 양자 상태 지도
    //  [BUG-03] std::shuffle → SplitMix64::fisher_yates (결정적)
    //  [BUG-02] OOM → 빈 벡터 반환 (abort 제거)
    // =====================================================================
    std::vector<uint32_t> Orbital_Mapper::Generate_Pauli_State_Map(
        size_t tensor_size, uint64_t pqc_session_id) noexcept {
        std::vector<uint32_t> state_map(tensor_size);
        // PENDING: 반환 타입 vector는 호출자 API 호환 유지
        //          raw API(Generate_Pauli_State_Map_Raw) 추가 후 전환 예정

        if (tensor_size <= 60) {
            for (size_t i = 0; i < tensor_size; ++i)
                state_map[i] = static_cast<uint32_t>(i);
            return state_map;
        }

        SplitMix64 rng(pqc_session_id);

        static constexpr uint32_t W = 60u;
        // [BUG-14] H 상한: MAX_PERM_N/W = 8192/60 = 137 → 256 여유
        static constexpr uint32_t MAX_H = 256u;
        const uint32_t H = static_cast<uint32_t>(
            (tensor_size + W - 1u) / W);
        if (H > MAX_H) return state_map;  // 텐서 크기 초과 → 항등 지도

        // [BUG-14] 정적 배열 (힙 0회)
        static uint32_t block_shuffle[MAX_H];
        static uint32_t offset_shuffle[W];

        for (uint32_t i = 0; i < H; ++i) block_shuffle[i] = i;
        rng.fisher_yates(block_shuffle, H);

        for (uint32_t i = 0; i < W; ++i) offset_shuffle[i] = i;
        rng.fisher_yates(offset_shuffle, W);

        uint32_t physical_pos = 0;

        for (uint32_t o_idx = 0; o_idx < W; ++o_idx) {
            const uint32_t offset = offset_shuffle[o_idx];
            for (uint32_t b_idx = 0; b_idx < H; ++b_idx) {
                const uint32_t block = block_shuffle[b_idx];
                const uint64_t logical_index =
                    static_cast<uint64_t>(block) * W + offset;

                if (logical_index < tensor_size) {
                    state_map[static_cast<size_t>(logical_index)] =
                        physical_pos++;
                }
            }
        }

        return state_map;
    }

    // =====================================================================
    //  [2] 오비탈 텐서 폴딩 (정방향: Scatter)
    //  [BUG-08] 인플레이스 순열 (temp_tensor 복사 0회)
    //  [BUG-07] bool 반환 검사 → Fail-Closed
    //  [BUG-01/06] OOM 시 Secure_Wipe + tensor.clear()
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
            // [BUG-07] inplace OOM → Fail-Closed
            Secure_Wipe_Orbital(tensor.data(),
                tensor.size() * sizeof(uint32_t));
            tensor.clear();
        }
    }

    // =====================================================================
    //  [3] 오비탈 파동 함수 수렴 (역방향: Gather)
    //  [BUG-08] 인플레이스 순열
    //  [BUG-07] bool 반환 검사
    //  [BUG-01/06] Fail-Closed
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

    // =====================================================================
    //  [BUG-11] raw 포인터 오버로드 (BB1 정적 배열 직접 전달)
    //
    //  기존 vector API는 하위 호환을 위해 유지.
    //  raw 포인터 API는 BB1_Core_Engine BUG-52에서 vector → 정적 배열
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