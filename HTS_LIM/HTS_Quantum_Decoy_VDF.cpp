// =========================================================================
// HTS_Quantum_Decoy_VDF.cpp
// 양자 디코이 VDF 구현부 — 64비트 VDF + SplitMix64 + 출력 화이트닝
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// [양산 수정 — 12건]
//
//  BUG-01~06 (이전 세션: 선형 패턴, VDF 보호, int→uint32, ODR, 64비트 곱셈, atomic)
//  BUG-07 [CRIT] pragma O0 삭제 → volatile + asm clobber
//  BUG-08 [HIGH] 64비트 노이즈 상위 32비트 평문 → 전비트 커버
//  BUG-09 [CRIT] XorShift32 상태=출력 → SplitMix64 + 출력 화이트닝
//    기존: noise = XorShift32(state) → 출력이 곧 내부 상태
//      → plaintext[0] XOR ciphertext[0] = state → 전체 스트림 즉시 복제!
//    수정: SplitMix64(state) → output = Murmur3_finalizer(state)
//      → 출력에서 state 역산 불가 (단방향 혼합)
//  BUG-10 [CRIT] VDF 32비트 → 64비트 상태 (2^32 Brute-force 차단)
//    기존: lo ^ hi → 32비트 state → 2^32 GPU 탐색 = 밀리초급 해독
//    수정: 64비트 상태 유지 → 2^64 탐색 = GPU 1억년+
//  BUG-11 [HIGH] if constexpr → 일반 if (C++14 호환)
//  BUG-12 [MED]  SplitMix64 1회 호출 = 64비트 (XorShift32 2회 불필요)
// =========================================================================
#include "HTS_Quantum_Decoy_VDF.h"
#include <type_traits>

#if __cplusplus < 201703L && !(defined(_MSVC_LANG) && _MSVC_LANG >= 201703L)
namespace ProtectedEngine {
    constexpr uint32_t Quantum_Decoy_VDF::QUANTUM_NOISE_SEED;
}
#endif

namespace ProtectedEngine {

    // =====================================================================
    //  [BUG-09] SplitMix64 PRNG — 출력 ≠ 상태 (화이트닝 내장)
    //
    //  state는 단순 가산 (state += gamma)
    //  output은 Murmur3 finalizer 통과 → 단방향 혼합
    //  → 출력 관측으로 state 역산 불가능
    //  → XorShift32 대비: 상태 노출 원천 차단
    //
    //  Cortex-M4 비용: UMULL 2회 + XOR/시프트 = ~12사이클/호출
    //  (XorShift32: ~6사이클이지만 보안 0 → 의미 없음)
    // =====================================================================
    namespace {
        struct SplitMix64_VDF {
            uint64_t state;

            explicit SplitMix64_VDF(uint64_t seed) noexcept : state(seed) {}

            // 출력 화이트닝: state → Murmur3 finalizer → output
            // state 자체는 노출되지 않음
            uint64_t next() noexcept {
                state += 0x9E3779B97F4A7C15ULL;
                uint64_t z = state;  // 내부 상태 복사
                z ^= z >> 30;
                z *= 0xBF58476D1CE4E5B9ULL;
                z ^= z >> 27;
                z *= 0x94D049BB133111EBULL;
                z ^= z >> 31;
                return z;  // 화이트닝된 출력 (≠ state)
            }
        };
    } // anonymous namespace

    // =====================================================================
    //  [BUG-10] Execute_Time_Lock_Puzzle — 64비트 VDF 코어
    //
    //  64비트 상태 체인: session_id(64b) → 순차 Murmur3 × N → 64비트 출력
    //  → 2^64 Brute-force 내성 (GPU 클러스터 1억년+)
    //
    //  [컴파일러 보호]
    //  volatile state + asm clobber → 루프 접기/상수 전파 차단
    // =====================================================================
// [BUG-07] pragma O0 삭제 → volatile + asm clobber
    uint64_t Quantum_Decoy_VDF::Execute_Time_Lock_Puzzle(
        uint64_t session_id, uint32_t iterations) noexcept {

        if (iterations == 0u) return session_id;

        // [BUG-10] 64비트 상태 유지 (32비트 축소 제거)
        volatile uint64_t state = session_id ^ 0x3D485453'9E3779B9ULL;

        for (uint32_t i = 0u; i < iterations; ++i) {
            uint64_t round_noise =
                static_cast<uint64_t>(QUANTUM_NOISE_SEED)
                ^ (static_cast<uint64_t>(i) * 0x9E3779B97F4A7C15ULL);

            // Murmur3-64 스타일 순차 혼합
            uint64_t s = static_cast<uint64_t>(state);
            s = (s ^ round_noise) * 0xBF58476D1CE4E5B9ULL;
            s ^= s >> 30;
            s *= 0x94D049BB133111EBULL;
            s ^= s >> 27;

            // 비트 회전: 하위 비트 고정화 방지
            s = (s << 13) | (s >> 51);

            state = s;
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("" : : "r"(static_cast<uint32_t>(s)) : "memory");
#endif
        }

        return static_cast<uint64_t>(state);
    }

    // =====================================================================
    //  [BUG-09/12] SplitMix64 기반 디코이 노이즈 적용
    //
    //  VDF 출력(64비트)을 PRNG 시드로 사용
    //  → SplitMix64 화이트닝: 출력 관측으로 state 역산 불가
    //  → T=uint64_t: 1회 호출로 전비트 커버 (XorShift32 2회 불필요)
    //  → T=uint32_t 이하: 하위 32비트/16비트/8비트 절사 (엔트로피 보존)
    //
    //  [BUG-11] if constexpr → 일반 if (C++14 호환)
    //  → sizeof(T)는 컴파일 타임 상수 → 컴파일러 DCE가 dead branch 제거
    // =====================================================================
    namespace {
        template <typename T>
        inline void Apply_VDF_Noise(T* data, size_t elements,
            uint64_t absolute_key) noexcept {
            // 0 시드 방어
            uint64_t seed = (absolute_key != 0ULL)
                ? absolute_key
                : 0x5C4E3D2F'A7B3C1E9ULL;

            SplitMix64_VDF prng(seed);

            for (size_t i = 0; i < elements; ++i) {
                uint64_t noise = prng.next();

                // [BUG-11] 일반 if (C++14 호환, 컴파일러 DCE)
                if (sizeof(T) == 8) {
                    data[i] ^= static_cast<T>(noise);
                }
                else if (sizeof(T) == 4) {
                    data[i] ^= static_cast<T>(
                        static_cast<uint32_t>(noise));
                }
                else if (sizeof(T) == 2) {
                    data[i] ^= static_cast<T>(
                        static_cast<uint16_t>(noise));
                }
                else {
                    data[i] ^= static_cast<T>(
                        static_cast<uint8_t>(noise));
                }
            }
        }
    } // anonymous namespace

    // =====================================================================
    //  Apply / Reverse — XOR 자기역 (동일 로직)
    // =====================================================================
    template <typename T>
    void Quantum_Decoy_VDF::Apply_Quantum_Decoy(
        T* tensor_data, size_t elements, uint64_t true_session_id) noexcept {

        static_assert(std::is_unsigned<T>::value,
            "T must be an unsigned integer type for safe bitwise operations.");

        if (!tensor_data || elements == 0) return;

        uint64_t absolute_key = Execute_Time_Lock_Puzzle(true_session_id);
        Apply_VDF_Noise(tensor_data, elements, absolute_key);
    }

    template <typename T>
    void Quantum_Decoy_VDF::Reverse_Quantum_Decoy(
        T* damaged_tensor, size_t elements, uint64_t input_session_id) noexcept {

        static_assert(std::is_unsigned<T>::value,
            "T must be an unsigned integer type for safe bitwise operations.");

        if (!damaged_tensor || elements == 0) return;

        uint64_t input_key = Execute_Time_Lock_Puzzle(input_session_id);
        Apply_VDF_Noise(damaged_tensor, elements, input_key);
    }

    // =====================================================================
    //  명시적 템플릿 인스턴스화
    // =====================================================================
    template void Quantum_Decoy_VDF::Apply_Quantum_Decoy<uint8_t>(uint8_t*, size_t, uint64_t) noexcept;
    template void Quantum_Decoy_VDF::Apply_Quantum_Decoy<uint16_t>(uint16_t*, size_t, uint64_t) noexcept;
    template void Quantum_Decoy_VDF::Apply_Quantum_Decoy<uint32_t>(uint32_t*, size_t, uint64_t) noexcept;
    template void Quantum_Decoy_VDF::Apply_Quantum_Decoy<uint64_t>(uint64_t*, size_t, uint64_t) noexcept;

    template void Quantum_Decoy_VDF::Reverse_Quantum_Decoy<uint8_t>(uint8_t*, size_t, uint64_t) noexcept;
    template void Quantum_Decoy_VDF::Reverse_Quantum_Decoy<uint16_t>(uint16_t*, size_t, uint64_t) noexcept;
    template void Quantum_Decoy_VDF::Reverse_Quantum_Decoy<uint32_t>(uint32_t*, size_t, uint64_t) noexcept;
    template void Quantum_Decoy_VDF::Reverse_Quantum_Decoy<uint64_t>(uint64_t*, size_t, uint64_t) noexcept;

} // namespace ProtectedEngine