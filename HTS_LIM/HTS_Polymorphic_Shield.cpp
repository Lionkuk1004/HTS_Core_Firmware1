// =========================================================================
// HTS_Polymorphic_Shield.cpp
// 다형성 암호 쉴드 구현부 — CTR 모드 스트림 암호화
// Target: STM32F407 (Cortex-M4)
//
#include "HTS_Polymorphic_Shield.h"
#include <type_traits>

namespace ProtectedEngine {

    namespace {

        // =================================================================
        //  SplitMix64 변형 스트림 생성기
        // =================================================================
        uint64_t Generate_Chaotic_Stream_64(
            uint64_t session_id,
            uint32_t gyro_seed,
            uint32_t block_index) noexcept {

            // CTR 3요소 혼합: Key(gyro_seed) + Nonce(session_id) + Counter(block_index)
            uint64_t state = (session_id + 0x9E3779B97F4A7C15ULL)
                ^ (static_cast<uint64_t>(gyro_seed) * 0x6C62272E07BB0142ULL)
                ^ (static_cast<uint64_t>(block_index) * 0x517CC1B727220A95ULL);

            // SplitMix64 Avalanche 믹서
            state ^= state >> 33;
            state *= 0xFF51AFD7ED558CCDULL;
            state ^= state >> 33;
            state *= 0xC4CEB9FE1A85EC53ULL;
            state ^= state >> 33;
            return state;
        }

        template <typename T>
        constexpr T Get_Folding_Key() noexcept {
            static_assert(std::is_unsigned<T>::value,
                "T must be an unsigned type for folding key.");

            return (sizeof(T) == 8u) ? static_cast<T>(0x9E3779B19E3779B1ULL) :
                (sizeof(T) == 4u) ? static_cast<T>(0x9E3779B1UL) :
                (sizeof(T) == 2u) ? static_cast<T>(0xA3C5U) :
                static_cast<T>(0xB7U);
        }

    } // anonymous namespace

    // =====================================================================
    //  32비트 레거시 API (하위 호환 — block_index=0 고정)
    // =====================================================================
    uint32_t Polymorphic_Shield::Generate_AES_CTR_Stream(
        uint64_t session_id, uint32_t gyro_seed) noexcept {
        return static_cast<uint32_t>(
            Generate_Chaotic_Stream_64(session_id, gyro_seed, static_cast<uint32_t>(0u)));
    }

    // =====================================================================
    //  Apply_Holographic_Folding — CTR 모드 암호화
    // =====================================================================
    template <typename T>
    T Polymorphic_Shield::Apply_Holographic_Folding(
        T data, uint32_t gyro_seed,
        uint64_t session_id, uint32_t block_index) noexcept {

        static_assert(std::is_unsigned<T>::value,
            "T must be an unsigned type for safe bitwise shift.");

        T dynamic_stream = static_cast<T>(
            Generate_Chaotic_Stream_64(session_id, gyro_seed, block_index));
        T folded = static_cast<T>(data ^ dynamic_stream);

        const unsigned int bit_width = sizeof(T) * 8u;
        const unsigned int shift = 13u % bit_width;

        if (shift > 0u) {
            folded = static_cast<T>(
                (folded << shift) | (folded >> (bit_width - shift)));
        }

        const T folding_key = Get_Folding_Key<T>();
        return static_cast<T>(folded ^ folding_key);
    }

    // =====================================================================
    //  Reverse_Holographic_Folding — CTR 모드 복호화 (Apply 정확한 역순)
    // =====================================================================
    template <typename T>
    T Polymorphic_Shield::Reverse_Holographic_Folding(
        T folded_data, uint32_t gyro_seed,
        uint64_t session_id, uint32_t block_index) noexcept {

        static_assert(std::is_unsigned<T>::value,
            "T must be an unsigned type for safe bitwise shift.");

        const T folding_key = Get_Folding_Key<T>();
        T unfolded = static_cast<T>(folded_data ^ folding_key);

        const unsigned int bit_width = sizeof(T) * 8u;
        const unsigned int shift = 13u % bit_width;

        if (shift > 0u) {
            unfolded = static_cast<T>(
                (unfolded >> shift) | (unfolded << (bit_width - shift)));
        }

        T dynamic_stream = static_cast<T>(
            Generate_Chaotic_Stream_64(session_id, gyro_seed, block_index));
        return static_cast<T>(unfolded ^ dynamic_stream);
    }

    // =====================================================================
    //  명시적 템플릿 인스턴스화
    // =====================================================================
    template uint8_t  Polymorphic_Shield::Apply_Holographic_Folding<uint8_t>(uint8_t, uint32_t, uint64_t, uint32_t);
    template uint16_t Polymorphic_Shield::Apply_Holographic_Folding<uint16_t>(uint16_t, uint32_t, uint64_t, uint32_t);
    template uint32_t Polymorphic_Shield::Apply_Holographic_Folding<uint32_t>(uint32_t, uint32_t, uint64_t, uint32_t);
    template uint64_t Polymorphic_Shield::Apply_Holographic_Folding<uint64_t>(uint64_t, uint32_t, uint64_t, uint32_t);

    template uint8_t  Polymorphic_Shield::Reverse_Holographic_Folding<uint8_t>(uint8_t, uint32_t, uint64_t, uint32_t);
    template uint16_t Polymorphic_Shield::Reverse_Holographic_Folding<uint16_t>(uint16_t, uint32_t, uint64_t, uint32_t);
    template uint32_t Polymorphic_Shield::Reverse_Holographic_Folding<uint32_t>(uint32_t, uint32_t, uint64_t, uint32_t);
    template uint64_t Polymorphic_Shield::Reverse_Holographic_Folding<uint64_t>(uint64_t, uint32_t, uint64_t, uint32_t);

} // namespace ProtectedEngine
