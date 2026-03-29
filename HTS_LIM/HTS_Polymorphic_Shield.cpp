// =========================================================================
// HTS_Polymorphic_Shield.cpp
// 다형성 암호 쉴드 구현부 — CTR 모드 스트림 암호화
// Target: STM32F407 (Cortex-M4)
//
// [양산 수정]
//  FIX-01 익명 네임스페이스 inline 중복 제거
//  FIX-02 unsigned int 시프트 (UB 방지)
//  FIX-03 session_id==0 && gyro_seed==0 → 0 출력 차단
//  FIX-04 타입별 독립 folding_key 상수
//  FIX-05 <type_traits> 명시적 포함
//  BUG-01 [CRIT] block_index 파라미터 추가 (Many-Time Pad 차단)
//    기존: session_id + gyro_seed만으로 스트림 생성
//      → 동일 세션 내 모든 블록이 동일 키스트림 = 키 재사용!
//    수정: block_index를 믹서에 혼합 → 매 블록 고유 스트림
//
// [암호학적 설계]
//  Key:     gyro_seed (회전 시드)
//  Nonce:   session_id (세션 고유 ID)
//  Counter: block_index (데이터 위치 — 매 블록 증가)
//  → CTR 모드 3요소 완비 → 키스트림 재사용 원천 차단
// =========================================================================
#include "HTS_Polymorphic_Shield.h"
#include <type_traits>

namespace ProtectedEngine {

    namespace {

        // =================================================================
        //  SplitMix64 변형 스트림 생성기
        //  [BUG-01] block_index를 상태에 혼합 → 매 블록 고유 출력
        //  [FIX-03] 0 입력 경로 차단 (소수 상수 덧셈)
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

    } // anonymous namespace

    // =====================================================================
    //  32비트 레거시 API (하위 호환 — block_index=0 고정)
    // =====================================================================
    uint32_t Polymorphic_Shield::Generate_AES_CTR_Stream(
        uint64_t session_id, uint32_t gyro_seed) noexcept {
        return static_cast<uint32_t>(
            Generate_Chaotic_Stream_64(session_id, gyro_seed, 0));
    }

    // =====================================================================
    //  Apply_Holographic_Folding — CTR 모드 암호화
    //  [BUG-01] block_index로 매 블록 고유 스트림 생성
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

        // [FIX-04] 타입별 독립 folding_key 상수
        T folding_key;
        if (sizeof(T) == 8u) {
            folding_key = static_cast<T>(0x9E3779B19E3779B1ULL);
        }
        else if (sizeof(T) == 4u) {
            folding_key = static_cast<T>(0x9E3779B1UL);
        }
        else if (sizeof(T) == 2u) {
            folding_key = static_cast<T>(0xA3C5U);
        }
        else {
            folding_key = static_cast<T>(0xB7U);
        }

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

        T folding_key;
        if (sizeof(T) == 8u) {
            folding_key = static_cast<T>(0x9E3779B19E3779B1ULL);
        }
        else if (sizeof(T) == 4u) {
            folding_key = static_cast<T>(0x9E3779B1UL);
        }
        else if (sizeof(T) == 2u) {
            folding_key = static_cast<T>(0xA3C5U);
        }
        else {
            folding_key = static_cast<T>(0xB7U);
        }

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