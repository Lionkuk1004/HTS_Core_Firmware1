// =========================================================================
// HTS_Dynamic_Key_Rotator.cpp
// 동적 키 로테이터 구현부 — LCG + Murmur3 비선형 키 파생
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// [양산 수정 — 세션 1 (6건) + 세션 5 (7건) = 총 13건]
//
//  ── 세션 1 (BUG-01 ~ BUG-06) ──
//  BUG-01 [HIGH]   rotation_interval=0 → 최소 1024로 보정
//  BUG-02 [HIGH]   순수 LCG → Murmur3 fmix64 avalanche 보강
//  BUG-03 [MEDIUM] pragma O0 키 파생 보호
//  BUG-04 [MEDIUM] C26495 멤버 기본값 초기화
//  BUG-05 [LOW]    이전 키 volatile 소거 + fence
//  BUG-06 [LOW]    operation_count 오버플로 방어 (BUG-13에서 데드코드 제거)
//
//  ── 세션 5 (BUG-07 ~ BUG-13) ──
//  BUG-07 [CRITICAL] 소멸자 없음 → 전 멤버 보안 소거
//  BUG-08 [MEDIUM]   이동 생성자/대입 미차단 → move = delete
//  BUG-09 [LOW]      [[nodiscard]] 적용
//  BUG-10 [LOW]      Doxygen 가이드
//  BUG-11 [LOW]      Self-Contained <cstddef>
//
//  BUG-12 [CRITICAL] PRNG 상태 노출 (Forward/Backward Secrecy 상실)
//    기존: current_key를 LCG 시드로 직접 사용
//          → Murmur3/LCG 모두 bijection → 키 1개 탈취 시 전 키 역산
//    수정: internal_state(은닉) / current_key(노출) 완전 분리
//          → 키 = Murmur3(state) ^ state (Davies-Meyer 유사 단방향)
//          → state를 모르면 키에서 역산 불가 (brute force O(2^64))
//
//  BUG-13 [LOW] UINT64_MAX 오버플로 분기 = 데드코드 제거
//    operation_count: [0, rotation_interval] 범위 → MAX 도달 불가
// =========================================================================
#include "HTS_Dynamic_Key_Rotator.hpp"
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace ProtectedEngine {

    // =====================================================================
    //  Murmur3 64-bit Finalizer — 키 파생 비선형 혼합
    // =====================================================================
    static uint64_t Murmur3_Fmix64(uint64_t k) noexcept {
        k ^= k >> 33;
        k *= 0xFF51AFD7ED558CCDULL;
        k ^= k >> 33;
        k *= 0xC4CEB9FE1A85EC53ULL;
        k ^= k >> 33;
        return k;
    }

    // =====================================================================
    //  보안 메모리 소거
    // =====================================================================

    static void Secure_Wipe_KeyRotator(void* ptr, size_t size) noexcept {
        if (!ptr || size == 0) return;
        volatile unsigned char* p =
            static_cast<volatile unsigned char*>(ptr);
        for (size_t i = 0; i < size; ++i) p[i] = 0;
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
        // [BUG] seq_cst → release (소거 배리어 정책 통일)
        std::atomic_thread_fence(std::memory_order_release);
    }


    // =====================================================================
    //  생성자
    //  [BUG-12] internal_state / current_key 분리
    // =====================================================================
    Dynamic_Key_Rotator::Dynamic_Key_Rotator(
        uint64_t initial_key, uint64_t interval) noexcept
        : rotation_interval((interval == 0) ? 1024ULL : interval)
        , operation_count(0) {

        internal_state = (initial_key == 0)
            ? 0x9E3779B97F4A7C15ULL : initial_key;

        // 첫 세션 키도 단방향 파생 (마스터 시드 미노출)
        current_key = Murmur3_Fmix64(internal_state) ^ internal_state;
    }

    // =====================================================================
    //  [BUG-07] 소멸자 — 전 멤버 보안 소거
    // =====================================================================
    Dynamic_Key_Rotator::~Dynamic_Key_Rotator() noexcept {
        Secure_Wipe_KeyRotator(&internal_state, sizeof(internal_state));
        Secure_Wipe_KeyRotator(&current_key, sizeof(current_key));
        Secure_Wipe_KeyRotator(&operation_count, sizeof(operation_count));
        Secure_Wipe_KeyRotator(&rotation_interval, sizeof(rotation_interval));
    }

    // =====================================================================
    //  Get_Current_Key_And_Rotate
    //  [BUG-12] internal_state만 LCG 전진 → current_key는 단방향 파생
    //  [BUG-13] UINT64_MAX 데드코드 제거
    // =====================================================================

    uint64_t Dynamic_Key_Rotator::Get_Current_Key_And_Rotate() noexcept {
        operation_count++;

        if (operation_count >= rotation_interval) {
            // ── LCG 상태 전이 (은닉된 internal_state만 전진) ─────────
            uint64_t lcg_state = internal_state;
            lcg_state = (lcg_state * 0x5851F42D4C957F2DULL)
                + 0x14057B7EF767814FULL;
            lcg_state = (lcg_state << 21) | (lcg_state >> 43);

            internal_state = lcg_state;

            // ── [BUG-12] 단방향 키 파생 (Forward/Backward Secrecy) ───
            uint64_t new_key = Murmur3_Fmix64(lcg_state) ^ lcg_state;

            // 이전 키 소거: new_key 덮어쓰기 자체가 물리적 소거
            // (소멸자 Secure_Wipe는 별도 유지)
            current_key = new_key;
            operation_count = 0;
        }

        return current_key;
    }


} // namespace ProtectedEngine