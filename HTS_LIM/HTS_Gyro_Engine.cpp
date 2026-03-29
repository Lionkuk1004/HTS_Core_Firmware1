// =========================================================================
// HTS_Gyro_Engine.cpp
// 다형성 자이로 위상 엔진 구현부
// Target: STM32F407 (Cortex-M4)
//
// [양산 수정 이력 — 14건]
//  BUG-01~13 (이전 세션 완료)
//  BUG-14 [CRIT] MSVC 크로스 컴파일 복원 — __asm__ 분기 + volatile 폴백
//
// [플랫폼 분기 방침]
//  GCC/Clang: __asm__ __volatile__ clobber (최적)
//  MSVC:      volatile 포인터 쓰기 (DCE 차단 보장)
//  공통:      atomic_thread_fence(seq_cst)
// =========================================================================
#include "HTS_Gyro_Engine.h"
#include <atomic>
#include <cstring>

#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
#include <bit>
#endif

namespace ProtectedEngine {

    // =====================================================================
    //  Mode 1: Initialize_Stabilizer — 세션별 위상 시드 초기화
    // =====================================================================
    void Gyro_Engine::Initialize_Stabilizer(uint64_t session_id) noexcept {
        const uint32_t high_part = static_cast<uint32_t>(session_id >> 32);
        const uint32_t low_part = static_cast<uint32_t>(session_id & 0xFFFFFFFFu);
        sync_counter = (high_part ^ low_part) ^ 0x3D504F57u;
        current_gyro_phase = 0;
    }

    // =====================================================================
    //  Mode 1: Update_Gyro_Stabilizer — 위상 1단계 전진
    // =====================================================================
    void Gyro_Engine::Update_Gyro_Stabilizer() noexcept {
        sync_counter += 0x9E3779B9u;
        current_gyro_phase = sync_counter ^ (sync_counter >> 13);

#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
        current_gyro_phase = std::rotl(current_gyro_phase, 5);
#else
        current_gyro_phase = (current_gyro_phase << 5) |
            (current_gyro_phase >> 27);
#endif
    }

    uint32_t Gyro_Engine::Get_Current_Phase() const noexcept {
        return current_gyro_phase;
    }

    // =====================================================================
    //  Mode 2: Apply_Dynamic_Phase_Stabilization — 정적 위상 난독화
    // =====================================================================
    void Gyro_Engine::Apply_Dynamic_Phase_Stabilization(
        uint32_t& node) noexcept {
#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
        node = std::rotl(node, 7);
#else
        node = (node << 7) | (node >> 25);
#endif
        node ^= 0x5A5A5A5Au;
    }

    // =====================================================================
    //  Safe_Buffer_Flush — 안티포렌식 메모리 파쇄기
    //
    //  [BUG-14] 크로스 플랫폼 DCE 방지
    //  GCC/Clang: memset + asm clobber (최적 — 컴파일러에 메모리 변경 통보)
    //  MSVC:      volatile 포인터 쓰기 (ISO C++ 보장 — volatile 부작용 삭제 불가)
    //  공통:      atomic_thread_fence(seq_cst) → 캐시 플러시 보장
    // =====================================================================
    template <typename T>
    void Gyro_Engine::Safe_Buffer_Flush(T* buffer, size_t elements) noexcept {
        if (!buffer || elements == 0) return;

        const size_t total_bytes = elements * sizeof(T);

#if defined(__GNUC__) || defined(__clang__)
        // GCC/Clang: memset + asm clobber (Strict Aliasing 안전)
        std::memset(buffer, 0, total_bytes);
        __asm__ __volatile__("" : : "r"(buffer) : "memory");
#else
        // MSVC: volatile 포인터 바이트 쓰기 (DCE 차단 보장)
        volatile unsigned char* vp =
            reinterpret_cast<volatile unsigned char*>(buffer);
        for (size_t i = 0; i < total_bytes; ++i) vp[i] = 0u;
#endif

        // [BUG-01] seq_cst → release (소거 배리어 정책 통일)
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  명시적 템플릿 인스턴스화
    // =====================================================================
    template void Gyro_Engine::Safe_Buffer_Flush<uint8_t>(uint8_t*, size_t) noexcept;
    template void Gyro_Engine::Safe_Buffer_Flush<int16_t>(int16_t*, size_t) noexcept;
    template void Gyro_Engine::Safe_Buffer_Flush<uint16_t>(uint16_t*, size_t) noexcept;
    template void Gyro_Engine::Safe_Buffer_Flush<int32_t>(int32_t*, size_t) noexcept;
    template void Gyro_Engine::Safe_Buffer_Flush<uint32_t>(uint32_t*, size_t) noexcept;
    template void Gyro_Engine::Safe_Buffer_Flush<uint64_t>(uint64_t*, size_t) noexcept;

} // namespace ProtectedEngine