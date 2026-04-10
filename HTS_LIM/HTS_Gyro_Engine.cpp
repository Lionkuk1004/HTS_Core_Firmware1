// =========================================================================
// HTS_Gyro_Engine.cpp
// 다형성 자이로 위상 엔진 구현부
// Target: STM32F407 (Cortex-M4)
//
#include "HTS_Gyro_Engine.h"
#include <atomic>
#include <cstddef>      // size_t
#include <cstdint>      // uint32_t

#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
#include <bit>
#endif

#ifdef _MSC_VER
#include <intrin.h>
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
    //   memset + asm("memory") → 레지스터 전량 Spill/Reload
    //   volatile uint32_t 워드 소거 + 경량 이스케이프("r")
    //   정책: HTS_Universal_API.cpp 확립 표준과 통일
    //
    //  [플랫폼 분기]
    //   GCC/Clang: volatile 바이트 소거 + __asm__("memory") 컴파일러 배리어
    //   MSVC:      동일 소거 + _ReadWriteBarrier() (인라인 asm 불가)
    //   공통:      atomic_thread_fence(release)
    // =====================================================================
    template <typename T>
    void Gyro_Engine::Safe_Buffer_Flush(T* buffer, size_t elements) noexcept {
        if (!buffer || elements == 0) return;
        if (elements > (SIZE_MAX / sizeof(T))) return;

        const size_t total_bytes = elements * sizeof(T);

#if defined(__GNUC__) || defined(__clang__)
        //
        //  위험: T=uint8_t 시 buffer가 비정렬(0x20000001 등)일 수 있음
        //   → reinterpret_cast<volatile uint32_t*> = C++ UB (정렬 위반)
        //   → UNALIGN_TRP=1 설정 시 UsageFault/HardFault 즉사
        //
        //  volatile uint8_t 바이트 단위 소거
        //   · unsigned char*는 C++ 표준 모든 타입 앨리어싱 허용 (UB 0건)
        //   · 정렬 요구사항 없음 (1바이트 = 자연정렬)
        //   · DSE 차단: volatile 쓰기 최적화 불가
        //   · 성능: 256B 버퍼 기준 +192cyc (~1.1µs@168MHz, 소거 함수 허용)
        volatile uint8_t* bp =
            reinterpret_cast<volatile uint8_t*>(buffer);
        for (size_t i = 0u; i < total_bytes; ++i) { bp[i] = 0u; }
        // 경량 이스케이프: 포인터만 클로버 (글로벌 "memory" 배제)
        __asm__ __volatile__("" : : "r"(bp) : "memory");
#else
        // MSVC: volatile 바이트 소거 + 컴파일러 메모리 배리어 (GCC asm 대응)
        volatile unsigned char* vp =
            reinterpret_cast<volatile unsigned char*>(buffer);
        for (size_t i = 0u; i < total_bytes; ++i) { vp[i] = 0u; }
        _ReadWriteBarrier();
#endif

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
