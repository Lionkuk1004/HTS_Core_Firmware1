// =========================================================================
// HTS_Hardware_Auto_Scaler.cpp
// 텐서 자동 스케일링 구현부
// Target: STM32F407 (Cortex-M4, DMA SRAM 128KB)
//
#include "HTS_Hardware_Auto_Scaler.h"
#include <algorithm>
#include <cstdint>

#ifdef _MSC_VER
#include <intrin.h>
#endif

// =========================================================================
//  3단 플랫폼 분기 — RAM 감지 헤더
// =========================================================================
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#define HTS_PLATFORM_ARM
#endif

#ifndef HTS_PLATFORM_ARM
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif
#endif

namespace ProtectedEngine {

    // =====================================================================
    //  플랫폼 메모리 상수 (매크로 대신 namespace 내 상수)
    // =====================================================================
    namespace {
        // STM32F407 DMA 접근 가능 SRAM: SRAM1(112KB) + SRAM2(16KB) = 128KB
        // CCM(64KB)은 DMA 불가 → 텐서 버퍼에 사용 불가
        static const size_t ARM_DMA_SRAM_BYTES = 128u * 1024u;  // 131072

        // PC 폴백: RAM 감지 실패 시 보수적 추정 (128MB)
        static const size_t PC_FALLBACK_BYTES = 128u * 1024u * 1024u;
    }

    // =====================================================================
    //  2의 제곱수 내림 — DMA 버스트/모듈러 연산 최적화
    //
    //  GCC/Clang: CLZ + 시프트 (CM4 CLZ 1cyc) / MSVC: _BitScanReverse
    //  기타: 비트 스미어 + MSB만 남김(n - (n>>1)) 폴백
    //  16384 → 16384, 16000 → 8192, 0 → 0
    // =====================================================================
    static size_t Floor_Power_Of_Two(size_t n) noexcept {
        if (n == 0) return 0;

#if defined(__GNUC__) || defined(__clang__)
#if SIZE_MAX > 0xFFFFFFFFu
        const uint64_t v = static_cast<uint64_t>(n);
        return static_cast<size_t>(
            1ull << (63u
                - static_cast<unsigned>(__builtin_clzll(v))));
#else
        const uint32_t v = static_cast<uint32_t>(n);
        return static_cast<size_t>(
            1u << (31u
                - static_cast<unsigned>(__builtin_clz(v))));
#endif
#elif defined(_MSC_VER)
#if SIZE_MAX > 0xFFFFFFFFu
        unsigned long idx = 0;
        const unsigned char ok = _BitScanReverse64(
            &idx, static_cast<unsigned __int64>(n));
        return ok ? (static_cast<size_t>(1ull) << idx) : 0;
#else
        unsigned long idx = 0;
        const unsigned char ok = _BitScanReverse(
            &idx, static_cast<unsigned long>(n));
        return ok ? (static_cast<size_t>(1ul) << idx) : 0;
#endif
#else
        size_t x = n;
        x |= (x >> 1);
        x |= (x >> 2);
        x |= (x >> 4);
        x |= (x >> 8);
        x |= (x >> 16);
#if SIZE_MAX > 0xFFFFFFFFu
        x |= (x >> 32);
#endif
        return x - (x >> 1);
#endif
    }

    // =====================================================================
    //  Get_Free_System_Memory — 플랫폼별 가용 메모리 감지
    //
    //  ARM:     DMA SRAM 정적 상수 (OS 없음 → 감지 API 없음)
    //  Windows: GlobalMemoryStatusEx → ullAvailPhys
    //  Linux:   sysconf(_SC_AVPHYS_PAGES) × page_size
    //  감지 실패: PC_FALLBACK_BYTES (128MB)
    // =====================================================================
    size_t Hardware_Auto_Scaler::Get_Free_System_Memory() noexcept {
#ifdef HTS_PLATFORM_ARM
        // ARM 베어메탈: DMA 가능 SRAM 정적 반환
        return ARM_DMA_SRAM_BYTES;
#else
#if defined(_WIN32)
        // Windows: 물리 가용 메모리 감지
        MEMORYSTATUSEX status;
        status.dwLength = sizeof(status);
        if (GlobalMemoryStatusEx(&status) && status.ullAvailPhys > 0) {
            // size_t 클램핑 (32비트 PC에서 4GB 초과 방어)
            if (status.ullAvailPhys > SIZE_MAX) return SIZE_MAX;
            return static_cast<size_t>(status.ullAvailPhys);
        }
        return PC_FALLBACK_BYTES;
#else
        // Linux/macOS: POSIX sysconf
        long avail_pages = sysconf(_SC_AVPHYS_PAGES);
        long page_size = sysconf(_SC_PAGE_SIZE);
        if (avail_pages > 0 && page_size > 0) {
            uint64_t total = static_cast<uint64_t>(avail_pages)
                * static_cast<uint64_t>(page_size);
            if (total > SIZE_MAX) return SIZE_MAX;
            return static_cast<size_t>(total);
        }
        return PC_FALLBACK_BYTES;
#endif
#endif
    }

    // =====================================================================
    //  Calculate_Optimal_Tensor_Count — 최적 듀얼 텐서 개수 산출
    //
    //  [알고리즘]
    //  1. 플랫폼 가용 메모리 감지
    //  2. 50% HTS 엔진 할당
    //  3. 4바이트(듀얼 텐서)로 나누기
    //  4. [MIN_TENSORS, MAX_TENSORS] 클리핑 (두 값 모두 2의제곱)
    //  5. 2의 제곱수 내림 정렬 (DMA 버스트 최적)
    //
    //  [STM32F407 결과]
    //  128KB → 64KB → 16384 → clip[1024, 2^20] = 16384 → pow2 = 16384 (2^14) ✓
    //
    //  [PC 16GB 결과]
    //  16GB → 8GB → 2G → clip[1024, 2^20] = 1048576 → pow2 = 1048576 (2^20) ✓
    // =====================================================================
    size_t Hardware_Auto_Scaler::Calculate_Optimal_Tensor_Count() noexcept {
        size_t free_mem = Get_Free_System_Memory();

        // 전체 가용 메모리의 50%만 HTS 엔진에 할당
        // ⑨ /2 → >>1u
        size_t allocatable_mem = free_mem >> 1u;

        // 듀얼 텐서(4바이트) 단위 개수 산출
        // ⑨ /BYTES_PER_DUAL_TENSOR(=4) → >>2u
        size_t optimal_tensors = allocatable_mem >> 2u;

        // 안전 클리핑 [MIN, MAX] — 두 값 모두 2의제곱수 (헤더 static_assert)
        if (optimal_tensors < MIN_TENSORS) optimal_tensors = MIN_TENSORS;
        if (optimal_tensors > MAX_TENSORS) optimal_tensors = MAX_TENSORS;

        //   Floor(optimal) ≥ MIN 항상 성립 (optimal ≥ MIN이고 MIN=2^k)
        //   재클리핑은 EMI 비트플립 방어용 방어적 코드
        size_t aligned = Floor_Power_Of_Two(optimal_tensors);
        if (aligned < MIN_TENSORS) aligned = MIN_TENSORS;  // 방어: MIN도 2의제곱

        return aligned;
    }

} // namespace ProtectedEngine
