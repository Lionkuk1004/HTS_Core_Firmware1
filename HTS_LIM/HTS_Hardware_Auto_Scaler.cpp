// =========================================================================
// HTS_Hardware_Auto_Scaler.cpp
// 텐서 자동 스케일링 구현부
// Target: STM32F407 (Cortex-M4, DMA SRAM 128KB)
//
// [양산 수정 — 5건 결함 교정]
//
//  BUG-01 [MEDIUM] Get_Free_System_Memory: 모든 플랫폼에서 128KB 고정
//    기존: #define IOT_MCU_TOTAL_SRAM (128*1024) → return 항상 128KB
//          PC 테스트: 16GB RAM에서도 텐서 16384개 (인위적 제한)
//          → Dual_Tensor_Pipeline이 과소 할당 → 대량 데이터 테스트 불가
//    수정: 3단 플랫폼 분기 (HTS_Dynamic_Config의 Get_System_Physical_RAM 패턴)
//          ARM:     128KB DMA SRAM (정적 상수)
//          Windows: GlobalMemoryStatusEx
//          Linux:   sysconf
//
//  BUG-02 [MEDIUM] #define IOT_MCU_TOTAL_SRAM 매크로
//    기존: .cpp 내 #define — 타입 안전성 없음, 디버거 불투명
//    수정: namespace 내 constexpr 상수로 교체
//
//  BUG-03 [LOW] 상수 정의: 헤더 선언 + .cpp 정의 분리
//    기존: static const 헤더 선언 → .cpp에서 별도 정의 필요
//    수정: 헤더에서 인라인 초기화 (static const size_t X = N;)
//          → .cpp에서 정의 불필요 (C++17 implicit inline / C++14 ODR safe)
//
//  BUG-04 [LOW] 텐서 개수 2의 제곱수 정렬 없음
//    기존: 16384 → 이미 2^14이지만, PC에서 다른 값이 나올 수 있음
//    수정: floor_power_of_two 내림 정렬 (DMA 버스트 + 모듈러 연산 최적)
//
//  BUG-05 [LOW] 문서화 — HTS_Config와의 관계 미기록
//    수정: 헤더에 관계 설명 추가
//
// [최종 확정값 (STM32F407)]
//  DMA SRAM 128KB → 50% = 64KB → / 4B = 16384 텐서 (2^14)
// =========================================================================
#include "HTS_Hardware_Auto_Scaler.h"
#include <algorithm>

// =========================================================================
//  3단 플랫폼 분기 — RAM 감지 헤더
// =========================================================================
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#define HTS_SCALER_PLATFORM_ARM
#elif defined(_WIN32)
#define HTS_SCALER_PLATFORM_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#define HTS_SCALER_PLATFORM_LINUX
#include <unistd.h>
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
    //  비재귀 비트 조작: 최상위 비트만 남기는 패턴
    //  16384 → 16384 (이미 2^14)
    //  16000 → 8192  (2^13)
    //  입력 0 → 0
    // =====================================================================
    static size_t Floor_Power_Of_Two(size_t n) noexcept {
        if (n == 0) return 0;
        n |= (n >> 1);
        n |= (n >> 2);
        n |= (n >> 4);
        n |= (n >> 8);
        n |= (n >> 16);
#if SIZE_MAX > 0xFFFFFFFFu
        n |= (n >> 32);
#endif
        return n - (n >> 1);
    }

    // =====================================================================
    //  Get_Free_System_Memory — 플랫폼별 가용 메모리 감지
    //
    //  [BUG-01 수정] 3단 플랫폼 분기
    //  ARM:     DMA SRAM 정적 상수 (OS 없음 → 감지 API 없음)
    //  Windows: GlobalMemoryStatusEx → ullAvailPhys
    //  Linux:   sysconf(_SC_AVPHYS_PAGES) × page_size
    //  감지 실패: PC_FALLBACK_BYTES (128MB)
    // =====================================================================
    size_t Hardware_Auto_Scaler::Get_Free_System_Memory() noexcept {
#if defined(HTS_SCALER_PLATFORM_ARM)
        // ARM 베어메탈: DMA 가능 SRAM 정적 반환
        return ARM_DMA_SRAM_BYTES;

#elif defined(HTS_SCALER_PLATFORM_WIN)
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
    }

    // =====================================================================
    //  Calculate_Optimal_Tensor_Count — 최적 듀얼 텐서 개수 산출
    //
    //  [알고리즘]
    //  1. 플랫폼 가용 메모리 감지
    //  2. 50% HTS 엔진 할당
    //  3. 4바이트(듀얼 텐서)로 나누기
    //  4. [MIN_TENSORS, MAX_TENSORS] 클리핑
    //  5. [BUG-04] 2의 제곱수 내림 정렬 (DMA 버스트 최적)
    //
    //  [STM32F407 결과]
    //  128KB → 64KB → 16384 → clip[1000, 1M] = 16384 → pow2 = 16384 (2^14) ✓
    //
    //  [PC 16GB 결과]
    //  16GB → 8GB → 2G → clip[1000, 1M] = 1000000 → pow2 = 524288 (2^19)
    // =====================================================================
    size_t Hardware_Auto_Scaler::Calculate_Optimal_Tensor_Count() noexcept {
        size_t free_mem = Get_Free_System_Memory();

        // 전체 가용 메모리의 50%만 HTS 엔진에 할당
        size_t allocatable_mem = free_mem / 2;

        // 듀얼 텐서(4바이트) 단위 개수 산출
        size_t optimal_tensors = allocatable_mem / BYTES_PER_DUAL_TENSOR;

        // 안전 클리핑 [MIN, MAX]
        if (optimal_tensors < MIN_TENSORS) optimal_tensors = MIN_TENSORS;
        if (optimal_tensors > MAX_TENSORS) optimal_tensors = MAX_TENSORS;

        // [BUG-04] 2의 제곱수 내림 (DMA 버스트 + 모듈러 연산 최적)
        // MIN_TENSORS(1000)이 이미 비2의제곱이므로,
        // 클리핑 후 floor_pow2가 MIN 이하로 떨어질 수 있음 → 재클리핑
        size_t aligned = Floor_Power_Of_Two(optimal_tensors);
        if (aligned < MIN_TENSORS) aligned = MIN_TENSORS;

        return aligned;
    }

} // namespace ProtectedEngine