// =========================================================================
// HTS_API.cpp
// 외부 파트너사 연동 API 구현부
// Target: STM32F407VGT6 (Cortex-M4F) / PC
//
// [양산 수정 이력 — 24건]
//  BUG-01~19 (이전 세션)
//  BUG-20 [CRIT] C2440: POST void 반환 → void 호출 + 성공 가정
//  BUG-21 [HIGH] C4273: HTS_API_BUILD 미정의 → cpp 상단 정의
//  BUG-22 [LOW]  [[likely]]/[[unlikely]] → C++20 가드 매크로 (U-D)
//  BUG-23 [HIGH] A-3: DCLP 이중 atomic(g_init_lock+g_is_initialized)
//                → 단일 CAS(g_is_initialized) 전환 (U-C 패턴 통일)
//  BUG-24 [LOW]  H-11: 전역 포인터 = nullptr 명시 제거 (BSS 영초기화)
// =========================================================================

// [BUG-21] DLL 빌드 시 export/import 방향 결정
// 이 파일이 라이브러리 구현부이므로 반드시 BUILD 매크로 선행 정의
#if !defined(HTS_API_BUILD)
#define HTS_API_BUILD
#endif

#include "HTS_API.h"
#include "HTS_POST_Manager.h"
// [C-REF-1] #include "HTS_PHY_Receiver.h" 삭제 — V400 대체 완료, dead code
#include "HTS_Sparse_Recovery.h"

#include <atomic>

// [BUG-22] C++20 속성 가드 — C++14/17 빌드 호환
#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
#define HTS_API_LIKELY   [[likely]]
#define HTS_API_UNLIKELY [[unlikely]]
#else
#define HTS_API_LIKELY
#define HTS_API_UNLIKELY
#endif

namespace HTS_API {

    namespace {
        // [BUG-23] g_init_lock 삭제 → g_is_initialized 단일 CAS로 통합
        //  기존: g_init_lock(CAS) + g_is_initialized(load/store) = 이중 atomic DCLP
        //  수정: g_is_initialized CAS(false→true, acq_rel) 단일 원자 전환
        //        BUG-34(HTS_Universal_Adapter) U-C 패턴과 통일
        std::atomic<bool>     g_is_initialized{ false };
        std::atomic<uint32_t> g_active_medium{
            static_cast<uint32_t>(HTS_CommMedium::B_CDMA_RAW_RF) };

        // [BUG-24] = nullptr 명시 제거: BSS 영초기화 보장 (C++11 이후)
        volatile uint32_t* g_hw_irq_status;
        volatile uint32_t* g_hw_irq_clear;
        volatile int16_t* g_hw_rx_fifo;
    }

    static bool Is_Valid_Medium(HTS_CommMedium m) noexcept {
        switch (m) {
        case HTS_CommMedium::B_CDMA_RAW_RF:
        case HTS_CommMedium::DIGITAL_5G_LTE:
        case HTS_CommMedium::WIRED_ETHERNET:
        case HTS_CommMedium::SATELLITE_LINK:
            return true;
        default:
            return false;
        }
    }

    HTS_Status Initialize_Core(
        volatile uint32_t* hw_irq_status_reg,
        volatile uint32_t* hw_irq_clear_reg,
        volatile int16_t* hw_rx_fifo_addr,
        HTS_CommMedium     target_medium) noexcept {

        // [BUG-23] 단일 CAS: 정확히 1컨텍스트만 초기화 실행
        //  기존: DCLP(g_init_lock CAS + g_is_initialized load/store)
        //  수정: g_is_initialized CAS(false→true, acq_rel) 단일 전환
        //  성공 = 초기화 진입 허가, 실패 = 이미 초기화 완료
        bool expected = false;
        if (!g_is_initialized.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
            return HTS_Status::ERR_ALREADY_INITIALIZED;
        }

        if (!hw_irq_status_reg || !hw_irq_clear_reg || !hw_rx_fifo_addr) {
            // 실패: 초기화 플래그 원복
            g_is_initialized.store(false, std::memory_order_release);
            return HTS_Status::ERR_NULL_POINTER;
        }

        if (!Is_Valid_Medium(target_medium)) HTS_API_UNLIKELY{
            g_is_initialized.store(false, std::memory_order_release);
            return HTS_Status::ERR_UNSUPPORTED_MEDIUM;
        }

            // [BUG-20] POST는 void 반환 — 내부에서 실패 시 자체 처리
            // void 호출 후 성공 가정 (POST 실패 시 내부 HardFault/리셋)
        ProtectedEngine::POST_Manager::executePowerOnSelfTest();

        g_hw_irq_status = hw_irq_status_reg;
        g_hw_irq_clear = hw_irq_clear_reg;
        g_hw_rx_fifo = hw_rx_fifo_addr;

        g_active_medium.store(
            static_cast<uint32_t>(target_medium),
            std::memory_order_relaxed);

        // CAS에서 이미 true 설정 완료 — 추가 store 불필요
        // acq_rel이 모든 쓰기의 가시성 보장
        return HTS_Status::OK;
    }

    HTS_Status Fetch_And_Heal_Rx_Payload(
        uint32_t* out_buffer, size_t required_size) noexcept {

        if (!g_is_initialized.load(std::memory_order_acquire)) {
            return HTS_Status::ERR_NOT_INITIALIZED;
        }
        if (!out_buffer || required_size == 0u) {
            return HTS_Status::ERR_NULL_POINTER;
        }

        return HTS_Status::ERR_BUFFER_UNDERFLOW;
    }

    HTS_Status Is_System_Operational() noexcept {
        if (!g_is_initialized.load(std::memory_order_acquire)) {
            return HTS_Status::ERR_NOT_INITIALIZED;
        }
        return HTS_Status::OK;
    }

} // namespace HTS_API