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
        // [BUG-FIX FATAL] 초기화 플래그: bool → 3상 상태머신
        //  기존: CAS(false→true) 즉시 → 포인터 미할당 상태에서 true 노출
        //        → 외부 스레드가 nullptr 참조 → HardFault
        //  수정: NONE(0) → BUSY(1) → READY(2)
        //        BUSY 상태에서 외부 스레드는 ERR_NOT_INITIALIZED 반환
        //        READY는 모든 포인터 할당 + release 배리어 후에만 설정
        static constexpr uint32_t INIT_NONE = 0u;  ///< 미초기화
        static constexpr uint32_t INIT_BUSY = 1u;  ///< 초기화 진행 중 (포인터 미완성)
        static constexpr uint32_t INIT_READY = 2u;  ///< 초기화 완료 (포인터 유효)

        std::atomic<uint32_t>     g_init_state{ INIT_NONE };
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

        // [BUG-FIX FATAL] 3상 초기화: NONE→BUSY→READY
        //  CAS(NONE→BUSY): 단일 컨텍스트만 초기화 진입
        //  BUSY 상태: 외부 스레드가 포인터 접근 불가 (READY가 아니므로)
        //  READY 설정: 모든 포인터 할당 + release 배리어 후에만
        uint32_t expected = INIT_NONE;
        if (!g_init_state.compare_exchange_strong(
            expected, INIT_BUSY, std::memory_order_acq_rel)) {
            return HTS_Status::ERR_ALREADY_INITIALIZED;
        }

        if (!hw_irq_status_reg || !hw_irq_clear_reg || !hw_rx_fifo_addr) {
            g_init_state.store(INIT_NONE, std::memory_order_release);
            return HTS_Status::ERR_NULL_POINTER;
        }

        if (!Is_Valid_Medium(target_medium)) HTS_API_UNLIKELY{
            g_init_state.store(INIT_NONE, std::memory_order_release);
            return HTS_Status::ERR_UNSUPPORTED_MEDIUM;
        }

            // [BUG-20] POST는 void 반환
        ProtectedEngine::POST_Manager::executePowerOnSelfTest();

        g_hw_irq_status = hw_irq_status_reg;
        g_hw_irq_clear = hw_irq_clear_reg;
        g_hw_rx_fifo = hw_rx_fifo_addr;

        g_active_medium.store(
            static_cast<uint32_t>(target_medium),
            std::memory_order_relaxed);

        // [BUG-FIX FATAL] READY 설정: 모든 포인터 할당 완료 후
        //  release 배리어 → 다른 스레드에서 READY를 보면 포인터도 반드시 가시
        g_init_state.store(INIT_READY, std::memory_order_release);
        return HTS_Status::OK;
    }

    HTS_Status Fetch_And_Heal_Rx_Payload(
        uint32_t* out_buffer, size_t required_size) noexcept {

        // [BUG-FIX FATAL] READY 상태만 허용 (BUSY 상태 포인터 접근 차단)
        if (g_init_state.load(std::memory_order_acquire) != INIT_READY) {
            return HTS_Status::ERR_NOT_INITIALIZED;
        }
        if (!out_buffer || required_size == 0u) {
            return HTS_Status::ERR_NULL_POINTER;
        }

        return HTS_Status::ERR_BUFFER_UNDERFLOW;
    }

    HTS_Status Is_System_Operational() noexcept {
        if (g_init_state.load(std::memory_order_acquire) != INIT_READY) {
            return HTS_Status::ERR_NOT_INITIALIZED;
        }
        return HTS_Status::OK;
    }

} // namespace HTS_API