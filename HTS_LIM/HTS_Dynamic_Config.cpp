#if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
#define HTS_LIKELY   [[likely]]
#define HTS_UNLIKELY [[unlikely]]
#else
#define HTS_LIKELY
#define HTS_UNLIKELY
#endif
// =========================================================================
// HTS_Dynamic_Config.cpp
// 시스템 체급(Tier)별 파라미터 프로파일 구현부
// Target: STM32F407 (Cortex-M4F, 168MHz)
//
#include "HTS_Dynamic_Config.h"

namespace ProtectedEngine {

    namespace {
        // ── AIRCR 레지스터 상수 (⑨강화 J-3) ─────────────────────
        constexpr uintptr_t k_AIRCR_ADDR = 0xE000ED0Cu;
        constexpr uint32_t  k_AIRCR_VECTKEY = 0x05FA0000u;
        constexpr uint32_t  k_AIRCR_SYSRST = 0x04u;

        // ── 단위 변환 명명 상수 (J-3) ───────────────────────────
        constexpr uint64_t  k_ARM_SRAM = 128ULL << 10u;    // 128 KB
        constexpr uint8_t   k_RATIO_MAX_PCT = 100u;

        // ── Q16 역수: 1/100 × 65536 ≈ 656 (Ceiling) ─────────────
        //   655/65536 = 0.009994… (−0.06% 절사 오차)
        //    → 131072×25×655>>16<<3 = 262,000 → Floor_Pow2 = 131,072 (−50%!)
        //   656/65536 = 0.010009… (+0.09% 양의 오차)
        //    → 131072×25×656>>16<<3 = 262,400 → Floor_Pow2 = 262,144 (0%!)
        //   원리: Floor_Pow2 앞에서는 반드시 양의 오차(ceil)를 써야
        //         2^N 경계를 살짝 넘겨 절반 손실을 방지
        constexpr uint64_t  k_RECIP_100_Q16 = 656ULL;

        constexpr uint32_t k_NF_INIT_Q16 = 100u << 16u;
        constexpr uint32_t k_CALIB_FRAMES = 72u;
        constexpr uint32_t k_JAM_MARGIN = 4000u;
        constexpr int32_t  k_SQUELCH_TH = 8;
        constexpr int32_t  k_CFAR_MULT = 4;
        constexpr int32_t  k_KP_32IQ = 30;
        constexpr int32_t  k_KI_32IQ = 2;

        constexpr uint32_t k_MIN_NODES = 256u;
        constexpr uint32_t k_EMBEDDED_NODES = 256u;
        constexpr uint32_t k_STANDARD_NODES = 1024u;
        constexpr uint8_t  k_DEFAULT_ANCHOR_PCT = 5u;
        constexpr uint32_t k_EMBEDDED_VDF = 5000u;
        constexpr uint32_t k_STANDARD_VDF = 50000u;
        constexpr uint32_t k_WORKSTATION_VDF = 100000u;
        constexpr uint32_t k_SERVER_VDF = 500000u;
        constexpr uint32_t k_EMBEDDED_CHUNK = 16u;
        constexpr uint32_t k_STANDARD_CHUNK = 32u;
        constexpr uint32_t k_WORKSTATION_CHUNK = 256u;
        constexpr uint32_t k_SERVER_CHUNK = 1024u;

        // Cortex-M4: CLZ → 단일 사이클; GCC/Clang 내장으로 매핑, 그 외는 비트 전파 폴백
        constexpr uint32_t Floor_Power_Of_Two(uint32_t v) noexcept {
            if (v == 0u) { return 0u; }
#if defined(__GNUC__) || defined(__clang__)
            return 1u
                << (31u
                    - static_cast<uint32_t>(__builtin_clz(v)));
#else
            v |= (v >> 1u);
            v |= (v >> 2u);
            v |= (v >> 4u);
            v |= (v >> 8u);
            v |= (v >> 16u);
            return (v >> 1u) + 1u;
#endif
        }

        // ── C++20 속성 가드 ─────────────────────────────────────
#if __cplusplus >= 202002L
#define HTS_DYNCFG_LIKELY   HTS_LIKELY
#else
#define HTS_DYNCFG_LIKELY
#endif

        // ── System_Panic: ARM AIRCR 즉시 리셋 / PC abort 폴백 ──
        //   __GNUC__로 가드 → x86 GCC에서 cpsid/dsb/wfi 컴파일 에러
        //   __arm__ 가드로 ARM asm 격리 + PC는 무한루프 폴백
        [[noreturn]] inline void System_Panic() noexcept {
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
            // ARM Cortex-M: 인터럽트 차단 + AIRCR 즉시 리셋
            __asm__ __volatile__("cpsid i" ::: "memory");
            __asm__ __volatile__("dsb" ::: "memory");
            *reinterpret_cast<volatile uint32_t*>(
                static_cast<uintptr_t>(k_AIRCR_ADDR)) =
                (k_AIRCR_VECTKEY | k_AIRCR_SYSRST);
            __asm__ __volatile__("dsb" ::: "memory");
            __asm__ __volatile__("isb");
            while (true) { __asm__ __volatile__("wfi"); }
#else
            // PC/A55: 무한루프 (디버거 브레이크 포인트 대기)
            while (true) {}
#endif
        }
    }

    HTS_Phy_Config HTS_Phy_Config_Factory::make(HTS_Phy_Tier tier) noexcept {
        HTS_Phy_Config cfg{};

        switch (tier) {
        case HTS_Phy_Tier::TIER_32_IQ:
            cfg.chip_count = 32u;
            cfg.min_valid_chips = 16u;
            cfg.noise_floor_init_q16 = k_NF_INIT_Q16;
            cfg.calib_frames = k_CALIB_FRAMES;
            cfg.kp = k_KP_32IQ;
            cfg.ki = k_KI_32IQ;
            cfg.jamming_margin = k_JAM_MARGIN;
            cfg.squelch_threshold = k_SQUELCH_TH;
            cfg.cfar_default_mult = k_CFAR_MULT;
            break;

        case HTS_Phy_Tier::TIER_64_ECCM:
            cfg.chip_count = 64u;
            cfg.min_valid_chips = 32u;
            cfg.noise_floor_init_q16 = k_NF_INIT_Q16;
            cfg.calib_frames = k_CALIB_FRAMES;
            cfg.kp = 0;
            cfg.ki = 0;
            cfg.jamming_margin = k_JAM_MARGIN;
            cfg.squelch_threshold = k_SQUELCH_TH;
            cfg.cfar_default_mult = k_CFAR_MULT;
            break;

        default:
            System_Panic();
        }
        return cfg;
    }

    std::atomic<uint8_t> HTS_Sys_Config_Factory::g_admin_ram_ratio{ 0u };

    void HTS_Sys_Config_Factory::Override_RAM_Ratio(uint8_t ratio_percent) noexcept {
        const uint8_t clamped = (ratio_percent > k_RATIO_MAX_PCT)
            ? k_RATIO_MAX_PCT : ratio_percent;
        g_admin_ram_ratio.store(clamped, std::memory_order_release);
    }

    // =====================================================================
    //  Get_System_Physical_RAM — ARM 고정 128KB
    // =====================================================================
    static uint64_t Get_System_Physical_RAM() noexcept {
        return k_ARM_SRAM;
    }

    HTS_Sys_Config HTS_Sys_Config_Factory::Get_Tier_Profile(
        HTS_Sys_Tier tier) noexcept {
        HTS_Sys_Config result{};

        switch (tier) {
        case HTS_Sys_Tier::EMBEDDED_MINI:
            result.node_count = k_EMBEDDED_NODES;
            result.anchor_ratio_percent = k_DEFAULT_ANCHOR_PCT;
            result.vdf_iterations = k_EMBEDDED_VDF;
            result.temporal_slice_chunk = k_EMBEDDED_CHUNK;
            return result;

        case HTS_Sys_Tier::STANDARD_CHIP:
            result.node_count = k_STANDARD_NODES;
            result.anchor_ratio_percent = k_DEFAULT_ANCHOR_PCT;
            result.vdf_iterations = k_STANDARD_VDF;
            result.temporal_slice_chunk = k_STANDARD_CHUNK;
            return result;

        case HTS_Sys_Tier::WORKSTATION:
        case HTS_Sys_Tier::HYPER_SERVER:
            break;

        default:
            System_Panic();
        }

        const uint64_t system_ram = Get_System_Physical_RAM();
        const uint8_t admin = g_admin_ram_ratio.load(std::memory_order_acquire);

        uint8_t active_ratio;
        if (admin > 0u) {
            active_ratio = admin;
        }
        else if (tier == HTS_Sys_Tier::WORKSTATION) {
            active_ratio = 1u;
        }
        else {
            active_ratio = 2u;
        }

        //  (ram * ratio / 100) << 3
        //  (ram * ratio * 655) >> 16 << 3
        //  Q16 역수: floor(65536 / 100) = 655
        //  오차 -0.06% — Floor_Power_Of_Two가 2^N 정렬하므로 무영향
        const uint64_t calc_nodes_64 =
            ((system_ram * static_cast<uint64_t>(active_ratio)
                * k_RECIP_100_Q16) >> 16u) << 3u;

        uint32_t final_nodes;
        if (calc_nodes_64 > UINT32_MAX) {
            final_nodes = UINT32_MAX;
        }
        else if (calc_nodes_64 < static_cast<uint64_t>(k_MIN_NODES)) {
            final_nodes = k_MIN_NODES;
        }
        else {
            final_nodes = static_cast<uint32_t>(calc_nodes_64);
        }

        final_nodes = Floor_Power_Of_Two(final_nodes);
        if (final_nodes < k_MIN_NODES) {
            final_nodes = k_MIN_NODES;
        }

        result.node_count = final_nodes;
        result.anchor_ratio_percent = k_DEFAULT_ANCHOR_PCT;

        if (tier == HTS_Sys_Tier::WORKSTATION) {
            result.vdf_iterations = k_WORKSTATION_VDF;
            result.temporal_slice_chunk = k_WORKSTATION_CHUNK;
        }
        else {
            result.vdf_iterations = k_SERVER_VDF;
            result.temporal_slice_chunk = k_SERVER_CHUNK;
        }

        return result;
    }

} // namespace ProtectedEngine
