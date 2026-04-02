// =========================================================================
// HTS_Crc32Util.cpp
// IEEE 802.3 CRC-32 — constexpr LUT 엔진 (Flash 배치, SRAM 0B)
// Target: STM32F407 (Cortex-M4, 168MHz)
//
#include "HTS_Crc32Util.h"

namespace ProtectedEngine {

    // =====================================================================
    //
    //  다항식: 0xEDB88320 (IEEE 802.3 반사형)
    //  256 엔트리 × 4바이트 = 1KB → Flash(.rodata) 배치
    //  부팅 초기화 0사이클, SRAM 점유 0바이트
    //
    //  C++14 이상: constexpr 함수 내 루프 허용
    //  C++11:      재귀 템플릿 필요 (미지원 — C++14 최소 요구)
    // =====================================================================
    namespace {

        struct Crc32Table {
            uint32_t data[256];

            constexpr Crc32Table() noexcept : data{} {
                for (uint32_t i = 0; i < 256; ++i) {
                    uint32_t crc = i;
                    for (int j = 0; j < 8; ++j) {
                        uint32_t mask = static_cast<uint32_t>(
                            ~(crc & 1u) + 1u);
                        crc = (crc >> 1u) ^ (0xEDB88320u & mask);
                    }
                    data[i] = crc;
                }
            }
        };

        // constexpr 인스턴스 → .rodata(Flash) 배치
        static constexpr Crc32Table CRC32_LUT{};

    } // anonymous namespace

    // =====================================================================
    //
    //  → constexpr LUT = 읽기 전용 → 레이스 프리
    // =====================================================================
    uint32_t Crc32Util::calculate(
        const uint8_t* data, size_t len) noexcept {
        if (!data || len == 0) return 0;

        uint32_t crc = 0xFFFFFFFFu;

        for (size_t i = 0u; i < len; ++i) {
            crc = (crc >> 8u) ^
                CRC32_LUT.data[(crc ^ static_cast<uint32_t>(data[i])) & 0xFFu];
        }

        return ~crc;
    }

} // namespace ProtectedEngine
