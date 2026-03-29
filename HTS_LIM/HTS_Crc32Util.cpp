// =========================================================================
// HTS_Crc32Util.cpp
// IEEE 802.3 CRC-32 — constexpr LUT 엔진 (Flash 배치, SRAM 0B)
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// [양산 수정 — 7건]
//  BUG-01 [HIGH] #include "Crc32Util.h" → "HTS_Crc32Util.h"
//  BUG-02 [HIGH] 전역 네임스페이스 → ProtectedEngine
//  BUG-04 [MED]  단일 컨텍스트 전용 (ISR 동시 호출 금지)
//  BUG-05 [MED]  런타임 LUT 1KB(.bss) → constexpr LUT(.rodata/Flash)
//    기존: static uint32_t crc32_lut[256] + Initialize 함수
//      → SRAM 1024B 점유 + 부팅 시 초기화 필요
//    수정: constexpr 컴파일 타임 테이블 생성
//      → Flash(1MB) 배치 → SRAM 0B + 초기화 0사이클
//  BUG-06 [LOW]  ARM11 → Cortex-M4 주석 수정
//  BUG-07 [LOW]  raw 포인터 API 추가 (힙 0회)
//
// [STM32F407 성능]
//  1바이트당: LDRB + EOR + LSR + LDR(LUT) = ~4사이클
//  32바이트(HMAC 태그): ~128사이클 ≈ 0.8µs @168MHz
//  LUT: Flash 1KB (.rodata) — SRAM 점유 0B
// =========================================================================
#include "HTS_Crc32Util.h"

namespace ProtectedEngine {

    // =====================================================================
    //  [BUG-05] constexpr CRC-32 LUT — 컴파일 타임 생성
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
                        crc = (crc >> 1) ^ (0xEDB88320u & mask);
                    }
                    data[i] = crc;
                }
            }
        };

        // constexpr 인스턴스 → .rodata(Flash) 배치
        static constexpr Crc32Table CRC32_LUT{};

    } // anonymous namespace

    // =====================================================================
    //  [BUG-07] calculate (raw 포인터) — Primary API (힙 0회)
    //
    //  [BUG-04] 단일 컨텍스트 전용 (ISR 동시 호출 안전 — LUT 읽기 전용)
    //  → constexpr LUT = 읽기 전용 → 레이스 프리
    // =====================================================================
    uint32_t Crc32Util::calculate(
        const uint8_t* data, size_t len) noexcept {
        if (!data || len == 0) return 0;

        uint32_t crc = 0xFFFFFFFFu;

        for (size_t i = 0; i < len; ++i) {
            crc = (crc >> 8) ^
                CRC32_LUT.data[(crc ^ data[i]) & 0xFFu];
        }

        return ~crc;
    }

    // =====================================================================
    //  calculate (vector) — 레거시 래퍼
    // =====================================================================
    uint32_t Crc32Util::calculate(
        const std::vector<uint8_t>& data) noexcept {
        return calculate(
            data.empty() ? nullptr : data.data(),
            data.size());
    }

} // namespace ProtectedEngine