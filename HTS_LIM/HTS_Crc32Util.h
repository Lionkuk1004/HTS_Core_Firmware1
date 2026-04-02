// =========================================================================
// HTS_Crc32Util.h
// IEEE 802.3 CRC-32 유틸리티 — constexpr LUT (Flash 배치)
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [설계 목적]
//  IEEE 802.3 CRC-32 체크섬 연산. KCMVP 암호 태그, 펌웨어 무결성,
//  통신 페이로드 등 프로젝트 전반에서 오류 검출에 사용됩니다.
//
//  [사용법]
//   // raw 포인터 (Primary — 힙 0회)
//   uint32_t crc = Crc32Util::calculate(ptr, len);
//
//
//  [성능 — STM32F407 @168MHz]
//   1바이트: ~4사이클 (LDRB + EOR + LSR + LDR)
//   32바이트(HMAC 태그): ~128사이클 ≈ 0.8us
//   LUT: Flash(.rodata) 1KB — SRAM 점유 0B, 부팅 초기화 0사이클
//
//  [동시성] constexpr LUT 읽기 전용 → ISR/멀티스레드 레이스 프리
//
//  [양산 수정 이력 — 7건 + 세션 14 (2건) = 총 9건]
//   BUG-08 [LOW]  Target / PC 제거
//   BUG-09 [LOW]  외주 업체 Doxygen 가이드 추가
//
// ─────────────────────────────────────────────────────────────────────────
// =========================================================================
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    class Crc32Util {
    public:
        /// @brief [Primary] raw 포인터 CRC-32 (힙 할당 0회)
        [[nodiscard]]
        static uint32_t calculate(
            const uint8_t* data, size_t len) noexcept;

    };

} // namespace ProtectedEngine
