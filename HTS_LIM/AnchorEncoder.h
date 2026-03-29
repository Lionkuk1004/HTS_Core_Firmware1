#pragma once
// =========================================================================
// AnchorEncoder.h
// GF(2^8) Cauchy Reed-Solomon 이레이저 코딩 인코더 — 공개 인터페이스
// Target: Cortex-A55 (CORE-X Pro 메인CPU) / Server
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [설계 목적]
//  3D 텐서 FEC 파이프라인의 앵커(패리티) 생성 모듈
//  GF(2^8) Cauchy RS 코드 기반 이레이저 복원용 패리티 블록 생성
//  LUT: exp[512] + log[256] = 768바이트 (Flash 상주)
//
//  [사용법]
//   1. 생성: AnchorEncoder(anchorManager)
//      → AnchorManager 참조 주입 (비율 제어)
//      → 생성자에서 GF(2^8) LUT 1회 초기화
//
//   2. 인코딩: encode(originalData)
//      → uint16_t 벡터 → Cauchy RS 패리티 + CRC-32 부착
//      → 앵커 비율 0% 시 빈 벡터 반환
//      → OOM/세션 미초기화 시 빈 벡터 반환 (abort 제거)
//
//  [양산 수정 이력 — 세션 5: 12건]
//   BUG-01~12 (abort 제거, dead include 8개, GF8Bit 초기화,
//             AnchorManager 전방선언, copy/move, cstdlib,
//             nodiscard, Self-Contained, dead extern, Doxygen,
//             Cauchy xor_val 가드, CRC32 Zero-copy)
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

// [BUG-21] STM32 (Cortex-M) 빌드 차단 — <vector> 힙 인프라 + GF(2^8) LUT 메모리 초과
// A55 (aarch64) 및 PC는 정상 통과
// STM32 실시간 FEC는 HTS_FEC_HARQ를 사용하십시오
#if (defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
     defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)) && \
    !defined(__aarch64__)
#error "[HTS_FATAL] AnchorEncoder.h는 A55/서버 전용입니다. STM32 빌드에서 제외하십시오."
#endif

#include <cstdint>
#include <cstddef>
#include <vector>

// AnchorManager는 전역 네임스페이스
class AnchorManager;

namespace ProtectedEngine {

    class AnchorEncoder {
    public:
        /// @brief RS 인코더 생성 (GF(2^8) LUT 초기화)
        /// @param anchorManager  앵커 비율 관리자 참조
        explicit AnchorEncoder(AnchorManager& anchorManager) noexcept;

        // AnchorManager& 참조 복제 방지
        AnchorEncoder(const AnchorEncoder&) = delete;
        AnchorEncoder& operator=(const AnchorEncoder&) = delete;
        AnchorEncoder(AnchorEncoder&&) = delete;
        AnchorEncoder& operator=(AnchorEncoder&&) = delete;

        /// @brief 원본 데이터 → RS 패리티 + CRC-32 생성
        /// @param originalData  uint16_t 원본 벡터
        /// @return 패리티 벡터 (빈 벡터 = 비율 0% 또는 오류)
        [[nodiscard]]
        std::vector<uint16_t> encode(
            const std::vector<uint16_t>& originalData) const noexcept;

    private:
        AnchorManager& manager;

        std::vector<uint16_t> generateParityBlock(
            const std::vector<uint16_t>& dataChunk,
            size_t anchorSize) const noexcept;
    };

} // namespace ProtectedEngine