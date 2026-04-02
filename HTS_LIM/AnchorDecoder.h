#pragma once
// =========================================================================
// AnchorDecoder.h
// GF(2^8) Cauchy Reed-Solomon 이레이저 복구 디코더 — 공개 인터페이스
// Target: Cortex-A55 (CORE-X Pro 메인CPU) / Server
//
// @note STM32F407(B-CDMA 칩)에서는 사용 금지 — FEC_HARQ가 실시간 FEC 담당
//       이 모듈은 A55/서버에서 상위 레벨 이레이저 보정용
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [설계 목적]
//  3D 텐서 FEC 파이프라인의 이레이저 복원 모듈
//  GF(2^8) Cauchy RS 역행렬 기반 소실 데이터 복구
//
//  [사용법]
//   1. 생성: AnchorDecoder(anchorManager)
//   2. 복호: decode(brokenData, anchorData)
//      → 0xFFFF 마커 위치를 이레이저로 식별 → RS 복원
//      → CRC-32 매치 시 즉시 반환 (이미 정상)
//      → 복원 불가 시 빈 벡터 반환 (훼손 원본 전파 차단)
//
//  [양산 수정 이력 — 세션 5+6+11+14: 22건]
//   BUG-01~12 (abort 7회 제거, dead include 8개, GF8Bit 초기화,
//   divide/0 방어, Cauchy xor_val 가드, copy/move, AnchorManager,
//   CRC32 Zero-copy, nodiscard, Self-Contained, iostream/cstdlib, Doxygen)
//   BUG-13~22 (CRC 엔디안, Post-CRC, 빈 벡터 통일, DRY, decode_inplace)
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

// A55 (aarch64) 및 PC는 정상 통과
// STM32 실시간 FEC는 HTS_FEC_HARQ를 사용하십시오
#if (defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
     defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)) && \
    !defined(__aarch64__)
#error "[HTS_FATAL] AnchorDecoder.h는 A55/서버 전용입니다. STM32 빌드에서 제외하십시오."
#endif

#include <cstdint>
#include <cstddef>
#include <vector>

class AnchorManager;

namespace ProtectedEngine {

    class AnchorDecoder {
    public:
        static constexpr uint32_t SECURE_TRUE = 0x5A5A5A5Au;
        static constexpr uint32_t SECURE_FALSE = 0xA5A5A5A5u;

        /// @brief RS 디코더 생성 (GF(2^8) LUT 초기화)
        explicit AnchorDecoder(AnchorManager& anchorManager) noexcept;

        AnchorDecoder(const AnchorDecoder&) = delete;
        AnchorDecoder& operator=(const AnchorDecoder&) = delete;
        AnchorDecoder(AnchorDecoder&&) = delete;
        AnchorDecoder& operator=(AnchorDecoder&&) = delete;

        /// @brief 이레이저 복구 (0xFFFF 마커 → RS 복원)
        /// @param brokenData  손상된 데이터 (0xFFFF = 이레이저)
        /// @param anchorData  앵커(패리티 + CRC-32)
        /// @return 복원된 벡터 (복원 불가 시 빈 벡터 — empty() 검사 필수)
        [[nodiscard]]
        std::vector<uint16_t> decode(
            const std::vector<uint16_t>& brokenData,
            const std::vector<uint16_t>& anchorData) const noexcept;

        /// @brief In-place 이레이저 복구 — 호출자 버퍼 재사용 (힙 할당 0회)
        ///
        /// [PENDING-1 해결] TensorCodec 터보 루프에서 decode() 반환 벡터
        /// 생성/소멸 ~18,000회 → out 버퍼 사전 할당 + assign 재사용
        ///
        /// @param brokenData  손상된 데이터
        /// @param anchorData  앵커(패리티 + CRC-32)
        /// @param out         복원 결과 (사전 reserve 권장 — capacity 재사용)
        /// @return SECURE_TRUE=복원 성공(out 유효), SECURE_FALSE=실패(out clear)
        uint32_t decode_inplace(
            const std::vector<uint16_t>& brokenData,
            const std::vector<uint16_t>& anchorData,
            std::vector<uint16_t>& out) const noexcept;

    private:
        AnchorManager& manager;

        /// @brief In-place RS 복원 — data를 직접 수정
        /// @param data  brokenData 복사본 (assign으로 전달, 직접 수정됨)
        /// @param parityChunk  패리티 블록
        /// @return SECURE_TRUE=복원 성공, SECURE_FALSE=실패
        uint32_t restoreBlock_inplace(
            std::vector<uint16_t>& data,
            const std::vector<uint16_t>& parityChunk) const noexcept;
    };

} // namespace ProtectedEngine
