#pragma once
// =========================================================================
// AnchorManager.h
// 적응형 앵커 비율 관리자 (AMC: Adaptive Modulation and Coding)
// Target: Cortex-A55 (CORE-X Pro 메인CPU) / Server
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [설계 목적]
//  3D 텐서 FEC 파이프라인의 앵커(패리티) 비율 관리
//  AnchorEncoder/Decoder가 참조하여 동적 비율 조정
//
//  [운용 모드]
//   STORAGE:        로컬 저장 → isStorageAvailable 시에만 앵커 생성
//   COMMUNICATION:  RF 통신 → 항상 앵커 생성
//
//  [AMC 자동 조절]
//   autoScaleRatio(residual_errors, turbo_loops_used):
//     오류 감지 → +5% (최대 30%)
//     안정 상태 → -1% (최소 5%)
//
//  [⚠ 네임스페이스]
//   AnchorManager는 전역 네임스페이스에 정의됨
//   (AnchorEncoder/Decoder가 ProtectedEngine 안에서 ::AnchorManager& 참조)
//   변경 시 Encoder/Decoder/TensorCodec 연쇄 빌드 에러 → 유지
//
//  [양산 수정 이력 — 세션 5: 8건]
//   BUG-01~08 (abort 클램핑, string ARM 가드, getStatusMessage,
//             copy/move, iostream/cstdlib, nodiscard, cstddef, Doxygen)
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>

// [BUG-02] <string> ARM 전파 차단 — PC 디버그 전용
#if !defined(__arm__) && !defined(__TARGET_ARCH_ARM) && !defined(__TARGET_ARCH_THUMB) && !defined(__ARM_ARCH)
#include <string>
#endif

enum class OperationMode : uint8_t {
    STORAGE,
    COMMUNICATION
};

enum class SecurityLevel : uint8_t {
    DANGER,
    WARNING,
    SAFE
};

class AnchorManager {
public:
    /// @brief 기본 생성자 (비율 15%, STORAGE 모드)
    AnchorManager() noexcept;

    /// AnchorManager 상태 복제 방지 (Encoder/Decoder 참조 일관성)
    AnchorManager(const AnchorManager&) = delete;
    AnchorManager& operator=(const AnchorManager&) = delete;
    AnchorManager(AnchorManager&&) = delete;
    AnchorManager& operator=(AnchorManager&&) = delete;

    /// @brief 앵커 비율 설정 (5~30% 범위 클램핑)
    /// @param ratio  목표 비율 (범위 외 시 min/max 클램핑)
    void setAnchorRatio(uint8_t ratio) noexcept;

    /// @brief 현재 보안 수준 조회
    /// @return DANGER(≤10%), WARNING(≤20%), SAFE(>20%)
    [[nodiscard]]
    SecurityLevel getSecurityLevel() const noexcept;

    /// @brief 앵커 크기 계산 (정수 반올림 나눗셈)
    /// @param originalDataSizeBytes  원본 크기 (바이트)
    /// @return 앵커 크기 = (size × ratio + 50) / 100
    [[nodiscard]]
    uint64_t calculateAnchorSize(uint64_t originalDataSizeBytes) const noexcept;

    /// @brief 현재 비율 조회
    [[nodiscard]]
    uint8_t getCurrentRatio() const noexcept;

    /// @brief 운용 모드 설정
    void setOperationMode(OperationMode mode) noexcept;

    /// @brief 저장소 가용 상태 설정
    void setStorageStatus(bool isAvailable) noexcept;

    /// @brief 앵커 생성 여부 판단
    /// @return COMMUNICATION 모드 → true, STORAGE → isStorageAvailable
    [[nodiscard]]
    bool shouldGenerateAnchor() const noexcept;

    /// @brief 적응형 방어력 자동 조절 (AMC)
    /// @param residual_errors   잔여 오류 수
    /// @param turbo_loops_used  터보 루프 사용 횟수
    void autoScaleRatio(int residual_errors, int turbo_loops_used) noexcept;

    // [BUG-02/03] getStatusMessage: ARM에서 std::string/to_string 위험
    // PC 디버그 전용 → ARM 가드 적용
#if !defined(__arm__) && !defined(__TARGET_ARCH_ARM) && !defined(__TARGET_ARCH_THUMB) && !defined(__ARM_ARCH)
    /// @brief 상태 메시지 (A55/서버 디버그 전용 — STM32 빌드 제외)
    std::string getStatusMessage() const;
#endif

private:
    uint8_t currentRatio;
    OperationMode currentMode;
    bool isStorageAvailable;
};