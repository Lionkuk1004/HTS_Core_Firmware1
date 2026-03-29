// =========================================================================
// AnchorManager.cpp
// 적응형 앵커 비율 관리자 구현부
// Target: Cortex-A55 (CORE-X Pro 메인CPU) / Server
//
// [양산 수정 — 세션 5: 8건 결함 교정]
//
//  BUG-01 [CRITICAL] setAnchorRatio abort × 2 → 클램핑
//    기존: 범위 외 → std::abort() → MCU 정지
//    수정: 범위 외 → MIN/MAX 클램핑 (양산 원칙: 조용한 보정)
//
//  BUG-02 [HIGH]     <string> 헤더 전파 → ARM includer 전체에 STL string
//    수정: getStatusMessage를 ARM 가드 (#if !ARM) 안으로 이동
//          <string> include도 조건부
//
//  BUG-03 [HIGH]     getStatusMessage std::to_string → ARM newlib 위험
//    수정: ARM 빌드에서 완전 제외
//
//  BUG-04 [MEDIUM]   복사/이동 미차단 → = delete
//  BUG-05 [MEDIUM]   <iostream>/<cstdlib> → 제거 (abort/cerr 제거)
//  BUG-06 [LOW]      [[nodiscard]] 미적용
//  BUG-07 [LOW]      Self-Contained <cstddef> 누락
//  BUG-08 [LOW]      외부업체 Doxygen 가이드 없음
// =========================================================================
#include "AnchorManager.h"

// [BUG-05] <iostream>, <cstdlib> 제거 (abort/cerr 제거에 따라 불필요)
// [BUG-02/03] <string> PC 전용
#if !defined(__arm__) && !defined(__TARGET_ARCH_ARM) && !defined(__TARGET_ARCH_THUMB) && !defined(__ARM_ARCH)
#include <string>
#endif

#include <cstddef>
#include <cstdint>

// 치명적 시스템 임계치 (바이너리 내부 은닉)
namespace {
    constexpr uint8_t ANCHOR_MIN_RATIO = 5;
    constexpr uint8_t ANCHOR_MAX_RATIO = 30;
}

AnchorManager::AnchorManager() noexcept
    : currentRatio(15)
    , currentMode(OperationMode::STORAGE)
    , isStorageAvailable(true) {
}

// =========================================================================
//  [BUG-01] abort → 클램핑
//  기존: 범위 외 시 std::abort() → MCU 정지
//  수정: MIN/MAX 클램핑 (양산 원칙: 조용한 보정)
// =========================================================================
void AnchorManager::setAnchorRatio(uint8_t ratio) noexcept {
    if (ratio < ANCHOR_MIN_RATIO) {
        currentRatio = ANCHOR_MIN_RATIO;
        return;
    }
    if (ratio > ANCHOR_MAX_RATIO) {
        currentRatio = ANCHOR_MAX_RATIO;
        return;
    }
    currentRatio = ratio;
}

SecurityLevel AnchorManager::getSecurityLevel() const noexcept {
    if (currentRatio <= 10) return SecurityLevel::DANGER;
    if (currentRatio <= 20) return SecurityLevel::WARNING;
    return SecurityLevel::SAFE;
}

// [BUG-02/03] A55/서버 디버그 전용 — STM32 빌드 제외
// [BUG-09] try-catch 삭제 + noexcept 제거 (std::string 할당 실패 시 예외 전파)
#if !defined(__arm__) && !defined(__TARGET_ARCH_ARM) && !defined(__TARGET_ARCH_THUMB) && !defined(__ARM_ARCH)
std::string AnchorManager::getStatusMessage() const {
    std::string msg = "[Anchor Ratio: " +
        std::to_string(currentRatio) + "%] ";

    if (currentRatio <= 10)
        return msg + "DANGER - Minimal recovery capability.";
    if (currentRatio <= 20)
        return msg + "WARNING - Standard recovery.";
    return msg + "SAFE - Maximum recovery assurance.";
}
#endif

// =========================================================================
//  부동소수점 완전 제거: (size × ratio + 50) / 100 (반올림 정수 나눗셈)
// =========================================================================
uint64_t AnchorManager::calculateAnchorSize(
    uint64_t originalDataSizeBytes) const noexcept {
    return (originalDataSizeBytes *
        static_cast<uint64_t>(currentRatio) + 50ULL) / 100ULL;
}

uint8_t AnchorManager::getCurrentRatio() const noexcept {
    return currentRatio;
}

void AnchorManager::setOperationMode(OperationMode mode) noexcept {
    currentMode = mode;
}

void AnchorManager::setStorageStatus(bool isAvailable) noexcept {
    isStorageAvailable = isAvailable;
}

bool AnchorManager::shouldGenerateAnchor() const noexcept {
    if (currentMode == OperationMode::COMMUNICATION) return true;
    return isStorageAvailable;
}

// =========================================================================
//  적응형 방어력 자동 조절 (Auto-Scaling)
//  상향: +5% (위협 감지 시) → MAX 클램핑
//  하향: -1% (안정 상태 시) → MIN 클램핑
// =========================================================================
void AnchorManager::autoScaleRatio(
    int residual_errors, int turbo_loops_used) noexcept {

    if (residual_errors > 0 || turbo_loops_used >= 5) {
        // 위협 감지 → 방어력 상향
        uint8_t next = static_cast<uint8_t>(currentRatio + 5u);
        if (next > ANCHOR_MAX_RATIO) next = ANCHOR_MAX_RATIO;
        currentRatio = next;
    }
    else if (residual_errors == 0 && turbo_loops_used <= 1) {
        // 안정 → 소폭 하향
        if (currentRatio > ANCHOR_MIN_RATIO) {
            currentRatio = static_cast<uint8_t>(currentRatio - 1u);
        }
    }
}