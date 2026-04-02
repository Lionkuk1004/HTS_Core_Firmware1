// =========================================================================
// AnchorManager.cpp
// 적응형 앵커 비율 관리자 구현부
// Target: Cortex-A55 (CORE-X Pro 메인CPU) / Server
//
#if (defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
     defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)) && \
    !defined(__aarch64__)
#error "[HTS_FATAL] AnchorManager는 A55/서버 전용. STM32 빌드에서 제외하십시오."
#endif

#include "AnchorManager.h"

#if !defined(__arm__) && !defined(__TARGET_ARCH_ARM) && !defined(__TARGET_ARCH_THUMB) && !defined(__ARM_ARCH)
#include <string>
#endif

#include <cstddef>
#include <cstdint>

// 치명적 시스템 임계치 (바이너리 내부 은닉)
namespace {
    constexpr uint8_t ANCHOR_MIN_RATIO = 5;
    constexpr uint8_t ANCHOR_MAX_RATIO = 30;
    constexpr uint64_t SAFE_MAX_DATA = 614891469123651720ULL;  // floor(UINT64_MAX / 30)

    // floor(v / 100) without / or % operators
    static uint64_t div_u64_by_100_no_div(uint64_t v) noexcept {
        uint64_t q = 0u;
        uint64_t r = 0u;
        for (int bit = 63; bit >= 0; --bit) {
            r = (r << 1u) | ((v >> static_cast<uint32_t>(bit)) & 1u);
            const uint64_t ge = (r >= 100u) ? 1u : 0u;
            r -= (100u * ge);
            q |= (ge << static_cast<uint32_t>(bit));
        }
        return q;
    }
}

AnchorManager::AnchorManager() noexcept
    : currentRatio(15)
    , currentMode(OperationMode::STORAGE)
    , isStorageAvailable(true) {
}

// =========================================================================
//  비율은 MIN/MAX로 클램핑 (범위 밖 시 조용한 보정)
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
    const uint64_t ratio = static_cast<uint64_t>(currentRatio);
    if (ratio == 0u) { return 0u; }
    if (originalDataSizeBytes > SAFE_MAX_DATA) {
        // fail-closed: 포화 처리로 래핑/언더사이즈 앵커 방지
        return div_u64_by_100_no_div(~0ULL);
    }
    const uint64_t scaled = originalDataSizeBytes * ratio + 50ULL;
    return div_u64_by_100_no_div(scaled);
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
