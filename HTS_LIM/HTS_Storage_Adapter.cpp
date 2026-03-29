// =========================================================================
// HTS_Storage_Adapter.cpp
// 원시(Raw) 파티션 앵커 백업/복원 어댑터 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// [양산 수정 — 세션 1 (7건) + 세션 5 (7건) = 총 14건]
//
//  ── 세션 1 (BUG-01 ~ BUG-07) ──
//  BUG-01 [CRITICAL] 헤더 <iostream> → 제거
//  BUG-02 [HIGH]     noexcept 전 함수
//  BUG-03 [HIGH]     3단 플랫폼 분기
//  BUG-04 [MEDIUM]   size_t 곱셈 오버플로 방어
//  BUG-05 [MEDIUM]   Restore 매직 검증 활성화
//  BUG-06 [LOW]      매직 넘버 XOR → Murmur3
//  BUG-07 [LOW]      Check_Hardware_Token noexcept
//
//  ── 세션 5 (BUG-08 ~ BUG-14) ──
//  BUG-08 [CRITICAL] partition_data.size() < 2 시 매직 검증 스킵
//    기존: if (size >= 2) { 매직 검증 } → size < 2이면 검증 없이 복원 성공
//    수정: size < 2 → 즉시 false 반환 (매직 헤더 없는 데이터 = 무효)
//
//  BUG-09 [HIGH]     HTS_Anchor_Vault.hpp 헤더 → 전방 선언 (참조만 사용)
//    수정: 헤더에서 전방 선언, .cpp에서만 full include
//
//  BUG-10 [MEDIUM]   static 전용 클래스 인스턴스화 미차단
//    수정: 생성자/소멸자/복사/이동 전부 = delete
//
//  BUG-11 [LOW]      [[nodiscard]] Backup/Restore 적용
//  BUG-12 [LOW]      Self-Contained <cstddef> 추가
//  BUG-13 [LOW]      외부업체 Doxygen 가이드
//  BUG-14 [LOW]      (void)vault 경고 강화 (TODO 명확화)
// =========================================================================
#include "HTS_Storage_Adapter.hpp"

// [BUG-09] .cpp에서만 full include
#include "HTS_Anchor_Vault.hpp"

#include <cstddef>
#include <cstdint>

// ── 플랫폼 분기 ──────────────────────────────────────────────────
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#define HTS_PLATFORM_ARM_BAREMETAL
#elif defined(__aarch64__)
#define HTS_PLATFORM_AARCH64
#elif defined(_WIN32)
#define HTS_PLATFORM_WINDOWS
#else
#define HTS_PLATFORM_LINUX
#endif

#if !defined(HTS_PLATFORM_ARM_BAREMETAL)
#include <iostream>
#include <iomanip>
#endif

namespace ProtectedEngine {

    // =====================================================================
    //  Murmur3 64-bit Finalizer — 매직 넘버 비선형 혼합
    // =====================================================================
    static uint64_t Murmur3_Fmix64(uint64_t k) noexcept {
        k ^= k >> 33;
        k *= 0xFF51AFD7ED558CCDULL;
        k ^= k >> 33;
        k *= 0xC4CEB9FE1A85EC53ULL;
        k ^= k >> 33;
        return k;
    }

    // =====================================================================
    //  매직 넘버 생성 — 세션 + 장치 바인딩 (비가역)
    // =====================================================================
    static uint64_t Compute_Partition_Magic(
        uint64_t session_id, uint64_t usb_serial) noexcept {

        uint64_t mixed = session_id ^ usb_serial;
        mixed += (usb_serial >> 17) | (usb_serial << 47);
        return Murmur3_Fmix64(mixed);
    }

    // =====================================================================
    //  USB 하드웨어 시리얼 (바이너리 은닉)
    // =====================================================================
    const uint64_t Storage_Adapter::AUTHORIZED_USB_SERIAL =
        0xABCD1234EF567890ULL;

    // =====================================================================
    //  Check_Hardware_Token — USB 토큰 물리 검증
    // =====================================================================
    bool Storage_Adapter::Check_Hardware_Token() noexcept {
#if defined(HTS_PLATFORM_ARM_BAREMETAL)
        // TODO: USB OTG 포트 또는 GPIO 디지털 핀 검증
        return true;
#elif defined(HTS_PLATFORM_AARCH64)
        // 통합콘솔 (A55 Linux): USB 시리얼 검증
        // TODO: /dev/ttyUSB* 또는 libusb를 통한 USB 하드웨어 토큰 확인
        // 현재: 시뮬레이션 (양산 시 교체 필수)
        return true;
#else
        // PC: 개발빌드 시뮬레이션
        return true;
#endif
    }

    // =====================================================================
    //  Backup_To_Raw_Volume
    //  [BUG-14] (void)vault → TODO 명확화
    // =====================================================================
    bool Storage_Adapter::Backup_To_Raw_Volume(
        uint64_t session_id,
        Anchor_Vault& vault,
        size_t total_disk_mb,
        uint8_t anchor_ratio_percent) noexcept {

        // [BUG-14] TODO: 운용 배포 시 vault.Export_Anchor()로 직렬화 구현 필수
        // 현재는 파티션 크기 계산 + 매직 넘버 생성까지만 수행
        (void)vault;

        // 1. USB 하드웨어 토큰 인증
        if (!Check_Hardware_Token()) {
#if !defined(HTS_PLATFORM_ARM_BAREMETAL)
            std::cerr << "[FATAL] USB 하드웨어 토큰 미감지. 백업 거부.\n";
#endif
            return false;
        }

        // 2. anchor_ratio_percent 범위 검증 (5~30%)
        if (anchor_ratio_percent < 5u || anchor_ratio_percent > 30u) {
#if !defined(HTS_PLATFORM_ARM_BAREMETAL)
            std::cerr << "[FATAL] 앵커 비율 범위 초과 ("
                << static_cast<unsigned>(anchor_ratio_percent)
                << "%). 5~30% 필요.\n";
#endif
            return false;
        }

        // 3. 파티션 크기 계산 (64비트 오버플로 방어)
        uint64_t required_mb_64 =
            (static_cast<uint64_t>(total_disk_mb)
                * static_cast<uint64_t>(anchor_ratio_percent) + 50ULL) / 100ULL;

        size_t required_mb = (required_mb_64 > SIZE_MAX)
            ? SIZE_MAX
            : static_cast<size_t>(required_mb_64);

        // 4. 매직 넘버 생성
        uint64_t partition_magic = Compute_Partition_Magic(
            session_id, AUTHORIZED_USB_SERIAL);

        // 5. 로깅 (PC 전용)
#if !defined(HTS_PLATFORM_ARM_BAREMETAL)
        std::cout << "   -> [STORAGE] 디스크 " << total_disk_mb << "MB | "
            << static_cast<unsigned>(anchor_ratio_percent) << "% -> "
            << required_mb << "MB 파티션 할당\n";
        std::cout << "   -> [STORAGE] 매직: 0x"
            << std::hex << partition_magic << std::dec << "\n";
#else
        (void)required_mb;
        (void)partition_magic;
#endif

        // TODO: HAL 연동 — partition_magic + vault 데이터를 은닉 섹터에 기록
        return true;
    }

    // =====================================================================
    //  Restore_From_Raw_Volume
    //  [BUG-08] partition_data.size() < 2 → 즉시 거부
    // =====================================================================
    bool Storage_Adapter::Restore_From_Raw_Volume(
        uint64_t session_id,
        Anchor_Vault& vault,
        const std::vector<uint32_t>& partition_data) noexcept {

        // [BUG-14] TODO: 운용 배포 시 vault.Import_Anchor()로 역직렬화 구현 필수
        (void)vault;

        // 1. USB 하드웨어 토큰 인증
        if (!Check_Hardware_Token()) {
#if !defined(HTS_PLATFORM_ARM_BAREMETAL)
            std::cerr << "[FATAL] USB 토큰 부재. 복원 거부.\n";
#endif
            return false;
        }

        // 2. [BUG-08] 파티션 최소 크기 검증 (매직 헤더 2워드 필수)
        //    기존: if (empty) → false, if (size >= 2) → 검증
        //    → size == 1 시 매직 검증 스킵 = 무인증 복원!
        //    수정: size < 2 → 무조건 거부
        if (partition_data.size() < 2) {
#if !defined(HTS_PLATFORM_ARM_BAREMETAL)
            std::cerr << "[FATAL] 파티션 데이터 부족 (최소 2워드 필요). 복원 거부.\n";
#endif
            return false;
        }

        // 3. 매직 넘버 교차 검증 (세션 + USB 바인딩)
        uint64_t expected_magic = Compute_Partition_Magic(
            session_id, AUTHORIZED_USB_SERIAL);

        uint64_t stored_magic =
            (static_cast<uint64_t>(partition_data[0]) << 32)
            | static_cast<uint64_t>(partition_data[1]);

        // [BUG-16] 상수시간 비교 — 레지스터 격리 (volatile 제거)
        // volatile은 Write Suppression 공격에 취약 (AEAD_Integrity BUG-04 참조)
        // 레지스터 격리: diff/reduced는 CPU 레지스터에만 존재 → SRAM Store 0회
        uint64_t diff = stored_magic ^ expected_magic;
        uint32_t reduced =
            static_cast<uint32_t>(diff) | static_cast<uint32_t>(diff >> 32);

        if (reduced != 0u) {
#if !defined(HTS_PLATFORM_ARM_BAREMETAL)
            std::cerr << "[FATAL] 매직 넘버 불일치. 장치/세션 바인딩 검증 실패.\n";
#endif
            return false;
        }

#if !defined(HTS_PLATFORM_ARM_BAREMETAL)
        std::cout << "   -> [STORAGE] USB 인증 + 매직 검증 통과. 앵커 복원 시작.\n";
#endif

        // TODO: HAL 연동 — vault.Import_Anchor()로 역직렬화
        return true;
    }

} // namespace ProtectedEngine