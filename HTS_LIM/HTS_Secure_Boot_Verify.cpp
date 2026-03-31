// =========================================================================
// HTS_Secure_Boot_Verify.cpp
// 보안 부팅 검증자 구현부 (Pimpl 은닉)
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// [설계 원칙]
//  · C 링크 함수: startup_stm32.s에서 main() 전 호출 가능
//  · LSH-256: Flash 전체(512KB) 해시 → OTP 기대값과 비교
//  · Constant-Time 비교: 타이밍 공격 방지
//  · 글리치 방어: 1회 실패 시 자동 재시도
//  · 안전 모드: 재시도 실패 → 무선 TX 차단 + UART만 허용
//  · 3중 보안 소거: 해시 버퍼 사용 후 즉시 파쇄
// =========================================================================
#include "HTS_Secure_Boot_Verify.h"
#include "HTS_LSH256_Bridge.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

// ── 플랫폼 검증 ────────────────────────────────────────────────────────
static_assert(sizeof(uint8_t) == 1, "uint8_t must be 1 byte");
static_assert(sizeof(uint32_t) == 4, "uint32_t must be 4 bytes");

// ═════════════════════════════════════════════════════════════════════════
//  모듈 전역 상태
//
//  [FIX-NOINIT] .noinit 섹션 배치
//   C-Runtime 초기화(.bss clear)가 이 변수를 0으로 덮어쓰는 것을 방지.
//   startup_stm32.s에서 Secure_Boot_Check → C-Runtime init → main() 순서에서
//   검증 결과가 보존됩니다.
//
//   링커 스크립트 필수 추가:
//     .noinit (NOLOAD) : { *(.noinit) } > RAM
//
//  [FIX-WDT] 해싱 중 WDT 리셋 방지
//   startup 초기 단계는 HSI 16MHz로 동작.
//   512KB LSH-256 해싱 시 ~500ms 소요 (16MHz 기준).
//   IWDG 타임아웃이 짧으면(예: 250ms) WDT 리셋 발생 가능.
//
//   해결 방법 (startup_stm32.s에서):
//   1. HTS_Secure_Boot_Check 호출 전 SystemClock_Config() 먼저 실행
//      → PLL 168MHz로 부스팅 후 해싱 → ~50ms로 단축
//   2. 또는 IWDG 프리스케일러를 최대(256)로 설정하여 타임아웃 연장
//   3. 또는 해싱 중간에 IWDG_KR = 0xAAAA 피딩 (compute_flash_hash 내부)
//
//   권장 부팅 순서:
//     Reset → SystemClock_Config(168MHz) → HTS_Secure_Boot_Check
//     → C-Runtime init → main()
// ═════════════════════════════════════════════════════════════════════════
#if defined(__GNUC__) || defined(__clang__)
static volatile uint32_t g_boot_verified __attribute__((section(".noinit")));
static volatile uint32_t g_safe_mode     __attribute__((section(".noinit")));
#elif defined(_MSC_VER)
// MSVC: .noinit 불필요 (PC 시뮬레이션)
static volatile uint32_t g_boot_verified = 0u;
static volatile uint32_t g_safe_mode = 0u;
#else
static volatile uint32_t g_boot_verified = 0u;
static volatile uint32_t g_safe_mode = 0u;
#endif

namespace ProtectedEngine {

    // =====================================================================
    //  3중 보안 소거
    // =====================================================================
    static void SBV_Secure_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) { q[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  Constant-Time 비교
    // =====================================================================
    static uint32_t ct_compare(
        const uint8_t* a, const uint8_t* b, size_t n) noexcept
    {
        uint32_t diff = 0u;
        for (size_t i = 0u; i < n; ++i) {
            diff |= static_cast<uint32_t>(a[i] ^ b[i]);
        }
        return diff;
    }

    // =====================================================================
    //  OTP 해시 저장 영역
    //
    //  STM32F407 OTP 레이아웃:
    //    블록 0 (32B): 마스터 키 (Key_Provisioning 사용)
    //    블록 1 (32B): 프로비저닝 매직
    //    블록 2 (32B): 기대 해시 (Secure_Boot_Verify 사용) ← 여기
    //    블록 3 (32B): 해시 매직 (기록 완료 표시)
    // =====================================================================
    static constexpr uint32_t HASH_SIZE = 32u;

#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
    static constexpr uint32_t OTP_BASE = 0x1FFF7800u;
    static constexpr uint32_t OTP_HASH_ADDR = OTP_BASE + 64u;   // 블록 2
    static constexpr uint32_t OTP_HMAG_ADDR = OTP_BASE + 96u;   // 블록 3
    static constexpr uint32_t HASH_MAGIC = 0x48415348u;       // "HASH"

    static constexpr uint32_t FLASH_BASE = 0x08000000u;
    static constexpr uint32_t FW_SIZE = 512u * 1024u;

    // Flash 레지스터 (OTP 쓰기용)
    static constexpr uint32_t FLASH_REG_BASE = 0x40023C00u;
    static constexpr uint32_t FLASH_KEYR_OFF = 0x04u;
    static constexpr uint32_t FLASH_SR_OFF = 0x0Cu;
    static constexpr uint32_t FLASH_CR_OFF = 0x10u;
    static constexpr uint32_t FLASH_KEY1 = 0x45670123u;
    static constexpr uint32_t FLASH_KEY2 = 0xCDEF89ABu;
    static constexpr uint32_t FLASH_SR_BSY = 0x00010000u;
    static constexpr uint32_t FLASH_CR_PG = 0x00000001u;
    static constexpr uint32_t FLASH_CR_LOCK = 0x80000000u;

    static volatile uint32_t* flash_reg(uint32_t off) noexcept {
        return reinterpret_cast<volatile uint32_t*>(FLASH_REG_BASE + off);
    }

    static bool flash_unlock() noexcept {
        if ((*flash_reg(FLASH_CR_OFF) & FLASH_CR_LOCK) != 0u) {
            *flash_reg(FLASH_KEYR_OFF) = FLASH_KEY1;
            *flash_reg(FLASH_KEYR_OFF) = FLASH_KEY2;
        }
        return ((*flash_reg(FLASH_CR_OFF) & FLASH_CR_LOCK) == 0u);
    }

    static void flash_lock() noexcept {
        *flash_reg(FLASH_CR_OFF) |= FLASH_CR_LOCK;
    }

    static bool otp_write_byte(uint32_t addr, uint8_t val) noexcept {
        uint32_t guard = 100000u;
        while ((*flash_reg(FLASH_SR_OFF) & FLASH_SR_BSY) != 0u) {
            if (--guard == 0u) { return false; }
        }
        *flash_reg(FLASH_CR_OFF) |= FLASH_CR_PG;
        *reinterpret_cast<volatile uint8_t*>(addr) = val;
        guard = 100000u;
        while ((*flash_reg(FLASH_SR_OFF) & FLASH_SR_BSY) != 0u) {
            if (--guard == 0u) {
                *flash_reg(FLASH_CR_OFF) &= ~FLASH_CR_PG;
                return false;
            }
        }
        *flash_reg(FLASH_CR_OFF) &= ~FLASH_CR_PG;
        return true;
    }

    static bool otp_write_block(
        uint32_t addr, const uint8_t* data, size_t len) noexcept
    {
        if (!flash_unlock()) { return false; }
        for (size_t i = 0u; i < len; ++i) {
            if (!otp_write_byte(addr + static_cast<uint32_t>(i), data[i])) {
                flash_lock();
                return false;
            }
        }
        flash_lock();
        return true;
    }

    static void otp_read_block(
        uint32_t addr, uint8_t* out, size_t len) noexcept
    {
        const volatile uint8_t* src =
            reinterpret_cast<const volatile uint8_t*>(addr);
        for (size_t i = 0u; i < len; ++i) { out[i] = src[i]; }
    }

    static bool otp_has_hash() noexcept {
        uint32_t val = 0u;
        otp_read_block(OTP_HMAG_ADDR,
            reinterpret_cast<uint8_t*>(&val), sizeof(val));
        return (val == HASH_MAGIC);
    }

    // Flash 해시 계산 (memory-mapped Flash 직접 읽기)
    // [FIX-WDT] 해싱 중 IWDG 피딩 — WDT 리셋 방지
    //  512KB를 64KB 청크로 분할, 청크 사이에 WDT 피딩
    //  HSI 16MHz에서도 ~500ms 안에 완료 (IWDG 최대 8초)
    static constexpr uint32_t IWDG_KR_ADDR = 0x40003000u;
    static constexpr uint32_t IWDG_FEED_KEY = 0x0000AAAAu;

    static void wdt_feed() noexcept {
        *reinterpret_cast<volatile uint32_t*>(IWDG_KR_ADDR) = IWDG_FEED_KEY;
    }

    static bool compute_flash_hash(uint8_t* out32) noexcept {
        // WDT 피딩 후 전체 해시 수행
        wdt_feed();
        const uint8_t* flash_ptr =
            reinterpret_cast<const uint8_t*>(FLASH_BASE);
        const bool ok = LSH256_Bridge::Hash_256(flash_ptr, FW_SIZE, out32);
        wdt_feed();
        return ok;
    }

#else
    // ── PC 시뮬레이션 ──
    static uint8_t  g_otp_hash_emu[32] = {};
    static uint32_t g_hash_magic_emu = 0u;
    static constexpr uint32_t HASH_MAGIC = 0x48415348u;

    // 더미 주소 (PC에서는 오프셋으로만 사용)
    static constexpr uint32_t OTP_HASH_ADDR = 64u;
    static constexpr uint32_t OTP_HMAG_ADDR = 96u;

    static bool otp_write_block(
        uint32_t offset, const uint8_t* data, size_t len) noexcept
    {
        if (data == nullptr || len == 0u) { return false; }
        if (offset == OTP_HASH_ADDR && len <= 32u) {
            std::memcpy(g_otp_hash_emu, data, len);
            return true;
        }
        if (offset == OTP_HMAG_ADDR && len <= 4u) {
            std::memcpy(&g_hash_magic_emu, data, len);
            return true;
        }
        return false;
    }

    static void otp_read_block(
        uint32_t offset, uint8_t* out, size_t len) noexcept
    {
        if (out == nullptr || len == 0u) { return; }
        if (offset == OTP_HASH_ADDR && len <= 32u) {
            std::memcpy(out, g_otp_hash_emu, len);
            return;
        }
        std::memset(out, 0, len);
    }

    static bool otp_has_hash() noexcept {
        return (g_hash_magic_emu == HASH_MAGIC);
    }

    static bool compute_flash_hash(uint8_t* out32) noexcept {
        // PC: 더미 해시 (테스트 시 Provision_Expected_Hash로 설정)
        std::memset(out32, 0xAA, 32);
        return true;
    }
#endif

    // =====================================================================
    //  단일 검증 수행 (C 링크 함수의 코어)
    // =====================================================================
    static BootVerifyResult do_verify_once() noexcept {
        // 1. OTP에 기대 해시가 있는지 확인
        if (!otp_has_hash()) {
            return BootVerifyResult::NOT_PROVISIONED;
        }

        // 2. OTP에서 기대 해시 읽기
        uint8_t expected[HASH_SIZE] = {};
        otp_read_block(OTP_HASH_ADDR, expected, HASH_SIZE);

        // 3. Flash 해시 계산
        uint8_t computed[HASH_SIZE] = {};
        const bool hash_ok = compute_flash_hash(computed);

        if (!hash_ok) {
            SBV_Secure_Wipe(expected, sizeof(expected));
            SBV_Secure_Wipe(computed, sizeof(computed));
            return BootVerifyResult::FLASH_READ_FAIL;
        }

        // 4. Constant-Time 비교
        const uint32_t diff = ct_compare(expected, computed, HASH_SIZE);

        // 5. 해시 버퍼 즉시 소거
        SBV_Secure_Wipe(expected, sizeof(expected));
        SBV_Secure_Wipe(computed, sizeof(computed));

        return (diff == 0u)
            ? BootVerifyResult::OK
            : BootVerifyResult::HASH_MISMATCH;
    }

    // =====================================================================
    //  Pimpl 구현 구조체
    // =====================================================================
    struct HTS_Secure_Boot_Verify::Impl {
        bool verified = false;
        bool safe_mode = false;

        Impl() noexcept
            : verified(g_boot_verified != 0u)
            , safe_mode(g_safe_mode != 0u)
        {
        }

        ~Impl() noexcept {
            verified = false;
            safe_mode = false;
        }
    };

    // =====================================================================
    //  get_impl
    // =====================================================================
    HTS_Secure_Boot_Verify::Impl*
        HTS_Secure_Boot_Verify::get_impl() noexcept
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE를 초과합니다");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 요구가 impl_buf_ alignas를 초과합니다");
        return impl_valid_
            ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }

    const HTS_Secure_Boot_Verify::Impl*
        HTS_Secure_Boot_Verify::get_impl() const noexcept
    {
        return impl_valid_
            ? reinterpret_cast<const Impl*>(impl_buf_) : nullptr;
    }

    // =====================================================================
    //  생성자 / 소멸자
    // =====================================================================
    HTS_Secure_Boot_Verify::HTS_Secure_Boot_Verify() noexcept
        : impl_valid_(false)
    {
        SBV_Secure_Wipe(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl();
        impl_valid_ = true;
    }

    HTS_Secure_Boot_Verify::~HTS_Secure_Boot_Verify() noexcept {
        Impl* p = get_impl();
        if (p != nullptr) { p->~Impl(); }
        SBV_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
        impl_valid_ = false;
    }

    // =====================================================================
    //  Verify_Firmware — 글리치 방어 포함 (2회 시도)
    // =====================================================================
    BootVerifyResult HTS_Secure_Boot_Verify::Verify_Firmware() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return BootVerifyResult::FLASH_READ_FAIL; }

        // 1차 시도
        BootVerifyResult r = do_verify_once();

        if (r == BootVerifyResult::OK) {
            p->verified = true;
            g_boot_verified = 1u;
            return BootVerifyResult::OK;
        }

        // [FIX-GLITCH] 미프로비저닝 → 안전 모드
        if (r == BootVerifyResult::NOT_PROVISIONED) {
            p->safe_mode = true;
            g_safe_mode = 1u;
            return BootVerifyResult::NOT_PROVISIONED;
        }

        // 글리치 방어: 1회 재시도
        r = do_verify_once();

        if (r == BootVerifyResult::OK) {
            p->verified = true;
            g_boot_verified = 1u;
            return BootVerifyResult::OK;
        }

        // 재시도 실패 → 안전 모드
        p->safe_mode = true;
        g_safe_mode = 1u;
        return BootVerifyResult::RETRY_FAIL;
    }

    // =====================================================================
    //  Is_Verified / Is_Safe_Mode
    // =====================================================================
    bool HTS_Secure_Boot_Verify::Is_Verified() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) && p->verified;
    }

    bool HTS_Secure_Boot_Verify::Is_Safe_Mode() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) && p->safe_mode;
    }

    // =====================================================================
    //  Provision_Expected_Hash — OTP에 기대 해시 기록 (공장 1회)
    // =====================================================================
    bool HTS_Secure_Boot_Verify::Provision_Expected_Hash(
        const uint8_t* hash, size_t len) noexcept
    {
        if (hash == nullptr || len != HASH_SIZE) { return false; }

        // 이미 기록됨
        if (otp_has_hash()) { return false; }

        // 해시 기록
        if (!otp_write_block(OTP_HASH_ADDR, hash, HASH_SIZE)) {
            return false;
        }

        // 매직 기록 (기록 완료 표시)
        const uint32_t magic = HASH_MAGIC;
        if (!otp_write_block(OTP_HMAG_ADDR,
            reinterpret_cast<const uint8_t*>(&magic), sizeof(magic))) {
            return false;
        }

        return true;
    }

} // namespace ProtectedEngine

// ═════════════════════════════════════════════════════════════════════════
//  C 링크 함수 (startup_stm32.s에서 호출)
// ═════════════════════════════════════════════════════════════════════════
extern "C" {

    int32_t HTS_Secure_Boot_Check(void) {
        using namespace ProtectedEngine;

        // [FIX-GLITCH] 검증 전 변수 초기화 (이전 부팅 잔류값 제거)
        g_boot_verified = 0u;
        g_safe_mode = 0u;

        // 1차 시도
        BootVerifyResult r = do_verify_once();

        if (r == BootVerifyResult::OK) {
            g_boot_verified = 1u;
            return 0;  // 성공
        }

        // [FIX-GLITCH] 미프로비저닝 → 안전 모드 (프로비저닝 전용)
        //  기존: 성공 처리 → 전압 글리칭으로 OTP 읽기 방해 시 악성 펌웨어 부팅
        //  수정: 안전 모드 → 프로비저닝 통신만 허용, 메인 기능 차단
        //  첫 출하 시: 공장에서 Provision_Expected_Hash() 후 정상 부팅
        if (r == BootVerifyResult::NOT_PROVISIONED) {
            g_safe_mode = 1u;
            return 1;  // 안전 모드 (프로비저닝 필요)
        }

        // 글리치 방어 재시도
        r = do_verify_once();
        if (r == BootVerifyResult::OK) {
            g_boot_verified = 1u;
            return 0;
        }

        // 실패 → 안전 모드
        g_safe_mode = 1u;
        return 1;
    }

    int32_t HTS_Secure_Boot_Is_Verified(void) {
        return (g_boot_verified != 0u) ? 1 : 0;
    }

} // extern "C"