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
//  · K-4 [HIGH] 기대/계산 해시 비교: HTS_ConstantTimeUtil::compare (C-1 정합)
// =========================================================================
#include "HTS_Secure_Boot_Verify.h"
#include "HTS_ConstantTimeUtil.h"
#include "HTS_LSH256_Bridge.h"
#include "HTS_Secure_Memory.h"
#include "HTS_Hardware_Init.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <new>

namespace {
/// C 링크(HTS_Secure_Boot_Check) + C++ API 공통 상호 배제 — impl_buf_/g_* 경쟁 UAF 방지
std::atomic_flag g_sb_op_busy = ATOMIC_FLAG_INIT;

constexpr uint32_t kSbDestructorSpinTries = 8u;

struct SbOpBusyGuard final {
    std::atomic_flag* f_;
    explicit SbOpBusyGuard(std::atomic_flag& fl) noexcept : f_(&fl) {
        for (uint32_t i = 0u; i < 100000u; ++i) {
            if (!f_->test_and_set(std::memory_order_acquire)) {
                return;
            }
        }
        ProtectedEngine::Hardware_Init_Manager::Terminal_Fault_Action();
    }
    ~SbOpBusyGuard() noexcept { f_->clear(std::memory_order_release); }
    SbOpBusyGuard(const SbOpBusyGuard&) = delete;
    SbOpBusyGuard& operator=(const SbOpBusyGuard&) = delete;
};

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || \
    defined(__ARM_ARCH)
[[noreturn]] static void HTS_SB_Destructor_Lock_Contention_Fault() noexcept {
    static constexpr uintptr_t ADDR_AIRCR = 0xE000ED0Cu;
    static constexpr uint32_t  AIRCR_RESET =
        (0x05FAu << 16) | (1u << 2);
    volatile uint32_t* const aircr =
        reinterpret_cast<volatile uint32_t*>(ADDR_AIRCR);
    *aircr = AIRCR_RESET;
#if defined(__GNUC__) || defined(__clang__)
    static constexpr uintptr_t ADDR_DBGMCU_FZ = 0xE0042008u;
    static constexpr uint32_t DBGMCU_WWDG_STOP = (1u << 11);
    static constexpr uint32_t DBGMCU_IWDG_STOP = (1u << 12);
    volatile uint32_t* const dbgmcu_fz =
        reinterpret_cast<volatile uint32_t*>(ADDR_DBGMCU_FZ);
    *dbgmcu_fz &= ~(DBGMCU_WWDG_STOP | DBGMCU_IWDG_STOP);
    __asm__ __volatile__("dsb sy\n\tisb\n\t" ::: "memory");
#endif
    for (;;) {
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("wfi");
#else
        __asm__ __volatile__("nop");
#endif
    }
}
#endif
} // namespace

// ── 플랫폼 검증 ────────────────────────────────────────────────────────
static_assert(sizeof(uint8_t) == 1, "uint8_t must be 1 byte");
static_assert(sizeof(uint32_t) == 4, "uint32_t must be 4 bytes");

// ═════════════════════════════════════════════════════════════════════════
//  모듈 전역 상태
//
//   C-Runtime 초기화(.bss clear)가 이 변수를 0으로 덮어쓰는 것을 방지.
//   startup_stm32.s에서 Secure_Boot_Check → C-Runtime init → main() 순서에서
//   검증 결과가 보존됩니다.
//
//   링커 스크립트 필수 추가:
//     .noinit (NOLOAD) : { *(.noinit) } > RAM
//
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
    //  보안 소거 — SecureMemory::secureWipe (D-2 / X-5-1, MSVC GCC 공통)
    // =====================================================================

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
    // 링커 ROM 이미지 길이와 반드시 일치(미일치 시 무결성 검증 무의미). F407VG 1MB Flash 중
    // 실제 배치가 512KB인 경우의 상수 — 1MB 전체를 해시하려면 링커·OTP 프로비저닝과 함께 갱신.
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
#if defined(__GNUC__) || defined(__clang__)
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || \
    defined(__ARM_ARCH)
        __asm__ __volatile__("dsb sy" ::: "memory");
#endif
#endif
        guard = 100000u;
        while ((*flash_reg(FLASH_SR_OFF) & FLASH_SR_BSY) != 0u) {
            if (--guard == 0u) {
                *flash_reg(FLASH_CR_OFF) &= ~FLASH_CR_PG;
                return false;
            }
        }
        *flash_reg(FLASH_CR_OFF) &= ~FLASH_CR_PG;
        // ⑯ Read-back: 프로그램 바이트 검증 (불완전 쓰기·Brown-out 조기 탐지)
        const uint8_t rb =
            *reinterpret_cast<const volatile uint8_t*>(addr);
        return (rb == val);
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

    // Flash 해시 (memory-mapped 직접 읽기)
    //  LSH256_Bridge::Hash_256_WithPeriodicCallback: 64KB마다 IWDG 피드(해시 루프 중 타임아웃·리셋 방지).
    //  클럭이 낮을수록 전체 시간 증가 — startup 주석의 SystemClock_Config·IWDG 설정과 함께 검증.
    static constexpr uint32_t IWDG_KR_ADDR = 0x40003000u;
    static constexpr uint32_t IWDG_FEED_KEY = 0x0000AAAAu;

    static void wdt_feed() noexcept {
        *reinterpret_cast<volatile uint32_t*>(IWDG_KR_ADDR) = IWDG_FEED_KEY;
    }

    static bool compute_flash_hash(uint8_t* out32) noexcept {
        wdt_feed();
        const uint8_t* flash_ptr =
            reinterpret_cast<const uint8_t*>(FLASH_BASE);
        const uint32_t ok = LSH256_Bridge::Hash_256_WithPeriodicCallback(
            flash_ptr, FW_SIZE, out32, wdt_feed);
        wdt_feed();
        return (ok == LSH_SECURE_TRUE);
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
        if (offset == OTP_HMAG_ADDR && len <= sizeof(g_hash_magic_emu)) {
            std::memcpy(out, &g_hash_magic_emu, len);
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

#if defined(HTS_ALLOW_HOST_BUILD)
    /// PC OTP 에뮬 + 부트 플래그 초기화 — 호스트 결함주입/연속 검증 전용 (실칩 미사용).
    extern "C" void HTS_Test_Host_Reset_SecureBoot_OTP_Emulation(void) noexcept {
        std::memset(g_otp_hash_emu, 0, sizeof(g_otp_hash_emu));
        g_hash_magic_emu = 0u;
        g_boot_verified = 0u;
        g_safe_mode = 0u;
    }
#endif
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
            SecureMemory::secureWipe(expected, sizeof(expected));
            SecureMemory::secureWipe(computed, sizeof(computed));
            return BootVerifyResult::FLASH_READ_FAIL;
        }

        // 4. Constant-Time 비교 (ConstantTimeUtil::compare)
        const bool hash_match = ConstantTimeUtil::compare(
            expected, computed, HASH_SIZE);

        // 5. 해시 버퍼 즉시 소거
        SecureMemory::secureWipe(expected, sizeof(expected));
        SecureMemory::secureWipe(computed, sizeof(computed));

        return hash_match
            ? BootVerifyResult::OK
            : BootVerifyResult::HASH_MISMATCH;
    }

    namespace detail {
        /// 승인 시 g_boot_verified에 기록하는 다중 비트 매직(단일 비트 0/1보다 글리치 우회 난이도 증가)
        constexpr uint32_t kBootVerifiedMagic = 0x5A5A5A5Au;

        /// OK이면 kBootVerifiedMagic, 아니면 0 — if(r==OK) 없이 마스크만으로 커밋
        uint32_t ct_boot_result_is_ok(BootVerifyResult r) noexcept {
            uint8_t a = static_cast<uint8_t>(r);
            uint8_t b = static_cast<uint8_t>(BootVerifyResult::OK);
            const bool eq = ConstantTimeUtil::compare(&a, &b, 1u);
            const uint32_t mask =
                static_cast<uint32_t>(-(static_cast<int32_t>(eq)));
            return mask & kBootVerifiedMagic;
        }

        /// g_boot_verified가 매직과 일치하는지 상수시간 4바이트 비교
        bool boot_verified_storage_matches() noexcept {
            const uint32_t gv = g_boot_verified;
            const uint32_t mv = kBootVerifiedMagic;
            uint8_t a[sizeof(gv)];
            uint8_t b[sizeof(mv)];
            std::memcpy(a, &gv, sizeof(gv));
            std::memcpy(b, &mv, sizeof(mv));
            const bool ok = ConstantTimeUtil::compare(a, b, sizeof(a));
            SecureMemory::secureWipe(a, sizeof(a));
            SecureMemory::secureWipe(b, sizeof(b));
            return ok;
        }
    } // namespace detail

    // =====================================================================
    //  Pimpl 구현 구조체
    // =====================================================================
    struct HTS_Secure_Boot_Verify::Impl {
        bool verified = false;
        bool safe_mode = false;

        Impl() noexcept
            : verified(detail::boot_verified_storage_matches())
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
            ? std::launder(reinterpret_cast<Impl*>(impl_buf_)) : nullptr;
    }

    const HTS_Secure_Boot_Verify::Impl*
        HTS_Secure_Boot_Verify::get_impl() const noexcept
    {
        return impl_valid_
            ? std::launder(reinterpret_cast<const Impl*>(impl_buf_)) : nullptr;
    }

    // =====================================================================
    //  생성자 / 소멸자
    // =====================================================================
    HTS_Secure_Boot_Verify::HTS_Secure_Boot_Verify() noexcept
        : impl_valid_(false)
    {
        SbOpBusyGuard guard(g_sb_op_busy);
        SecureMemory::secureWipe(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl();
        impl_valid_ = true;
    }

    HTS_Secure_Boot_Verify::~HTS_Secure_Boot_Verify() noexcept {
        uint32_t spins = 0;
        while (g_sb_op_busy.test_and_set(std::memory_order_acquire)) {
            if (++spins >= kSbDestructorSpinTries) {
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || \
    defined(__ARM_ARCH)
                HTS_SB_Destructor_Lock_Contention_Fault();
#else
                std::abort();
#endif
            }
        }
        const bool was_valid = impl_valid_;
        impl_valid_ = false;
        if (was_valid) {
            std::launder(reinterpret_cast<Impl*>(impl_buf_))->~Impl();
        }
        SecureMemory::secureWipe(impl_buf_, IMPL_BUF_SIZE);
        g_sb_op_busy.clear(std::memory_order_release);
    }

    // =====================================================================
    //  Verify_Firmware — 글리치 방어 포함 (2회 시도)
    // =====================================================================
    BootVerifyResult HTS_Secure_Boot_Verify::Verify_Firmware() noexcept {
        SbOpBusyGuard guard(g_sb_op_busy);
        Impl* p = get_impl();
        if (p == nullptr) { return BootVerifyResult::FLASH_READ_FAIL; }

        if (p->verified) {
            return BootVerifyResult::OK;
        }

        BootVerifyResult r = do_verify_once();

        const uint32_t ok_mask = detail::ct_boot_result_is_ok(r);
        g_boot_verified |= ok_mask;
        p->verified = detail::boot_verified_storage_matches();

        if (ok_mask != 0u) {
            return BootVerifyResult::OK;
        }

        if (r == BootVerifyResult::NOT_PROVISIONED) {
            p->safe_mode = true;
            g_safe_mode = 1u;
            return BootVerifyResult::NOT_PROVISIONED;
        }

        r = do_verify_once();
        const uint32_t ok_mask2 = detail::ct_boot_result_is_ok(r);
        g_boot_verified |= ok_mask2;
        p->verified = detail::boot_verified_storage_matches();

        if (ok_mask2 != 0u) {
            return BootVerifyResult::OK;
        }

        p->safe_mode = true;
        g_safe_mode = 1u;
        return BootVerifyResult::RETRY_FAIL;
    }

    // =====================================================================
    //  Is_Verified / Is_Safe_Mode
    // =====================================================================
    bool HTS_Secure_Boot_Verify::Is_Verified() const noexcept {
        SbOpBusyGuard guard(g_sb_op_busy);
        const Impl* p = get_impl();
        return (p != nullptr) && p->verified;
    }

    bool HTS_Secure_Boot_Verify::Is_Safe_Mode() const noexcept {
        SbOpBusyGuard guard(g_sb_op_busy);
        const Impl* p = get_impl();
        return (p != nullptr) && p->safe_mode;
    }

    // =====================================================================
    //  Provision_Expected_Hash — OTP에 기대 해시 기록 (공장 1회)
    // =====================================================================
    bool HTS_Secure_Boot_Verify::Provision_Expected_Hash(
        const uint8_t* hash, size_t len) noexcept
    {
        SbOpBusyGuard guard(g_sb_op_busy);
        if (hash == nullptr || len != HASH_SIZE) { return false; }

        // 이미 기록됨
        if (otp_has_hash()) { return false; }

        // 해시 기록
        if (!otp_write_block(OTP_HASH_ADDR, hash, HASH_SIZE)) {
            return false;
        }

        // ⑯ 기록 직후 Read-Back 검증 (OTP/Flash)
        uint8_t verify_hash[HASH_SIZE] = {};
        otp_read_block(OTP_HASH_ADDR, verify_hash, HASH_SIZE);
        const bool hash_ok = ConstantTimeUtil::compare(
            verify_hash, hash, HASH_SIZE);
        SecureMemory::secureWipe(verify_hash, sizeof(verify_hash));
        if (!hash_ok) { return false; }

        // 매직 기록 (기록 완료 표시)
        const uint32_t magic = HASH_MAGIC;
        uint8_t magic_bytes[sizeof(magic)] = {};
        std::memcpy(magic_bytes, &magic, sizeof(magic));
        if (!otp_write_block(OTP_HMAG_ADDR, magic_bytes, sizeof(magic))) {
            SecureMemory::secureWipe(magic_bytes, sizeof(magic_bytes));
            return false;
        }

        // ⑯ 매직 기록 직후 Read-Back 검증
        uint8_t verify_magic[sizeof(magic)] = {};
        otp_read_block(OTP_HMAG_ADDR, verify_magic, sizeof(magic));
        const bool magic_ok = ConstantTimeUtil::compare(
            verify_magic, magic_bytes, sizeof(magic));
        SecureMemory::secureWipe(verify_magic, sizeof(verify_magic));
        if (!magic_ok) {
            SecureMemory::secureWipe(magic_bytes, sizeof(magic_bytes));
            return false;
        }
        SecureMemory::secureWipe(magic_bytes, sizeof(magic_bytes));

        return true;
    }

} // namespace ProtectedEngine

// ═════════════════════════════════════════════════════════════════════════
//  C 링크 함수 (startup_stm32.s에서 호출)
// ═════════════════════════════════════════════════════════════════════════
extern "C" {

    int32_t HTS_Secure_Boot_Check(void) {
        using namespace ProtectedEngine;
        using ProtectedEngine::detail::ct_boot_result_is_ok;

        // C 런타임(BSS) 초기화 전에 startup에서 호출될 수 있음 — g_sb_op_busy 미초기화
        // 데드락 방지를 위해 본 함수에서는 락을 사용하지 않음(단일 코어·인터럽트 미개입 가정).

        g_boot_verified = 0u;
        g_safe_mode = 0u;

        BootVerifyResult r = do_verify_once();

        const uint32_t ok_mask = ct_boot_result_is_ok(r);
        g_boot_verified = ok_mask;

        if (ok_mask != 0u) {
            return 0;
        }

        if (r == BootVerifyResult::NOT_PROVISIONED) {
            g_safe_mode = 1u;
            return 1;
        }

        r = do_verify_once();
        const uint32_t ok_mask2 = ct_boot_result_is_ok(r);
        g_boot_verified |= ok_mask2;

        if (ok_mask2 != 0u) {
            return 0;
        }

        g_safe_mode = 1u;
        return 1;
    }

    int32_t HTS_Secure_Boot_Is_Verified(void) {
        using ProtectedEngine::detail::boot_verified_storage_matches;
        SbOpBusyGuard lock(g_sb_op_busy);
        return boot_verified_storage_matches() ? 1 : 0;
    }

} // extern "C"
