// =========================================================================
// HTS_Key_Provisioning.cpp
// 공장 출하 키 프로비저닝 엔진 구현부 (Pimpl 은닉)
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
#include "HTS_Key_Provisioning.h"
#include "HTS_AES_Bridge.h"
#include "HTS_ConstantTimeUtil.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

// ── 플랫폼 검증 ────────────────────────────────────────────────────────
static_assert(sizeof(uint8_t) == 1, "uint8_t must be 1 byte");
static_assert(sizeof(uint32_t) == 4, "uint32_t must be 4 bytes");

namespace ProtectedEngine {

    // =====================================================================
    //  3중 보안 소거 — impl_buf_ 전체 파쇄
    // =====================================================================
    static void Key_Prov_Secure_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) { q[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(q) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // ── 양산: PWR에서 PVD가 설정된 경우에만 HTS_KEYPROV_ENFORCE_PVD=1 권장 (RM0090 PVDO)
#ifndef HTS_KEYPROV_ENFORCE_PVD
#define HTS_KEYPROV_ENFORCE_PVD 0
#endif

#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
    static bool keyprov_voltage_ok_for_flash() noexcept
    {
#if HTS_KEYPROV_ENFORCE_PVD
        constexpr uintptr_t PWR_CSR_ADDR = 0x40007004u;
        constexpr uint32_t  PWR_CSR_PVDO = (1u << 2u);
        const uint32_t csr = *reinterpret_cast<volatile uint32_t*>(PWR_CSR_ADDR);
        return (csr & PWR_CSR_PVDO) == 0u;
#else
        return true;
#endif
    }
#else
    static bool keyprov_voltage_ok_for_flash() noexcept { return true; }
#endif

    // RFC 3394: 64-bit semiblock t 를 A(8B)와 XOR (빅엔디안)
    static void keyprov_kw_xor_t(uint64_t t, const uint8_t a[8], uint8_t out_xor[8]) noexcept
    {
        for (int k = 0; k < 8; ++k) {
            out_xor[k] = static_cast<uint8_t>(t >> (56 - 8 * k));
        }
        for (int k = 0; k < 8; ++k) {
            out_xor[k] ^= a[k];
        }
    }

    // =====================================================================
    //  OTP HAL 추상화
    //
    //  STM32F407 OTP: 0x1FFF7800 ~ 0x1FFF7A0F (528B)
    //  16블록 × 32바이트 + 16 잠금바이트
    //  블록 0: 마스터 키 저장용 (32B 중 16B 사용)
    //  블록 1: 프로비저닝 매직 + 타임스탬프
    //
    //  주의: OTP는 1회만 기록 가능 (0→1 전용, 1→0 불가)
    //        양산 라인에서 최초 1회만 Inject_Key 호출
    // =====================================================================
#if defined(__arm__) || defined(__TARGET_ARCH_ARM)

    // STM32F407 Flash 레지스터 주소
    static constexpr uint32_t FLASH_BASE_ADDR = 0x40023C00u;
    static constexpr uint32_t FLASH_KEYR_OFFSET = 0x04u;
    static constexpr uint32_t FLASH_SR_OFFSET = 0x0Cu;
    static constexpr uint32_t FLASH_CR_OFFSET = 0x10u;

    static constexpr uint32_t FLASH_KEY1 = 0x45670123u;
    static constexpr uint32_t FLASH_KEY2 = 0xCDEF89ABu;
    static constexpr uint32_t FLASH_SR_BSY = 0x00010000u;
    static constexpr uint32_t FLASH_CR_PG = 0x00000001u;
    static constexpr uint32_t FLASH_CR_LOCK = 0x80000000u;

    // OTP 영역 기본 주소
    static constexpr uint32_t OTP_BASE = 0x1FFF7800u;
    static constexpr uint32_t OTP_LOCK_BASE = 0x1FFF7A00u;

    // 마스터 키: OTP 블록 0 (32B 중 16B 사용)
    static constexpr uint32_t OTP_KEY_ADDR = OTP_BASE;
    // 매직 넘버: OTP 블록 1
    static constexpr uint32_t OTP_MAGIC_ADDR = OTP_BASE + 32u;
    static constexpr uint32_t PROV_MAGIC = 0x4B455931u;  // "KEY1"

    static volatile uint32_t* flash_reg(uint32_t offset) noexcept {
        return reinterpret_cast<volatile uint32_t*>(FLASH_BASE_ADDR + offset);
    }

    static bool flash_unlock() noexcept {
        if ((*flash_reg(FLASH_CR_OFFSET) & FLASH_CR_LOCK) != 0u) {
            *flash_reg(FLASH_KEYR_OFFSET) = FLASH_KEY1;
            *flash_reg(FLASH_KEYR_OFFSET) = FLASH_KEY2;
        }
        return ((*flash_reg(FLASH_CR_OFFSET) & FLASH_CR_LOCK) == 0u);
    }

    static void flash_lock() noexcept {
        *flash_reg(FLASH_CR_OFFSET) |= FLASH_CR_LOCK;
    }

    // OTP 바이트 프로그래밍 (타임아웃 가드 포함)
    static bool otp_write_byte(uint32_t addr, uint8_t val) noexcept {
        // Brown-out 시 섹터 오염 방지: PVD(선택) 또는 양산 시 HTS_KEYPROV_ENFORCE_PVD=1
        if (!keyprov_voltage_ok_for_flash()) {
            return false;
        }
        // BSY 대기 (타임아웃 100,000 사이클 ≈ 0.6ms @ 168MHz)
        uint32_t guard = 100000u;
        while ((*flash_reg(FLASH_SR_OFFSET) & FLASH_SR_BSY) != 0u) {
            if (--guard == 0u) { return false; }
        }
        // PG 비트 설정
        *flash_reg(FLASH_CR_OFFSET) |= FLASH_CR_PG;
        // 바이트 쓰기
        *reinterpret_cast<volatile uint8_t*>(addr) = val;
        // 완료 대기
        guard = 100000u;
        while ((*flash_reg(FLASH_SR_OFFSET) & FLASH_SR_BSY) != 0u) {
            if (--guard == 0u) {
                *flash_reg(FLASH_CR_OFFSET) &= ~FLASH_CR_PG;
                return false;
            }
        }
        *flash_reg(FLASH_CR_OFFSET) &= ~FLASH_CR_PG;
        // ⑯ Read-back: 프로그램 바이트 검증 (Brown-out/불완전 쓰기 조기 탐지)
        const uint8_t rb =
            *reinterpret_cast<const volatile uint8_t*>(addr);
        return (rb == val);
    }

    static bool otp_write_block(
        uint32_t base_addr, const uint8_t* data, size_t len) noexcept
    {
        if (!flash_unlock()) { return false; }
        for (size_t i = 0u; i < len; ++i) {
            const uint32_t off = static_cast<uint32_t>(i);
            if (static_cast<size_t>(off) != i) {
                flash_lock();
                return false;
            }
            const uint32_t phys_addr = base_addr + off;
            if (phys_addr < base_addr) {
                flash_lock();
                return false;
            }
            if (!otp_write_byte(phys_addr, data[i])) {
                flash_lock();
                return false;
            }
        }
        flash_lock();
        return true;
    }

    static void otp_read_block(
        uint32_t base_addr, uint8_t* out, size_t len) noexcept
    {
        const volatile uint8_t* src =
            reinterpret_cast<const volatile uint8_t*>(base_addr);
        for (size_t i = 0u; i < len; ++i) {
            out[i] = src[i];
        }
    }

    static bool otp_check_magic() noexcept {
        uint32_t val = 0u;
        otp_read_block(OTP_MAGIC_ADDR,
            reinterpret_cast<uint8_t*>(&val), sizeof(val));
        return (val == PROV_MAGIC);
    }

    static bool otp_write_magic() noexcept {
        const uint32_t magic = PROV_MAGIC;
        return otp_write_block(OTP_MAGIC_ADDR,
            reinterpret_cast<const uint8_t*>(&magic), sizeof(magic));
    }

    // RDP Level 2 설정 (영구 JTAG 잠금)
    static constexpr uint32_t FLASH_OPTKEYR_OFFSET = 0x08u;
    static constexpr uint32_t FLASH_OPTCR_OFFSET = 0x14u;
    static constexpr uint32_t OPT_KEY1 = 0x08192A3Bu;
    static constexpr uint32_t OPT_KEY2 = 0x4C5D6E7Fu;
    static constexpr uint32_t RDP_LEVEL_2 = 0x000000CCu;
    static constexpr uint32_t OPTCR_OPTSTRT = 0x00000002u;
    static constexpr uint32_t OPTCR_OPTLOCK = 0x00000001u;
    static constexpr uint32_t RDP_MASK = 0x0000FF00u;

    static bool set_rdp_level2() noexcept {
        if (!keyprov_voltage_ok_for_flash()) {
            return false;
        }
        // Option byte 잠금 해제
        *flash_reg(FLASH_OPTKEYR_OFFSET) = OPT_KEY1;
        *flash_reg(FLASH_OPTKEYR_OFFSET) = OPT_KEY2;
        if ((*flash_reg(FLASH_OPTCR_OFFSET) & OPTCR_OPTLOCK) != 0u) {
            return false;
        }
        // RDP Level 2 설정
        uint32_t optcr = *flash_reg(FLASH_OPTCR_OFFSET);
        optcr = (optcr & ~RDP_MASK) | (RDP_LEVEL_2 << 8u);
        *flash_reg(FLASH_OPTCR_OFFSET) = optcr;
        // 적용 시작
        *flash_reg(FLASH_OPTCR_OFFSET) |= OPTCR_OPTSTRT;
        // BSY 대기
        uint32_t guard = 500000u;
        while ((*flash_reg(FLASH_SR_OFFSET) & FLASH_SR_BSY) != 0u) {
            if (--guard == 0u) { return false; }
        }
        // Option byte 잠금
        *flash_reg(FLASH_OPTCR_OFFSET) |= OPTCR_OPTLOCK;
        const uint32_t chk = *flash_reg(FLASH_OPTCR_OFFSET);
        const uint32_t rdp_byte = (chk & RDP_MASK) >> 8u;
        if (rdp_byte != static_cast<uint32_t>(RDP_LEVEL_2 & 0xFFu)) {
            return false;
        }
        return true;
    }

#else
    // ── PC 시뮬레이션: OTP를 정적 배열로 에뮬레이션 ──
    static uint8_t  g_otp_emu[528] = {};
    static uint32_t g_rdp_level = 0u;
    static constexpr uint32_t PROV_MAGIC = 0x4B455931u;

    // PC에서는 base_addr를 g_otp_emu 오프셋으로 사용
    static constexpr uint32_t OTP_KEY_ADDR = 0u;     // 오프셋 0
    static constexpr uint32_t OTP_MAGIC_ADDR = 32u;    // 오프셋 32

    static bool otp_write_block(
        uint32_t offset, const uint8_t* data, size_t len) noexcept
    {
        if (data == nullptr || len == 0u) { return false; }
        if (len > sizeof(g_otp_emu) || offset > sizeof(g_otp_emu) - len) {
            return false;
        }
        std::memcpy(&g_otp_emu[offset], data, len);
        return true;
    }

    static void otp_read_block(
        uint32_t offset, uint8_t* out, size_t len) noexcept
    {
        if (out == nullptr || len == 0u) { return; }
        if (len > sizeof(g_otp_emu) || offset > sizeof(g_otp_emu) - len) {
            std::memset(out, 0, len);
            return;
        }
        std::memcpy(out, &g_otp_emu[offset], len);
    }

    static bool otp_check_magic() noexcept {
        uint32_t val = 0u;
        otp_read_block(OTP_MAGIC_ADDR,
            reinterpret_cast<uint8_t*>(&val), sizeof(val));
        return (val == PROV_MAGIC);
    }

    static bool otp_write_magic() noexcept {
        const uint32_t magic = PROV_MAGIC;
        return otp_write_block(OTP_MAGIC_ADDR,
            reinterpret_cast<const uint8_t*>(&magic), sizeof(magic));
    }

    static bool set_rdp_level2() noexcept {
        g_rdp_level = 2u;
        return true;
    }

#if defined(HTS_ALLOW_HOST_BUILD)
    /// 호스트 전원차단/복원 시뮬레이션 전용 — 실칩 미사용.
    extern "C" void HTS_Test_Host_KeyProv_OTP_Clear(void) noexcept {
        std::memset(g_otp_emu, 0, sizeof(g_otp_emu));
        g_rdp_level = 0u;
    }

    extern "C" void HTS_Test_Host_KeyProv_OTP_Import(const uint8_t* src, size_t len) noexcept {
        if (src == nullptr || len != sizeof(g_otp_emu)) { return; }
        std::memcpy(g_otp_emu, src, sizeof(g_otp_emu));
    }
#endif
#endif

    // =====================================================================
    //  AES-KW 언래핑 (RFC 3394, AES-256 키 / KEK)
    //
    //  입력: 래핑 40바이트 = (n+1)×8, n=4 세미블록(평문 32B)
    //  KEK:  32바이트 — AES_Bridge ECB 복호
    // =====================================================================
    static bool aes_kw_unwrap(
        const uint8_t* wrapped, size_t wrapped_len,
        const uint8_t* kek, size_t kek_len,
        uint8_t* plain_out, size_t plain_cap) noexcept
    {
        static constexpr size_t KEY_SIZE = 32u;
        static constexpr size_t KEK_SIZE = 32u;
        static constexpr size_t WRAP_SIZE = 40u;
        static constexpr uint32_t N = 4u;
        static constexpr uint8_t AES_KW_IV[8] = {
            0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6
        };

        if (wrapped == nullptr || kek == nullptr || plain_out == nullptr) {
            return false;
        }
        if (wrapped_len != WRAP_SIZE || kek_len != KEK_SIZE || plain_cap < KEY_SIZE) {
            return false;
        }

        AES_Bridge aes;
        if (!aes.Initialize_Decryption(kek, 256)) {
            Key_Prov_Secure_Wipe(plain_out, KEY_SIZE);
            return false;
        }

        uint8_t a[8];
        uint8_t r[4][8];
        for (int i = 0; i < 8; ++i) {
            a[i] = wrapped[i];
        }
        for (uint32_t b = 0u; b < N; ++b) {
            for (int i = 0; i < 8; ++i) {
                r[b][i] = wrapped[8 + static_cast<int>(b) * 8 + i];
            }
        }

        uint8_t block_in[16];
        uint8_t block_out[16];
        for (int j = 5; j >= 0; --j) {
            for (int ii = static_cast<int>(N); ii >= 1; --ii) {
                const uint64_t t =
                    static_cast<uint64_t>(N) * static_cast<uint64_t>(j)
                    + static_cast<uint64_t>(ii);
                uint8_t axor[8];
                keyprov_kw_xor_t(t, a, axor);
                for (int k = 0; k < 8; ++k) {
                    block_in[k] = axor[k];
                }
                for (int k = 0; k < 8; ++k) {
                    block_in[8 + k] = r[static_cast<uint32_t>(ii - 1)][k];
                }
                if (!aes.Process_Block(block_in, block_out)) {
                    aes.Reset();
                    Key_Prov_Secure_Wipe(plain_out, KEY_SIZE);
                    Key_Prov_Secure_Wipe(static_cast<void*>(a), sizeof(a));
                    Key_Prov_Secure_Wipe(static_cast<void*>(r), sizeof(r));
                    Key_Prov_Secure_Wipe(static_cast<void*>(block_in), sizeof(block_in));
                    Key_Prov_Secure_Wipe(static_cast<void*>(block_out), sizeof(block_out));
                    return false;
                }
                for (int k = 0; k < 8; ++k) {
                    a[k] = block_out[k];
                }
                for (int k = 0; k < 8; ++k) {
                    r[static_cast<uint32_t>(ii - 1)][k] = block_out[8 + k];
                }
            }
        }

        aes.Reset();

        if (!ConstantTimeUtil::compare(a, AES_KW_IV, 8u)) {
            Key_Prov_Secure_Wipe(plain_out, KEY_SIZE);
            Key_Prov_Secure_Wipe(static_cast<void*>(a), sizeof(a));
            Key_Prov_Secure_Wipe(static_cast<void*>(r), sizeof(r));
            Key_Prov_Secure_Wipe(static_cast<void*>(block_in), sizeof(block_in));
            Key_Prov_Secure_Wipe(static_cast<void*>(block_out), sizeof(block_out));
            return false;
        }
        for (uint32_t b = 0u; b < N; ++b) {
            for (int i = 0; i < 8; ++i) {
                plain_out[static_cast<size_t>(b) * 8u + static_cast<size_t>(i)] =
                    r[b][i];
            }
        }
        Key_Prov_Secure_Wipe(static_cast<void*>(a), sizeof(a));
        Key_Prov_Secure_Wipe(static_cast<void*>(r), sizeof(r));
        Key_Prov_Secure_Wipe(static_cast<void*>(block_in), sizeof(block_in));
        Key_Prov_Secure_Wipe(static_cast<void*>(block_out), sizeof(block_out));
        return true;
    }

    // =====================================================================
    //  Pimpl 구현 구조체
    // =====================================================================
    struct HTS_Key_Provisioning::Impl {
        // 프로비저닝 상태
        bool provisioned = false;
        bool debug_locked = false;
        bool key_destroyed = false;

        //  캐싱 없이 매번 OTP 직접 읽기 = 키 잔류 표면적 최소화

        Impl() noexcept {
            provisioned = otp_check_magic();
            debug_locked = false;
            key_destroyed = false;
        }

        ~Impl() noexcept {
            provisioned = false;
            debug_locked = false;
            key_destroyed = false;
        }
    };

    // =====================================================================
    //  컴파일 타임 크기·정렬 검증 + get_impl()
    //  (static_assert는 get_impl 내부에서 수행 — private Impl 접근 가능)
    // =====================================================================

    HTS_Key_Provisioning::Impl*
        HTS_Key_Provisioning::get_impl() noexcept
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl이 IMPL_BUF_SIZE를 초과합니다");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN,
            "Impl 정렬 요구가 impl_buf_ alignas를 초과합니다");
        return impl_valid_
            ? std::launder(reinterpret_cast<Impl*>(impl_buf_)) : nullptr;
    }

    const HTS_Key_Provisioning::Impl*
        HTS_Key_Provisioning::get_impl() const noexcept
    {
        return impl_valid_
            ? std::launder(reinterpret_cast<const Impl*>(impl_buf_)) : nullptr;
    }

    // =====================================================================
    //  생성자 — placement new (zero-heap)
    // =====================================================================
    HTS_Key_Provisioning::HTS_Key_Provisioning() noexcept
        : impl_valid_(false)
    {
        Key_Prov_Secure_Wipe(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl();
        impl_valid_ = true;
    }

    // =====================================================================
    //  소멸자 — p->~Impl() + 3중 보안 소거
    // =====================================================================
    HTS_Key_Provisioning::~HTS_Key_Provisioning() noexcept {
        Impl* p = get_impl();
        if (p != nullptr) { p->~Impl(); }
        Key_Prov_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
        impl_valid_ = false;
    }

    // =====================================================================
    //  Is_Provisioned — OTP 매직 확인
    // =====================================================================
    uint32_t HTS_Key_Provisioning::Is_Provisioned() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) { return SECURE_FALSE; }
        return p->provisioned ? SECURE_TRUE : SECURE_FALSE;
    }

    // =====================================================================
    //  Inject_Key — 래핑 해제 → OTP 기록 → Read-Back 검증
    // =====================================================================
    KeyProvResult HTS_Key_Provisioning::Inject_Key(
        const uint8_t* wrapped_key, size_t wrapped_len,
        const uint8_t* factory_kek, size_t kek_len) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return KeyProvResult::NULL_INPUT; }

        if (!keyprov_voltage_ok_for_flash()) {
            return KeyProvResult::POWER_UNSTABLE;
        }

        // 이미 프로비저닝 완료
        if (p->provisioned || otp_check_magic()) {
            p->provisioned = true;
            return KeyProvResult::ALREADY_DONE;
        }

        // 입력 검증
        if (wrapped_key == nullptr || factory_kek == nullptr) {
            return KeyProvResult::NULL_INPUT;
        }
        if (wrapped_len != WRAPPED_KEY_SIZE) {
            return KeyProvResult::INVALID_LEN;
        }
        if (kek_len != MASTER_KEY_SIZE) {
            return KeyProvResult::INVALID_LEN;
        }

        // 1단계: AES-KW 언래핑
        uint8_t plain_key[MASTER_KEY_SIZE] = {};
        const bool unwrap_ok = aes_kw_unwrap(
            wrapped_key, wrapped_len,
            factory_kek, kek_len,
            plain_key, sizeof(plain_key));

        if (!unwrap_ok) {
            Key_Prov_Secure_Wipe(plain_key, sizeof(plain_key));
            return KeyProvResult::UNWRAP_FAIL;
        }

        // 2단계: OTP 기록 (ARM/PC 공통 — otp_write_block 플랫폼별 구현)
        const bool write_ok = otp_write_block(
            OTP_KEY_ADDR, plain_key, MASTER_KEY_SIZE);

        if (!write_ok) {
            Key_Prov_Secure_Wipe(plain_key, sizeof(plain_key));
            return KeyProvResult::OTP_WRITE_FAIL;
        }

        // 3단계: Read-Back 검증 (Constant-Time)
        uint8_t readback[MASTER_KEY_SIZE] = {};
        otp_read_block(OTP_KEY_ADDR, readback, MASTER_KEY_SIZE);

        const bool readback_ok = ConstantTimeUtil::compare(
            plain_key, readback, MASTER_KEY_SIZE);

        // 평문 즉시 소거 (사용 완료)
        Key_Prov_Secure_Wipe(plain_key, sizeof(plain_key));
        Key_Prov_Secure_Wipe(readback, sizeof(readback));

        if (!readback_ok) {
            return KeyProvResult::VERIFY_FAIL;
        }

        // 4단계: 프로비저닝 매직 기록
        if (!otp_write_magic()) {
            return KeyProvResult::OTP_WRITE_FAIL;
        }

        p->provisioned = true;
        return KeyProvResult::OK;
    }

#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
    /// RDP 적용 직후 AIRCR 시스템 리셋 + (GCC/Clang만) DBGMCU WDT 프리즈 해제.
    /// 컴파일러 무관: fence·AIRCR·무한 대기 / DBGMCU·dsb·isb·wfi 는 전처리로 분리.
    [[noreturn]] static void keyprov_arm_aircr_reset_and_hang() noexcept
    {
        static constexpr uint32_t AIRCR_ADDR = 0xE000ED0Cu;
        static constexpr uint32_t AIRCR_VECTKEY = 0x05FA0000u;
        static constexpr uint32_t AIRCR_SYSRESET = 0x00000004u;
        std::atomic_thread_fence(std::memory_order_release);
        volatile uint32_t* const aircr =
            reinterpret_cast<volatile uint32_t*>(
                static_cast<uintptr_t>(AIRCR_ADDR));
        *aircr = AIRCR_VECTKEY | AIRCR_SYSRESET;
#if defined(__GNUC__) || defined(__clang__)
        static constexpr uint32_t ADDR_DBGMCU_FZ = 0xE0042008u;
        static constexpr uint32_t DBGMCU_WWDG_STOP = (1u << 11);
        static constexpr uint32_t DBGMCU_IWDG_STOP = (1u << 12);
        volatile uint32_t* const dbgmcu_fz =
            reinterpret_cast<volatile uint32_t*>(
                static_cast<uintptr_t>(ADDR_DBGMCU_FZ));
        *dbgmcu_fz &= ~(DBGMCU_WWDG_STOP | DBGMCU_IWDG_STOP);
        __asm__ __volatile__("dsb sy\n\t" "isb\n\t" ::: "memory");
#endif
        for (;;) {
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("wfi");
#endif
        }
    }
#endif

    // =====================================================================
    //  Read_Master_Key — OTP에서 마스터 키 읽기
    // =====================================================================
    uint32_t HTS_Key_Provisioning::Read_Master_Key(
        uint8_t* out_buf, size_t out_len) const noexcept
    {
        const Impl* p = get_impl();
        if (p == nullptr || out_buf == nullptr) { return SECURE_FALSE; }
        if (out_len < MASTER_KEY_SIZE) { return SECURE_FALSE; }
        if (!p->provisioned) { return SECURE_FALSE; }
        if (p->key_destroyed) { return SECURE_FALSE; }

        otp_read_block(OTP_KEY_ADDR, out_buf, MASTER_KEY_SIZE);
        return SECURE_TRUE;
    }

    // =====================================================================
    //  Lock_Debug_Port — JTAG/SWD 영구 잠금
    //
    //  RAM의 debug_locked만 믿으면 재부팅 후 초기화 → RDP L2인데
    //  set_rdp_level2() 재호출 시 FLASH_OPTCR 접근으로 Brick 위험.
    //  FLASH_OPTCR에서 RDP 바이트를 직접 읽어 L2면 ALREADY_DONE (하드웨어 기준).
    // =====================================================================
    KeyProvResult HTS_Key_Provisioning::Lock_Debug_Port() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return KeyProvResult::NULL_INPUT; }

        if (!keyprov_voltage_ok_for_flash()) {
            return KeyProvResult::POWER_UNSTABLE;
        }

        //  RAM 플래그(p->debug_locked)는 재부팅 시 초기화되므로 신뢰 불가
        //  → FLASH_OPTCR[15:8] = RDP 바이트 직접 읽기
#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
        {
            // FLASH_OPTCR 주소: FLASH_BASE(0x40023C00) + 오프셋(0x14)
            const uint32_t cur_optcr = *flash_reg(FLASH_OPTCR_OFFSET);
            const uint32_t cur_rdp = (cur_optcr & RDP_MASK) >> 8u;
            if (cur_rdp == RDP_LEVEL_2) {
                // 이미 Level 2 잠금 완료 — 재접근 시도 차단 (Brick 방지)
                p->debug_locked = true;  // RAM 플래그 동기화
                return KeyProvResult::ALREADY_DONE;
            }
        }
#else
        // PC 시뮬레이션: RAM 플래그로 fallback
        if (p->debug_locked) { return KeyProvResult::ALREADY_DONE; }
#endif

        if (!set_rdp_level2()) {
            return KeyProvResult::LOCK_FAIL;
        }

        p->debug_locked = true;

        //  리셋 없이 반환하면 다음 재부팅 전까지 JTAG 열림 (보안 공백)
        //  AIRCR.SYSRESETREQ — ARM: noreturn 헬퍼 / PC: OK 반환만
#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
        keyprov_arm_aircr_reset_and_hang();
#else
        return KeyProvResult::OK;
#endif
    }

    // =====================================================================
    // =====================================================================
    //  Destroy_Key — 마스터 키 + 프로비저닝 매직 물리적 소각
    //
    //  키만 태우고 매직이 남으면 재부팅 후 Is_Provisioned()가 참이 될 수 있음.
    //  키 블록 소각 직후 매직 블록도 0으로 덮어 프로비저닝 상태를 하드웨어에서 무효화.
    // =====================================================================
    void HTS_Key_Provisioning::Destroy_Key() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        if (!keyprov_voltage_ok_for_flash()) {
            return;
        }

        // 1단계: 마스터 키 물리 소각
        //  OTP 특성: 1→0 쓰기만 가능 (비가역)
        //  0x00 덮어쓰기 → 모든 비트를 0으로 태움
        const uint8_t zero_block[MASTER_KEY_SIZE] = {};
        const bool wiped_key = otp_write_block(OTP_KEY_ADDR, zero_block, MASTER_KEY_SIZE);

        // 2단계: 프로비저닝 매직도 함께 물리 소각
        //  sizeof(PROV_MAGIC) = 4B → 4바이트 영역 소각
        //  재부팅 후 Is_Provisioned() = false 보장
        //  (매직 불일치 → provisioned=false → Read_Master_Key 반환 차단)
        const uint8_t zero_magic[sizeof(PROV_MAGIC)] = {};
        const bool wiped_magic = otp_write_block(OTP_MAGIC_ADDR,
            zero_magic, static_cast<uint32_t>(sizeof(PROV_MAGIC)));

        if (!wiped_key || !wiped_magic) {
            return;
        }

        // 3단계: RAM 플래그 갱신 (현재 세션 즉시 차단) — OTP와 일치할 때만
        p->key_destroyed = true;
        p->provisioned = false;  // RAM 상태도 동기화
    }

    // =====================================================================
    //  Shutdown — 안전 종료
    // =====================================================================
    void HTS_Key_Provisioning::Shutdown() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        // Impl에 키 캐시 없음 → 추가 소거 불필요
        // impl_buf_ 전체 소거는 소멸자에서 수행
    }

} // namespace ProtectedEngine
