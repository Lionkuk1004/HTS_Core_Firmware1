// =========================================================================
// HTS_Key_Provisioning.cpp
// 공장 출하 키 프로비저닝 엔진 구현부 (Pimpl 은닉)
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// [양산 수정 이력]
//  v1.0 — 초기 작성
//    · Pimpl placement new (zero-heap)
//    · AES-KW 언래핑 → OTP 기록 → Read-Back 검증
//    · Constant-Time 비교 (타이밍 공격 방지)
//    · 3중 보안 소거 (volatile + asm clobber + release fence)
//    · OTP 타임아웃 가드 (무한 루프 방지)
//    · 디버그 포트 잠금 (RDP Level 2)
// =========================================================================
#include "HTS_Key_Provisioning.h"

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
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  Constant-Time 비교 (타이밍 사이드채널 차단)
    //  반환: 0 = 일치, 비0 = 불일치
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
        return true;
    }

    static bool otp_write_block(
        uint32_t base_addr, const uint8_t* data, size_t len) noexcept
    {
        if (!flash_unlock()) { return false; }
        for (size_t i = 0u; i < len; ++i) {
            if (!otp_write_byte(base_addr + static_cast<uint32_t>(i), data[i])) {
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
        if (offset + len > sizeof(g_otp_emu)) { return false; }
        std::memcpy(&g_otp_emu[offset], data, len);
        return true;
    }

    static void otp_read_block(
        uint32_t offset, uint8_t* out, size_t len) noexcept
    {
        if (out == nullptr || len == 0u) { return; }
        if (offset + len > sizeof(g_otp_emu)) {
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
#endif

    // =====================================================================
    //  AES-KW 경량 언래핑 (RFC 3394, 128비트 키 전용)
    //
    //  입력: 래핑된 키 24바이트 (IV 8B + 암호문 16B)
    //  출력: 평문 키 16바이트
    //  KEK:  공장 라인 공통 키 16바이트
    //
    //  AES-KW는 AES_Bridge 없이도 구현 가능하나,
    //  기존 ARIA/AES 브릿지를 재사용하기 위해 ECB 디크립트를 직접 호출.
    //  → 현재 버전: 단순 XOR 래핑 (POC)
    //  → 양산 시: AES_Bridge::Decrypt_ECB 연동으로 교체
    // =====================================================================
    static bool aes_kw_unwrap(
        const uint8_t* wrapped, size_t wrapped_len,
        const uint8_t* kek, size_t kek_len,
        uint8_t* plain_out, size_t plain_cap) noexcept
    {
        static constexpr size_t KEY_SIZE = 32u;   // 256비트 마스터 키
        static constexpr size_t KEK_SIZE = 32u;   // 256비트 KEK
        static constexpr size_t WRAP_SIZE = 40u;  // KEY + 8B IV
        static constexpr uint8_t AES_KW_IV[8] = {
            0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6
        };

        if (wrapped == nullptr || kek == nullptr || plain_out == nullptr) {
            return false;
        }
        if (wrapped_len != WRAP_SIZE || kek_len != KEK_SIZE || plain_cap < KEY_SIZE) {
            return false;
        }

        // POC: XOR 기반 간이 언래핑 (양산 시 AES-ECB로 교체)
        // IV 검증
        uint32_t iv_diff = 0u;
        for (size_t i = 0u; i < 8u; ++i) {
            const uint8_t dec_iv = wrapped[i] ^ kek[i % KEK_SIZE];
            iv_diff |= static_cast<uint32_t>(dec_iv ^ AES_KW_IV[i]);
        }

        // 평문 추출 (32바이트 전체를 KEK로 XOR)
        for (size_t i = 0u; i < KEY_SIZE; ++i) {
            plain_out[i] = wrapped[8u + i] ^ kek[i % KEK_SIZE];
        }

        // IV 불일치 시 평문 소거 후 실패
        if (iv_diff != 0u) {
            Key_Prov_Secure_Wipe(plain_out, KEY_SIZE);
            return false;
        }
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

        // [FIX-DEAD] key_buf 삭제 — Read_Master_Key는 OTP→호출자 직접 복사
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
            ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }

    const HTS_Key_Provisioning::Impl*
        HTS_Key_Provisioning::get_impl() const noexcept
    {
        return impl_valid_
            ? reinterpret_cast<const Impl*>(impl_buf_) : nullptr;
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
    bool HTS_Key_Provisioning::Is_Provisioned() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr) { return false; }
        return p->provisioned;
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

        const uint32_t diff = ct_compare(plain_key, readback, MASTER_KEY_SIZE);

        // 평문 즉시 소거 (사용 완료)
        Key_Prov_Secure_Wipe(plain_key, sizeof(plain_key));
        Key_Prov_Secure_Wipe(readback, sizeof(readback));

        if (diff != 0u) {
            return KeyProvResult::VERIFY_FAIL;
        }

        // 4단계: 프로비저닝 매직 기록
        if (!otp_write_magic()) {
            return KeyProvResult::OTP_WRITE_FAIL;
        }

        p->provisioned = true;
        return KeyProvResult::OK;
    }

    // =====================================================================
    //  Read_Master_Key — OTP에서 마스터 키 읽기
    // =====================================================================
    bool HTS_Key_Provisioning::Read_Master_Key(
        uint8_t* out_buf, size_t out_len) const noexcept
    {
        const Impl* p = get_impl();
        if (p == nullptr || out_buf == nullptr) { return false; }
        if (out_len < MASTER_KEY_SIZE) { return false; }
        if (!p->provisioned) { return false; }
        if (p->key_destroyed) { return false; }

        otp_read_block(OTP_KEY_ADDR, out_buf, MASTER_KEY_SIZE);
        return true;
    }

    // =====================================================================
    //  Lock_Debug_Port — JTAG/SWD 영구 잠금
    // =====================================================================
    KeyProvResult HTS_Key_Provisioning::Lock_Debug_Port() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return KeyProvResult::NULL_INPUT; }
        if (p->debug_locked) { return KeyProvResult::ALREADY_DONE; }

        if (!set_rdp_level2()) {
            return KeyProvResult::LOCK_FAIL;
        }

        p->debug_locked = true;

        // [FIX-JTAG] RDP Level 2는 시스템 리셋 후에만 하드웨어 적용
        //  리셋 없이 반환하면 다음 재부팅 전까지 JTAG 열림 (보안 공백)
        //  AIRCR.SYSRESETREQ로 즉시 하드웨어 리셋 강제
#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
        static constexpr uint32_t AIRCR_ADDR = 0xE000ED0Cu;
        static constexpr uint32_t AIRCR_VECTKEY = 0x05FA0000u;
        static constexpr uint32_t AIRCR_SYSRESET = 0x00000004u;
        std::atomic_thread_fence(std::memory_order_seq_cst);
        *reinterpret_cast<volatile uint32_t*>(AIRCR_ADDR) =
            AIRCR_VECTKEY | AIRCR_SYSRESET;
        // 이 아래 코드는 도달 불가 (리셋 즉시 실행)
        for (;;) {}  // 리셋 대기 (CPU가 리셋될 때까지 홀드)
#endif
        return KeyProvResult::OK;  // PC: 리셋 불필요
    }

    // =====================================================================
    //  Destroy_Key — 마스터 키 무효화 (논리적)
    // =====================================================================
    void HTS_Key_Provisioning::Destroy_Key() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        // [FIX-FORENSIC] OTP 키 영역 물리적 소각
        //  OTP 특성: 1→0 쓰기만 가능 (0→1 불가)
        //  0x00 블록 덮어쓰기 → 모든 비트를 0으로 태움
        //  → 전원 사이클 후에도 키 복구 불가 (비가역)
        const uint8_t zero_block[MASTER_KEY_SIZE] = {};
        otp_write_block(OTP_KEY_ADDR, zero_block, MASTER_KEY_SIZE);

        p->key_destroyed = true;
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