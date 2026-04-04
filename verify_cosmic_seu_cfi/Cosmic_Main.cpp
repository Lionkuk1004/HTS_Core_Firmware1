// Verify_Cosmic_SEU_CFI — 16단계: SEU 비트 플립, CFI 가상 HardFault, 패닉 시 Secure Wipe + 덤프 검증
// 호스트 x64: 예외로 “살리기” 금지 — 감지 시 즉시 Terminate + secureWipe + 0 덤프 스캔

#include "HTS_Crc32Util.h"
#include "HTS_IPC_Protocol_Defs.h"
#include "HTS_Secure_Memory.h"
#include "HTS_Security_Session.h"

#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace {

namespace PE = ProtectedEngine;

using PE::CipherAlgorithm;
using PE::Crc32Util;
using PE::HTS_Security_Session;
using PE::MacAlgorithm;
using PE::SecureMemory;

constexpr uint32_t kPhaseAuth = 0xA70FA70Fu;
constexpr size_t   kPhaseBytes = 12u;
constexpr size_t   kVaultBytes = 64u;
constexpr size_t   kSignedBytes = kPhaseBytes + kVaultBytes;

static_assert(kSignedBytes == 76u, "signed layout");

struct alignas(16) CosmicBlob {
    uint8_t signed_region[kSignedBytes]{};
    uint32_t crc_committed = 0u;
};

std::mutex g_blob_mu;

[[nodiscard]] bool phases_all_auth(const CosmicBlob& b) noexcept
{
    uint32_t p[3u];
    std::memcpy(p, b.signed_region, sizeof(p));
    return p[0] == kPhaseAuth && p[1] == kPhaseAuth && p[2] == kPhaseAuth;
}

[[nodiscard]] uint32_t crc_of_signed(const CosmicBlob& b) noexcept
{
    return Crc32Util::calculate(b.signed_region, kSignedBytes);
}

void blob_init_auth(CosmicBlob& b, const uint8_t* vault_src) noexcept
{
    const uint32_t p[3u] = { kPhaseAuth, kPhaseAuth, kPhaseAuth };
    std::memcpy(b.signed_region, p, sizeof(p));
    std::memcpy(b.signed_region + kPhaseBytes, vault_src, kVaultBytes);
    b.crc_committed = crc_of_signed(b);
}

[[nodiscard]] bool blob_integrity_ok(const CosmicBlob& b) noexcept
{
    if (!phases_all_auth(b)) {
        return false;
    }
    return crc_of_signed(b) == b.crc_committed;
}

void volatile_zero_tail(uint8_t* p, size_t n) noexcept
{
    volatile uint8_t* v = reinterpret_cast<volatile uint8_t*>(p);
    for (size_t i = 0u; i < n; ++i) {
        v[i] = 0u;
    }
    std::atomic_thread_fence(std::memory_order_release);
#if defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
}

[[nodiscard]] bool dump_all_zero(const uint8_t* buf, size_t n) noexcept
{
    for (size_t i = 0u; i < n; ++i) {
        if (buf[i] != 0u) {
            return false;
        }
    }
    return true;
}

std::atomic<bool> g_seu_stop{ true };

void seu_thread_main(CosmicBlob* blob, std::atomic<uint64_t>& flips)
{
    uint64_t s = 0xDEADBEEFCAFEBABEULL;
    while (!g_seu_stop.load(std::memory_order_acquire)) {
        uint32_t x = static_cast<uint32_t>(s >> 32u);
        x ^= x << 13u;
        x ^= x >> 17u;
        x ^= x << 5u;
        s = (s << 32u) | static_cast<uint64_t>(x);

        std::lock_guard<std::mutex> lk(g_blob_mu);
        uint8_t* raw = reinterpret_cast<uint8_t*>(blob);
        constexpr size_t total = sizeof(CosmicBlob);
        const size_t idx = static_cast<size_t>(x % total);
        const uint32_t bit = x & 7u;
        raw[idx] ^= static_cast<uint8_t>(1u << bit);
        flips.fetch_add(1u, std::memory_order_relaxed);
    }
}

void cosmic_panic_wipe(
    HTS_Security_Session& sess,
    CosmicBlob& blob,
    uint8_t* enc_copy,
    uint8_t* mac_copy,
    uint8_t* enc_live,
    uint8_t* mac_live,
    uint8_t* iv_live,
    size_t key_len,
    size_t iv_len) noexcept
{
    g_seu_stop.store(true, std::memory_order_release);
    sess.Terminate_Session();
    {
        std::lock_guard<std::mutex> lk(g_blob_mu);
        SecureMemory::secureWipe(static_cast<void*>(&blob), sizeof(blob));
        volatile_zero_tail(reinterpret_cast<uint8_t*>(&blob), sizeof(blob));
    }
    SecureMemory::secureWipe(static_cast<void*>(enc_copy), key_len);
    SecureMemory::secureWipe(static_cast<void*>(mac_copy), key_len);
    volatile_zero_tail(enc_copy, key_len);
    volatile_zero_tail(mac_copy, key_len);
    SecureMemory::secureWipe(static_cast<void*>(enc_live), key_len);
    SecureMemory::secureWipe(static_cast<void*>(mac_live), key_len);
    SecureMemory::secureWipe(static_cast<void*>(iv_live), iv_len);
    volatile_zero_tail(enc_live, key_len);
    volatile_zero_tail(mac_live, key_len);
    volatile_zero_tail(iv_live, iv_len);
}

[[nodiscard]] bool run_seu_and_panic() noexcept
{
    CosmicBlob blob{};
    alignas(8) uint8_t enc_key[32]{};
    alignas(8) uint8_t mac_key[32]{};
    alignas(8) uint8_t iv[16]{};
    alignas(8) uint8_t enc_copy[32]{};
    alignas(8) uint8_t mac_copy[32]{};

    for (size_t i = 0u; i < 32u; ++i) {
        enc_key[i] = static_cast<uint8_t>(0xCEu ^ static_cast<uint8_t>(i));
        mac_key[i] = static_cast<uint8_t>(0x2Du ^ static_cast<uint8_t>(i));
        enc_copy[i] = enc_key[i];
        mac_copy[i] = mac_key[i];
    }
    for (size_t i = 0u; i < 16u; ++i) {
        iv[i] = static_cast<uint8_t>(0x55u ^ static_cast<uint8_t>(i));
    }

    uint8_t* const vault_ptr = blob.signed_region + kPhaseBytes;
    std::memcpy(vault_ptr, enc_key, 32u);
    std::memcpy(vault_ptr + 32u, mac_key, 32u);
    blob_init_auth(blob, vault_ptr);

    HTS_Security_Session sess;
    if (!sess.Initialize(
            CipherAlgorithm::LEA_256_CTR, MacAlgorithm::HMAC_SHA256,
            enc_key, mac_key, iv)) {
        std::printf("COSMIC[SEU] FAIL: session init\n");
        return false;
    }
    if (!sess.Is_Active()) {
        std::printf("COSMIC[SEU] FAIL: not active\n");
        return false;
    }

    std::atomic<uint64_t> flip_count{ 0u };
    g_seu_stop.store(false, std::memory_order_release);
    std::thread seu(seu_thread_main, &blob, std::ref(flip_count));

    bool tripped = false;
    const auto t_deadline
        = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (std::chrono::steady_clock::now() < t_deadline) {
        CosmicBlob snap{};
        {
            std::lock_guard<std::mutex> lk(g_blob_mu);
            snap = blob;
        }
        if (!blob_integrity_ok(snap)) {
            tripped = true;
            break;
        }
        if (flip_count.load(std::memory_order_relaxed) > 12'000'000ull) {
            std::printf("COSMIC[SEU] FAIL: no corruption in 12M flips\n");
            g_seu_stop.store(true, std::memory_order_release);
            seu.join();
            return false;
        }
        std::this_thread::yield();
    }

    g_seu_stop.store(true, std::memory_order_release);
    seu.join();

    if (!tripped) {
        std::printf("COSMIC[SEU] FAIL: timeout without trip\n");
        sess.Terminate_Session();
        return false;
    }

    std::printf(
        "COSMIC[SEU] TRIP: flips=%" PRIu64 " — fail-closed panic (no recovery)\n",
        flip_count.load(std::memory_order_relaxed));

    cosmic_panic_wipe(
        sess, blob, enc_copy, mac_copy, enc_key, mac_key, iv, 32u, 16u);

    if (sess.Is_Active()) {
        std::printf("COSMIC[SEU] FAIL: session still active after panic\n");
        return false;
    }

    if (!dump_all_zero(reinterpret_cast<const uint8_t*>(&blob), sizeof(blob))) {
        std::printf("COSMIC[WIPE] FAIL: blob post-dump not all-zero\n");
        return false;
    }
    if (!dump_all_zero(enc_copy, sizeof(enc_copy))
        || !dump_all_zero(mac_copy, sizeof(mac_copy))) {
        std::printf("COSMIC[WIPE] FAIL: key mirror not all-zero\n");
        return false;
    }
    if (!dump_all_zero(enc_key, sizeof(enc_key)) || !dump_all_zero(mac_key, sizeof(mac_key))
        || !dump_all_zero(iv, sizeof(iv))) {
        std::printf("COSMIC[WIPE] FAIL: live key/iv stack not all-zero\n");
        return false;
    }

    std::printf(
        "COSMIC[WIPE] PASS: blob+mirrors+live keys/iv all-zero dump (%zu B blob)\n",
        sizeof(blob));
    return true;
}

using VoidFn = void (*)();

static void cfi_good_a() noexcept {}
static void cfi_good_b() noexcept {}

[[nodiscard]] bool cfi_allowlisted(VoidFn fn) noexcept
{
    const uintptr_t a = reinterpret_cast<uintptr_t>(fn);
    return a == reinterpret_cast<uintptr_t>(&cfi_good_a)
        || a == reinterpret_cast<uintptr_t>(&cfi_good_b);
}

[[nodiscard]] bool run_cfi_virtual_hardfault() noexcept
{
    alignas(64) uint8_t decoy_executable_shape[64]{};
    decoy_executable_shape[0] = 0xC3u;

    uint64_t worst_us = 0u;
    constexpr int kTrials = 20'000;

    for (int i = 0; i < kTrials; ++i) {
        VoidFn rogue = reinterpret_cast<VoidFn>(
            static_cast<void*>(decoy_executable_shape + (i & 15)));
        const auto t0 = std::chrono::steady_clock::now();
        if (cfi_allowlisted(rogue)) {
            std::printf("COSMIC[CFI] FAIL: rogue allowlisted\n");
            return false;
        }
        alignas(64) uint8_t scratch[64]{};
        for (size_t j = 0u; j < sizeof(scratch); ++j) {
            scratch[j] = static_cast<uint8_t>(0x5Au ^ static_cast<uint8_t>(j));
        }
        SecureMemory::secureWipe(scratch, sizeof(scratch));
        volatile_zero_tail(scratch, sizeof(scratch));
        const auto t1 = std::chrono::steady_clock::now();
        const uint64_t us = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0)
                .count());
        if (us > worst_us) {
            worst_us = us;
        }
        for (size_t j = 0u; j < sizeof(scratch); ++j) {
            if (scratch[j] != 0u) {
                std::printf("COSMIC[CFI] FAIL: scratch not zero\n");
                return false;
            }
        }
        (void)rogue;
    }

    if (worst_us >= 1000ull) {
        std::printf(
            "COSMIC[CFI] FAIL: virtual HF path %" PRIu64 " us (cap 999us)\n",
            worst_us);
        return false;
    }
    std::printf(
        "COSMIC[CFI] PASS: %" PRIu32 " rogue targets blocked, worst_us=%" PRIu64
        " (no jump executed)\n",
        static_cast<uint32_t>(kTrials), worst_us);
    return true;
}

[[nodiscard]] bool run_ipc_cfi_glitch_guard() noexcept
{
    const uint8_t glitched = 0x1Fu;
    const PE::IPC_State bad = static_cast<PE::IPC_State>(glitched);
    if (PE::IPC_Is_Valid_State(bad)) {
        std::printf("COSMIC[CFI] FAIL: multi-bit glitch accepted\n");
        return false;
    }
    return true;
}

} // namespace

int main()
{
    std::printf("Verify_Cosmic_SEU_CFI: SEU + CFI gate + panic wipe\n");
    std::fflush(stdout);

    if (!run_ipc_cfi_glitch_guard()) {
        return 1;
    }
    if (!run_seu_and_panic()) {
        return 2;
    }
    if (!run_cfi_virtual_hardfault()) {
        return 3;
    }

    VoidFn ok = &cfi_good_a;
    if (!cfi_allowlisted(ok)) {
        std::printf("COSMIC[CFI] FAIL: good fn rejected\n");
        return 4;
    }

    std::printf("Verify_Cosmic_SEU_CFI: ALL PASS\n");
    return 0;
}
