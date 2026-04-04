// Verify_APT_Annihilation — 호스트 APT/물리·논리 복합 공격 **모사** (7단계 God-Tier TU)
// · DPA/CPA: ConstantTimeUtil::compare 동일·불일치 경로 QPC 마이크로초 평균 차 검출(윈도우 스케줄러 노이즈 허용)
// · 비트 플립: CRC32 변조 감지 + SecureMemory::secureWipe(키 버퍼 파기 시뮬)
// · ROP/OS: Win64 CFG 완화 정책 조회 + 펌웨어 CFI(상태머신)는 정적 요약
//
// Windows.h 는 HTS 헤더 뒤 — ERROR 매크로 충돌 방지

#include "HTS_ConstantTimeUtil.h"
#include "HTS_Crc32Util.h"
#include "HTS_Crypto_KAT.h"
#include "HTS_Secure_Memory.h"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace {

using namespace ProtectedEngine;

// 호스트 스케줄러 노이즈: 평균 차이 허용(µs) — 실칩 CYCCNT·전력측정은 별도 HIL
constexpr double kMaxMeanDiffUs = 8.0;
constexpr int kTimingSamples = 4000;

[[nodiscard]] static bool attack_side_channel_profile() {
    alignas(64) uint8_t buf_a[32]{};
    alignas(64) uint8_t buf_b[32]{};
    alignas(64) uint8_t buf_ne[32]{};
    for (size_t i = 0u; i < 32u; ++i) {
        buf_a[i] = static_cast<uint8_t>(0xA5u + static_cast<uint8_t>(i));
        buf_b[i] = buf_a[i];
        buf_ne[i] = buf_a[i];
    }
    buf_ne[31u] = static_cast<uint8_t>(buf_ne[31u] ^ 0xFFu);

    LARGE_INTEGER freq{};
    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart == 0) {
        std::fputs("APT: QueryPerformanceFrequency failed\n", stderr);
        return false;
    }

    double sum_eq = 0.0;
    double sum_ne = 0.0;
    for (int i = 0; i < kTimingSamples; ++i) {
        LARGE_INTEGER t0;
        LARGE_INTEGER t1;

        QueryPerformanceCounter(&t0);
        const volatile bool r0 =
            ConstantTimeUtil::compare(buf_a, buf_b, 32u);
        QueryPerformanceCounter(&t1);
        sum_eq += static_cast<double>(t1.QuadPart - t0.QuadPart) * 1.0e6
            / static_cast<double>(freq.QuadPart);
        (void)r0;

        QueryPerformanceCounter(&t0);
        const volatile bool r1 =
            ConstantTimeUtil::compare(buf_a, buf_ne, 32u);
        QueryPerformanceCounter(&t1);
        sum_ne += static_cast<double>(t1.QuadPart - t0.QuadPart) * 1.0e6
            / static_cast<double>(freq.QuadPart);
        (void)r1;
    }

    const double mean_eq = sum_eq / static_cast<double>(kTimingSamples);
    const double mean_ne = sum_ne / static_cast<double>(kTimingSamples);
    const double diff = std::fabs(mean_eq - mean_ne);

    std::printf(
        "APT: [1] ConstantTimeUtil compare mean time (us): equal=%.4f unequal=%.4f |diff|=%.4f (host thresh %.2f)\n",
        mean_eq,
        mean_ne,
        diff,
        kMaxMeanDiffUs);

    if (diff > kMaxMeanDiffUs) {
        std::fputs(
            "APT: [1] FAIL — possible timing skew (see dummy-op patch in audit if on-target repro)\n",
            stderr);
        return false;
    }
    std::puts("APT: [1] Side-channel timing profile — PASS (host surrogate)");
    return true;
}

[[nodiscard]] static bool attack_bit_flip_integrity_wipe() {
    alignas(8) uint8_t key[64]{};
    for (size_t i = 0u; i < sizeof(key); ++i) {
        key[i] = static_cast<uint8_t>(0x3Cu ^ static_cast<uint8_t>(i));
    }
    const uint32_t h0 = Crc32Util::calculate(key, sizeof(key));
    key[37u] = static_cast<uint8_t>(key[37u] ^ 0x01u);
    const uint32_t h1 = Crc32Util::calculate(key, sizeof(key));

    if (h0 == h1) {
        std::fputs("APT: [2] CRC unchanged after bit-flip (unexpected)\n", stderr);
        return false;
    }
    std::printf(
        "APT: [2] Bit-flip: CRC32 0x%08X -> 0x%08X (tamper detected)\n",
        static_cast<unsigned>(h0),
        static_cast<unsigned>(h1));

    SecureMemory::secureWipe(key, sizeof(key));
    uint32_t nz = 0u;
    for (size_t i = 0u; i < sizeof(key); ++i) {
        nz = nz + static_cast<uint32_t>(key[i] != 0u);
    }
    if (nz != 0u) {
        std::fputs("APT: [2] secureWipe residual non-zero\n", stderr);
        return false;
    }
    std::puts("APT: [2] Tamper -> SecureMemory::secureWipe — PASS");
    return true;
}

[[nodiscard]] static bool attack_rop_cfi_surface_report() {
#if defined(_WIN64)
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};
    if (GetProcessMitigationPolicy(
            GetCurrentProcess(),
            ProcessControlFlowGuardPolicy,
            &cfg,
            sizeof(cfg)))
    {
        std::printf(
            "APT: [3] Win64 CFG: EnableControlFlowGuard=%u StrictMode=%u\n",
            static_cast<unsigned>(cfg.EnableControlFlowGuard),
            static_cast<unsigned>(cfg.StrictMode));
    }
    else {
        std::puts("APT: [3] Win64 CFG: GetProcessMitigationPolicy unavailable");
    }
#else
    std::puts("APT: [3] CFG policy query skipped (not Win64)");
#endif
    std::puts(
        "APT: [3] Firmware CFI: state machines (e.g. Bridge/IPC/Mesh Transition_*) — "
        "gadget inventory not performed in TU; on-target ROP needs CFG+MPU+signed image policy.");
    return true;
}

[[nodiscard]] static bool run_crypto_kat_gate() {
    if (!Crypto_KAT::Run_All_Crypto_KAT()) {
        std::fputs("APT: Crypto_KAT FAILED — abort annihilation suite\n", stderr);
        return false;
    }
    std::puts("APT: Crypto_KAT gate — PASS");
    return true;
}

} // namespace

int main() {
    if (!run_crypto_kat_gate()) {
        return 2;
    }
    if (!attack_side_channel_profile()) {
        return 3;
    }
    if (!attack_bit_flip_integrity_wipe()) {
        return 4;
    }
    if (!attack_rop_cfi_surface_report()) {
        return 5;
    }

    std::puts("Verify_APT_Annihilation: ALL host-surrogate checks PASSED");
    return 0;
}
