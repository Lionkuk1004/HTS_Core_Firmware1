// Verify_Fault_Injection — 호스트(PC) 물리 결함 주입 방어 시뮬레이션
//  공격 1: JTAG/디버거 부착 모사 → 감사 링 secureWipe 후 Terminal_Fault(std::abort)
//  공격 2: Flash/OTP 무결성 붕괴 모사 → 기대 해시≠계산(0xAA) 시 HTS_Secure_Boot_Check≠0
//
// ARM 실칩 DHCSR 폴링은 본 TU에서 재현 불가; 실제 JTAG 탐지는 타겟 전용 경로로 검증.

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdio>
#include <cstring>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>

#include "HTS_ConstantTimeUtil.h"
#include "HTS_Secure_Boot_Verify.h"
#include "HTS_Secure_Logger.h"
#include "HTS_Secure_Memory.h"

extern "C" void HTS_Test_Host_Reset_SecureBoot_OTP_Emulation(void) noexcept;

using ProtectedEngine::ConstantTimeUtil;
using ProtectedEngine::HTS_Secure_Boot_Verify;
using ProtectedEngine::SecureLogger;
using ProtectedEngine::SecureMemory;

namespace {

int RunAttackFlashIntegrity() noexcept {
    HTS_Test_Host_Reset_SecureBoot_OTP_Emulation();

    uint8_t fake_key[32];
    for (unsigned i = 0u; i < 32u; ++i) {
        fake_key[i] = static_cast<uint8_t>(0x5Au + i);
    }
    SecureMemory::secureWipe(fake_key, sizeof(fake_key));
    uint8_t z32[32] = {};
    if (!ConstantTimeUtil::compare(fake_key, z32, sizeof(fake_key))) {
        std::fputs("FI: secureWipe key buffer verify failed\n", stderr);
        return 1;
    }

    alignas(8) uint8_t stack_secret[64];
    std::memset(stack_secret, 0xCC, sizeof(stack_secret));
    SecureMemory::secureWipe(stack_secret, sizeof(stack_secret));
    uint8_t z64[64] = {};
    if (!ConstantTimeUtil::compare(stack_secret, z64, sizeof(stack_secret))) {
        std::fputs("FI: secureWipe stack buffer verify failed\n", stderr);
        return 1;
    }

    HTS_Secure_Boot_Verify boot;
    uint8_t wrong_expected[32] = {};
    if (!boot.Provision_Expected_Hash(wrong_expected, sizeof(wrong_expected))) {
        std::fputs("FI: Provision_Expected_Hash failed (OTP already locked?)\n", stderr);
        return 1;
    }

    const int32_t boot_rc = HTS_Secure_Boot_Check();
    if (boot_rc == 0) {
        std::fputs("FI: expected HTS_Secure_Boot_Check failure for hash mismatch\n", stderr);
        return 1;
    }

    std::fputs(
        "FI: Attack 2 (flash/integrity mismatch) — HTS_Secure_Boot_Check returned non-zero; "
        "key/stack wipe verified.\n",
        stdout);
    return 0;
}

[[noreturn]] void RunAttackJtagSimulated() noexcept {
    SecureLogger::logSecurityEvent("FI_SIM", "JTAG_DEBUGGER_ATTACH");
    SecureLogger_WipeRingAndFault();
}

int SpawnChildWithArg(const char* arg) noexcept {
    char exe_path[MAX_PATH];
    const DWORD n = GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
    if (n == 0u || n >= MAX_PATH) {
        std::fputs("FI: GetModuleFileNameA failed\n", stderr);
        return 1;
    }

    // CreateProcess는 명령줄 버퍼를 수정할 수 있어야 함 (문서 요구).
    char cmdline[1024];
    const int w = std::snprintf(cmdline, sizeof(cmdline), "\"%s\" %s", exe_path, arg);
    if (w < 0 || static_cast<size_t>(w) >= sizeof(cmdline)) {
        std::fputs("FI: command line too long for spawn buffer\n", stderr);
        return 1;
    }

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (CreateProcessA(
            nullptr,
            cmdline,
            nullptr,
            nullptr,
            FALSE,
            0,
            nullptr,
            nullptr,
            &si,
            &pi)
        == 0) {
        std::fprintf(stderr, "FI: CreateProcessA failed (%lu)\n",
            static_cast<unsigned long>(GetLastError()));
        return 1;
    }

    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = STILL_ACTIVE;
    (void)GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);

    // std::abort / FastFail 등: 정상 종료(0)가 아니어야 함.
    if (exit_code == 0u || exit_code == static_cast<DWORD>(STILL_ACTIVE)) {
        std::fprintf(stderr, "FI: child exit code %lu (expected abnormal after wipe+fault)\n",
            static_cast<unsigned long>(exit_code));
        return 1;
    }

    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc >= 2 && std::strcmp(argv[1], "--fi-flash") == 0) {
        return RunAttackFlashIntegrity();
    }
    if (argc >= 2 && std::strcmp(argv[1], "--fi-jtag") == 0) {
        RunAttackJtagSimulated();
    }

    std::puts("Verify_Fault_Injection: orchestrator (host)");

    if (RunAttackFlashIntegrity() != 0) {
        return 1;
    }
    if (SpawnChildWithArg("--fi-jtag") != 0) {
        return 1;
    }

    std::puts(
        "FI: Attack 1 (JTAG sim) — child: audit ring secureWipe + Terminal_Fault(abort) OK.");
    std::puts("Verify_Fault_Injection: ALL host FI checks PASSED");
    return 0;
}
