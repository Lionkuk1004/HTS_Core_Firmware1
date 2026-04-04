// Verify_PowerLoss_Tear — 호스트 전원 차단(Tear) 시뮬레이션: OTA Bank B 부분 기록 후 abort → 재기동 복구
// 타겟: HTS_OTA_Manager(Flash 콜백) · HTS_Key_Provisioning(OTP 에뮬) · Secure Boot(브릭 방지 신호)

#ifdef NDEBUG
#undef NDEBUG
#endif

#include "HTS_IPC_Protocol_Defs.h"
#include "HTS_Key_Provisioning.h"
#include "HTS_OTA_Manager.h"
#include "HTS_OTA_Manager_Defs.h"
#include "HTS_Secure_Boot_Verify.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

extern "C" void HTS_Test_Host_Reset_SecureBoot_OTP_Emulation(void) noexcept;
extern "C" void HTS_Test_Host_KeyProv_OTP_Clear(void) noexcept;
extern "C" void HTS_Test_Host_KeyProv_OTP_Import(const uint8_t* src, size_t len) noexcept;

namespace {

namespace PE = ProtectedEngine;

std::filesystem::path BankBinPath() {
    char exe[MAX_PATH];
    const DWORD n = GetModuleFileNameA(nullptr, exe, MAX_PATH);
    if (n == 0u || n >= MAX_PATH) {
        return std::filesystem::path("hts_power_tear_bank.bin");
    }
    return std::filesystem::path(exe).parent_path() / "hts_power_tear_bank.bin";
}

std::vector<uint8_t> g_bank;
std::filesystem::path g_bank_path;
bool g_tear_second_write = false;
int g_flash_write_count = 0;

static uint32_t Crc32Update(uint32_t crc, uint8_t byte) noexcept {
    crc ^= static_cast<uint32_t>(byte);
    for (uint8_t bit = 0u; bit < 8u; ++bit) {
        const uint32_t mask = static_cast<uint32_t>(-static_cast<int32_t>(crc & 1u));
        crc = (crc >> 1u) ^ (0xEDB88320u & mask);
    }
    return crc;
}

static uint32_t Crc32Image(const uint8_t* data, uint32_t len) noexcept {
    uint32_t crc = 0xFFFFFFFFu;
    for (uint32_t i = 0u; i < len; ++i) {
        crc = Crc32Update(crc, data[static_cast<size_t>(i)]);
    }
    return crc ^ 0xFFFFFFFFu;
}

bool FlushBank() {
    std::ofstream f(g_bank_path, std::ios::binary | std::ios::trunc);
    if (!f) {
        return false;
    }
    f.write(reinterpret_cast<const char*>(g_bank.data()),
        static_cast<std::streamsize>(g_bank.size()));
    return static_cast<bool>(f);
}

bool LoadBankFromFile() {
    std::ifstream f(g_bank_path, std::ios::binary);
    if (!f) {
        return false;
    }
    f.seekg(0, std::ios::end);
    const auto sz = f.tellg();
    f.seekg(0, std::ios::beg);
    if (sz != static_cast<std::streamoff>(PE::OTA_BANK_SIZE)) {
        return false;
    }
    g_bank.resize(static_cast<size_t>(PE::OTA_BANK_SIZE));
    f.read(reinterpret_cast<char*>(g_bank.data()),
        static_cast<std::streamsize>(g_bank.size()));
    return static_cast<bool>(f);
}

void InitBankFf() {
    g_bank.assign(static_cast<size_t>(PE::OTA_BANK_SIZE), 0xFFu);
    (void)FlushBank();
}

bool EraseSectorCb(uint32_t sector_addr) noexcept {
    const uint32_t rel = sector_addr - PE::OTA_BANK_B_BASE;
    if (rel >= PE::OTA_BANK_SIZE || (rel % PE::OTA_SECTOR_SIZE) != 0u) {
        return false;
    }
    for (uint32_t i = 0u; i < PE::OTA_SECTOR_SIZE; ++i) {
        g_bank[static_cast<size_t>(rel + i)] = 0xFFu;
    }
    return FlushBank();
}

bool WriteFlashCb(uint32_t addr, const uint8_t* data, uint32_t len) noexcept {
    ++g_flash_write_count;
    const uint32_t off = addr - PE::OTA_BANK_B_BASE;
    if (data == nullptr || off > PE::OTA_BANK_SIZE
        || static_cast<uint64_t>(off) + static_cast<uint64_t>(len)
            > static_cast<uint64_t>(PE::OTA_BANK_SIZE)) {
        return false;
    }
    if (g_tear_second_write && g_flash_write_count == 2) {
        const uint32_t half = len / 2u;
        for (uint32_t i = 0u; i < half; ++i) {
            g_bank[static_cast<size_t>(off + i)] = data[i];
        }
        (void)FlushBank();
        std::abort();
    }
    for (uint32_t i = 0u; i < len; ++i) {
        g_bank[static_cast<size_t>(off + i)] = data[i];
    }
    return FlushBank();
}

bool ReadFlashCb(uint32_t addr, uint8_t* buf, uint32_t len) noexcept {
    const uint32_t off = addr - PE::OTA_BANK_B_BASE;
    if (buf == nullptr || off > PE::OTA_BANK_SIZE
        || static_cast<uint64_t>(off) + static_cast<uint64_t>(len)
            > static_cast<uint64_t>(PE::OTA_BANK_SIZE)) {
        return false;
    }
    for (uint32_t i = 0u; i < len; ++i) {
        buf[i] = g_bank[static_cast<size_t>(off + i)];
    }
    return true;
}

uint32_t CurrentFwVerCb(void) noexcept {
    return 1u;
}

void BuildBeginPayload(uint8_t* out, uint32_t total_size, uint32_t fw_ver,
    uint32_t crc32, uint16_t total_chunks, uint16_t chunk_size) noexcept {
    out[0] = static_cast<uint8_t>(total_size >> 24);
    out[1] = static_cast<uint8_t>((total_size >> 16) & 0xFFu);
    out[2] = static_cast<uint8_t>((total_size >> 8) & 0xFFu);
    out[3] = static_cast<uint8_t>(total_size & 0xFFu);
    out[4] = static_cast<uint8_t>(fw_ver >> 24);
    out[5] = static_cast<uint8_t>((fw_ver >> 16) & 0xFFu);
    out[6] = static_cast<uint8_t>((fw_ver >> 8) & 0xFFu);
    out[7] = static_cast<uint8_t>(fw_ver & 0xFFu);
    out[8] = static_cast<uint8_t>(crc32 >> 24);
    out[9] = static_cast<uint8_t>((crc32 >> 16) & 0xFFu);
    out[10] = static_cast<uint8_t>((crc32 >> 8) & 0xFFu);
    out[11] = static_cast<uint8_t>(crc32 & 0xFFu);
    out[12] = static_cast<uint8_t>(total_chunks >> 8);
    out[13] = static_cast<uint8_t>(total_chunks & 0xFFu);
    out[14] = static_cast<uint8_t>(chunk_size >> 8);
    out[15] = static_cast<uint8_t>(chunk_size & 0xFFu);
}

void BuildChunkFrame(uint8_t* frame, uint16_t seq, uint16_t total_chunks,
    uint8_t chunk_len, const uint8_t* data) noexcept {
    frame[0] = static_cast<uint8_t>(PE::OTA_Command::CHUNK_DATA);
    frame[1] = static_cast<uint8_t>(seq >> 8);
    frame[2] = static_cast<uint8_t>(seq & 0xFFu);
    frame[3] = static_cast<uint8_t>(total_chunks >> 8);
    frame[4] = static_cast<uint8_t>(total_chunks & 0xFFu);
    frame[5] = chunk_len;
    if (chunk_len > 0u && data != nullptr) {
        std::memcpy(&frame[6], data, chunk_len);
    }
}

int RunOtaTear() {
    using namespace ProtectedEngine;
    g_bank_path = BankBinPath();
    InitBankFf();
    g_tear_second_write = true;
    g_flash_write_count = 0;

    constexpr uint32_t kImg = 500u;
    constexpr uint16_t kChunks = 3u;
    constexpr uint16_t kChunkSz = 200u;
    std::vector<uint8_t> image(static_cast<size_t>(kImg));
    for (uint32_t i = 0u; i < kImg; ++i) {
        image[static_cast<size_t>(i)] = static_cast<uint8_t>(i & 0xFFu);
    }
    const uint32_t expect_crc = Crc32Image(image.data(), kImg);

    HTS_OTA_Manager ota;
    assert(ota.Initialize(nullptr) == IPC_Error::OK);
    OTA_Flash_Callbacks cb{};
    cb.erase_sector = &EraseSectorCb;
    cb.write_flash = &WriteFlashCb;
    cb.read_flash = &ReadFlashCb;
    cb.execute_bank_swap = nullptr;
    cb.get_current_fw_version = &CurrentFwVerCb;
    ota.Register_Flash_Callbacks(cb);

    uint8_t begin_frame[1 + sizeof(OTA_ImageHeader)] = {};
    begin_frame[0] = static_cast<uint8_t>(OTA_Command::BEGIN);
    BuildBeginPayload(&begin_frame[1], kImg, 2u, expect_crc, kChunks, kChunkSz);
    ota.Process_OTA_Command(begin_frame, static_cast<uint16_t>(sizeof(begin_frame)));
    assert(ota.Get_Last_Result() == OTA_Result::IN_PROGRESS);

    uint8_t c0[6u + 200u] = {};
    BuildChunkFrame(c0, 0u, kChunks, 200u, image.data());
    ota.Process_OTA_Command(c0, static_cast<uint16_t>(sizeof(c0)));

    uint8_t c1[6u + 200u] = {};
    BuildChunkFrame(c1, 1u, kChunks, 200u, image.data() + 200u);
    ota.Process_OTA_Command(c1, static_cast<uint16_t>(sizeof(c1)));

    std::fputs("PL: expected abort before completing chunk 1 — not reached\n", stderr);
    return 9;
}

int RunOtaRecover() {
    using namespace ProtectedEngine;
    g_bank_path = BankBinPath();
    if (!LoadBankFromFile()) {
        std::fputs("PL: bank bin missing or wrong size\n", stderr);
        return 8;
    }

    g_tear_second_write = false;
    g_flash_write_count = 0;

    constexpr uint32_t kImg = 500u;
    constexpr uint16_t kChunks = 3u;
    constexpr uint16_t kChunkSz = 200u;
    std::vector<uint8_t> image(static_cast<size_t>(kImg));
    for (uint32_t i = 0u; i < kImg; ++i) {
        image[static_cast<size_t>(i)] = static_cast<uint8_t>(i & 0xFFu);
    }
    const uint32_t expect_crc = Crc32Image(image.data(), kImg);

    HTS_OTA_Manager ota;
    assert(ota.Initialize(nullptr) == IPC_Error::OK);
    OTA_Flash_Callbacks cb{};
    cb.erase_sector = &EraseSectorCb;
    cb.write_flash = &WriteFlashCb;
    cb.read_flash = &ReadFlashCb;
    cb.execute_bank_swap = nullptr;
    cb.get_current_fw_version = &CurrentFwVerCb;
    ota.Register_Flash_Callbacks(cb);

    uint8_t begin_frame[1 + sizeof(OTA_ImageHeader)] = {};
    begin_frame[0] = static_cast<uint8_t>(OTA_Command::BEGIN);
    BuildBeginPayload(&begin_frame[1], kImg, 2u, expect_crc, kChunks, kChunkSz);
    ota.Process_OTA_Command(begin_frame, static_cast<uint16_t>(sizeof(begin_frame)));
    assert(ota.Get_Last_Result() == OTA_Result::IN_PROGRESS);

    bool all_ff = true;
    for (uint8_t b : g_bank) {
        if (b != 0xFFu) {
            all_ff = false;
            break;
        }
    }
    if (!all_ff) {
        std::fputs("PL: BEGIN did not erase torn bank (unexpected)\n", stderr);
        return 7;
    }

    uint8_t c0[6u + 200u] = {};
    BuildChunkFrame(c0, 0u, kChunks, 200u, image.data());
    ota.Process_OTA_Command(c0, static_cast<uint16_t>(sizeof(c0)));

    uint8_t c1[6u + 200u] = {};
    BuildChunkFrame(c1, 1u, kChunks, 200u, image.data() + 200u);
    ota.Process_OTA_Command(c1, static_cast<uint16_t>(sizeof(c1)));

    uint8_t c2[6u + 100u] = {};
    BuildChunkFrame(c2, 2u, kChunks, 100u, image.data() + 400u);
    ota.Process_OTA_Command(c2, static_cast<uint16_t>(sizeof(c2)));

    uint8_t vrf[1] = { static_cast<uint8_t>(OTA_Command::VERIFY) };
    ota.Process_OTA_Command(vrf, 1u);

    if (ota.Get_Last_Result() != OTA_Result::OK) {
        std::fprintf(stderr, "PL: VERIFY last_result=%u\n",
            static_cast<unsigned>(static_cast<uint8_t>(ota.Get_Last_Result())));
        return 6;
    }
    if (static_cast<uint8_t>(ota.Get_State()) != static_cast<uint8_t>(OTA_State::VERIFIED)) {
        std::fprintf(stderr, "PL: state not VERIFIED (%u)\n",
            static_cast<unsigned>(static_cast<uint8_t>(ota.Get_State())));
        return 6;
    }

    std::puts("PL: OTA recover — Bank B re-erase + full chunks + VERIFY OK");
    return 0;
}

int RunColdVerifyNoSession() {
    using namespace ProtectedEngine;
    HTS_OTA_Manager ota;
    assert(ota.Initialize(nullptr) == IPC_Error::OK);
    uint8_t vrf[1] = { static_cast<uint8_t>(OTA_Command::VERIFY) };
    ota.Process_OTA_Command(vrf, 1u);
    if (ota.Get_Last_Result() != OTA_Result::NOT_READY) {
        std::fprintf(stderr, "PL: cold VERIFY expected NOT_READY got %u\n",
            static_cast<unsigned>(static_cast<uint8_t>(ota.Get_Last_Result())));
        return 5;
    }
    std::puts("PL: cold VERIFY — NOT_READY (no infinite lock)");
    return 0;
}

int RunKeyPartialState() {
    using namespace ProtectedEngine;
    HTS_Test_Host_KeyProv_OTP_Clear();
    alignas(8) uint8_t snap[528] = {};
    for (size_t i = 0u; i < 32u; ++i) {
        snap[i] = static_cast<uint8_t>(0xA0u + i);
    }
    HTS_Test_Host_KeyProv_OTP_Import(snap, sizeof(snap));

    HTS_Key_Provisioning kp;
    assert(kp.Is_Provisioned() == HTS_Key_Provisioning::SECURE_FALSE);
    alignas(8) uint8_t out[32] = {};
    assert(kp.Read_Master_Key(out, sizeof(out)) == HTS_Key_Provisioning::SECURE_FALSE);

    HTS_Test_Host_KeyProv_OTP_Clear();
    std::puts("PL: key — partial OTP without magic; Read_Master_Key blocked");
    return 0;
}

int RunSecureBootStillOk() {
    using namespace ProtectedEngine;
    HTS_Test_Host_Reset_SecureBoot_OTP_Emulation();
    HTS_Secure_Boot_Verify boot;
    alignas(8) uint8_t pc_expected_hash[32] = {};
    for (size_t i = 0u; i < 32u; ++i) {
        pc_expected_hash[i] = 0xAAu;
    }
    if (!boot.Provision_Expected_Hash(pc_expected_hash, 32u)) {
        std::fputs("PL: Secure Boot provision skip (already set)\n", stderr);
    }
    const int32_t br = HTS_Secure_Boot_Check();
    if (br != 0) {
        std::fprintf(stderr, "PL: Secure Boot check %d (expected 0 on host)\n",
            static_cast<int>(br));
        return 3;
    }
    std::puts("PL: Secure Boot still OK after tear suite (host single-hash emu)");
    return 0;
}

int SpawnPhase(const char* arg) {
    char exe_path[MAX_PATH];
    const DWORD n = GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
    if (n == 0u || n >= MAX_PATH) {
        return 1;
    }
    char cmdline[1024];
    const int w = std::snprintf(cmdline, sizeof(cmdline), "\"%s\" %s", exe_path, arg);
    if (w < 0 || static_cast<size_t>(w) >= sizeof(cmdline)) {
        return 1;
    }
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (CreateProcessA(nullptr, cmdline, nullptr, nullptr, FALSE, 0, nullptr,
            nullptr, &si, &pi)
        == 0) {
        return 1;
    }
    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD ec = 1u;
    (void)GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hProcess);
    if (ec == 0u || ec == static_cast<DWORD>(STILL_ACTIVE)) {
        std::fprintf(stderr, "PL: child %s exit %lu (expected abnormal for tear)\n", arg,
            static_cast<unsigned long>(ec));
        return 1;
    }
    return 0;
}

int RunOrchestrator() {
    g_bank_path = BankBinPath();
    std::error_code ec;
    std::filesystem::remove(g_bank_path, ec);

    if (SpawnPhase("--ota-tear") != 0) {
        return 1;
    }
    if (RunOtaRecover() != 0) {
        return 1;
    }
    if (RunColdVerifyNoSession() != 0) {
        return 1;
    }
    if (RunKeyPartialState() != 0) {
        return 1;
    }
    if (RunSecureBootStillOk() != 0) {
        return 1;
    }
    std::puts("Verify_PowerLoss_Tear: ALL checks PASSED");
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc >= 2 && std::strcmp(argv[1], "--ota-tear") == 0) {
        return RunOtaTear();
    }
    if (argc >= 2 && std::strcmp(argv[1], "--ota-recover") == 0) {
        return RunOtaRecover();
    }
    return RunOrchestrator();
}
