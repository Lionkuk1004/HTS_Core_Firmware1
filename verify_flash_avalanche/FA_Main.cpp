// Verify_Flash_Avalanche — 배드블록·Flash HW_ERROR 확률 에뮬 + OTA FSM 생존/중단 검증
// 타겟: HTS_OTA_Manager (OTA_Flash_Callbacks), Storage/KeyProv는 문서상 HAL 하위 책임

#include "HTS_OTA_Manager.h"
#include "HTS_OTA_Manager_Defs.h"

#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace {

namespace PE = ProtectedEngine;

std::vector<uint8_t> g_bank;

uint32_t g_rng = 0xA1A51A5u;
uint32_t g_fail_permille_erase = 0u;
uint32_t g_fail_permille_write = 0u;
uint32_t g_fail_permille_read = 0u;
/// HAL 에뮬: 단일 OTA 호출당 erase/write/read 내부 시도 상한 (1=재시도 없음, 3=최대 3회)
uint32_t g_hal_max_attempts = 1u;
/// erase_sector 콜백 1회당: 선행 루프 횟수만큼 "일시 HW_ERROR" (웨어 HAL 재시도 상한 검증용)
uint32_t g_erase_synthetic_fails_per_sector = 0u;

uint64_t g_stat_erase = 0u;
uint64_t g_stat_write = 0u;
uint64_t g_stat_read = 0u;

[[nodiscard]] uint32_t xorshift32(uint32_t& s) noexcept
{
    s ^= s << 13u;
    s ^= s >> 17u;
    s ^= s << 5u;
    return s;
}

[[nodiscard]] bool inject_hw_error(uint32_t permille) noexcept
{
    if (permille == 0u) {
        return false;
    }
    if (permille >= 1000u) {
        return true;
    }
    return (xorshift32(g_rng) % 1000u) < permille;
}

[[nodiscard]] bool erase_sector_phys(uint32_t sector_addr) noexcept
{
    const uint32_t rel = sector_addr - PE::OTA_BANK_B_BASE;
    if (rel >= PE::OTA_BANK_SIZE || (rel % PE::OTA_SECTOR_SIZE) != 0u) {
        return false;
    }
    for (uint32_t i = 0u; i < PE::OTA_SECTOR_SIZE; ++i) {
        g_bank[static_cast<size_t>(rel + i)] = 0xFFu;
    }
    return true;
}

[[nodiscard]] bool write_flash_phys(uint32_t addr, const uint8_t* data,
    uint32_t len) noexcept
{
    const uint32_t off = addr - PE::OTA_BANK_B_BASE;
    if (data == nullptr || off > PE::OTA_BANK_SIZE
        || static_cast<uint64_t>(off) + static_cast<uint64_t>(len)
            > static_cast<uint64_t>(PE::OTA_BANK_SIZE)) {
        return false;
    }
    for (uint32_t i = 0u; i < len; ++i) {
        g_bank[static_cast<size_t>(off + i)] = data[i];
    }
    return true;
}

[[nodiscard]] bool read_flash_phys(uint32_t addr, uint8_t* buf,
    uint32_t len) noexcept
{
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

extern "C" bool EraseSectorCb(uint32_t sector_addr) noexcept
{
    ++g_stat_erase;
    const uint32_t max_a = (g_hal_max_attempts == 0u) ? 1u : g_hal_max_attempts;
    for (uint32_t a = 0u; a < max_a; ++a) {
        if (a < g_erase_synthetic_fails_per_sector) {
            continue;
        }
        if (inject_hw_error(g_fail_permille_erase)) {
            continue;
        }
        return erase_sector_phys(sector_addr);
    }
    return false;
}

extern "C" bool WriteFlashCb(uint32_t addr, const uint8_t* data,
    uint32_t len) noexcept
{
    ++g_stat_write;
    const uint32_t max_a = (g_hal_max_attempts == 0u) ? 1u : g_hal_max_attempts;
    for (uint32_t a = 0u; a < max_a; ++a) {
        if (inject_hw_error(g_fail_permille_write)) {
            continue;
        }
        return write_flash_phys(addr, data, len);
    }
    return false;
}

extern "C" bool ReadFlashCb(uint32_t addr, uint8_t* buf, uint32_t len) noexcept
{
    ++g_stat_read;
    const uint32_t max_a = (g_hal_max_attempts == 0u) ? 1u : g_hal_max_attempts;
    for (uint32_t a = 0u; a < max_a; ++a) {
        if (inject_hw_error(g_fail_permille_read)) {
            continue;
        }
        return read_flash_phys(addr, buf, len);
    }
    return false;
}

extern "C" uint32_t CurrentFwVerCb(void) noexcept
{
    return 1u;
}

[[nodiscard]] uint32_t crc32_image(const uint8_t* data, uint32_t len) noexcept
{
    uint32_t crc = 0xFFFFFFFFu;
    for (uint32_t i = 0u; i < len; ++i) {
        crc ^= static_cast<uint32_t>(data[static_cast<size_t>(i)]);
        for (uint8_t b = 0u; b < 8u; ++b) {
            const uint32_t mask = static_cast<uint32_t>(
                -static_cast<int32_t>(crc & 1u));
            crc = (crc >> 1u) ^ (0xEDB88320u & mask);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

void build_begin_payload(uint8_t* out, uint32_t total_size, uint32_t fw_ver,
    uint32_t crc32v, uint16_t total_chunks, uint16_t chunk_size) noexcept
{
    out[0] = static_cast<uint8_t>(total_size >> 24);
    out[1] = static_cast<uint8_t>((total_size >> 16) & 0xFFu);
    out[2] = static_cast<uint8_t>((total_size >> 8) & 0xFFu);
    out[3] = static_cast<uint8_t>(total_size & 0xFFu);
    out[4] = static_cast<uint8_t>(fw_ver >> 24);
    out[5] = static_cast<uint8_t>((fw_ver >> 16) & 0xFFu);
    out[6] = static_cast<uint8_t>((fw_ver >> 8) & 0xFFu);
    out[7] = static_cast<uint8_t>(fw_ver & 0xFFu);
    out[8] = static_cast<uint8_t>(crc32v >> 24);
    out[9] = static_cast<uint8_t>((crc32v >> 16) & 0xFFu);
    out[10] = static_cast<uint8_t>((crc32v >> 8) & 0xFFu);
    out[11] = static_cast<uint8_t>(crc32v & 0xFFu);
    out[12] = static_cast<uint8_t>(total_chunks >> 8);
    out[13] = static_cast<uint8_t>(total_chunks & 0xFFu);
    out[14] = static_cast<uint8_t>(chunk_size >> 8);
    out[15] = static_cast<uint8_t>(chunk_size & 0xFFu);
}

void build_chunk_frame(uint8_t* frame, uint16_t seq, uint16_t total_chunks,
    uint8_t chunk_len, const uint8_t* data) noexcept
{
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

void reset_stats() noexcept
{
    g_stat_erase = 0u;
    g_stat_write = 0u;
    g_stat_read = 0u;
}

[[nodiscard]] bool run_one_ota_session_expect_fail_on_begin() noexcept
{
    g_bank.assign(static_cast<size_t>(PE::OTA_BANK_SIZE), 0xFFu);
    reset_stats();
    g_erase_synthetic_fails_per_sector = 0u;
    g_fail_permille_erase = 1000u;
    g_fail_permille_write = 0u;
    g_fail_permille_read = 0u;
    g_hal_max_attempts = 3u;

    PE::HTS_OTA_Manager ota;
    if (ota.Initialize(nullptr) != PE::IPC_Error::OK) {
        return false;
    }
    PE::OTA_Flash_Callbacks cb{};
    cb.erase_sector = &EraseSectorCb;
    cb.write_flash = &WriteFlashCb;
    cb.read_flash = &ReadFlashCb;
    cb.execute_bank_swap = nullptr;
    cb.get_current_fw_version = &CurrentFwVerCb;
    ota.Register_Flash_Callbacks(cb);

    constexpr uint32_t kImg = 600u;
    constexpr uint16_t kChunks = 3u;
    constexpr uint16_t kChunkSz = 200u;
    std::vector<uint8_t> image(static_cast<size_t>(kImg));
    for (uint32_t i = 0u; i < kImg; ++i) {
        image[static_cast<size_t>(i)] = static_cast<uint8_t>(i & 0xFFu);
    }
    const uint32_t expect_crc = crc32_image(image.data(), kImg);

    uint8_t begin_frame[1 + sizeof(PE::OTA_ImageHeader)] = {};
    begin_frame[0] = static_cast<uint8_t>(PE::OTA_Command::BEGIN);
    build_begin_payload(&begin_frame[1], kImg, 2u, expect_crc, kChunks, kChunkSz);

    const auto t0 = std::chrono::steady_clock::now();
    ota.Process_OTA_Command(begin_frame,
        static_cast<uint16_t>(sizeof(begin_frame)));
    const auto ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();

    const bool ok = (ota.Get_State() == PE::OTA_State::ERROR)
        && (ota.Get_Last_Result() == PE::OTA_Result::FLASH_FAIL)
        && (ms < 5000.0);
    std::printf(
        "FA: 100%% erase fail — state=ERROR FLASH_FAIL, %.2f ms, erase_calls=%" PRIu64 " %s\n",
        ms, g_stat_erase, ok ? "PASS" : "FAIL");
    ota.Shutdown();
    return ok;
}

[[nodiscard]] bool run_one_ota_session_success_zero_fail() noexcept
{
    g_bank.assign(static_cast<size_t>(PE::OTA_BANK_SIZE), 0xFFu);
    reset_stats();
    g_erase_synthetic_fails_per_sector = 0u;
    g_fail_permille_erase = 0u;
    g_fail_permille_write = 0u;
    g_fail_permille_read = 0u;
    g_hal_max_attempts = 1u;

    PE::HTS_OTA_Manager ota;
    if (ota.Initialize(nullptr) != PE::IPC_Error::OK) {
        return false;
    }
    PE::OTA_Flash_Callbacks cb{};
    cb.erase_sector = &EraseSectorCb;
    cb.write_flash = &WriteFlashCb;
    cb.read_flash = &ReadFlashCb;
    cb.execute_bank_swap = nullptr;
    cb.get_current_fw_version = &CurrentFwVerCb;
    ota.Register_Flash_Callbacks(cb);

    constexpr uint32_t kImg = 600u;
    constexpr uint16_t kChunks = 3u;
    constexpr uint16_t kChunkSz = 200u;
    std::vector<uint8_t> image(static_cast<size_t>(kImg));
    for (uint32_t i = 0u; i < kImg; ++i) {
        image[static_cast<size_t>(i)] = static_cast<uint8_t>(i & 0xFFu);
    }
    const uint32_t expect_crc = crc32_image(image.data(), kImg);

    uint8_t begin_frame[1 + sizeof(PE::OTA_ImageHeader)] = {};
    begin_frame[0] = static_cast<uint8_t>(PE::OTA_Command::BEGIN);
    build_begin_payload(&begin_frame[1], kImg, 2u, expect_crc, kChunks, kChunkSz);
    ota.Process_OTA_Command(begin_frame,
        static_cast<uint16_t>(sizeof(begin_frame)));
    if (ota.Get_Last_Result() != PE::OTA_Result::IN_PROGRESS) {
        std::puts("FA: golden BEGIN unexpected FAIL");
        ota.Shutdown();
        return false;
    }

    for (uint16_t c = 0u; c < kChunks; ++c) {
        uint8_t frame[6u + 200u] = {};
        const uint8_t* src = image.data() + static_cast<size_t>(c) * kChunkSz;
        build_chunk_frame(frame, c, kChunks, 200u, src);
        ota.Process_OTA_Command(frame, static_cast<uint16_t>(sizeof(frame)));
        if (ota.Get_State() == PE::OTA_State::ERROR) {
            std::printf("FA: golden chunk %" PRIu16 " FLASH fail\n", c);
            ota.Shutdown();
            return false;
        }
    }

    uint8_t verify_cmd[1] = { static_cast<uint8_t>(PE::OTA_Command::VERIFY) };
    ota.Process_OTA_Command(verify_cmd, 1u);

    const bool ok = (ota.Get_State() == PE::OTA_State::VERIFIED)
        && (ota.Get_Last_Result() == PE::OTA_Result::OK);
    std::printf(
        "FA: 0%% fail golden path — VERIFIED=%d erase=%" PRIu64 " write=%" PRIu64 " read=%" PRIu64 " %s\n",
        static_cast<int>(ota.Get_State() == PE::OTA_State::VERIFIED),
        g_stat_erase, g_stat_write, g_stat_read, ok ? "PASS" : "FAIL");
    ota.Shutdown();
    return ok;
}

[[nodiscard]] bool run_chaos_sessions(uint32_t permille, int sessions,
    double time_limit_sec) noexcept
{
    g_erase_synthetic_fails_per_sector = 0u;
    g_fail_permille_erase = permille;
    g_fail_permille_write = permille;
    g_fail_permille_read = permille;
    g_hal_max_attempts = 1u;

    const auto t0 = std::chrono::steady_clock::now();
    int completed = 0;
    for (int s = 0; s < sessions; ++s) {
        g_rng = static_cast<uint32_t>(0xF1A5u + static_cast<uint32_t>(s) * 997u);
        g_bank.assign(static_cast<size_t>(PE::OTA_BANK_SIZE), 0xFFu);
        reset_stats();

        PE::HTS_OTA_Manager ota;
        if (ota.Initialize(nullptr) != PE::IPC_Error::OK) {
            return false;
        }
        PE::OTA_Flash_Callbacks cb{};
        cb.erase_sector = &EraseSectorCb;
        cb.write_flash = &WriteFlashCb;
        cb.read_flash = &ReadFlashCb;
        cb.execute_bank_swap = nullptr;
        cb.get_current_fw_version = &CurrentFwVerCb;
        ota.Register_Flash_Callbacks(cb);

        constexpr uint32_t kImg = 600u;
        constexpr uint16_t kChunks = 3u;
        constexpr uint16_t kChunkSz = 200u;
        std::vector<uint8_t> image(static_cast<size_t>(kImg));
        for (uint32_t i = 0u; i < kImg; ++i) {
            image[static_cast<size_t>(i)] = static_cast<uint8_t>((i + s) & 0xFFu);
        }
        const uint32_t expect_crc = crc32_image(image.data(), kImg);

        uint8_t begin_frame[1 + sizeof(PE::OTA_ImageHeader)] = {};
        begin_frame[0] = static_cast<uint8_t>(PE::OTA_Command::BEGIN);
        build_begin_payload(&begin_frame[1], kImg, 2u, expect_crc, kChunks, kChunkSz);
        ota.Process_OTA_Command(begin_frame,
            static_cast<uint16_t>(sizeof(begin_frame)));

        constexpr uint32_t kMaxSteps = 500u;
        uint32_t steps = 0u;
        if (ota.Get_State() != PE::OTA_State::ERROR) {
            for (uint16_t c = 0u; c < kChunks; ++c) {
                if (ota.Get_State() == PE::OTA_State::ERROR) {
                    break;
                }
                uint8_t frame[6u + 200u] = {};
                build_chunk_frame(frame, c, kChunks, 200u,
                    image.data() + static_cast<size_t>(c) * kChunkSz);
                ota.Process_OTA_Command(frame, static_cast<uint16_t>(sizeof(frame)));
                ++steps;
            }
            if (ota.Get_State() != PE::OTA_State::ERROR) {
                uint8_t verify_cmd[1] = {
                    static_cast<uint8_t>(PE::OTA_Command::VERIFY)
                };
                ota.Process_OTA_Command(verify_cmd, 1u);
                ++steps;
            }
        }

        if (steps > kMaxSteps) {
            std::puts("FA: CHAOS step cap exceeded (infinite loop suspect)");
            ota.Shutdown();
            return false;
        }

        const auto elapsed = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - t0).count();
        if (elapsed > time_limit_sec) {
            std::puts("FA: CHAOS time limit exceeded");
            ota.Shutdown();
            return false;
        }

        ota.Shutdown();
        ++completed;
    }

    const double total_sec = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t0).count();
    std::printf(
        "FA: chaos permille=%" PRIu32 " sessions=%d completed=%d in %.3f s — PASS\n",
        permille, sessions, completed, total_sec);
    return true;
}

[[nodiscard]] bool hal_deterministic_three_attempts_erase() noexcept
{
    g_bank.assign(static_cast<size_t>(PE::OTA_BANK_SIZE), 0xFFu);
    reset_stats();
    g_fail_permille_erase = 0u;
    g_fail_permille_write = 0u;
    g_fail_permille_read = 0u;
    g_hal_max_attempts = 3u;
    g_erase_synthetic_fails_per_sector = 2u;

    PE::HTS_OTA_Manager ota;
    if (ota.Initialize(nullptr) != PE::IPC_Error::OK) {
        g_erase_synthetic_fails_per_sector = 0u;
        return false;
    }
    PE::OTA_Flash_Callbacks cb{};
    cb.erase_sector = &EraseSectorCb;
    cb.write_flash = &WriteFlashCb;
    cb.read_flash = &ReadFlashCb;
    cb.execute_bank_swap = nullptr;
    cb.get_current_fw_version = &CurrentFwVerCb;
    ota.Register_Flash_Callbacks(cb);

    constexpr uint32_t kImg = 600u;
    constexpr uint16_t kChunks = 3u;
    constexpr uint16_t kChunkSz = 200u;
    std::vector<uint8_t> image(static_cast<size_t>(kImg));
    for (uint32_t i = 0u; i < kImg; ++i) {
        image[static_cast<size_t>(i)] = static_cast<uint8_t>(i & 0xFFu);
    }
    const uint32_t expect_crc = crc32_image(image.data(), kImg);

    uint8_t begin_frame[1 + sizeof(PE::OTA_ImageHeader)] = {};
    begin_frame[0] = static_cast<uint8_t>(PE::OTA_Command::BEGIN);
    build_begin_payload(&begin_frame[1], kImg, 2u, expect_crc, kChunks, kChunkSz);
    ota.Process_OTA_Command(begin_frame,
        static_cast<uint16_t>(sizeof(begin_frame)));

    const bool begin_ok = (ota.Get_State() == PE::OTA_State::RECEIVING);
    for (uint16_t c = 0u; c < kChunks && begin_ok; ++c) {
        uint8_t frame[6u + 200u] = {};
        build_chunk_frame(frame, c, kChunks, 200u,
            image.data() + static_cast<size_t>(c) * kChunkSz);
        ota.Process_OTA_Command(frame, static_cast<uint16_t>(sizeof(frame)));
    }
    uint8_t verify_cmd[1] = { static_cast<uint8_t>(PE::OTA_Command::VERIFY) };
    ota.Process_OTA_Command(verify_cmd, 1u);

    g_erase_synthetic_fails_per_sector = 0u;

    const bool ok = begin_ok
        && (ota.Get_State() == PE::OTA_State::VERIFIED)
        && (ota.Get_Last_Result() == PE::OTA_Result::OK);
    std::printf(
        "FA: HAL max 3 (2 synthetic HW_ERROR/sector + success) — VERIFIED=%d erase_cb=%" PRIu64 " %s\n",
        static_cast<int>(ok), g_stat_erase, ok ? "PASS" : "FAIL");
    ota.Shutdown();
    return ok;
}

} // namespace

int main()
{
    if (!run_one_ota_session_expect_fail_on_begin()) {
        return 1;
    }
    if (!run_one_ota_session_success_zero_fail()) {
        return 2;
    }
    if (!run_chaos_sessions(300u, 60, 30.0)) {
        return 3;
    }
    if (!run_chaos_sessions(800u, 40, 30.0)) {
        return 4;
    }
    if (!hal_deterministic_three_attempts_erase()) {
        return 5;
    }

    std::puts("Verify_Flash_Avalanche: ALL checks PASSED (no OTA infinite retry)");
    return 0;
}
