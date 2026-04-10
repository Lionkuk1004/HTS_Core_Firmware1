/// @file  HTS_OTA_Manager.cpp
/// @brief HTS OTA Manager -- Remote Firmware Update Implementation
/// @note  ARM only. Pure ASCII. No PC/server code.
///
/// @author Lim Young-jun
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_OTA_Manager.h"
#include "HTS_IPC_Protocol.h"
#include <new>
#include <atomic>
#include <cstring>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
// 보드에서 강한 심볼로 재정의 — 기본 true(기존 동작 100% 유지)
extern "C" __attribute__((weak)) bool HTS_OTA_Board_Power_Stable(void) {
    return true;
}
#endif

namespace ProtectedEngine {

    // ============================================================
    //  공개 API / Shutdown 상호 배제 (Modbus/AMI 패턴 — 스핀락)
    // ============================================================
    struct OTA_Busy_Guard {
        std::atomic_flag& f;
        explicit OTA_Busy_Guard(std::atomic_flag& flag) noexcept
            : f(flag)
        {
            while (f.test_and_set(std::memory_order_acquire)) {
                // spin — Shutdown과 교차 시 완료까지 대기
            }
        }
        ~OTA_Busy_Guard() noexcept
        {
            f.clear(std::memory_order_release);
        }
        OTA_Busy_Guard(const OTA_Busy_Guard&) = delete;
        OTA_Busy_Guard& operator=(const OTA_Busy_Guard&) = delete;
    };

    // ============================================================
    //  [OTA-2] 보안 메모리 소거 (프로젝트 표준)
    // ============================================================
    static void OTA_Secure_Wipe(void* ptr, size_t size) noexcept {
        if (ptr == nullptr || size == 0u) { return; }
        volatile unsigned char* p =
            static_cast<volatile unsigned char*>(ptr);
        for (size_t i = 0u; i < size; ++i) { p[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(ptr) : "memory");
#elif defined(_MSC_VER)
        _ReadWriteBarrier();
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // ============================================================
    //  Endian Helpers
    // ============================================================

    static inline void OTA_Write_U16(uint8_t* b, uint16_t v) noexcept
    {
        b[static_cast<size_t>(0u)] = static_cast<uint8_t>(v >> 8u);
        b[static_cast<size_t>(1u)] = static_cast<uint8_t>(v & 0xFFu);
    }
    static inline void OTA_Write_U32(uint8_t* b, uint32_t v) noexcept
    {
        b[static_cast<size_t>(0u)] = static_cast<uint8_t>(v >> 24u);
        b[static_cast<size_t>(1u)] = static_cast<uint8_t>((v >> 16u) & 0xFFu);
        b[static_cast<size_t>(2u)] = static_cast<uint8_t>((v >> 8u) & 0xFFu);
        b[static_cast<size_t>(3u)] = static_cast<uint8_t>(v & 0xFFu);
    }
    static inline uint16_t OTA_Read_U16(const uint8_t* b) noexcept
    {
        return static_cast<uint16_t>(
            (static_cast<uint16_t>(b[static_cast<size_t>(0u)]) << 8u)
            | static_cast<uint16_t>(b[static_cast<size_t>(1u)]));
    }
    static inline uint32_t OTA_Read_U32(const uint8_t* b) noexcept
    {
        return (static_cast<uint32_t>(b[static_cast<size_t>(0u)]) << 24u) |
            (static_cast<uint32_t>(b[static_cast<size_t>(1u)]) << 16u) |
            (static_cast<uint32_t>(b[static_cast<size_t>(2u)]) << 8u) |
            static_cast<uint32_t>(b[static_cast<size_t>(3u)]);
    }

    // ============================================================
    //  CRC-32 (IEEE 802.3, same polynomial as STM32 HW CRC)
    // ============================================================

    /// @brief CRC-32 single-byte update (bit-by-bit, no LUT to save Flash)
    static inline uint32_t CRC32_Update(uint32_t crc, uint8_t byte) noexcept
    {
        crc ^= static_cast<uint32_t>(byte);
        for (uint8_t bit = 0u; bit < 8u; ++bit) {
            const uint32_t mask = static_cast<uint32_t>(
                -static_cast<int32_t>(crc & 1u));
            crc = (crc >> 1u) ^ (0xEDB88320u & mask);
        }
        return crc;
    }

    // ============================================================
    //  [OTA-5] CRC-32 블록 업데이트 (256B 단위)
    // ============================================================
    static inline uint32_t CRC32_Update_Block(
        uint32_t crc, const uint8_t* data, uint32_t len) noexcept
    {
        for (uint32_t i = 0u; i < len; ++i) {
            crc = CRC32_Update(crc, data[static_cast<size_t>(i)]);
        }
        return crc;
    }

    // ============================================================
    //  Impl Structure
    // ============================================================

    struct HTS_OTA_Manager::Impl {
        // --- Dependencies ---
        HTS_IPC_Protocol* ipc;

        // --- Flash HAL ---
        OTA_Flash_Callbacks flash_cb;

        // --- CFI State ---
        OTA_State  state;
        OTA_Result last_result;
        uint8_t    cfi_violation_count;
        uint8_t    pad_;

        // --- Image Metadata (from BEGIN) ---
        OTA_ImageHeader image_header;

        // --- Progress ---
        uint16_t received_chunks;
        /// 다음 기대 청크 시퀀스 (0..total_chunks-1), uint32로 래핑 모호 제거
        uint32_t expected_next_seq;
        uint32_t write_offset;       ///< Current write offset within Bank B

        // [OTA-1] Q16 역수: 100/total_chunks를 Q16 고정소수점으로 사전 계산
        //  Handle_Begin에서 1회 계산 (cold path, 32비트 HW UDIV 2-12cyc)
        //  Get_Progress_Percent에서 곱셈+시프트만 사용 (hot path, 나눗셈 0)
        //  inv_progress_q16 = (100 << 16) / total_chunks
        //  percent = (received * inv_progress_q16) >> 16
        uint32_t inv_progress_q16;

        // --- Response Buffer ---
        uint8_t rsp_buf[16];

        // ============================================================
        //  CFI Transition
        // ============================================================
        bool Transition_State(OTA_State target) noexcept
        {
            if (!OTA_Is_Legal_Transition(state, target)) {
                if (OTA_Is_Legal_Transition(state, OTA_State::ERROR)) {
                    state = OTA_State::ERROR;
                }
                cfi_violation_count++;
                return false;
            }
            state = target;
            return true;
        }

        // ============================================================
        //  Handle BEGIN
        // ============================================================
        void Handle_Begin(const uint8_t* payload, uint16_t len) noexcept
        {
            // Idempotency: if already receiving, restart
            if ((static_cast<uint8_t>(state) & static_cast<uint8_t>(OTA_State::RECEIVING)) != 0u) {
                state = OTA_State::IDLE;
            }

            // CFI: IDLE -> RECEIVING
            if (!Transition_State(OTA_State::RECEIVING)) {
                last_result = OTA_Result::NOT_READY;
                return;
            }

            // Parse image header (overflow-safe)
            if (len < static_cast<uint16_t>(sizeof(OTA_ImageHeader))) {
                last_result = OTA_Result::SIZE_FAIL;
                Transition_State(OTA_State::ERROR);
                return;
            }

            image_header.total_size =
                OTA_Read_U32(&payload[static_cast<size_t>(0u)]);
            image_header.fw_version =
                OTA_Read_U32(&payload[static_cast<size_t>(4u)]);
            image_header.expected_crc32 =
                OTA_Read_U32(&payload[static_cast<size_t>(8u)]);
            image_header.total_chunks =
                OTA_Read_U16(&payload[static_cast<size_t>(12u)]);
            image_header.chunk_size =
                OTA_Read_U16(&payload[static_cast<size_t>(14u)]);

            // Validate size
            if (image_header.total_size == 0u || image_header.total_size > OTA_BANK_SIZE) {
                last_result = OTA_Result::SIZE_FAIL;
                Transition_State(OTA_State::ERROR);
                return;
            }

            // Validate chunk parameters (zero-division defense + sanity)
            if (image_header.total_chunks == 0u || image_header.chunk_size == 0u) {
                last_result = OTA_Result::SIZE_FAIL;
                Transition_State(OTA_State::ERROR);
                return;
            }
            if (image_header.total_chunks > OTA_MAX_CHUNKS) {
                last_result = OTA_Result::SIZE_FAIL;
                Transition_State(OTA_State::ERROR);
                return;
            }
            if (image_header.chunk_size > OTA_CHUNK_MAX_SIZE) {
                last_result = OTA_Result::SIZE_FAIL;
                Transition_State(OTA_State::ERROR);
                return;
            }

            // Anti-rollback: version must be strictly greater
            if (flash_cb.get_current_fw_version != nullptr) {
                const uint32_t current_ver = flash_cb.get_current_fw_version();
                if (image_header.fw_version <= current_ver) {
                    last_result = OTA_Result::VERSION_FAIL;
                    Transition_State(OTA_State::ERROR);
                    return;
                }
            }

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
            if (!HTS_OTA_Board_Power_Stable()) {
                last_result = OTA_Result::FLASH_FAIL;
                Transition_State(OTA_State::ERROR);
                return;
            }
#endif

            // Erase Bank B sectors
            for (uint32_t i = 0u; i < OTA_SECTOR_COUNT; ++i) {
                const uint32_t sector_addr = OTA_BANK_B_BASE + (i * OTA_SECTOR_SIZE);
                if (flash_cb.erase_sector != nullptr) {
                    if (!flash_cb.erase_sector(sector_addr)) {
                        last_result = OTA_Result::FLASH_FAIL;
                        Transition_State(OTA_State::ERROR);
                        return;
                    }
                }
            }

            received_chunks = 0u;
            expected_next_seq = 0u;
            write_offset = 0u;
            last_result = OTA_Result::IN_PROGRESS;

            // [OTA-1] Q16 역수 사전 계산 (cold path, OTA 세션당 1회)
            //  total_chunks != 0 검증 완료 후 도달 → 제로 나눗셈 불가
            //  100 << 16 = 6,553,600, total_chunks max=2200
            //  6,553,600 / 1 = 6,553,600 < UINT32_MAX ✓
            //  32비트 HW UDIV 2-12cyc (Cortex-M4)
            inv_progress_q16 = (100u << 16u) /
                static_cast<uint32_t>(image_header.total_chunks);
        }

        // ============================================================
        //  Handle CHUNK_DATA
        // ============================================================
        void Handle_Chunk(const uint8_t* payload, uint16_t len) noexcept
        {
            if ((static_cast<uint8_t>(state) & static_cast<uint8_t>(OTA_State::RECEIVING)) == 0u) {
                last_result = OTA_Result::NOT_READY;
                return;
            }

            // Parse chunk header: SEQ(2) + TOTAL(2) + LEN(1) = 5
            if (len < 5u) {
                last_result = OTA_Result::SEQUENCE_FAIL;
                return;
            }

            const uint16_t seq = OTA_Read_U16(&payload[static_cast<size_t>(0u)]);
            const uint16_t total = OTA_Read_U16(&payload[static_cast<size_t>(2u)]);
            const uint8_t  chunk_len = payload[static_cast<size_t>(4u)];

            const uint32_t seq32 = static_cast<uint32_t>(seq);

            // 이미 커밋된 시퀀스 재전송 — Flash 재기록 방지(마모·STM32 AND 쓰기 오염 방지)
            if (seq32 < expected_next_seq) {
                last_result = OTA_Result::IN_PROGRESS;
                return;
            }

            // Sequence validation (다음 기대 시퀀스와 일치)
            if (seq32 != expected_next_seq) {
                last_result = OTA_Result::SEQUENCE_FAIL;
                return;
            }

            // Total chunks consistency
            if (total != image_header.total_chunks) {
                last_result = OTA_Result::SEQUENCE_FAIL;
                return;
            }

            // Chunk data bounds (overflow-safe)
            if (chunk_len > OTA_CHUNK_MAX_SIZE) { return; }
            if (len < 5u) { return; }
            if (static_cast<uint32_t>(len) - 5u < static_cast<uint32_t>(chunk_len)) { return; }

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
            if (!HTS_OTA_Board_Power_Stable()) {
                last_result = OTA_Result::FLASH_FAIL;
                Transition_State(OTA_State::ERROR);
                return;
            }
#endif

            // Flash write bounds check (뺄셈 기반 — write_offset+chunk_len 합산 오버플로우 회피)
            if (write_offset > OTA_BANK_SIZE) {
                last_result = OTA_Result::SIZE_FAIL;
                Transition_State(OTA_State::ERROR);
                return;
            }
            const uint32_t bank_remain = OTA_BANK_SIZE - write_offset;
            if (static_cast<uint32_t>(chunk_len) > bank_remain) {
                last_result = OTA_Result::SIZE_FAIL;
                Transition_State(OTA_State::ERROR);
                return;
            }

            // Write to Flash Bank B
            if (flash_cb.write_flash != nullptr) {
                const uint32_t addr = OTA_BANK_B_BASE + write_offset;
                if (!flash_cb.write_flash(addr,
                    &payload[static_cast<size_t>(5u)],
                    static_cast<uint32_t>(chunk_len)))
                {
                    last_result = OTA_Result::FLASH_FAIL;
                    Transition_State(OTA_State::ERROR);
                    return;
                }

                // [항목⑯] Flash read-back 검증 — 기록 직후 읽어서 원본과 비교
                if (flash_cb.read_flash != nullptr) {
                    uint8_t rb[OTA_CHUNK_MAX_SIZE];
                    if (!flash_cb.read_flash(addr, rb,
                        static_cast<uint32_t>(chunk_len)))
                    {
                        last_result = OTA_Result::FLASH_FAIL;
                        Transition_State(OTA_State::ERROR);
                        return;
                    }
                    if (std::memcmp(rb,
                        &payload[static_cast<size_t>(5u)],
                        static_cast<size_t>(chunk_len)) != 0)
                    {
                        last_result = OTA_Result::FLASH_FAIL;
                        Transition_State(OTA_State::ERROR);
                        return;
                    }
                }
            }

            write_offset += static_cast<uint32_t>(chunk_len);
            received_chunks++;
            ++expected_next_seq;
            last_result = OTA_Result::IN_PROGRESS;
        }

        // ============================================================
        //  Handle VERIFY
        //
        //  [OTA-5] 256B 청크 단위 Flash 읽기 (read_flash 호출 횟수 감소)
        //   스택 사용: +256B (OTA 컨텍스트에서 허용 범위)
        //   양산 환경: STM32 HW CRC + DMA로 대체 권장
        // ============================================================
        void Handle_Verify() noexcept
        {
            // CFI: RECEIVING -> VERIFYING
            if (!Transition_State(OTA_State::VERIFYING)) {
                last_result = OTA_Result::NOT_READY;
                return;
            }

            // Check all chunks received
            if (received_chunks != image_header.total_chunks) {
                last_result = OTA_Result::SEQUENCE_FAIL;
                Transition_State(OTA_State::ERROR);
                return;
            }

            // Check written size matches expected
            if (write_offset != image_header.total_size) {
                last_result = OTA_Result::SIZE_FAIL;
                Transition_State(OTA_State::ERROR);
                return;
            }

            // 수신 경로에 사용된 Flash HAL이 없으면 CRC 검증 무의미(무음 통과 방지)
            if (flash_cb.erase_sector == nullptr
                || flash_cb.write_flash == nullptr
                || flash_cb.read_flash == nullptr)
            {
                last_result = OTA_Result::FLASH_FAIL;
                Transition_State(OTA_State::ERROR);
                return;
            }

            // CRC-32 verification over entire Bank B image
            //  [OTA-5] 256B 스택 버퍼로 청크 읽기
            static constexpr uint32_t VERIFY_CHUNK = 256u;
            uint32_t crc = 0xFFFFFFFFu;
            {
                uint8_t read_buf[VERIFY_CHUNK];
                uint32_t remaining = image_header.total_size;
                uint32_t offset = 0u;

                while (remaining > 0u) {
                    const uint32_t chunk = (remaining < VERIFY_CHUNK)
                        ? remaining : VERIFY_CHUNK;
                    if (!flash_cb.read_flash(
                        OTA_BANK_B_BASE + offset, read_buf, chunk))
                    {
                        last_result = OTA_Result::FLASH_FAIL;
                        Transition_State(OTA_State::ERROR);
                        OTA_Secure_Wipe(read_buf, VERIFY_CHUNK);
                        return;
                    }
                    crc = CRC32_Update_Block(crc, read_buf, chunk);
                    offset += chunk;
                    remaining -= chunk;
                }

                // [OTA-2] 읽기 버퍼 보안 소거 (평문 펌웨어 잔존 방지)
                OTA_Secure_Wipe(read_buf, VERIFY_CHUNK);
            }
            crc ^= 0xFFFFFFFFu;

            if (crc != image_header.expected_crc32) {
                last_result = OTA_Result::CRC_FAIL;
                Transition_State(OTA_State::ERROR);
                return;
            }

            // CFI: VERIFYING -> VERIFIED
            if (!Transition_State(OTA_State::VERIFIED)) {
                last_result = OTA_Result::NOT_READY;
                return;
            }
            last_result = OTA_Result::OK;
        }

        // ============================================================
        //  Handle COMMIT
        // ============================================================
        void Handle_Commit() noexcept
        {
            // CFI: VERIFIED -> COMMITTING
            if (!Transition_State(OTA_State::COMMITTING)) {
                last_result = OTA_Result::NOT_READY;
                return;
            }

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
            if (!HTS_OTA_Board_Power_Stable()) {
                last_result = OTA_Result::FLASH_FAIL;
                state = OTA_State::ERROR;
                return;
            }
#endif

            // Execute bank swap (system will reset -- no return)
            if (flash_cb.execute_bank_swap != nullptr) {
                flash_cb.execute_bank_swap();
                // [[noreturn]] -- should never reach here
            }

            // If bank swap callback missing, fall back to error
            last_result = OTA_Result::FLASH_FAIL;
            state = OTA_State::ERROR;
        }

        // ============================================================
        //  Handle ABORT
        // ============================================================
        void Handle_Abort() noexcept
        {
            if ((static_cast<uint8_t>(state) &
                (static_cast<uint8_t>(OTA_State::RECEIVING)
                    | static_cast<uint8_t>(OTA_State::VERIFYING)
                    | static_cast<uint8_t>(OTA_State::VERIFIED)
                    | static_cast<uint8_t>(OTA_State::ERROR))) != 0u)
            {
                Transition_State(OTA_State::IDLE);
            }
            received_chunks = 0u;
            expected_next_seq = 0u;
            write_offset = 0u;
            inv_progress_q16 = 0u;
            last_result = OTA_Result::OK;
        }

        // ============================================================
        //  Send Status Response
        // ============================================================
        void Send_Status() noexcept
        {
            if (ipc == nullptr) { return; }

            uint32_t pos = 0u;
            rsp_buf[static_cast<size_t>(pos++)] =
                static_cast<uint8_t>(OTA_Command::STATUS_RSP);
            rsp_buf[static_cast<size_t>(pos++)] = static_cast<uint8_t>(state);
            rsp_buf[static_cast<size_t>(pos++)] = static_cast<uint8_t>(last_result);
            OTA_Write_U16(&rsp_buf[static_cast<size_t>(pos)], received_chunks);
            pos += 2u;
            OTA_Write_U16(&rsp_buf[static_cast<size_t>(pos)], image_header.total_chunks);
            pos += 2u;

            const IPC_Error se = ipc->Send_Frame(IPC_Command::DATA_TX,
                rsp_buf, static_cast<uint16_t>(pos));
            if (se != IPC_Error::OK) {
                last_result = OTA_Result::IPC_TX_FAIL;
            }
        }
    };

    // ============================================================
    //  Public API
    // ============================================================

    // [OTA-3] 생성자: impl_buf_ memset 0 초기화
    HTS_OTA_Manager::HTS_OTA_Manager() noexcept
        : initialized_{ false }
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "HTS_OTA_Manager::Impl exceeds IMPL_BUF_SIZE");

        std::memset(impl_buf_, 0, IMPL_BUF_SIZE);
    }

    HTS_OTA_Manager::~HTS_OTA_Manager() noexcept
    {
        Shutdown();
    }

    IPC_Error HTS_OTA_Manager::Initialize(HTS_IPC_Protocol* ipc) noexcept
    {
        OTA_Busy_Guard guard(op_busy_);

        bool expected = false;
        if (!initialized_.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel))
        {
            return IPC_Error::OK;
        }

        if (ipc == nullptr) {
#if defined(HTS_ALLOW_HOST_BUILD)
            // 호스트 단위검증: IPC 하드웨어 없이 Flash 콜백·OTA FSM만 검증(Send_Status는 ipc nullptr 시 no-op).
            Impl* impl_host = new (impl_buf_) Impl{};
            impl_host->ipc = nullptr;
            impl_host->state = OTA_State::IDLE;
            impl_host->last_result = OTA_Result::OK;
            impl_host->cfi_violation_count = 0u;
            impl_host->received_chunks = 0u;
            impl_host->expected_next_seq = 0u;
            impl_host->write_offset = 0u;
            impl_host->inv_progress_q16 = 0u;
            impl_host->flash_cb.erase_sector = nullptr;
            impl_host->flash_cb.write_flash = nullptr;
            impl_host->flash_cb.read_flash = nullptr;
            impl_host->flash_cb.execute_bank_swap = nullptr;
            impl_host->flash_cb.get_current_fw_version = nullptr;
            return IPC_Error::OK;
#else
            initialized_.store(false, std::memory_order_release);
            return IPC_Error::NOT_INITIALIZED;
#endif
        }

        Impl* impl = new (impl_buf_) Impl{};

        impl->ipc = ipc;
        impl->state = OTA_State::IDLE;
        impl->last_result = OTA_Result::OK;
        impl->cfi_violation_count = 0u;
        impl->received_chunks = 0u;
        impl->expected_next_seq = 0u;
        impl->write_offset = 0u;
        impl->inv_progress_q16 = 0u;

        impl->flash_cb.erase_sector = nullptr;
        impl->flash_cb.write_flash = nullptr;
        impl->flash_cb.read_flash = nullptr;
        impl->flash_cb.execute_bank_swap = nullptr;
        impl->flash_cb.get_current_fw_version = nullptr;

        return IPC_Error::OK;
    }

    // [OTA-2] Shutdown: impl 소멸 후 impl_buf_ 전체 보안 소거
    void HTS_OTA_Manager::Shutdown() noexcept
    {
        OTA_Busy_Guard guard(op_busy_);

        if (!initialized_.load(std::memory_order_acquire)) { return; }
        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        // 파괴·소거 전 공개 API 차단 — ~Impl/버퍼 소거 중 Get_* UAF 방지
        initialized_.store(false, std::memory_order_release);
        impl->ipc = nullptr;
        impl->state = OTA_State::IDLE;
        impl->~Impl();

        // [OTA-2] 보안 소거 — 프로젝트 표준 3중 방어
        OTA_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
    }

    void HTS_OTA_Manager::Register_Flash_Callbacks(const OTA_Flash_Callbacks& cb) noexcept
    {
        OTA_Busy_Guard guard(op_busy_);

        if (!initialized_.load(std::memory_order_acquire)) { return; }
        std::launder(reinterpret_cast<Impl*>(impl_buf_))->flash_cb = cb;
    }

    void HTS_OTA_Manager::Process_OTA_Command(const uint8_t* payload,
        uint16_t len) noexcept
    {
        OTA_Busy_Guard guard(op_busy_);

        if (payload == nullptr) { return; }
        if (len < 1u) { return; }
        if (!initialized_.load(std::memory_order_acquire)) { return; }

        Impl* impl = std::launder(reinterpret_cast<Impl*>(impl_buf_));
        const OTA_Command cmd =
            static_cast<OTA_Command>(payload[static_cast<size_t>(0u)]);

        switch (cmd) {
        case OTA_Command::BEGIN:
            impl->Handle_Begin(&payload[static_cast<size_t>(1u)],
                static_cast<uint16_t>(len - 1u));
            break;
        case OTA_Command::CHUNK_DATA:
            impl->Handle_Chunk(&payload[static_cast<size_t>(1u)],
                static_cast<uint16_t>(len - 1u));
            break;
        case OTA_Command::VERIFY:
            impl->Handle_Verify();
            break;
        case OTA_Command::COMMIT:
            impl->Handle_Commit();
            break;
        case OTA_Command::ABORT:
            impl->Handle_Abort();
            break;
        case OTA_Command::STATUS_REQ:
            impl->Send_Status();
            break;
        default:
            break;
        }
    }

    OTA_State HTS_OTA_Manager::Get_State() const noexcept
    {
        OTA_Busy_Guard guard(op_busy_);

        if (!initialized_.load(std::memory_order_acquire)) { return OTA_State::IDLE; }
        return reinterpret_cast<const Impl*>(impl_buf_)->state;
    }

    // [OTA-1] Get_Progress_Percent — 나눗셈 완전 제거
    //  received * 100 / total_chunks (매 호출 UDIV 2-12cyc)
    //  received * inv_progress_q16 >> 16 (MUL 1cyc + shift 1cyc)
    //  inv_progress_q16 = (100 << 16) / total_chunks (Handle_Begin에서 1회)
    //
    //  정밀도 검증:
    //   total=2200, inv=(100<<16)/2200=2978
    //   received=2200: 2200*2978=6,551,600 >> 16 = 99 (실제 100)
    //   → Q16 절삭으로 최대 1% 미달 가능 — 진행률 표시에 무영향
    //   received=2200 특수 처리로 100% 보장
    uint8_t HTS_OTA_Manager::Get_Progress_Percent() const noexcept
    {
        OTA_Busy_Guard guard(op_busy_);

        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        const Impl* impl = reinterpret_cast<const Impl*>(impl_buf_);
        if (impl->image_header.total_chunks == 0u) { return 0u; }

        // 완료 시 정확히 100% 반환 (Q16 절삭 보정)
        if (impl->received_chunks >= impl->image_header.total_chunks) {
            return 100u;
        }

        // [OTA-1] Q16 역수 곱셈 — 나눗셈 0회
        //  received max=2199, inv_progress_q16 max=6,553,600
        //  2199 * 6,553,600 = 14,415,422,400 > UINT32_MAX
        //  → uint64_t 승격 필요 (Cortex-M4: UMULL 단일명령어)
        const uint64_t numerator =
            static_cast<uint64_t>(impl->received_chunks) *
            static_cast<uint64_t>(impl->inv_progress_q16);
        const uint32_t percent = static_cast<uint32_t>(numerator >> 16u);

        return (percent > 100u) ? 100u : static_cast<uint8_t>(percent);
    }

    OTA_Result HTS_OTA_Manager::Get_Last_Result() const noexcept
    {
        OTA_Busy_Guard guard(op_busy_);

        if (!initialized_.load(std::memory_order_acquire)) { return OTA_Result::NOT_READY; }
        return reinterpret_cast<const Impl*>(impl_buf_)->last_result;
    }

    uint16_t HTS_OTA_Manager::Get_Received_Chunks() const noexcept
    {
        OTA_Busy_Guard guard(op_busy_);

        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        return reinterpret_cast<const Impl*>(impl_buf_)->received_chunks;
    }

} // namespace ProtectedEngine