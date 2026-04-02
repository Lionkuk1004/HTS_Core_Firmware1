/// @file  HTS_IPC_Protocol_A55.cpp
/// @brief HTS IPC Protocol Engine -- A55 SPI Master Implementation (Linux aarch64)
/// @details
///   Pimpl implementation of HTS_IPC_Protocol_A55 for Cortex-A55 Linux.
///   Linux spidev full-duplex SPI master, GPIO chardev DRDY edge detection,
///   pthread-based RX background thread, lock-free ring buffers.
///
/// @note  AArch64 Linux only. Guarded by HTS_PLATFORM_AARCH64.
///        Pure ASCII. No STM32 register-level code.
/// @author Lim Young-jun
/// @copyright INNOViD 2026. All rights reserved.

#ifdef HTS_PLATFORM_AARCH64

#include "HTS_IPC_Protocol_A55.h"
#include <cstring>
#include <atomic>
#include <new>          // placement new
#include <cstdio>       // snprintf

// Linux system headers (aarch64 only)
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <pthread.h>
#include <errno.h>

// ============================================================
//  Linux SPI / GPIO UAPI Constants (self-contained, no kernel header dependency)
// ============================================================

// -- SPI ioctl definitions (from <linux/spi/spidev.h>) --
#define HTS_SPI_IOC_MAGIC           'k'
#define HTS_SPI_IOC_WR_MODE         _IOW(HTS_SPI_IOC_MAGIC, 1, uint8_t)
#define HTS_SPI_IOC_WR_BITS         _IOW(HTS_SPI_IOC_MAGIC, 3, uint8_t)
#define HTS_SPI_IOC_WR_MAX_SPEED    _IOW(HTS_SPI_IOC_MAGIC, 4, uint32_t)
#define HTS_SPI_IOC_MESSAGE_1       _IOW(HTS_SPI_IOC_MAGIC, 0, struct HTS_SPI_Transfer)

/// @brief Linux SPI full-duplex transfer descriptor
struct HTS_SPI_Transfer {
    uint64_t tx_buf;            ///< Pointer to TX buffer (cast to uintptr_t)
    uint64_t rx_buf;            ///< Pointer to RX buffer (cast to uintptr_t)
    uint32_t len;               ///< Transfer length in bytes
    uint32_t speed_hz;          ///< Override SPI speed (0 = use default)
    uint16_t delay_usecs;       ///< Delay after transfer
    uint8_t  bits_per_word;     ///< Override bits per word (0 = use default)
    uint8_t  cs_change;         ///< CS deassert between transfers
    uint8_t  tx_nbits;          ///< TX bus width (0 = single)
    uint8_t  rx_nbits;          ///< RX bus width (0 = single)
    uint8_t  word_delay_usecs;  ///< Delay between words
    uint8_t  pad;               ///< Padding
};

// -- GPIO chardev ioctl definitions (V1 API, from <linux/gpio.h>) --
#define HTS_GPIO_GET_LINEEVENT_IOCTL  _IOWR(0xB4, 0x04, struct HTS_GPIO_Event_Request)

#define HTS_GPIOHANDLE_REQUEST_INPUT     (1u << 0u)
#define HTS_GPIOEVENT_REQUEST_RISING     (1u << 0u)

/// @brief GPIO line event request (V1 API)
struct HTS_GPIO_Event_Request {
    uint32_t lineoffset;                ///< GPIO line number
    uint32_t handleflags;               ///< GPIOHANDLE_REQUEST_INPUT etc.
    uint32_t eventflags;                ///< GPIOEVENT_REQUEST_RISING_EDGE etc.
    char     consumer_label[32];        ///< Consumer name
    int      fd;                        ///< Output: file descriptor for events
};

/// @brief GPIO line event data
struct HTS_GPIO_Event_Data {
    uint64_t timestamp;                 ///< Nanosecond timestamp
    uint32_t id;                        ///< Event type (rising/falling)
    uint32_t pad;
};

namespace ProtectedEngine {
    static constexpr uint32_t SECURE_TRUE = 0x5A5A5A5Au;
    static constexpr uint32_t SECURE_FALSE = 0xA5A5A5A5u;

    // ============================================================
    //  Constants
    // ============================================================

    static constexpr int INVALID_FD = -1;
    static constexpr uint32_t DRDY_POLL_TIMEOUT = 50u;     ///< Default poll timeout ms
    static constexpr uint32_t GPIO_PATH_MAX = 32u;

    // ============================================================
    //  Impl Structure
    // ============================================================

    struct HTS_IPC_Protocol_A55::Impl {
        // --- Configuration ---
        IPC_A55_Config config;

        // --- File Descriptors ---
        int spi_fd;
        int gpio_chip_fd;
        int gpio_event_fd;

        // --- CFI State Machine ---
        IPC_State state;
        uint32_t  state_entry_tick;

        // --- Sequence Tracking ---
        // tx_seq is atomic: Tick_Heartbeat() and Send_Frame() may run
        // from different threads, both incrementing the sequence counter.
        std::atomic<uint8_t> tx_seq;
        uint8_t rx_expected_seq;
        uint8_t pad0_[2];

        // --- Ring Buffers ---
        // RX ring: SPSC (RX thread produces, main thread consumes)
        // TX ring: MPSC lock-free (CAS reserve + ordered commit),
        //          RX thread consumes committed slots only.
        IPC_Ring_Entry rx_ring[IPC_RING_DEPTH];
        IPC_Ring_Entry tx_ring[IPC_RING_DEPTH];
        std::atomic<uint32_t> rx_head;      ///< Written by RX thread (release)
        std::atomic<uint32_t> rx_tail;      ///< Written by main thread (release)
        std::atomic<uint32_t> tx_head;      ///< Written by producers (CAS reserve)
        std::atomic<uint32_t> tx_commit;    ///< Written by producers (ordered commit)
        std::atomic<uint32_t> tx_tail;      ///< Written by RX thread consumer (release)

        // --- SPI Full-Duplex Buffers ---
        alignas(8) uint8_t spi_tx_buf[IPC_SPI_DMA_BUF_SIZE];
        alignas(8) uint8_t spi_rx_buf[IPC_SPI_DMA_BUF_SIZE];

        // --- RX Thread ---
        pthread_t rx_thread;
        std::atomic<bool> rx_thread_running;
        std::atomic<bool> rx_thread_exit_request;
        bool rx_thread_created;
        uint8_t pad1_[7];

        // --- Heartbeat ---
        uint32_t last_ping_sent_tick;
        uint32_t last_pong_recv_tick;

        // --- Statistics ---
        IPC_Statistics stats;

        // ============================================================
        //  CFI Transition
        // ============================================================
        uint32_t Transition_State(IPC_State target) noexcept
        {
            if (!IPC_Is_Legal_Transition(state, target)) {
                stats.cfi_violations.fetch_add(1u, std::memory_order_relaxed);
                state = IPC_State::ERROR_RECOVERY;
                return SECURE_FALSE;
            }
            state = target;
            return SECURE_TRUE;
        }

        // ============================================================
        //  Linux SPI: Open and Configure
        // ============================================================
        uint32_t Open_SPI() noexcept
        {
            spi_fd = ::open(config.spidev_path, O_RDWR);
            if (spi_fd < 0) { return SECURE_FALSE; }

            // Set SPI mode
            uint8_t mode = config.spi_mode;
            if (::ioctl(spi_fd, HTS_SPI_IOC_WR_MODE, &mode) < 0) {
                ::close(spi_fd);
                spi_fd = INVALID_FD;
                return SECURE_FALSE;
            }

            // Set bits per word
            uint8_t bpw = config.spi_bits_per_word;
            if (bpw == 0u) { bpw = 8u; }
            if (::ioctl(spi_fd, HTS_SPI_IOC_WR_BITS, &bpw) < 0) {
                ::close(spi_fd);
                spi_fd = INVALID_FD;
                return SECURE_FALSE;
            }

            // Set max speed
            uint32_t speed = config.spi_speed_hz;
            if (speed == 0u) { speed = 8000000u; }  // Default 8 MHz
            if (::ioctl(spi_fd, HTS_SPI_IOC_WR_MAX_SPEED, &speed) < 0) {
                ::close(spi_fd);
                spi_fd = INVALID_FD;
                return SECURE_FALSE;
            }

            return SECURE_TRUE;
        }

        // ============================================================
        //  Linux GPIO: Open Chardev and Configure DRDY Line
        // ============================================================
        uint32_t Open_GPIO_DRDY() noexcept
        {
            // Build gpiochip path
            char chip_path[GPIO_PATH_MAX];
            // snprintf: "/dev/gpiochipN"
            int written = ::snprintf(chip_path, GPIO_PATH_MAX,
                "/dev/gpiochip%u", static_cast<unsigned>(config.gpio_drdy_chip));
            if ((written < 0) || (static_cast<uint32_t>(written) >= GPIO_PATH_MAX)) {
                return SECURE_FALSE;
            }

            gpio_chip_fd = ::open(chip_path, O_RDONLY);
            if (gpio_chip_fd < 0) { return SECURE_FALSE; }

            // Request line event (rising edge on DRDY)
            HTS_GPIO_Event_Request req = {};
            req.lineoffset = static_cast<uint32_t>(config.gpio_drdy_line);
            req.handleflags = HTS_GPIOHANDLE_REQUEST_INPUT;
            req.eventflags = HTS_GPIOEVENT_REQUEST_RISING;

            // Consumer label
            static constexpr char k_label[] = "hts_ipc_drdy";
            for (uint32_t i = 0u; i < sizeof(k_label) && i < 32u; ++i) {
                req.consumer_label[i] = k_label[i];
            }

            if (::ioctl(gpio_chip_fd, HTS_GPIO_GET_LINEEVENT_IOCTL, &req) < 0) {
                ::close(gpio_chip_fd);
                gpio_chip_fd = INVALID_FD;
                return SECURE_FALSE;
            }

            gpio_event_fd = req.fd;
            return SECURE_TRUE;
        }

        // ============================================================
        //  SPI Full-Duplex Transfer
        // ============================================================
        uint32_t SPI_Transfer(const uint8_t* tx, uint8_t* rx, uint32_t len) noexcept
        {
            if (spi_fd < 0) { return SECURE_FALSE; }

            HTS_SPI_Transfer xfer = {};
            xfer.tx_buf = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(tx));
            xfer.rx_buf = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(rx));
            xfer.len = len;
            xfer.speed_hz = config.spi_speed_hz;
            xfer.bits_per_word = (config.spi_bits_per_word != 0u) ? config.spi_bits_per_word : 8u;

            int ret = ::ioctl(spi_fd, HTS_SPI_IOC_MESSAGE_1, &xfer);
            if (ret < 0) {
                stats.hw_faults.fetch_add(1u, std::memory_order_relaxed);
                return SECURE_FALSE;
            }
            return SECURE_TRUE;
        }

        // ============================================================
        //  Ring Buffer Helpers (identical logic to STM32 side)
        // ============================================================

        uint32_t Ring_RX_Push(const uint8_t* data, uint16_t len) noexcept
        {
            const uint32_t head = rx_head.load(std::memory_order_relaxed);
            const uint32_t tail = rx_tail.load(std::memory_order_acquire);
            if ((head - tail) >= IPC_RING_DEPTH) {
                stats.queue_overflows.fetch_add(1u, std::memory_order_relaxed);
                return SECURE_FALSE;
            }
            IPC_Ring_Entry& entry = rx_ring[head & IPC_RING_MASK];
            const uint32_t copy_len = (len <= IPC_MAX_FRAME_SIZE)
                ? static_cast<uint32_t>(len)
                : IPC_MAX_FRAME_SIZE;
            for (uint32_t i = 0u; i < copy_len; ++i) {
                entry.data[i] = data[i];
            }
            entry.length = static_cast<uint16_t>(copy_len);
            rx_head.store(head + 1u, std::memory_order_release);
            return SECURE_TRUE;
        }

        uint32_t Ring_RX_Pop(uint8_t* data, uint16_t buf_size, uint16_t& out_len) noexcept
        {
            const uint32_t head = rx_head.load(std::memory_order_acquire);
            const uint32_t tail = rx_tail.load(std::memory_order_relaxed);
            if (head == tail) {
                out_len = 0u;
                return SECURE_FALSE;
            }
            const IPC_Ring_Entry& entry = rx_ring[tail & IPC_RING_MASK];
            const uint16_t copy_len = (entry.length <= buf_size) ? entry.length : buf_size;
            if (data != nullptr) {
                for (uint16_t i = 0u; i < copy_len; ++i) {
                    data[i] = entry.data[i];
                }
            }
            out_len = copy_len;
            rx_tail.store(tail + 1u, std::memory_order_release);
            return SECURE_TRUE;
        }

        /// @brief Push frame into TX ring (MPSC lock-free CAS + commit)
        uint32_t Ring_TX_Push(const uint8_t* data, uint16_t len) noexcept
        {
            uint32_t head = 0u;
            uint32_t next_head = 0u;
            do {
                head = tx_head.load(std::memory_order_acquire);
                const uint32_t tail = tx_tail.load(std::memory_order_acquire);
                if ((head - tail) >= IPC_RING_DEPTH) {
                    stats.queue_overflows.fetch_add(1u, std::memory_order_relaxed);
                    return SECURE_FALSE;
                }
                next_head = head + 1u;
            } while (!tx_head.compare_exchange_weak(
                head, next_head, std::memory_order_acq_rel, std::memory_order_acquire));

            IPC_Ring_Entry& entry = tx_ring[head & IPC_RING_MASK];
            const uint32_t copy_len = (len <= IPC_MAX_FRAME_SIZE)
                ? static_cast<uint32_t>(len)
                : IPC_MAX_FRAME_SIZE;
            for (uint32_t i = 0u; i < copy_len; ++i) {
                entry.data[i] = data[i];
            }
            entry.length = static_cast<uint16_t>(copy_len);

            while (tx_commit.load(std::memory_order_acquire) != head) {
#if defined(__aarch64__)
                __asm__ __volatile__("yield" ::: "memory");
#else
                std::atomic_signal_fence(std::memory_order_acq_rel);
#endif
            }
            tx_commit.store(next_head, std::memory_order_release);
            return SECURE_TRUE;
        }

        uint32_t Ring_TX_Pop(uint8_t* data, uint16_t buf_size, uint16_t& out_len) noexcept
        {
            const uint32_t head = tx_commit.load(std::memory_order_acquire);
            const uint32_t tail = tx_tail.load(std::memory_order_relaxed);
            if (head == tail) {
                out_len = 0u;
                return SECURE_FALSE;
            }
            const IPC_Ring_Entry& entry = tx_ring[tail & IPC_RING_MASK];
            const uint16_t copy_len = (entry.length <= buf_size) ? entry.length : buf_size;
            if (data != nullptr) {
                for (uint16_t i = 0u; i < copy_len; ++i) {
                    data[i] = entry.data[i];
                }
            }
            out_len = copy_len;
            tx_tail.store(tail + 1u, std::memory_order_release);
            return SECURE_TRUE;
        }

        uint32_t Ring_RX_Count() const noexcept
        {
            return rx_head.load(std::memory_order_acquire) -
                rx_tail.load(std::memory_order_relaxed);
        }

        uint32_t Ring_TX_Count() const noexcept
        {
            return tx_commit.load(std::memory_order_acquire) -
                tx_tail.load(std::memory_order_relaxed);
        }

        // ============================================================
        //  Process Received SPI Data (called by RX thread or TX pump)
        // ============================================================
        void Process_RX_Data() noexcept
        {
            // Check if RX buffer contains a valid frame (not idle/zero)
            if (spi_rx_buf[0] == 0u && spi_rx_buf[1] == 0u) {
                return;  // Idle pattern from STM32, skip
            }

            uint8_t         payload_scratch[IPC_MAX_PAYLOAD];
            uint8_t         seq = 0u;
            IPC_Command     cmd = IPC_Command::PING;
            uint16_t        payload_len = 0u;

            const IPC_Error err = IPC_Parse_Frame(
                spi_rx_buf, IPC_SPI_DMA_BUF_SIZE, seq, cmd,
                payload_scratch, static_cast<uint16_t>(sizeof(payload_scratch)), payload_len);

            if (err != IPC_Error::OK) {
                IPC_Secure_Wipe(payload_scratch, sizeof(payload_scratch));
                if (err == IPC_Error::CRC_MISMATCH) {
                    stats.crc_errors.fetch_add(1u, std::memory_order_relaxed);
                }
                return;
            }

            stats.rx_frames.fetch_add(1u, std::memory_order_relaxed);

            // Internal protocol handling
            switch (cmd) {
            case IPC_Command::PONG:
                // Update heartbeat (approximate: use last known tick)
                last_pong_recv_tick = state_entry_tick;
                break;

            case IPC_Command::ACK:
            case IPC_Command::NACK:
                // Protocol-level ACK/NACK -- future: retry logic
                break;

            case IPC_Command::KILL_SWITCH:
                // STM32 should not send KILL_SWITCH to A55, but handle gracefully
                break;

            default:
                // Application-level frames: push to RX ring for main thread
                Ring_RX_Push(spi_rx_buf, static_cast<uint16_t>(
                    IPC_HEADER_SIZE + static_cast<uint32_t>(payload_len) + IPC_CRC_SIZE));
                break;
            }

            IPC_Secure_Wipe(payload_scratch, sizeof(payload_scratch));
        }

        // ============================================================
        //  RX Thread: Poll DRDY GPIO, Perform SPI Transfer on Edge
        // ============================================================
        static void* RX_Thread_Entry(void* arg) noexcept
        {
            Impl* self = static_cast<Impl*>(arg);
            self->RX_Thread_Loop();
            return nullptr;
        }

        void RX_Thread_Loop() noexcept
        {
            rx_thread_running.store(true, std::memory_order_release);

            struct pollfd pfd;
            pfd.fd = gpio_event_fd;
            pfd.events = POLLIN | POLLPRI;

            const int poll_timeout = static_cast<int>(
                (config.poll_timeout_ms > 0u) ? config.poll_timeout_ms : DRDY_POLL_TIMEOUT);

            while (!rx_thread_exit_request.load(std::memory_order_acquire)) {
                pfd.revents = 0;
                int ret = ::poll(&pfd, 1, poll_timeout);

                if (ret < 0) {
                    if (errno == EINTR) { continue; }
                    stats.hw_faults.fetch_add(1u, std::memory_order_relaxed);
                    continue;
                }

                if (ret == 0) {
                    // Timeout: no DRDY edge -- check if we have TX data to send
                    Pump_TX_From_Thread();
                    continue;
                }

                // DRDY rising edge detected
                if ((pfd.revents & (POLLIN | POLLPRI)) != 0) {
                    // Consume the event
                    HTS_GPIO_Event_Data ev;
                    ssize_t rd = ::read(gpio_event_fd, &ev, sizeof(ev));
                    (void)rd;  // Event consumed regardless of read result

                    // Perform full-duplex SPI transfer
                    // Load TX buffer: next queued frame or idle zeros
                    Load_TX_Buffer_For_Transfer();

                    if (SPI_Transfer(spi_tx_buf, spi_rx_buf, IPC_SPI_DMA_BUF_SIZE) == SECURE_TRUE) {
                        Process_RX_Data();
                    }
                }
            }

            rx_thread_running.store(false, std::memory_order_release);
        }

        // ============================================================
        //  Load TX Buffer for SPI Transfer
        // ============================================================
        void Load_TX_Buffer_For_Transfer() noexcept
        {
            uint16_t frame_len = 0u;
            if (Ring_TX_Pop(spi_tx_buf, IPC_SPI_DMA_BUF_SIZE, frame_len) == SECURE_TRUE) {
                // Zero-pad remainder
                for (uint32_t i = static_cast<uint32_t>(frame_len); i < IPC_SPI_DMA_BUF_SIZE; ++i) {
                    spi_tx_buf[i] = 0x00u;
                }
                stats.tx_frames.fetch_add(1u, std::memory_order_relaxed);
            }
            else {
                // No TX data -- send idle pattern
                for (uint32_t i = 0u; i < IPC_SPI_DMA_BUF_SIZE; ++i) {
                    spi_tx_buf[i] = 0x00u;
                }
            }
        }

        // ============================================================
        //  TX Pump: Send Queued Frames (called from RX thread on poll timeout)
        // ============================================================
        void Pump_TX_From_Thread() noexcept
        {
            // If TX ring has data, initiate a transfer even without DRDY
            // (master-initiated transfer; STM32 will receive simultaneously)
            if (Ring_TX_Count() == 0u) { return; }

            Load_TX_Buffer_For_Transfer();

            if (SPI_Transfer(spi_tx_buf, spi_rx_buf, IPC_SPI_DMA_BUF_SIZE) == SECURE_TRUE) {
                Process_RX_Data();  // Check if STM32 sent data simultaneously
            }
        }

        // ============================================================
        //  Heartbeat
        // ============================================================
        void Tick_Heartbeat(uint32_t now_ms) noexcept
        {
            if (config.ping_interval_ms == 0u) { return; }

            const uint32_t elapsed = now_ms - last_ping_sent_tick;
            if (elapsed >= config.ping_interval_ms) {
                // Queue PING frame
                uint8_t frame_buf[IPC_HEADER_SIZE + IPC_CRC_SIZE];
                uint32_t flen = 0u;
                if (IPC_Serialize_Frame(
                        frame_buf, tx_seq.fetch_add(1u, std::memory_order_relaxed),
                        IPC_Command::PING, nullptr, 0u, flen) == IPC_Error::OK
                    && flen > 0u) {
                    (void)Ring_TX_Push(frame_buf, static_cast<uint16_t>(flen));
                }
                last_ping_sent_tick = now_ms;
            }
        }

        uint32_t Is_Heartbeat_Alive(uint32_t now_ms) const noexcept
        {
            if (config.ping_interval_ms == 0u) { return SECURE_TRUE; }
            const uint32_t dead_threshold =
                (config.ping_interval_ms <= (0xFFFFFFFFu / 3u))
                ? (config.ping_interval_ms * 3u)
                : 0xFFFFFFFFu;
            return ((now_ms - last_pong_recv_tick) < dead_threshold)
                ? SECURE_TRUE
                : SECURE_FALSE;
        }

        // ============================================================
        //  Close All File Descriptors
        // ============================================================
        void Close_All_FDs() noexcept
        {
            if (gpio_event_fd >= 0) {
                ::close(gpio_event_fd);
                gpio_event_fd = INVALID_FD;
            }
            if (gpio_chip_fd >= 0) {
                ::close(gpio_chip_fd);
                gpio_chip_fd = INVALID_FD;
            }
            if (spi_fd >= 0) {
                ::close(spi_fd);
                spi_fd = INVALID_FD;
            }
        }
    };

    // ============================================================
    //  Public API Implementation
    // ============================================================

    HTS_IPC_Protocol_A55::HTS_IPC_Protocol_A55() noexcept
        : initialized_{ false }
    {
        // Build-time size verification
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "HTS_IPC_Protocol_A55::Impl exceeds IMPL_BUF_SIZE -- "
            "increase buffer or reduce ring depth");

        for (uint32_t i = 0u; i < IMPL_BUF_SIZE; ++i) {
            impl_buf_[i] = 0u;
        }
    }

    HTS_IPC_Protocol_A55::~HTS_IPC_Protocol_A55() noexcept
    {
        Shutdown();
    }

    IPC_Error HTS_IPC_Protocol_A55::Initialize(const IPC_A55_Config& config) noexcept
    {
        // Idempotent CAS guard
        bool expected = false;
        if (!initialized_.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel))
        {
            return IPC_Error::OK;  // Already initialized
        }

        // Validate config
        if (config.spidev_path[0] == '\0') {
            initialized_.store(false, std::memory_order_release);
            return IPC_Error::HW_FAULT;
        }

        // Construct Impl via placement new
        Impl* impl = new (impl_buf_) Impl{};

        // Store config
        impl->config = config;
        if (impl->config.frame_timeout_ms == 0u) {
            impl->config.frame_timeout_ms = IPC_FRAME_TIMEOUT_MS;
        }
        if (impl->config.spi_bits_per_word == 0u) {
            impl->config.spi_bits_per_word = 8u;
        }
        if (impl->config.spi_speed_hz == 0u) {
            impl->config.spi_speed_hz = 8000000u;  // 8 MHz default
        }

        // Initialize FDs
        impl->spi_fd = INVALID_FD;
        impl->gpio_chip_fd = INVALID_FD;
        impl->gpio_event_fd = INVALID_FD;

        // Initialize state
        impl->state = IPC_State::UNINITIALIZED;
        impl->state_entry_tick = 0u;
        impl->tx_seq.store(0u, std::memory_order_relaxed);
        impl->rx_expected_seq = 0u;

        // Initialize ring buffer pointers
        impl->rx_head.store(0u, std::memory_order_relaxed);
        impl->rx_tail.store(0u, std::memory_order_relaxed);
        impl->tx_head.store(0u, std::memory_order_relaxed);
        impl->tx_commit.store(0u, std::memory_order_relaxed);
        impl->tx_tail.store(0u, std::memory_order_relaxed);

        // Initialize thread state
        impl->rx_thread_running.store(false, std::memory_order_relaxed);
        impl->rx_thread_exit_request.store(false, std::memory_order_relaxed);
        impl->rx_thread_created = false;

        // Zero heartbeat
        impl->last_ping_sent_tick = 0u;
        impl->last_pong_recv_tick = 0u;

        // Zero statistics
        IPC_Statistics_Reset(impl->stats);

        // --- Open SPI ---
        if (impl->Open_SPI() != SECURE_TRUE) {
            impl->~Impl();
            initialized_.store(false, std::memory_order_release);
            return IPC_Error::HW_FAULT;
        }

        // --- Open GPIO DRDY ---
        if (impl->Open_GPIO_DRDY() != SECURE_TRUE) {
            impl->Close_All_FDs();
            impl->~Impl();
            initialized_.store(false, std::memory_order_release);
            return IPC_Error::HW_FAULT;
        }

        // --- Spawn RX Thread ---
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        // Set detached state: cleanup on exit, no join needed at normal operation
        // But we DO join on shutdown, so use joinable (default)
        int rc = pthread_create(&impl->rx_thread, &attr,
            Impl::RX_Thread_Entry, impl);
        pthread_attr_destroy(&attr);

        if (rc != 0) {
            impl->Close_All_FDs();
            impl->~Impl();
            initialized_.store(false, std::memory_order_release);
            return IPC_Error::HW_FAULT;
        }
        impl->rx_thread_created = true;

        // Wait for RX thread to start (bounded spin)
        uint32_t spin = 0u;
        while (!impl->rx_thread_running.load(std::memory_order_acquire) && spin < 100000u) {
            ++spin;
        }
        if (!impl->rx_thread_running.load(std::memory_order_acquire)) {
            impl->rx_thread_exit_request.store(true, std::memory_order_release);
            if (impl->rx_thread_created) {
                pthread_join(impl->rx_thread, nullptr);
                impl->rx_thread_created = false;
            }
            impl->Close_All_FDs();
            impl->~Impl();
            initialized_.store(false, std::memory_order_release);
            return IPC_Error::HW_FAULT;
        }

        // Transition to IDLE
        impl->Transition_State(IPC_State::IDLE);

        return IPC_Error::OK;
    }

    void HTS_IPC_Protocol_A55::Shutdown() noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }

        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        // Signal RX thread to exit
        impl->rx_thread_exit_request.store(true, std::memory_order_release);

        // Join RX thread
        if (impl->rx_thread_created) {
            pthread_join(impl->rx_thread, nullptr);
            impl->rx_thread_created = false;
        }

        // Close file descriptors
        impl->Close_All_FDs();

        // Secure wipe SPI buffers
        IPC_Secure_Wipe(impl->spi_rx_buf, IPC_SPI_DMA_BUF_SIZE);
        IPC_Secure_Wipe(impl->spi_tx_buf, IPC_SPI_DMA_BUF_SIZE);
        IPC_Secure_Wipe(impl->rx_ring, sizeof(impl->rx_ring));
        IPC_Secure_Wipe(impl->tx_ring, sizeof(impl->tx_ring));
        std::atomic_thread_fence(std::memory_order_release);

        // Explicit destructor
        impl->~Impl();

        IPC_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);

        initialized_.store(false, std::memory_order_release);
    }

    IPC_Error HTS_IPC_Protocol_A55::Reset() noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) {
            return IPC_Error::NOT_INITIALIZED;
        }

        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        // Clear ring buffers
        impl->rx_head.store(0u, std::memory_order_relaxed);
        impl->rx_tail.store(0u, std::memory_order_relaxed);
        impl->tx_head.store(0u, std::memory_order_relaxed);
        impl->tx_commit.store(0u, std::memory_order_relaxed);
        impl->tx_tail.store(0u, std::memory_order_relaxed);

        // Reset sequence
        impl->tx_seq.store(0u, std::memory_order_relaxed);
        impl->rx_expected_seq = 0u;

        // Transition to IDLE
        impl->state = IPC_State::IDLE;

        return IPC_Error::OK;
    }

    void HTS_IPC_Protocol_A55::Tick(uint32_t monotonic_ms) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }

        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        impl->state_entry_tick = monotonic_ms;

        // Heartbeat management
        impl->Tick_Heartbeat(monotonic_ms);

        // Note: TX pump and RX processing happen in the RX thread.
        // Tick() is mainly for heartbeat and timeout management on A55 side.
    }

    IPC_Error HTS_IPC_Protocol_A55::Send_Frame(
        IPC_Command     cmd,
        const uint8_t* payload,
        uint16_t        payload_len) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) {
            return IPC_Error::NOT_INITIALIZED;
        }
        if (payload_len > IPC_MAX_PAYLOAD) {
            return IPC_Error::INVALID_LEN;
        }
        if ((payload == nullptr) && (payload_len != 0u)) {
            return IPC_Error::BUFFER_OVERFLOW;
        }

        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        // Serialize frame
        uint8_t frame_buf[IPC_MAX_FRAME_SIZE];
        uint32_t flen = 0u;
        const IPC_Error ser = IPC_Serialize_Frame(
            frame_buf, impl->tx_seq.fetch_add(1u, std::memory_order_relaxed),
            cmd, payload, payload_len, flen);
        if (ser != IPC_Error::OK) {
            return ser;
        }
        if (flen == 0u) {
            return IPC_Error::BUFFER_OVERFLOW;
        }

        // Push to TX ring (RX thread will pick up and send via SPI)
        if (impl->Ring_TX_Push(frame_buf, static_cast<uint16_t>(flen)) != SECURE_TRUE) {
            return IPC_Error::QUEUE_FULL;
        }

        return IPC_Error::OK;
    }

    IPC_Error HTS_IPC_Protocol_A55::Receive_Frame(
        IPC_Command& out_cmd,
        uint8_t* out_payload,
        uint16_t        out_buf_size,
        uint16_t& out_payload_len) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) {
            return IPC_Error::NOT_INITIALIZED;
        }

        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        // Pop from RX ring
        uint8_t raw_buf[IPC_MAX_FRAME_SIZE];
        uint16_t raw_len = 0u;
        if (impl->Ring_RX_Pop(raw_buf, IPC_MAX_FRAME_SIZE, raw_len) != SECURE_TRUE) {
            out_payload_len = 0u;
            return IPC_Error::QUEUE_FULL;  // Ring empty
        }

        // Parse (payload copied into caller buffer by parser)
        uint8_t seq = 0u;
        const IPC_Error err = IPC_Parse_Frame(
            raw_buf, raw_len, seq, out_cmd, out_payload, out_buf_size, out_payload_len);

        if (err != IPC_Error::OK) {
            out_payload_len = 0u;
            return err;
        }

        return IPC_Error::OK;
    }

    IPC_State HTS_IPC_Protocol_A55::Get_State() const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) {
            return IPC_State::UNINITIALIZED;
        }
        const Impl* impl = reinterpret_cast<const Impl*>(impl_buf_);
        return impl->state;
    }

    void HTS_IPC_Protocol_A55::Get_Statistics(IPC_Statistics& out_stats) const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) {
            IPC_Statistics_Reset(out_stats);
            return;
        }
        const Impl* impl = reinterpret_cast<const Impl*>(impl_buf_);
        IPC_Statistics_Copy(impl->stats, out_stats);
    }

    bool HTS_IPC_Protocol_A55::Is_Link_Alive() const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return false; }
        const Impl* impl = reinterpret_cast<const Impl*>(impl_buf_);
        return impl->Is_Heartbeat_Alive(impl->state_entry_tick) == SECURE_TRUE;
    }

    uint32_t HTS_IPC_Protocol_A55::Get_TX_Pending() const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        const Impl* impl = reinterpret_cast<const Impl*>(impl_buf_);
        return impl->Ring_TX_Count();
    }

    uint32_t HTS_IPC_Protocol_A55::Get_RX_Pending() const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        const Impl* impl = reinterpret_cast<const Impl*>(impl_buf_);
        return impl->Ring_RX_Count();
    }

} // namespace ProtectedEngine

#endif // HTS_PLATFORM_AARCH64
