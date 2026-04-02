/// @file  HTS_IPC_Protocol.cpp
/// @brief HTS IPC Protocol Engine -- STM32 SPI Slave Implementation
/// @details
///   Pimpl implementation of HTS_IPC_Protocol for STM32F407VGT6.
///   Register-level SPI slave + DMA setup, lock-free ring buffers,
///   CRC-16 validated framing, CFI state machine, DRDY GPIO signaling.
///
/// @note  ARM-only. No PC/server code. Pure ASCII.
/// @author Lim Young-jun
/// @copyright INNOViD 2026. All rights reserved.
///
/// AIRCR 폴백 전 DBGMCU IWDG/WWDG 프리즈 해제
///   (HTS_Anti_Debug forceHalt Phase 3 동일 — 디버거 STOP 시 IWDG 리셋 보장)

#include "HTS_IPC_Protocol.h"
#include <cstring>    // memset (secure wipe uses volatile loop instead)
#include <atomic>
#include <new>        // placement new
#include <cstddef>

namespace ProtectedEngine {

    namespace {
        /// 스택 프레임/임시 버퍼 종료 시 IPC_Secure_Wipe (Send/Receive/핸들러 공통)
        struct Scoped_IPC_Frame_Wipe final {
            uint8_t* buf;
            uint32_t len;
            explicit Scoped_IPC_Frame_Wipe(uint8_t* b, uint32_t l) noexcept
                : buf(b)
                , len(l)
            {
            }
            ~Scoped_IPC_Frame_Wipe() noexcept { IPC_Secure_Wipe(buf, len); }
            Scoped_IPC_Frame_Wipe(const Scoped_IPC_Frame_Wipe&) = delete;
            Scoped_IPC_Frame_Wipe& operator=(const Scoped_IPC_Frame_Wipe&) = delete;
        };
    } // namespace

    // ============================================================
    //  STM32F407 Register Definitions (constexpr, no magic numbers)
    // ============================================================

    // -- HW Register Access --
    // NOTE: STM32F407 = 32-bit ARM. On 64-bit host (syntax check), uintptr_t
    //       prevents truncation warnings. Actual execution is ARM-only.
    static inline volatile uint32_t& HW_REG(uint32_t addr) noexcept
    {
        return *reinterpret_cast<volatile uint32_t*>(static_cast<uintptr_t>(addr));
    }

    // -- Pointer-to-uint32 for DMA M0AR/PAR registers (32-bit ARM addresses) --
    // On 64-bit host syntax check: explicit truncation via uintptr_t avoids warning.
    // On ARM32: uintptr_t == uint32_t, zero overhead.
    static inline uint32_t PTR_TO_U32(const volatile void* ptr) noexcept
    {
        return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ptr));
    }

    // -- RCC Base & Offsets --
    static constexpr uint32_t RCC_BASE = 0x40023800u;
    static constexpr uint32_t RCC_AHB1ENR_OFF = 0x30u;
    static constexpr uint32_t RCC_APB1ENR_OFF = 0x40u;
    static constexpr uint32_t RCC_APB2ENR_OFF = 0x44u;

    // -- RCC Enable Bits --
    static constexpr uint32_t RCC_AHB1_DMA1EN = (1u << 21u);
    static constexpr uint32_t RCC_AHB1_DMA2EN = (1u << 22u);
    static constexpr uint32_t RCC_APB2_SPI1EN = (1u << 12u);
    static constexpr uint32_t RCC_APB1_SPI2EN = (1u << 14u);
    static constexpr uint32_t RCC_APB1_SPI3EN = (1u << 15u);

    // -- GPIO Bases --
    static constexpr uint32_t GPIO_BASE_ARRAY[6] = {
        0x40020000u,    // GPIOA
        0x40020400u,    // GPIOB
        0x40020800u,    // GPIOC
        0x40020C00u,    // GPIOD
        0x40021000u,    // GPIOE
        0x40021400u     // GPIOF
    };

    // -- GPIO Register Offsets --
    static constexpr uint32_t GPIO_MODER_OFF = 0x00u;
    static constexpr uint32_t GPIO_OTYPER_OFF = 0x04u;
    static constexpr uint32_t GPIO_OSPEEDR_OFF = 0x08u;
    static constexpr uint32_t GPIO_PUPDR_OFF = 0x0Cu;
    static constexpr uint32_t GPIO_BSRR_OFF = 0x18u;
    static constexpr uint32_t GPIO_AFRL_OFF = 0x20u;
    static constexpr uint32_t GPIO_AFRH_OFF = 0x24u;

    // -- SPI Register Offsets --
    static constexpr uint32_t SPI_CR1_OFF = 0x00u;
    static constexpr uint32_t SPI_CR2_OFF = 0x04u;
    static constexpr uint32_t SPI_SR_OFF = 0x08u;
    static constexpr uint32_t SPI_DR_OFF = 0x0Cu;

    // -- SPI CR1 Bits --
    static constexpr uint32_t SPI_CR1_SPE = (1u << 6u);
    static constexpr uint32_t SPI_CR1_MSTR = (1u << 2u);
    static constexpr uint32_t SPI_CR1_SSM = (1u << 9u);

    // -- SPI CR2 Bits --
    static constexpr uint32_t SPI_CR2_TXDMAEN = (1u << 1u);
    static constexpr uint32_t SPI_CR2_RXDMAEN = (1u << 0u);
    static constexpr uint32_t SPI_CR2_ERRIE = (1u << 5u);

    // -- SPI SR Bits --
    static constexpr uint32_t SPI_SR_RXNE = (1u << 0u);
    static constexpr uint32_t SPI_SR_TXE = (1u << 1u);
    static constexpr uint32_t SPI_SR_OVR = (1u << 6u);
    static constexpr uint32_t SPI_SR_BSY = (1u << 7u);

    // -- SPI Peripheral Bases --
    static constexpr uint32_t SPI1_BASE = 0x40013000u;
    static constexpr uint32_t SPI2_BASE = 0x40003800u;
    static constexpr uint32_t SPI3_BASE = 0x40003C00u;

    // -- DMA Bases --
    static constexpr uint32_t DMA1_BASE = 0x40026000u;
    static constexpr uint32_t DMA2_BASE = 0x40026400u;

    // -- DMA Register Offsets (global) --
    static constexpr uint32_t DMA_LISR_OFF = 0x00u;
    static constexpr uint32_t DMA_HISR_OFF = 0x04u;
    static constexpr uint32_t DMA_LIFCR_OFF = 0x08u;
    static constexpr uint32_t DMA_HIFCR_OFF = 0x0Cu;

    // -- DMA Stream Register Offsets (relative to stream base) --
    static constexpr uint32_t DMA_SxCR_OFF = 0x00u;
    static constexpr uint32_t DMA_SxNDTR_OFF = 0x04u;
    static constexpr uint32_t DMA_SxPAR_OFF = 0x08u;
    static constexpr uint32_t DMA_SxM0AR_OFF = 0x0Cu;
    static constexpr uint32_t DMA_SxFCR_OFF = 0x14u;

    // -- DMA SxCR Bits --
    static constexpr uint32_t DMA_SxCR_EN = (1u << 0u);
    static constexpr uint32_t DMA_SxCR_TCIE = (1u << 4u);
    static constexpr uint32_t DMA_SxCR_TEIE = (1u << 2u);
    static constexpr uint32_t DMA_SxCR_DIR_P2M = (0u << 6u);     // Peripheral to Memory
    static constexpr uint32_t DMA_SxCR_DIR_M2P = (1u << 6u);     // Memory to Peripheral
    static constexpr uint32_t DMA_SxCR_MINC = (1u << 10u);
    static constexpr uint32_t DMA_SxCR_PSIZE_8 = (0u << 11u);    // Byte
    static constexpr uint32_t DMA_SxCR_MSIZE_8 = (0u << 13u);    // Byte
    static constexpr uint32_t DMA_SxCR_PL_HIGH = (2u << 16u);    // Priority High

    // -- DMA TCIF bit positions per stream --
    static constexpr uint8_t DMA_TCIF_BIT[8] = { 5u, 11u, 21u, 27u, 5u, 11u, 21u, 27u };

    // -- HW Polling Timeout (systick iterations, not ms) --
    static constexpr uint32_t HW_POLL_TIMEOUT = 10000u;

    // ============================================================
    //  Impl Structure
    // ============================================================

    struct HTS_IPC_Protocol::Impl {
        // --- Configuration ---
        IPC_Config config;

        // --- CFI State Machine ---
        IPC_State state;
        uint32_t  state_entry_tick;

        // --- Sequence Tracking ---
        // tx_seq is atomic: defensive safety against future RTOS/multi-priority usage.
        // Current design: all producers (Queue_ACK, Queue_NACK, Tick_Heartbeat,
        // Send_Frame) run in main loop context only. ISR callbacks set flags only.
        std::atomic<uint8_t> tx_seq;
        uint8_t rx_expected_seq;
        uint8_t pad0_[1];              // Explicit padding for alignment

        // --- Lock-free Ring Buffers (SPSC: ISR<->Main) ---
        IPC_Ring_Entry rx_ring[IPC_RING_DEPTH];     // ISR produces, Main consumes
        IPC_Ring_Entry tx_ring[IPC_RING_DEPTH];     // Main produces, Main/ISR consumes
        std::atomic<uint32_t> rx_head;              // Written by ISR (release)
        std::atomic<uint32_t> rx_tail;              // Written by Main (release)
        std::atomic<uint32_t> tx_head;              // Written by Main (release)
        std::atomic<uint32_t> tx_tail;              // Written by ISR/Main (release)

        // --- SPI DMA Buffers ---
        alignas(4) uint8_t spi_rx_buf[IPC_SPI_DMA_BUF_SIZE];
        alignas(4) uint8_t spi_tx_buf[IPC_SPI_DMA_BUF_SIZE];

        // Static idle buffer: always 0x00, never modified, used for TX DMA idle
        // Prevents SPI underrun while DRDY deasserted (master-initiated transfers)
        alignas(4) uint8_t spi_idle_buf[IPC_SPI_DMA_BUF_SIZE];

        // TX DMA state tracking
        bool tx_dma_has_payload;            ///< true if TX DMA points to real frame

        // --- Heartbeat ---
        uint32_t last_ping_sent_tick;
        uint32_t last_pong_recv_tick;

        // --- Statistics ---
        IPC_Statistics stats;

        // --- ISR Flags (atomic, lock-free) ---
        std::atomic<bool> rx_dma_complete;
        std::atomic<bool> tx_dma_complete;
        std::atomic<bool> spi_error_flag;
        bool drdy_asserted;
        uint8_t pad1_[3];              // Explicit padding

        // --- Computed HW Addresses (cached at init) ---
        uint32_t dma_stream_rx_base;
        uint32_t dma_stream_tx_base;
        uint32_t gpio_drdy_base;

        // ============================================================
        //  Helper: CFI Transition
        // ============================================================
        bool Transition_State(IPC_State target) noexcept
        {
            if (!IPC_Is_Legal_Transition(state, target)) {
                stats.cfi_violations.fetch_add(1u, std::memory_order_relaxed);
                state = IPC_State::ERROR_RECOVERY;
                return false;
            }
            state = target;
            return true;
        }

        // ============================================================
        //  Helper: DRDY GPIO Control
        // ============================================================
        void Assert_DRDY() noexcept
        {
            if (config.drdy_port_index >= 6u) { return; }
            if (config.drdy_pin > 15u) { return; }
            const uint32_t bsrr_addr = gpio_drdy_base + GPIO_BSRR_OFF;
            HW_REG(bsrr_addr) = (1u << config.drdy_pin);  // Set pin
            drdy_asserted = true;
        }

        void Deassert_DRDY() noexcept
        {
            if (config.drdy_port_index >= 6u) { return; }
            if (config.drdy_pin > 15u) { return; }
            const uint32_t bsrr_addr = gpio_drdy_base + GPIO_BSRR_OFF;
            HW_REG(bsrr_addr) = (1u << (config.drdy_pin + 16u));  // Reset pin
            drdy_asserted = false;
        }

        // ============================================================
        //  Helper: DMA Stream Address Computation
        // ============================================================
        static uint32_t Compute_Stream_Base(uint32_t dma_base, uint8_t stream) noexcept
        {
            // Stream registers start at offset 0x10, each stream = 0x18 bytes
            return dma_base + 0x10u + (static_cast<uint32_t>(stream) * 0x18u);
        }

        // ============================================================
        //  Helper: Clear DMA Interrupt Flags
        // ============================================================
        void Clear_DMA_Flags(uint8_t stream) const noexcept
        {
            // Streams 0-3 use LIFCR, streams 4-7 use HIFCR
            const uint32_t fcr_off = (stream < 4u) ? DMA_LIFCR_OFF : DMA_HIFCR_OFF;
            // All interrupt flags for the stream (TCIF + HTIF + TEIF + DMEIF + FEIF)
            // Bit positions: TCIF at DMA_TCIF_BIT[stream],
            //   HTIF = TCIF-1, TEIF = TCIF-2, DMEIF = TCIF-3, FEIF = TCIF-4 (for streams 0,4)
            //   or shifted pattern for other streams
            uint32_t shift;
            const uint8_t stream_in_half = stream & 3u;
            switch (stream_in_half) {
            case 0u: shift = 0u;  break;
            case 1u: shift = 6u;  break;
            case 2u: shift = 16u; break;
            case 3u: shift = 22u; break;
            default: return;  // Unreachable
            }
            // Clear all 5 flags: bits [shift+5 : shift+0] = 0x3F << shift
            HW_REG(config.dma_base_addr + fcr_off) = (0x3Du << shift);
        }

        // ============================================================
        //  HW Init: Enable RCC Clocks
        // ============================================================
        void Enable_Clocks() const noexcept
        {
            // GPIO clock (port for DRDY + SPI pins)
            if (config.drdy_port_index < 6u) {
                HW_REG(RCC_BASE + RCC_AHB1ENR_OFF) |= (1u << config.drdy_port_index);
            }

            // DMA clock
            if (config.dma_base_addr == DMA1_BASE) {
                HW_REG(RCC_BASE + RCC_AHB1ENR_OFF) |= RCC_AHB1_DMA1EN;
            }
            else if (config.dma_base_addr == DMA2_BASE) {
                HW_REG(RCC_BASE + RCC_AHB1ENR_OFF) |= RCC_AHB1_DMA2EN;
            }

            // SPI clock
            if (config.spi_base_addr == SPI1_BASE) {
                HW_REG(RCC_BASE + RCC_APB2ENR_OFF) |= RCC_APB2_SPI1EN;
                // SPI1 pins on GPIOA: enable GPIOA clock
                HW_REG(RCC_BASE + RCC_AHB1ENR_OFF) |= (1u << 0u);
            }
            else if (config.spi_base_addr == SPI2_BASE) {
                HW_REG(RCC_BASE + RCC_APB1ENR_OFF) |= RCC_APB1_SPI2EN;
                // SPI2 pins on GPIOB: enable GPIOB clock
                HW_REG(RCC_BASE + RCC_AHB1ENR_OFF) |= (1u << 1u);
            }
            else if (config.spi_base_addr == SPI3_BASE) {
                HW_REG(RCC_BASE + RCC_APB1ENR_OFF) |= RCC_APB1_SPI3EN;
                // SPI3 pins on GPIOB: enable GPIOB clock
                HW_REG(RCC_BASE + RCC_AHB1ENR_OFF) |= (1u << 1u);
            }

            // Brief delay for clock stabilization (4 AHB cycles)
            volatile uint32_t dummy = HW_REG(RCC_BASE + RCC_AHB1ENR_OFF);
            (void)dummy;
        }

        // ============================================================
        //  HW Init: Configure GPIO for SPI AF + DRDY Output
        // ============================================================
        void Configure_GPIO() const noexcept
        {
            // --- SPI Pin Configuration ---
            // SPI1: PA4(NSS), PA5(SCK), PA6(MISO), PA7(MOSI) - AF5
            // SPI2: PB12(NSS), PB13(SCK), PB14(MISO), PB15(MOSI) - AF5
            // SPI3: PA15(NSS), PB3(SCK), PB4(MISO), PB5(MOSI) - AF6

            uint32_t gpio_base = 0u;
            uint8_t  pins[4] = { 0u, 0u, 0u, 0u };  // NSS, SCK, MISO, MOSI
            uint8_t  af_num = 5u;
            uint32_t pin_count = 4u;

            if (config.spi_base_addr == SPI1_BASE) {
                gpio_base = GPIO_BASE_ARRAY[0];     // GPIOA
                pins[0] = 4u; pins[1] = 5u; pins[2] = 6u; pins[3] = 7u;
                af_num = 5u;
                pin_count = 4u;
            }
            else if (config.spi_base_addr == SPI2_BASE) {
                gpio_base = GPIO_BASE_ARRAY[1];     // GPIOB
                pins[0] = 12u; pins[1] = 13u; pins[2] = 14u; pins[3] = 15u;
                af_num = 5u;
                pin_count = 4u;
            }
            else if (config.spi_base_addr == SPI3_BASE) {
                // SPI3 split: PA15(NSS) on GPIOA, PB3(SCK)/PB4(MISO)/PB5(MOSI) on GPIOB
                Configure_Pin_AF(GPIO_BASE_ARRAY[0], 15u, 6u);  // PA15 NSS
                gpio_base = GPIO_BASE_ARRAY[1];     // GPIOB for SCK/MISO/MOSI
                pins[0] = 3u; pins[1] = 4u; pins[2] = 5u;
                af_num = 6u;
                pin_count = 3u;
            }

            if (gpio_base != 0u) {
                for (uint32_t i = 0u; i < pin_count; ++i) {
                    Configure_Pin_AF(gpio_base, pins[i], af_num);
                }
            }

            // --- DRDY Pin: Output Push-Pull, High Speed ---
            if (config.drdy_port_index < 6u && config.drdy_pin <= 15u) {
                const uint32_t drdy_base = GPIO_BASE_ARRAY[config.drdy_port_index];
                const uint32_t pin = config.drdy_pin;

                // MODER: Output (01)
                uint32_t moder = HW_REG(drdy_base + GPIO_MODER_OFF);
                moder &= ~(3u << (pin << 1u));          // Clear 2 bits
                moder |= (1u << (pin << 1u));           // Set output mode
                HW_REG(drdy_base + GPIO_MODER_OFF) = moder;

                // OTYPER: Push-Pull (0)
                HW_REG(drdy_base + GPIO_OTYPER_OFF) &= ~(1u << pin);

                // OSPEEDR: High Speed (10)
                uint32_t ospeed = HW_REG(drdy_base + GPIO_OSPEEDR_OFF);
                ospeed &= ~(3u << (pin << 1u));
                ospeed |= (2u << (pin << 1u));
                HW_REG(drdy_base + GPIO_OSPEEDR_OFF) = ospeed;

                // PUPDR: No pull (00)
                HW_REG(drdy_base + GPIO_PUPDR_OFF) &= ~(3u << (pin << 1u));

                // Start deasserted
                HW_REG(drdy_base + GPIO_BSRR_OFF) = (1u << (pin + 16u));
            }
        }

        // ============================================================
        //  Helper: Configure Single GPIO Pin as Alternate Function
        // ============================================================
        static void Configure_Pin_AF(uint32_t gpio_base, uint8_t pin, uint8_t af) noexcept
        {
            if (pin > 15u) { return; }

            // MODER: AF mode (10)
            uint32_t moder = HW_REG(gpio_base + GPIO_MODER_OFF);
            moder &= ~(3u << (static_cast<uint32_t>(pin) << 1u));
            moder |= (2u << (static_cast<uint32_t>(pin) << 1u));
            HW_REG(gpio_base + GPIO_MODER_OFF) = moder;

            // OSPEEDR: Very High Speed (11)
            uint32_t ospeed = HW_REG(gpio_base + GPIO_OSPEEDR_OFF);
            ospeed &= ~(3u << (static_cast<uint32_t>(pin) << 1u));
            ospeed |= (3u << (static_cast<uint32_t>(pin) << 1u));
            HW_REG(gpio_base + GPIO_OSPEEDR_OFF) = ospeed;

            // PUPDR: No pull (00)
            HW_REG(gpio_base + GPIO_PUPDR_OFF) &= ~(3u << (static_cast<uint32_t>(pin) << 1u));

            // AF register: AFRL (pin 0~7) or AFRH (pin 8~15)
            const uint32_t af_off = (pin < 8u) ? GPIO_AFRL_OFF : GPIO_AFRH_OFF;
            const uint32_t af_pos = (static_cast<uint32_t>(pin) & 7u) << 2u;  // 4 bits per pin
            uint32_t afr = HW_REG(gpio_base + af_off);
            afr &= ~(0xFu << af_pos);
            afr |= (static_cast<uint32_t>(af) << af_pos);
            HW_REG(gpio_base + af_off) = afr;
        }

        // ============================================================
        //  HW Init: Configure SPI Slave (SPE deferred until DMA ready)
        // ============================================================
        void Configure_SPI_Slave() const noexcept
        {
            const uint32_t spi = config.spi_base_addr;

            // Disable SPI before configuration
            HW_REG(spi + SPI_CR1_OFF) &= ~SPI_CR1_SPE;

            // CR1: Slave mode, 8-bit, CPOL=0, CPHA=0, SSM disabled (hardware NSS)
            // MSTR=0 (slave), DFF=0 (8-bit), LSBFIRST=0 (MSB first)
            HW_REG(spi + SPI_CR1_OFF) = 0u;  // All defaults = slave, 8-bit, Mode 0

            // CR2: Enable DMA TX/RX, enable error interrupt
            HW_REG(spi + SPI_CR2_OFF) = SPI_CR2_RXDMAEN | SPI_CR2_TXDMAEN | SPI_CR2_ERRIE;

            // NOTE: SPE is NOT enabled here.
            // DMA must be fully armed before SPE=1, otherwise TXE fires
            // and DMA prefetches stale data from an uninitialized buffer.
            // Caller must call Enable_SPI() after Configure_DMA().
        }

        // ============================================================
        //  HW: Enable / Disable SPI
        // ============================================================
        void Enable_SPI() const noexcept
        {
            HW_REG(config.spi_base_addr + SPI_CR1_OFF) |= SPI_CR1_SPE;
        }

        void Disable_SPI() const noexcept
        {
            // Wait until not busy, then disable
            uint32_t timeout = HW_POLL_TIMEOUT;
            while (((HW_REG(config.spi_base_addr + SPI_SR_OFF) & SPI_SR_BSY) != 0u)
                && (timeout > 0u))
            {
                --timeout;
            }
            HW_REG(config.spi_base_addr + SPI_CR1_OFF) &= ~SPI_CR1_SPE;
        }

        // ============================================================
        //  HW: Flush SPI DR FIFO (drain residual prefetch data)
        // ============================================================
        void Flush_SPI_DR() const noexcept
        {
            const uint32_t spi = config.spi_base_addr;
            // Read SR to check flags, then read DR to drain FIFO
            // Repeat until RXNE is clear (handles multi-byte FIFO)
            volatile uint32_t dummy;
            uint32_t guard = 16u;  // Max 16 reads (STM32F4 has 1-byte DR, but be safe)
            while (guard > 0u) {
                const uint32_t sr = HW_REG(spi + SPI_SR_OFF);
                if ((sr & SPI_SR_RXNE) == 0u) { break; }
                dummy = HW_REG(spi + SPI_DR_OFF);
                (void)dummy;
                --guard;
            }
            // Also clear OVR flag: read SR then DR
            dummy = HW_REG(spi + SPI_SR_OFF);
            dummy = HW_REG(spi + SPI_DR_OFF);
            (void)dummy;
        }

        // ============================================================
        //  HW Init: Configure DMA Streams
        // ============================================================
        void Configure_DMA() noexcept
        {
            const uint32_t spi_dr = config.spi_base_addr + SPI_DR_OFF;
            const uint32_t ch_sel = static_cast<uint32_t>(config.dma_channel) << 25u;

            // --- RX DMA Stream (Peripheral -> Memory) ---
            {
                const uint32_t s = dma_stream_rx_base;

                // Disable stream first
                HW_REG(s + DMA_SxCR_OFF) &= ~DMA_SxCR_EN;
                Wait_DMA_Disabled(s);

                Clear_DMA_Flags(config.dma_stream_rx);

                HW_REG(s + DMA_SxPAR_OFF) = spi_dr;
                HW_REG(s + DMA_SxM0AR_OFF) = PTR_TO_U32(spi_rx_buf);
                HW_REG(s + DMA_SxNDTR_OFF) = IPC_SPI_DMA_BUF_SIZE;

                // CR: Channel select, P2M, byte size, memory increment, high priority,
                //     transfer complete + error interrupt enable
                HW_REG(s + DMA_SxCR_OFF) = ch_sel
                    | DMA_SxCR_DIR_P2M
                    | DMA_SxCR_PSIZE_8
                    | DMA_SxCR_MSIZE_8
                    | DMA_SxCR_MINC
                    | DMA_SxCR_PL_HIGH
                    | DMA_SxCR_TCIE
                    | DMA_SxCR_TEIE;

                // Disable FIFO (direct mode)
                HW_REG(s + DMA_SxFCR_OFF) = 0u;

                // Enable stream
                HW_REG(s + DMA_SxCR_OFF) |= DMA_SxCR_EN;
            }

            // --- TX DMA Stream (Memory -> Peripheral) ---
            // Points to spi_idle_buf (permanent zeros) for idle state.
            // Pump_TX() will re-point to spi_tx_buf when real data is available.
            {
                const uint32_t s = dma_stream_tx_base;

                // Disable stream first
                HW_REG(s + DMA_SxCR_OFF) &= ~DMA_SxCR_EN;
                Wait_DMA_Disabled(s);

                Clear_DMA_Flags(config.dma_stream_tx);

                HW_REG(s + DMA_SxPAR_OFF) = spi_dr;
                HW_REG(s + DMA_SxM0AR_OFF) = PTR_TO_U32(spi_idle_buf);
                HW_REG(s + DMA_SxNDTR_OFF) = IPC_SPI_DMA_BUF_SIZE;

                // CR: Channel select, M2P, byte size, memory increment, high priority,
                //     transfer complete + error interrupt enable
                HW_REG(s + DMA_SxCR_OFF) = ch_sel
                    | DMA_SxCR_DIR_M2P
                    | DMA_SxCR_PSIZE_8
                    | DMA_SxCR_MSIZE_8
                    | DMA_SxCR_MINC
                    | DMA_SxCR_PL_HIGH
                    | DMA_SxCR_TCIE
                    | DMA_SxCR_TEIE;

                // Disable FIFO (direct mode)
                HW_REG(s + DMA_SxFCR_OFF) = 0u;

                // Enable stream -- DMA prefetches idle_buf[0]=0x00 (harmless)
                HW_REG(s + DMA_SxCR_OFF) |= DMA_SxCR_EN;
            }

            tx_dma_has_payload = false;
        }

        // ============================================================
        //  Helper: Wait for DMA Stream Disabled (with timeout)
        // ============================================================
        static void Wait_DMA_Disabled(uint32_t stream_base) noexcept
        {
            uint32_t timeout = HW_POLL_TIMEOUT;
            while (((HW_REG(stream_base + DMA_SxCR_OFF) & DMA_SxCR_EN) != 0u)
                && (timeout > 0u))
            {
                --timeout;
            }
            // If timeout expires, proceed anyway (best-effort recovery)
        }

        // ============================================================
        //  Re-arm DMA for Next Transfer
        // ============================================================
        void Rearm_DMA() noexcept
        {
            // --- Disable both streams ---
            HW_REG(dma_stream_rx_base + DMA_SxCR_OFF) &= ~DMA_SxCR_EN;
            HW_REG(dma_stream_tx_base + DMA_SxCR_OFF) &= ~DMA_SxCR_EN;
            Wait_DMA_Disabled(dma_stream_rx_base);
            Wait_DMA_Disabled(dma_stream_tx_base);

            // --- Clear flags ---
            Clear_DMA_Flags(config.dma_stream_rx);
            Clear_DMA_Flags(config.dma_stream_tx);

            // --- Flush SPI DR to remove any stale byte from TX FIFO ---
            Flush_SPI_DR();

            // --- Re-arm RX DMA (always) ---
            HW_REG(dma_stream_rx_base + DMA_SxM0AR_OFF) = PTR_TO_U32(spi_rx_buf);
            HW_REG(dma_stream_rx_base + DMA_SxNDTR_OFF) = IPC_SPI_DMA_BUF_SIZE;
            HW_REG(dma_stream_rx_base + DMA_SxCR_OFF) |= DMA_SxCR_EN;

            // --- Re-arm TX DMA ---
            // CRITICAL: Data must be in the buffer BEFORE DMA Enable.
            //   SPI TXE fires as soon as DMA is enabled, causing DMA to
            //   prefetch M0AR[0] into SPI DR immediately. If we point to
            //   a buffer that was written AFTER enable, the first byte
            //   is stale -> 1-byte frame shift -> 100% CRC failure.
            const uint32_t th = tx_head.load(std::memory_order_acquire);
            const uint32_t tt = tx_tail.load(std::memory_order_relaxed);
            if (th != tt) {
                // Copy next TX frame to SPI buffer (data written FIRST)
                const IPC_Ring_Entry& entry =
                    tx_ring[static_cast<size_t>(tt & IPC_RING_MASK)];
                for (uint32_t i = 0u; i < entry.length; ++i) {
                    const size_t ii = static_cast<size_t>(i);
                    spi_tx_buf[ii] = entry.data[ii];
                }
                for (uint32_t i = entry.length; i < IPC_SPI_DMA_BUF_SIZE; ++i) {
                    spi_tx_buf[static_cast<size_t>(i)] = 0x00u;
                }
                tx_tail.store(tt + 1u, std::memory_order_release);
                stats.tx_frames.fetch_add(1u, std::memory_order_relaxed);

                // Point DMA to spi_tx_buf (valid data), THEN enable
                HW_REG(dma_stream_tx_base + DMA_SxM0AR_OFF) = PTR_TO_U32(spi_tx_buf);
                HW_REG(dma_stream_tx_base + DMA_SxNDTR_OFF) = IPC_SPI_DMA_BUF_SIZE;
                HW_REG(dma_stream_tx_base + DMA_SxCR_OFF) |= DMA_SxCR_EN;
                tx_dma_has_payload = true;
                Assert_DRDY();
            }
            else {
                // No pending TX: point DMA to permanent-zero idle buffer
                // DMA prefetches 0x00 from idle_buf -> harmless if master
                // clocks while DRDY deasserted (slave sends all-zero)
                HW_REG(dma_stream_tx_base + DMA_SxM0AR_OFF) = PTR_TO_U32(spi_idle_buf);
                HW_REG(dma_stream_tx_base + DMA_SxNDTR_OFF) = IPC_SPI_DMA_BUF_SIZE;
                HW_REG(dma_stream_tx_base + DMA_SxCR_OFF) |= DMA_SxCR_EN;
                tx_dma_has_payload = false;
                Deassert_DRDY();
            }
        }

        // ============================================================
        //  Ring Buffer Helpers
        // ============================================================

        /// @brief Push received frame into RX ring (main loop: Tick → Process_RX_Frame)
        /// @return true on success, false if ring full
        bool Ring_RX_Push(const uint8_t* data, uint16_t len) noexcept
        {
            const uint32_t head = rx_head.load(std::memory_order_relaxed);
            const uint32_t tail = rx_tail.load(std::memory_order_acquire);
            if ((head - tail) >= IPC_RING_DEPTH) {
                stats.queue_overflows.fetch_add(1u, std::memory_order_relaxed);
                return false;
            }
            IPC_Ring_Entry& entry =
                rx_ring[static_cast<size_t>(head & IPC_RING_MASK)];
            const uint32_t copy_len = (len <= IPC_MAX_FRAME_SIZE) ? len : IPC_MAX_FRAME_SIZE;
            for (uint32_t i = 0u; i < copy_len; ++i) {
                const size_t ii = static_cast<size_t>(i);
                entry.data[ii] = data[ii];
            }
            entry.length = static_cast<uint16_t>(copy_len);
            rx_head.store(head + 1u, std::memory_order_release);
            return true;
        }

        /// @brief Pop frame from RX ring (Main context)
        /// @return true if frame available
        bool Ring_RX_Pop(uint8_t* data, uint16_t buf_size, uint16_t& out_len) noexcept
        {
            const uint32_t head = rx_head.load(std::memory_order_acquire);
            const uint32_t tail = rx_tail.load(std::memory_order_relaxed);
            if (head == tail) {
                out_len = 0u;
                return false;
            }
            const IPC_Ring_Entry& entry =
                rx_ring[static_cast<size_t>(tail & IPC_RING_MASK)];
            const uint16_t copy_len = (entry.length <= buf_size) ? entry.length : buf_size;
            if (data != nullptr) {
                for (uint16_t i = 0u; i < copy_len; ++i) {
                    const size_t ii = static_cast<size_t>(i);
                    data[ii] = entry.data[ii];
                }
            }
            out_len = copy_len;
            rx_tail.store(tail + 1u, std::memory_order_release);
            return true;
        }

        /// @brief Push frame into TX ring (SPSC: main loop context only)
        /// @return true on success, false if ring full
        /// @note  All callers (Send_Frame, Queue_ACK, Queue_NACK, Tick_Heartbeat)
        ///        execute in main loop. ISR callbacks only set atomic flags.
        ///        No spinlock needed on single-core Cortex-M4.
        bool Ring_TX_Push(const uint8_t* data, uint16_t len) noexcept
        {
            const uint32_t head = tx_head.load(std::memory_order_relaxed);
            const uint32_t tail = tx_tail.load(std::memory_order_acquire);
            if ((head - tail) >= IPC_RING_DEPTH) {
                stats.queue_overflows.fetch_add(1u, std::memory_order_relaxed);
                return false;
            }
            IPC_Ring_Entry& entry =
                tx_ring[static_cast<size_t>(head & IPC_RING_MASK)];
            const uint32_t copy_len = (len <= IPC_MAX_FRAME_SIZE) ? len : IPC_MAX_FRAME_SIZE;
            for (uint32_t i = 0u; i < copy_len; ++i) {
                const size_t ii = static_cast<size_t>(i);
                entry.data[ii] = data[ii];
            }
            entry.length = static_cast<uint16_t>(copy_len);
            tx_head.store(head + 1u, std::memory_order_release);
            return true;
        }

        /// @brief Get number of entries in RX ring
        uint32_t Ring_RX_Count() const noexcept
        {
            return rx_head.load(std::memory_order_acquire) -
                rx_tail.load(std::memory_order_relaxed);
        }

        /// @brief Get number of entries in TX ring
        uint32_t Ring_TX_Count() const noexcept
        {
            return tx_head.load(std::memory_order_acquire) -
                tx_tail.load(std::memory_order_relaxed);
        }

        // ============================================================
        //  Process Received Frame
        // ============================================================
        void Process_RX_Frame() noexcept
        {
            uint8_t         payload_scratch[IPC_MAX_PAYLOAD];
            uint8_t         seq = 0u;
            IPC_Command     cmd = IPC_Command::PING;
            uint16_t        payload_len = 0u;

            // Parse and validate (payload copied into scratch, isolated from DMA wire buffer)
            const IPC_Error err = IPC_Parse_Frame(
                spi_rx_buf, IPC_SPI_DMA_BUF_SIZE, seq, cmd,
                payload_scratch, static_cast<uint16_t>(sizeof(payload_scratch)), payload_len);

            if (err != IPC_Error::OK) {
                IPC_Secure_Wipe(payload_scratch, sizeof(payload_scratch));
                // Check if it's just an idle/padding frame (all zeros)
                if (spi_rx_buf[static_cast<size_t>(0u)] == 0u
                    && spi_rx_buf[static_cast<size_t>(1u)] == 0u) {
                    // Idle frame from master, ignore silently
                    return;
                }
                if (err == IPC_Error::CRC_MISMATCH) {
                    stats.crc_errors.fetch_add(1u, std::memory_order_relaxed);
                }
                // Send NACK if frame had valid sync but bad CRC/length
                if (IPC_Deserialize_U16(&spi_rx_buf[static_cast<size_t>(0u)])
                    == IPC_SYNC_WORD) {
                    Queue_NACK(static_cast<uint8_t>(err));
                }
                return;
            }

            stats.rx_frames.fetch_add(1u, std::memory_order_relaxed);

            // Command dispatch
            switch (cmd) {
            case IPC_Command::PING:
                Handle_Ping(seq);
                break;

            case IPC_Command::PONG:
                Handle_Pong(seq);
                break;

            case IPC_Command::ACK:
            case IPC_Command::NACK:
                // ACK/NACK from master: update tracking (future: retry logic)
                break;

            case IPC_Command::DATA_TX:
            case IPC_Command::DATA_TX_BURST:
            case IPC_Command::CONFIG_SET:
            case IPC_Command::CONFIG_GET:
            case IPC_Command::STATUS_REQ:
            case IPC_Command::DIAG_REQ:
            case IPC_Command::BPS_NOTIFY:
            case IPC_Command::RESET_CMD:
                // Push to RX ring for main-loop processing
                Ring_RX_Push(spi_rx_buf, static_cast<uint16_t>(
                    IPC_HEADER_SIZE + static_cast<uint32_t>(payload_len) + IPC_CRC_SIZE));
                // ACK the command
                Queue_ACK(seq);
                break;

            case IPC_Command::KILL_SWITCH:
                IPC_Secure_Wipe(payload_scratch, sizeof(payload_scratch));
                // Emergency: immediate handling, no ring buffer
                Handle_Kill_Switch();
                break;

            default:
                stats.crc_errors.fetch_add(1u, std::memory_order_relaxed);  // Reuse counter for invalid commands
                Queue_NACK(static_cast<uint8_t>(IPC_Error::INVALID_CMD));
                break;
            }

            IPC_Secure_Wipe(payload_scratch, sizeof(payload_scratch));
        }

        // ============================================================
        //  Command Handlers
        // ============================================================

        void Handle_Ping(uint8_t seq) noexcept
        {
            // Respond with PONG (same seq)
            uint8_t frame_buf[IPC_HEADER_SIZE + IPC_CRC_SIZE];
            const Scoped_IPC_Frame_Wipe wipe_frame(
                frame_buf, static_cast<uint32_t>(sizeof(frame_buf)));
            uint32_t flen = 0u;
            if (IPC_Serialize_Frame(
                    frame_buf, seq, IPC_Command::PONG, nullptr, 0u, flen) == IPC_Error::OK
                && flen > 0u) {
                Ring_TX_Push(frame_buf, static_cast<uint16_t>(flen));
            }
        }

        void Handle_Pong(uint8_t /*seq*/) noexcept
        {
            // Update heartbeat timestamp (set by Tick caller via state_entry_tick)
            last_pong_recv_tick = state_entry_tick;  // Will be updated in next Tick
        }

        void Queue_ACK(uint8_t seq) noexcept
        {
            uint8_t frame_buf[IPC_HEADER_SIZE + IPC_CRC_SIZE];
            const Scoped_IPC_Frame_Wipe wipe_frame(
                frame_buf, static_cast<uint32_t>(sizeof(frame_buf)));
            uint32_t flen = 0u;
            if (IPC_Serialize_Frame(
                    frame_buf, seq, IPC_Command::ACK, nullptr, 0u, flen) == IPC_Error::OK
                && flen > 0u) {
                Ring_TX_Push(frame_buf, static_cast<uint16_t>(flen));
            }
        }

        void Queue_NACK(uint8_t error_code) noexcept
        {
            uint8_t frame_buf[IPC_HEADER_SIZE + 1u + IPC_CRC_SIZE];
            const Scoped_IPC_Frame_Wipe wipe_frame(
                frame_buf, static_cast<uint32_t>(sizeof(frame_buf)));
            uint32_t flen = 0u;
            if (IPC_Serialize_Frame(
                    frame_buf, tx_seq.fetch_add(1u, std::memory_order_relaxed),
                    IPC_Command::NACK, &error_code, 1u, flen) == IPC_Error::OK
                && flen > 0u) {
                Ring_TX_Push(frame_buf, static_cast<uint16_t>(flen));
            }
        }

        void Handle_Kill_Switch() noexcept
        {
            // Emergency shutdown: secure wipe + system reset
            IPC_Secure_Wipe(spi_rx_buf, IPC_SPI_DMA_BUF_SIZE);
            IPC_Secure_Wipe(spi_tx_buf, IPC_SPI_DMA_BUF_SIZE);
            std::atomic_thread_fence(std::memory_order_release);

            // Trigger system reset via AIRCR
            static constexpr uint32_t SCB_AIRCR = 0xE000ED0Cu;
            static constexpr uint32_t AIRCR_VECTKEY = 0x05FA0000u;
            static constexpr uint32_t AIRCR_SYSRESET = (1u << 2u);
            HW_REG(SCB_AIRCR) = AIRCR_VECTKEY | AIRCR_SYSRESET;

#if defined(__GNUC__) || defined(__clang__)
            // DBGMCU IWDG/WWDG 프리즈 해제 — AIRCR 리셋 지연 시 IWDG가 WDT 리셋을 보장
            // HTS_Anti_Debug.h / Phase 3와 동일 (DBGMCU_APB1_FZ @ 0xE0042008, bit11·12)
            static constexpr uint32_t ADDR_DBGMCU_FZ = 0xE0042008u;
            static constexpr uint32_t DBGMCU_WWDG_STOP = (1u << 11);
            static constexpr uint32_t DBGMCU_IWDG_STOP = (1u << 12);
            volatile uint32_t* const dbgmcu_fz =
                reinterpret_cast<volatile uint32_t*>(
                    static_cast<uintptr_t>(ADDR_DBGMCU_FZ));
            *dbgmcu_fz &= ~(DBGMCU_WWDG_STOP | DBGMCU_IWDG_STOP);
            __asm__ __volatile__("dsb sy\n\t" "isb\n\t" ::: "memory");
#endif

            // Should not reach here; infinite loop as fallback
            for (;;) {
#if defined(__GNUC__) || defined(__clang__)
                __asm__ __volatile__("nop");
#endif
            }
        }

        // ============================================================
        //  Heartbeat Management
        // ============================================================
        void Tick_Heartbeat(uint32_t now_ms) noexcept
        {
            if (config.ping_interval_ms == 0u) { return; }

            // Send PING if interval elapsed
            const uint32_t elapsed = now_ms - last_ping_sent_tick;
            if (elapsed >= config.ping_interval_ms) {
                uint8_t frame_buf[IPC_HEADER_SIZE + IPC_CRC_SIZE];
                const Scoped_IPC_Frame_Wipe wipe_frame(
                    frame_buf, static_cast<uint32_t>(sizeof(frame_buf)));
                uint32_t flen = 0u;
                if (IPC_Serialize_Frame(
                        frame_buf, tx_seq.fetch_add(1u, std::memory_order_relaxed),
                        IPC_Command::PING, nullptr, 0u, flen) == IPC_Error::OK
                    && flen > 0u) {
                    Ring_TX_Push(frame_buf, static_cast<uint16_t>(flen));
                }
                last_ping_sent_tick = now_ms;
            }
        }

        bool Is_Heartbeat_Alive(uint32_t now_ms) const noexcept
        {
            if (config.ping_interval_ms == 0u) { return true; }  // Disabled = always alive
            const uint32_t dead_threshold = config.ping_interval_ms * 3u;
            return (now_ms - last_pong_recv_tick) < dead_threshold;
        }

        // ============================================================
        //  TX Pump: If DRDY not asserted and TX ring has data, trigger next send
        // ============================================================
        void Pump_TX() noexcept
        {
            if (drdy_asserted) { return; }  // Transfer in progress

            const uint32_t th = tx_head.load(std::memory_order_acquire);
            const uint32_t tt = tx_tail.load(std::memory_order_relaxed);
            if (th == tt) { return; }  // Nothing to send

            // --- CRITICAL: SPI Slave DMA TX Pre-fetch Race Prevention ---
            //
            // Root cause (STM32F4 SPI slave + DMA):
            //   In idle state, TX DMA is enabled pointing to spi_idle_buf (all-zero).
            //   SPI TXE fires immediately, so DMA pre-fetches idle_buf[0]=0x00 into
            //   the SPI TX buffer (DR write side). This byte sits in the TX FIFO.
            //
            //   If we just overwrite spi_tx_buf and re-point DMA, the first byte
            //   transmitted to master is still the stale 0x00 from the TX FIFO.
            //   -> 1-byte frame shift -> 100% CRC failure.
            //
            // Fix: SPI SPE reset (only way to flush TX FIFO on STM32F4).
            //   DRDY is deasserted here, so master MUST NOT be clocking.
            //   Brief SPI disable is safe in this protocol state.
            //
            // Sequence:
            //   Disable DMA TX+RX -> Disable SPI -> Write buffer ->
            //   Re-arm DMA TX(data)+RX -> Enable SPI -> Enable DMA -> DRDY
            //
            // After SPI re-enable: TXE fires, DMA prefetches spi_tx_buf[0] = correct.

            const uint32_t spi = config.spi_base_addr;

            // 1) Disable both DMA streams (SPI reset invalidates all DMA state)
            HW_REG(dma_stream_tx_base + DMA_SxCR_OFF) &= ~DMA_SxCR_EN;
            HW_REG(dma_stream_rx_base + DMA_SxCR_OFF) &= ~DMA_SxCR_EN;
            Wait_DMA_Disabled(dma_stream_tx_base);
            Wait_DMA_Disabled(dma_stream_rx_base);
            Clear_DMA_Flags(config.dma_stream_tx);
            Clear_DMA_Flags(config.dma_stream_rx);

            // 2) Disable SPI -- flushes TX shift register + TX buffer (DR write side)
            //    RM0090: clearing SPE resets the SPI slave state machine entirely.
            HW_REG(spi + SPI_CR1_OFF) &= ~SPI_CR1_SPE;

            // 3) Write frame data into spi_tx_buf (SPI off, no prefetch possible)
            const IPC_Ring_Entry& entry =
                tx_ring[static_cast<size_t>(tt & IPC_RING_MASK)];
            for (uint32_t i = 0u; i < entry.length; ++i) {
                const size_t ii = static_cast<size_t>(i);
                spi_tx_buf[ii] = entry.data[ii];
            }
            for (uint32_t i = entry.length; i < IPC_SPI_DMA_BUF_SIZE; ++i) {
                spi_tx_buf[static_cast<size_t>(i)] = 0x00u;
            }
            tx_tail.store(tt + 1u, std::memory_order_release);
            stats.tx_frames.fetch_add(1u, std::memory_order_relaxed);

            // 4) Re-arm TX DMA -> spi_tx_buf (valid data already in place)
            HW_REG(dma_stream_tx_base + DMA_SxM0AR_OFF) = PTR_TO_U32(spi_tx_buf);
            HW_REG(dma_stream_tx_base + DMA_SxNDTR_OFF) = IPC_SPI_DMA_BUF_SIZE;

            // 5) Re-arm RX DMA (SPI reset cleared RX state too)
            HW_REG(dma_stream_rx_base + DMA_SxM0AR_OFF) = PTR_TO_U32(spi_rx_buf);
            HW_REG(dma_stream_rx_base + DMA_SxNDTR_OFF) = IPC_SPI_DMA_BUF_SIZE;

            // 6) Enable DMA streams BEFORE SPI re-enable
            //    (DMA must be ready when SPI fires TXE after SPE=1)
            HW_REG(dma_stream_tx_base + DMA_SxCR_OFF) |= DMA_SxCR_EN;
            HW_REG(dma_stream_rx_base + DMA_SxCR_OFF) |= DMA_SxCR_EN;

            // 7) Re-enable SPI -- TXE fires -> DMA prefetches spi_tx_buf[0] = CORRECT
            HW_REG(spi + SPI_CR1_OFF) |= SPI_CR1_SPE;

            tx_dma_has_payload = true;

            // 8) Signal master: data ready to clock out
            Assert_DRDY();
        }
    };

    // ============================================================
    //  Public API Implementation
    // ============================================================

    HTS_IPC_Protocol::HTS_IPC_Protocol() noexcept
        : initialized_{ false }
    {
        // Build-time verification: Impl fits in IMPL_BUF_SIZE
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "HTS_IPC_Protocol::Impl exceeds IMPL_BUF_SIZE -- "
            "increase buffer or reduce ring depth / payload size");

        // Zero-fill impl buffer (deterministic initial state)
        for (uint32_t i = 0u; i < IMPL_BUF_SIZE; ++i) {
            impl_buf_[i] = 0u;
        }
    }

    HTS_IPC_Protocol::~HTS_IPC_Protocol() noexcept
    {
        Shutdown();
    }

    IPC_Error HTS_IPC_Protocol::Initialize(const IPC_Config& config) noexcept
    {
        // Idempotent guard: CAS (compare_exchange_strong)
        bool expected = false;
        if (!initialized_.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel))
        {
            return IPC_Error::OK;  // Already initialized
        }

        // Validate config
        if (config.spi_base_addr == 0u) { initialized_.store(false, std::memory_order_release); return IPC_Error::HW_FAULT; }
        if (config.dma_base_addr == 0u) { initialized_.store(false, std::memory_order_release); return IPC_Error::HW_FAULT; }
        if (config.dma_stream_rx > 7u) { initialized_.store(false, std::memory_order_release); return IPC_Error::HW_FAULT; }
        if (config.dma_stream_tx > 7u) { initialized_.store(false, std::memory_order_release); return IPC_Error::HW_FAULT; }
        if (config.drdy_port_index >= 6u) { initialized_.store(false, std::memory_order_release); return IPC_Error::HW_FAULT; }
        if (config.drdy_pin > 15u) { initialized_.store(false, std::memory_order_release); return IPC_Error::HW_FAULT; }

        // Construct Impl via placement new
        Impl* impl = new (impl_buf_) Impl{};

        // Store config
        impl->config = config;
        if (impl->config.frame_timeout_ms == 0u) {
            impl->config.frame_timeout_ms = IPC_FRAME_TIMEOUT_MS;
        }
        if (impl->config.ping_interval_ms == 0u) {
            impl->config.ping_interval_ms = IPC_PING_INTERVAL_MS;
        }

        // Initialize state
        impl->state = IPC_State::UNINITIALIZED;
        impl->state_entry_tick = 0u;
        impl->tx_seq.store(0u, std::memory_order_relaxed);
        impl->rx_expected_seq = 0u;

        // Initialize ring buffer pointers
        impl->rx_head.store(0u, std::memory_order_relaxed);
        impl->rx_tail.store(0u, std::memory_order_relaxed);
        impl->tx_head.store(0u, std::memory_order_relaxed);
        impl->tx_tail.store(0u, std::memory_order_relaxed);

        // Initialize flags
        impl->rx_dma_complete.store(false, std::memory_order_relaxed);
        impl->tx_dma_complete.store(false, std::memory_order_relaxed);
        impl->spi_error_flag.store(false, std::memory_order_relaxed);
        impl->drdy_asserted = false;

        // Initialize heartbeat
        impl->last_ping_sent_tick = 0u;
        impl->last_pong_recv_tick = 0u;

        // Zero statistics
        IPC_Statistics_Reset(impl->stats);

        // Compute cached HW addresses
        impl->dma_stream_rx_base = Impl::Compute_Stream_Base(config.dma_base_addr, config.dma_stream_rx);
        impl->dma_stream_tx_base = Impl::Compute_Stream_Base(config.dma_base_addr, config.dma_stream_tx);
        impl->gpio_drdy_base = GPIO_BASE_ARRAY[config.drdy_port_index];

        // --- Hardware Initialization ---
        impl->Enable_Clocks();
        impl->Configure_GPIO();
        impl->Configure_SPI_Slave();
        impl->Configure_DMA();

        // Transition to IDLE
        impl->Transition_State(IPC_State::IDLE);

        return IPC_Error::OK;
    }

    void HTS_IPC_Protocol::Shutdown() noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }

        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        // Disable SPI
        if (impl->config.spi_base_addr != 0u) {
            HW_REG(impl->config.spi_base_addr + SPI_CR1_OFF) &= ~SPI_CR1_SPE;
        }

        // Disable DMA streams
        if (impl->dma_stream_rx_base != 0u) {
            HW_REG(impl->dma_stream_rx_base + DMA_SxCR_OFF) &= ~DMA_SxCR_EN;
        }
        if (impl->dma_stream_tx_base != 0u) {
            HW_REG(impl->dma_stream_tx_base + DMA_SxCR_OFF) &= ~DMA_SxCR_EN;
        }

        // Deassert DRDY
        impl->Deassert_DRDY();

        // Secure wipe all sensitive data
        IPC_Secure_Wipe(impl->spi_rx_buf, IPC_SPI_DMA_BUF_SIZE);
        IPC_Secure_Wipe(impl->spi_tx_buf, IPC_SPI_DMA_BUF_SIZE);
        IPC_Secure_Wipe(impl->rx_ring, sizeof(impl->rx_ring));
        IPC_Secure_Wipe(impl->tx_ring, sizeof(impl->tx_ring));
        std::atomic_thread_fence(std::memory_order_release);

        // Explicit destructor call (placement new cleanup)
        impl->~Impl();

        IPC_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);

        initialized_.store(false, std::memory_order_release);
    }

    IPC_Error HTS_IPC_Protocol::Reset() noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) {
            return IPC_Error::NOT_INITIALIZED;
        }

        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        // Disable DMA temporarily
        HW_REG(impl->dma_stream_rx_base + DMA_SxCR_OFF) &= ~DMA_SxCR_EN;
        HW_REG(impl->dma_stream_tx_base + DMA_SxCR_OFF) &= ~DMA_SxCR_EN;

        // Deassert DRDY
        impl->Deassert_DRDY();

        // Clear ring buffers
        impl->rx_head.store(0u, std::memory_order_relaxed);
        impl->rx_tail.store(0u, std::memory_order_relaxed);
        impl->tx_head.store(0u, std::memory_order_relaxed);
        impl->tx_tail.store(0u, std::memory_order_relaxed);

        // Reset sequence numbers
        impl->tx_seq.store(0u, std::memory_order_relaxed);
        impl->rx_expected_seq = 0u;

        // Clear flags
        impl->rx_dma_complete.store(false, std::memory_order_relaxed);
        impl->tx_dma_complete.store(false, std::memory_order_relaxed);
        impl->spi_error_flag.store(false, std::memory_order_relaxed);

        // Clear SPI error flags by reading SR then DR
        volatile uint32_t dummy = HW_REG(impl->config.spi_base_addr + SPI_SR_OFF);
        dummy = HW_REG(impl->config.spi_base_addr + SPI_DR_OFF);
        (void)dummy;

        // Re-arm DMA
        impl->Configure_DMA();

        // Transition to IDLE
        impl->state = IPC_State::IDLE;

        return IPC_Error::OK;
    }

    void HTS_IPC_Protocol::Tick(uint32_t systick_ms) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }

        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        impl->state_entry_tick = systick_ms;  // Update current tick for handlers

        // --- Handle SPI Error ---
        if (impl->spi_error_flag.load(std::memory_order_acquire)) {
            impl->spi_error_flag.store(false, std::memory_order_relaxed);
            impl->stats.hw_faults.fetch_add(1u, std::memory_order_relaxed);

            // Clear SPI overrun: read SR then DR
            volatile uint32_t dummy = HW_REG(impl->config.spi_base_addr + SPI_SR_OFF);
            dummy = HW_REG(impl->config.spi_base_addr + SPI_DR_OFF);
            (void)dummy;

            impl->Rearm_DMA();
        }

        // --- Handle RX DMA Complete ---
        if (impl->rx_dma_complete.load(std::memory_order_acquire)) {
            impl->rx_dma_complete.store(false, std::memory_order_relaxed);

            // Bitmask check: IDLE(0x01) | RESPONDING(0x08) = valid states for RX processing
            static constexpr uint8_t k_rx_valid_mask = static_cast<uint8_t>(
                static_cast<uint8_t>(IPC_State::IDLE) |
                static_cast<uint8_t>(IPC_State::RESPONDING));
            if ((static_cast<uint8_t>(impl->state) & k_rx_valid_mask) != 0u) {
                impl->Transition_State(IPC_State::PROCESSING);
                impl->Process_RX_Frame();
                impl->Transition_State(IPC_State::IDLE);
            }

            impl->Rearm_DMA();
        }

        // --- Handle TX DMA Complete ---
        if (impl->tx_dma_complete.load(std::memory_order_acquire)) {
            impl->tx_dma_complete.store(false, std::memory_order_relaxed);
            impl->Deassert_DRDY();
        }

        // --- Heartbeat ---
        impl->Tick_Heartbeat(systick_ms);

        // --- TX Pump: send queued responses ---
        impl->Pump_TX();
    }

    IPC_Error HTS_IPC_Protocol::Send_Frame(
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

        uint8_t s_frame_buf[IPC_MAX_FRAME_SIZE];
        const Scoped_IPC_Frame_Wipe wipe_frame(
            s_frame_buf, static_cast<uint32_t>(sizeof(s_frame_buf)));
        uint32_t flen = 0u;
        const IPC_Error ser = IPC_Serialize_Frame(
            s_frame_buf, impl->tx_seq.fetch_add(1u, std::memory_order_relaxed), cmd, payload, payload_len, flen);
        if (ser != IPC_Error::OK) {
            return ser;
        }
        if (flen == 0u) {
            return IPC_Error::BUFFER_OVERFLOW;
        }

        // Push to TX ring
        if (!impl->Ring_TX_Push(s_frame_buf, static_cast<uint16_t>(flen))) {
            return IPC_Error::QUEUE_FULL;
        }

        return IPC_Error::OK;
    }

    IPC_Error HTS_IPC_Protocol::Receive_Frame(
        IPC_Command& out_cmd,
        uint8_t* out_payload,
        uint16_t        out_buf_size,
        uint16_t& out_payload_len) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) {
            return IPC_Error::NOT_INITIALIZED;
        }

        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        uint8_t s_raw_buf[IPC_MAX_FRAME_SIZE];
        const Scoped_IPC_Frame_Wipe wipe_raw(
            s_raw_buf, static_cast<uint32_t>(sizeof(s_raw_buf)));
        uint16_t raw_len = 0u;
        if (!impl->Ring_RX_Pop(s_raw_buf, IPC_MAX_FRAME_SIZE, raw_len)) {
            out_payload_len = 0u;
            return IPC_Error::QUEUE_FULL;  // Ring empty
        }

        // Parse the raw frame (payload copied into caller buffer by parser)
        uint8_t seq = 0u;
        const IPC_Error err = IPC_Parse_Frame(
            s_raw_buf, raw_len, seq, out_cmd, out_payload, out_buf_size, out_payload_len);

        if (err != IPC_Error::OK) {
            out_payload_len = 0u;
            return err;
        }

        return IPC_Error::OK;
    }

    IPC_State HTS_IPC_Protocol::Get_State() const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) {
            return IPC_State::UNINITIALIZED;
        }
        const Impl* impl = reinterpret_cast<const Impl*>(impl_buf_);
        return impl->state;
    }

    void HTS_IPC_Protocol::Get_Statistics(IPC_Statistics& out_stats) const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) {
            IPC_Statistics_Reset(out_stats);
            return;
        }
        const Impl* impl = reinterpret_cast<const Impl*>(impl_buf_);
        IPC_Statistics_Copy(impl->stats, out_stats);
    }

    uint32_t HTS_IPC_Protocol::Is_Link_Alive() const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return SECURE_FALSE; }
        const Impl* impl = reinterpret_cast<const Impl*>(impl_buf_);
        return impl->Is_Heartbeat_Alive(impl->state_entry_tick)
            ? SECURE_TRUE : SECURE_FALSE;
    }

    uint32_t HTS_IPC_Protocol::Get_TX_Pending() const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        const Impl* impl = reinterpret_cast<const Impl*>(impl_buf_);
        return impl->Ring_TX_Count();
    }

    uint32_t HTS_IPC_Protocol::Get_RX_Pending() const noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return 0u; }
        const Impl* impl = reinterpret_cast<const Impl*>(impl_buf_);
        return impl->Ring_RX_Count();
    }

    // ============================================================
    //  ISR Callbacks (Lock-free, minimal cycle count)
    // ============================================================

    void HTS_IPC_Protocol::ISR_SPI_RX_Complete() noexcept
    {
        if (!initialized_.load(std::memory_order_relaxed)) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        impl->rx_dma_complete.store(true, std::memory_order_release);
    }

    void HTS_IPC_Protocol::ISR_SPI_TX_Complete() noexcept
    {
        if (!initialized_.load(std::memory_order_relaxed)) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        impl->tx_dma_complete.store(true, std::memory_order_release);
    }

    void HTS_IPC_Protocol::ISR_SPI_Error() noexcept
    {
        if (!initialized_.load(std::memory_order_relaxed)) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        impl->spi_error_flag.store(true, std::memory_order_release);
    }

} // namespace ProtectedEngine
