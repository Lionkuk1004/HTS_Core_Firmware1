// =========================================================================
// HTS_OTA_AMI_Manager.cpp
// AMI 보안 일제 무선 펌웨어 갱신 (Secure FUOTA) 구현부
// Target: STM32F407 (Cortex-M4, 168MHz, SRAM 192KB)
//
// [보안 설계]
//  · HMAC-LSH256 전체 서명 (KCMVP)
//  · 세션 논스 Anti-Replay
//  · 청크별 4B 절삭 MAC
//  · CRC32 전송 무결성 (기존 유지)
//  · 점진적 검증 (WDT 안전, Tick 분산)
//  · Constant-Time HMAC 비교 (타이밍 부채널 차단)
// =========================================================================
#include "HTS_OTA_AMI_Manager.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <new>

namespace ProtectedEngine {

    // =====================================================================
    //  보안 유틸리티
    // =====================================================================
    static void OTA_Secure_Wipe(void* p, size_t n) noexcept {
        if (p == nullptr || n == 0u) { return; }
        volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
        for (size_t i = 0u; i < n; ++i) { q[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    /// @brief Constant-Time 비교 (타이밍 부채널 방어)
    ///  비트마스크 OR 누적 → 전 바이트 비교 후 판정
    static uint32_t ct_compare(
        const uint8_t* a, const uint8_t* b, size_t len) noexcept
    {
        uint32_t diff = 0u;
        for (size_t i = 0u; i < len; ++i) {
            diff |= static_cast<uint32_t>(a[i] ^ b[i]);
        }
        return diff;  // 0 = 일치
    }

    // CRC32 (기존 유지 — 전송 무결성)
    static uint32_t sw_crc32_block(
        const uint8_t* data, size_t len, uint32_t crc) noexcept
    {
        for (size_t i = 0u; i < len; ++i) {
            crc ^= static_cast<uint32_t>(data[i]);
            for (uint8_t bit = 0u; bit < 8u; ++bit) {
                if ((crc & 1u) != 0u) {
                    crc = (crc >> 1u) ^ 0xEDB88320u;
                }
                else {
                    crc >>= 1u;
                }
            }
        }
        return crc;
    }

    // Flash 스텁
#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
    static bool flash_write(uint32_t off, const uint8_t* d, size_t l) noexcept {
        (void)off; (void)d; (void)l; return true;
    }
    static bool flash_read(uint32_t off, uint8_t* b, size_t l) noexcept {
        (void)off; (void)b; (void)l; return true;
    }
    static bool flash_erase_bank_b() noexcept { return true; }
    static void system_reset() noexcept {
        static constexpr uint32_t AIRCR = 0xE000ED0Cu;
        static constexpr uint32_t KEY = 0x05FA0004u;
        *reinterpret_cast<volatile uint32_t*>(AIRCR) = KEY;
        for (;;) {}
    }
#else
    static bool flash_write(uint32_t, const uint8_t*, size_t) noexcept { return true; }
    static bool flash_read(uint32_t, uint8_t*, size_t) noexcept { return true; }
    static bool flash_erase_bank_b() noexcept { return true; }
    static void system_reset() noexcept {}
#endif

    // 비트맵 연산
    static void bmap_set(uint8_t* m, uint16_t i) noexcept {
        m[i >> 3u] |= static_cast<uint8_t>(1u << (i & 7u));
    }
    static bool bmap_test(const uint8_t* m, uint16_t i) noexcept {
        return (m[i >> 3u] & static_cast<uint8_t>(1u << (i & 7u))) != 0u;
    }
    static uint16_t bmap_missing(const uint8_t* m, uint16_t total) noexcept {
        uint16_t cnt = 0u;
        for (uint16_t i = 0u; i < total; ++i) {
            if (!bmap_test(m, i)) { ++cnt; }
        }
        return cnt;
    }

    // =====================================================================
    //  Pimpl
    // =====================================================================
    struct HTS_OTA_AMI_Manager::Impl {
        uint16_t my_id = 0u;
        uint32_t cur_version = 0u;
        uint32_t new_version = 0u;
        uint32_t total_size = 0u;
        uint16_t total_chunks = 0u;
        uint16_t received_count = 0u;
        uint32_t expected_crc32 = 0u;
        uint32_t last_chunk_ms = 0u;
        uint8_t  nack_rounds = 0u;
        AMI_OtaState  state = AMI_OtaState::IDLE;
        AMI_OtaReject reject = AMI_OtaReject::NONE;

        // 보안 상태
        uint8_t session_nonce[OTA_NONCE_SIZE] = {};
        uint8_t prev_nonce[OTA_NONCE_SIZE] = {};  // 이전 세션 논스
        uint8_t expected_hmac[OTA_HMAC_SIZE] = {};
        bool    nonce_set = false;  // 이전 논스 존재 여부

        // 암호 HAL
        OTA_Crypto_Callbacks crypto = {};

        // 수신 비트맵
        uint8_t recv_bitmap[OTA_BITMAP_SIZE] = {};

        // 점진적 검증
        uint32_t verify_crc = 0xFFFFFFFFu;
        uint32_t verify_offset = 0u;
        uint32_t verify_remaining = 0u;
        bool     verify_hmac_started = false;

        explicit Impl(uint16_t id, uint32_t ver) noexcept
            : my_id(id), cur_version(ver) {
        }
        ~Impl() noexcept = default;
    };

    HTS_OTA_AMI_Manager::Impl*
        HTS_OTA_AMI_Manager::get_impl() noexcept
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE, "Impl 초과");
        static_assert(alignof(Impl) <= IMPL_BUF_ALIGN, "정렬 초과");
        return impl_valid_
            ? reinterpret_cast<Impl*>(impl_buf_) : nullptr;
    }
    const HTS_OTA_AMI_Manager::Impl*
        HTS_OTA_AMI_Manager::get_impl() const noexcept
    {
        return impl_valid_
            ? reinterpret_cast<const Impl*>(impl_buf_) : nullptr;
    }

    HTS_OTA_AMI_Manager::HTS_OTA_AMI_Manager(
        uint16_t my_id, uint32_t current_version) noexcept
        : impl_valid_(false)
    {
        OTA_Secure_Wipe(impl_buf_, sizeof(impl_buf_));
        ::new (static_cast<void*>(impl_buf_)) Impl(my_id, current_version);
        impl_valid_ = true;
    }

    HTS_OTA_AMI_Manager::~HTS_OTA_AMI_Manager() noexcept {
        Impl* p = get_impl();
        if (p != nullptr) { p->~Impl(); }
        OTA_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
        impl_valid_ = false;
    }

    void HTS_OTA_AMI_Manager::Register_Crypto(
        const OTA_Crypto_Callbacks& cb) noexcept
    {
        Impl* p = get_impl();
        if (p != nullptr) { p->crypto = cb; }
    }

    // =====================================================================
    //  On_Begin — 보안 검증 포함
    //
    //  [보안 1] 안티 롤백: new_version > cur_version
    //  [보안 2] 논스 재전송 차단: nonce ≠ prev_nonce
    //  [보안 3] size↔chunks 교차 검증
    // =====================================================================
    bool HTS_OTA_AMI_Manager::On_Begin(
        uint32_t new_version, uint32_t total_size,
        uint16_t total_chunks,
        const uint8_t* nonce,
        const uint8_t* expected_hmac,
        uint32_t expected_crc32) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return false; }
        if (p->state != AMI_OtaState::IDLE &&
            p->state != AMI_OtaState::FAILED) {
            return false;
        }
        if (nonce == nullptr || expected_hmac == nullptr) { return false; }

        // [보안 1] 안티 롤백
        if (new_version <= p->cur_version) {
            p->reject = AMI_OtaReject::VERSION_OLD;
            return false;
        }

        // [보안 2] 논스 재전송 차단
        if (p->nonce_set) {
            if (ct_compare(nonce, p->prev_nonce, OTA_NONCE_SIZE) == 0u) {
                p->reject = AMI_OtaReject::NONCE_REPLAY;
                return false;
            }
        }

        // [보안 3] size↔chunks 교차 검증
        if (total_size == 0u || total_chunks == 0u) { return false; }
        if (total_chunks > MAX_CHUNKS) { return false; }
        const uint32_t expected_cnt =
            (total_size + CHUNK_SIZE - 1u) / CHUNK_SIZE;
        if (static_cast<uint32_t>(total_chunks) != expected_cnt) {
            p->reject = AMI_OtaReject::SIZE_MISMATCH;
            return false;
        }

        // Flash 초기화
        if (!flash_erase_bank_b()) {
            p->reject = AMI_OtaReject::FLASH_FAIL;
            return false;
        }

        // 상태 저장
        p->new_version = new_version;
        p->total_size = total_size;
        p->total_chunks = total_chunks;
        p->expected_crc32 = expected_crc32;
        p->received_count = 0u;
        p->nack_rounds = 0u;
        p->reject = AMI_OtaReject::NONE;

        // 논스 저장 (현재 → 이전으로 교대)
        for (size_t i = 0u; i < OTA_NONCE_SIZE; ++i) {
            p->prev_nonce[i] = p->session_nonce[i];
            p->session_nonce[i] = nonce[i];
        }
        p->nonce_set = true;

        // 기대 HMAC 저장
        for (size_t i = 0u; i < OTA_HMAC_SIZE; ++i) {
            p->expected_hmac[i] = expected_hmac[i];
        }

        OTA_Secure_Wipe(p->recv_bitmap, OTA_BITMAP_SIZE);
        p->state = AMI_OtaState::RECEIVING;
        return true;
    }

    // =====================================================================
    //  On_Chunk — 청크별 MAC 검증
    //
    //  [보안 4] chunk_mac ≠ nullptr → 4B 절삭 HMAC 검증
    //   HMAC(chunk_key, idx_be2 ‖ data)[0:4]
    //   → 개별 청크 변조 즉시 감지
    // =====================================================================
    bool HTS_OTA_AMI_Manager::On_Chunk(
        uint16_t chunk_idx,
        const uint8_t* data, size_t data_len,
        const uint8_t* chunk_mac) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr || data == nullptr) { return false; }
        if (p->state != AMI_OtaState::RECEIVING &&
            p->state != AMI_OtaState::NACK_WAIT) {
            return false;
        }
        if (chunk_idx >= p->total_chunks) { return false; }
        if (data_len == 0u || data_len > CHUNK_SIZE) { return false; }

        // 중복 수신 무시
        if (bmap_test(p->recv_bitmap, chunk_idx)) { return true; }

        // [보안 4] 청크 MAC 검증 (선택적)
        if (chunk_mac != nullptr && p->crypto.hmac_lsh256 != nullptr) {
            // idx(2B big-endian) ‖ data → HMAC → 4B 절삭 비교
            uint8_t mac_input[2u + CHUNK_SIZE];
            mac_input[0] = static_cast<uint8_t>(chunk_idx >> 8u);
            mac_input[1] = static_cast<uint8_t>(chunk_idx & 0xFFu);
            for (size_t i = 0u; i < data_len; ++i) {
                mac_input[2u + i] = data[i];
            }

            uint8_t full_mac[OTA_HMAC_SIZE] = {};
            p->crypto.hmac_lsh256(
                p->session_nonce,  // 논스를 청크 키로 사용
                mac_input, 2u + data_len,
                full_mac);

            // 4B 절삭 Constant-Time 비교
            const uint32_t mac_diff =
                ct_compare(chunk_mac, full_mac, OTA_CHUNK_MAC_SIZE);

            OTA_Secure_Wipe(full_mac, sizeof(full_mac));
            OTA_Secure_Wipe(mac_input, sizeof(mac_input));

            if (mac_diff != 0u) {
                p->reject = AMI_OtaReject::CHUNK_MAC_FAIL;
                return false;
            }
        }

        // Flash 기록
        const uint32_t offset =
            static_cast<uint32_t>(chunk_idx) * CHUNK_SIZE;
        if (!flash_write(offset, data, data_len)) {
            p->reject = AMI_OtaReject::FLASH_FAIL;
            return false;
        }

        bmap_set(p->recv_bitmap, chunk_idx);
        p->received_count++;
        p->last_chunk_ms = 0u;
        return true;
    }

    // =====================================================================
    //  On_Broadcast_Complete
    // =====================================================================
    void HTS_OTA_AMI_Manager::On_Broadcast_Complete(
        uint32_t systick_ms) noexcept
    {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        if (p->state != AMI_OtaState::RECEIVING) { return; }

        if (p->received_count >= p->total_chunks) {
            (void)Verify();
        }
        else {
            p->state = AMI_OtaState::NACK_WAIT;
            p->last_chunk_ms = systick_ms;
        }
    }

    // =====================================================================
    //  Get_NACK_Bitmap
    // =====================================================================
    uint16_t HTS_OTA_AMI_Manager::Get_NACK_Bitmap(
        uint8_t* out_bitmap) const noexcept
    {
        const Impl* p = get_impl();
        if (p == nullptr || out_bitmap == nullptr) { return 0u; }

        for (size_t i = 0u; i < OTA_BITMAP_SIZE; ++i) {
            out_bitmap[i] = static_cast<uint8_t>(~p->recv_bitmap[i]);
        }

        const uint16_t tc = p->total_chunks;
        const size_t full_bytes = static_cast<size_t>(tc >> 3u);
        const uint8_t tail_bits = static_cast<uint8_t>(tc & 7u);

        if (tail_bits != 0u && full_bytes < OTA_BITMAP_SIZE) {
            out_bitmap[full_bytes] &= static_cast<uint8_t>(
                (1u << tail_bits) - 1u);
            for (size_t i = full_bytes + 1u; i < OTA_BITMAP_SIZE; ++i) {
                out_bitmap[i] = 0u;
            }
        }
        else {
            for (size_t i = full_bytes; i < OTA_BITMAP_SIZE; ++i) {
                out_bitmap[i] = 0u;
            }
        }

        return bmap_missing(p->recv_bitmap, p->total_chunks);
    }

    bool HTS_OTA_AMI_Manager::Is_Complete() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) && (p->received_count >= p->total_chunks);
    }

    // =====================================================================
    //  Verify — CRC32 + HMAC-LSH256 점진적 검증 시작
    //
    //  [보안 5] HMAC-LSH256 전체 검증
    //   hmac_init(fw_key) → hmac_update(nonce‖version) →
    //   Tick에서 hmac_update(flash_block×N) →
    //   hmac_final(computed_mac) → ct_compare(expected)
    // =====================================================================
    bool HTS_OTA_AMI_Manager::Verify() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return false; }
        if (p->received_count < p->total_chunks) { return false; }

        p->verify_crc = 0xFFFFFFFFu;
        p->verify_offset = 0u;
        p->verify_remaining = p->total_size;
        p->verify_hmac_started = false;
        p->state = AMI_OtaState::VERIFYING;

        // HMAC 점진적 시작 (논스 ‖ 버전 선행 입력)
        if (p->crypto.hmac_init != nullptr) {
            p->crypto.hmac_init(p->session_nonce);

            // 선행 데이터: nonce(8B) ‖ version(4B big-endian)
            uint8_t prefix[12] = {};
            for (size_t i = 0u; i < OTA_NONCE_SIZE; ++i) {
                prefix[i] = p->session_nonce[i];
            }
            prefix[8] = static_cast<uint8_t>(p->new_version >> 24u);
            prefix[9] = static_cast<uint8_t>((p->new_version >> 16u) & 0xFFu);
            prefix[10] = static_cast<uint8_t>((p->new_version >> 8u) & 0xFFu);
            prefix[11] = static_cast<uint8_t>(p->new_version & 0xFFu);

            if (p->crypto.hmac_update != nullptr) {
                p->crypto.hmac_update(prefix, 12u);
            }
            OTA_Secure_Wipe(prefix, sizeof(prefix));
            p->verify_hmac_started = true;
        }

        return true;
    }

    // =====================================================================
    //  Commit
    // =====================================================================
    void HTS_OTA_AMI_Manager::Commit() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        if (p->state != AMI_OtaState::READY) { return; }

        // 보안 상태 소거 후 리부팅
        OTA_Secure_Wipe(p->expected_hmac, OTA_HMAC_SIZE);
        OTA_Secure_Wipe(p->session_nonce, OTA_NONCE_SIZE);
        system_reset();
    }

    void HTS_OTA_AMI_Manager::Abort() noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }
        OTA_Secure_Wipe(p->recv_bitmap, OTA_BITMAP_SIZE);
        OTA_Secure_Wipe(p->expected_hmac, OTA_HMAC_SIZE);
        p->received_count = 0u;
        p->reject = AMI_OtaReject::NONE;
        p->state = AMI_OtaState::IDLE;
    }

    // =====================================================================
    //  상태 조회
    // =====================================================================
    AMI_OtaState HTS_OTA_AMI_Manager::Get_State() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? p->state : AMI_OtaState::IDLE;
    }

    AMI_OtaReject HTS_OTA_AMI_Manager::Get_Reject_Reason() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? p->reject : AMI_OtaReject::NONE;
    }

    uint8_t HTS_OTA_AMI_Manager::Get_Progress_Pct() const noexcept {
        const Impl* p = get_impl();
        if (p == nullptr || p->total_chunks == 0u) { return 0u; }
        if (p->received_count >= p->total_chunks) { return 100u; }
        return static_cast<uint8_t>(
            (static_cast<uint32_t>(p->received_count) * 100u) /
            static_cast<uint32_t>(p->total_chunks));
    }

    uint16_t HTS_OTA_AMI_Manager::Get_Received_Count() const noexcept {
        const Impl* p = get_impl();
        return (p != nullptr) ? p->received_count : 0u;
    }

    // =====================================================================
    //  Tick — 타임아웃 + 점진적 CRC/HMAC 검증
    // =====================================================================
    void HTS_OTA_AMI_Manager::Tick(uint32_t systick_ms) noexcept {
        Impl* p = get_impl();
        if (p == nullptr) { return; }

        if (p->last_chunk_ms == 0u) {
            p->last_chunk_ms = systick_ms;
            return;
        }
        const uint32_t elapsed = systick_ms - p->last_chunk_ms;

        // RECEIVING: 5분 타임아웃
        if (p->state == AMI_OtaState::RECEIVING) {
            if (elapsed >= OTA_TIMEOUT_MS) {
                p->reject = AMI_OtaReject::TIMEOUT;
                Abort();
            }
            return;
        }

        // NACK_WAIT
        if (p->state == AMI_OtaState::NACK_WAIT) {
            if (elapsed >= NACK_TIMEOUT_MS) {
                p->nack_rounds++;
                if (p->nack_rounds >= MAX_NACK_ROUNDS) {
                    p->reject = AMI_OtaReject::TIMEOUT;
                    p->state = AMI_OtaState::FAILED;
                    return;
                }
                if (p->received_count >= p->total_chunks) {
                    (void)Verify();
                }
                else {
                    p->state = AMI_OtaState::RECEIVING;
                    p->last_chunk_ms = systick_ms;
                }
            }
            return;
        }

        // VERIFYING: 점진적 CRC + HMAC
        if (p->state == AMI_OtaState::VERIFYING) {
            if (p->verify_remaining == 0u) {
                // ── 검증 완료: CRC + HMAC 최종 비교 ──
                const uint32_t final_crc = p->verify_crc ^ 0xFFFFFFFFu;

                // CRC 검증
                if (final_crc != p->expected_crc32) {
                    p->reject = AMI_OtaReject::CRC_FAIL;
                    p->state = AMI_OtaState::FAILED;
                    return;
                }

                // HMAC 검증 (Constant-Time)
                if (p->verify_hmac_started &&
                    p->crypto.hmac_final != nullptr)
                {
                    uint8_t computed[OTA_HMAC_SIZE] = {};
                    p->crypto.hmac_final(computed);

                    const uint32_t hmac_diff = ct_compare(
                        computed, p->expected_hmac, OTA_HMAC_SIZE);
                    OTA_Secure_Wipe(computed, sizeof(computed));

                    if (hmac_diff != 0u) {
                        p->reject = AMI_OtaReject::HMAC_FAIL;
                        p->state = AMI_OtaState::FAILED;
                        return;
                    }
                }

                p->state = AMI_OtaState::READY;
                return;
            }

            // Tick당 16청크 (4KB) 처리
            static constexpr uint32_t CHUNKS_PER_TICK = 16u;
            for (uint32_t c = 0u;
                c < CHUNKS_PER_TICK && p->verify_remaining > 0u; ++c)
            {
                uint8_t buf[CHUNK_SIZE];
                const uint32_t chunk =
                    (p->verify_remaining < CHUNK_SIZE)
                    ? p->verify_remaining : CHUNK_SIZE;

                if (!flash_read(p->verify_offset, buf,
                    static_cast<size_t>(chunk)))
                {
                    p->reject = AMI_OtaReject::FLASH_FAIL;
                    p->state = AMI_OtaState::FAILED;
                    OTA_Secure_Wipe(buf, sizeof(buf));
                    return;
                }

                // CRC 누적
                p->verify_crc = sw_crc32_block(
                    buf, static_cast<size_t>(chunk), p->verify_crc);

                // HMAC 누적
                if (p->verify_hmac_started &&
                    p->crypto.hmac_update != nullptr)
                {
                    p->crypto.hmac_update(buf, static_cast<size_t>(chunk));
                }

                p->verify_offset += chunk;
                p->verify_remaining -= chunk;
                OTA_Secure_Wipe(buf, sizeof(buf));
            }
        }
    }

    void HTS_OTA_AMI_Manager::Shutdown() noexcept {
        Abort();
    }

} // namespace ProtectedEngine