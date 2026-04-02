// =========================================================================
// HTS_Security_Session.cpp
// KCMVP 암호/인증 통합 오케스트레이터 구현부 (Pimpl 은닉)
// Target: STM32F407 (Cortex-M4, 168MHz) / PC
//
#include "HTS_Security_Session.h"

#include "HTS_HMAC_Bridge.hpp"
#include "HTS_ARIA_Bridge.hpp"
#include "HTS_LEA_Bridge.h"
#if defined(HTS_CRYPTO_FIPS) || defined(HTS_CRYPTO_DUAL)
#include "HTS_AES_Bridge.h"    // [🟡 8] FIPS AES-256-CTR 지원
#endif
#include "HTS_Secure_Memory.h"

#include <cstring>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <climits>
#include <new>     // placement new (힙 할당 아님)

namespace ProtectedEngine {
    // =====================================================================
    //  루프 오버헤드를 없애고 N개의 블록을 한 번에 더하는 O(1) 알고리즘
    // =====================================================================
    static void Add_To_Counter(uint8_t* counter, uint64_t blocks) noexcept {
        if (blocks == 0) return;
        uint64_t carry = blocks;
        for (int i = 15; i >= 0 && carry > 0; --i) {
            carry += counter[i];
            counter[i] = static_cast<uint8_t>(carry & 0xFFu);
            carry >>= 8u;
        }
    }

    // =====================================================================
    // =====================================================================
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4324)
#endif
    struct HTS_Security_Session::Impl {
        CipherAlgorithm cipher_alg = CipherAlgorithm::LEA_256_CTR;
        MacAlgorithm    mac_alg = MacAlgorithm::HMAC_SHA256;
        bool            is_session_active = false;

        alignas(4) uint8_t session_enc_key[32] = {};
        alignas(4) uint8_t session_mac_key[32] = {};
        alignas(4) uint8_t tx_counter[16] = {};
        alignas(4) uint8_t rx_counter[16] = {};
        alignas(4) uint8_t last_init_iv[16] = {};
        bool last_iv_valid = false;

        alignas(4) uint8_t tx_partial_block[16] = {};
        size_t tx_partial_len = 0;

        alignas(4) uint8_t rx_partial_block[16] = {};
        size_t rx_partial_len = 0;

        HMAC_Context tx_mac_ctx;
        HMAC_Context rx_mac_ctx;

        // Do_CTR_Chunk에서는 Process_Block만 호출 (키 확장 0회)
        // ARIA: 라운드 키 테이블 (~1KB), LEA: 확장 키 (~800B)
        ARIA_Bridge cached_aria;
#if defined(HTS_CRYPTO_FIPS) || defined(HTS_CRYPTO_DUAL)
        AES_Bridge  cached_aes;            // [🟡 8] FIPS AES-256-CTR
#endif
        LEA_KEY     cached_lea_key{};  // [C26495] 제로 초기화
        bool        crypto_ctx_ready = false;  // 키 확장 완료 플래그

        //  Unprotect_Verify에서 즉시 Terminate 안 함 → 타이밍 일정
        //  다음 API 호출 시 거부 + 종료 (백그라운드 디커플링)
        bool deferred_terminate = false;

        alignas(4) uint8_t scratch_ctr[16] = {};

        static_assert(sizeof(session_enc_key) == 32,
            "AES/ARIA/LEA-256 key must be 32 bytes");
        static_assert(sizeof(tx_counter) == 16,
            "CTR counter must be 16 bytes (128-bit block)");
        static_assert(sizeof(tx_partial_block) == 16,
            "Partial keystream buffer must match block size");

        // ── 전체 보안 소거 ───────────────────────────────────────────
        void Clean_State() noexcept {
            SecureMemory::secureWipe(session_enc_key, sizeof(session_enc_key));
            SecureMemory::secureWipe(session_mac_key, sizeof(session_mac_key));
            SecureMemory::secureWipe(tx_counter, sizeof(tx_counter));
            SecureMemory::secureWipe(rx_counter, sizeof(rx_counter));
            SecureMemory::secureWipe(last_init_iv, sizeof(last_init_iv));
            last_iv_valid = false;

            // 스트리밍 버퍼 소거
            SecureMemory::secureWipe(tx_partial_block, sizeof(tx_partial_block));
            SecureMemory::secureWipe(rx_partial_block, sizeof(rx_partial_block));
            tx_partial_len = 0;
            rx_partial_len = 0;

            // HMAC 컨텍스트 보안 소거 (640바이트 키 소재)
            SecureMemory::secureWipe(&tx_mac_ctx, sizeof(tx_mac_ctx));
            SecureMemory::secureWipe(&rx_mac_ctx, sizeof(rx_mac_ctx));

            SecureMemory::secureWipe(&cached_lea_key, sizeof(cached_lea_key));
            // cached_aria: ARIA_Bridge 소멸자가 라운드 키 소거 보장 (계약)
            crypto_ctx_ready = false;
            deferred_terminate = false;
            SecureMemory::secureWipe(scratch_ctr, sizeof(scratch_ctr));

            is_session_active = false;
        }

        // ── CTR 청크 암/복호화 (스트리밍 무결성 보장) ───────────────
        bool Do_CTR_Chunk(
            const uint8_t* input, size_t length,
            uint8_t* output, uint8_t* counter,
            uint8_t* partial_block, size_t& partial_len) noexcept {

            if (!input || !output || !counter || length == 0) return false;

            size_t offset = 0;

            // 1. 남은 잔여 키스트림(Residue) 우선 소진
            //
            //   partial_len = "이미 소비된 바이트 수" (= 다음 사용 오프셋)
            //   partial_block[partial_len] = 다음에 XOR할 키스트림 바이트
            //   partial_len=0: 잔여 없음 (while 진입 안 함)
            //   partial_len=5: partial_block[5..15] 미소비 → [5]부터 사용
            //   partial_len=16: 블록 완전 소비 → 카운터 증가 후 리셋
            while (partial_len > 0 && offset < length) {
                output[offset] = input[offset] ^ partial_block[partial_len];
                partial_len++;
                offset++;
                if (partial_len == 16) {
                    partial_len = 0;
                    Add_To_Counter(counter, 1);
                }
            }

            if (offset == length) return true;

            size_t remaining = length - offset;
            // 문제: ~15u = 0xFFFFFFF0 (32비트)
            //   64비트 size_t로 제로 확장 → 0x00000000FFFFFFF0
            //   → 4GB 이상 데이터에서 상위 32비트 증발!
            // size_t 캐스트 후 반전 → 0xFFFFFFFFFFFFFFF0 (64비트)
            //   32비트에서도 동일: ~(size_t)15 = 0xFFFFFFF0
            size_t full_blocks_bytes = remaining & ~static_cast<size_t>(15u);

            // 2. 16바이트 정렬된 전체 블록 고속 처리
            if (full_blocks_bytes > 0) {
                if (!crypto_ctx_ready) return false;  // Initialize 미호출 방어

                if (cipher_alg == CipherAlgorithm::ARIA_256_CTR) {
                    for (size_t b = 0; b < full_blocks_bytes; b += 16) {
                        uint8_t keystream[16];
                        if (!cached_aria.Process_Block(counter, keystream)) return false;
                        for (int i = 0; i < 16; ++i) {
                            output[offset + b + i] = input[offset + b + i] ^ keystream[i];
                        }
                        SecureMemory::secureWipe(keystream, sizeof(keystream));
                        Add_To_Counter(counter, 1);
                    }
                }
#if defined(HTS_CRYPTO_FIPS) || defined(HTS_CRYPTO_DUAL)
                else if (cipher_alg == CipherAlgorithm::AES_256_CTR) {
                    // [🟡 8] AES-256-CTR: ARIA와 동일 패턴 (블록 암호 교체)
                    for (size_t b = 0; b < full_blocks_bytes; b += 16) {
                        uint8_t keystream[16];
                        if (!cached_aes.Process_Block(counter, keystream)) return false;
                        for (int i = 0; i < 16; ++i) {
                            output[offset + b + i] = input[offset + b + i] ^ keystream[i];
                        }
                        SecureMemory::secureWipe(keystream, sizeof(keystream));
                        Add_To_Counter(counter, 1);
                    }
                }
#endif
                else {
                    std::memcpy(scratch_ctr, counter, 16);

                    size_t rem = full_blocks_bytes;
                    size_t done = 0;
                    while (rem > 0) {
                        unsigned int chunk = (rem > UINT_MAX)
                            ? static_cast<unsigned int>(UINT_MAX & ~static_cast<unsigned int>(15u))
                            : static_cast<unsigned int>(rem);
                        lea_ctr_enc(output + offset + done,
                            input + offset + done, chunk, scratch_ctr, &cached_lea_key);
                        done += chunk;
                        rem -= chunk;
                    }

                    Add_To_Counter(counter, full_blocks_bytes / 16);
                    SecureMemory::secureWipe(scratch_ctr, sizeof(scratch_ctr));
                }
                offset += full_blocks_bytes;
                remaining -= full_blocks_bytes;
            }

            // 3. 마지막 1~15 바이트 처리 (새 키스트림 생성 후 보관)
            //   full_blocks_bytes = remaining & ~15 이므로 이론적으로 항상 <16
            //   이중 안전: 계산 오류/패딩 공격 시에도 메모리 파괴 0%
            if (remaining >= 16u) { return false; }
            if (remaining > 0) {
                if (!crypto_ctx_ready) return false;

                if (cipher_alg == CipherAlgorithm::ARIA_256_CTR) {
                    if (!cached_aria.Process_Block(counter, partial_block)) return false;
                }
#if defined(HTS_CRYPTO_FIPS) || defined(HTS_CRYPTO_DUAL)
                else if (cipher_alg == CipherAlgorithm::AES_256_CTR) {
                    if (!cached_aes.Process_Block(counter, partial_block)) return false;
                }
#endif
                else {
                    std::memcpy(scratch_ctr, counter, 16);
                    uint8_t zeros[16] = { 0 };
                    lea_ctr_enc(partial_block, zeros, 16, scratch_ctr, &cached_lea_key);
                }

                for (size_t i = 0; i < remaining; ++i) {
                    output[offset + i] = input[offset + i] ^ partial_block[i];
                }
                partial_len = remaining;
            }

            return true;
        }
    };
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

    // 아래 static_assert는 get_impl() 함수 내부로 이동

    // =====================================================================
    //  In-Place Pimpl 접근자
    // =====================================================================
    HTS_Security_Session::Impl* HTS_Security_Session::get_impl() noexcept {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "Impl exceeds IMPL_BUF_SIZE — increase buffer or reduce Impl");
        static_assert(alignof(Impl) <= 8,
            "Impl alignment exceeds impl_buf_ alignment");

        return impl_valid_.load(std::memory_order_acquire)
            ? reinterpret_cast<Impl*>(impl_buf_)
            : nullptr;
    }
    const HTS_Security_Session::Impl* HTS_Security_Session::get_impl() const noexcept {
        return impl_valid_.load(std::memory_order_acquire)
            ? reinterpret_cast<const Impl*>(impl_buf_)
            : nullptr;
    }

    // =====================================================================
    //  생성자 / 소멸자
    //
    //  문제: 스택에 HTS_Security_Session이 할당되면 impl_buf_는
    //        이전 함수의 쓰레기값(암호키 찌꺼기 포함)으로 오염됨.
    //        Impl()의 기본 생성자는 명시적 멤버만 초기화하고
    //        패딩(padding) 바이트는 건드리지 않음.
    //        → 패딩에 과거 키 잔류 (Information Leak)
    //        → 64비트 정렬 HW 가속기가 패딩을 해석 시 BusFault
    //
    //  placement new 전에 SecureWipe로 전체 버퍼 0클린
    //        → 패딩 포함 모든 바이트 = 0
    //        → Impl() 생성자가 멤버를 덮어쓰더라도 패딩은 0 유지
    // =====================================================================
    HTS_Security_Session::HTS_Security_Session() noexcept
        : impl_valid_(false) {
        // volatile 기반 SecureWipe → 컴파일러가 "어차피 덮어쓸 거니까" 생략 불가
        SecureMemory::secureWipe(impl_buf_, sizeof(impl_buf_));

        // placement new: 0클린된 버퍼 위에 Impl 구축 (힙 접근 0)
        ::new (static_cast<void*>(impl_buf_)) Impl();
        impl_valid_.store(true, std::memory_order_release);
    }

    HTS_Security_Session::~HTS_Security_Session() noexcept {
        Impl* const p = reinterpret_cast<Impl*>(impl_buf_);
        const bool was_valid = impl_valid_.exchange(false, std::memory_order_acq_rel);
        if (was_valid) {
            p->Clean_State();       // 멤버 필드 보안 소거
            p->~Impl();
        }
        SecureMemory::secureWipe(impl_buf_, sizeof(impl_buf_));
    }

    bool HTS_Security_Session::Is_Active() const noexcept {
        const Impl* p = get_impl();
        return p && p->is_session_active;
    }

    // =====================================================================
    //  Initialize — 세션 키/IV 주입
    //  ⚠ TX/RX 동일 IV 사용 시 Two-Time Pad 취약점 발생
    //  호출자는 통신 방향별 독립 IV 주입 필수
    // =====================================================================
    bool HTS_Security_Session::Initialize(
        CipherAlgorithm c_alg, MacAlgorithm m_alg,
        const uint8_t* enc_key, const uint8_t* mac_key,
        const uint8_t* iv_16bytes) noexcept {

        if (!get_impl() || !enc_key || !mac_key || !iv_16bytes) return false;
        auto* impl = get_impl(); if (!impl) return false;

        if (impl->is_session_active) Terminate_Session();

        // [R-2] nonce/IV 재사용 차단: 직전 세션과 동일 IV 금지.
        // 동일 IV 반복은 CTR keystream 재사용으로 이어져 세션 하이재킹/평문 노출 위험.
        if (impl->last_iv_valid) {
            uint8_t iv_diff = 0u;
            for (size_t i = 0u; i < 16u; ++i) {
                iv_diff |= static_cast<uint8_t>(impl->last_init_iv[i] ^ iv_16bytes[i]);
            }
            if (iv_diff == 0u) { return false; }
        }

        impl->cipher_alg = c_alg;
        impl->mac_alg = m_alg;

        std::memcpy(impl->session_enc_key, enc_key, 32);
        std::memcpy(impl->session_mac_key, mac_key, 32);
        std::memcpy(impl->tx_counter, iv_16bytes, 16);
        std::memcpy(impl->rx_counter, iv_16bytes, 16);
        std::memcpy(impl->last_init_iv, iv_16bytes, 16);
        impl->last_iv_valid = true;

        // ARIA-256: 라운드 키 테이블 생성 (~수천 사이클)
        // LEA-256: 확장 키 생성 (~수천 사이클)
        // 이후 Do_CTR_Chunk에서는 Process_Block/lea_ctr_enc만 호출
        impl->crypto_ctx_ready = false;
        if (c_alg == CipherAlgorithm::ARIA_256_CTR) {
            if (!impl->cached_aria.Initialize_Encryption(enc_key, 256)) {
                return false;
            }
        }
#if defined(HTS_CRYPTO_FIPS) || defined(HTS_CRYPTO_DUAL)
        else if (c_alg == CipherAlgorithm::AES_256_CTR) {
            if (!impl->cached_aes.Initialize_Encryption(enc_key, 256)) {
                return false;
            }
        }
#endif
        else {
            lea_set_key(&impl->cached_lea_key, enc_key, 32);
        }
        impl->crypto_ctx_ready = true;

        impl->is_session_active = true;
        return true;
    }

    // =====================================================================
    //  송신 스트리밍 API
    // =====================================================================
    bool HTS_Security_Session::Protect_Begin() noexcept {
        if (!get_impl() || !get_impl()->is_session_active) return false;
        return HMAC_Bridge::Init(
            get_impl()->tx_mac_ctx, get_impl()->session_mac_key, 32)
            == HMAC_Bridge::SECURE_TRUE;
    }

    bool HTS_Security_Session::Protect_Chunk(
        const uint8_t* plaintext_chunk, size_t chunk_len,
        uint8_t* ciphertext_out) noexcept {

        if (!get_impl() || !get_impl()->is_session_active ||
            !plaintext_chunk || !ciphertext_out || chunk_len == 0)
            return false;

        if (!get_impl()->Do_CTR_Chunk(plaintext_chunk, chunk_len,
            ciphertext_out, get_impl()->tx_counter,
            get_impl()->tx_partial_block, get_impl()->tx_partial_len))
            return false;

        return HMAC_Bridge::Update(
            get_impl()->tx_mac_ctx, ciphertext_out, chunk_len)
            == HMAC_Bridge::SECURE_TRUE;
    }

    bool HTS_Security_Session::Protect_End(uint8_t* mac_tag_out) noexcept {
        if (!get_impl() || !get_impl()->is_session_active || !mac_tag_out)
            return false;
        return HMAC_Bridge::Final(get_impl()->tx_mac_ctx, mac_tag_out)
            == HMAC_Bridge::SECURE_TRUE;
    }

    // =====================================================================
    //  수신 스트리밍 API
    // =====================================================================
    bool HTS_Security_Session::Unprotect_Begin() noexcept {
        if (!get_impl() || !get_impl()->is_session_active) return false;
        return HMAC_Bridge::Init(
            get_impl()->rx_mac_ctx, get_impl()->session_mac_key, 32)
            == HMAC_Bridge::SECURE_TRUE;
    }

    bool HTS_Security_Session::Unprotect_Feed(
        const uint8_t* ciphertext_chunk, size_t chunk_len) noexcept {

        if (!get_impl() || !get_impl()->is_session_active ||
            !ciphertext_chunk || chunk_len == 0)
            return false;
        return HMAC_Bridge::Update(
            get_impl()->rx_mac_ctx, ciphertext_chunk, chunk_len)
            == HMAC_Bridge::SECURE_TRUE;
    }

    bool HTS_Security_Session::Unprotect_Verify(
        const uint8_t* received_mac_tag) noexcept {

        if (!get_impl() || !get_impl()->is_session_active || !received_mac_tag)
            return false;

        const bool mac_ok = (HMAC_Bridge::Verify_Final(
            get_impl()->rx_mac_ctx, received_mac_tag)
            == HMAC_Bridge::SECURE_TRUE);
        if (!mac_ok) {
            Terminate_Session();
            return false;
        }
        return true;
    }

    bool HTS_Security_Session::Decrypt_Chunk(
        const uint8_t* ciphertext_chunk, size_t chunk_len,
        uint8_t* plaintext_out) noexcept {

        if (!get_impl() || !get_impl()->is_session_active ||
            !ciphertext_chunk || !plaintext_out || chunk_len == 0)
            return false;

        return get_impl()->Do_CTR_Chunk(ciphertext_chunk, chunk_len,
            plaintext_out, get_impl()->rx_counter,
            get_impl()->rx_partial_block, get_impl()->rx_partial_len);
    }

    // =====================================================================
    //  단일 호출 API
    // =====================================================================
    bool HTS_Security_Session::Protect_Payload(
        const uint8_t* plaintext, size_t length,
        uint8_t* ciphertext_out, uint8_t* mac_tag_out) noexcept {

        if (!Protect_Begin()) return false;
        if (!Protect_Chunk(plaintext, length, ciphertext_out)) return false;
        return Protect_End(mac_tag_out);
    }

    bool HTS_Security_Session::Unprotect_Payload(
        const uint8_t* ciphertext, size_t length,
        const uint8_t* received_mac_tag,
        uint8_t* plaintext_out) noexcept {

        if (!Unprotect_Begin()) return false;
        if (!Unprotect_Feed(ciphertext, length)) return false;
        if (!Unprotect_Verify(received_mac_tag)) return false;
        return Decrypt_Chunk(ciphertext, length, plaintext_out);
    }

    // =====================================================================
    //  Terminate_Session — 안티포렌식 세션 종료
    // =====================================================================
    void HTS_Security_Session::Terminate_Session() noexcept {
        if (get_impl()) {
            get_impl()->Clean_State();
        }
    }

} // namespace ProtectedEngine
