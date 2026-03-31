// =========================================================================
// HTS_OTA_AMI_Manager.h
// AMI 계량기 보안 일제 무선 펌웨어 갱신 (Secure FUOTA)
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  [보안 계층] KCMVP 인증 기반
//
//   ① HMAC-LSH256 전체 서명
//     서버: HMAC(fw_key, nonce‖version‖firmware) → 32B 서명
//     장비: 수신 완료 후 동일 HMAC 계산 → 비교
//     → 사전 공유 키 없이는 위조 불가
//
//   ② 세션 논스 (Anti-Replay)
//     매 OTA 세션마다 서버가 8B 랜덤 논스 생성
//     장비: 이전 논스와 중복 시 거부
//     → 녹음 재전송 공격 차단
//
//   ③ 청크별 MAC (부분 주입 방지)
//     각 청크: 4B 절삭 HMAC = HMAC(chunk_key, idx‖data)[0:4]
//     → 개별 청크 변조 즉시 감지
//
//   ④ CRC32 (전송 무결성, 비보안)
//     RF 노이즈/비트 에러 감지용 (기존 유지)
//
//  [암호 HAL]
//   LSH256_Bridge / ARIA_Bridge 등 기존 KCMVP 모듈 연동
//   콜백 구조체로 주입 → 모듈 독립성 유지
//
//  @warning sizeof ≈ 560B — 전역/정적 배치 권장
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    class HTS_Priority_Scheduler;

    enum class AMI_OtaState : uint8_t {
        IDLE = 0u,
        RECEIVING = 1u,
        NACK_WAIT = 2u,
        VERIFYING = 3u,
        READY = 4u,
        FAILED = 5u,
    };

    /// @brief OTA 실패 사유
    enum class AMI_OtaReject : uint8_t {
        NONE = 0u,
        VERSION_OLD = 1u,   ///< 안티 롤백 거부
        NONCE_REPLAY = 2u,   ///< 재전송 공격 감지
        HMAC_FAIL = 3u,   ///< 서명 불일치 (위조)
        CHUNK_MAC_FAIL = 4u,   ///< 청크 MAC 불일치
        CRC_FAIL = 5u,   ///< CRC32 불일치 (비트에러)
        SIZE_MISMATCH = 6u,   ///< size↔chunks 불일치
        TIMEOUT = 7u,
        FLASH_FAIL = 8u,
    };

    static constexpr size_t OTA_BITMAP_SIZE = 256u;
    static constexpr size_t OTA_HMAC_SIZE = 32u;   // LSH-256 = 32B
    static constexpr size_t OTA_NONCE_SIZE = 8u;
    static constexpr size_t OTA_CHUNK_MAC_SIZE = 4u;     // 절삭 HMAC

    /// @brief 암호 HAL 콜백 (KCMVP 모듈 연동)
    struct OTA_Crypto_Callbacks {
        /// @brief HMAC-LSH256 전체 계산
        /// @param key      32B 키
        /// @param data     입력 데이터
        /// @param data_len 길이
        /// @param out_mac  32B 출력
        /// @return true = 성공
        bool (*hmac_lsh256)(
            const uint8_t* key,
            const uint8_t* data, size_t data_len,
            uint8_t* out_mac);

        /// @brief HMAC-LSH256 점진적: 초기화
        void (*hmac_init)(const uint8_t* key);
        /// @brief HMAC-LSH256 점진적: 블록 추가
        void (*hmac_update)(const uint8_t* data, size_t len);
        /// @brief HMAC-LSH256 점진적: 최종 MAC 출력
        void (*hmac_final)(uint8_t* out_mac);

        /// @brief 보안 랜덤 (논스 검증용)
        bool (*secure_random)(uint8_t* out, size_t len);
    };

    class HTS_OTA_AMI_Manager {
    public:
        static constexpr size_t   CHUNK_SIZE = 256u;
        static constexpr size_t   MAX_CHUNKS = 2048u;
        static constexpr uint32_t NACK_TIMEOUT_MS = 10000u;
        static constexpr uint32_t OTA_TIMEOUT_MS = 300000u;
        static constexpr uint8_t  MAX_NACK_ROUNDS = 5u;

        explicit HTS_OTA_AMI_Manager(
            uint16_t my_id, uint32_t current_version) noexcept;
        ~HTS_OTA_AMI_Manager() noexcept;

        HTS_OTA_AMI_Manager(const HTS_OTA_AMI_Manager&) = delete;
        HTS_OTA_AMI_Manager& operator=(const HTS_OTA_AMI_Manager&) = delete;
        HTS_OTA_AMI_Manager(HTS_OTA_AMI_Manager&&) = delete;
        HTS_OTA_AMI_Manager& operator=(HTS_OTA_AMI_Manager&&) = delete;

        // ─── 암호 HAL 등록 ──────────────────────────────

        void Register_Crypto(const OTA_Crypto_Callbacks& cb) noexcept;

        // ─── 보안 OTA 수신 ──────────────────────────────

        /// @brief BEGIN: 메타데이터 + 논스 + 서명
        /// @param new_version    새 펌웨어 버전
        /// @param total_size     전체 바이트 수
        /// @param total_chunks   청크 수
        /// @param nonce          8B 세션 논스
        /// @param expected_hmac  32B HMAC-LSH256 서명
        /// @param expected_crc32 CRC32 (전송 무결성)
        [[nodiscard]]
        bool On_Begin(uint32_t new_version, uint32_t total_size,
            uint16_t total_chunks,
            const uint8_t* nonce,
            const uint8_t* expected_hmac,
            uint32_t expected_crc32) noexcept;

        /// @brief CHUNK: 데이터 + 4B 절삭 MAC
        /// @param chunk_idx  인덱스
        /// @param data       청크 데이터
        /// @param data_len   길이
        /// @param chunk_mac  4B 절삭 HMAC (nullptr=MAC 미검증)
        [[nodiscard]]
        bool On_Chunk(uint16_t chunk_idx,
            const uint8_t* data, size_t data_len,
            const uint8_t* chunk_mac) noexcept;

        void On_Broadcast_Complete(uint32_t systick_ms) noexcept;

        [[nodiscard]]
        uint16_t Get_NACK_Bitmap(uint8_t* out_bitmap) const noexcept;

        [[nodiscard]] bool Is_Complete() const noexcept;

        /// @brief 보안 검증: CRC32 + HMAC-LSH256 (점진적)
        [[nodiscard]] bool Verify() noexcept;

        void Commit() noexcept;
        void Abort() noexcept;

        [[nodiscard]] AMI_OtaState  Get_State() const noexcept;
        [[nodiscard]] AMI_OtaReject Get_Reject_Reason() const noexcept;
        [[nodiscard]] uint8_t       Get_Progress_Pct() const noexcept;
        [[nodiscard]] uint16_t      Get_Received_Count() const noexcept;

        void Tick(uint32_t systick_ms) noexcept;
        void Shutdown() noexcept;

    private:
        static constexpr size_t IMPL_BUF_SIZE = 560u;
        static constexpr size_t IMPL_BUF_ALIGN = 8u;
        struct Impl;
        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        bool impl_valid_ = false;
        Impl* get_impl() noexcept;
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine