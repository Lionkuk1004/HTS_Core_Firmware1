// =========================================================================
// HTS_LSH256_Bridge.h
// KCMVP 승인 알고리즘: LSH-256 / LSH-224 해시 브릿지
// 규격: KS X 3262
// 제공: NSR (국가보안기술연구소)
// Target: STM32F407 (Cortex-M4)
//
// [KCMVP 인증 범위]
//  LSH-256-256: 32바이트(256비트) 해시 출력
//  LSH-256-224: 28바이트(224비트) 해시 출력
//
// [용도]
//  펌웨어 무결성 측정 (Remote_Attestation 보조)
//  키 파생 함수(KDF) 입력 전처리
//  디지털 서명 전 해시
//
#pragma once
// ─────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────
//  [사용법] 기본 사용 예시를 여기에 기재하세요.
//  [메모리] sizeof(클래스명) 확인 후 전역/정적 배치 필수.
//  [보안]   복사/이동 연산자 = delete (키 소재 복제 차단).
//
//  ⚠ [파트너사 필수 확인]
//    HW 레지스터 주소(UART/WDT 등)는 보드 설계에 맞게 교체.
//    IRQ 번호는 STM32F407 RM0090 벡터 테이블 기준으로 교체.
// ─────────────────────────────────────────────────────────

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {
    static const uint32_t LSH_SECURE_TRUE = 0x5A5A5A5Au;
    static const uint32_t LSH_SECURE_FALSE = 0xA5A5A5A5u;

    /// @note 성공/실패 모두 비영(0) — if(Hash_*()) 불가.
    ///       `Hash_*(...) == LSH_SECURE_TRUE` 로 판정 (기준서 G-2 / 호출 계약)

    // LSH 출력 길이 상수 (바이트)
    static const size_t LSH256_DIGEST_BYTES = 32u;
    static const size_t LSH224_DIGEST_BYTES = 28u;

    class LSH256_Bridge {
    public:
        // 인스턴스 생성 금지 — 정적 유틸리티 클래스
        LSH256_Bridge() = delete;
        LSH256_Bridge(const LSH256_Bridge&) = delete;
        LSH256_Bridge& operator=(const LSH256_Bridge&) = delete;
        LSH256_Bridge(LSH256_Bridge&&) = delete;
        LSH256_Bridge& operator=(LSH256_Bridge&&) = delete;

        // =================================================================
        //  Hash_256 — LSH-256 해시 (32바이트 출력)
        //
        //  data:      입력 데이터 (null 시 data_len=0 필수)
        //  data_len:  바이트 단위 (0 허용 — 빈 메시지 해시)
        //  output_32: 출력 버퍼 — 반드시 32바이트 이상
        //  실패 시: output_32를 0으로 소거 (정보 누출 방지)
        // =================================================================
        [[nodiscard]] static uint32_t Hash_256(
            const uint8_t* data, size_t data_len,
            uint8_t* output_32) noexcept;

        /// @brief 장시간 Flash 연속 해시용 — 64KB 단위 lsh256_update 후 callback (IWDG 피드 등).
        ///        알고리즘 출력은 Hash_256(단일 update)과 동일.
        [[nodiscard]] static uint32_t Hash_256_WithPeriodicCallback(
            const uint8_t* data, size_t data_len,
            uint8_t* output_32,
            void (*callback)(void)) noexcept;

        // =================================================================
        //  Hash_224 — LSH-224 해시 (28바이트 출력)
        //
        //  data:      입력 데이터 (null 시 data_len=0 필수)
        //  data_len:  바이트 단위 (0 허용 — 빈 메시지 해시)
        //  output_28: 출력 버퍼 — 반드시 28바이트 이상
        //  실패 시: output_28을 0으로 소거 (정보 누출 방지)
        // =================================================================
        [[nodiscard]] static uint32_t Hash_224(
            const uint8_t* data, size_t data_len,
            uint8_t* output_28) noexcept;
    };

} // namespace ProtectedEngine
