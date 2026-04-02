// =========================================================================
// HTS_LEA_Bridge.h
// KCMVP 승인 알고리즘: LEA 블록 암호 CTR 모드 브릿지
// 규격: TTAS.KO-12.0223 (LEA)
// 제공: KISA (한국인터넷진흥원)
// Target: STM32F407 (Cortex-M4)
//
// [KCMVP 인증 범위]
//  LEA-128 (24라운드), LEA-192 (28라운드), LEA-256 (32라운드)
//  블록 크기: 128비트 (16바이트) 고정
//  운용 모드: CTR (카운터 모드 — 스트림 암호화)
//
// [CTR 모드 보안 요건]
//  동일 (키, IV) 쌍으로 동일 평문을 암호화하면 동일 암호문 생성
//  → 동일 키 하에서 IV 재사용은 절대 금지 (키스트림 반복 → 평문 XOR 노출)
//  → 매 세션 또는 매 전송마다 고유 IV 사용 필수
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
#include <atomic>
#include "lea.h"

namespace ProtectedEngine {

    class LEA_Bridge {
    public:
        static constexpr uint32_t SECURE_TRUE = 0x5A5A5A5Au;
        static constexpr uint32_t SECURE_FALSE = 0xA5A5A5A5u;

        /// @note 성공/실패 모두 비영(0) — if(api()) 불가. 반드시
        ///       `api(...) == SECURE_TRUE` 로 판정 (기준서 G-2 / 호출 계약)

        LEA_Bridge() noexcept;
        ~LEA_Bridge() noexcept;

        // 키 소재 복사 경로 원천 차단
        LEA_Bridge(const LEA_Bridge&) = delete;
        LEA_Bridge& operator=(const LEA_Bridge&) = delete;
        LEA_Bridge(LEA_Bridge&&) = delete;
        LEA_Bridge& operator=(LEA_Bridge&&) = delete;

        // =================================================================
        //  Initialize — LEA 키 스케줄 + IV 설정
        //
        //  master_key:      마스터 키 (null 불가)
        //  key_len_bytes:   16(128bit) / 24(192bit) / 32(256bit)
        //  initial_vector:  128비트 초기 카운터 (16바이트, null 불가)
        // =================================================================
        [[nodiscard]] uint32_t Initialize(
            const uint8_t* master_key,
            uint32_t       key_len_bytes,
            const uint8_t* initial_vector) noexcept;

        // =================================================================
        //  Encrypt_Payload — LEA-CTR 암호화 (인플레이스)
        //
        //  CTR 카운터: KISA lea_ctr_enc가 내부 증가 (수동 증가 불필요)
        //  payload_data는 4바이트 정렬된 버퍼여야 함 (uint32_t* 계약)
        // =================================================================
        [[nodiscard]] uint32_t Encrypt_Payload(
            uint32_t* payload_data, size_t elements) noexcept;

        // =================================================================
        //  Decrypt_Payload — LEA-CTR 복호화 (인플레이스)
        //
        //  CTR 카운터: KISA lea_ctr_dec가 내부 증가 (수동 증가 불필요)
        //  payload_data는 4바이트 정렬된 버퍼여야 함 (uint32_t* 계약)
        // =================================================================
        [[nodiscard]] uint32_t Decrypt_Payload(
            uint32_t* payload_data, size_t elements) noexcept;

    private:
        // [C26495] LEA_KEY는 POD — 값 초기화는 생성자에서 Secure_Zero로 수행
        LEA_KEY  session_key;
        uint8_t  iv_counter[16] = {};   // CTR 모드 128비트 카운터
        bool     is_initialized = false;
        std::atomic_flag op_busy_ = ATOMIC_FLAG_INIT;
    };

} // namespace ProtectedEngine
