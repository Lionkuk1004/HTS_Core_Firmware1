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
// [양산 수정 — 6건]
//  1. [CRITICAL] Secure_Zero_Self() 미정의 → LNK2019 제거
//  2. [CRITICAL] KISA lea_ctr_enc/dec가 CTR 내부 증가 → 수동 증가 이중 카운팅 제거
//  3. [MEDIUM] Secure_Zero: pragma O0 보호 추가
//  4. [MEDIUM] C26495 멤버 기본값 초기화
//  5. [MEDIUM] [[nodiscard]] 추가
//  6. [LOW] Initialize 내 이중 Secure_Zero 호출 정리
// =========================================================================
#pragma once

#include <cstdint>
#include <cstddef>
#include "lea.h"

namespace ProtectedEngine {

    class LEA_Bridge {
    public:
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
        [[nodiscard]] bool Initialize(
            const uint8_t* master_key,
            uint32_t       key_len_bytes,
            const uint8_t* initial_vector) noexcept;

        // =================================================================
        //  Encrypt_Payload — LEA-CTR 암호화 (인플레이스)
        //
        //  CTR 카운터: KISA lea_ctr_enc가 내부 증가 (수동 증가 불필요)
        // =================================================================
        [[nodiscard]] bool Encrypt_Payload(
            uint32_t* payload_data, size_t elements) noexcept;

        // =================================================================
        //  Decrypt_Payload — LEA-CTR 복호화 (인플레이스)
        //
        //  CTR 카운터: KISA lea_ctr_dec가 내부 증가 (수동 증가 불필요)
        // =================================================================
        [[nodiscard]] bool Decrypt_Payload(
            uint32_t* payload_data, size_t elements) noexcept;

    private:
        // [C26495] LEA_KEY는 POD — 값 초기화는 생성자에서 Secure_Zero로 수행
        LEA_KEY  session_key;
        uint8_t  iv_counter[16] = {};   // CTR 모드 128비트 카운터
        bool     is_initialized = false;
    };

} // namespace ProtectedEngine