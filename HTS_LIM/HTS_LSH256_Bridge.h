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
// [양산 수정]
//  1. Secure_Zero: pragma O0 보호 추가
//  2. Do_Hash: 실패 시 출력 버퍼 소거 (정보 누출 방지)
//  3. 매직 넘버 → 명명 상수 일관 사용
//  4. 문서화 보강 (KCMVP 인증 범위, 용도)
// =========================================================================
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

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
        [[nodiscard]] static bool Hash_256(
            const uint8_t* data, size_t data_len,
            uint8_t* output_32) noexcept;

        // =================================================================
        //  Hash_224 — LSH-224 해시 (28바이트 출력)
        //
        //  data:      입력 데이터 (null 시 data_len=0 필수)
        //  data_len:  바이트 단위 (0 허용 — 빈 메시지 해시)
        //  output_28: 출력 버퍼 — 반드시 28바이트 이상
        //  실패 시: output_28을 0으로 소거 (정보 누출 방지)
        // =================================================================
        [[nodiscard]] static bool Hash_224(
            const uint8_t* data, size_t data_len,
            uint8_t* output_28) noexcept;
    };

} // namespace ProtectedEngine