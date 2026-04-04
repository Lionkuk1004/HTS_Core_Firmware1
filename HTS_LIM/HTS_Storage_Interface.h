// =========================================================================
// HTS_Storage_Interface.h
// 스토리지 보안 레이어 (PQC 키 브릿지 + 유니버설 어댑터)
// Target: 통합콘솔 (A55 Linux) / PC (STM32 베어메탈 제외)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [설계 목적]
//  PQC(Post-Quantum Cryptography) 키 브릿지와 유니버설 어댑터를
//  결합하여 파일 단위 보안 스트림(암호화 + L1 힐링)을 제공합니다.
//
//  [사용법]
//   Storage_Interface si;
//   si.Initialize_Storage(pqc_seed);      // PQC 시드 주입 + 장치 초기화
//   si.Protect_File(buffer);              // TX: 전체 파일 보안 스트림
//   si.Self_Heal_File(damaged);           // RX: 전체 파일 복구 스트림
//   si.Protect_File_Partial(buf, buf_u32_len, n, offset); // TX: 부분 키 로테이션 (원시 버퍼)
//
//  [보안 설계]
//   file_session_id: Quantum_Key_Bridge CTR 동기화 기반
//   Protect_File_Partial: Dynamic_Key_Rotator 스택 + 반환 직전 SecureMemory 파쇄(이중 방어)
//   키 로테이션: 1,048,576 연산마다 키 자동 갱신 (통계적 공격 차단)
//   동일 파일·메타데이터 고빈도 갱신 시 호스트 스토리지(eMMC/SSD) 마모 — FS/드라이버
//   웨어 레벨링·저널 정책은 플랫폼 가이드와 병행 검토.
//
//  [플랫폼]
//   통합콘솔 (A55 Linux): 정상 동작 — Linux 파일시스템 + DDR 힙 사용 가능
//   PC 개발빌드:          정상 동작 — 디버그/테스트
//   STM32 (Cortex-M4):    #error 차단 — 베어메탈에 파일시스템 없음 + 힙 금지
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

// STM32 (Cortex-M) 빌드 차단 — 베어메탈에 파일시스템 없음 + 힙 금지
// A55 (aarch64) Linux는 차단 대상 아님 — 파일시스템 + DDR 힙 사용 가능
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#error "[HTS_FATAL] HTS_Storage_Interface는 A55 Linux/PC 전용입니다. STM32 베어메탈 빌드에서 제외하십시오."
#endif

#include <vector>
#include <string>
#include "HTS_Universal_Adapter.h"
#include "HTS_Quantum_Key_Bridge.h"

namespace ProtectedEngine {

    /// @brief 스토리지 보안 레이어 (A55 Linux / PC 전용)
    /// @note  STM32 빌드 시 #error 발생 — 베어메탈에 파일시스템 없음
    class Storage_Interface {
    private:
        HTS_Adapter adapter;                ///< 유니버설 디바이스 어댑터
        Quantum_Key_Bridge key_bridge;      ///< PQC 키 브릿지
        uint64_t file_session_id = 0;       ///< CTR 동기화 세션 ID

    public:
        /// @brief PQC 시드 주입 + 장치 초기화
        /// @param pqc_seed  양자 엔트로피 시드 (32~64바이트)
        void Initialize_Storage(const std::vector<uint8_t>& pqc_seed) noexcept;

        /// @brief 전체 파일 보안 스트림 (암호화)
        /// @param file_buffer  원본 데이터 (in-place 변환)
        /// @return true = 성공
        /// @note H-1: 비어 있지 않은 경우 `data()!=nullptr` 이어야 함(방어적 false)
        [[nodiscard]]
        bool Protect_File(std::vector<uint32_t>& file_buffer) noexcept;

        /// @brief 전체 파일 복구 스트림 (복호화 + L1 힐링)
        /// @param damaged_buffer  손상 데이터 (in-place 복원)
        /// @return true = 성공
        /// @note H-1: 비어 있지 않은 경우 `data()!=nullptr` 이어야 함(방어적 false)
        [[nodiscard]]
        bool Self_Heal_File(std::vector<uint32_t>& damaged_buffer) noexcept;

        /// @brief 부분 키 로테이션 암호화 (힙 STL 미사용 — 원시 버퍼만)
        /// @param buffer            uint32_t 단위 버퍼 (in-place XOR)
        /// @param buffer_u32_length 버퍼에 있는 uint32_t 개수(용량)
        /// @param elements          처리 상한(실제 처리 = min(용량, elements), 분기 없는 min)
        /// @param chunk_offset      청크 시작 오프셋 — FNV-1a 64로 file_session_id와 혼합되어 시드 도출
        ///
        /// chunk_offset 필수 — 매 청크 고유 값. 8바이트 정렬 시 64비트 XOR 1회/키로 처리.
        void Protect_File_Partial(
            uint32_t* buffer,
            size_t buffer_u32_length,
            size_t elements,
            uint64_t chunk_offset) noexcept;
    };

} // namespace ProtectedEngine