// =========================================================================
// HTS_Dynamic_Key_Rotator.hpp
// 파일 I/O 및 스토리지 동적 키 로테이터 (블랙박스 은닉형)
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [설계 목적]
//  장기 세션에서 동일 키로 반복 암호화 시 발생하는 통계적 공격 차단
//  N회 연산마다 키를 자동 갱신하여 동일 키 노출 횟수를 제한
//
//  [사용법]
//   Dynamic_Key_Rotator rotator(session_id, 1048576);
//   for (size_t i = 0; i < elements; ++i) {
//       uint64_t key = rotator.Get_Current_Key_And_Rotate();
//       data[i] ^= static_cast<uint32_t>(key);
//   }
//
//  [보안 설계]
//   internal_state: PRNG 은닉 상태 (외부 미노출 — Forward/Backward Secrecy)
//   current_key: Murmur3(state) ^ state 단방향 파생 (역산 불가)
//   소멸자: internal_state + current_key + 카운터 전체 보안 소거
//   복사/이동: = delete (키 상태 복제 원천 차단)
//   키 파생: LCG(은닉 상태) → Murmur3 ^ state (Davies-Meyer 유사)
//
//  [양산 수정 이력 — 세션 1 (6건) + 세션 5 (7건) = 총 13건]
//   세션 1: BUG-01~06 (interval=0, Murmur3, pragma O0, C26495,
//           이전 키 소거, 오버플로)
//   세션 5: BUG-07~13 (소멸자, move 차단, nodiscard, Doxygen, cstddef,
//           Forward/Backward Secrecy 상태분리, 데드코드 제거)
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    class Dynamic_Key_Rotator {
    public:
        /// @brief 동적 키 로테이터 생성
        /// @param initial_key  세션 ID 또는 PQC 파생 키 (0 → 골든 레이시오 폴백)
        /// @param interval     키 회전 주기 (연산 횟수, 0 → 최소 1024로 보정)
        Dynamic_Key_Rotator(uint64_t initial_key, uint64_t interval) noexcept;

        /// @brief 소멸자 — internal_state + current_key + 카운터 보안 소거
        ~Dynamic_Key_Rotator() noexcept;

        /// 키 상태 복제/이동 원천 차단
        Dynamic_Key_Rotator(const Dynamic_Key_Rotator&) = delete;
        Dynamic_Key_Rotator& operator=(const Dynamic_Key_Rotator&) = delete;
        Dynamic_Key_Rotator(Dynamic_Key_Rotator&&) = delete;
        Dynamic_Key_Rotator& operator=(Dynamic_Key_Rotator&&) = delete;

        /// @brief 현재 키 반환 + 자동 회전 검사
        /// @return 현재 세션 키 (64비트)
        /// @note  호출마다 operation_count 증가, interval 도달 시 키 파생
        [[nodiscard]]
        uint64_t Get_Current_Key_And_Rotate() noexcept;

    private:
        uint64_t current_key = 0;
        uint64_t internal_state = 0;    ///< PRNG 은닉 상태 (외부 미노출)
        uint64_t rotation_interval = 0;
        uint64_t operation_count = 0;
    };

} // namespace ProtectedEngine