// =========================================================================
// HTS_PUF_Adapter.h
// PUF (Physical Unclonable Function) 하드웨어 시드 추출 어댑터
// Target: STM32F407 (Cortex-M4)
//
// [양산 수정]
//  1. ProtectedEngine 네임스페이스 추가 (프로젝트 일관성)
//  2. 미사용 #include "HTS_Secure_Memory.h" 제거
// =========================================================================
#pragma once

#include <vector>
#include <cstdint>

namespace ProtectedEngine {

    class PUF_Adapter {
    public:
        // PUF 칩에 Challenge를 인가하여 고유 Response(시드)를 추출
        // ARM: 하드웨어 레지스터 직접 읽기
        // PC:  목업 데이터 반환 (테스트용)
        static void getHardwareSeed(
            const std::vector<uint8_t>& challenge,
            std::vector<uint8_t>& out_seed) noexcept;

        /// @brief PUF 시드 추출 — 고정 배열 API (ARM Zero-Heap)
        /// @param challenge     챌린지 배열 (nullptr 불가)
        /// @param challenge_len 챌린지 길이
        /// @param out_buf       출력 버퍼 (호출자 제공)
        /// @param buf_size      출력 버퍼 크기 (최소 32 권장)
        /// @param out_len       실제 출력 바이트 수
        /// @return true=성공, false=실패
        [[nodiscard]]
        static bool getHardwareSeed_Fixed(
            const uint8_t* challenge, size_t challenge_len,
            uint8_t* out_buf, size_t buf_size,
            size_t* out_len) noexcept;
    };

} // namespace ProtectedEngine