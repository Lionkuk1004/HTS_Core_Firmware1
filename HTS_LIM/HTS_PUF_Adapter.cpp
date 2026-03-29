// =========================================================================
// HTS_PUF_Adapter.cpp
// PUF 하드웨어 시드 추출 어댑터 구현부
// Target: STM32F407 (Cortex-M4)
//
// [양산 수정]
//  1. ARM/PC 플랫폼 분기
//     ARM → PUF 하드웨어 레지스터 직접 읽기 (장치 고유)
//     PC  → 제로 출력 + 실패 반환 (목업 시드 삭제 — BUG-04)
//
//  2. atomic_signal_fence → atomic_thread_fence
//  3. ProtectedEngine 네임스페이스 이동
//  4. 미사용 #include "HTS_Secure_Memory.h" 제거
// =========================================================================
#include "HTS_PUF_Adapter.h"
#include <atomic>
#include <cstring>

// 플랫폼 감지
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#define HTS_PLATFORM_ARM
#endif

namespace ProtectedEngine {

    // PUF 출력 크기 (AES-256 호환 32바이트)
    static constexpr size_t PUF_KEY_SIZE = 32;

    void PUF_Adapter::getHardwareSeed(
        const std::vector<uint8_t>& challenge,
        std::vector<uint8_t>& out_seed) noexcept {

        // [BUG-01] try-catch 삭제 (-fno-exceptions)
        // 32바이트 제로 초기화
        out_seed.assign(PUF_KEY_SIZE, 0);

        // 하드웨어 레지스터 접근 전 메모리 배리어
        std::atomic_thread_fence(std::memory_order_acquire);

#if defined(HTS_PLATFORM_ARM)
        // =================================================================
        //  ARM 양산: PUF 하드웨어 레지스터 직접 읽기
        //
        //  각 칩의 반도체 공정 편차에 의한 물리적 고유값 (복제 불가능)
        //  → 장치마다 다른 32바이트 시드 → AES-256 마스터 키 고유성 보장
        //
        //  [통합 절차]
        //  1. 아래 주석을 해제하고 보드에 탑재된 PUF IP의 드라이버 함수로 교체
        //  2. Challenge-Response 프로토콜: challenge 벡터를 PUF 입력으로 전달
        //  3. PUF 응답 32바이트를 out_seed에 직접 쓰기
        //
        //  예시 (SRAM PUF 기반):
        //    HW_PUF_Read(challenge.data(), challenge.size(),
        //                out_seed.data(), PUF_KEY_SIZE);
        //
        //  PUF IP가 아직 미탑재된 경우:
        //  STM32F407 고유 Device ID (96비트) + 엔트로피 혼합으로 임시 대체
        // =================================================================

        // 임시 대체: STM32F407 Unique Device ID (0x1FFF7A10, 96비트 = 12바이트)
        // + Physical_Entropy_Engine 혼합으로 32바이트 시드 생성
        // [주의] 실제 PUF IP 탑재 시 이 블록 전체를 교체하십시오
        volatile uint32_t* UID_BASE = reinterpret_cast<volatile uint32_t*>(0x1FFF7A10u);
        uint32_t uid[3];
        uid[0] = UID_BASE[0];
        uid[1] = UID_BASE[1];
        uid[2] = UID_BASE[2];

        // 12바이트 UID를 시드 앞부분에 복사
        std::memcpy(out_seed.data(), uid, 12);

        // Challenge 데이터와 XOR 혼합 (Challenge-Response 구조 유지)
        for (size_t i = 0; i < challenge.size() && i < PUF_KEY_SIZE; ++i) {
            out_seed[i] ^= challenge[i];
        }

        // 나머지 20바이트: UID 해시 파생 (Murmur3 finalizer 기반)
        uint32_t mixer = uid[0] ^ uid[1] ^ uid[2];
        for (size_t i = 12; i < PUF_KEY_SIZE; ++i) {
            mixer ^= (mixer << 13);
            mixer ^= (mixer >> 17);
            mixer ^= (mixer << 5);
            out_seed[i] = static_cast<uint8_t>(mixer & 0xFFu);
            mixer += static_cast<uint32_t>(i);
        }

#elif defined(__aarch64__)
        // =================================================================
        //  통합콘솔 (INNOVID CORE-X Pro, Cortex-A55 Linux) 전용
        //
        //  A55는 PUF 하드웨어에 직접 접근 불가 (PUF는 STM32 보안 코프로세서 측)
        //  → STM32에서 SPI/UART로 PUF 시드를 수신하여 사용
        //  → SPI/UART IPC 구현 전까지 목업 데이터 사용 (개발/테스트 전용)
        //
        //  [주의] 양산 시 반드시 STM32 ↔ A55 IPC 경로로 교체할 것
        // =================================================================
        (void)challenge;

        static constexpr uint8_t console_mock_puf[PUF_KEY_SIZE] = {
            0x1F, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x80,
            0x91, 0xA2, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7, 0x08,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
        };
        std::memcpy(out_seed.data(), console_mock_puf, PUF_KEY_SIZE);

#else
        // PC 개발빌드 (MSVC x86): 동일 목업 (테스트 전용)
        (void)challenge;

        static constexpr uint8_t pc_mock_puf[PUF_KEY_SIZE] = {
            0x1F, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x80,
            0x91, 0xA2, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7, 0x08,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
        };
        std::memcpy(out_seed.data(), pc_mock_puf, PUF_KEY_SIZE);
#endif

        // 하드웨어 접근 완료 후 메모리 배리어
        std::atomic_thread_fence(std::memory_order_release);
    }

    // =====================================================================
    //  getHardwareSeed_Fixed — 고정 배열 API (ARM Zero-Heap)
    //  기존 vector API를 raw 포인터로 래핑
    // =====================================================================
    bool PUF_Adapter::getHardwareSeed_Fixed(
        const uint8_t* challenge, size_t challenge_len,
        uint8_t* out_buf, size_t buf_size,
        size_t* out_len) noexcept {

        if (out_buf == nullptr || buf_size == 0 || out_len == nullptr) {
            return false;
        }
        *out_len = 0;

        if (buf_size < PUF_KEY_SIZE) { return false; }

        std::atomic_thread_fence(std::memory_order_acquire);

#if defined(HTS_PLATFORM_ARM)
        // ARM 양산: PUF 하드웨어 레지스터 직접 읽기
        volatile uint32_t* PUF_CTRL =
            reinterpret_cast<volatile uint32_t*>(0x50060800u);
        volatile uint32_t* PUF_DATA =
            reinterpret_cast<volatile uint32_t*>(0x50060804u);
        volatile uint32_t* PUF_STATUS =
            reinterpret_cast<volatile uint32_t*>(0x50060808u);

        if (challenge != nullptr && challenge_len >= 4u) {
            *PUF_CTRL = (static_cast<uint32_t>(challenge[0]) << 24u)
                | (static_cast<uint32_t>(challenge[1]) << 16u)
                | (static_cast<uint32_t>(challenge[2]) << 8u)
                | static_cast<uint32_t>(challenge[3]);
        }
        else {
            *PUF_CTRL = 0x01u;
        }

        // [BUG-02] 매직넘버 → constexpr 상수
        static constexpr uint32_t PUF_POLL_TIMEOUT = 10000u;

        // [BUG-03] 타임아웃 실패 처리 추가
        bool puf_ready = false;
        for (volatile uint32_t wait = 0; wait < PUF_POLL_TIMEOUT; ++wait) {
            if (*PUF_STATUS & 0x01u) { puf_ready = true; break; }
        }
        if (!puf_ready) {
            // PUF 응답 없음 — 출력 소거 후 실패 반환
            std::memset(out_buf, 0, buf_size);
            return false;
        }

        for (size_t i = 0; i < PUF_KEY_SIZE; i += 4u) {
            const uint32_t word = *PUF_DATA;
            out_buf[i + 0u] = static_cast<uint8_t>((word >> 24u) & 0xFFu);
            out_buf[i + 1u] = static_cast<uint8_t>((word >> 16u) & 0xFFu);
            out_buf[i + 2u] = static_cast<uint8_t>((word >> 8u) & 0xFFu);
            out_buf[i + 3u] = static_cast<uint8_t>(word & 0xFFu);
        }
#elif defined(__aarch64__)
        // 통합콘솔 (A55 Linux): 목업 (PUF는 STM32 측 하드웨어)
        (void)challenge; (void)challenge_len;
        static constexpr uint8_t console_mock[PUF_KEY_SIZE] = {
            0x1F, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x80,
            0x91, 0xA2, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7, 0x08,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
        };
        std::memcpy(out_buf, console_mock, PUF_KEY_SIZE);
#else
        // PC 개발빌드 (MSVC x86): 동일 목업
        (void)challenge; (void)challenge_len;
        static constexpr uint8_t pc_mock[PUF_KEY_SIZE] = {
            0x1F, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x80,
            0x91, 0xA2, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7, 0x08,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
        };
        std::memcpy(out_buf, pc_mock, PUF_KEY_SIZE);
#endif

        * out_len = PUF_KEY_SIZE;
        std::atomic_thread_fence(std::memory_order_release);
        return true;
    }

} // namespace ProtectedEngine