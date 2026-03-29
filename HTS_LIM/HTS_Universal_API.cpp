// =========================================================================
// HTS_Universal_API.cpp
// ProtectedEngine 내부 보안 게이트 / 세션 검증 / 물리적 파쇄
// Target: STM32F407VGT6 (Cortex-M4F, 168MHz)
//
// [양산 수정 이력 — 13건]
//  BUG-01 [CRIT] Secure_Gate_Open 타이밍 부채널 → constant-time 비교
//  BUG-02 [CRIT] XOR 루프 Dead Store Elimination → pragma O0 보호
//  BUG-03 [HIGH] Absolute_Trace_Erasure pragma O0 미적용 → 적용
//  BUG-04 [MED]  entropy_shredder 결정론적 상수 → 호출마다 가변 시드
//  BUG-05 [HIGH] i % 8 모듈로 → i & 7u 비트마스크
//  BUG-06 [HIGH] x86 전용 헤더 ARM 타겟 빌드 에러 → 제거
//  BUG-07 [LOW]  인클루드 가드 예약 식별자 → (헤더에서 수정)
//  BUG-08 [MED]  500회 busy-wait → atomic_thread_fence, seq_cst→release
//  FIX-09 [CRIT] LCG 난수 31비트 마스킹 제거 → 32비트 자연 오버플로우
//  BUG-10 [MED]  주석 "seq_cst" 3곳 → release 미갱신 수정 (⑦주석-코드 불일치)
//  BUG-11 [LOW]  125행 "[BUG]" 번호 누락 → 정식 "BUG-08" 번호 부여
//  BUG-12 [CRIT] Secure_Gate_Open return(==0u) → 브랜치리스 비트 연산
//                (== 비교는 CMP+분기 → 타이밍 부채널 잔존, 비트 시프트로 완전 제거)
//  BUG-13 [MED]  Absolute_Trace_Erasure 이중 주석 블록 → 통합 (⑦주석-코드 불일치)
//
// [HTS_API 구현부는 HTS_API.cpp에 존재 → LNK2005 이중 정의 방지]
// =========================================================================
#include "HTS_Universal_API.h"

#include <atomic>
#include <cstdint>
#include <cstring>

namespace ProtectedEngine {

    // ── 마스터 키 (바이너리 내부 은닉) ──────────────────────────
    static constexpr uint64_t HOLOGRAPHIC_INTERFACE_KEY = 0x3D504F574E533332ULL;

    // =====================================================================
    //  [BUG-01+12] Constant-time 보안 게이트
    //
    //  BUG-01: uint64_t == 비교 → XOR + OR 접기로 교체
    //  BUG-12: return (combined == 0u) → 비트 시프트 브랜치리스 교체
    //          == 비교는 CMP+B(조건분기)로 컴파일 가능 → 타이밍 부채널 잔존
    //          비트 연산: (combined | -combined) >> 31 → nonzero=1, zero=0
    //          XOR 1 반전 → zero=1(true), nonzero=0(false)
    //          조건분기/조건실행 0개 — 모든 아키텍처에서 일정 시간 보장
    // =====================================================================
    bool Universal_API::Secure_Gate_Open(uint64_t session_id) noexcept {
        const uint64_t diff = session_id ^ HOLOGRAPHIC_INTERFACE_KEY;
        // 64비트 XOR 결과를 32비트로 접기 (OR 누산)
        const uint32_t hi = static_cast<uint32_t>(diff >> 32);
        const uint32_t lo = static_cast<uint32_t>(diff & 0xFFFFFFFFu);
        const uint32_t combined = hi | lo;
        // [BUG-12] 브랜치리스 zero 검출: 조건분기/CMP 완전 제거
        // combined=0 → (0|0)>>31 = 0 → 0^1 = 1 (true)
        // combined≠0 → (v|(-v))>>31 = 1 → 1^1 = 0 (false)
        const uint32_t neg = ~combined + 1u;  // 2의 보수 부정
        const uint32_t nz = (combined | neg) >> 31;  // nonzero flag
        return static_cast<bool>(nz ^ 1u);  // 반전: zero→true
    }

    bool Universal_API::Continuous_Session_Verification(
        uint64_t session_id) noexcept {
        return Secure_Gate_Open(session_id);
    }

    // =====================================================================
    //  [BUG-02~05+13] 물리적 파쇄 (3단계: 엔트로피 XOR → 0 오버라이트 → DSE 방어)
    //
    //  수정 이력:
    //   BUG-02: XOR 루프 DSE 위험 → volatile 보호 (이후 asm clobber로 대체)
    //   BUG-03: pragma O0 미적용 → 적용 (이후 pragma O0 삭제, asm clobber로 대체)
    //   BUG-04: entropy_shredder 결정론적 → target 주소 기반 가변 시드
    //   BUG-05: i % 8 → i & 7u 비트마스크
    //   BUG-13: 이중 주석 블록(구+현) 통합 — ⑦주석-코드 불일치 해소
    //
    //  현행 구현:
    //   · pragma O0 전면 삭제 → XOR 루프 레지스터 최적화 회복
    //   · uint8_t 바이트 순회 → uint32_t 워드 단위 (75% 사이클 절감)
    //   · uintptr_t 64비트 잘림 경고 → & 0xFFFFFFFFu 명시 마스킹
    //   · DSE 방어: asm volatile memory clobber + release fence
    // =====================================================================
    void Universal_API::Absolute_Trace_Erasure(
        void* target, size_t size) noexcept {
        if (!target || size == 0) return;

        // [수정 3] 64비트 빌드 호환: 하위 32비트 명시 마스킹
        uint32_t shredder = static_cast<uint32_t>(
            (reinterpret_cast<uintptr_t>(target) & 0xFFFFFFFFu)
            ^ static_cast<uint32_t>(size) ^ 0xDEADBEEFu);

        // ── 1단계: 엔트로피 셔레더 XOR (Unaligned 안전 처리) ────
        uint8_t* b_ptr = static_cast<uint8_t*>(target);
        size_t bytes_left = size;

        // 프롤로그: 4바이트 정렬 맞추기
        while (bytes_left > 0u &&
            (reinterpret_cast<uintptr_t>(b_ptr) & 3u) != 0u) {
            // [FIX-09] 31비트 마스킹(& 0x7FFFFFFFu) 제거, 32비트 오버플로우 활용
            shredder = shredder * 1103515245u + 12345u;
            *b_ptr ^= static_cast<uint8_t>(shredder >> 16);
            ++b_ptr;
            --bytes_left;
        }

        // 메인 바디: 정렬된 32비트 워드 고속 타격
        // Strict Aliasing 준수: memcpy 4B → 컴파일러가 LDR/STR 인라인 치환
        if (bytes_left >= 4u) {
            const size_t words = bytes_left / 4u;
            for (size_t i = 0; i < words; ++i) {
                // [FIX-09] 31비트 마스킹(& 0x7FFFFFFFu) 제거
                shredder = shredder * 1103515245u + 12345u;
                uint32_t temp;
                std::memcpy(&temp, b_ptr, sizeof(uint32_t));
                temp ^= shredder; // 32비트 전 영역 스크램블링 보장
                std::memcpy(b_ptr, &temp, sizeof(uint32_t));
                b_ptr += 4u;
            }
            bytes_left &= 3u; // 잔여 바이트만 남김 (Dead Store 제거)
        }

        // 에필로그: 잔여 바이트 처리 (최대 3)
        while (bytes_left-- > 0u) {
            // [FIX-09] 31비트 마스킹(& 0x7FFFFFFFu) 제거
            shredder = shredder * 1103515245u + 12345u;
            *b_ptr ^= static_cast<uint8_t>(shredder >> 16);
            ++b_ptr;
        }

        // ── 2단계: 0 오버라이트 (고속 표준 함수) ────────────────
        std::memset(target, 0, size);

        // ── 3단계: DSE 방어 + 하드웨어 메모리 배리어 ────────────
        // [수정 1] pragma 없이 asm clobber로 memset 제거 원천 차단
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(target) : "memory");
#endif
        // [BUG-08] seq_cst → release (소거 배리어 정책 통일, HTS_Secure_Memory.cpp 동일)
        std::atomic_thread_fence(std::memory_order_release);
    }

} // namespace ProtectedEngine