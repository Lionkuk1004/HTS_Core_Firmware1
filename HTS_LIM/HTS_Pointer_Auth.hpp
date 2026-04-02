// =========================================================================
// HTS_Pointer_Auth.hpp
// 포인터 인증 코드(PAC) — Murmur3 비가역 해시 기반
// Target: STM32F407 (Cortex-M4, 32-bit)
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

namespace ProtectedEngine {

    class PAC_Manager {
    private:
        // ── 플랫폼별 PAC/주소 비트 레이아웃 ──
#if UINTPTR_MAX <= 0xFFFFFFFFu
        static constexpr unsigned ADDR_BITS = 32u;
#else
        static constexpr unsigned ADDR_BITS = 48u;
#endif
        static constexpr unsigned    PAC_BITS = 64u - ADDR_BITS;
        static constexpr unsigned    PAC_SHIFT = ADDR_BITS;
        static constexpr uint64_t    ADDR_MASK = (1ULL << ADDR_BITS) - 1u;
        static constexpr uint64_t    PAC_MASK = ~ADDR_MASK;

        static_assert(PAC_BITS > 0, "PAC must have at least 1 bit");
        static_assert(ADDR_BITS + PAC_BITS == 64u, "Bits must sum to 64");
        static_assert((ADDR_MASK | PAC_MASK) == ~uint64_t(0),
            "ADDR_MASK and PAC_MASK must cover all 64 bits");
        static_assert((ADDR_MASK& PAC_MASK) == 0u,
            "ADDR_MASK and PAC_MASK must not overlap");

        static uint32_t Compute_PAC(uint64_t raw_addr) noexcept;
        static void Ensure_Key_Initialized() noexcept;

        [[noreturn]] static void Halt_PAC_Violation(const char* reason) noexcept;

    public:
        /// @brief 부팅 시 PUF/TRNG 엔트로피 주입 (선택적)
        /// @warning Sign_Pointer보다 반드시 먼저 호출할 것
        ///          호출 전 서명된 포인터는 새 키로 재서명 필수
        static void Initialize_Runtime_Key(uint64_t entropy_seed) noexcept;

        static void Wipe_Runtime_Key() noexcept;

        /// @brief 포인터에 비가역 PAC 서명 부착
        /// @warning nullptr 서명 금지 — Authenticate에서 abort
        template<typename T>
        static uint64_t Sign_Pointer(T* ptr) noexcept {
            Ensure_Key_Initialized();
            if (ptr == nullptr) {
                Halt_PAC_Violation("Attempt to sign nullptr");
            }

            uint64_t raw_addr = static_cast<uint64_t>(
                reinterpret_cast<uintptr_t>(ptr)) & ADDR_MASK;

            uint32_t pac = Compute_PAC(raw_addr);
            uint64_t pac_field = static_cast<uint64_t>(
                pac & static_cast<uint32_t>((1ULL << PAC_BITS) - 1u));

            return (pac_field << PAC_SHIFT) | raw_addr;
        }

        /// @brief PAC 검증 후 원본 포인터 복원
        /// @note  변조 시 자가 치유 + 시스템 정지 (반환 안 함)
        template<typename T>
        static T* Authenticate_Pointer(uint64_t signed_ptr) noexcept {
            Ensure_Key_Initialized();

            // 1. PAC/주소 분리
            uint32_t stored_pac = static_cast<uint32_t>(
                (signed_ptr >> PAC_SHIFT) &
                static_cast<uint64_t>((1ULL << PAC_BITS) - 1u));
            uint64_t raw_addr = signed_ptr & ADDR_MASK;

            // 2. PAC 재계산
            uint32_t expected_pac = Compute_PAC(raw_addr);
            expected_pac &= static_cast<uint32_t>((1ULL << PAC_BITS) - 1u);

            // 3. 상수시간 PAC 비교 (volatile XOR)
            volatile uint32_t diff = stored_pac ^ expected_pac;

            // 2회 독립 검사로 단일 글리치 방어
            if (diff != 0u) {
                Halt_PAC_Violation("PAC mismatch — pointer tampered");
            }
            // 2차 확인: volatile 재읽기
            if (diff != 0u) {
                Halt_PAC_Violation("PAC mismatch — redundant check");
            }

            // 4. 포인터 복원 및 nullptr 방어
            T* ptr = reinterpret_cast<T*>(static_cast<uintptr_t>(raw_addr));
            if (ptr == nullptr) {
                Halt_PAC_Violation("Authenticated pointer is nullptr");
            }
            return ptr;
        }

        PAC_Manager() = delete;
        ~PAC_Manager() = delete;
        PAC_Manager(const PAC_Manager&) = delete;
        PAC_Manager& operator=(const PAC_Manager&) = delete;
        PAC_Manager(PAC_Manager&&) = delete;
        PAC_Manager& operator=(PAC_Manager&&) = delete;
    };

} // namespace ProtectedEngine
