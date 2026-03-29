// =========================================================================
// HTS_Pointer_Auth.hpp
// 포인터 인증 코드(PAC) — Murmur3 비가역 해시 기반
// Target: STM32F407 (Cortex-M4, 32-bit)
//
// [양산 수정 — 22건]
//  BUG-01~05: XOR→Murmur3, 런타임키, 상수시간비교, iostream제거, 64비트호환
//  BUG-06~14: atomic 타입 통일, abort→자가치유, redundant check,
//             매직 넘버 상수화, 키 소거 API, include 파일명,
//             static_assert, 인스턴스화 차단, 무한스핀→유한대기+폴백
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [사용법]
//   PAC_Manager::Initialize_Runtime_Key(puf_seed);  // 부팅 시 최우선 호출!
//   uint64_t sp = PAC_Manager::Sign_Pointer(my_ptr);
//   auto* p = PAC_Manager::Authenticate_Pointer<MyType>(sp);
//   // p == my_ptr (변조 시 자가치유)
//   PAC_Manager::Wipe_Runtime_Key();  // 세션 종료 시
//
//  [⚠ 호출 순서 필수]
//   Initialize_Runtime_Key를 Sign_Pointer보다 먼저 호출해야 합니다.
//   순서 역전 시: Ensure_Key가 임시키 생성 → Initialize가 덮어쓰기
//   → 임시키로 서명된 포인터 전부 무효 → Authenticate에서 Halt
//
//  [보안 모델]
//   PAC = Murmur3_Fmix64(addr ⊕ key + rotr(key,17)) 32비트 절사
//   키 역산 수학적 불가, 관측 N쌍 수집해도 연립방정식 풀기 불가
//   ARM 32-bit: PAC[63:32] + addr[31:0] → 1/2^32 위변조 탐지
//   PC  64-bit: PAC[63:48] + addr[47:0] → 1/2^16 (테스트 전용)
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

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

        // [BUG-07] 빌드 타임 검증
        static_assert(PAC_BITS > 0, "PAC must have at least 1 bit");
        static_assert(ADDR_BITS + PAC_BITS == 64u, "Bits must sum to 64");
        static_assert((ADDR_MASK | PAC_MASK) == ~uint64_t(0),
            "ADDR_MASK and PAC_MASK must cover all 64 bits");
        static_assert((ADDR_MASK& PAC_MASK) == 0u,
            "ADDR_MASK and PAC_MASK must not overlap");

        static uint32_t Compute_PAC(uint64_t raw_addr) noexcept;
        static void Ensure_Key_Initialized() noexcept;

        // [BUG-02] 자가 치유 헬퍼 (abort 대체)
        [[noreturn]] static void Halt_PAC_Violation(const char* reason) noexcept;

    public:
        /// @brief 부팅 시 PUF/TRNG 엔트로피 주입 (선택적)
        /// @warning Sign_Pointer보다 반드시 먼저 호출할 것
        ///          호출 전 서명된 포인터는 새 키로 재서명 필수
        static void Initialize_Runtime_Key(uint64_t entropy_seed) noexcept;

        /// @brief [BUG-05] 런타임 키 보안 소거 — 세션 종료 시 호출
        static void Wipe_Runtime_Key() noexcept;

        /// @brief 포인터에 비가역 PAC 서명 부착
        /// @warning nullptr 서명 금지 — Authenticate에서 abort
        template<typename T>
        static uint64_t Sign_Pointer(T* ptr) noexcept {
            Ensure_Key_Initialized();

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

            // [BUG-03] Redundant check — 글리치로 첫 번째 분기 스킵 대비
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

        // [BUG-08] 정적 전용 클래스 — 인스턴스화 차단 (6종)
        PAC_Manager() = delete;
        ~PAC_Manager() = delete;
        PAC_Manager(const PAC_Manager&) = delete;
        PAC_Manager& operator=(const PAC_Manager&) = delete;
        PAC_Manager(PAC_Manager&&) = delete;
        PAC_Manager& operator=(PAC_Manager&&) = delete;
    };

} // namespace ProtectedEngine