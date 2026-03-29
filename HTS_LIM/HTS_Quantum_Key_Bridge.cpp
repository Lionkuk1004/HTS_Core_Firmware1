// =========================================================================
// HTS_Quantum_Key_Bridge.cpp
// PQC 양자 내성 키 브릿지 구현부
// Target: STM32F407 (Cortex-M4)
//
// [양산 수정 — 12건]
//  BUG-01~09 (이전)
//  BUG-10 [CRIT] TX/RX 동기화 붕괴: Extract_Quantum_Seed 제거 → 결정론적 해시 체인
//  BUG-11 [HIGH] Unsequenced 평가 순서: |= 분리 → 명시적 순서 보장
//  BUG-12 [MED]  memcpy 32 → sizeof(quantum_master_seed)
//  BUG-01 [CRIT] 소멸자 보안 소거 (quantum_master_seed 256비트)
//  BUG-02 [CRIT] 고정 폴백 session_id → Physical_Entropy 동적 폴백
//  BUG-03 [CRIT] 키 파생 XOR+ROTL+ADD → Murmur3 다중 혼합
//  BUG-04 [HIGH] XOR 자기역 → 인덱스별 독립 소수 상수
//  BUG-05 [HIGH] 시드 갱신 하위 비트 고정 → 인덱스별 독립 시드
//  BUG-06 [MED]  memcpy 엔디안 주석
//  BUG-07 [MED]  단일 컨텍스트 전용 주석
//  BUG-08 [CRIT] static sync_counter → 멤버 변수 (인스턴스 독립)
//  BUG-09 [CRIT] 소멸자 + sec_wipe 복구 (증발 수정)
// =========================================================================
#include "HTS_Quantum_Key_Bridge.h"
#include "HTS_Physical_Entropy_Engine.h"
#include "HTS_Universal_API.h"
#include <cstring>
#include <atomic>

namespace ProtectedEngine {

    // ── 보안 소거 (DCE 방어) ──
    static void sec_wipe_bridge(void* ptr, size_t size) noexcept {
        if (!ptr || size == 0) return;
        volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
        for (size_t i = 0; i < size; ++i) p[i] = 0;
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
        // [BUG-01] seq_cst → release (소거 배리어 정책 통일)
        std::atomic_thread_fence(std::memory_order_release);
    }

    // ── Murmur3 64비트 화이트닝 (키 파생용) ──
    static uint64_t murmur3_mix64(uint64_t k) noexcept {
        k ^= k >> 33;
        k *= 0xFF51AFD7ED558CCDULL;
        k ^= k >> 33;
        k *= 0xC4CEB9FE1A85EC53ULL;
        k ^= k >> 33;
        return k;
    }

    // =====================================================================
    //  [BUG-09] 소멸자: 256비트 마스터 키 + sync_counter 보안 소거
    // =====================================================================
    Quantum_Key_Bridge::~Quantum_Key_Bridge() noexcept {
        sec_wipe_bridge(quantum_master_seed, sizeof(quantum_master_seed));
        sync_counter = 0;
        is_pqc_established = false;
    }

    // =====================================================================
    //  Inject_Quantum_Entropy — PQC 키 교환 결과물 주입
    //  [BUG-04] 인덱스별 독립 소수 상수 (자기역 방지)
    //  [BUG-06] memcpy 리틀엔디안 전용 (STM32F407)
    // =====================================================================
    void Quantum_Key_Bridge::Inject_Quantum_Entropy(
        const std::vector<uint8_t>& pqc_material) noexcept {
        if (pqc_material.size() < sizeof(quantum_master_seed)) return;

        // [BUG-12] sizeof 사용 (하드코딩 32 제거)
        std::memcpy(quantum_master_seed, pqc_material.data(),
            sizeof(quantum_master_seed));

        // [BUG-04] 인덱스별 독립 소수 상수
        static constexpr uint64_t INJECT_KEYS[4] = {
            0x3D504F574E533332ULL,
            0x6C62272E07BB0142ULL,
            0x94D049BB133111EBULL,
            0xBF58476D1CE4E5B9ULL
        };
        for (int i = 0; i < 4; ++i) {
            quantum_master_seed[i] ^= INJECT_KEYS[i];
        }

        is_pqc_established = true;
    }

    // =====================================================================
    //  Derive_Quantum_Session_ID — 256비트 → 64비트 세션 ID 파생
    //  [BUG-02] 고정 폴백 → Physical_Entropy 동적 폴백
    //  [BUG-03] Murmur3 다중 혼합 (단방향)
    // =====================================================================
    uint64_t Quantum_Key_Bridge::Derive_Quantum_Session_ID() noexcept {
        if (!is_pqc_established) {
            // [BUG-11] 평가 순서 명시 보장 (|= 분리)
            uint32_t seed_hi =
                Physical_Entropy_Engine::Extract_Quantum_Seed();
            uint32_t seed_lo =
                Physical_Entropy_Engine::Extract_Quantum_Seed();
            uint64_t fallback =
                (static_cast<uint64_t>(seed_hi) << 32) |
                static_cast<uint64_t>(seed_lo);
            return fallback;
        }

        uint64_t derived = 0;
        for (int i = 0; i < 4; ++i) {
            derived ^= murmur3_mix64(
                quantum_master_seed[i] + static_cast<uint64_t>(i));
        }

        return derived;
    }

    // =====================================================================
    //  Synchronize_CTR_State — 세션 ID 출력 + 마스터 시드 전진
    //  [BUG-05] 인덱스별 독립 시드 갱신
    //  [BUG-08] static sync_counter → 멤버 변수 (this->sync_counter)
    // =====================================================================
    void Quantum_Key_Bridge::Synchronize_CTR_State(
        uint64_t& out_session_id) noexcept {
        out_session_id = Derive_Quantum_Session_ID();

        // [BUG-08] 멤버 변수 카운터 (인스턴스 독립)
        ++sync_counter;

        // [BUG-10] 결정론적 해시 체인만으로 시드 전진
        // Extract_Quantum_Seed 완전 제거 → TX/RX 로컬 TRNG 발산 차단
        // 동일 초기 시드 + 동일 카운터 → 양쪽 동일 결과 보장
        for (int i = 0; i < 4; ++i) {
            quantum_master_seed[i] = murmur3_mix64(
                quantum_master_seed[i] ^
                sync_counter ^
                (static_cast<uint64_t>(i) * 0x9E3779B97F4A7C15ULL));
        }
    }

} // namespace ProtectedEngine