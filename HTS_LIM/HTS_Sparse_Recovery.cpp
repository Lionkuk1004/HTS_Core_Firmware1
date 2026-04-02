// =========================================================================
// HTS_Sparse_Recovery.cpp
// L1 스파스 하이브리드 복구 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
// =========================================================================
#include "HTS_Sparse_Recovery.h"
#include <climits>       // INT32_MAX
#include <cstdint>       // uintptr_t (B-2 정렬 검증)
#include <type_traits>   // std::is_unsigned (Safe_Obfuscate static_assert)

namespace {
    /// i + span 이 size_t 오버플로 없이 [i, elements) 구간만 덮도록 끝 인덱스 계산
    inline size_t sparse_block_end_exclusive(
        const size_t i,
        const size_t span,
        const size_t elements) noexcept
    {
        if (i >= elements) { return elements; }
        const size_t remain = elements - i;
        const size_t take = (span < remain) ? span : remain;
        return i + take;
    }

    /// RecoveryStats 임시 객체/복사 할당 없이 제로 클리어 (베어메탈)
    inline void recovery_stats_zero(ProtectedEngine::RecoveryStats& s) noexcept {
        s.total_elements = 0u;
        s.destroyed_count = 0u;
        s.recovered_by_parity = 0u;
        s.recovered_by_gravity = 0u;
        s.unrecoverable = 0u;
        s.noise_ratio_q16 = 0u;
    }

    /// Cortex-M4 UsageFault 방지 — T* 가 alignof(T) 경계에 있을 것 (기준서 B-2 / K-2)
    template <typename T>
    inline bool sparse_ptr_aligned(const T* p) noexcept {
        constexpr std::size_t al = alignof(T);
        static_assert((al & (al - 1u)) == 0u, "alignof(T) must be power of 2");
        const uintptr_t a = reinterpret_cast<uintptr_t>(p);
        const uintptr_t mask = static_cast<uintptr_t>(al - 1u);
        return (a & mask) == 0u;
    }
} // namespace


namespace ProtectedEngine {

    /// 3의 모듈러 역원 (mod 2^N). Safe_Obfuscate / Safe_Deobfuscate 공통 — INV3 이중 정의 방지
    template <typename T>
    static constexpr T modular_inverse_3() noexcept {
        static_assert(std::is_unsigned<T>::value,
            "modular_inverse_3: unsigned 타입만 허용");
        constexpr T inv = static_cast<T>(
            static_cast<T>(static_cast<T>(~static_cast<T>(0)) / static_cast<T>(3))
            * static_cast<T>(2) + static_cast<T>(1));
        static_assert(static_cast<T>(static_cast<T>(3) * inv) == static_cast<T>(1),
            "Modular inverse verification failed: 3 * INV3 != 1");
        return inv;
    }

    // =====================================================================
    //  가역적 모듈러 난독화 / 역난독화 (Safe_Obfuscate / Safe_Deobfuscate)
    //
    //  수학적 보증:
    //   Forward:  y = (x ^ interference) × 3        mod 2^N
    //   Reverse:  x = (y × INV3) ^ interference     mod 2^N
    //   여기서 3 × INV3 ≡ 1 (mod 2^N) — 모든 unsigned N 비트폭에서 성립
    //
    //  INV3 산출:  (~T(0) / 3) × 2 + 1
    //   8비트: 0xAB, 16비트: 0xAAAB, 32비트: 0xAAAAAAAB, 64비트: 0xAAAAAAAAAAAAAAAB
    //   빌드타임 static_assert: 3 × INV3 ≡ 1 (mod 2^N) 검증
    //
    //  XOR 단독 대비:
    //   · 곱셈이 비트 확산(Diffusion) 제공 → interference 편향 시에도 평문 패턴 차단
    //   · 가역성 수학적 보장 (홀수 곱셈은 모듈러 산술에서 항상 전단사 함수)
    //   · Cortex-M4 MUL 1사이클 추가 (무시 가능)
    //
    //
    //   INV3 경로에서 MARKER·bad_plaintext 충돌 시 평문 도메인에서 1-LSB(또는 2-LSB) 이격
    //
    //   추가: plaintext == MARKER 자체도 방어 (RX 파손 오인 차단)
    // =====================================================================
    template <typename T>
    static T Safe_Obfuscate(T plaintext, T interference) noexcept {
        static_assert(std::is_unsigned<T>::value,
            "Safe_Obfuscate: unsigned 타입만 허용");

        const T MARKER = Get_Erasure_Marker<T>();

        // ① 평문 자체가 MARKER이면 RX에서 파손 오인 → 1-LSB 이격
        if (plaintext == MARKER) {
            plaintext ^= static_cast<T>(1u);
        }

        // ② 위험 평문 사전 탐지: (bad_x ^ I) * 3 ≡ MARKER (mod 2^N)
        //    bad_x ^ I = MARKER * INV3 = ~INV3 + 1  (모듈러 산술)
        //    bad_x = (~INV3 + 1) ^ I
        static constexpr T INV3 = modular_inverse_3<T>();
        const T neg_inv3 = static_cast<T>(~INV3 + static_cast<T>(1u));
        const T bad_plaintext = static_cast<T>(neg_inv3 ^ interference);

        if (plaintext == bad_plaintext) {
            plaintext ^= static_cast<T>(1u);
            // 1-LSB 이격 결과가 MARKER와 우연히 겹치면 2-LSB로 회피
            if (plaintext == MARKER) {
                plaintext ^= static_cast<T>(2u);
            }
        }

        // UDIV 0회 — 안전하고 빠른 가역 난독화
        return static_cast<T>(
            static_cast<T>(plaintext ^ interference) * static_cast<T>(3u));
    }

    template <typename T>
    static T Safe_Deobfuscate(T obfuscated, T interference) noexcept {
        static_assert(std::is_unsigned<T>::value,
            "Safe_Deobfuscate: unsigned 타입만 허용");
        static constexpr T INV3 = modular_inverse_3<T>();
        return static_cast<T>(
            static_cast<T>(obfuscated * INV3) ^ interference);
    }

    // ④ noise_ratio: uint32_t Q16 (0~65536 = 0.0~1.0)
    //  ARM/A55: double 연산 0회 (기존 동일)
    //  PC: (destroyed << 16) / total (정수 연산, double 제거)
    static uint32_t compute_noise_ratio_q16(
        size_t destroyed, size_t total) noexcept {
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH) || \
    defined(__aarch64__)
        (void)destroyed;
        (void)total;
        return 0u;  // ARM/A55: 상수 대입, FPU 미사용
#else
        // PC 개발빌드: Q16 정수 비율 계산
        if (total == 0u) return 0u;
        // destroyed ≤ total 이므로 (destroyed << 16) ≤ (total << 16) → 오버플로 안전
        return static_cast<uint32_t>(
            (static_cast<uint64_t>(destroyed) << 16u) / total);
#endif
    }

    // 제네릭 파괴 마커 생성 (8/16/32/64비트 완벽 호환)
    template <typename T>
    constexpr T Get_Erasure_Marker() {
        return static_cast<T>(~static_cast<T>(0));
    }

    template <typename T>
    static T Make_Anchor_Mask(uint32_t master_seed) {
        uint32_t lo = master_seed ^ 0x3D414E43u;
        if (sizeof(T) <= 4) {
            return static_cast<T>(lo);
        }
        else {
            uint32_t hi = lo * 0x9E3779B9u;
            return static_cast<T>((static_cast<uint64_t>(hi) << 32) |
                static_cast<uint64_t>(lo));
        }
    }

    template <typename T>
    static T Make_Interference(uint32_t master_seed, uint32_t idx) {
        uint32_t zeta = (master_seed ^ idx) * 0x9E3779B9u;
        uint32_t rot = (zeta >> 5) | (zeta << 27);
        if (sizeof(T) <= 4) {
            return static_cast<T>(rot);
        }
        else {
            uint32_t hi = zeta * 0x85EBCA6Bu;
            return static_cast<T>((static_cast<uint64_t>(hi) << 32) |
                static_cast<uint64_t>(rot));
        }
    }

    // =================================================================================
    // [TX 송신단] 간섭 패턴 생성 및 XOR 패리티 백업 (데이터 증가율 0%, Throughput 극대화)
    // =================================================================================
    template <typename T>
    void Sparse_Recovery_Engine::Generate_Interference_Pattern(T* tensor_block, size_t elements, uint64_t session_id, uint32_t anchor_interval, bool is_test_mode) {
        if ((tensor_block == nullptr) || (elements == 0u)) { return; }
        if (!sparse_ptr_aligned(tensor_block)) { return; }

        // 오토 튜닝 및 상용망 규격 락다운
        //  interval=1 → 모든 요소=앵커 → 내부 루프 미진입 → parity=0
        //  → 원본 데이터 100% ANCHOR_MASK 덮어쓰기 (비가역 파괴)
        //  최소 2 이상 (앵커 1개 + 데이터 1개) 필요
        if (anchor_interval == 1u) { anchor_interval = 0u; }

        if (!is_test_mode) {
            if (anchor_interval == 0u
                || anchor_interval > SparseRecoveryLimits::ANCHOR_INTERVAL_CAP) {
                anchor_interval = (anchor_interval != 0u)
                    ? SparseRecoveryLimits::ANCHOR_INTERVAL_CAP : 0u;
            }
        }
        else {
            if (anchor_interval == 0u) {
                anchor_interval = SparseRecoveryLimits::TEST_MODE_DEFAULT_ANCHOR;
            }
        }

        uint32_t master_seed = static_cast<uint32_t>(session_id ^ 0x3D485453);
        const T ANCHOR_MASK = Make_Anchor_Mask<T>(master_seed);

        // [최적화 1] O(N) 블록 단위 Loop Fusion (패리티 압축 + 난독화 1 Cycle 통합)
        if (anchor_interval > 0) {
            for (size_t i = 0; i < elements; i += anchor_interval) {
                T parity = 0;
                const size_t end_idx = sparse_block_end_exclusive(
                    i, static_cast<size_t>(anchor_interval), elements);

                for (size_t j = i + 1; j < end_idx; ++j) {
                    parity ^= tensor_block[j]; // 1. 원본 페이로드 패리티 누적

                    // 2. 가역적 모듈러 난독화 (XOR + ×3 Diffusion)
                    T interference = Make_Interference<T>(master_seed, static_cast<uint32_t>(j));
                    tensor_block[j] = Safe_Obfuscate(tensor_block[j], interference);
                }
                // 3. 앵커: 패리티 + 마스크 (Safe_Obfuscate로 MARKER 충돌 방어)
                tensor_block[i] = Safe_Obfuscate(parity, ANCHOR_MASK);
            }
        }
        else {
            // 앵커 미사용 시 순수 난독화만 고속 진행
            for (size_t i = 0; i < elements; ++i) {
                T interference = Make_Interference<T>(master_seed, static_cast<uint32_t>(i));
                tensor_block[i] = Safe_Obfuscate(tensor_block[i], interference);
            }
        }
    }

    // =================================================================================
    // [RX 수신단] 패리티(1차) + 중력 지평선(2차) 하이브리드 스마트 힐링
    // =================================================================================
    template <typename T>
    bool Sparse_Recovery_Engine::Execute_L1_Reconstruction(T* damaged_tensor, size_t elements, uint64_t session_id, uint32_t anchor_interval, bool is_test_mode, bool strict_mode, RecoveryStats& out_stats) {
        recovery_stats_zero(out_stats);
        if ((damaged_tensor == nullptr) || (elements == 0u)) {
            return false;
        }
        if (!sparse_ptr_aligned(damaged_tensor)) {
            return false;
        }

        out_stats.total_elements = elements;

        if (anchor_interval == 1u) { anchor_interval = 0u; }

        if (!is_test_mode) {
            if (anchor_interval == 0u
                || anchor_interval > SparseRecoveryLimits::ANCHOR_INTERVAL_CAP) {
                anchor_interval = (anchor_interval != 0u)
                    ? SparseRecoveryLimits::ANCHOR_INTERVAL_CAP : 0u;
            }
        }
        else {
            if (anchor_interval == 0u) {
                anchor_interval = SparseRecoveryLimits::TEST_MODE_DEFAULT_ANCHOR;
            }
        }

        // [무결성 1] Type Promotion 버그를 차단하는 범용 파괴 마커
        const T ERASURE_MARKER = Get_Erasure_Marker<T>();
        uint32_t master_seed = static_cast<uint32_t>(session_id ^ 0x3D485453);
        const T ANCHOR_MASK = Make_Anchor_Mask<T>(master_seed);

        size_t total_destroyed = 0;

        // 1단계: 동적 간격에 맞춘 패턴 해제 (Erasure Aware)
        if (anchor_interval > 0) {
            for (size_t i = 0; i < elements; i += anchor_interval) {
                if (damaged_tensor[i] != ERASURE_MARKER) {
                    damaged_tensor[i] = Safe_Deobfuscate(damaged_tensor[i], ANCHOR_MASK);
                }
                else {
                    total_destroyed++;
                }

                const size_t end_idx = sparse_block_end_exclusive(
                    i, static_cast<size_t>(anchor_interval), elements);
                for (size_t j = i + 1; j < end_idx; ++j) {
                    if (damaged_tensor[j] != ERASURE_MARKER) {
                        T interference = Make_Interference<T>(master_seed, static_cast<uint32_t>(j));
                        damaged_tensor[j] = Safe_Deobfuscate(damaged_tensor[j], interference);
                    }
                    else {
                        total_destroyed++;
                    }
                }
            }
        }
        else {
            for (size_t i = 0; i < elements; ++i) {
                if (damaged_tensor[i] != ERASURE_MARKER) {
                    T interference = Make_Interference<T>(master_seed, static_cast<uint32_t>(i));
                    damaged_tensor[i] = Safe_Deobfuscate(damaged_tensor[i], interference);
                }
                else {
                    total_destroyed++;
                }
            }
            out_stats.destroyed_count = total_destroyed;
            out_stats.noise_ratio_q16 = compute_noise_ratio_q16(total_destroyed, elements);
            return true;
        }

        out_stats.destroyed_count = total_destroyed;
        if (total_destroyed == 0) {
            out_stats.noise_ratio_q16 = 0u;
            return true;
        }

        bool is_reconstruction_successful = true;

        // [최적화 2] O(N^2) 중력 보간 스캔 딜레이를 소멸시키는 스마트 캐싱 포인터
        size_t cached_R_idx = 0;
        bool has_cached_R = false;

        // 2단계: 스마트 하이브리드 복구 로직
        for (size_t block_start = 0; block_start < elements; block_start += anchor_interval) {
            const size_t block_end = sparse_block_end_exclusive(
                block_start, static_cast<size_t>(anchor_interval), elements);

            size_t local_destroyed_count = 0;
            size_t last_destroyed_idx = 0;
            T block_xor_sum = 0; // [최적화 3] 분기 예측 이중 루프 제거용 캐시

            for (size_t j = block_start; j < block_end; ++j) {
                if (damaged_tensor[j] == ERASURE_MARKER) {
                    local_destroyed_count++;
                    last_destroyed_idx = j;
                }
                else {
                    block_xor_sum ^= damaged_tensor[j]; // 정상 데이터만 미리 XOR 합산
                }
            }

            if (local_destroyed_count == 0) continue;

            // [1차 방어막] XOR 패리티 확정 복구 (미리 구해둔 합계를 대입하여 O(1) 복구 완료)
            if (local_destroyed_count == 1) {
                damaged_tensor[last_destroyed_idx] = block_xor_sum;
                out_stats.recovered_by_parity++;
            }
            // [2차 방어막] 중력의 지평선 보간 아날로그 힐링 (연쇄 파괴 시)
            else {
                if (strict_mode) {
                    out_stats.unrecoverable += local_destroyed_count;
                    for (size_t j = block_start; j < block_end; ++j) {
                        if (damaged_tensor[j] == ERASURE_MARKER)
                            damaged_tensor[j] = 0;
                    }
                    is_reconstruction_successful = false;
                    continue;
                }

                for (size_t j = block_start; j < block_end; ++j) {
                    if (damaged_tensor[j] == ERASURE_MARKER) {

                        // 패리티(앵커)는 아날로그 데이터가 아니므로 중력 보간 제외
                        if (j == block_start) {
                            damaged_tensor[j] = 0;
                            continue;
                        }

                        out_stats.recovered_by_gravity++;

                        // 1. 왼쪽 인력 탐색 (블록 경계 제한)
                        size_t L_idx = j;
                        bool found_L = false;
                        while (L_idx > block_start) {
                            L_idx--;
                            if (damaged_tensor[L_idx] != ERASURE_MARKER && (L_idx != block_start)) {
                                found_L = true; break;
                            }
                        }

                        // 2. 오른쪽 인력 탐색 (캐시 활용)
                        size_t R_idx = j;
                        bool found_R = false;
                        if (has_cached_R && cached_R_idx > j) {
                            R_idx = cached_R_idx;
                            found_R = true;
                        }
                        else if (cached_R_idx < elements) {
                            // 캐시 무효 → 새로 탐색
                            if (cached_R_idx <= j) cached_R_idx = j + 1;
                            has_cached_R = false;
                            while (cached_R_idx < elements) {
                                if (damaged_tensor[cached_R_idx] != ERASURE_MARKER && (cached_R_idx % anchor_interval != 0)) {
                                    has_cached_R = true; break;
                                }
                                cached_R_idx++;
                            }
                            if (has_cached_R) {
                                R_idx = cached_R_idx;
                                found_R = true;
                            }
                            // else: cached_R_idx >= elements → 다음 j에서 재스캔 안 함
                        }
                        // else: cached_R_idx >= elements → 이미 끝 도달, 재스캔 불필요

                        // 3. 중력 가중치 연산
                        //
                        // 중력 가중: 64비트 나눗셈 회피 — int32·Q16 역수 경로(타입·크기별 분기)
                        if (found_L && found_R) {
                            // dist는 블록 내 거리: 최대 anchor_interval (~20)
                            // uint32_t로 충분 (기존 uint64_t는 불필요한 64비트 유발)
                            const uint32_t dL = static_cast<uint32_t>(j - L_idx);
                            const uint32_t dR = static_cast<uint32_t>(R_idx - j);
                            const uint32_t sd = dL + dR;

                            if (sizeof(T) <= 2u) {
                                // ── 경로 A: int32_t 완결 (ARM SDIV, 64비트 0회) ──
                                // static_assert: 최악치 65535 × 20 = 1,310,700 < INT32_MAX
                                static_assert(
                                    static_cast<int64_t>(65535) * 20 <
                                    static_cast<int64_t>(INT32_MAX),
                                    "16-bit gravity must fit int32_t");
                                const int32_t mL = static_cast<int32_t>(
                                    damaged_tensor[L_idx]);
                                const int32_t mR = static_cast<int32_t>(
                                    damaged_tensor[R_idx]);
                                const int32_t md = mR - mL;
                                const int32_t num = md * static_cast<int32_t>(dL);
                                const int32_t half = static_cast<int32_t>(sd >> 1u);
                                const int32_t isd = static_cast<int32_t>(sd);
                                const int32_t grav = (num >= 0)
                                    ? (num + half) / isd
                                    : (num - half) / isd;
                                damaged_tensor[j] = static_cast<T>(mL + grav);
                            }
                            else {
                                // ── 경로 B: 역수 Q16 곱셈 (UDIV + SMULL) ──
                                // 64비트 나눗셈(__aeabi_ldivmod) 완전 회피
                                const int64_t mL = static_cast<int64_t>(
                                    damaged_tensor[L_idx]);
                                const int64_t mR = static_cast<int64_t>(
                                    damaged_tensor[R_idx]);
                                const int64_t md = mR - mL;
                                const int64_t num = md * static_cast<int64_t>(dL);

                                // 역수 Q16: UDIV 32비트 1회 (~12cyc)
                                // sd ≥ 2 보장 (dL ≥ 1, dR ≥ 1)
                                const uint32_t recip_q16 =
                                    (65536u + (sd >> 1u)) / sd;
                                // 부호 보존 곱셈 + 시프트: SMULL 1회 (~1cyc)
                                const int64_t grav =
                                    (num * static_cast<int64_t>(recip_q16)) >> 16;
                                damaged_tensor[j] = static_cast<T>(mL + grav);
                            }
                        }
                        else if (found_L) damaged_tensor[j] = damaged_tensor[L_idx];
                        else if (found_R) damaged_tensor[j] = damaged_tensor[R_idx];
                        else {
                            damaged_tensor[j] = 0;
                            out_stats.unrecoverable++;
                        }
                    }
                }
            }
        }

        out_stats.noise_ratio_q16 = compute_noise_ratio_q16(out_stats.destroyed_count, elements);
        return is_reconstruction_successful;
    }

    // 명시적 템플릿 인스턴스화
    template void Sparse_Recovery_Engine::Generate_Interference_Pattern<uint8_t>(uint8_t*, size_t, uint64_t, uint32_t, bool);
    template void Sparse_Recovery_Engine::Generate_Interference_Pattern<uint16_t>(uint16_t*, size_t, uint64_t, uint32_t, bool);
    template void Sparse_Recovery_Engine::Generate_Interference_Pattern<uint32_t>(uint32_t*, size_t, uint64_t, uint32_t, bool);
    template void Sparse_Recovery_Engine::Generate_Interference_Pattern<uint64_t>(uint64_t*, size_t, uint64_t, uint32_t, bool);

    template bool Sparse_Recovery_Engine::Execute_L1_Reconstruction<uint8_t>(uint8_t*, size_t, uint64_t, uint32_t, bool, bool, RecoveryStats&);
    template bool Sparse_Recovery_Engine::Execute_L1_Reconstruction<uint16_t>(uint16_t*, size_t, uint64_t, uint32_t, bool, bool, RecoveryStats&);
    template bool Sparse_Recovery_Engine::Execute_L1_Reconstruction<uint32_t>(uint32_t*, size_t, uint64_t, uint32_t, bool, bool, RecoveryStats&);
    template bool Sparse_Recovery_Engine::Execute_L1_Reconstruction<uint64_t>(uint64_t*, size_t, uint64_t, uint32_t, bool, bool, RecoveryStats&);

} // namespace ProtectedEngine
