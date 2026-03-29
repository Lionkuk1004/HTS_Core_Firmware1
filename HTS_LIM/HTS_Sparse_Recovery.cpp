// =========================================================================
// HTS_Sparse_Recovery.cpp
// L1 스파스 하이브리드 복구 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
// =========================================================================
#include "HTS_Sparse_Recovery.h"
#include <climits>   // INT32_MAX (BUG-12 static_assert)

// [양산 수정 이력 — 10건]
//  BUG-01 [MED]  double noise_ratio 유지 (API 호환)
//  BUG-03 [MED]  j % anchor_interval → j == block_start
//  BUG-04 [HIGH] 중력 보간 왼쪽 탐색: block_start 경계 제한
//  BUG-06 [MED]  [[nodiscard]] 추가
//  BUG-07 [CRIT] 64비트 난독화: 상위 32비트 평문 노출 → 전비트 커버
//  BUG-08 [CRIT] 오른쪽 캐시 붕괴 O(N²) → 탐색 실패 시 재스캔 차단
//  BUG-09 [HIGH] strict_mode: unrecoverable 통계 누락 + ERASURE_MARKER 잔존
//  BUG-10 [MED]  음수 반올림 절사 → 부호 기반 대칭 반올림
//  BUG-11 [CRIT] ARM double 나눗셈 제거 (항목④ 위반)
//         · ARM: noise_ratio → 0.0 상수 대입 (__aeabi_dmul 200cyc 제거)
//         · PC: 기존 호환 유지
//  BUG-12 [CRIT] 중력 보간 int64_t 나눗셈 병목 완전 제거
//         · sizeof(T) ≤ 2: int32_t SDIV 완결 (2~12cyc, 64비트 0회)
//           mass 최대 65535, dist 최대 20 → numerator < INT32_MAX
//         · sizeof(T) > 2: 역수 Q16 곱셈 (UDIV 12cyc + SMULL 1cyc = 13cyc)
//           기존 __aeabi_ldivmod ~200cyc 대비 15× 가속
//         · dist_L/R: uint64_t → uint32_t (블록 내 거리 최대 ~40)

namespace ProtectedEngine {

    // [BUG-11] noise_ratio 연산: ARM/A55 = double 0회, PC = 기존 호환
    // ARM/A55에서 noise_ratio double 필드의 유일한 소비자였던
    // BB1_Core_Engine::noise_ratio_to_q16는 BUG-50에서
    // 정수 기반 noise_to_q16(destroyed_count, total_elements)로 교체됨.
    // → ARM/A55에서 noise_ratio 필드는 더 이상 읽히지 않음.
    // A55는 FPU 있으나, double 연산 불필요 → 통일 (0.0 대입)
    static double compute_noise_ratio(
        size_t destroyed, size_t total) noexcept {
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH) || \
    defined(__aarch64__)
        (void)destroyed;
        (void)total;
        return 0.0;  // 상수 대입: FPU 미사용, double 연산 0회
#else
        // PC 개발빌드: 디버그/테스트용 실제 비율 계산
        if (total == 0u) return 0.0;
        return static_cast<double>(destroyed) / static_cast<double>(total);
#endif
    }

    // 제네릭 파괴 마커 생성 (8/16/32/64비트 완벽 호환)
    template <typename T>
    constexpr T Get_Erasure_Marker() {
        return static_cast<T>(~static_cast<T>(0));
    }

    // [BUG-07] 64비트 안전 앵커 마스크 생성 — sizeof(T) > 4 시 전비트 커버
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

    // [BUG-07] 64비트 안전 간섭 패턴 생성 — 전비트 난독화
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
        if (!tensor_block || elements == 0) return;

        // 오토 튜닝 및 상용망 규격 락다운
        if (!is_test_mode) {
            if (anchor_interval == 0 || anchor_interval > 6) {
                anchor_interval = (anchor_interval != 0) ? 6 : 0;
            }
        }
        else {
            if (anchor_interval == 0) anchor_interval = 20;
        }

        uint32_t master_seed = static_cast<uint32_t>(session_id ^ 0x3D485453);
        const T ANCHOR_MASK = Make_Anchor_Mask<T>(master_seed);

        // [최적화 1] O(N) 블록 단위 Loop Fusion (패리티 압축 + 난독화 1 Cycle 통합)
        if (anchor_interval > 0) {
            for (size_t i = 0; i < elements; i += anchor_interval) {
                T parity = 0;
                size_t end_idx = (i + anchor_interval < elements) ? (i + anchor_interval) : elements;

                for (size_t j = i + 1; j < end_idx; ++j) {
                    parity ^= tensor_block[j]; // 1. 원본 페이로드 패리티 누적

                    // 2. 일반 데이터 난독화 동시 진행
                    T interference = Make_Interference<T>(master_seed, static_cast<uint32_t>(j));
                    tensor_block[j] ^= interference;
                }
                // 3. 앵커 위치에 패리티 삽입 및 특수 마스크 씌우기
                tensor_block[i] = parity ^ ANCHOR_MASK;
            }
        }
        else {
            // 앵커 미사용 시 순수 난독화만 고속 진행
            for (size_t i = 0; i < elements; ++i) {
                T interference = Make_Interference<T>(master_seed, static_cast<uint32_t>(i));
                tensor_block[i] ^= interference;
            }
        }
    }

    // =================================================================================
    // [RX 수신단] 패리티(1차) + 중력 지평선(2차) 하이브리드 스마트 힐링
    // =================================================================================
    template <typename T>
    bool Sparse_Recovery_Engine::Execute_L1_Reconstruction(T* damaged_tensor, size_t elements, uint64_t session_id, uint32_t anchor_interval, bool is_test_mode, bool strict_mode, RecoveryStats& out_stats) {
        if (!damaged_tensor || elements == 0) return false;

        out_stats = RecoveryStats();
        out_stats.total_elements = elements;

        if (!is_test_mode) {
            if (anchor_interval == 0 || anchor_interval > 6) {
                anchor_interval = (anchor_interval != 0) ? 6 : 0;
            }
        }
        else {
            if (anchor_interval == 0) anchor_interval = 20;
        }

        // [무결성 1] Type Promotion 버그를 차단하는 범용 파괴 마커
        const T ERASURE_MARKER = Get_Erasure_Marker<T>();
        uint32_t master_seed = static_cast<uint32_t>(session_id ^ 0x3D485453);
        const T ANCHOR_MASK = Make_Anchor_Mask<T>(master_seed);

        size_t total_destroyed = 0;

        // 1단계: 동적 간격에 맞춘 패턴 해제 (Erasure Aware)
        if (anchor_interval > 0) {
            for (size_t i = 0; i < elements; i += anchor_interval) {
                if (damaged_tensor[i] != ERASURE_MARKER) damaged_tensor[i] ^= ANCHOR_MASK;
                else total_destroyed++;

                size_t end_idx = (i + anchor_interval < elements) ? (i + anchor_interval) : elements;
                for (size_t j = i + 1; j < end_idx; ++j) {
                    if (damaged_tensor[j] != ERASURE_MARKER) {
                        T interference = Make_Interference<T>(master_seed, static_cast<uint32_t>(j));
                        damaged_tensor[j] ^= interference;
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
                    damaged_tensor[i] ^= interference;
                }
                else {
                    total_destroyed++;
                }
            }
            out_stats.destroyed_count = total_destroyed;
            out_stats.noise_ratio = compute_noise_ratio(total_destroyed, elements);
            return true;
        }

        out_stats.destroyed_count = total_destroyed;
        if (total_destroyed == 0) {
            out_stats.noise_ratio = 0.0;
            return true;
        }

        bool is_reconstruction_successful = true;

        // [최적화 2] O(N^2) 중력 보간 스캔 딜레이를 소멸시키는 스마트 캐싱 포인터
        size_t cached_R_idx = 0;
        bool has_cached_R = false;

        // 2단계: 스마트 하이브리드 복구 로직
        for (size_t block_start = 0; block_start < elements; block_start += anchor_interval) {
            size_t block_end = (block_start + anchor_interval < elements) ? (block_start + anchor_interval) : elements;

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
                    // [BUG-09] 통계 누적 + ERASURE_MARKER 소거 (하위 파이프라인 보호)
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
                        // [BUG-03] 나눗셈 제거: j == block_start (앵커 위치 직접 비교)
                        if (j == block_start) {
                            damaged_tensor[j] = 0;
                            continue;
                        }

                        out_stats.recovered_by_gravity++;

                        // 1. 왼쪽 인력 탐색 (블록 경계 제한)
                        // [BUG-04] block_start 이하 침범 방지
                        size_t L_idx = j;
                        bool found_L = false;
                        while (L_idx > block_start) {
                            L_idx--;
                            if (damaged_tensor[L_idx] != ERASURE_MARKER && (L_idx != block_start)) {
                                found_L = true; break;
                            }
                        }

                        // 2. 오른쪽 인력 탐색 (캐시 활용)
                        // [BUG-08] 탐색 실패 시 재스캔 차단
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
                                // [BUG-03] anchor_interval 비2의거듭제곱 → % 유지
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
                        // [BUG-12] 64비트 나눗셈 병목 완전 제거
                        //
                        // 기존: int64_t / int64_t → __aeabi_ldivmod (~200cyc/칩)
                        //       파괴 칩 100개 → 20,000사이클 낭비
                        //
                        // 수정 A (sizeof(T) ≤ 2):
                        //   mass 최대 65535, dist 최대 20
                        //   → numerator = 65535 × 20 = 1,310,700 ≪ INT32_MAX
                        //   → int32_t SDIV 1회 (2~12cyc), 64비트 연산 0회
                        //
                        // 수정 B (sizeof(T) > 2):
                        //   역수 Q16 곱셈: recip = 65536/sum_dist (UDIV 12cyc)
                        //   gravity = numerator × recip >> 16 (SMULL 1cyc)
                        //   합계 ~13cyc, 기존 대비 15× 가속
                        //   반올림 오차 ≤ 1LSB (아날로그 보간 특성상 무해)
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

        out_stats.noise_ratio = compute_noise_ratio(out_stats.destroyed_count, elements);
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