// =========================================================================
// HTS_Server_Stress_Test.cpp
// 서버급 대용량 스트레스 테스트 구현부 (PC/서버 전용)
// Target: PC / Server (ARM 빌드 제외)
//
// [양산 수정]
//  1. ARM #error 가드 추가 (.h에서 이미 차단하지만 .cpp 단독 컴파일 방어)
//  2. 재밍 크기 계산: node_count * 0.8 → node_count * 4 / 5 (부동소수점 제거)
//  3. 엔트로피 출력: node_count * 0.30103 → 정수 근사 (node_count * 301 / 1000)
//  4. OOM try-catch 추가 (수십MB 벡터 2개 할당)
// =========================================================================
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#error "[HTS_FATAL] HTS_Server_Stress_Test.cpp는 PC/서버 전용입니다. ARM 빌드에서 제외하십시오."
#endif

#include "HTS_Server_Stress_Test.h"
#include "HTS_Dynamic_Config.h"
#include "BB1_Core_Engine.hpp"
#include <chrono>
#include <iostream>
#include <vector>
#include <cstdlib>

namespace ProtectedEngine {

    // [C6262] 스택 82KB: 서버급 벡터 2개(힙) + config 구조체
    // PC/서버 전용 — ARM 빌드 제외됨, 서버 스택 충분
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 6262)
#endif
    void Server_Stress_Test::Run_Hyper_Scale_Test() {
        try {
            // 서버급 10만+ 노드 설정
            auto config = HTS_Sys_Config_Factory::Get_Tier_Profile(HTS_Sys_Tier::HYPER_SERVER);
            std::vector<uint32_t> large_tensor(config.node_count, 0xABCDEFFu);
            uint64_t session_id = 0x20260307ULL;

            // 무결성 검증용 원본 백업
            std::vector<uint32_t> original_tensor = large_tensor;

            BB1_Core_Engine engine;

            auto start = std::chrono::high_resolution_clock::now();

            // 1. 송신 파이프라인
            (void)engine.Process_Tensor_Pipeline(
                large_tensor.data(), config.node_count,
                session_id, config.temporal_slice_chunk);

            // =================================================================
            //  심우주 극한 환경 시뮬레이션
            // =================================================================

            // 1단계: 10% 연속 신호 소실 (Continuous Blackout)
            size_t blackout_size = config.node_count / 10u;
            size_t blackout_start = config.node_count / 2u;
            for (size_t i = blackout_start; i < blackout_start + blackout_size; ++i) {
                large_tensor[i] = 0x00000000u;
            }

            // 2단계: 80% 위상 역전 재밍 (Phase Inversion Jamming)
            // [양산 수정] node_count * 0.8 → 정수 연산
            size_t jamming_size = static_cast<size_t>(
                static_cast<uint64_t>(config.node_count) * 4u / 5u);

            for (size_t i = 0; i < jamming_size; ++i) {
                // 이미 증발한 구간 제외
                if (i >= blackout_start && i < blackout_start + blackout_size) continue;
                large_tensor[i] = ~large_tensor[i] + 1u;  // S_rx(t) = -S_tx(t)
            }

            // 2. 수신 파이프라인
            (void)engine.Recover_Tensor_Pipeline(
                large_tensor.data(), config.node_count,
                session_id, config.temporal_slice_chunk);

            auto end = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double, std::milli> elapsed = end - start;

            // 3. 1비트 단위 무결성 검증
            bool is_perfect_recovery = true;
            size_t corrupted_nodes = 0;
            for (size_t i = 0; i < config.node_count; ++i) {
                if (large_tensor[i] != original_tensor[i]) {
                    is_perfect_recovery = false;
                    corrupted_nodes++;
                }
            }

            // 4. 결과 출력
            // [양산 수정] node_count * 0.30103 → 정수 근사 (log10(2) ≈ 301/1000)
            uint32_t entropy_exponent = static_cast<uint32_t>(
                static_cast<uint64_t>(config.node_count) * 301u / 1000u);

            std::cout << "\n=================================================================\n";
            std::cout << " [INNOVID HTS] HTS-32 SERVER STRESS TEST RESULT\n";
            std::cout << "=================================================================\n";
            std::cout << " -> System Tier      : HYPER_SERVER\n";
            std::cout << " -> Total Nodes      : " << config.node_count << " Nodes\n";
            std::cout << " -> Processing Time  : " << elapsed.count() << " ms\n";
            std::cout << " -> Security Entropy : 10^" << entropy_exponent << "\n";
            std::cout << "-----------------------------------------------------------------\n";
            std::cout << " [Deep Space Environment Simulation]\n";
            std::cout << " -> Jamming Applied  : 80% Phase Inversion (-S_tx)\n";
            std::cout << " -> Signal Loss      : 10% Continuous Blackout\n";
            std::cout << " -> Recovery Status  : "
                << (is_perfect_recovery ? "SUCCESS (100% Data Restored)" : "FAILED") << "\n";
            if (!is_perfect_recovery) {
                std::cout << " -> Corrupted Nodes  : " << corrupted_nodes
                    << " / " << config.node_count << "\n";
            }
            std::cout << "=================================================================\n";

        }
        catch (const std::bad_alloc&) {
            std::cerr << "\n[FATAL] Server Stress Test: Memory allocation failed.\n";
            std::abort();
        }
        catch (...) {
            std::cerr << "\n[FATAL] Server Stress Test: Unexpected error.\n";
        }
    }
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

} // namespace ProtectedEngine