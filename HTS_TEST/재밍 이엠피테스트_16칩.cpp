// =========================================================================
// HTS_DIOC_Jamming_Test.cpp
// B-CDMA DIOC 항재밍 코어 — 재밍 시나리오별 성능 검증
// Target: PC 시뮬레이션 전용
//
// [시나리오]
//  1. Clean      : 재밍 없음 (기준선)
//  2. AWGN       : 백색 가우시안 잡음
//  3. Barrage    : 광대역 재밍 (전 슬롯 J/S +30~60dB)
//  4. EMP Pulse  : 고에너지 임펄스 (랜덤 슬롯 3~10% 파괴)
//  5. Spot Tone  : 단일 주파수 재밍 (특정 슬롯 집중)
//  6. Composite  : Barrage + EMP + Spot 복합
//
// [측정 지표]
//  - Symbol Error Rate (SER): 4비트 심볼 오류율
//  - Detection Failure Rate: Decode_4Bit == -1 비율
//  - Throughput: 유효 심볼/초 (재밍 하에서)
//
// [빌드]
//  g++ -std=c++17 -O2 -o dioc_test HTS_DIOC_Jamming_Test.cpp \
//      HTS_3D_Tensor_FEC.cpp -I.
// =========================================================================

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
    defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#error "[HTS_FATAL] 이 파일은 PC 시뮬레이션 전용입니다."
#endif

#include "HTS_3D_Tensor_FEC.h"

#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
#include <vector>
#include <chrono>

using namespace ProtectedEngine;

// =========================================================================
//  채널 파라미터
// =========================================================================
namespace Channel {
    static constexpr int UNIVERSE = 1024;  // 슬롯 수

    // 재밍 강도 프리셋
    struct JammingProfile {
        const char* name;

        // AWGN
        double awgn_sigma;          // 가우시안 잡음 표준편차

        // Barrage
        double barrage_sigma;       // 광대역 재밍 강도
        double barrage_coverage;    // 재밍 커버리지 (0.0~1.0)

        // EMP
        double emp_amplitude;       // 임펄스 진폭
        double emp_rate;            // 슬롯당 피격 확률

        // Spot Tone
        int    spot_center;         // 중심 슬롯
        int    spot_width;          // 반경 (슬롯 수)
        double spot_amplitude;      // 톤 진폭
    };

    // ── 프리셋 정의 ──
    static const JammingProfile PROFILES[] = {
        // 1. Clean
        {
            "Clean (No Jamming)",
            0.0,        // awgn
            0.0, 0.0,   // barrage
            0.0, 0.0,   // emp
            0, 0, 0.0   // spot
        },
        // 2. AWGN Only (SNR ~10dB)
        {
            "AWGN Only (sigma=50)",
            50.0,
            0.0, 0.0,
            0.0, 0.0,
            0, 0, 0.0
        },
        // 3. Barrage Jamming (J/S +40dB, 전 슬롯)
        {
            "Barrage J/S +40dB (full band)",
            20.0,               // 배경 AWGN
            500.0, 1.0,         // 광대역 전체
            0.0, 0.0,
            0, 0, 0.0
        },
        // 4. Barrage Jamming (J/S +50dB, 전 슬롯)
        {
            "Barrage J/S +50dB (full band)",
            20.0,
            1500.0, 1.0,
            0.0, 0.0,
            0, 0, 0.0
        },
        // 5. EMP Pulse (3% 슬롯 파괴, 고에너지)
        {
            "EMP Pulse (3% slots, amp=99999)",
            10.0,
            0.0, 0.0,
            99999.0, 0.03,
            0, 0, 0.0
        },
        // 6. EMP Pulse (10% 슬롯 파괴)
        {
            "EMP Pulse (10% slots, amp=99999)",
            10.0,
            0.0, 0.0,
            99999.0, 0.10,
            0, 0, 0.0
        },
        // 7. Spot Tone (슬롯 500 중심, 반경 30)
        {
            "Spot Tone (center=500, width=30)",
            10.0,
            0.0, 0.0,
            0.0, 0.0,
            500, 30, 5000.0
        },
        // 8. Composite: Barrage + EMP
        {
            "Composite: Barrage+EMP",
            30.0,
            800.0, 1.0,        // 중간 광대역
            99999.0, 0.05,      // 5% EMP
            0, 0, 0.0
        },
        // 9. Composite: Barrage + EMP + Spot (최악)
        {
            "Composite: Barrage+EMP+Spot (Worst)",
            50.0,
            1000.0, 1.0,
            99999.0, 0.08,
            512, 50, 8000.0
        },
        // 10. Extreme: J/S +60dB + 15% EMP
        {
            "EXTREME: J/S+60dB + 15% EMP",
            50.0,
            5000.0, 1.0,
            99999.0, 0.15,
            256, 40, 10000.0
        },
    };

    static constexpr int NUM_PROFILES =
        static_cast<int>(sizeof(PROFILES) / sizeof(PROFILES[0]));

    // =====================================================================
    //  채널 시뮬레이터 — 재밍 프로파일 적용
    // =====================================================================
    static void apply_channel(
        int16_t* universe_I,
        int16_t* universe_Q,
        const std::array<HTS16_DIOC_Core::SparseChip, 16>& tx_frame,
        const JammingProfile& prof,
        std::mt19937& rng) noexcept
    {
        // 1. 초기화: 배경 잡음
        std::normal_distribution<double> awgn(0.0, std::max(prof.awgn_sigma, 0.1));
        for (int s = 0; s < UNIVERSE; ++s) {
            universe_I[s] = static_cast<int16_t>(
                std::clamp(awgn(rng), -32000.0, 32000.0));
            universe_Q[s] = static_cast<int16_t>(
                std::clamp(awgn(rng), -32000.0, 32000.0));
        }

        // 2. 신호 삽입 (칩당 에너지 = ±128 × NUM_CHIPS 스케일링)
        static constexpr int16_t CHIP_ENERGY = 128;
        for (int i = 0; i < 16; ++i) {
            int s = tx_frame[i].slot_index;
            universe_I[s] += static_cast<int16_t>(
                tx_frame[i].polarity_I * CHIP_ENERGY);
            universe_Q[s] += static_cast<int16_t>(
                tx_frame[i].polarity_Q * CHIP_ENERGY);
        }

        // 3. Barrage 재밍
        if (prof.barrage_sigma > 0.0 && prof.barrage_coverage > 0.0) {
            std::normal_distribution<double> barrage(0.0, prof.barrage_sigma);
            std::uniform_real_distribution<double> u01(0.0, 1.0);
            for (int s = 0; s < UNIVERSE; ++s) {
                if (u01(rng) < prof.barrage_coverage) {
                    universe_I[s] += static_cast<int16_t>(
                        std::clamp(barrage(rng), -30000.0, 30000.0));
                    universe_Q[s] += static_cast<int16_t>(
                        std::clamp(barrage(rng), -30000.0, 30000.0));
                }
            }
        }

        // 4. EMP 임펄스
        if (prof.emp_amplitude > 0.0 && prof.emp_rate > 0.0) {
            std::uniform_real_distribution<double> u01(0.0, 1.0);
            for (int s = 0; s < UNIVERSE; ++s) {
                if (u01(rng) < prof.emp_rate) {
                    double sign = (u01(rng) > 0.5) ? 1.0 : -1.0;
                    universe_I[s] = static_cast<int16_t>(std::clamp(
                        sign * prof.emp_amplitude, -32767.0, 32767.0));
                    universe_Q[s] = static_cast<int16_t>(std::clamp(
                        sign * prof.emp_amplitude, -32767.0, 32767.0));
                }
            }
        }

        // 5. Spot Tone
        if (prof.spot_amplitude > 0.0 && prof.spot_width > 0) {
            const int lo = std::max(0, prof.spot_center - prof.spot_width);
            const int hi = std::min(UNIVERSE - 1,
                prof.spot_center + prof.spot_width);
            std::normal_distribution<double> tone(0.0, prof.spot_amplitude);
            for (int s = lo; s <= hi; ++s) {
                universe_I[s] += static_cast<int16_t>(
                    std::clamp(tone(rng), -32000.0, 32000.0));
                universe_Q[s] += static_cast<int16_t>(
                    std::clamp(tone(rng), -32000.0, 32000.0));
            }
        }
    }

} // namespace Channel

// =========================================================================
//  테스트 실행기
// =========================================================================
struct TestResult {
    const char* scenario_name;
    int         total_symbols;
    int         correct;
    int         errors;
    int         failures;       // Decode == -1
    double      ser;            // Symbol Error Rate
    double      failure_rate;
    double      throughput_pct; // 유효 처리율 (%)
    double      elapsed_ms;
};

static TestResult run_scenario(
    const Channel::JammingProfile& prof,
    int num_symbols,
    uint32_t seed)
{
    TestResult res{};
    res.scenario_name = prof.name;
    res.total_symbols = num_symbols;

    std::mt19937 rng(seed + 12345u);

    auto t_start = std::chrono::high_resolution_clock::now();

    int correct = 0, errors = 0, failures = 0;

    for (int sym = 0; sym < num_symbols; ++sym) {
        // TX/RX 독립 인스턴스 — 동일 시드 (PRNG 동기)
        const uint32_t frame_seed = seed + static_cast<uint32_t>(sym) * 31u;
        HTS16_DIOC_Core tx(frame_seed);
        HTS16_DIOC_Core rx(frame_seed);

        // 랜덤 4비트 데이터
        const uint8_t data = static_cast<uint8_t>(rng() & 0x0Fu);

        // 송신
        auto tx_frame = tx.Transmit_4Bit(data);

        // 채널 시뮬레이션
        int16_t universe_I[Channel::UNIVERSE] = {};
        int16_t universe_Q[Channel::UNIVERSE] = {};
        Channel::apply_channel(universe_I, universe_Q,
            tx_frame, prof, rng);

        // 수신
        int16_t decoded = rx.Decode_4Bit(universe_I, universe_Q);

        if (decoded == -1) {
            ++failures;
        }
        else if (static_cast<uint8_t>(decoded) != data) {
            ++errors;
        }
        else {
            ++correct;
        }
    }

    auto t_end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(
        t_end - t_start).count();

    res.correct = correct;
    res.errors = errors;
    res.failures = failures;
    res.ser = static_cast<double>(errors + failures) / num_symbols;
    res.failure_rate = static_cast<double>(failures) / num_symbols;
    res.throughput_pct = 100.0 * correct / num_symbols;
    res.elapsed_ms = ms;
    return res;
}

// =========================================================================
//  결과 출력
// =========================================================================
static void print_header() {
    std::cout
        << "\n"
        << "+====================================================================+\n"
        << "|     HTS B-CDMA DIOC Anti-Jamming Performance Test                  |\n"
        << "|     16-chip PSL=4 Optimal Codebook + OS-CFAR + PRNG FH            |\n"
        << "+====================================================================+\n\n";
}

static void print_result(const TestResult& r) {
    std::cout << std::fixed;
    std::cout
        << "+--------------------------------------------------------------------+\n"
        << "| Scenario: " << std::left << std::setw(53)
        << r.scenario_name << "|\n"
        << "+--------------------------------------------------------------------+\n"
        << "|  Total Symbols  : " << std::setw(8) << r.total_symbols
        << "                                        |\n"
        << "|  Correct        : " << std::setw(8) << r.correct
        << "  (" << std::setprecision(2) << std::setw(6)
        << r.throughput_pct << "%)                            |\n"
        << "|  Symbol Errors  : " << std::setw(8) << r.errors
        << "                                        |\n"
        << "|  Detect Failures: " << std::setw(8) << r.failures
        << "  (rate=" << std::setprecision(4) << std::setw(8)
        << r.failure_rate << ")                       |\n"
        << "|  SER            : " << std::scientific << std::setprecision(3)
        << r.ser << std::fixed
        << "                                     |\n"
        << "|  Elapsed        : " << std::setprecision(1)
        << r.elapsed_ms << " ms"
        << "                                        |\n"
        << "+--------------------------------------------------------------------+\n\n";
}

static void print_summary(const std::vector<TestResult>& results) {
    std::cout
        << "\n"
        << "+=======================================================================+\n"
        << "|                         Summary Table                                 |\n"
        << "+=======================================================================+\n"
        << "| # | Scenario                            |   SER    | Fail%  | OK%    |\n"
        << "+---+-------------------------------------+----------+--------+--------+\n";

    for (int i = 0; i < static_cast<int>(results.size()); ++i) {
        const auto& r = results[i];
        char line[128];
        std::snprintf(line, sizeof(line),
            "| %d | %-35.35s | %8.2e | %5.2f%% | %5.1f%% |",
            i + 1, r.scenario_name, r.ser,
            r.failure_rate * 100.0, r.throughput_pct);
        std::cout << line << "\n";
    }

    std::cout
        << "+---+-------------------------------------+----------+--------+--------+\n\n";

    // 판정
    std::cout << "[판정 기준]\n"
        << "  PASS : Clean SER=0, Barrage+40dB SER<5%, EMP 3% SER<1%\n"
        << "  WARN : Composite SER<20%\n"
        << "  FAIL : Clean SER>0 또는 EXTREME SER>50%\n\n";

    for (const auto& r : results) {
        const char* verdict = "PASS";
        if (r.ser > 0.50) verdict = "FAIL";
        else if (r.ser > 0.20) verdict = "WARN";
        else if (r.ser > 0.05) verdict = "MARGINAL";

        std::string name(r.scenario_name);
        if (name.find("Clean") != std::string::npos && r.ser > 0.0)
            verdict = "FAIL";

        std::cout << "  [" << verdict << "] " << r.scenario_name
            << " (SER=" << std::scientific << std::setprecision(2)
            << r.ser << std::fixed << ")\n";
    }
    std::cout << "\n";
}

// =========================================================================
//  메인
// =========================================================================
int main() {
    print_header();

    static constexpr int SYMBOLS_PER_SCENARIO = 10000;
    static constexpr uint32_t BASE_SEED = 0xB0CD0A01u;

    std::vector<TestResult> results;
    results.reserve(Channel::NUM_PROFILES);

    for (int i = 0; i < Channel::NUM_PROFILES; ++i) {
        std::cout << "[" << (i + 1) << "/" << Channel::NUM_PROFILES
            << "] Running: " << Channel::PROFILES[i].name
            << " (" << SYMBOLS_PER_SCENARIO << " symbols)...\n";

        auto r = run_scenario(
            Channel::PROFILES[i],
            SYMBOLS_PER_SCENARIO,
            BASE_SEED + static_cast<uint32_t>(i) * 1000u);

        print_result(r);
        results.push_back(r);
    }

    print_summary(results);

    return 0;
}