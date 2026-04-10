// =========================================================================
// HTS_TPE_Bitwise_Simulation_main.cpp
// TPE 비트 논리 코어 — PC 콘솔 시뮬레이션 (Dummy 폭탄 + 타이밍)
// Build: HTS_TEST\HTS_검증_TPE_Bitwise.vcxproj (헤더: HTS_TEST\HTS_TPE_Bitwise_Controller.h)
// =========================================================================

#include "HTS_TPE_Bitwise_Controller.h"

#include <chrono>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace {

    using clock_hr = std::chrono::high_resolution_clock;

    [[nodiscard]] int32_t neighbor_prev(
        const std::vector<int32_t>& v,
        std::size_t i) noexcept
    {
        if (i == 0u) {
            return v[0];
        }
        return v[i - 1u];
    }

    [[nodiscard]] int32_t neighbor_next(
        const std::vector<int32_t>& v,
        std::size_t i) noexcept
    {
        if (i + 1u >= v.size()) {
            return v[i];
        }
        return v[i + 1u];
    }

    [[nodiscard]] std::string status_for_row(int32_t raw, int32_t out) noexcept
    {
        const bool zeroed = (out == 0) && (raw != 0);
        const bool strong = (raw > 1000) || (raw < -1000);

        if (zeroed && strong) {
            return "[폭탄 제거 완료]";
        }
        if ((!zeroed) && strong) {
            return "[극단값 유지 — 국소최대 또는 thr 미충족]";
        }
        if ((!zeroed) && (!strong)) {
            return "[정상 부호 추출]";
        }
        if (zeroed && (!strong)) {
            return "[출력 0 — 저에너지 샘플]";
        }
        return "[기타]";
    }

} // namespace

int main()
{
    constexpr int32_t k_threshold = 1000;

    std::vector<int32_t> raw_data;
    raw_data.reserve(32u);

    // 정상 신호: -50 ~ +50 사이를 번갈아 채움
    for (int i = 0; i < 8; ++i) {
        raw_data.push_back(static_cast<int32_t>(-40 + i * 7));
    }
    // (+) 폭탄 1: 국소 최대 + 임계 초과
    raw_data.push_back(12);
    raw_data.push_back(850000);
    raw_data.push_back(15);
    raw_data.push_back(-30);
    // (+) 폭탄 2
    raw_data.push_back(20);
    raw_data.push_back(910000);
    raw_data.push_back(22);
    // (-) 극단 (thr=1000 규약상 TPE 피크로 잘리지 않음 — 교육용)
    raw_data.push_back(-920000);
    raw_data.push_back(5);
    // (+) 폭탄 3
    raw_data.push_back(-10);
    raw_data.push_back(875000);
    raw_data.push_back(-12);
    // 꼬리 정상
    for (int i = 0; i < 5; ++i) {
        raw_data.push_back(static_cast<int32_t>(10 - i * 3));
    }

    std::vector<int32_t> tpe_out;
    tpe_out.resize(raw_data.size());

    const auto t0 = clock_hr::now();
    for (std::size_t i = 0u; i < raw_data.size(); ++i) {
        const int32_t prev = neighbor_prev(raw_data, i);
        const int32_t next = neighbor_next(raw_data, i);
        const int32_t curr = raw_data[i];
        tpe_out[i] = ProtectedEngine::TPE_Bitwise::TPE_Core_Process_I32(
            prev,
            curr,
            next,
            k_threshold);
    }
    const auto t1 = clock_hr::now();
    const auto elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        t1 - t0);

    std::cout << "=== HTS TPE Bitwise — field simulation ===\n";
    std::cout << "Threshold (int32): " << k_threshold << "\n";
    std::cout << "Samples: " << raw_data.size() << "\n";
    std::cout << "Total TPE pass (high_resolution_clock): "
              << elapsed_ns.count() << " ns\n\n";

    std::cout << std::left << std::setw(6) << "idx"
              << " | " << std::setw(12) << "Raw"
              << " | " << std::setw(12) << "TPE out"
              << " | " << std::setw(6) << "Sign"
              << " | " << "Status\n";
    std::cout << std::string(88u, '-') << "\n";

    for (std::size_t i = 0u; i < raw_data.size(); ++i) {
        const int32_t raw = raw_data[i];
        const int32_t out = tpe_out[i];
        const int32_t sg = ProtectedEngine::TPE_Bitwise::Extract_State(raw);
        const std::string st = status_for_row(raw, out);

        std::cout << std::setw(6) << static_cast<int>(i) << " | "
                  << std::setw(12) << raw << " | "
                  << std::setw(12) << out << " | "
                  << std::setw(6) << sg << " | "
                  << st << "\n";
    }

    std::cout << "\nNote: TPE_Core_Process_I32 절단 조건 = 국소 최대이면서 curr > thr.\n"
                 "      음의 극단(-920000 등)은 thr=1000 에서 'curr > thr' 가 거짓이라 유지됩니다.\n";
    return 0;
}
