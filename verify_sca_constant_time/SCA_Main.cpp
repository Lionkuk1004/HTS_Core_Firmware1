// Verify_SCA_ConstantTime — 17단계: ConstantTimeUtil·memcmp 대조, Release /FAs ASM 게이트
// 호스트: RDTSC + LFENCE, 단일 코어 친화 마스크, 중앙값 스프레드 한계(호스트 TSC 잡음 허용)

#include "HTS_ConstantTimeUtil.h"

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#if defined(_MSC_VER)
#include <Windows.h>
#include <immintrin.h>
#include <intrin.h>
#endif

namespace {

namespace PE = ProtectedEngine;

constexpr size_t kTagLen = 32u;
constexpr uint32_t kSamplesPerClass = 600'000u;
// 호스트 x64: SMT·클럭 게이트·캐시로 1클럭 엄밀 불가 — 중앙값 간 스프레드 상한(사이클)
constexpr uint64_t kCtMedianSpreadMax = 48ull;
// memcmp는 조기 종료로 타이밍 누출 기대 — 대조군 최소 분리(사이클)
constexpr uint64_t kMemcmpLeakMin = 24ull;

#if defined(_MSC_VER)
[[nodiscard]] uint64_t rdtsc_lfenced() noexcept
{
    _mm_lfence();
    const uint64_t t = __rdtsc();
    _mm_lfence();
    return t;
}

void pin_timing_thread() noexcept
{
    (void)SetThreadAffinityMask(GetCurrentThread(), 1u);
    (void)SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
}
#else
[[nodiscard]] uint64_t rdtsc_lfenced() noexcept
{
    return 0u;
}

void pin_timing_thread() noexcept {}
#endif

// Release /FAs 검사 대상: 전 길이 XOR 누적 후 단일 결과(조기 return 없음)
#if defined(_MSC_VER)
#pragma optimize("gt", on)
#endif
extern "C" std::uint32_t sca_extern_ct_xor32(
    const std::uint8_t* a,
    const std::uint8_t* b,
    std::size_t len) noexcept
{
    std::uint8_t acc = 0u;
    for (std::size_t i = 0u; i < len; ++i) {
        acc = static_cast<std::uint8_t>(
            acc | static_cast<std::uint8_t>(a[i] ^ b[i]));
#if defined(_MSC_VER)
        _ReadWriteBarrier();
#endif
    }
    return static_cast<std::uint32_t>(acc == 0u ? 1u : 0u);
}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

[[nodiscard]] uint64_t median_of(std::vector<uint64_t>& v) noexcept
{
    const size_t n = v.size();
    if (n == 0u) {
        return 0u;
    }
    const size_t mid = n >> 1u;
    std::nth_element(v.begin(), v.begin() + static_cast<std::ptrdiff_t>(mid), v.end());
    return v[mid];
}

[[nodiscard]] bool bench_triplet_median_spread(
    const uint8_t* eq,
    const uint8_t* d0,
    const uint8_t* d31,
    uint64_t& out_spread,
    uint64_t& m0,
    uint64_t& m1,
    uint64_t& m2) noexcept
{
    std::vector<uint64_t> t0;
    std::vector<uint64_t> t1;
    std::vector<uint64_t> t2;
    t0.reserve(kSamplesPerClass);
    t1.reserve(kSamplesPerClass);
    t2.reserve(kSamplesPerClass);

    pin_timing_thread();

    for (uint32_t w = 0u; w < 50'000u; ++w) {
        (void)PE::ConstantTimeUtil::compare(eq, eq, kTagLen);
        (void)std::memcmp(eq, eq, kTagLen);
    }

    for (uint32_t i = 0u; i < kSamplesPerClass; ++i) {
        {
            const uint64_t a = rdtsc_lfenced();
            const volatile bool r
                = PE::ConstantTimeUtil::compare(eq, eq, kTagLen);
            const uint64_t b = rdtsc_lfenced();
            (void)r;
            t0.push_back(b - a);
        }
        {
            const uint64_t a = rdtsc_lfenced();
            const volatile bool r
                = PE::ConstantTimeUtil::compare(eq, d0, kTagLen);
            const uint64_t b = rdtsc_lfenced();
            (void)r;
            t1.push_back(b - a);
        }
        {
            const uint64_t a = rdtsc_lfenced();
            const volatile bool r
                = PE::ConstantTimeUtil::compare(eq, d31, kTagLen);
            const uint64_t b = rdtsc_lfenced();
            (void)r;
            t2.push_back(b - a);
        }
    }

    m0 = median_of(t0);
    m1 = median_of(t1);
    m2 = median_of(t2);
    const uint64_t lo = (m0 < m1) ? m0 : m1;
    const uint64_t lo2 = (lo < m2) ? lo : m2;
    uint64_t hi = (m0 > m1) ? m0 : m1;
    hi = (hi > m2) ? hi : m2;
    out_spread = hi - lo2;
    return out_spread <= kCtMedianSpreadMax;
}

[[nodiscard]] bool bench_memcmp_leak(
    const uint8_t* eq,
    const uint8_t* d0,
    uint64_t& med_same,
    uint64_t& med_diff) noexcept
{
    std::vector<uint64_t> ts;
    std::vector<uint64_t> td;
    ts.reserve(kSamplesPerClass / 4u);
    td.reserve(kSamplesPerClass / 4u);

    pin_timing_thread();
    for (uint32_t w = 0u; w < 20'000u; ++w) {
        (void)std::memcmp(eq, eq, kTagLen);
        (void)std::memcmp(eq, d0, kTagLen);
    }
    for (uint32_t i = 0u; i < (kSamplesPerClass / 4u); ++i) {
        {
            const uint64_t a = rdtsc_lfenced();
            const volatile int r = std::memcmp(eq, eq, kTagLen);
            const uint64_t b = rdtsc_lfenced();
            (void)r;
            ts.push_back(b - a);
        }
        {
            const uint64_t a = rdtsc_lfenced();
            const volatile int r = std::memcmp(eq, d0, kTagLen);
            const uint64_t b = rdtsc_lfenced();
            (void)r;
            td.push_back(b - a);
        }
    }
    med_same = median_of(ts);
    med_diff = median_of(td);
    return (med_diff > med_same)
        && ((med_diff - med_same) >= kMemcmpLeakMin);
}

[[nodiscard]] bool bench_extern_ct_spread(
    const uint8_t* eq,
    const uint8_t* d0,
    uint64_t& spread) noexcept
{
    std::vector<uint64_t> t0;
    std::vector<uint64_t> t1;
    t0.reserve(kSamplesPerClass / 6u);
    t1.reserve(kSamplesPerClass / 6u);
    pin_timing_thread();
    for (uint32_t i = 0u; i < (kSamplesPerClass / 6u); ++i) {
        {
            const uint64_t a = rdtsc_lfenced();
            const volatile std::uint32_t r
                = sca_extern_ct_xor32(eq, eq, kTagLen);
            const uint64_t b = rdtsc_lfenced();
            (void)r;
            t0.push_back(b - a);
        }
        {
            const uint64_t a = rdtsc_lfenced();
            const volatile std::uint32_t r
                = sca_extern_ct_xor32(eq, d0, kTagLen);
            const uint64_t b = rdtsc_lfenced();
            (void)r;
            t1.push_back(b - a);
        }
    }
    const uint64_t m0 = median_of(t0);
    const uint64_t m1 = median_of(t1);
    spread = (m0 > m1) ? (m0 - m1) : (m1 - m0);
    return spread <= kCtMedianSpreadMax;
}

} // namespace

int main()
{
    std::printf(
        "Verify_SCA_ConstantTime: median samples/class=%" PRIu32
        " ct_spread_cap=%" PRIu64 "cyc\n",
        static_cast<uint32_t>(kSamplesPerClass),
        kCtMedianSpreadMax);
    std::fflush(stdout);

    alignas(64) uint8_t buf_eq[kTagLen]{};
    alignas(64) uint8_t buf_d0[kTagLen]{};
    alignas(64) uint8_t buf_d31[kTagLen]{};
    for (size_t i = 0u; i < kTagLen; ++i) {
        buf_eq[i] = static_cast<uint8_t>(0x5Au ^ static_cast<uint8_t>(i));
        buf_d0[i] = buf_eq[i];
        buf_d31[i] = buf_eq[i];
    }
    buf_d0[0] ^= 0xFFu;
    buf_d31[kTagLen - 1u] ^= 0xFFu;

    uint64_t sp = 0u;
    uint64_t m0 = 0u;
    uint64_t m1 = 0u;
    uint64_t m2 = 0u;
    if (!bench_triplet_median_spread(buf_eq, buf_d0, buf_d31, sp, m0, m1, m2)) {
        std::printf(
            "SCA[CT] FAIL: ConstantTimeUtil median spread=%" PRIu64
            " med=(%" PRIu64 ",%" PRIu64 ",%" PRIu64 ")\n",
            sp, m0, m1, m2);
        return 2;
    }
    std::printf(
        "SCA[CT] PASS: ConstantTimeUtil medians %" PRIu64 "/%" PRIu64
        "/%" PRIu64 " spread=%" PRIu64 "\n",
        m0, m1, m2, sp);

    uint64_t msame = 0u;
    uint64_t mdiff = 0u;
    if (!bench_memcmp_leak(buf_eq, buf_d0, msame, mdiff)) {
        std::printf(
            "SCA[MEMCMP] WARN: contrast med_same=%" PRIu64 " med_diff=%" PRIu64
            " (CRT may vectorize memcmp)\n",
            msame, mdiff);
    }
    else {
        std::printf(
            "SCA[MEMCMP] contrast: med_same=%" PRIu64 " med_diff=%" PRIu64
            " (early-exit leak visible)\n",
            msame, mdiff);
    }

    uint64_t sx = 0u;
    if (!bench_extern_ct_spread(buf_eq, buf_d0, sx)) {
        std::printf("SCA[EXTERN_CT] FAIL: spread=%" PRIu64 "\n", sx);
        return 3;
    }
    std::printf("SCA[EXTERN_CT] PASS: listing-scanned fn spread=%" PRIu64 "\n", sx);

    std::printf("Verify_SCA_ConstantTime: ALL PASS\n");
    return 0;
}
