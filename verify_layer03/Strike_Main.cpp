// HTS 3단계 실전 검증 — Layer 0~3 경계값 스트라이크 (호스트 링크 HTS_LIM_V3.lib)
// NULL / 극단 길이 / 출력 NULL 등 악의적 인자 — 크래시 없이 기대 불리만 반환하는지 확인

#include "HTS_ConstantTimeUtil.h"
#include "HTS_Crc32Util.h"
#include "HTS_Secure_Memory.h"
#include "HTS_SHA256_Bridge.h"

#include <cstddef>
#include <cstdint>

namespace {

int g_failures = 0;

void strike_check(const char* /*tag*/, bool ok) noexcept {
    if (!ok) {
        ++g_failures;
    }
}

} // namespace

int main() {
    using namespace ProtectedEngine;

    alignas(8) uint8_t buf[4] = {1u, 2u, 3u, 4u};
    alignas(8) uint8_t out[ProtectedEngine::SHA256_Bridge::DIGEST_LEN] = {};

    strike_check("ct_compare_null_null_len0",
                 ConstantTimeUtil::compare(nullptr, nullptr, 0u));
    strike_check("ct_compare_null_buf_reject",
                 !ConstantTimeUtil::compare(nullptr, buf, 1u));
    strike_check("ct_compare_variable_both_empty",
                 ConstantTimeUtil::compare_variable(nullptr, 0u, nullptr, 0u));

    strike_check("crc32_null_maxlen_zero",
                 Crc32Util::calculate(nullptr, static_cast<size_t>(-1)) == 0u);

    SecureMemory::secureWipe(nullptr, static_cast<size_t>(-1));
    SecureMemory::lockMemory(nullptr, 1u);

    strike_check("sha256_null_in_len0",
                 SHA256_Bridge::Hash(nullptr, 0u, out));
    strike_check("sha256_null_in_len1_fail",
                 !SHA256_Bridge::Hash(nullptr, 1u, out));
    strike_check("sha256_null_out_fail",
                 !SHA256_Bridge::Hash(buf, sizeof(buf), nullptr));

    return (g_failures == 0) ? 0 : 1;
}
