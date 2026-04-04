// HTS 3단계 실전 검증 — Layer 4~7 경계값 스트라이크 (호스트 + HTS_LIM_V3.lib)
// Layer 4: KAT / 조건부 자가진단
// Layer 5: 키 프로비저닝 / 시드 로테이터 / 시큐어 부트 C API
// Layer 6: 안티디버그 폴링(호스트 무해)
// Layer 7: SecureLogger / Device_Profile / Dynamic_Config / 정적 Config

#include "HTS_Anti_Debug.h"
#include "HTS_Conditional_SelfTest.h"
#include "HTS_Config.h"
#include "HTS_Crypto_KAT.h"
#include "HTS_Device_Profile.h"
#include "HTS_Dynamic_Config.h"
#include "HTS_Key_Provisioning.h"
#include "HTS_Key_Rotator.h"
#include "HTS_Secure_Boot_Verify.h"
#include "HTS_Secure_Logger.h"

#include <cstddef>
#include <cstdint>

namespace {

int g_failures = 0;

void strike_check(const char* /*tag*/, bool ok) noexcept {
    if (!ok) {
        ++g_failures;
    }
}

size_t flash_read_always_fail(uint32_t /*addr*/, uint8_t* /*buf*/, size_t /*len*/) noexcept {
    return 0u;
}

} // namespace

int main() {
    using namespace ProtectedEngine;

    strike_check("static_config_nodes",
                 HTS_Static_Config::Get_Tensor_Node_Count() >= 32u);

    // ── Layer 4: KAT (악의적 인자 없음 — 전원 투입 시나리오) ─────────────
    strike_check("crypto_kat_run_all", Crypto_KAT::Run_All_Crypto_KAT());

    alignas(8) uint8_t aria_key[32] = {};
    strike_check("cst_aria_null_key", !Conditional_SelfTest::Verify_ARIA_Key(nullptr, 128));
    strike_check("cst_aria_bad_bits", !Conditional_SelfTest::Verify_ARIA_Key(aria_key, -1));
    strike_check("cst_aria_bad_bits2", !Conditional_SelfTest::Verify_ARIA_Key(aria_key, 127));

    alignas(8) uint8_t lea_iv[16] = {};
    strike_check("cst_lea_null_key", !Conditional_SelfTest::Verify_LEA_Key(nullptr, 16u, lea_iv));
    strike_check("cst_lea_null_iv", !Conditional_SelfTest::Verify_LEA_Key(aria_key, 16u, nullptr));
    strike_check("cst_lea_bad_len", !Conditional_SelfTest::Verify_LEA_Key(aria_key, 15u, lea_iv));

    alignas(8) uint8_t hmac_key[32] = {};
    alignas(8) uint8_t expect_hmac[32] = {};
    strike_check("cst_flash_null_cb",
                 !Conditional_SelfTest::Verify_Flash_Integrity(
                     nullptr, 0u, 256u, hmac_key, expect_hmac));
    strike_check("cst_flash_null_key",
                 !Conditional_SelfTest::Verify_Flash_Integrity(
                     flash_read_always_fail, 0u, 256u, nullptr, expect_hmac));
    strike_check("cst_flash_zero_size",
                 !Conditional_SelfTest::Verify_Flash_Integrity(
                     flash_read_always_fail, 0u, 0u, hmac_key, expect_hmac));
    strike_check("cst_flash_cb_fail",
                 !Conditional_SelfTest::Verify_Flash_Integrity(
                     flash_read_always_fail, 0u, 256u, hmac_key, expect_hmac));

    // ── Layer 5: 키 / 부트 ─────────────────────────────────────────────
    {
        HTS_Key_Provisioning kp;
        alignas(8) uint8_t wrap40[40] = {};
        alignas(8) uint8_t kek[32] = {};
        strike_check("keyprov_inject_null_wrap",
                     kp.Inject_Key(nullptr, HTS_Key_Provisioning::WRAPPED_KEY_SIZE,
                                   kek, HTS_Key_Provisioning::MASTER_KEY_SIZE)
                         == KeyProvResult::NULL_INPUT);
        strike_check("keyprov_inject_null_kek",
                     kp.Inject_Key(wrap40, HTS_Key_Provisioning::WRAPPED_KEY_SIZE,
                                   nullptr, HTS_Key_Provisioning::MASTER_KEY_SIZE)
                         == KeyProvResult::NULL_INPUT);
        strike_check("keyprov_inject_bad_wrap_len",
                     kp.Inject_Key(wrap40, static_cast<size_t>(-1),
                                   kek, HTS_Key_Provisioning::MASTER_KEY_SIZE)
                         == KeyProvResult::INVALID_LEN);
        strike_check("keyprov_inject_bad_kek_len",
                     kp.Inject_Key(wrap40, HTS_Key_Provisioning::WRAPPED_KEY_SIZE,
                                   kek, 0u)
                         == KeyProvResult::INVALID_LEN);

        uint8_t* null_out = nullptr;
        strike_check("keyprov_read_null_out",
                     kp.Read_Master_Key(null_out, HTS_Key_Provisioning::MASTER_KEY_SIZE)
                         == HTS_Key_Provisioning::SECURE_FALSE);
        alignas(8) uint8_t outmk[32] = {};
        strike_check("keyprov_read_short_buf",
                     kp.Read_Master_Key(outmk, HTS_Key_Provisioning::MASTER_KEY_SIZE - 1u)
                         == HTS_Key_Provisioning::SECURE_FALSE);
    }

    {
        DynamicKeyRotator rot(nullptr, static_cast<size_t>(-1));
        size_t out_len = 0u;
        alignas(8) uint8_t seed_out[32] = {};
        strike_check("keyrot_derive_null_out",
                     !rot.deriveNextSeed(0xFFFFFFFFu, nullptr, sizeof(seed_out), out_len));
        strike_check("keyrot_derive_zero_cap",
                     !rot.deriveNextSeed(0u, seed_out, 0u, out_len));
        strike_check("keyrot_derive_ok_small",
                     rot.deriveNextSeed(0u, seed_out, sizeof(seed_out), out_len)
                         && (out_len == 32u));
    }

    (void)HTS_Secure_Boot_Check();
    (void)HTS_Secure_Boot_Is_Verified();

    // ── Layer 6 (호스트: MMIO 폴링 경로 비활성) ─────────────────────────
    AntiDebugManager::pollHardwareOrFault();

    // ── Layer 7 ────────────────────────────────────────────────────────
    SecureLogger::logSecurityEvent(nullptr, nullptr);

    {
        HTS_Device_Profile profile;
        strike_check("device_profile_null_console",
                     profile.Initialize(nullptr) == IPC_Error::NOT_INITIALIZED);
    }

    volatile const auto phy_cfg = HTS_Phy_Config_Factory::make(HTS_Phy_Tier::TIER_32_IQ);
    strike_check("phycfg_chip", phy_cfg.chip_count == 32u);

    HTS_Sys_Config_Factory::Override_RAM_Ratio(255u);
    volatile const auto sys_cfg =
        HTS_Sys_Config_Factory::Get_Tier_Profile(HTS_Sys_Tier::HYPER_SERVER);
    strike_check("syscfg_nodes", sys_cfg.node_count >= 256u);

    return (g_failures == 0) ? 0 : 1;
}
