// HTS 4단계 — End-to-End 통합 시나리오 (호스트 + HTS_LIM_V3.lib)
// 부팅·POST·세션·텐서·IPC 와이어 시뮬레이션을 순차 검증 (Release에서도 assert 활성)

#ifdef NDEBUG
#undef NDEBUG
#endif

#include "HTS_Crypto_KAT.h"
#include "HTS_Holo_Dispatcher.h"
#include "HTS_IPC_Protocol_Defs.h"
#include "HTS_Key_Rotator.h"
#include "HTS_Network_Bridge.h"
#include "HTS_Network_Bridge_Defs.h"
#include "HTS_POST_Manager.h"
#include "HTS_Secure_Boot_Verify.h"
#include "HTS_Secure_Memory.h"
#include "HTS_Session_Gateway.hpp"

#include <cassert>
#include <cstdint>
#include <cstring>

namespace {

enum class E2E_Phase : uint8_t {
    Idle = 0u,
    BootCryptoDone = 1u,
    PostDone = 2u,
    SessionKeyDone = 3u,
    TensorDone = 4u,
    TransportDone = 5u,
};

E2E_Phase g_phase = E2E_Phase::Idle;

} // namespace

int main() {
    using namespace ProtectedEngine;

    alignas(8) uint8_t block_seed[32] = {};

    // ── Step 1: 가상 부팅 + Secure Boot + 암호 KAT (Layer 0~4) ───────────
    {
        assert(g_phase == E2E_Phase::Idle);
        HTS_Secure_Boot_Verify boot;

        alignas(8) uint8_t pc_expected_hash[32] = {};
        for (size_t i = 0u; i < 32u; ++i) {
            pc_expected_hash[i] = 0xAAu;
        }
        (void)boot.Provision_Expected_Hash(pc_expected_hash, 32u);

        const int32_t boot_rc = HTS_Secure_Boot_Check();
        assert(boot_rc == 0);
        assert(HTS_Secure_Boot_Is_Verified() == 1);

        assert(Crypto_KAT::Run_All_Crypto_KAT());
        g_phase = E2E_Phase::BootCryptoDone;
        assert(g_phase == E2E_Phase::BootCryptoDone);

        POST_Manager::executePowerOnSelfTest();

        g_phase = E2E_Phase::PostDone;
        assert(g_phase == E2E_Phase::PostDone);
    }

    // ── Step 2: 세션 마스터 시드 + KDF 체인 + Forward Secrecy 로테이터 (5~7) ─
    {
        assert(g_phase == E2E_Phase::PostDone);
        Session_Gateway::Open_Session();
        assert(Session_Gateway::Is_Session_Active());

        alignas(8) uint8_t session_key[32] = {};
        const size_t sk_len = Session_Gateway::Derive_Session_Material(
            Session_Gateway::DOMAIN_ANCHOR_HMAC,
            session_key,
            sizeof(session_key));
        assert(sk_len == sizeof(session_key));

        DynamicKeyRotator rotator(session_key, sizeof(session_key));
        size_t derived_len = 0u;
        assert(rotator.deriveNextSeed(
            0u, block_seed, sizeof(block_seed), derived_len));
        assert(derived_len == 32u);

        SecureMemory::secureWipe(session_key, sizeof(session_key));

        g_phase = E2E_Phase::SessionKeyDone;
        assert(g_phase == E2E_Phase::SessionKeyDone);
    }

    // ── Step 3: 센서 페이로드 + Holo 텐서 인코딩 (8~11) ─────────────────
    {
        assert(g_phase == E2E_Phase::SessionKeyDone);

        uint32_t hseed[4] = {};
        static_assert(sizeof(hseed) <= 32u, "hseed fits block_seed");
        std::memcpy(hseed, block_seed, sizeof(hseed));

        HTS_Holo_Dispatcher holo;
        assert(holo.Initialize(hseed) == HTS_Holo_Dispatcher::SECURE_TRUE);

        alignas(8) uint8_t sensor_blob[16] = {
            0x01u, 0x02u, 0x03u, 0x04u, 0x55u, 0xAAu, 0x5Au, 0xA5u,
            0x10u, 0x20u, 0x30u, 0x40u, 0x50u, 0x60u, 0x70u, 0x80u
        };
        alignas(8) int16_t oI[4096] = {};
        alignas(8) int16_t oQ[4096] = {};

        holo.Set_Current_Mode(HoloPayload::DATA_HOLO);
        const size_t n_chips = holo.Build_Holo_Packet(
            HoloPayload::DATA_HOLO,
            sensor_blob,
            sizeof(sensor_blob),
            12345,
            oI,
            oQ,
            sizeof(oI) / sizeof(oI[0]));
        assert(n_chips > 0u);

        (void)holo.Shutdown();

        g_phase = E2E_Phase::TensorDone;
        assert(g_phase == E2E_Phase::TensorDone);
    }

    // ── Step 4: IPC 와이어 직렬화/역직렬화 + 네트워크 브리지 링크다운 (12~17) ─
    {
        assert(g_phase == E2E_Phase::TensorDone);

        alignas(8) uint8_t ipc_payload[16] = {
            0xC0u, 0xDEu, 0xFAu, 0x11u, 0u, 0u, 0u, 0u,
            0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u
        };
        alignas(4) uint8_t wire[IPC_MAX_FRAME_SIZE] = {};
        uint32_t frame_len = 0u;
        assert(IPC_Serialize_Frame(
            wire,
            3u,
            IPC_Command::DATA_TX,
            ipc_payload,
            static_cast<uint16_t>(sizeof(ipc_payload)),
            frame_len) == IPC_Error::OK);
        assert(frame_len >= IPC_HEADER_SIZE + IPC_CRC_SIZE);

        uint8_t out_seq = 0u;
        IPC_Command out_cmd = IPC_Command::PING;
        alignas(4) uint8_t round_payload[IPC_MAX_PAYLOAD] = {};
        uint16_t out_plen = 0u;
        assert(IPC_Parse_Frame(
            wire,
            frame_len,
            out_seq,
            out_cmd,
            round_payload,
            static_cast<uint16_t>(sizeof(round_payload)),
            out_plen) == IPC_Error::OK);
        assert(out_seq == 3u);
        assert(out_cmd == IPC_Command::DATA_TX);
        assert(out_plen == static_cast<uint16_t>(sizeof(ipc_payload)));
        assert(std::memcmp(round_payload, ipc_payload, sizeof(ipc_payload)) == 0);

        HTS_Network_Bridge bridge;
        alignas(4) uint8_t frag[BRIDGE_FRAG_HEADER_SIZE + 8] = {};
        frag[0] = 0u;
        frag[1] = 1u;
        frag[2] = 1u;
        frag[3] = 0u;
        const uint32_t feed_ret = bridge.Feed_Fragment(
            frag,
            static_cast<uint16_t>(sizeof(frag)),
            0u);
        assert(feed_ret != BRIDGE_SECURE_TRUE);

        g_phase = E2E_Phase::TransportDone;
        assert(g_phase == E2E_Phase::TransportDone);
    }

    Session_Gateway::Close_Session();
    assert(!Session_Gateway::Is_Session_Active());

    SecureMemory::secureWipe(block_seed, sizeof(block_seed));

    g_phase = E2E_Phase::Idle;
    return 0;
}
