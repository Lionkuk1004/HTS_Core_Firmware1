// HTS 3단계 실전 검증 — Layer 12~17 외곽망 스트라이크 (호스트 + HTS_LIM_V3.lib)
// NULL·극단 길이·와이어 조작·미초기화 게이트웨이 조합 — 크래시 없이 거부 검증

#include "HTS_AMI_Protocol.h"
#include "HTS_API.h"
#include "HTS_BLE_NFC_Gateway.h"
#include "HTS_CoAP_Engine.h"
#include "HTS_IoT_Codec.h"
#include "HTS_IPC_Protocol_Defs.h"
#include "HTS_Modbus_Gateway.h"
#include "HTS_Modbus_Gateway_Defs.h"
#include "HTS_Network_Bridge.h"
#include "HTS_OTA_Manager.h"
#include "HTS_Priority_Scheduler.h"
#include "HTS_Security_Pipeline.h"
#include "HTS_Session_Gateway.hpp"
#include "HTS_Universal_API.h"

#include <atomic>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <limits>

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

    // ── Layer 12: 보안 파이프라인 + 세션 게이트 ─────────────────────────
    {
        Security_Pipeline pipe;
        std::atomic<bool> abort_flag{ false };
        pipe.Secure_Master_Worker(nullptr, 0u, 4u, abort_flag, 0u);

        std::atomic<uint32_t> tag_hi{ 0u };
        std::atomic<uint32_t> tag_lo{ 0u };
        pipe.Secure_Master_Worker_AEAD(nullptr, 0u, 2u, abort_flag,
            tag_hi, tag_lo, 0u);

        strike_check("session_derive_null_out",
            Session_Gateway::Derive_Session_Material(
                "HTS.Session.Anchor.HMAC.v1", nullptr, 16u) == 0u);
        uint8_t dom_out[8] = {};
        strike_check("session_derive_zero_len",
            Session_Gateway::Derive_Session_Material(
                nullptr, dom_out, 0u) == 0u);
        (void)Session_Gateway::Is_Session_Active();
    }

    // ── Layer 14: IPC 프레임 파서 (뺄셈·상한) ───────────────────────────
    {
        uint8_t seq = 0u;
        IPC_Command cmd = IPC_Command::PING;
        uint16_t plen_out = 0u;
        alignas(4) uint8_t pay[IPC_MAX_PAYLOAD] = {};

        strike_check("ipc_parse_null_wire",
            IPC_Parse_Frame(nullptr, 100u, seq, cmd, pay,
                static_cast<uint16_t>(sizeof(pay)), plen_out)
                == IPC_Error::BUFFER_OVERFLOW);

        alignas(4) uint8_t small[8] = { 0u };
        strike_check("ipc_parse_wire_too_short",
            IPC_Parse_Frame(small, 4u, seq, cmd, pay,
                static_cast<uint16_t>(sizeof(pay)), plen_out)
                == IPC_Error::INVALID_LEN);

        // wire_len은 거대하나 버퍼는 8B — 동기화/CRC 단계에서 조기 거부(뺄셈 기대 길이 vs 실제 불일치)
        strike_check("ipc_parse_claim_huge_wire_len_rejected",
            IPC_Parse_Frame(small, 0xFFFFFFFFu, seq, cmd, pay,
                static_cast<uint16_t>(sizeof(pay)), plen_out)
                != IPC_Error::OK);

        // 위조 헤더: declared plen 초과 (256 초과)
        alignas(4) uint8_t forged[16] = {};
        IPC_Serialize_U16(&forged[0], IPC_SYNC_WORD);
        forged[2] = 1u;
        forged[3] = static_cast<uint8_t>(IPC_Command::DATA_TX);
        IPC_Serialize_U16(&forged[4], 300u);
        strike_check("ipc_parse_plen_over_max",
            IPC_Parse_Frame(forged, sizeof(forged), seq, cmd, pay,
                static_cast<uint16_t>(sizeof(pay)), plen_out)
                == IPC_Error::INVALID_LEN);

        const uint8_t payload4[4] = { 0x11u, 0x22u, 0x33u, 0x44u };
        alignas(4) uint8_t wire[IPC_MAX_FRAME_SIZE] = {};
        uint32_t flen = 0u;
        strike_check("ipc_serialize_ok",
            IPC_Serialize_Frame(wire, 7u, IPC_Command::STATUS_REQ,
                payload4, 4u, flen) == IPC_Error::OK);

        strike_check("ipc_parse_out_cap_too_small",
            IPC_Parse_Frame(wire, flen, seq, cmd, pay, 2u, plen_out)
                == IPC_Error::BUFFER_OVERFLOW);

        strike_check("ipc_parse_null_out_when_plen_positive",
            IPC_Parse_Frame(wire, flen, seq, cmd, nullptr, 0u, plen_out)
                == IPC_Error::BUFFER_OVERFLOW);
    }

    // ── Layer 14: 네트워크 브리지 분할 수신 ─────────────────────────────
    {
        HTS_Network_Bridge bridge;
        alignas(4) uint8_t frag[32] = { 0u };
        strike_check("bridge_feed_null",
            bridge.Feed_Fragment(nullptr, 16u, 0u) != BRIDGE_SECURE_TRUE);
        strike_check("bridge_feed_not_init",
            bridge.Feed_Fragment(frag, 16u, 0u) != BRIDGE_SECURE_TRUE);
    }

    // ── Layer 15: OTA / Modbus / BLE/NFC / AMI ──────────────────────────
    {
        HTS_OTA_Manager ota;
        alignas(4) uint8_t ota_pay[64] = {};
        ota_pay[0] = static_cast<uint8_t>(OTA_Command::CHUNK_DATA);
        ota.Process_OTA_Command(nullptr, 10u);
        ota.Process_OTA_Command(ota_pay, 0u);
        ota.Process_OTA_Command(ota_pay, 0xFFFFu);

        HTS_Modbus_Gateway modbus;
        alignas(4) uint8_t mb[32] = {};
        modbus.Process_GW_Command(nullptr, 100u);
        modbus.Process_GW_Command(mb, static_cast<uint16_t>(MODBUS_GW_HEADER_SIZE - 1u));
        modbus.Process_GW_Command(mb, 0xFFFFu);

        HTS_BLE_NFC_Gateway ble;
        LocationCode loc{};
        loc.code = 1u;
        ble.Relay_From_BCDMA(nullptr, 8u);
        ble.Relay_From_BCDMA(mb, 0u);
        strike_check("ble_send_text_null_with_len",
            ble.Send_Text(nullptr, 4u, 0u) == IPC_Error::BUFFER_OVERFLOW);
        strike_check("ble_send_text_not_init",
            ble.Send_Text(mb, 1u, 0u) == IPC_Error::NOT_INITIALIZED);

        HTS_AMI_Protocol ami;
        ami.Process_Request(nullptr, 128u);
        ami.Process_Request(mb, AMI_APDU_HEADER_SIZE + AMI_APDU_CRC_SIZE - 1u);
    }

    // ── Layer 14: CoAP + 우선순위 스케줄러 ──────────────────────────────
    {
        HTS_CoAP_Engine coap(0x1001u);
        HTS_Priority_Scheduler sched;
        alignas(4) uint8_t pkt[HTS_CoAP_Engine::MAX_PKT_SIZE + 8u] = {};

        coap.On_Message_Received(nullptr, 20u, 1u, 0u, sched);
        coap.On_Message_Received(pkt, std::numeric_limits<size_t>::max(),
            1u, 0u, sched);
        coap.On_Message_Received(pkt, 7u, 1u, 0u, sched);

        strike_check("prio_enqueue_null",
            sched.Enqueue(PacketPriority::DATA, nullptr, 1u, 0u)
                == EnqueueResult::NULL_INPUT);
        strike_check("prio_enqueue_oversize",
            sched.Enqueue(PacketPriority::DATA, pkt, 999u, 0u)
                == EnqueueResult::OVER_SIZE);
    }

    // ── Layer 16: IoT 코덱 파서 ─────────────────────────────────────────
    {
        HTS_IoT_Codec iot;
        IoT_Frame_Header hdr{};
        IoT_TLV_Item items[4] = {};
        uint8_t ic = 0u;
        strike_check("iot_parse_null",
            iot.Parse(nullptr, 100u, hdr, items, 4u, ic) == HTS_IoT_Codec::SECURE_FALSE);
        alignas(4) uint8_t junk[8] = { 0xFFu };
        strike_check("iot_parse_short",
            iot.Parse(junk, 4u, hdr, items, 4u, ic) == HTS_IoT_Codec::SECURE_FALSE);
    }

    // ── Layer 12 / 17: Universal API + HTS_API ───────────────────────────
    {
        const uint32_t fail = Universal_API::Secure_Gate_Open(0u);
        strike_check("uapi_gate_wrong_session",
            (fail & Universal_API::SECURE_GATE_MASK_OK) == 0u);
        Universal_API::Absolute_Trace_Erasure(nullptr, 16u);

        const HTS_API::HTS_Status null_rx =
            HTS_API::Fetch_And_Heal_Rx_Payload(nullptr, 4u);
        strike_check(
            "hts_api_fetch_null_or_uninit",
            null_rx == HTS_API::HTS_Status::ERR_NULL_POINTER
                || null_rx == HTS_API::HTS_Status::ERR_NOT_INITIALIZED);
        alignas(4) uint32_t outw[4] = {};
        // 미초기화 시 상한 검사 전에 ERR_NOT_INITIALIZED (호스트 스트라이크는 HW 부트 없음)
        const HTS_API::HTS_Status big_rx =
            HTS_API::Fetch_And_Heal_Rx_Payload(outw, SIZE_MAX);
        strike_check(
            "hts_api_fetch_size_max_or_uninit",
            big_rx == HTS_API::HTS_Status::ERR_BUFFER_UNDERFLOW
                || big_rx == HTS_API::HTS_Status::ERR_NOT_INITIALIZED);
    }

    return (g_failures == 0) ? 0 : 1;
}
