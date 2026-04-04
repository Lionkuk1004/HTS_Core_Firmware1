// Verify_BlackSwan_Annihilation — 9단계: 비잔틴·32비트 틱 롤오버·무음 1바이트 드롭(프레임 시프트) 동시 융합
// 단일 메인 루프에서 3중 재앙을 매 이터레이션 겹쳐 호출 (추가 스레드 없음).
// 타겟: HTS_Mesh_Router, IPC_Parse_Frame(Def), uint32_t 모듈러 시간차(세션/OTA 타임아웃 모델)

#include "HTS_IPC_Protocol_Defs.h"
#include "HTS_Mesh_Router.h"
#include "HTS_Priority_Scheduler.h"

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

namespace PE = ProtectedEngine;

using PE::HTS_Mesh_Router;
using PE::HTS_Priority_Scheduler;
using PE::IPC_Command;
using PE::IPC_Error;
using PE::RouteEntry;

constexpr uint16_t kMyId = 1u;
/// 신뢰 이웃(정상 벡터) — 배신자 군단과 분리
constexpr uint16_t kGoodNeighbor = 50u;
constexpr uint16_t kGoodDest = 900u;
/// 비잔틴 10인: 600..609
constexpr uint16_t kTraitorBase = 600u;
constexpr uint32_t kTraitorCount = 10u;
/// 반복 횟수(논스톱 스트레스)
constexpr uint32_t kFusionIterations = 12000u;

[[nodiscard]] uint32_t xorshift32(uint32_t& s) noexcept
{
    s ^= s << 13u;
    s ^= s >> 17u;
    s ^= s << 5u;
    return s;
}

/// 32비트 SysTick 래핑 가정: (now - start) 만으로 경과 판정 (부호 없음)
[[nodiscard]] bool u32_elapsed_at_least(
    uint32_t now, uint32_t start, uint32_t need_ms) noexcept
{
    return (now - start) >= need_ms;
}

void fill_route(
    RouteEntry& o, uint16_t dest, uint8_t hops, uint8_t metric, uint8_t lqi) noexcept
{
    std::memset(&o, 0, sizeof(o));
    o.dest_id = dest;
    o.next_hop = 0u;
    o.hop_count = hops;
    o.metric = metric;
    o.lqi = lqi;
    o.valid = 1u;
}

/// wire_buf[0..full_len) 에서 drop_idx 바이트 1개 제거 → out_len
void copy_without_byte(const uint8_t* wire, uint32_t full_len, uint32_t drop_idx,
    uint8_t* out, uint32_t& out_len) noexcept
{
    if (full_len == 0u || wire == nullptr || out == nullptr) {
        out_len = 0u;
        return;
    }
    if (drop_idx >= full_len) {
        std::memcpy(out, wire, static_cast<size_t>(full_len));
        out_len = full_len;
        return;
    }
    if (drop_idx > 0u) {
        std::memcpy(out, wire, static_cast<size_t>(drop_idx));
    }
    const uint32_t tail = full_len - drop_idx - 1u;
    if (tail > 0u) {
        std::memcpy(out + drop_idx, wire + drop_idx + 1u, static_cast<size_t>(tail));
    }
    out_len = full_len - 1u;
}

} // namespace

int main()
{
    HTS_Mesh_Router router(kMyId);
    HTS_Priority_Scheduler sched;

    // 정상 경로 1개 확보(배신자만으로는 목적지 도달 불가능한 상태 방지용 기준선)
    RouteEntry good{};
    fill_route(good, kGoodDest, 1u, 4u, 95u);
    router.On_Route_Update(kGoodNeighbor, &good, 1u, 96u);

    uint32_t traitor_bad_inject[kTraitorCount] = {};
    bool traitor_quarantined[kTraitorCount] = {};
    uint32_t rng = 0xDEADBEEFu;

    uint64_t ipc_crc_fail = 0u;
    uint64_t ipc_len_fail = 0u;
    uint64_t ipc_ok_wrong = 0u;

    std::printf(
        "BLACK_SWAN: fusion loop %" PRIu32 " iters (Byzantine+TickRollover+SilentDrop)\n",
        kFusionIterations);

    for (uint32_t iter = 0u; iter < kFusionIterations; ++iter) {
        // ─── 재앙 2: 49일 부근 롤오버를 매 사이클 틱에 겹침 ───
        const uint32_t tick_hi = 0xFFFFFFFFu - (2000u + (iter & 0x3FFu));
        const uint32_t tick_lo = 10u + (iter & 0xFFu);
        router.Tick(tick_hi, sched);
        router.Tick(tick_lo, sched);

        const uint32_t hs_start = tick_hi - 500u;
        if (!u32_elapsed_at_least(tick_lo, hs_start, 200u)) {
            std::printf("TIME_FAIL: wrap elapsed check (handshake model)\n");
            return 3;
        }
        const uint32_t ota_start = 0xFFFFFF00u + (iter & 0x7Fu);
        const uint32_t ota_now = 0x200u + ((iter * 7u) & 0xFFu);
        if (u32_elapsed_at_least(ota_now, ota_start, 0x100000u)) {
            std::printf("TIME_FAIL: false positive long timeout after wrap\n");
            return 4;
        }

        // ─── 재앙 1: 10인 비잔틴 — 초과 홉·루프 유도 광고 + 느린 쓰레기 ───
        RouteEntry adv[4]{};
        for (uint32_t t = 0u; t < kTraitorCount; ++t) {
            const uint16_t nid = static_cast<uint16_t>(kTraitorBase + t);
            // (a) hop_count=255 → uint8+1 래핑 악용 시도 (펌웨어는 32비트로 거절)
            fill_route(adv[0], static_cast<uint16_t>(7000u + t), 255u, 2u, 90u);
            // (b) 그럴듯한 짧은 경로(다목적지 로테이션) — 테이블 상한 내에서만 유효
            const uint16_t decoy_dest =
                static_cast<uint16_t>(2000u + ((iter + t) % 800u));
            fill_route(adv[1], decoy_dest, 1u,
                static_cast<uint8_t>(6u + static_cast<uint8_t>(t & 3u)), 85u);
            // (c) 동일 목적지에 대해 이웃이 더 나쁜 메트릭을 광고(루프성) — 기존 로직이 거절
            fill_route(adv[2], kGoodDest, 2u, 80u, 70u);
            // (d) 자기 모순: 극단 메트릭 INF 광고(독 리버스 흉내) — 유효 필드로 처리 경로 스트레스
            fill_route(adv[3], static_cast<uint16_t>(7100u + t), 1u,
                HTS_Mesh_Router::METRIC_INF, 50u);

            router.On_Route_Update(nid, adv, 4u, 88u);
            traitor_bad_inject[t] += 1u;

            // 정책 계층 격리: 알려진 악성 주입이 임계를 넘으면 링크 단절(Quarantine)
            constexpr uint32_t kQuarantineAfter = 24u;
            if (!traitor_quarantined[t]
                && traitor_bad_inject[t] >= kQuarantineAfter) {
                router.On_Link_Down(nid, tick_lo);
                traitor_quarantined[t] = true;
            }
        }

        const size_t rc = router.Get_Route_Count();
        if (rc > HTS_Mesh_Router::MAX_ROUTES) {
            std::printf("MESH_FAIL: route_count overflow %" PRIu64 "\n",
                static_cast<uint64_t>(rc));
            return 5;
        }

        // ─── 재앙 3: IPC 프레임 중 무작위 위치 1바이트 증발 → 파서 즉시 실패(재동기 전제) ───
        uint8_t wire[PE::IPC_MAX_FRAME_SIZE]{};
        uint8_t payload[16]{};
        for (uint32_t i = 0u; i < sizeof(payload); ++i) {
            payload[i] = static_cast<uint8_t>(
                0xA5u ^ static_cast<uint8_t>(i + iter));
        }
        uint32_t full_len = 0u;
        const PE::IPC_Error ser = PE::IPC_Serialize_Frame(
            wire, static_cast<uint8_t>(iter & 0xFFu), IPC_Command::DATA_TX,
            payload, static_cast<uint16_t>(sizeof(payload)), full_len);
        if (ser != IPC_Error::OK || full_len < PE::IPC_HEADER_SIZE + PE::IPC_CRC_SIZE) {
            std::printf("IPC_FAIL: serialize\n");
            return 6;
        }

        uint8_t corrupted[PE::IPC_MAX_FRAME_SIZE]{};
        uint32_t corrupt_len = 0u;
        const uint32_t drop_pos = (xorshift32(rng) % full_len);
        copy_without_byte(wire, full_len, drop_pos, corrupted, corrupt_len);

        uint8_t out_pl[PE::IPC_MAX_PAYLOAD]{};
        uint8_t seq = 0u;
        IPC_Command cmd = IPC_Command::PING;
        uint16_t plen = 0u;
        const IPC_Error pr = PE::IPC_Parse_Frame(
            corrupted, corrupt_len, seq, cmd, out_pl,
            static_cast<uint16_t>(sizeof(out_pl)), plen);

        if (pr == IPC_Error::OK) {
            ++ipc_ok_wrong;
        }
        else if (pr == IPC_Error::CRC_MISMATCH) {
            ++ipc_crc_fail;
        }
        else if (pr == IPC_Error::INVALID_LEN) {
            ++ipc_len_fail;
        }
        // 그 외 에러 코드도 즉시 반환(무한 대기 없음)
    }

    if (ipc_ok_wrong != 0u) {
        std::printf("IPC_FAIL: dropped-byte frame parsed as OK count=%" PRIu64 "\n",
            static_cast<uint64_t>(ipc_ok_wrong));
        return 7;
    }

    uint32_t qcount = 0u;
    for (uint32_t t = 0u; t < kTraitorCount; ++t) {
        if (traitor_quarantined[t]) {
            ++qcount;
        }
    }
    std::printf(
        "BLACK_SWAN: PASS — routes<=%" PRIu64 ", ipc_crc_fail=%" PRIu64
        ", ipc_len_fail=%" PRIu64 ", traitors_quarantined=%" PRIu32 "/%" PRIu32 "\n",
        static_cast<uint64_t>(HTS_Mesh_Router::MAX_ROUTES),
        static_cast<uint64_t>(ipc_crc_fail),
        static_cast<uint64_t>(ipc_len_fail),
        qcount,
        kTraitorCount);
    return 0;
}
