// =========================================================================
// HTS_Anchor_Vault.cpp
// 5% 위상 닻(Anchor) 보안 금고 구현부
// Target: Cortex-A55 (CORE-X Pro 메인CPU) / Server
//
#include "HTS_Anchor_Vault.hpp"

// ARM(STM32) 빌드 차단 — A55/서버 전용 모듈
#if (defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
     defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)) && \
    !defined(__aarch64__)
#error "[HTS_FATAL] HTS_Anchor_Vault는 A55/서버 전용. STM32 빌드에서 제외하십시오."
#endif

#include <atomic>
#include <mutex>   // [BUG-07] lock_guard 멀티스레드 직렬화
#include <cstring>

#include "HTS_HMAC_Bridge.hpp"
#include "HTS_Session_Gateway.hpp"
#include "HTS_Secure_Memory.h"

namespace ProtectedEngine {

    // =====================================================================
    //  보안 메모리 소거 (인라인, DCE 차단)
    // =====================================================================
    static void Vault_Secure_Wipe(void* ptr, size_t size) noexcept {
        if (ptr == nullptr || size == 0u) { return; }
        volatile unsigned char* p =
            static_cast<volatile unsigned char*>(ptr);
        for (size_t i = 0u; i < size; ++i) { p[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        // [PEND FIX] 프로젝트 보안 소거 표준 통일: memory clobber
        __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }



    // =====================================================================
    //  [1] 닻 추출 및 내부 격리
    //
    //  ratio_percent = 5 → anchor_step = 20 → 매 20번째 원소 = 5%
    //  ratio_percent = 100 → anchor_step = 1 → 전체 텐서 복사 (의도적)
    // =====================================================================
    void Anchor_Vault::Sequestrate_Anchors(
        uint64_t block_id,
        const std::vector<uint8_t>& tensor,
        uint8_t ratio_percent) noexcept {

        std::lock_guard<std::mutex> lock(mtx_);  // [BUG-07]
        if (ratio_percent == 0) return;
        if (ratio_percent > 100u) ratio_percent = 100u;

        //  기존: anchor_step = 100/ratio → 80% 요청 시 step=1 → 100% 추출(20% 낭비)
        //  수정: 오차 누적(Bresenham): 임의 퍼센티지에서 소수점 오차 0으로 균등 추출
        //  원리: total개 중 target = total*ratio/100 개를 균등 선택
        //        err += target; if (err >= total) { 선택, err -= total; }
        const size_t total = tensor.size();
        // 산술 가드: size_t 곱셈 오버플로우 시 fail-closed
        if (total > (static_cast<size_t>(-1) / static_cast<size_t>(ratio_percent))) {
            return;
        }
        const size_t target = (total * static_cast<size_t>(ratio_percent)) / 100u;
        if (target == 0u) return;

        std::vector<uint8_t> anchors;
        anchors.reserve(target + 1u);

        size_t err = 0u;
        for (size_t i = 0u; i < total; ++i) {
            err += target;
            if (err >= total) {
                err -= total;
                anchors.push_back(tensor[i]);
            }
        }

        // std::vector 대입은 기존 버퍼를 소거 없이 해제 → 메모리 잔존
        auto it = secret_enclave.find(block_id);
        if (it != secret_enclave.end() && !it->second.empty()) {
            Vault_Secure_Wipe(it->second.data(),
                it->second.size() * sizeof(uint8_t));
        }

        secret_enclave[block_id] = std::move(anchors);
    }

    // =====================================================================
    //  [2] 금고에서 닻 복원
    // =====================================================================
    void Anchor_Vault::Replant_Anchors(
        uint64_t block_id,
        std::vector<uint8_t>& damaged_tensor,
        uint8_t ratio_percent) noexcept {

        std::lock_guard<std::mutex> lock(mtx_);  // [BUG-07]
        if (ratio_percent == 0) return;
        if (ratio_percent > 100u) ratio_percent = 100u;

        auto it = secret_enclave.find(block_id);
        if (it == secret_enclave.end()) return;
        const auto& anchors = it->second;

        //  동일 ratio_percent + 동일 tensor.size() → 동일 인덱스 선택 보장
        const size_t total = damaged_tensor.size();
        // 산술 가드: size_t 곱셈 오버플로우 시 fail-closed
        if (total > (static_cast<size_t>(-1) / static_cast<size_t>(ratio_percent))) {
            return;
        }
        const size_t target = (total * static_cast<size_t>(ratio_percent)) / 100u;
        if (target == 0u) return;

        size_t err = 0u;
        size_t anchor_idx = 0u;
        for (size_t i = 0u; i < total && anchor_idx < anchors.size(); ++i) {
            err += target;
            if (err >= total) {
                err -= total;
                damaged_tensor[i] = anchors[anchor_idx++];
            }
        }
    }

    // =====================================================================
    //  [3] 외부 반출
    // =====================================================================
    std::vector<uint8_t> Anchor_Vault::Export_Anchor(uint64_t block_id) noexcept {
        std::lock_guard<std::mutex> lock(mtx_);  // [BUG-07]
        auto it = secret_enclave.find(block_id);
        if (it == secret_enclave.end()) return {};
        if (it->second.empty()) return {};

        const std::vector<uint8_t>& payload = it->second;

        // [HTS-12] export: payload||HMAC(tag) appended (fail-closed if session/key unavailable)
        uint8_t masterSeed[MAX_SEED_SIZE] = {};
        const size_t seed_len = Session_Gateway::Get_Master_Seed_Raw(
            masterSeed, MAX_SEED_SIZE);
        if (seed_len < 32u) {
            SecureMemory::secureWipe(masterSeed, sizeof(masterSeed));
            return {};
        }

        uint8_t block_id_be[8] = {};
        for (size_t i = 0u; i < 8u; ++i) {
            block_id_be[7u - i] = static_cast<uint8_t>(
                static_cast<uint64_t>(block_id >> (i * 8u)) & 0xFFu);
        }

        HMAC_Context ctx;
        uint32_t r = HMAC_Bridge::Init(ctx, masterSeed, 32u);
        if (r != HMAC_Bridge::SECURE_TRUE) {
            SecureMemory::secureWipe(masterSeed, sizeof(masterSeed));
            return {};
        }
        r = HMAC_Bridge::Update(ctx, block_id_be, sizeof(block_id_be));
        if (r != HMAC_Bridge::SECURE_TRUE) {
            SecureMemory::secureWipe(masterSeed, sizeof(masterSeed));
            return {};
        }
        r = HMAC_Bridge::Update(ctx, payload.data(), payload.size());
        if (r != HMAC_Bridge::SECURE_TRUE) {
            SecureMemory::secureWipe(masterSeed, sizeof(masterSeed));
            return {};
        }

        uint8_t mac_tag[ANCHOR_HMAC_TAG_SIZE_BYTES] = {};
        r = HMAC_Bridge::Final(ctx, mac_tag);
        if (r != HMAC_Bridge::SECURE_TRUE) {
            SecureMemory::secureWipe(masterSeed, sizeof(masterSeed));
            SecureMemory::secureWipe(mac_tag, sizeof(mac_tag));
            return {};
        }

        SecureMemory::secureWipe(masterSeed, sizeof(masterSeed));

        std::vector<uint8_t> out;
        out.resize(payload.size() + ANCHOR_HMAC_TAG_SIZE_BYTES);
        if (!payload.empty()) {
            std::memcpy(out.data(), payload.data(), payload.size());
        }
        std::memcpy(
            out.data() + payload.size(),
            mac_tag,
            ANCHOR_HMAC_TAG_SIZE_BYTES);

        SecureMemory::secureWipe(mac_tag, sizeof(mac_tag));

        return out;
    }

    // =====================================================================
    //  [4] 외부 반입
    // =====================================================================
    void Anchor_Vault::Import_Anchor(
        uint64_t block_id,
        const std::vector<uint8_t>& external_anchor) noexcept {

        std::lock_guard<std::mutex> lock(mtx_);  // [BUG-07]
        if (external_anchor.empty()) return;
        if (external_anchor.size() <= ANCHOR_HMAC_TAG_SIZE_BYTES) return;

        const size_t payload_len =
            external_anchor.size() - ANCHOR_HMAC_TAG_SIZE_BYTES;
        if (payload_len == 0u) return;

        const uint8_t* const payload_ptr = external_anchor.data();
        const uint8_t* const recv_tag_ptr = payload_ptr + payload_len;

        // [HTS-12] import: verify (block_id||payload) HMAC first
        uint8_t masterSeed[MAX_SEED_SIZE] = {};
        const size_t seed_len = Session_Gateway::Get_Master_Seed_Raw(
            masterSeed, MAX_SEED_SIZE);
        if (seed_len < 32u) {
            SecureMemory::secureWipe(masterSeed, sizeof(masterSeed));
            return;
        }

        uint8_t block_id_be[8] = {};
        for (size_t i = 0u; i < 8u; ++i) {
            block_id_be[7u - i] = static_cast<uint8_t>(
                static_cast<uint64_t>(block_id >> (i * 8u)) & 0xFFu);
        }

        HMAC_Context ctx;
        uint32_t r = HMAC_Bridge::Init(ctx, masterSeed, 32u);
        if (r != HMAC_Bridge::SECURE_TRUE) {
            SecureMemory::secureWipe(masterSeed, sizeof(masterSeed));
            return;
        }
        r = HMAC_Bridge::Update(ctx, block_id_be, sizeof(block_id_be));
        if (r != HMAC_Bridge::SECURE_TRUE) {
            SecureMemory::secureWipe(masterSeed, sizeof(masterSeed));
            return;
        }
        r = HMAC_Bridge::Update(ctx, payload_ptr, payload_len);
        if (r != HMAC_Bridge::SECURE_TRUE) {
            SecureMemory::secureWipe(masterSeed, sizeof(masterSeed));
            return;
        }
        r = HMAC_Bridge::Verify_Final(ctx, recv_tag_ptr);
        SecureMemory::secureWipe(masterSeed, sizeof(masterSeed));
        if (r != HMAC_Bridge::SECURE_TRUE) {
            // fail-closed: do not overwrite existing payload
            return;
        }

        auto it = secret_enclave.find(block_id);
        if (it != secret_enclave.end() && !it->second.empty()) {
            Vault_Secure_Wipe(it->second.data(),
                it->second.size() * sizeof(uint8_t));
        }

        secret_enclave[block_id] = std::vector<uint8_t>(
            payload_ptr,
            payload_ptr + payload_len);
    }

    // =====================================================================
    //  [6] 처리 완료 앵커 보안 소거 + 맵 삭제 (OOM 방지)
    //
    //   기존: Sequestrate + Import만 존재, 개별 삭제 로직 없음
    //   → 패킷 처리 후 앵커가 영구 잔존 → RAM 무한 증식 → OOM Killer
    //   수정: ACK 수신 후 해당 block_id 앵커를 보안 소거 + erase
    //   호출 시점: V400_Dispatcher에서 블록 전송 완료(ACK) 후 즉시
    // =====================================================================
    void Anchor_Vault::Discard_Anchor(uint64_t block_id) noexcept {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = secret_enclave.find(block_id);
        if (it == secret_enclave.end()) return;

        // 보안 소거: 힙 반환 전 앵커 데이터 volatile 덮어쓰기
        if (!it->second.empty()) {
            Vault_Secure_Wipe(it->second.data(),
                it->second.size() * sizeof(uint8_t));
        }
        // 맵에서 제거: Red-Black Tree 노드 해제
        secret_enclave.erase(it);
    }

    // =====================================================================
    //  [7] 금고 전체 보안 소거 후 해제
    //
    //  [양산 수정] 보안 소거 추가
    //  기존: secret_enclave.clear()
    //    → std::map 노드 해제 → 힙 메모리 반환
    //    → 반환된 메모리에 앵커 데이터가 그대로 잔존
    //    → 콜드 부트 공격: SRAM 전원 차단 후 즉시 덤프
    //      → 해제된 힙 영역에서 앵커 패턴 복원 가능
    //    → 힙 스캔 공격: 디버거로 free list 탐색
    //      → 해제된 블록 내용에서 앵커 데이터 추출
    //
    //  수정: clear() 전에 모든 벡터를 volatile 소거
    //    → 힙 메모리가 반환되기 전에 0으로 덮어쓰기
    //    → atomic_thread_fence로 재배치 금지
    //    → 콜드 부트/힙 스캔 모두 방어
    // =====================================================================
    void Anchor_Vault::Clear_Vault() noexcept {
        std::lock_guard<std::mutex> lock(mtx_);  // [BUG-07]
        for (auto& pair : secret_enclave) {
            if (!pair.second.empty()) {
                Vault_Secure_Wipe(pair.second.data(),
                    pair.second.size() * sizeof(uint8_t));
            }
        }
        secret_enclave.clear();
    }

} // namespace ProtectedEngine
