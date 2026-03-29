// =========================================================================
// HTS_Anchor_Vault.cpp
// 5% 위상 닻(Anchor) 보안 금고 구현부
// Target: Cortex-A55 (CORE-X Pro 메인CPU) / Server
//
// [양산 수정 — 8건]
//  BUG-01 Clear_Vault:
//  BUG-02 [CRIT] pragma O0 삭제 → asm clobber + volatile
//  BUG-04 [MED]  ratio_percent > 100 클램핑
//  BUG-07 [CRIT] 전 메서드 std::mutex 동기화 (A55 멀티스레드 SIGSEGV 차단)
//         · std::map Red-Black Tree 동시 삽입/삭제 시 포인터 tearing → SIGSEGV
//         · 해결: lock_guard<mutex>로 전 메서드 직렬화
//         · STM32: 해당 없음 (#error 가드)
//  BUG-08 [MED]  Vault_Secure_Wipe while 루프 → for 루프 (프로젝트 표준 통일)
//         · 기존: while (size--) *p++ = 0; (BB1/TensorCodec/ECCM과 불일치)
//         · 수정: for (size_t i = 0u; i < size; ++i) { p[i] = 0u; }
//         · 기능 동등, 코드 리뷰 시 "다른 구현?" 의문 제거
//
//  1. Clear_Vault: secret_enclave.clear() 전에 모든 앵커 데이터 보안 소거
//     기존: clear()만 호출 → 힙 메모리 해제만 수행 → 데이터 RAM에 잔존
//     수정: 각 벡터를 volatile 소거 후 clear() → 콜드 부트 공격 방어
// =========================================================================
#include "HTS_Anchor_Vault.hpp"

// ARM(STM32) 빌드 차단 — A55/서버 전용 모듈
// [BUG-21] STM32 (Cortex-M) 빌드 차단 — 프로젝트 표준 4종 매크로
#if (defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
     defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)) && \
    !defined(__aarch64__)
#error "[HTS_FATAL] HTS_Anchor_Vault는 A55/서버 전용. STM32 빌드에서 제외하십시오."
#endif

#include <atomic>
#include <mutex>   // [BUG-07] lock_guard 멀티스레드 직렬화

namespace ProtectedEngine {

    // =====================================================================
    //  보안 메모리 소거 (인라인, DCE 차단)
    //  [BUG-02] pragma O0 삭제 → volatile + asm clobber로 DCE 차단
    //  [BUG-08] while 루프 → for 루프 (프로젝트 표준 통일)
    // =====================================================================
    static void Vault_Secure_Wipe(void* ptr, size_t size) noexcept {
        if (ptr == nullptr || size == 0u) { return; }
        volatile unsigned char* p =
            static_cast<volatile unsigned char*>(ptr);
        for (size_t i = 0u; i < size; ++i) { p[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
        // [BUG-05] seq_cst → release (소거 배리어 정책 통일)
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
        // [BUG-04] 범위 클램핑 (최대 100%)
        if (ratio_percent > 100u) ratio_percent = 100u;

        size_t anchor_step = static_cast<size_t>(100u / ratio_percent);
        if (anchor_step == 0) anchor_step = 1;

        // [BUG-05] try-catch 삭제 (-fno-exceptions)
        std::vector<uint8_t> anchors;
        anchors.reserve((tensor.size() / anchor_step) + 1u);

        for (size_t i = 0; i < tensor.size(); i += anchor_step) {
            anchors.push_back(tensor[i]);
        }

        // [BUG-06] 기존 앵커 보안 소거 후 덮어쓰기
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

        // [BUG-05] try-catch 삭제
        auto it = secret_enclave.find(block_id);
        if (it == secret_enclave.end()) return;
        const auto& anchors = it->second;

        size_t anchor_step = static_cast<size_t>(100u / ratio_percent);
        if (anchor_step == 0) anchor_step = 1;

        for (size_t i = 0, anchor_idx = 0;
            i < damaged_tensor.size() && anchor_idx < anchors.size();
            i += anchor_step) {
            damaged_tensor[i] = anchors[anchor_idx++];
        }
    }

    // =====================================================================
    //  [3] 외부 반출
    // =====================================================================
    std::vector<uint8_t> Anchor_Vault::Export_Anchor(uint64_t block_id) noexcept {
        std::lock_guard<std::mutex> lock(mtx_);  // [BUG-07]
        // [BUG-05] try-catch 삭제
        auto it = secret_enclave.find(block_id);
        if (it != secret_enclave.end()) {
            return it->second;
        }
        return {};
    }

    // =====================================================================
    //  [4] 외부 반입
    // =====================================================================
    void Anchor_Vault::Import_Anchor(
        uint64_t block_id,
        const std::vector<uint8_t>& external_anchor) noexcept {

        std::lock_guard<std::mutex> lock(mtx_);  // [BUG-07]
        // [BUG-06] 기존 앵커 보안 소거 후 덮어쓰기
        auto it = secret_enclave.find(block_id);
        if (it != secret_enclave.end() && !it->second.empty()) {
            Vault_Secure_Wipe(it->second.data(),
                it->second.size() * sizeof(uint8_t));
        }

        secret_enclave[block_id] = external_anchor;
    }

    // =====================================================================
    //  [5] 금고 전체 보안 소거 후 해제
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