// =========================================================================
// HTS_Storage_Interface.cpp
// 스토리지 보안 레이어 구현부
// Target: 통합콘솔 (A55 Linux) / PC (STM32 베어메탈 제외)
//
#include "HTS_Storage_Interface.h"
#include "HTS_Dynamic_Key_Rotator.hpp"
#include <algorithm>

namespace ProtectedEngine {

    void Storage_Interface::Initialize_Storage(const std::vector<uint8_t>& pqc_seed) noexcept {
        adapter.Initialize_Device(DeviceType::SERVER_STORAGE);
        key_bridge.Inject_Quantum_Entropy(pqc_seed);
        key_bridge.Synchronize_CTR_State(file_session_id);
    }

    bool Storage_Interface::Protect_File(std::vector<uint32_t>& file_buffer) noexcept {
        if (file_buffer.empty()) return false;
        uint32_t* const p = file_buffer.data();
        if (p == nullptr) return false;
        return adapter.Secure_Data_Stream(p, file_buffer.size(), file_session_id);
    }

    bool Storage_Interface::Self_Heal_File(std::vector<uint32_t>& damaged_buffer) noexcept {
        if (damaged_buffer.empty()) return false;
        uint32_t* const p = damaged_buffer.data();
        if (p == nullptr) return false;
        return adapter.Recover_Data_Stream(p, damaged_buffer.size(), file_session_id);
    }

    // Dynamic_Key_Rotator: 4 × uint64_t = 32B (현재)
    // 향후 Pimpl 전환 시 팽창 방지 → 빌드 타임 상한 고정
    static_assert(sizeof(Dynamic_Key_Rotator) <= 256u,
        "Dynamic_Key_Rotator exceeds 256B stack budget — "
        "Protect_File_Partial 스택 안전 위반");

    // =====================================================================
    //
    //  기존: rotator(file_session_id, ...) → 매 호출 동일 시드 → 동일 키스트림!
    //        청크 N개 호출 → 모든 청크에 동일 키스트림 반복 적용
    //        → cipher[0] XOR cipher[1] = plain[0] XOR plain[1] (평문 유출)
    //
    //  수정: file_session_id ^ chunk_offset → 청크마다 고유 시드
    //        chunk_offset은 파일 내 절대 바이트 위치 (호출자 제공)
    //        → 각 청크가 서로 다른 PRNG 궤적을 탐 → 키스트림 재사용 0회
    //
    //
    //  기존: 64비트 키 → 하위 32비트만 사용 → 상위 32비트 폐기
    //        PRNG 1회 호출 비용(~12cyc)의 50%가 낭비
    //
    //  수정: 64비트 키를 상위/하위 분할 → 연속 2개 원소에 적용
    //        루프 2× 언롤 → PRNG 호출 횟수 절반 → 2× 처리량 향상
    // =====================================================================
    void Storage_Interface::Protect_File_Partial(
        std::vector<uint32_t>& data, size_t elements,
        uint64_t chunk_offset) noexcept {

        if (data.empty() || elements == 0) return;
        uint32_t* const base = data.data();
        if (base == nullptr) return;

        const uint64_t chunk_seed = file_session_id ^ chunk_offset;
        Dynamic_Key_Rotator rotator(chunk_seed, 1048576);

        const size_t safe_elements = std::min(data.size(), elements);

        size_t i = 0;
        for (; i + 1u < safe_elements; i += 2u) {
            const uint64_t key64 = rotator.Get_Current_Key_And_Rotate();
            base[i] ^= static_cast<uint32_t>(key64 & 0xFFFFFFFFu);
            base[i + 1u] ^= static_cast<uint32_t>(key64 >> 32u);
        }
        // 홀수 잔여 1개
        if (i < safe_elements) {
            const uint64_t key64 = rotator.Get_Current_Key_And_Rotate();
            base[i] ^= static_cast<uint32_t>(key64 & 0xFFFFFFFFu);
        }
    }

} // namespace ProtectedEngine
