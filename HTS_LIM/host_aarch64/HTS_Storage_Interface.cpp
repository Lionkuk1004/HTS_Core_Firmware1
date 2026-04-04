// =========================================================================
// HTS_Storage_Interface.cpp
// 스토리지 보안 레이어 구현부
// Target: 통합콘솔 (A55 Linux) / PC (STM32 베어메탈 제외)
//
// [보안] 청크 시드: FNV-1a 64 (session_id·offset 바이트 혼합) / rotator 명시적 secureWipe
// [성능] 8바이트 정렬 시 uint64_t* may_alias 단일 XOR / std::min·|| 제거
// =========================================================================
#include "HTS_Storage_Interface.h"
#include "HTS_Dynamic_Key_Rotator.hpp"
#include "HTS_Secure_Memory.h"
#include <cstdint>
namespace {
    /// file_session_id·chunk_offset를 16바이트로 펼쳐 FNV-1a 64 혼합 (단순 XOR 폐기)
    uint64_t fnv1a64_mix_session_offset(uint64_t session_id, uint64_t chunk_offset) noexcept
    {
        constexpr uint64_t k_fnv_offset = 14695981039346656037ULL;
        constexpr uint64_t k_fnv_prime = 1099511628211ULL;
        uint64_t h = k_fnv_offset;
        for (unsigned k = 0u; k < 8u; ++k) {
            h ^= (session_id >> (k * 8u)) & 0xFFULL;
            h *= k_fnv_prime;
        }
        for (unsigned k = 0u; k < 8u; ++k) {
            h ^= (chunk_offset >> (k * 8u)) & 0xFFULL;
            h *= k_fnv_prime;
        }
        return h;
    }
#if defined(__GNUC__) || defined(__clang__)
    typedef uint64_t __attribute__((may_alias)) u64_may_alias;
#else
    typedef uint64_t u64_may_alias;
#endif
} // namespace
namespace ProtectedEngine {
    void Storage_Interface::Initialize_Storage(const std::vector<uint8_t>& pqc_seed) noexcept {
        adapter.Initialize_Device(DeviceType::SERVER_STORAGE);
        key_bridge.Inject_Quantum_Entropy(pqc_seed.data(), pqc_seed.size());
        key_bridge.Synchronize_CTR_State(file_session_id);
    }
    bool Storage_Interface::Protect_File(std::vector<uint32_t>& file_buffer) noexcept {
        const uint32_t bad =
            static_cast<uint32_t>(file_buffer.empty())
            | static_cast<uint32_t>(file_buffer.data() == nullptr);
        if (bad != 0u) {
            return false;
        }
        uint32_t* const p = file_buffer.data();
        const uint32_t tx_mask =
            adapter.Secure_Data_Stream(p, file_buffer.size(), file_session_id);
        return tx_mask != HTS_Adapter::STREAM_MASK_FAIL;
    }
    bool Storage_Interface::Self_Heal_File(std::vector<uint32_t>& damaged_buffer) noexcept {
        const uint32_t bad =
            static_cast<uint32_t>(damaged_buffer.empty())
            | static_cast<uint32_t>(damaged_buffer.data() == nullptr);
        if (bad != 0u) {
            return false;
        }
        uint32_t* const p = damaged_buffer.data();
        const uint32_t rx_mask =
            adapter.Recover_Data_Stream(p, damaged_buffer.size(), file_session_id);
        return rx_mask != HTS_Adapter::STREAM_MASK_FAIL;
    }
    static_assert(sizeof(Dynamic_Key_Rotator) <= 256u,
        "Dynamic_Key_Rotator exceeds 256B stack budget — "
        "Protect_File_Partial 스택 안전 위반");
    void Storage_Interface::Protect_File_Partial(
        uint32_t* buffer,
        size_t buffer_u32_length,
        size_t elements,
        uint64_t chunk_offset) noexcept
    {
        const uint32_t bad =
            static_cast<uint32_t>(buffer == nullptr)
            | static_cast<uint32_t>(buffer_u32_length == 0u)
            | static_cast<uint32_t>(elements == 0u);
        if (bad != 0u) {
            return;
        }
        const size_t safe_elements =
            elements ^ ((buffer_u32_length ^ elements)
                & static_cast<size_t>(0u
                    - static_cast<size_t>(buffer_u32_length < elements)));
        const uint64_t chunk_seed =
            fnv1a64_mix_session_offset(file_session_id, chunk_offset);
        Dynamic_Key_Rotator rotator(chunk_seed, 1048576u);
        const uintptr_t buf_align = reinterpret_cast<uintptr_t>(buffer);
        const uint32_t use_u64 =
            static_cast<uint32_t>((buf_align & 7u) == 0u)
            & static_cast<uint32_t>(safe_elements >= 2u);
        size_t i = 0;
        if (use_u64 != 0u) {
            u64_may_alias* const w = reinterpret_cast<u64_may_alias*>(buffer);
            const size_t n_pair = safe_elements >> 1u;
            for (size_t k = 0; k < n_pair; ++k) {
                const uint64_t key64 = rotator.Get_Current_Key_And_Rotate();
                w[k] ^= key64;
            }
            i = n_pair << 1u;
        }
        for (; (i + 1u) < safe_elements; i += 2u) {
            const uint64_t key64 = rotator.Get_Current_Key_And_Rotate();
            buffer[i] ^= static_cast<uint32_t>(key64 & 0xFFFFFFFFu);
            buffer[i + 1u] ^= static_cast<uint32_t>(key64 >> 32u);
        }
        if (i < safe_elements) {
            const uint64_t key64 = rotator.Get_Current_Key_And_Rotate();
            buffer[i] ^= static_cast<uint32_t>(key64 & 0xFFFFFFFFu);
        }
        SecureMemory::secureWipe(static_cast<void*>(&rotator), sizeof(rotator));
    }
} // namespace ProtectedEngine
