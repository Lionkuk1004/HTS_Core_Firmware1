// =========================================================================
// HTS_Quantum_Key_Bridge.cpp
// PQC 양자 내성 키 브릿지 — 구현 (힙 할당 0)
// Target: STM32F407 (Cortex-M4) / 호스트 공통
// =========================================================================
#include "HTS_Quantum_Key_Bridge.h"
#include "HTS_Secure_Memory.h"

namespace ProtectedEngine {

Quantum_Key_Bridge::~Quantum_Key_Bridge() noexcept
{
    SecureMemory::secureWipe(
        static_cast<void*>(quantum_master_seed),
        sizeof(quantum_master_seed));
    is_pqc_established = false;
    sync_counter = 0u;
}

void Quantum_Key_Bridge::Inject_Quantum_Entropy(
    const uint8_t* entropy_buf,
    std::size_t length) noexcept
{
    if (entropy_buf == nullptr || length == 0u) {
        return;
    }

    // 32바이트 슬롯에 XOR-폴드 (동적 버퍼 없음)
    uint8_t acc[32] = {};
    for (std::size_t i = 0u; i < length; ++i) {
        acc[i % 32u] ^= entropy_buf[i];
    }

    const uint64_t len64 = static_cast<uint64_t>(length);
    acc[24] ^= static_cast<uint8_t>(len64 & 0xFFu);
    acc[25] ^= static_cast<uint8_t>((len64 >> 8u) & 0xFFu);
    acc[26] ^= static_cast<uint8_t>((len64 >> 16u) & 0xFFu);
    acc[27] ^= static_cast<uint8_t>((len64 >> 24u) & 0xFFu);
    acc[28] ^= static_cast<uint8_t>((len64 >> 32u) & 0xFFu);
    acc[29] ^= static_cast<uint8_t>((len64 >> 40u) & 0xFFu);
    acc[30] ^= static_cast<uint8_t>((len64 >> 48u) & 0xFFu);
    acc[31] ^= static_cast<uint8_t>((len64 >> 56u) & 0xFFu);

    uint64_t folded[4] = { 0u, 0u, 0u, 0u };
    for (unsigned w = 0u; w < 4u; ++w) {
        uint64_t v = 0u;
        for (unsigned b = 0u; b < 8u; ++b) {
            v |= static_cast<uint64_t>(acc[w * 8u + b])
                << (static_cast<unsigned>(b) * 8u);
        }
        folded[w] = v;
    }

    quantum_master_seed[0] ^= folded[0];
    quantum_master_seed[1] ^= folded[1];
    quantum_master_seed[2] ^= folded[2];
    quantum_master_seed[3] ^= folded[3];

    if (length >= 32u) {
        is_pqc_established = true;
    }

    // 키 파생 스택 소재 즉시 소거 (포렌식 방어)
    SecureMemory::secureWipe(acc, sizeof(acc));
    SecureMemory::secureWipe(folded, sizeof(folded));
}

uint64_t Quantum_Key_Bridge::Derive_Quantum_Session_ID() noexcept
{
    if (!is_pqc_established) {
        return 0u;
    }
    const uint64_t z = quantum_master_seed[0]
        ^ quantum_master_seed[1]
        ^ (quantum_master_seed[2] << 1u)
        ^ (quantum_master_seed[3] >> 1u)
        ^ sync_counter;
    sync_counter += 1u;
    return z;
}

void Quantum_Key_Bridge::Synchronize_CTR_State(uint64_t& out_session_id) noexcept
{
    if (!is_pqc_established) {
        out_session_id = 0u;
        return;
    }
    out_session_id = quantum_master_seed[0] ^ quantum_master_seed[1]
        ^ quantum_master_seed[2] ^ quantum_master_seed[3];
}

} // namespace ProtectedEngine
