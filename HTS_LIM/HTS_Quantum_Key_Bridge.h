// =========================================================================
// HTS_Quantum_Key_Bridge.h
// PQC 양자 내성 키 브릿지 (AES-CTR 세션 ID 도출)
// Target: STM32F407 (Cortex-M4)
// =========================================================================
#pragma once
#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    class Quantum_Key_Bridge {
    private:
        uint64_t quantum_master_seed[4] = { 0 };
        bool is_pqc_established = false;
        // 인스턴스별 독립 카운터
        uint64_t sync_counter = 0;

    public:
        Quantum_Key_Bridge() noexcept = default;

        // 소멸자: 256비트 마스터 키 보안 소거
        ~Quantum_Key_Bridge() noexcept;

        // 마스터 키 복제 원천 차단
        Quantum_Key_Bridge(const Quantum_Key_Bridge&) = delete;
        Quantum_Key_Bridge& operator=(const Quantum_Key_Bridge&) = delete;
        Quantum_Key_Bridge(Quantum_Key_Bridge&&) = delete;
        Quantum_Key_Bridge& operator=(Quantum_Key_Bridge&&) = delete;

        /// @brief PQC/양자 엔트로피 재료 주입 (힙 0 — 원시 버퍼만)
        /// @param entropy_buf  엔트로피 바이트 (nullptr이면 무동작)
        /// @param length       바이트 수 (0이면 무동작). 권장 32~64B(Storage_Interface 주석 정합).
        void Inject_Quantum_Entropy(
            const uint8_t* entropy_buf,
            std::size_t length) noexcept;

        [[nodiscard]]
        uint64_t Derive_Quantum_Session_ID() noexcept;

        void Synchronize_CTR_State(uint64_t& out_session_id) noexcept;
    };

} // namespace ProtectedEngine