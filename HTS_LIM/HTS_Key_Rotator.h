// =========================================================================
// HTS_Key_Rotator.h
// Forward Secrecy 기반 동적 시드 로테이터 — 공개 인터페이스
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [목적]
//  블록 인덱스(카운터) 기반 단방향 시드 파생.
//  파생 시드에서 이전 시드로의 역산이 수학적으로 불가 (Forward Secrecy).
//
//  [사용법]
//   1. 생성: DynamicKeyRotator(masterSeed, len)
//      → 마스터 시드 최대 32B를 Impl.currentSeed[32]에 복사 (Zero-Heap placement)
//      → PC 전용 vector 생성자는 Raw API로 위임
//
//   2. deriveNextSeed(blockIndex): 블록별 파생 시드 생성
//      → 내부 상태를 Murmur3 기반으로 비가역적 변이 (Forward Secrecy)
//
//  [메모리 요구량]
//   sizeof(DynamicKeyRotator) ≈ IMPL_BUF_SIZE(256B) + impl_valid_(원자) + 패딩
//   Impl: currentSeed[32] 고정 배열 + spin_lock 등 — 힙 미사용
//
//  [보안 설계]
//   마스터 시드: Impl 소멸자에서 volatile 보안 소거 + fence
//   impl_buf_: 소멸자에서 Key_Rotator_Secure_Wipe — 3중 방어 소거
//   파생 중간값(running_hash, Murmur3 로컬): 함수 반환 전 보안 소거
//   복사/이동: = delete (키 소재 복제 경로 원천 차단)
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <atomic>
#include <cstdint>
#include <cstddef>
#if !defined(__arm__) && !defined(__TARGET_ARCH_ARM) && \
    !defined(__TARGET_ARCH_THUMB) && !defined(__ARM_ARCH)
#include <vector>
#endif

namespace ProtectedEngine {

    class DynamicKeyRotator {
    public:
        /// @brief [Raw API] Zero-Heap — ARM/임베디드 기본 진입점
        explicit DynamicKeyRotator(
            const uint8_t* masterSeed, size_t master_len) noexcept;

#if !defined(__arm__) && !defined(__TARGET_ARCH_ARM) && \
    !defined(__TARGET_ARCH_THUMB) && !defined(__ARM_ARCH)
        /// @brief Forward Secrecy 시드 로테이터 생성
        /// @param masterSeed  초기 마스터 시드 (빈 벡터면 data()==nullptr → 0으로 채움)
        /// @note  PC: vector API는 Raw API로 위임 — 실패 시 deriveNextSeed 빈 벡터
        /// @note  소멸 시 마스터 시드 보안 소거 보장 (volatile + fence)
        explicit DynamicKeyRotator(
            const std::vector<uint8_t>& masterSeed) noexcept;
#endif

        /// @brief 소멸자 — p->~Impl() + Key_Rotator_Secure_Wipe(impl_buf_) 3중 방어
        ~DynamicKeyRotator() noexcept;

        /// 키 소재 복사 경로 원천 차단
        DynamicKeyRotator(const DynamicKeyRotator&) = delete;
        DynamicKeyRotator& operator=(const DynamicKeyRotator&) = delete;
        DynamicKeyRotator(DynamicKeyRotator&&) = delete;
        DynamicKeyRotator& operator=(DynamicKeyRotator&&) = delete;

        /// @brief [Raw API] 블록 인덱스 기반 단방향 시드 파생 (Zero-Heap)
        /// @param blockIndex   블록 카운터 (0, 1, 2, ...)
        /// @param out_buf      출력 버퍼 (호출자 소유)
        /// @param out_buf_size out_buf 크기 — seed_len(32) 미만이면 실패
        /// @param[out] out_len 성공 시 복사된 바이트 수(seed_len), 실패 시 0
        /// @return 성공 시 true, 실패(nullptr/미초기화/버퍼 부족) 시 false
        /// @post  내부 시드가 비가역적으로 변이됨 (Forward Secrecy)
        /// @note  Cortex-M 단일코어: PRIMASK로 상호배제. PC/A55: atomic_flag 스핀(타임아웃).
        ///        스핀 경로는 ISR에서 호출하지 말 것(데드락).
        bool deriveNextSeed(uint32_t blockIndex,
            uint8_t* out_buf, size_t out_buf_size, size_t& out_len) noexcept;

#if !defined(__arm__) && !defined(__TARGET_ARCH_ARM) && \
    !defined(__TARGET_ARCH_THUMB) && !defined(__ARM_ARCH)
        /// @brief [호환] 기존 vector API — Raw API 래퍼 (마이그레이션 후 삭제)
        /// @deprecated Raw API 사용 권장
        std::vector<uint8_t> deriveNextSeed(uint32_t blockIndex) noexcept;
#endif

    private:
        // ── Pimpl In-Place Storage (zero-heap) ─────────────────────
        // Impl: uint8_t currentSeed[32] 고정 + atomic_flag 등 (cpp와 일치)
        static constexpr size_t IMPL_BUF_SIZE = 256u;
        static constexpr size_t IMPL_BUF_ALIGN = 8u;

        struct Impl;  ///< 키 소재 완전 은닉 (ABI 안정성 보장)

        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        std::atomic<bool> impl_valid_{ false };  ///< placement new 성공 여부

        Impl* get_impl() noexcept;
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine