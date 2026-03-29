// =========================================================================
// TensorCodec.hpp
// 3D 텐서 FEC 코덱 — 공개 인터페이스
// Target: Cortex-A55 (CORE-X Pro 메인CPU) / Server
//
// ─────────────────────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────────────────────
//
//  [⚠ STM32 베어메탈 사용 금지 — A55/서버 전용]
//   vector 기반 3D 텐서 + AnchorEncoder/Decoder 힙 의존
//   STM32 빌드 시 cpp #error로 차단됨
//
//  [메모리 요구량]
//   sizeof(TensorCodec) ≈ IMPL_BUF_SIZE + impl_valid_ + padding
//   Impl: AnchorManager(값) + AnchorEncoder(값) + AnchorDecoder(값)
//         → sizeof(Impl)는 AnchorManager/Encoder/Decoder 크기에 의존
//         → get_impl() 내부 static_assert로 컴파일 타임 검증
//         → IMPL_BUF_SIZE = 2048B (초과 시 static_assert 즉시 실패)
//
//  [보안 설계]
//   tensor_data: TensorPacket 소멸자에서 보안 소거
//   impl_buf_: 소멸자에서 SecWipe — 전체 이중 소거
//   복사/이동: = delete (보안 상태 복제 차단)
//
//  [양산 수정 이력]
//   BUG-01~15 (소거, Pimpl, 헤더차단, copy/move, OOB방어, noexcept,
//              iostream제거, nodiscard, Self-Contained, Doxygen, SRAM문서,
//              앵커평탄화, insert크기검증, RAII소거, 네임스페이스빌드에러)
//   BUG-16~19 (pragma O0 삭제→asm clobber, DecodePacket 크기검증,
//              앵커슬라이싱 OOB 방어, RAII capacity→size)
//   BUG-20 [CRIT] unique_ptr + make_unique + try-catch(ctor) → placement new
//          · impl_buf_[2048] alignas(8)
//          · 소멸자 = default → 명시적 p->~Impl() + SecWipe_Tensor
//
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>

// [BUG-15] AnchorManager는 전역 네임스페이스 (ProtectedEngine 밖)
class AnchorManager;

namespace ProtectedEngine {

    class AnchorEncoder;
    class AnchorDecoder;

    // =====================================================================
    //  TensorPacket — [BUG-12] 평탄화 앵커 구조
    // =====================================================================
    class TensorPacket {
    private:
        std::vector<uint16_t> tensor_data;

        // 1차원 평탄화: flat[i * anchor_len .. (i+1)*anchor_len - 1]
        std::vector<uint16_t> row_anchors_flat;
        std::vector<uint16_t> col_anchors_flat;
        std::vector<uint16_t> depth_anchors_flat;
        size_t row_anchor_len = 0u;
        size_t col_anchor_len = 0u;
        size_t depth_anchor_len = 0u;
        size_t row_anchor_count = 0u;
        size_t col_anchor_count = 0u;
        size_t depth_anchor_count = 0u;

        size_t valid_bytes = 0u;
        bool   is_last = false;

        friend class TensorCodec;

    public:
        TensorPacket() = default;
        ~TensorPacket() noexcept;

        TensorPacket(TensorPacket&&) noexcept = default;
        TensorPacket& operator=(TensorPacket&&) noexcept = default;
        TensorPacket(const TensorPacket&) = delete;
        TensorPacket& operator=(const TensorPacket&) = delete;

        std::vector<uint16_t>& getMutableData() { return tensor_data; }
        const std::vector<uint16_t>& getData()        const { return tensor_data; }
        size_t getValidBytes()                        const { return valid_bytes; }
        bool   isLast()                               const { return is_last; }
    };

    // =====================================================================
    //  TensorCodec — 3D FEC 코덱 (Pimpl 완전 은닉)
    // =====================================================================
    class TensorCodec {
    public:
        /// @brief 코덱 생성 (AnchorManager/Encoder/Decoder In-Place 배치)
        /// @note  sizeof(Impl) ≤ IMPL_BUF_SIZE 는 get_impl() static_assert로 검증
        TensorCodec() noexcept;

        /// @brief 소멸자 — Impl 소멸자 호출 후 impl_buf_ 전체 SecWipe
        ~TensorCodec() noexcept;

        TensorCodec(const TensorCodec&) = delete;
        TensorCodec& operator=(const TensorCodec&) = delete;
        TensorCodec(TensorCodec&&) = delete;
        TensorCodec& operator=(TensorCodec&&) = delete;

        /// @brief 청크 인코딩 (3D 텐서 + 평탄 앵커 생성)
        /// @param buffer      원본 데이터 버퍼
        /// @param offset      현재 청크 시작 오프셋
        /// @param total_size  전체 전송 크기
        /// @return TensorPacket (실패 시 비어있는 패킷)
        [[nodiscard]]
        TensorPacket EncodeChunk(
            const std::vector<char>& buffer,
            size_t offset, size_t total_size) noexcept;

        /// @brief 패킷 디코딩 (터보 반복 복구)
        /// @param pkt              수신 패킷 (in-place 복구)
        /// @param turbo_iterations 터보 복구 반복 횟수 (기본 3)
        void DecodePacket(
            TensorPacket& pkt,
            int turbo_iterations = 3) noexcept;

        /// @brief 현재 AMC 앵커 비율 반환
        uint8_t getCurrentRatio() const noexcept;

        /// @brief AMC 자동 조정 피드백
        void provideFeedback(int residual_errors, int loops_used) noexcept;

    private:
        // ── [BUG-20] Pimpl In-Place Storage (zero-heap) ──────────────
        //
        // IMPL_BUF_SIZE 산출:
        //   Impl = AnchorManager(값) + AnchorEncoder(값) + AnchorDecoder(값)
        //   → 실제 크기는 AnchorManager/Encoder/Decoder 정의에 의존
        //   → get_impl() 내부 static_assert가 컴파일 타임에 검증
        //   → 초과 시 즉시 빌드 실패 → IMPL_BUF_SIZE 값을 늘릴 것
        //   → 2048B를 시작값으로 설정 (모자라면 static_assert가 알려줌)
        static constexpr size_t IMPL_BUF_SIZE = 2048u;
        static constexpr size_t IMPL_BUF_ALIGN = 8u;

        struct Impl;  ///< AnchorManager + Encoder + Decoder 완전 은닉

        alignas(IMPL_BUF_ALIGN) uint8_t impl_buf_[IMPL_BUF_SIZE];
        bool impl_valid_ = false;

        Impl* get_impl() noexcept;
        const Impl* get_impl() const noexcept;
    };

} // namespace ProtectedEngine