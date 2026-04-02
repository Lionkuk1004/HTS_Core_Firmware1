// =========================================================================
// HTS_Hardware_Auto_Scaler.h
// 하드웨어 가용 메모리 기반 텐서 자동 스케일링
// Target: STM32F407 (Cortex-M4, DMA SRAM 128KB)
//
// [설계 목적]
//  Dual_Tensor_Pipeline의 듀얼 레인 버퍼 크기를 런타임에 결정
//  플랫폼 가용 메모리의 50%를 HTS 엔진에 할당 → 듀얼 텐서 개수 산출
//
// [HTS_Config와의 관계]
//  HTS_Static_Config: 비트 레벨 텐서 크기 (262144 노드 = 8192 uint32_t)
//    → PHY 단위: 확산 코드 길이, 패킹 크기 등 고정 파라미터
//  Hardware_Auto_Scaler: 듀얼 레인 버퍼 크기 (16384 uint32_t)
//    → 파이프라인 단위: Tx/Rx 이중 처리 버퍼 크기 (가변)
//  두 값은 독립적 — 서로 다른 추상화 계층의 크기를 결정
//
#pragma once
// ─────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────
//  [사용법] 기본 사용 예시를 여기에 기재하세요.
//  [메모리] sizeof(클래스명) 확인 후 전역/정적 배치 필수.
//  [보안]   복사/이동 연산자 = delete (키 소재 복제 차단).
//
//  ⚠ [파트너사 필수 확인]
//    HW 레지스터 주소(UART/WDT 등)는 보드 설계에 맞게 교체.
//    IRQ 번호는 STM32F407 RM0090 벡터 테이블 기준으로 교체.
// ─────────────────────────────────────────────────────────

#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    class Hardware_Auto_Scaler {
    public:
        // ── 스케일링 한계 상수 ────────────────────────────────────────
        //
        //  위협: 비2의제곱 MIN_TENSORS(1000)가 Floor_Power_Of_Two 이후
        //        강제 대입되면 하위 모듈의 비트마스크 모듈러 연산
        //        (idx & (count-1)) 붕괴 → OOB/HardFault
        //
        //  MIN_TENSORS: 1024 (2^10) × 4B = 4KB — 최소 동작 보장
        //  MAX_TENSORS: 1048576 (2^20) × 4B = 4MB — 서버급 버퍼
        //  BYTES_PER_DUAL_TENSOR: 듀얼 레인 1요소 = uint32_t = 4바이트
        static const size_t MIN_TENSORS = 1024;
        static const size_t MAX_TENSORS = 1048576;
        static const size_t BYTES_PER_DUAL_TENSOR = 4;

        // [빌드타임 검증] MIN/MAX가 반드시 2의제곱수임을 보장
        //  위반 시 즉시 빌드 실패 → 런타임 비트마스크 붕괴 원천 차단

        // ── 최적 텐서 개수 계산 ──────────────────────────────────────
        //  반환: 플랫폼 메모리 50% 기준 듀얼 텐서 개수
        //  ARM STM32F407: 128KB × 50% / 4B = 16384
        //  PC (16GB):     16GB × 50% / 4B = 2G → MAX_TENSORS(1M)로 클리핑
        static size_t Calculate_Optimal_Tensor_Count() noexcept;

    private:
        // 플랫폼별 가용 메모리 감지
        static size_t Get_Free_System_Memory() noexcept;
    };

    static_assert(
        Hardware_Auto_Scaler::MIN_TENSORS > 0 &&
        (Hardware_Auto_Scaler::MIN_TENSORS &
            (Hardware_Auto_Scaler::MIN_TENSORS - 1)) == 0,
        "MIN_TENSORS must be a power of 2 — "
        "비트마스크 모듈러 연산(idx & (count-1)) 정합성 필수");
    static_assert(
        Hardware_Auto_Scaler::MAX_TENSORS > 0 &&
        (Hardware_Auto_Scaler::MAX_TENSORS &
            (Hardware_Auto_Scaler::MAX_TENSORS - 1)) == 0,
        "MAX_TENSORS must be a power of 2 — "
        "Floor_Power_Of_Two 이후에도 2의제곱 보장 필수");

} // namespace ProtectedEngine
