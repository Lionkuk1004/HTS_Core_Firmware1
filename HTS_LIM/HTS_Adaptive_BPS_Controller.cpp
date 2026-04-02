// =========================================================================
// HTS_Adaptive_BPS_Controller.cpp
// HTS 적응형 BPS 히스테리시스 컨트롤러 구현부
// Target: STM32F407 (Cortex-M4, 168MHz)
//
//
// [판단 로직 요약]
//
//  HEAVY → BPS_MIN 즉시 (재밍 감지 → 즉각 반응, 지연 허용 안 됨)
//  QUIET → quiet_count_++ → HYST_UP_COUNT 도달 시 BPS++ → count 리셋
//  HOLD  → quiet_count_ 리셋 (BPS 유지 — 불안정 구간에서 진동 방지)
//
// [왜 HOLD 구간에서 count를 리셋하는가]
//  HOLD 구간(ajc 500~2000 또는 snr 5~10)은 채널이 안정적이지 않은 상태입니다.
//  이 구간에서 count를 유지하면, QUIET → HOLD → QUIET를 반복할 때
//  count가 누적되어 충분히 안정되지 않은 채 BPS가 올라갈 수 있습니다.
//  완전한 QUIET 상태가 연속 8프레임 유지될 때만 상향하는 것이 목적이므로
//  HOLD 진입 즉시 리셋합니다.
//
// [왜 BPS를 내릴 때 즉시 BPS_MIN으로 점프하는가]
//  재밍 환경에서 BPS가 4→3→4→3으로 진동하면 HARQ 파라미터가 매 프레임 바뀌고
//  FEC 디코더가 일관된 상태를 유지할 수 없습니다.
//  BPS_MIN(3)이 변전소 +20dB 재밍에서 검증된 안전 최솟값이므로,
//  재밍 감지 즉시 확정 최솟값으로 떨어뜨리는 것이 가장 안전합니다.
// =========================================================================
#include "HTS_Adaptive_BPS_Controller.h"

namespace ProtectedEngine {

    HTS_Adaptive_BPS_Controller::HTS_Adaptive_BPS_Controller(
        HTS_RF_Metrics& metrics) noexcept
        : metrics_(metrics)
        , quiet_count_(0u)
    {
        // 초기 상태: 안전 최솟값으로 강제 설정
        // 시스템 부팅 직후 채널 상태를 알 수 없으므로 보수적 출발
        metrics_.current_bps.store(BPS_MIN, std::memory_order_release);
    }

    void HTS_Adaptive_BPS_Controller::Update() noexcept {
        // 단일 코어(Cortex-M): std::atomic_flag try-lock은 사용하지 않음.
        // 메인이 Set한 뒤 ISR이 동일 Update()를 호출하면 조기 반환으로
        // BPS/히스테리시스 갱신이 통째로 건너뛰어질 수 있음(실시간 적응 실패).
        // quiet_count_는 메인 루프 단일 컨텍스트에서만 갱신 — ISR 호출 금지(헤더 계약).

        // ── 측정값 읽기 (acquire: 쓰기 모듈의 release와 쌍을 이룸) ──
        const int32_t  snr = metrics_.snr_proxy.load(
            std::memory_order_acquire);
        const uint32_t ajc = metrics_.ajc_nf.load(
            std::memory_order_acquire);

        // ── 1순위: HEAVY 조건 — 즉시 BPS_MIN ───────────────────────
        // AJC 에너지가 2000 이상(기준값 20배) 이거나
        // SNR 프록시가 5 미만(피크가 노이즈의 5배도 안 됨)이면
        // 채널이 심각하게 손상된 것으로 판단 → 즉시 BPS_MIN
        if (ajc >= AJC_HEAVY_THR || snr < NOISY_SNR_THR) {
            metrics_.current_bps.store(BPS_MIN, std::memory_order_release);
            quiet_count_ = 0u;
            return;
        }

        // ── 2순위: QUIET 조건 — 카운터 누적 ────────────────────────
        // AJC 에너지가 500 미만(기준값 5배) AND SNR 프록시가 10 이상
        // 두 조건을 동시에 만족해야 카운터 증가 (OR이 아닌 AND)
        if (ajc < AJC_IDLE_THR && snr >= QUIET_SNR_THR) {
            // uint8_t 오버플로 방지: HYST_UP_COUNT(8) + 1 = 9 << 255
            if (quiet_count_ < HYST_UP_COUNT) {
                ++quiet_count_;
            }

            if (quiet_count_ >= HYST_UP_COUNT) {
                // 임계 도달 → BPS 한 단계 상향 (최대 BPS_MAX)
                const uint8_t cur = metrics_.current_bps.load(
                    std::memory_order_relaxed);
                if (cur < BPS_MAX) {
                    metrics_.current_bps.store(
                        static_cast<uint8_t>(cur + 1u),
                        std::memory_order_release);
                }
                // 다음 상향 조건을 위해 카운터 리셋
                // → BPS_MAX에 도달한 경우에도 리셋 (현재 레벨 유지)
                quiet_count_ = 0u;
            }
            return;
        }

        // ── 3순위: HOLD 구간 — 카운터 리셋, BPS 유지 ───────────────
        // ajc 500~2000 OR snr 5~10 인 불안정 경계 구간
        // 충분히 안정적이지 않으므로 BPS를 올리지 않고 count를 초기화
        quiet_count_ = 0u;
    }

    void HTS_Adaptive_BPS_Controller::Reset() noexcept {
        metrics_.current_bps.store(BPS_MIN, std::memory_order_release);
        quiet_count_ = 0u;
        // snr_proxy, ajc_nf는 측정 모듈이 곧 덮어쓰므로 리셋 불필요
    }

} // namespace ProtectedEngine
