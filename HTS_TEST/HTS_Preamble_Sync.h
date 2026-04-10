// =============================================================================
// HTS_Preamble_Sync.h — O(1) 경판정 + CFAR 연판정 프리앰블 상관기
//
// [설계 원리]
//  1단계: 경판정 해밍 거리 (O(1)/칩, shift register + XOR + popcount)
//   → 64비트 시프트 레지스터에 칩을 밀어넣고, 알려진 패턴과 XOR
//   → popcount로 해밍 거리 산출, tolerance 이하면 후보 검출
//   → 매 칩마다 검사 — 모든 정렬 위치를 놓치지 않음
//
//  2단계: 연판정 상관 검증 (O(64), 후보 검출 시에만 실행)
//   → 64칩 순환 버퍼의 soft 값으로 정밀 상관
//   → CFAR: 상관값이 잡음 추정 대비 충분히 큰지 검증
//   → 1단계 오경보 제거
//
//  [군용 기법 적용]
//   CFAR (Constant False Alarm Rate): MIL-STD-188-110C 방식
//    → 잡음 레벨 적응형 문턱으로 환경 변화에 자동 대응
//   Post-Detection Integration: NATO STANAG 4539 방식
//    → 프리앰블 반복(pre_reps) 시 연판정 누적으로 이득 확보
//
// [제약사항]
//  ARM/PC 3-플랫폼 호환. 힙 할당 없음. 분기 최소화.
//  __builtin_popcountll: GCC/Clang. MSVC: __popcnt64/_BitScanReverse64.
//
#pragma once
#include <cstdint>
#include <cstring>
namespace ProtectedEngine {
class HTS_Preamble_Sync {
  public:
    static constexpr int NC = 64;
    // ── 초기화 ──
    //  pre_sym0/1: Walsh 심볼 인덱스 (HTS: PRE_SYM0=63, PRE_SYM1=0)
    //  tolerance: 허용 해밍 거리 (기본 24 → 칩 에러 37.5%까지)
    //  cfar_factor_q8: CFAR 문턱 배율 Q8 (256 = 1.0×, 512 = 2.0×)
    void Init(uint8_t pre_sym0, uint8_t pre_sym1, int32_t tolerance = 24,
              int32_t cfar_factor_q8 = 384) noexcept {
        m_window = 0u;
        m_pattern0 = walsh_to_bits(pre_sym0);
        m_pattern1 = walsh_to_bits(pre_sym1);
        m_tolerance = tolerance;
        m_cfar_q8 = cfar_factor_q8;
        m_phase = 0;
        m_soft_idx = 0;
        m_noise_sum = 0;
        m_noise_n = 0;
        m_pre0_soft_accum = 0;
        m_pre0_count = 0;
        m_align_wait = 0;
        std::memset(m_soft_buf, 0, sizeof(m_soft_buf));
        // 부호 패턴 사전 계산 (연판정 상관용)
        for (int j = 0; j < NC; ++j) {
            m_sign0[j] = static_cast<int8_t>(
                ((m_pattern0 >> static_cast<unsigned>(j)) & 1u) ? 1 : -1);
            m_sign1[j] = static_cast<int8_t>(
                ((m_pattern1 >> static_cast<unsigned>(j)) & 1u) ? 1 : -1);
        }
    }
    // ── 칩 투입 + 동기 검출 ──
    //  rx_I, rx_Q: 수신 I/Q (int16)
    //  반환: 0xFFFFFFFF = PRE_SYM0+PRE_SYM1 시퀀스 검출 (동기 확정)
    //        0x00000000 = 미검출
    //
    //  호출 빈도: 매 칩마다 (O(1) 보장)
    uint32_t Feed(int16_t rx_I, int16_t rx_Q) noexcept {
        // I+Q 결합 (TX가 I=Q 동일 전송)
        const int32_t rx =
            (static_cast<int32_t>(rx_I) + static_cast<int32_t>(rx_Q)) >> 1;
        // ── 경판정: 시프트 레지스터 갱신 ──
        //  우측 시프트: bit0=chip[0](oldest), bit63=chip[63](newest)
        //  walsh_to_bits: bit j = chip[j] → 비트 순서 정합
        const uint64_t hard_bit =
            static_cast<uint64_t>(static_cast<uint32_t>(rx >= 0));
        m_window = (m_window >> 1u) | (hard_bit << 63u);
        // ── 연판정: 순환 버퍼 갱신 ──
        m_soft_buf[m_soft_idx] = rx;
        m_soft_idx = (m_soft_idx + 1) & (NC - 1);
        // ── 잡음 추정 (CFAR용): |rx| 이동 평균 ──
        const int32_t abs_rx = (rx >= 0) ? rx : -rx;
        m_noise_sum += static_cast<int64_t>(abs_rx);
        m_noise_n++;
        // ── 1단계: O(1) 해밍 거리 검사 ──
        if (m_phase == 0) {
            // PRE_SYM0 탐색
            const uint32_t det = hamming_check_(m_pattern0);
            if (det == 0u)
                return 0u;
            // ── 2단계: 연판정 검증 + CFAR ──
            const int32_t corr = soft_correlate_(m_sign0);
            const int32_t thr = cfar_threshold_();
            if (corr <= thr)
                return 0u; // 오경보 제거
            // PRE_SYM0 확정 → PRE_SYM1 탐색으로 전이
            m_phase = 1;
            m_pre0_soft_accum = corr;
            m_pre0_count = 1;
            m_align_wait = 64; // 다음 심볼 경계까지 64칩 대기
            return 0u;
        }
        // m_phase == 1: PRE_SYM1 탐색 (64칩 정렬 게이트)
        --m_align_wait;
        if (m_align_wait > 0)
            return 0u; // 정렬 대기 중 — 검사 건너뜀
        // 64칩 경계 도달 — 검사 실행 후 다음 경계 대기 설정
        m_align_wait = 64;
        {
            // PRE_SYM1 검출?
            const uint32_t det1 = hamming_check_(m_pattern1);
            if (det1 != 0u) {
                const int32_t corr1 = soft_correlate_(m_sign1);
                if (corr1 > 0) {
                    // ── 동기 확정: PRE_SYM0 + PRE_SYM1 시퀀스 완성 ──
                    m_phase = 0;
                    return 0xFFFFFFFFu;
                }
            }
            // 반복 PRE_SYM0? (TX pre_reps > 1)
            const uint32_t det0 = hamming_check_(m_pattern0);
            if (det0 != 0u) {
                const int32_t corr0 = soft_correlate_(m_sign0);
                if (corr0 > 0) {
                    m_pre0_soft_accum += corr0;
                    m_pre0_count++;
                    return 0u;
                }
            }
        }
        // 정렬 경계에서 어느 것도 검출 안 됨 → 오검출 리셋
        if (m_pre0_count > 72) {
            m_phase = 0;
        }
        return 0u;
    }
    // ── 리셋 ──
    void Reset() noexcept {
        m_window = 0u;
        m_phase = 0;
        m_soft_idx = 0;
        m_noise_sum = 0;
        m_noise_n = 0;
        m_pre0_soft_accum = 0;
        m_pre0_count = 0;
        m_align_wait = 0;
        std::memset(m_soft_buf, 0, sizeof(m_soft_buf));
    }
    [[nodiscard]] int Get_Phase() const noexcept { return m_phase; }
    [[nodiscard]] int32_t Get_Pre0_Accum() const noexcept {
        return m_pre0_soft_accum;
    }

  private:
    uint64_t m_window;         ///< 64비트 경판정 시프트 레지스터
    uint64_t m_pattern0;       ///< PRE_SYM0 경판정 비트 패턴
    uint64_t m_pattern1;       ///< PRE_SYM1 경판정 비트 패턴
    int32_t m_tolerance;       ///< 허용 해밍 거리
    int32_t m_cfar_q8;         ///< CFAR 문턱 배율 (Q8 고정소수점)
    int m_phase;               ///< 0=PRE_SYM0 탐색, 1=PRE_SYM1 대기
    int32_t m_soft_buf[NC];    ///< 연판정 순환 버퍼
    int8_t m_sign0[NC];        ///< PRE_SYM0 부호 패턴 (±1)
    int8_t m_sign1[NC];        ///< PRE_SYM1 부호 패턴 (±1)
    int m_soft_idx;            ///< 순환 버퍼 쓰기 인덱스
    int64_t m_noise_sum;       ///< |rx| 누적 (CFAR 잡음 추정)
    int32_t m_noise_n;         ///< 잡음 샘플 수
    int32_t m_pre0_soft_accum; ///< PRE_SYM0 연판정 누적 (PDI)
    int32_t m_pre0_count;      ///< PRE_SYM0 검출 횟수
    int m_align_wait;          ///< 64칩 정렬 대기 카운터
    // ── Walsh 심볼 → 64비트 경판정 비트 패턴 변환 ──
    //  chip[j] = (-1)^popcount(sym & j)
    //  bit[j] = 1 if chip positive, 0 if negative
    static uint64_t walsh_to_bits(uint8_t sym) noexcept {
        uint64_t pat = 0u;
        for (int j = 0; j < NC; ++j) {
            uint32_t x = static_cast<uint32_t>(sym) & static_cast<uint32_t>(j);
            // 인라인 popcount (8비트 이하)
            x = x - ((x >> 1u) & 0x55u);
            x = (x & 0x33u) + ((x >> 2u) & 0x33u);
            x = (x + (x >> 4u)) & 0x0Fu;
            const uint32_t even = 1u - (x & 1u); // 짝수 패리티 → +1 → bit=1
            pat |= static_cast<uint64_t>(even) << static_cast<unsigned>(j);
        }
        return pat;
    }
    // ── O(1) 해밍 거리 검사 (branchless) ──
    //  errors ≤ tolerance → 0xFFFFFFFF, 초과 → 0x00000000
    uint32_t hamming_check_(uint64_t pattern) const noexcept {
        const uint64_t diff = m_window ^ pattern;
        // portable popcount64: split into two 32-bit halves
        const uint32_t lo = static_cast<uint32_t>(diff);
        const uint32_t hi = static_cast<uint32_t>(diff >> 32u);
        auto pc32 = [](uint32_t v) noexcept -> uint32_t {
            v = v - ((v >> 1u) & 0x55555555u);
            v = (v & 0x33333333u) + ((v >> 2u) & 0x33333333u);
            return (((v + (v >> 4u)) & 0x0F0F0F0Fu) * 0x01010101u) >> 24u;
        };
        const int32_t errors = static_cast<int32_t>(pc32(lo) + pc32(hi));
        const int32_t d = errors - m_tolerance - 1;
        return 0u - (static_cast<uint32_t>(d) >> 31u);
    }
    // ── 연판정 상관 (O(64), 후보 검출 시에만 호출) ──
    int32_t soft_correlate_(const int8_t *sign) const noexcept {
        int32_t corr = 0;
        for (int i = 0; i < NC; ++i) {
            // oldest → newest 순서로 읽어 패턴과 정합
            const int idx = (m_soft_idx + i) & (NC - 1);
            corr += m_soft_buf[idx] * static_cast<int32_t>(sign[i]);
        }
        return corr;
    }
    // ── CFAR 적응 문턱 산출 ──
    //  noise_avg = |rx| 평균 (잡음 레벨 추정)
    //  threshold = noise_avg × NC × cfar_factor / 256
    //  신호 상관 = NC × amp = NC × noise_avg × SNR_lin
    //  문턱 << 신호 상관 → 검출, 문턱 >> 잡음 상관 → 오경보 억제
    int32_t cfar_threshold_() const noexcept {
        if (m_noise_n < NC)
            return 0; // 초기: 무조건 통과
        const int32_t noise_avg =
            static_cast<int32_t>(m_noise_sum / static_cast<int64_t>(m_noise_n));
        // threshold = noise_avg × cfar_factor_q8 / 256
        return static_cast<int32_t>((static_cast<int64_t>(noise_avg) *
                                     static_cast<int64_t>(m_cfar_q8)) >>
                                    8);
    }
};
} // namespace ProtectedEngine
