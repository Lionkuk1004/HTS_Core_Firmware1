// =============================================================================
// HTS_Polar_Codec.cpp — Polar SC 코덱 (N=512, K=80) — 정식 f/g 트리 전파
//
// [Phase 1] 인코더 + SC 디코더 (정식 구현)
// [Phase 2] SCL-4 CRC-Aided (별도 추가)
//
// [제약] float 0, double 0, 나눗셈 0, try-catch 0, 힙 0
// =============================================================================
#include "HTS_Polar_Codec.h"
#include <cstdint>
#include <cstring>
namespace ProtectedEngine {
namespace {
// ── Frozen 비트 마스크 (1024비트 = 128바이트) ───────────────
//  bit i = 1 → 정보 비트, bit i = 0 → frozen (=0)
//  K=80 비트가 1, FROZEN=944 비트가 0
//
//  byte[i] 의 bit j (LSB=0) → 인덱스 i*8+j
alignas(16) static constexpr uint8_t k_info_mask[128] = {
    //  Bhattacharyya bound (AWGN design SNR=1dB) 기반 신뢰도 상위 80개
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //    0-  63
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //   64- 127
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  128- 191
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, //  192- 255
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  256- 319
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, //  320- 383
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, //  384- 447
    0x00, 0x00, 0x00, 0x80, 0x00, 0x80, 0x80, 0xE8, //  448- 511
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  512- 575
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, //  576- 639
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, //  640- 703
    0x00, 0x00, 0x00, 0x80, 0x00, 0x80, 0x80, 0xE8, //  704- 767
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, //  768- 831
    0x00, 0x00, 0x00, 0x80, 0x00, 0x80, 0x80, 0xE8, //  832- 895
    0x00, 0x00, 0x00, 0x80, 0x00, 0x80, 0xE0, 0xFE, //  896- 959
    0x00, 0xE8, 0xE8, 0xFE, 0xE8, 0xFE, 0xFE, 0xFF, //  960-1023
};
static constexpr int count_info_bits_() noexcept {
    int cnt = 0;
    for (int i = 0; i < 128; ++i) {
        uint8_t b = k_info_mask[i];
        b = static_cast<uint8_t>(b - ((b >> 1u) & 0x55u));
        b = static_cast<uint8_t>((b & 0x33u) + ((b >> 2u) & 0x33u));
        cnt += static_cast<int>((b + (b >> 4u)) & 0x0Fu);
    }
    return cnt;
}
static_assert(count_info_bits_() == HTS_Polar_Codec::K,
              "Frozen mask info bit count must equal K=80");
// ── SC 디코더 스크래치 ────────────────────────────────────
static constexpr int SC_N = HTS_Polar_Codec::N;      // 1024
static constexpr int SC_LN = HTS_Polar_Codec::LOG_N; // 10
// P[stage][pos]: LLR — stage SC_LN=채널, stage 0=결정
// C[stage][pos]: 부분합 — stage 0=결정, stage SC_LN=코드워드
alignas(16) static int16_t g_P[(SC_LN + 1) * SC_N]; // 11*1024*2 = 22,528B
alignas(16) static uint8_t g_C[(SC_LN + 1) * SC_N]; // 11*1024   = 11,264B
static_assert(sizeof(g_P) + sizeof(g_C) <= 35000u,
              "SC scratch exceeds 35KB budget");
static inline int16_t &P_at(int s, int j) noexcept { return g_P[s * SC_N + j]; }
static inline uint8_t &C_at(int s, int j) noexcept { return g_C[s * SC_N + j]; }
// ── int16 포화 클램프 (branchless TPE) ────────────────────
//  ARM: __builtin_arm_ssat(v,16) 단일 명령어
//  PC:  비트마스크 기반 — 데이터 종속 분기 없음
static inline int16_t ssat16_(int32_t v) noexcept {
#if defined(__GNUC__) && defined(__ARM_ARCH) && (__ARM_ARCH >= 6)
    return static_cast<int16_t>(__builtin_arm_ssat(v, 16));
#else
    const uint32_t ov_hi = static_cast<uint32_t>(v > 32767);
    const uint32_t ov_lo = static_cast<uint32_t>(v < -32768);
    const int32_t msk = -static_cast<int32_t>(ov_hi | ov_lo);
    const int32_t repl = (32767 & -static_cast<int32_t>(ov_hi)) |
                         (-32768 & -static_cast<int32_t>(ov_lo));
    return static_cast<int16_t>((v & ~msk) | (repl & msk));
#endif
}
// ── 로컬 f/g/bit_reverse (SCL 익명 네임스페이스용) ────────
static inline int16_t local_f(int16_t a, int16_t b) noexcept {
    const int32_t va = static_cast<int32_t>(a);
    const int32_t vb = static_cast<int32_t>(b);
    const int32_t abs_a = (va ^ (va >> 31)) - (va >> 31);
    const int32_t abs_b = (vb ^ (vb >> 31)) - (vb >> 31);
    const int32_t diff = abs_a - abs_b;
    const int32_t sel = diff >> 31;
    const int32_t min_ab = abs_b + (diff & sel);
    const int32_t sign_xor = (va ^ vb) >> 31;
    return ssat16_((min_ab ^ sign_xor) - sign_xor);
}
static inline int16_t local_g(int16_t a, int16_t b, uint8_t u) noexcept {
    const int32_t va = static_cast<int32_t>(a);
    const int32_t vb = static_cast<int32_t>(b);
    return ssat16_(vb + va * (1 - 2 * static_cast<int32_t>(u & 1u)));
}
static inline int local_bit_reverse(int val, int bits) noexcept {
    int r = 0;
    for (int i = 0; i < bits; ++i) {
        r = (r << 1) | (val & 1);
        val >>= 1;
    }
    return r;
}
} // anonymous namespace
// ── Frozen 비트 조회 (자연 순서) ──────────────────────────
bool HTS_Polar_Codec::Is_Info_Bit(int i) noexcept {
    if (i < 0 || i >= N)
        return false;
    return (k_info_mask[i >> 3] >> (i & 7)) & 1u;
}
// ── CRC-16/CCITT ──────────────────────────────────────────
uint16_t HTS_Polar_Codec::CRC16(const uint8_t *data, int len) noexcept {
    if (data == nullptr || len <= 0)
        return 0u;
    uint16_t crc = 0xFFFFu;
    for (int i = 0; i < len; ++i) {
        crc ^= static_cast<uint16_t>(data[i]) << 8u;
        for (int b = 0; b < 8; ++b) {
            // branchless: 최상위 비트로 마스크 생성 (0xFFFF or 0x0000)
            const uint16_t mask = 0u - (crc >> 15u);
            crc = static_cast<uint16_t>((crc << 1u) ^ (0x1021u & mask));
        }
    }
    return crc;
}
// ── 비트 반전 순열 ────────────────────────────────────────
int HTS_Polar_Codec::bit_reverse_(int val, int bits) noexcept {
    int r = 0;
    for (int i = 0; i < bits; ++i) {
        r = (r << 1) | (val & 1);
        val >>= 1;
    }
    return r;
}
// ── 인코딩 나비 연산 (GF(2) XOR) ─────────────────────────
void HTS_Polar_Codec::encode_butterfly_(uint8_t *u, int n) noexcept {
    for (int half = 1; half < n; half <<= 1) {
        for (int i = 0; i < n; i += 2 * half) {
            for (int j = 0; j < half; ++j) {
                u[i + j] ^= u[i + j + half];
            }
        }
    }
}
// ── Polar 인코딩 ──────────────────────────────────────────
int HTS_Polar_Codec::Encode(const uint8_t *info, int info_len,
                            uint8_t *coded) noexcept {
    if (info == nullptr || coded == nullptr)
        return 0;
    if (info_len <= 0 || info_len > DATA_BYTES)
        return 0;
    const uint16_t crc = CRC16(info, info_len);
    // 80비트 평탄화: [data 64b | crc 16b]
    uint8_t flat[10] = {};
    for (int i = 0; i < info_len; ++i)
        flat[i] = info[i];
    flat[8] = static_cast<uint8_t>(crc >> 8u);
    flat[9] = static_cast<uint8_t>(crc & 0xFFu);
    // 정보 비트를 frozen mask 위치에 삽입
    static uint8_t u[N];
    std::memset(u, 0, sizeof(u));
    int info_bit_idx = 0;
    for (int i = 0; i < N; ++i) {
        if (Is_Info_Bit(i)) {
            const int byte_pos = info_bit_idx >> 3;
            const int bit_pos = 7 - (info_bit_idx & 7);
            u[i] = (flat[byte_pos] >> bit_pos) & 1u;
            info_bit_idx++;
        }
    }
    // 비트 반전 순열
    static uint8_t u_perm[N];
    std::memset(u_perm, 0, sizeof(u_perm));
    for (int i = 0; i < N; ++i) {
        u_perm[bit_reverse_(i, LOG_N)] = u[i];
    }
    // 나비 인코딩
    encode_butterfly_(u_perm, N);
    // 바이트 패킹 출력 (MSB first, branchless — 데이터 종속 분기 없음)
    std::memset(coded, 0, static_cast<std::size_t>(N >> 3));
    for (int i = 0; i < N; ++i) {
        coded[i >> 3] |= static_cast<uint8_t>(
            (u_perm[i] & 1u) << (7u - (static_cast<unsigned>(i) & 7u)));
    }
    return N;
}
// ── f-node (min-sum) ──────────────────────────────────────
//  f(a,b) = sign(a)×sign(b)×min(|a|,|b|)
int16_t HTS_Polar_Codec::f_node_(int16_t a, int16_t b) noexcept {
    const int32_t va = static_cast<int32_t>(a);
    const int32_t vb = static_cast<int32_t>(b);
    const int32_t abs_a = (va ^ (va >> 31)) - (va >> 31);
    const int32_t abs_b = (vb ^ (vb >> 31)) - (vb >> 31);
    const int32_t diff = abs_a - abs_b;
    const int32_t sel = diff >> 31;
    const int32_t min_ab = abs_b + (diff & sel);
    const int32_t sign_xor = (va ^ vb) >> 31;
    return ssat16_((min_ab ^ sign_xor) - sign_xor);
}
// ── g-node ────────────────────────────────────────────────
//  g(a,b,u) = b + (1-2u)×a
int16_t HTS_Polar_Codec::g_node_(int16_t a, int16_t b, uint8_t u) noexcept {
    const int32_t va = static_cast<int32_t>(a);
    const int32_t vb = static_cast<int32_t>(b);
    return ssat16_(vb + va * (1 - 2 * static_cast<int32_t>(u & 1u)));
}
// ═════════════════════════════════════════════════════════
//  SC 디코더 — 정식 f/g 트리 전파
//
//  [스케줄]
//   phi = 0..N-1 순차 처리:
//    1. LLR 전파: stage n → 0 (f/g)
//    2. 결정: frozen=0, info=hard(LLR)
//    3. 부분합 전파: stage 0 → n
//
//  [f-trigger] phi 가 블록 좌반 첫 위치
//  [g-trigger] phi 가 블록 우반 첫 위치
//  [C-trigger] phi 가 블록 마지막 위치
//
//  [비트 반전]
//   인코더: u[i] → u_perm[bit_rev(i)] → butterfly → coded
//   디코더 SC: 복원하는 것 = u_perm[phi]
//   u_perm[phi] = u[bit_rev(phi)]
//   frozen 판정: Is_Info_Bit(bit_rev(phi))
// ═════════════════════════════════════════════════════════
bool HTS_Polar_Codec::Decode_SC(const int16_t *llr, uint8_t *out,
                                int *out_len) noexcept {
    if (llr == nullptr || out == nullptr || out_len == nullptr)
        return false;
    *out_len = 0;
    // 채널 LLR 적재 (stage n = 최상위)
    for (int j = 0; j < N; ++j) {
        P_at(SC_LN, j) = llr[j];
    }
    std::memset(g_C, 0, sizeof(g_C));
    // 비트별 순차 디코딩
    for (int phi = 0; phi < N; ++phi) {
        // ── LLR 전파: stage n → stage 0 ──
        for (int s = SC_LN; s >= 1; --s) {
            const int block_size = 1 << s;
            const int half = block_size >> 1;
            const int block_start = phi & ~(block_size - 1);
            const int pos_in_block = phi & (block_size - 1);
            if (pos_in_block == 0) {
                // 좌반 첫 진입: f-operation
                for (int j = 0; j < half; ++j) {
                    P_at(s - 1, block_start + j) =
                        f_node_(P_at(s, block_start + j),
                                P_at(s, block_start + half + j));
                }
            } else if (pos_in_block == half) {
                // 우반 첫 진입: g-operation
                for (int j = 0; j < half; ++j) {
                    P_at(s - 1, block_start + half + j) =
                        g_node_(P_at(s, block_start + j),
                                P_at(s, block_start + half + j),
                                C_at(s - 1, block_start + j));
                }
            }
        }
        // ── 비트 결정 (branchless TPE) ──
        //  sign_bit = 1 if LLR<0 (bit=1), 0 if LLR>=0 (bit=0)
        //  is_info  = 1 if info, 0 if frozen
        //  decision = is_info & sign_bit → frozen 항상 0, info는 부호
        const int orig_idx = bit_reverse_(phi, LOG_N);
        const uint32_t is_info = static_cast<uint32_t>(
            (k_info_mask[orig_idx >> 3] >> (orig_idx & 7)) & 1u);
        const uint32_t sign_bit =
            static_cast<uint32_t>(static_cast<uint16_t>(P_at(0, phi)) >> 15u);
        C_at(0, phi) = static_cast<uint8_t>(is_info & sign_bit);
        // ── 부분합 전파: stage 0 → stage n ──
        for (int s = 0; s < SC_LN; ++s) {
            const int block_size = 1 << (s + 1);
            const int half = 1 << s;
            const int block_start = phi & ~(block_size - 1);
            const int pos_in_block = phi & (block_size - 1);
            if (pos_in_block == block_size - 1) {
                for (int j = 0; j < half; ++j) {
                    C_at(s + 1, block_start + j) =
                        C_at(s, block_start + j) ^
                        C_at(s, block_start + half + j);
                    C_at(s + 1, block_start + half + j) =
                        C_at(s, block_start + half + j);
                }
            }
        }
    }
    // 정보 비트 추출
    //  C_at(0, phi) = u_perm[phi] = u[bit_reverse(phi)]
    uint8_t flat[10] = {};
    int info_idx = 0;
    for (int i = 0; i < N; ++i) {
        if (Is_Info_Bit(i)) {
            const int phi = bit_reverse_(i, LOG_N);
            const int byte_pos = info_idx >> 3;
            const int bit_pos = 7 - (info_idx & 7);
            // branchless: 데이터 종속 분기 없음
            flat[byte_pos] |= static_cast<uint8_t>(
                (C_at(0, phi) & 1u) << static_cast<unsigned>(bit_pos));
            info_idx++;
        }
    }
    // CRC 검증
    const uint16_t calc_crc = CRC16(flat, DATA_BYTES);
    const uint16_t rx_crc =
        (static_cast<uint16_t>(flat[8]) << 8u) | static_cast<uint16_t>(flat[9]);
    if (calc_crc != rx_crc)
        return false;
    for (int i = 0; i < DATA_BYTES; ++i)
        out[i] = flat[i];
    *out_len = DATA_BYTES;
    return true;
}
// ═════════════════════════════════════════════════════════
//  SCL-4 CRC-Aided 디코더
//
//  [구조]
//   L=8 병렬 SC 경로, 정보 비트마다 분기+가지치기
//   최종 CRC 통과 경로 선택
//
//  [메모리] PC 테스트용 풀사이즈
//   STM32 최적화: lazy-copy + 오버레이 (Phase 3)
// ═════════════════════════════════════════════════════════
namespace {
static constexpr int SCL_L = HTS_Polar_Codec::SCL_L; // 4
static constexpr int SCL_2L = SCL_L * 2;             // 8
// per-path LLR 트리 + 부분합
alignas(
    16) static int16_t scl_P[SCL_L][(SC_LN + 1) * SC_N]; // 4×10×512×2 = 40KB
alignas(
    16) static uint8_t scl_C[SCL_L][(SC_LN + 1) * SC_N]; // 4×10×512   = 20KB
static int32_t scl_PM[SCL_2L]; // 경로 메트릭 (낮을수록 좋음)
static inline int16_t &sP(int l, int s, int j) noexcept {
    return scl_P[l][s * SC_N + j];
}
static inline uint8_t &sC(int l, int s, int j) noexcept {
    return scl_C[l][s * SC_N + j];
}
// 경로 복사
static void copy_path(int dst, int src) noexcept {
    if (dst == src)
        return;
    std::memcpy(scl_P[dst], scl_P[src], sizeof(scl_P[0]));
    std::memcpy(scl_C[dst], scl_C[src], sizeof(scl_C[0]));
}
// LLR 전파 (SC와 동일, 경로 l 전용)
static void scl_propagate_llr(int l, int phi) noexcept {
    for (int s = SC_LN; s >= 1; --s) {
        const int block_size = 1 << s;
        const int half = block_size >> 1;
        const int block_start = phi & ~(block_size - 1);
        const int pos_in_block = phi & (block_size - 1);
        if (pos_in_block == 0) {
            for (int j = 0; j < half; ++j) {
                sP(l, s - 1, block_start + j) =
                    local_f(sP(l, s, block_start + j),
                            sP(l, s, block_start + half + j));
            }
        } else if (pos_in_block == half) {
            for (int j = 0; j < half; ++j) {
                sP(l, s - 1, block_start + half + j) = local_g(
                    sP(l, s, block_start + j), sP(l, s, block_start + half + j),
                    sC(l, s - 1, block_start + j));
            }
        }
    }
}
// 부분합 갱신 (SC와 동일, 경로 l 전용)
static void scl_update_c(int l, int phi) noexcept {
    for (int s = 0; s < SC_LN; ++s) {
        const int block_size = 1 << (s + 1);
        const int half = 1 << s;
        const int block_start = phi & ~(block_size - 1);
        const int pos_in_block = phi & (block_size - 1);
        if (pos_in_block == block_size - 1) {
            for (int j = 0; j < half; ++j) {
                sC(l, s + 1, block_start + j) =
                    sC(l, s, block_start + j) ^
                    sC(l, s, block_start + half + j);
                sC(l, s + 1, block_start + half + j) =
                    sC(l, s, block_start + half + j);
            }
        }
    }
}
// 정보 비트 추출 + CRC 검사 (경로 l)
static bool scl_extract_and_crc(int l, uint8_t *out) noexcept {
    uint8_t flat[10] = {};
    int info_idx = 0;
    for (int i = 0; i < SC_N; ++i) {
        if (HTS_Polar_Codec::Is_Info_Bit(i)) {
            const int phi = local_bit_reverse(i, SC_LN);
            const int byte_pos = info_idx >> 3;
            const int bit_pos = 7 - (info_idx & 7);
            // branchless: 데이터 종속 분기 없음
            flat[byte_pos] |= static_cast<uint8_t>(
                (sC(l, 0, phi) & 1u) << static_cast<unsigned>(bit_pos));
            info_idx++;
        }
    }
    const uint16_t calc =
        HTS_Polar_Codec::CRC16(flat, HTS_Polar_Codec::DATA_BYTES);
    const uint16_t rx =
        (static_cast<uint16_t>(flat[8]) << 8u) | static_cast<uint16_t>(flat[9]);
    if (calc == rx) {
        std::memcpy(out, flat,
                    static_cast<std::size_t>(HTS_Polar_Codec::DATA_BYTES));
        return true;
    }
    return false;
}
// 2L 후보 중 최선 L개 선택 (삽입 정렬, L=4 고정이므로 O(1))
struct SclCandidate {
    int32_t pm;
    int src_path; // 원본 경로
    uint8_t bit;  // 결정 비트
};
static void scl_select_best(SclCandidate *cands, int n_cands, int *keep,
                            int n_keep) noexcept {
    // 간단 선택 정렬 (n_cands ≤ 8, O(1))
    for (int i = 0; i < n_cands; ++i) {
        for (int j = i + 1; j < n_cands; ++j) {
            if (cands[j].pm < cands[i].pm) {
                SclCandidate tmp = cands[i];
                cands[i] = cands[j];
                cands[j] = tmp;
            }
        }
    }
    // 상위 n_keep 인덱스 반환
    for (int i = 0; i < n_keep; ++i) {
        keep[i] = i;
    }
}
} // anonymous namespace
bool HTS_Polar_Codec::Decode_SCL(const int16_t *llr, uint8_t *out,
                                 int *out_len) noexcept {
    if (llr == nullptr || out == nullptr || out_len == nullptr)
        return false;
    *out_len = 0;
    // 초기화: 경로 1개
    for (int j = 0; j < N; ++j) {
        sP(0, SC_LN, j) = llr[j];
    }
    std::memset(scl_C[0], 0, sizeof(scl_C[0]));
    scl_PM[0] = 0;
    int n_paths = 1;
    for (int phi = 0; phi < N; ++phi) {
        const int orig_idx = bit_reverse_(phi, LOG_N);
        const bool is_info = Is_Info_Bit(orig_idx);
        // Step 1: 각 경로 LLR 전파
        for (int l = 0; l < n_paths; ++l) {
            scl_propagate_llr(l, phi);
        }
        if (!is_info) {
            // ── Frozen 비트: 전 경로 bit=0, PM 갱신 (branchless) ──
            for (int l = 0; l < n_paths; ++l) {
                const int32_t v = static_cast<int32_t>(sP(l, 0, phi));
                const int32_t neg = v >> 31; // -1 if v<0, 0 if v>=0
                const int32_t abs_v = (v ^ neg) - neg;
                scl_PM[l] += abs_v & neg; // penalty if v<0
                sC(l, 0, phi) = 0u;
            }
        } else if (n_paths < SCL_L) {
            // ── 경로 확장 단계 (아직 L 미달, branchless PM) ──
            for (int l = n_paths - 1; l >= 0; --l) {
                const int32_t v = static_cast<int32_t>(sP(l, 0, phi));
                const int32_t neg = v >> 31;
                const int32_t abs_v = (v ^ neg) - neg;
                copy_path(2 * l, l);
                scl_PM[2 * l] =
                    scl_PM[l] + (abs_v & neg); // bit=0: penalty if v<0
                sC(2 * l, 0, phi) = 0u;
                copy_path(2 * l + 1, l);
                scl_PM[2 * l + 1] =
                    scl_PM[l] + (abs_v & ~neg); // bit=1: penalty if v>=0
                sC(2 * l + 1, 0, phi) = 1u;
            }
            n_paths *= 2;
            if (n_paths > SCL_L)
                n_paths = SCL_L;
        } else {
            // ── 분기+가지치기 (n_paths == SCL_L, branchless PM) ──
            SclCandidate cands[SCL_2L];
            for (int l = 0; l < SCL_L; ++l) {
                const int32_t v = static_cast<int32_t>(sP(l, 0, phi));
                const int32_t neg = v >> 31;
                const int32_t abs_v = (v ^ neg) - neg;
                cands[2 * l].pm = scl_PM[l] + (abs_v & neg);
                cands[2 * l].src_path = l;
                cands[2 * l].bit = 0u;
                cands[2 * l + 1].pm = scl_PM[l] + (abs_v & ~neg);
                cands[2 * l + 1].src_path = l;
                cands[2 * l + 1].bit = 1u;
            }
            int keep[SCL_L];
            scl_select_best(cands, SCL_2L, keep, SCL_L);
            // 임시 버퍼에 생존 경로 복사
            // (src가 자기 자신을 덮어쓰는 것 방지)
            alignas(16) static int16_t tmp_P[SCL_L][(SC_LN + 1) * SC_N];
            alignas(16) static uint8_t tmp_C[SCL_L][(SC_LN + 1) * SC_N];
            int32_t tmp_PM[SCL_L];
            for (int i = 0; i < SCL_L; ++i) {
                const int ci = keep[i];
                const int src = cands[ci].src_path;
                std::memcpy(tmp_P[i], scl_P[src], sizeof(scl_P[0]));
                std::memcpy(tmp_C[i], scl_C[src], sizeof(scl_C[0]));
                tmp_PM[i] = cands[ci].pm;
                tmp_C[i][0 * SC_N + phi] = cands[ci].bit;
            }
            // 생존 경로를 주 버퍼로 복원
            std::memcpy(scl_P, tmp_P, sizeof(scl_P));
            std::memcpy(scl_C, tmp_C, sizeof(scl_C));
            for (int i = 0; i < SCL_L; ++i) {
                scl_PM[i] = tmp_PM[i];
            }
        }
        // Step 3: 부분합 갱신
        for (int l = 0; l < n_paths; ++l) {
            scl_update_c(l, phi);
        }
    }
    // Step 4: CRC-Aided 선택 — PM 최소인 CRC 통과 경로
    // PM 순 정렬
    int order[SCL_L];
    for (int i = 0; i < n_paths; ++i)
        order[i] = i;
    for (int i = 0; i < n_paths; ++i) {
        for (int j = i + 1; j < n_paths; ++j) {
            if (scl_PM[order[j]] < scl_PM[order[i]]) {
                int tmp = order[i];
                order[i] = order[j];
                order[j] = tmp;
            }
        }
    }
    for (int i = 0; i < n_paths; ++i) {
        uint8_t candidate[8] = {};
        if (scl_extract_and_crc(order[i], candidate)) {
            std::memcpy(out, candidate, static_cast<std::size_t>(DATA_BYTES));
            *out_len = DATA_BYTES;
            return true;
        }
    }
    return false;
}
} // namespace ProtectedEngine
