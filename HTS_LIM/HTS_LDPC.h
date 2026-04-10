// =============================================================================
// HTS_LDPC.h — QC-LDPC(128, 64) R=1/2 인코더/디코더
//
// [코드 규격]
//  K=64   N=128   M=64   R=0.5
//  Z=16   KB=4    MB=4   NB=8
//
// [방향 C 패킷 설계]
//  기존 172심볼 → 32심볼 페이로드 + 149심볼 프리앰블
//  프리앰블 한계: 18.1 + 21.7 = 39.8dB
//  페이로드 1R:   18.1 + 7(LDPC) = 25.1dB
//
// [베이스 그래프 — 4×8, 23 엣지]
//  INFO 4열: 전행 연결 (DEG=4)
//  PARITY 4열: staircase (쌍대각선)
//  시프트: prime[c]={1,3,5,7}, ofs[c]={0,2,4,6}
//
//  4-사이클 배제 증명:
//   (prime[c1]-prime[c2])×(r1-r2) mod 16
//   prime 차={±2,±4,±6}, r 차={±1,±2,±3}
//   곱 mod 16 ∈ {2,4,6,8,12} → 0 없음 → girth≥6 QED
//
// [메모리 ~1.5 KB]
//  베이스 46B + 채널 128B + VN 128B
//  + C2V 368B + V2C 368B + 엣지VN 736B
//  + CN시작 130B + VN누적 256B = 2,160B
//
#pragma once
#include <cstdint>
#include <cstring>
namespace ProtectedEngine {
class HTS_LDPC {
  public:
    // ═══════════════════════════════════
    //  코드 파라미터
    // ═══════════════════════════════════
    static constexpr int K = 64;
    static constexpr int N = 128;
    static constexpr int M = N - K; // 64
    static constexpr int Z = 16;
    static constexpr int KB = K / Z; // 4
    static constexpr int MB = M / Z; // 4
    static constexpr int NB = N / Z; // 8
    static constexpr int MAX_ITER = 20;
    static constexpr int INFO_DEG = 4;                           // 전행 연결
    static constexpr int PAR_EDGES = 1 + (MB - 1) * 2;           // 7
    static constexpr int BASE_EDGES = KB * INFO_DEG + PAR_EDGES; // 23
    static constexpr int REAL_EDGES = BASE_EDGES * Z;            // 368
    static_assert(K == KB * Z, "K = KB*Z");
    static_assert(M == MB * Z, "M = MB*Z");
    static_assert(N == NB * Z, "N = NB*Z");
    static_assert(NB == KB + MB, "NB = KB+MB");
    struct Edge {
        uint8_t row;
        uint8_t shift;
    };
    // ═══════════════════════════════════
    //  베이스 그래프 (23 엣지, 46 바이트)
    //
    //  시프트 = (prime[c]×row + ofs[c]) % 16
    //   c=0: (1r+0)  → {0,1,2,3}
    //   c=1: (3r+2)  → {2,5,8,11}
    //   c=2: (5r+4)  → {4,9,14,3}
    //   c=3: (7r+6)  → {6,13,4,11}
    // ═══════════════════════════════════
    static constexpr Edge g_bg[BASE_EDGES] = {
        // ── info col 0: rows 0,1,2,3 ──
        {0, 0},
        {1, 1},
        {2, 2},
        {3, 3},
        // ── info col 1: rows 0,1,2,3 ──
        {0, 2},
        {1, 5},
        {2, 8},
        {3, 11},
        // ── info col 2: rows 0,1,2,3 ──
        {0, 4},
        {1, 9},
        {2, 14},
        {3, 3},
        // ── info col 3: rows 0,1,2,3 ──
        {0, 6},
        {1, 13},
        {2, 4},
        {3, 11},
        // ── parity col 0 (abs 4): row 0 ──
        {0, 0},
        // ── parity col 1 (abs 5): rows 0,1 ──
        {0, 0},
        {1, 0},
        // ── parity col 2 (abs 6): rows 1,2 ──
        {1, 0},
        {2, 0},
        // ── parity col 3 (abs 7): rows 2,3 ──
        {2, 0},
        {3, 0},
    };
    // ═══════════════════════════════════
    //  인코더: systematic + staircase 하방역대입
    //
    //  Row 0: p0⊕p1 = s0
    //  Row 1: p1⊕p2 = s1
    //  Row 2: p2⊕p3 = s2
    //  Row 3: p3     = s3
    //
    //  해: p3=s3, p_r=s_r⊕p_{r+1}
    // ═══════════════════════════════════
    static void Encode(const uint8_t *info, uint8_t *cw) noexcept {
        if (!info || !cw)
            return;
        // systematic
        for (int i = 0; i < K; ++i)
            cw[i] = info[i] & 1u;
        // syndrome 계산 (정보 기여)
        uint8_t syn[M];
        std::memset(syn, 0, static_cast<std::size_t>(M));
        int off = 0;
        for (int bc = 0; bc < KB; ++bc) {
            for (int e = 0; e < INFO_DEG; ++e) {
                const int br = g_bg[off].row;
                const int sh = g_bg[off].shift;
                ++off;
                for (int j = 0; j < Z; ++j) {
                    const int ci = bc * Z + j;
                    const int ri = br * Z + ((j + sh) & (Z - 1));
                    syn[ri] ^= cw[ci];
                }
            }
        }
        // staircase 하방 역대입
        for (int j = 0; j < Z; ++j)
            cw[K + (MB - 1) * Z + j] = syn[(MB - 1) * Z + j];
        for (int r = MB - 2; r >= 0; --r) {
            for (int j = 0; j < Z; ++j)
                cw[K + r * Z + j] = syn[r * Z + j] ^ cw[K + (r + 1) * Z + j];
        }
    }
    // ═══════════════════════════════════
    //  디코더: NMS int8, TPE branchless
    //
    //  ch[N]: 채널 LLR (양수=bit0)
    //  dec[K]: 디코딩 결과
    //  반환: true=수렴 (신드롬=0)
    // ═══════════════════════════════════
    static bool Decode(const int8_t *ch, uint8_t *dec,
                       int max_iter = MAX_ITER) noexcept {
        if (!ch || !dec)
            return false;
        if (!s_built)
            build_();
        for (int i = 0; i < N; ++i) {
            s_ch[i] = ch[i];
            s_vn[i] = ch[i];
        }
        std::memset(s_c2v, 0, static_cast<std::size_t>(s_ne));
        for (int it = 0; it < max_iter; ++it) {
            // VN→CN
            for (int e = 0; e < s_ne; ++e) {
                const int16_t d = static_cast<int16_t>(s_vn[s_evn[e]]) -
                                  static_cast<int16_t>(s_c2v[e]);
                s_v2c[e] = sat8_(d);
            }
            // CN update
            cn_update_();
            // VN update (int16 누적)
            for (int i = 0; i < N; ++i)
                s_acc[i] = static_cast<int16_t>(s_ch[i]);
            for (int e = 0; e < s_ne; ++e)
                s_acc[s_evn[e]] += static_cast<int16_t>(s_c2v[e]);
            for (int i = 0; i < N; ++i)
                s_vn[i] = sat8_(s_acc[i]);
            // 신드롬 검사
            if (syndrome_ok_()) {
                hard_(dec);
                return true;
            }
        }
        hard_(dec);
        return false;
    }
    static void Reset_Tables() noexcept { s_built = false; }

  private:
    // ── int16 → int8 포화 (TPE branchless) ──
    //  over  = 0xFFFFFFFF if v > 127
    //  under = 0xFFFFFFFF if v < -127
    static int8_t sat8_(int16_t v) noexcept {
        const int32_t v32 = static_cast<int32_t>(v);
        const int32_t over = (127 - v32) >> 31;
        const int32_t under = (v32 + 127) >> 31;
        return static_cast<int8_t>((over & 127) | (under & (-127)) |
                                   (v32 & ~over & ~under));
    }
    static void hard_(uint8_t *d) noexcept {
        for (int i = 0; i < K; ++i)
            d[i] = (static_cast<uint8_t>(s_vn[i]) >> 7u) & 1u;
    }
    // 런타임 테이블
    static uint16_t s_evn[REAL_EDGES];
    static uint16_t s_cs[M + 1];
    static int s_ne;
    static bool s_built;
    // 워킹 버퍼
    static int8_t s_ch[N];
    static int8_t s_vn[N];
    static int8_t s_c2v[REAL_EDGES];
    static int8_t s_v2c[REAL_EDGES];
    static int16_t s_acc[N];
    // ═══════════════════════════════════
    //  엣지 테이블 구축
    // ═══════════════════════════════════
    static void build_() noexcept {
        struct P {
            uint16_t cn;
            uint16_t vn;
        };
        static P tmp[REAL_EDGES];
        int ne = 0;
        int off = 0;
        for (int bc = 0; bc < NB; ++bc) {
            int deg;
            if (bc < KB)
                deg = INFO_DEG;
            else if (bc == KB)
                deg = 1;
            else
                deg = 2;
            for (int e = 0; e < deg; ++e) {
                const int br = g_bg[off].row;
                const int sh = g_bg[off].shift;
                ++off;
                for (int j = 0; j < Z; ++j) {
                    tmp[ne].vn = static_cast<uint16_t>(bc * Z + j);
                    tmp[ne].cn =
                        static_cast<uint16_t>(br * Z + ((j + sh) & (Z - 1)));
                    ++ne;
                }
            }
        }
        s_ne = ne;
        // 삽입 정렬 (CN 순)
        for (int i = 1; i < ne; ++i) {
            P k = tmp[i];
            int j = i - 1;
            while (j >= 0 && tmp[j].cn > k.cn) {
                tmp[j + 1] = tmp[j];
                --j;
            }
            tmp[j + 1] = k;
        }
        for (int i = 0; i < ne; ++i)
            s_evn[i] = tmp[i].vn;
        std::memset(s_cs, 0, sizeof(s_cs));
        for (int i = 0; i < ne; ++i)
            s_cs[tmp[i].cn + 1]++;
        for (int i = 1; i <= M; ++i)
            s_cs[i] += s_cs[i - 1];
        s_built = true;
    }
    // ═══════════════════════════════════
    //  CN 업데이트: NMS int8 TPE
    // ═══════════════════════════════════
    static void cn_update_() noexcept {
        for (int cn = 0; cn < M; ++cn) {
            const int st = s_cs[cn];
            const int en = s_cs[cn + 1];
            if (en - st < 2)
                continue;
            uint8_t m1 = 127u, m2 = 127u;
            uint8_t sx = 0u;
            int m1p = st;
            for (int d = st; d < en; ++d) {
                const int8_t msg = s_v2c[d];
                // TPE abs
                const int8_t sa =
                    static_cast<int8_t>(static_cast<uint8_t>(msg) >> 7u);
                const uint8_t av = static_cast<uint8_t>((msg ^ sa) - sa);
                // sign XOR
                sx ^= static_cast<uint8_t>(msg);
                // branchless min
                const uint32_t lt =
                    (static_cast<uint32_t>(static_cast<int32_t>(av) -
                                           static_cast<int32_t>(m1)) >>
                     31u) &
                    1u;
                const uint8_t mk = static_cast<uint8_t>(0u - lt);
                const uint8_t nmk = static_cast<uint8_t>(~mk);
                const uint32_t mk32 = 0u - lt;
                const uint8_t m2a = (m1 & mk) | (m2 & nmk);
                const uint8_t nm1 = (av & mk) | (m1 & nmk);
                const uint32_t lt2 =
                    (static_cast<uint32_t>(static_cast<int32_t>(av) -
                                           static_cast<int32_t>(m2a)) >>
                     31u) &
                    1u;
                const uint8_t mk2 = static_cast<uint8_t>((0u - lt2) & nmk);
                m2 = (av & mk2) | (m2a & static_cast<uint8_t>(~mk2));
                m1 = nm1;
                m1p = static_cast<int>((static_cast<uint32_t>(d) & mk32) |
                                       (static_cast<uint32_t>(m1p) & ~mk32));
            }
            const uint8_t n1 = m1 - (m1 >> 2u);
            const uint8_t n2 = m2 - (m2 >> 2u);
            for (int d = st; d < en; ++d) {
                const uint32_t ism = 0u - static_cast<uint32_t>(d == m1p);
                const uint8_t mag =
                    static_cast<uint8_t>((n2 & static_cast<uint8_t>(ism)) |
                                         (n1 & static_cast<uint8_t>(~ism)));
                const uint8_t os =
                    (sx ^ static_cast<uint8_t>(s_v2c[d])) & 0x80u;
                const int8_t sm = static_cast<int8_t>(0u - (os >> 7u));
                s_c2v[d] =
                    static_cast<int8_t>((static_cast<int8_t>(mag) ^ sm) - sm);
            }
        }
    }
    // ═══════════════════════════════════
    //  신드롬 검사
    // ═══════════════════════════════════
    static bool syndrome_ok_() noexcept {
        for (int cn = 0; cn < M; ++cn) {
            uint8_t p = 0u;
            for (int d = s_cs[cn]; d < s_cs[cn + 1]; ++d)
                p ^= (static_cast<uint8_t>(s_vn[s_evn[d]]) >> 7u) & 1u;
            if (p != 0u)
                return false;
        }
        return true;
    }
};
// ═══════════════════════════════════
//  정적 멤버 (HTS_LDPC_IMPL 정의 필요)
// ═══════════════════════════════════
#if defined(HTS_LDPC_IMPL)
constexpr HTS_LDPC::Edge HTS_LDPC::g_bg[];
uint16_t HTS_LDPC::s_evn[HTS_LDPC::REAL_EDGES] = {};
uint16_t HTS_LDPC::s_cs[HTS_LDPC::M + 1] = {};
int HTS_LDPC::s_ne = 0;
bool HTS_LDPC::s_built = false;
int8_t HTS_LDPC::s_ch[HTS_LDPC::N] = {};
int8_t HTS_LDPC::s_vn[HTS_LDPC::N] = {};
int8_t HTS_LDPC::s_c2v[HTS_LDPC::REAL_EDGES] = {};
int8_t HTS_LDPC::s_v2c[HTS_LDPC::REAL_EDGES] = {};
int16_t HTS_LDPC::s_acc[HTS_LDPC::N] = {};
#endif
} // namespace ProtectedEngine
