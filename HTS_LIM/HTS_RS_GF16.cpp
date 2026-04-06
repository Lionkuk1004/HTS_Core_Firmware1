// =========================================================================
// HTS_RS_GF16.cpp — GF(2^4) RS(15,8), t≤3
// 디코드: 신드롬 + 오류 위치 브루트(전 조합 고정 순회) + GF 가우스(3열 고정·마스킹)
// 인코드: 생성다항식 g(x)=∏_{j=1}^{7}(x-α^j) 나눗셈(%) 없음·분기 최소화
//
// Cortex-M4F: UDIV 회피(m·idx≤98 → constexpr LUT), 스택 버퍼 종료 시 secureWipe
// =========================================================================
#include "HTS_RS_GF16.h"

#include "HTS_Secure_Memory.h"

#include <atomic>
#include <cstdint>
#include <cstring>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace ProtectedEngine {
namespace {

constexpr int RS_N = 15;
constexpr int RS_K = 8;
constexpr int NSYN = 7;
constexpr uint8_t GF_POLY = 0x13u;

uint8_t g_exp[32];
uint8_t g_log[16];
bool g_ok = false;

static inline void rs_compiler_fence() noexcept
{
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
}

static inline void rs_wipe_stack(void* p, std::size_t n) noexcept
{
    if (p == nullptr || n == 0u) {
        return;
    }
    SecureMemory::secureWipe(p, n);
    rs_compiler_fence();
    std::atomic_thread_fence(std::memory_order_release);
}

void gf_init() noexcept
{
    if (g_ok) {
        return;
    }
    uint8_t x = 1u;
    for (int i = 0; i < 15; ++i) {
        g_exp[static_cast<std::size_t>(i)] = x;
        g_log[static_cast<std::size_t>(x)] =
            static_cast<uint8_t>(i);
        const uint8_t y = static_cast<uint8_t>(x << 1);
        x = (y ^ ((static_cast<uint8_t>(x & 0x8u) >> 3u) * GF_POLY)) & 0xFu;
    }
    for (int i = 15; i < 30; ++i) {
        g_exp[static_cast<std::size_t>(i)] =
            g_exp[static_cast<std::size_t>(i - 15)];
    }
    g_log[0] = 0u;
    g_ok = true;
}

// m∈[1,7], idx∈[0,14] → (m*idx)%15 — UDIV 없음(컴파일 타임 테이블)
struct MiMod15Lut {
    uint8_t v[7][15];
    constexpr MiMod15Lut() noexcept : v{}
    {
        for (int m = 1; m <= 7; ++m) {
            for (int i = 0; i < 15; ++i) {
                v[static_cast<std::size_t>(m - 1)][static_cast<std::size_t>(i)] =
                    static_cast<uint8_t>((m * i) % 15);
            }
        }
    }
};
static constexpr MiMod15Lut k_mi_mod15{};

uint8_t gf_mul(uint8_t a, uint8_t b) noexcept
{
    const uint32_t ha = static_cast<uint32_t>(a != 0u);
    const uint32_t hb = static_cast<uint32_t>(b != 0u);
    const int ma = static_cast<int>(ha) * -1;
    const int mb = static_cast<int>(hb) * -1;
    const int la = static_cast<int>(g_log[static_cast<std::size_t>(a)]) & ma;
    const int lb = static_cast<int>(g_log[static_cast<std::size_t>(b)]) & mb;
    const uint8_t p =
        g_exp[static_cast<std::size_t>(la + lb)];
    const uint32_t hz = ha & hb;
    return static_cast<uint8_t>(
        p & static_cast<uint8_t>(0u - hz));
}

uint8_t gf_inv(uint8_t a) noexcept
{
    const uint32_t ha = static_cast<uint32_t>(a != 0u);
    const int m = static_cast<int>(ha) * -1;
    const int la = static_cast<int>(g_log[static_cast<std::size_t>(a)]) & m;
    const uint8_t raw =
        g_exp[static_cast<std::size_t>(15 - la)];
    return static_cast<uint8_t>(
        raw & static_cast<uint8_t>(0u - ha));
}

uint8_t gf_add(uint8_t a, uint8_t b) noexcept
{
    return static_cast<uint8_t>(a ^ b);
}

uint8_t gf_alpha_pow_mi(int m, int idx) noexcept
{
    const uint8_t e =
        k_mi_mod15.v[static_cast<std::size_t>(m - 1)][static_cast<std::size_t>(idx)];
    return g_exp[static_cast<std::size_t>(e)];
}

void syndromes(const uint8_t* r, uint8_t s[NSYN]) noexcept
{
    for (int m = 0; m < NSYN; ++m) {
        const int mi = m + 1;
        uint8_t sm = 0u;
        for (int i = 0; i < RS_N; ++i) {
            const uint8_t term =
                gf_mul(r[static_cast<std::size_t>(i)],
                    gf_alpha_pow_mi(mi, i));
            sm = gf_add(sm, term);
        }
        s[static_cast<std::size_t>(m)] = sm;
    }
}

uint32_t syn_all_zero_u32(const uint8_t* s) noexcept
{
    uint8_t o = 0u;
    for (int i = 0; i < NSYN; ++i) {
        o |= s[static_cast<std::size_t>(i)];
    }
    return static_cast<uint32_t>(o == 0u);
}

// n∈{1,2,3} — 계수열 0..n-1, 상수열(RHS) 인덱스 n. 항상 col=0..2 3회 반복(비활성은 마스크).
uint32_t gf_gauss_ct(uint8_t a[4][5], int n, uint8_t x[3]) noexcept
{
    uint32_t ok = 1u;
    const int rhs = n;

    for (int col = 0; col < 3; ++col) {
        const uint32_t act = static_cast<uint32_t>(col < n);
        const uint8_t actm = static_cast<uint8_t>(0u - act);

        int piv = col;
        uint8_t have = 0u;
        for (int r = col; r < 4; ++r) {
            const uint32_t row_in =
                static_cast<uint32_t>(r < n) & act;
            const uint8_t v =
                a[static_cast<std::size_t>(r)][static_cast<std::size_t>(col)];
            const uint32_t nz = static_cast<uint32_t>(v != 0u);
            const uint32_t take =
                row_in & nz & static_cast<uint32_t>(have == 0u);
            const int tmask = -static_cast<int>(take);
            piv = (piv & ~tmask) | (r & tmask);
            have = static_cast<uint8_t>(
                have | static_cast<uint8_t>(row_in & nz));
        }

        for (int c = col; c <= rhs; ++c) {
            const uint8_t ac =
                a[static_cast<std::size_t>(col)][static_cast<std::size_t>(c)];
            const uint8_t ap =
                a[static_cast<std::size_t>(piv)][static_cast<std::size_t>(c)];
            const uint32_t sw =
                act & static_cast<uint32_t>(piv != col);
            const uint8_t sm = static_cast<uint8_t>(0u - sw);
            a[static_cast<std::size_t>(col)][static_cast<std::size_t>(c)] =
                static_cast<uint8_t>((ac & ~sm) | (ap & sm));
            a[static_cast<std::size_t>(piv)][static_cast<std::size_t>(c)] =
                static_cast<uint8_t>((ap & ~sm) | (ac & sm));
        }

        const uint8_t diag =
            a[static_cast<std::size_t>(col)][static_cast<std::size_t>(col)];
        const uint32_t diag_nz = static_cast<uint32_t>(diag != 0u);
        ok &= (diag_nz | (1u - act));

        const uint8_t inv = gf_inv(diag);
        for (int c = col; c <= rhs; ++c) {
            const uint8_t oldv =
                a[static_cast<std::size_t>(col)][static_cast<std::size_t>(c)];
            const uint8_t scaled = gf_mul(oldv, inv);
            const uint8_t use_m =
                static_cast<uint8_t>(0u - (act & diag_nz));
            const uint8_t newv =
                static_cast<uint8_t>((oldv & ~use_m) | (scaled & use_m));
            const uint8_t outv =
                static_cast<uint8_t>((oldv & ~actm) | (newv & actm));
            a[static_cast<std::size_t>(col)][static_cast<std::size_t>(c)] = outv;  
        }

        for (int r = 0; r < 4; ++r) {
            const uint32_t row_act =
                static_cast<uint32_t>(r < n) & act;
            const uint32_t not_piv = static_cast<uint32_t>(r != col);
            const uint8_t rm = static_cast<uint8_t>(
                0u - (row_act & not_piv));
            const uint8_t f =
                a[static_cast<std::size_t>(r)][static_cast<std::size_t>(col)];
            for (int c = col; c <= rhs; ++c) {
                const uint8_t oldr =
                    a[static_cast<std::size_t>(r)][static_cast<std::size_t>(c)];
                const uint8_t term =
                    gf_mul(f, a[static_cast<std::size_t>(col)][static_cast<std::size_t>(c)]);
                const uint8_t nv = gf_add(oldr, term);
                const uint8_t merged =
                    static_cast<uint8_t>((oldr & ~rm) | (nv & rm));
                const uint8_t rowm = static_cast<uint8_t>(0u - (row_act & act));
                a[static_cast<std::size_t>(r)][static_cast<std::size_t>(c)] =
                    static_cast<uint8_t>((oldr & ~rowm) | (merged & rowm));
            }
        }
    }

    for (int i = 0; i < 3; ++i) {
        const uint32_t use = static_cast<uint32_t>(i < n);
        const uint8_t um = static_cast<uint8_t>(0u - use);
        const uint8_t xv =
            a[static_cast<std::size_t>(i)][static_cast<std::size_t>(rhs)];
        x[static_cast<std::size_t>(i)] =
            static_cast<uint8_t>((x[static_cast<std::size_t>(i)] & ~um) | (xv & um));
    }

    return ok;
}

// 항상 전체 GF 연산·가우스·신드롬 검증 수행, 성공 여부만 반환(조기 return 없음)
uint32_t try_err_pattern_full(uint8_t* trial, const int* pos, int e,
    const uint8_t* s) noexcept
{
    uint32_t ok_out = 0u;
    if (e < 1) {
        return 0u;
    }

    uint8_t mat[4][5] = {};
    for (int row = 0; row < e; ++row) {
        const int mi = row + 1;
        for (int c = 0; c < e; ++c) {
            const int pidx = pos[static_cast<std::size_t>(c)];
            mat[static_cast<std::size_t>(row)][static_cast<std::size_t>(c)] =
                gf_alpha_pow_mi(mi, pidx);
        }
        mat[static_cast<std::size_t>(row)][static_cast<std::size_t>(e)] =
            s[static_cast<std::size_t>(row)];
    }

    uint8_t y[3] = {};
    const uint32_t gok = gf_gauss_ct(mat, e, y);
    rs_wipe_stack(static_cast<void*>(mat), sizeof(mat));

    uint8_t t[RS_N];
    std::memcpy(t, trial, sizeof(t));
    for (int i = 0; i < e; ++i) {
        const int p = pos[static_cast<std::size_t>(i)];
        t[static_cast<std::size_t>(p)] =
            gf_add(t[static_cast<std::size_t>(p)], y[static_cast<std::size_t>(i)]);
    }
    rs_wipe_stack(static_cast<void*>(y), sizeof(y));

    uint8_t s2[NSYN];
    syndromes(t, s2);
    const uint32_t syn_ok = syn_all_zero_u32(s2);
    rs_wipe_stack(static_cast<void*>(s2), sizeof(s2));

    ok_out = gok & syn_ok;
    const uint8_t m = static_cast<uint8_t>(0u - ok_out);
    for (int i = 0; i < RS_N; ++i) {
        trial[static_cast<std::size_t>(i)] =
            static_cast<uint8_t>(
                (trial[static_cast<std::size_t>(i)] & ~m)
                | (t[static_cast<std::size_t>(i)] & m));
    }
    rs_wipe_stack(static_cast<void*>(t), sizeof(t));

    return ok_out;
}

bool decode_bruteforce(uint8_t r[RS_N]) noexcept
{
    uint8_t s[NSYN];
    syndromes(r, s);

    uint32_t found = syn_all_zero_u32(s);
    uint8_t cand[RS_N];
    std::memcpy(cand, r, sizeof(cand));

    int pos[3];

    for (int p0 = 0; p0 < RS_N; ++p0) {
        pos[0] = p0;
        uint8_t trial[RS_N];
        std::memcpy(trial, r, sizeof(trial));
        const uint32_t ok =
            try_err_pattern_full(trial, pos, 1, s);
        const uint32_t take = ok & (1u ^ found);
        found |= ok;
        const uint8_t tm = static_cast<uint8_t>(0u - take);
        for (int i = 0; i < RS_N; ++i) {
            cand[static_cast<std::size_t>(i)] =
                static_cast<uint8_t>(
                    (cand[static_cast<std::size_t>(i)] & ~tm)
                    | (trial[static_cast<std::size_t>(i)] & tm));
        }
        rs_wipe_stack(static_cast<void*>(trial), sizeof(trial));
    }

    for (int p0 = 0; p0 < RS_N; ++p0) {
        for (int p1 = p0 + 1; p1 < RS_N; ++p1) {
            pos[0] = p0;
            pos[1] = p1;
            uint8_t trial[RS_N];
            std::memcpy(trial, r, sizeof(trial));
            const uint32_t ok =
                try_err_pattern_full(trial, pos, 2, s);
            const uint32_t take = ok & (1u ^ found);
            found |= ok;
            const uint8_t tm = static_cast<uint8_t>(0u - take);
            for (int i = 0; i < RS_N; ++i) {
                cand[static_cast<std::size_t>(i)] =
                    static_cast<uint8_t>(
                        (cand[static_cast<std::size_t>(i)] & ~tm)
                        | (trial[static_cast<std::size_t>(i)] & tm));
            }
            rs_wipe_stack(static_cast<void*>(trial), sizeof(trial));
        }
    }

    for (int p0 = 0; p0 < RS_N; ++p0) {
        for (int p1 = p0 + 1; p1 < RS_N; ++p1) {
            for (int p2 = p1 + 1; p2 < RS_N; ++p2) {
                pos[0] = p0;
                pos[1] = p1;
                pos[2] = p2;
                uint8_t trial[RS_N];
                std::memcpy(trial, r, sizeof(trial));
                const uint32_t ok =
                    try_err_pattern_full(trial, pos, 3, s);
                const uint32_t take = ok & (1u ^ found);
                found |= ok;
                const uint8_t tm = static_cast<uint8_t>(0u - take);
                for (int i = 0; i < RS_N; ++i) {
                    cand[static_cast<std::size_t>(i)] =
                        static_cast<uint8_t>(
                            (cand[static_cast<std::size_t>(i)] & ~tm)
                            | (trial[static_cast<std::size_t>(i)] & tm));
                }
                rs_wipe_stack(static_cast<void*>(trial), sizeof(trial));
            }
        }
    }

    std::memcpy(r, cand, sizeof(cand));
    const bool ret = found != 0u;
    rs_wipe_stack(static_cast<void*>(s), sizeof(s));
    rs_wipe_stack(static_cast<void*>(cand), sizeof(cand));
    return ret;
}

// sym[0..7]=데이터(x^0..x^7), sym[8..14]=패리티(x^8..x^{14}) 에 대해 r(α^m)=0, m=1..7
//  Σ_j p_j·α^{m(8+j)} = Σ_i d_i·α^{m·i}   (GF(2)에서 등호)
bool rs_encode_systematic_low(const uint8_t d8[8], uint8_t out15[15]) noexcept
{
    uint8_t aug[7][8];
    for (int m = 0; m < 7; ++m) {
        const int mi = m + 1;
        for (int j = 0; j < 7; ++j) {
            aug[static_cast<std::size_t>(m)][static_cast<std::size_t>(j)] =
                gf_alpha_pow_mi(mi, 8 + j);
        }
        uint8_t rhs = 0u;
        for (int i = 0; i < 8; ++i) {
            const uint8_t di =
                static_cast<uint8_t>(d8[static_cast<std::size_t>(i)] & 0xFu);
            rhs = gf_add(rhs,
                gf_mul(di, gf_alpha_pow_mi(mi, i)));
        }
        aug[static_cast<std::size_t>(m)][7] = rhs;
    }

    constexpr int n = 7;
    constexpr int rhs_col = 7;
    for (int col = 0; col < n; ++col) {
        int piv = col;
        while (piv < n
            && aug[static_cast<std::size_t>(piv)][static_cast<std::size_t>(col)]
                == 0u) {
            ++piv;
        }
        if (piv >= n) {
            rs_wipe_stack(static_cast<void*>(aug), sizeof(aug));
            return false;
        }
        if (piv != col) {
            for (int c = col; c <= rhs_col; ++c) {
                const uint8_t t =
                    aug[static_cast<std::size_t>(col)][static_cast<std::size_t>(c)];
                aug[static_cast<std::size_t>(col)][static_cast<std::size_t>(c)] =
                    aug[static_cast<std::size_t>(piv)][static_cast<std::size_t>(c)];
                aug[static_cast<std::size_t>(piv)][static_cast<std::size_t>(c)] = t;
            }
        }
        const uint8_t inv =
            gf_inv(aug[static_cast<std::size_t>(col)][static_cast<std::size_t>(col)]);
        for (int c = col; c <= rhs_col; ++c) {
            aug[static_cast<std::size_t>(col)][static_cast<std::size_t>(c)] =
                gf_mul(aug[static_cast<std::size_t>(col)][static_cast<std::size_t>(c)],
                    inv);
        }
        for (int r = 0; r < n; ++r) {
            if (r == col) {
                continue;
            }
            const uint8_t f =
                aug[static_cast<std::size_t>(r)][static_cast<std::size_t>(col)];
            if (f == 0u) {
                continue;
            }
            for (int c = col; c <= rhs_col; ++c) {
                aug[static_cast<std::size_t>(r)][static_cast<std::size_t>(c)] =
                    gf_add(aug[static_cast<std::size_t>(r)][static_cast<std::size_t>(c)],
                        gf_mul(f,
                            aug[static_cast<std::size_t>(col)][static_cast<std::size_t>(c)]));
            }
        }
    }

    for (int i = 0; i < 8; ++i) {
        out15[static_cast<std::size_t>(i)] =
            static_cast<uint8_t>(d8[static_cast<std::size_t>(i)] & 0xFu);
    }
    for (int j = 0; j < 7; ++j) {
        out15[static_cast<std::size_t>(8 + j)] =
            aug[static_cast<std::size_t>(j)][7];
    }
    rs_wipe_stack(static_cast<void*>(aug), sizeof(aug));
    return true;
}

} // namespace

void HTS_RS_GF16_Encode15_8(const uint8_t data8[8], uint8_t out15[15]) noexcept
{
    gf_init();
    if (!data8 || !out15) {
        return;
    }
    if (!rs_encode_systematic_low(data8, out15)) {
        for (int i = 0; i < RS_N; ++i) {
            out15[static_cast<std::size_t>(i)] = 0u;
        }
    }
}

bool HTS_RS_GF16_Decode15_8(uint8_t inout15[15]) noexcept
{
    gf_init();
    if (!inout15) {
        return false;
    }
    uint8_t r[RS_N];
    for (int i = 0; i < RS_N; ++i) {
        r[static_cast<std::size_t>(i)] =
            static_cast<uint8_t>(inout15[static_cast<std::size_t>(i)] & 0xFu);
    }
    const bool ok = decode_bruteforce(r);
    for (int i = 0; i < RS_N; ++i) {
        inout15[static_cast<std::size_t>(i)] = r[static_cast<std::size_t>(i)];
    }
    rs_wipe_stack(static_cast<void*>(r), sizeof(r));
    return ok;
}

} // namespace ProtectedEngine
