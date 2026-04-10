// =========================================================================
// HTS_RS_GF16.cpp — GF(2^4) RS(15,8), t≤3
// 디코드: 신드롬 + 오류 위치 브루트(전 조합 고정 순회) + GF 가우스(3열 고정·마스킹)
// 인코드: 생성다항식 g(x)=∏_{j=1}^{7}(x-α^j) 나눗셈(%) 없음·분기 최소화
//
// Cortex-M4F: UDIV 회피(m·idx≤98 → constexpr LUT), 스택 버퍼 종료 시 secureWipe
// 메모리: 대형 로컬 배열은 파일 범위 스크래치(alignas)로 이동 — Encode/Decode 동시
//         재진입 없음 전제(FEC IR 등 단일 컨텍스트). 병렬 호출 시 별도 동기화 필요.
// =========================================================================
#include "HTS_RS_GF16.h"

#include "HTS_Arm_Irq_Mask_Guard.h"
#include "HTS_Secure_Memory.h"

#include <atomic>
#include <cstdint>
#include <cstring>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace ProtectedEngine {
namespace {

constexpr std::size_t kGfExpLen = 32u;
constexpr std::size_t kGaussRows = 4u;
constexpr std::size_t kGaussCols = 5u;

static inline std::size_t rs_gf_exp_index_clamped(int idx) noexcept
{
    int v = idx;
    if (v < 0) {
        v = 0;
    }
    if (v > 31) {
        v = 31;
    }
    const std::size_t u =
        static_cast<std::size_t>(v) & (kGfExpLen - 1u);
#if defined(_MSC_VER)
    __assume(u < kGfExpLen);
#endif
    return u;
}

static inline std::size_t rs_gauss_row_idx(int r) noexcept
{
    int v = r;
    if (v < 0) {
        v = 0;
    }
    if (v > static_cast<int>(kGaussRows - 1u)) {
        v = static_cast<int>(kGaussRows - 1u);
    }
    const std::size_t u =
        static_cast<std::size_t>(v) & (kGaussRows - 1u);
#if defined(_MSC_VER)
    __assume(u < kGaussRows);
#endif
    return u;
}

static inline std::size_t rs_gauss_col_idx(int c) noexcept
{
    int v = c;
    if (v < 0) {
        v = 0;
    }
    if (v > static_cast<int>(kGaussCols - 1u)) {
        v = static_cast<int>(kGaussCols - 1u);
    }
    std::size_t u = static_cast<std::size_t>(v);
#if defined(_MSC_VER)
    __assume(u < kGaussCols);
#endif
    return u;
}

constexpr int RS_N = 15;
constexpr int RS_K = 8;
constexpr int NSYN = 7;
constexpr uint8_t GF_POLY = 0x13u;

alignas(16) static uint8_t g_exp[32];
alignas(16) static uint8_t g_log[16];
static std::atomic<bool> g_ok{ false };

// 브루트포스·가우스·인코드 스크래치 (스택 피크 완화)
alignas(64) static uint8_t g_rs_bf_trial[15];
alignas(64) static uint8_t g_rs_bf_cand[15];
alignas(16) static uint8_t g_rs_bf_s[7];
alignas(64) static uint8_t g_rs_try_mat[4][5];
alignas(16) static uint8_t g_rs_try_t[15];
alignas(8) static uint8_t g_rs_try_y[3];
alignas(16) static uint8_t g_rs_try_s2[7];
alignas(32) static uint8_t g_rs_enc_aug[7][8];
alignas(16) static uint8_t g_rs_dec_r[15];

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
    if (g_ok.load(std::memory_order_acquire)) {
        return;
    }
    Armv7m_Irq_Mask_Guard irq_guard;
    if (g_ok.load(std::memory_order_relaxed)) {
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
    g_ok.store(true, std::memory_order_release);
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
    const int sum_idx = la + lb;
    int sum_clamped = sum_idx;
    if (sum_clamped < 0) {
        sum_clamped = 0;
    }
    if (sum_clamped > 31) {
        sum_clamped = 31;
    }
    const uint8_t p =
        g_exp[rs_gf_exp_index_clamped(sum_clamped)];
    const uint32_t hz = ha & hb;
    return static_cast<uint8_t>(
        p & static_cast<uint8_t>(0u - hz));
}

uint8_t gf_inv(uint8_t a) noexcept
{
    const uint32_t ha = static_cast<uint32_t>(a != 0u);
    const int m = static_cast<int>(ha) * -1;
    const int la = static_cast<int>(g_log[static_cast<std::size_t>(a)]) & m;
    const int inv_idx = 15 - la;
    int inv_clamped = inv_idx;
    if (inv_clamped < 0) {
        inv_clamped = 0;
    }
    if (inv_clamped > 31) {
        inv_clamped = 31;
    }
    const uint8_t raw =
        g_exp[rs_gf_exp_index_clamped(inv_clamped)];
    return static_cast<uint8_t>(
        raw & static_cast<uint8_t>(0u - ha));
}

uint8_t gf_add(uint8_t a, uint8_t b) noexcept
{
    return static_cast<uint8_t>(a ^ b);
}

uint8_t gf_alpha_pow_mi(int m, int idx) noexcept
{
    int mc = m;
    if (mc < 1) {
        mc = 1;
    }
    if (mc > 7) {
        mc = 7;
    }
    int ic = idx;
    if (ic < 0) {
        ic = 0;
    }
    if (ic >= RS_N) {
        ic = RS_N - 1;
    }
    const uint8_t e =
        k_mi_mod15.v[static_cast<std::size_t>(mc - 1)][static_cast<std::size_t>(ic)];
    return g_exp[rs_gf_exp_index_clamped(static_cast<int>(e))];
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
            const std::size_t r_u = rs_gauss_row_idx(r);
            const std::size_t col_row_u = rs_gauss_row_idx(col);
            const std::size_t col_dim_u = rs_gauss_col_idx(col);
            const uint8_t f = a[r_u][col_dim_u];
            for (int c = col; c <= rhs; ++c) {
                const std::size_t c_u = rs_gauss_col_idx(c);
                const uint8_t oldr = a[r_u][c_u];
                const uint8_t term =
                    gf_mul(f, a[col_row_u][c_u]);
                const uint8_t nv = gf_add(oldr, term);
                const uint8_t merged =
                    static_cast<uint8_t>((oldr & ~rm) | (nv & rm));
                const uint8_t rowm = static_cast<uint8_t>(0u - (row_act & act));
                a[r_u][c_u] =
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

    std::memset(static_cast<void*>(g_rs_try_mat), 0, sizeof(g_rs_try_mat));
    for (int row = 0; row < e; ++row) {
        const int mi = row + 1;
        for (int c = 0; c < e; ++c) {
            const int pidx = pos[static_cast<std::size_t>(c)];
            g_rs_try_mat[static_cast<std::size_t>(row)][static_cast<std::size_t>(c)] =
                gf_alpha_pow_mi(mi, pidx);
        }
        g_rs_try_mat[static_cast<std::size_t>(row)][static_cast<std::size_t>(e)] =
            s[static_cast<std::size_t>(row)];
    }

    std::memset(static_cast<void*>(g_rs_try_y), 0, sizeof(g_rs_try_y));
    const uint32_t gok = gf_gauss_ct(g_rs_try_mat, e, g_rs_try_y);
    rs_wipe_stack(static_cast<void*>(g_rs_try_mat), sizeof(g_rs_try_mat));

    std::memcpy(static_cast<void*>(g_rs_try_t),
        static_cast<const void*>(trial), sizeof(g_rs_try_t));
    for (int i = 0; i < e; ++i) {
        const int p = pos[static_cast<std::size_t>(i)];
        g_rs_try_t[static_cast<std::size_t>(p)] =
            gf_add(g_rs_try_t[static_cast<std::size_t>(p)],
                g_rs_try_y[static_cast<std::size_t>(i)]);
    }
    rs_wipe_stack(static_cast<void*>(g_rs_try_y), sizeof(g_rs_try_y));

    syndromes(g_rs_try_t, g_rs_try_s2);
    const uint32_t syn_ok = syn_all_zero_u32(g_rs_try_s2);
    rs_wipe_stack(static_cast<void*>(g_rs_try_s2), sizeof(g_rs_try_s2));

    ok_out = gok & syn_ok;
    const uint8_t m = static_cast<uint8_t>(0u - ok_out);
    for (int i = 0; i < RS_N; ++i) {
        trial[static_cast<std::size_t>(i)] =
            static_cast<uint8_t>(
                (trial[static_cast<std::size_t>(i)] & ~m)
                | (g_rs_try_t[static_cast<std::size_t>(i)] & m));
    }
    rs_wipe_stack(static_cast<void*>(g_rs_try_t), sizeof(g_rs_try_t));

    return ok_out;
}

bool decode_bruteforce(uint8_t r[RS_N]) noexcept
{
    uint8_t* const s = g_rs_bf_s;
    syndromes(r, s);

    uint32_t found = syn_all_zero_u32(s);
    uint8_t* const cand = g_rs_bf_cand;
    std::memcpy(static_cast<void*>(cand),
        static_cast<const void*>(r), sizeof(g_rs_bf_cand));

    int pos[3];

    for (int p0 = 0; p0 < RS_N; ++p0) {
        pos[0] = p0;
        uint8_t* const trial = g_rs_bf_trial;
        std::memcpy(static_cast<void*>(trial),
            static_cast<const void*>(r), sizeof(g_rs_bf_trial));
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
        rs_wipe_stack(static_cast<void*>(trial), sizeof(g_rs_bf_trial));
    }

    for (int p0 = 0; p0 < RS_N; ++p0) {
        for (int p1 = p0 + 1; p1 < RS_N; ++p1) {
            pos[0] = p0;
            pos[1] = p1;
            uint8_t* const trial = g_rs_bf_trial;
            std::memcpy(static_cast<void*>(trial),
                static_cast<const void*>(r), sizeof(g_rs_bf_trial));
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
            rs_wipe_stack(static_cast<void*>(trial), sizeof(g_rs_bf_trial));
        }
    }

    for (int p0 = 0; p0 < RS_N; ++p0) {
        for (int p1 = p0 + 1; p1 < RS_N; ++p1) {
            for (int p2 = p1 + 1; p2 < RS_N; ++p2) {
                pos[0] = p0;
                pos[1] = p1;
                pos[2] = p2;
                uint8_t* const trial = g_rs_bf_trial;
                std::memcpy(static_cast<void*>(trial),
                    static_cast<const void*>(r), sizeof(g_rs_bf_trial));
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
                rs_wipe_stack(static_cast<void*>(trial), sizeof(g_rs_bf_trial));
            }
        }
    }

    std::memcpy(static_cast<void*>(r),
        static_cast<const void*>(cand), sizeof(g_rs_bf_cand));
    const bool ret = found != 0u;
    rs_wipe_stack(static_cast<void*>(s), sizeof(g_rs_bf_s));
    rs_wipe_stack(static_cast<void*>(cand), sizeof(g_rs_bf_cand));
    return ret;
}

// sym[0..7]=데이터(x^0..x^7), sym[8..14]=패리티(x^8..x^{14}) 에 대해 r(α^m)=0, m=1..7
//  Σ_j p_j·α^{m(8+j)} = Σ_i d_i·α^{m·i}   (GF(2)에서 등호)
bool rs_encode_systematic_low(const uint8_t d8[8], uint8_t out15[15]) noexcept
{
    uint8_t (* const aug)[8] = g_rs_enc_aug;
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
            rs_wipe_stack(static_cast<void*>(g_rs_enc_aug), sizeof(g_rs_enc_aug));
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
    rs_wipe_stack(static_cast<void*>(g_rs_enc_aug), sizeof(g_rs_enc_aug));
    return true;
}

} // namespace

void HTS_RS_GF16_Encode15_8(const uint8_t data8[8], uint8_t out15[15]) noexcept
{
    gf_init();
    if (!data8 || !out15) {
        return;
    }
    Armv7m_Irq_Mask_Guard irq_guard;
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
    Armv7m_Irq_Mask_Guard irq_guard;
    uint8_t* const r = g_rs_dec_r;
    for (int i = 0; i < RS_N; ++i) {
        r[static_cast<std::size_t>(i)] =
            static_cast<uint8_t>(inout15[static_cast<std::size_t>(i)] & 0xFu);
    }
    const bool ok = decode_bruteforce(r);
    for (int i = 0; i < RS_N; ++i) {
        inout15[static_cast<std::size_t>(i)] = r[static_cast<std::size_t>(i)];
    }
    rs_wipe_stack(static_cast<void*>(g_rs_dec_r), sizeof(g_rs_dec_r));
    return ok;
}

} // namespace ProtectedEngine
