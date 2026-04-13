"""
Short LDPC kernel for HTS-HFC v2 architecture comparison
=========================================================

Gallager (3,6)-regular LDPC of length N_INNER = 160, dimension K = 80.
  * Random H (seeded, deterministic); rejection-sample to avoid parallel
    edges and enforce exactly column-weight 3 & row-weight 6.
  * Systematic encoder: Gauss-Jordan on GF(2) to transform H -> [A | I_M]
    with column permutation P, then for a payload u:
        parity = A^T @ u   (GF(2))
        codeword_sys = [u ; parity]         # length N in systematic order
        x = P @ codeword_sys                # un-permute so H x = 0
  * Decoder: flooding BP min-sum with scaling factor 0.75 (typical for
    short regular LDPC), CRC-aware early stop — caller checks CRC on the
    recovered payload.

Kept intentionally small and self-contained; only numpy is used.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

import numpy as np


# ---------------------------------------------------------------------------
#  Dimensions
# ---------------------------------------------------------------------------

N_INNER = 160      # codeword length
K_INNER = 80       # payload = 64 info + 16 CRC
M_INNER = N_INNER - K_INNER    # 80 parity checks
COL_W = 3
ROW_W = 6
assert N_INNER * COL_W == M_INNER * ROW_W


# ---------------------------------------------------------------------------
#  Code container
# ---------------------------------------------------------------------------


@dataclass
class LDPCCode:
    H: np.ndarray              # (M, N) uint8
    # Systematic generator info, reordered so that:
    #   codeword_sys[:K]  = payload
    #   codeword_sys[K:]  = parity = (A.T @ payload) mod 2
    #   codeword          = codeword_sys[inv_perm]     (H @ codeword = 0)
    A: np.ndarray              # (M, K) uint8  (parity generator)
    perm: np.ndarray           # (N,)  int    column permutation applied to H
    inv_perm: np.ndarray       # (N,)  int    inverse of `perm`
    # Adjacency lists for fast BP.
    var_to_checks: List[np.ndarray]   # length N, each entry: check indices
    check_to_vars: List[np.ndarray]   # length M, each entry: var indices


# ---------------------------------------------------------------------------
#  H construction
# ---------------------------------------------------------------------------


def _build_H(seed: int) -> np.ndarray:
    """
    Construct a random (3,6)-regular parity-check matrix using the
    Gallager-stripe method with small permutations per stripe.

    M=80, N=160, col-weight 3 means 3 stripes each of shape (M/3, N)?
    M=80 is not a multiple of 3. Instead use the "edge-list swap" method:
      1. Build a candidate edge list with each variable repeated 3 times
         and each check repeated 6 times (multiset).
      2. Shuffle and pair.
      3. Detect parallel edges (same (v,c)) and swap with random other
         edges until clean.
    """
    rng = np.random.default_rng(seed)
    var_edges = np.repeat(np.arange(N_INNER), COL_W)       # 480 entries
    chk_edges = np.repeat(np.arange(M_INNER), ROW_W)       # 480 entries
    rng.shuffle(var_edges)
    rng.shuffle(chk_edges)

    H = np.zeros((M_INNER, N_INNER), dtype=np.uint8)

    def has_parallel() -> Tuple[int, int, int, int]:
        """Return indices of any parallel-edge pair or (-1,...)"""
        seen = {}
        for i, (v, c) in enumerate(zip(var_edges, chk_edges)):
            key = (int(v), int(c))
            if key in seen:
                return seen[key], i, int(v), int(c)
            seen[key] = i
        return -1, -1, -1, -1

    # Iteratively repair parallel edges by swapping.
    for _ in range(10000):
        i, j, v, c = has_parallel()
        if i < 0:
            break
        # Pick a random other edge k and swap check endpoints (j <-> k)
        k = int(rng.integers(0, len(chk_edges)))
        if k == i or k == j:
            continue
        chk_edges[j], chk_edges[k] = chk_edges[k], chk_edges[j]
    else:
        raise RuntimeError("failed to remove all parallel edges")

    for v, c in zip(var_edges, chk_edges):
        H[c, v] = 1

    # Integrity: column weight 3 and row weight 6 everywhere.
    cw = H.sum(axis=0)
    rw = H.sum(axis=1)
    assert (cw == COL_W).all(), f"col-weight deviation: {np.unique(cw)}"
    assert (rw == ROW_W).all(), f"row-weight deviation: {np.unique(rw)}"
    return H


# ---------------------------------------------------------------------------
#  Systematic form via Gauss-Jordan on GF(2)
# ---------------------------------------------------------------------------


def _gf2_systematic(H: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Transform H by row-reduction + column permutation into [A | I_M]:
      H_sys = (row_ops @ H)[:, perm] = [A | I_M]
    Return (H_sys, A, perm). `A` has shape (M, K).

    Row operations don't change the null space; column permutation reorders
    variables, so any codeword_sys satisfying H_sys x = 0 corresponds to an
    original codeword  x_original = permuted_back(x_sys).
    """
    M, N = H.shape
    H = H.copy().astype(np.uint8)
    perm = np.arange(N, dtype=np.int64)

    col = N - 1      # place identity in the LAST M columns
    for row in range(M - 1, -1, -1):
        # Want H[row, col] == 1; search in columns <= col for a usable col.
        pivot_col = -1
        # first, among already-chosen "identity" columns (col+1..N-1) rows > row
        # must have zero H[row, c] (already handled by clearing below).
        # find a pivot column in 0..col that has H[row, cand] == 1
        for cand in range(col, -1, -1):
            if H[row, cand] == 1:
                pivot_col = cand
                break
        if pivot_col < 0:
            raise RuntimeError(
                f"H is rank-deficient at row {row} (col<= {col})")
        # swap pivot_col <-> col
        if pivot_col != col:
            H[:, [pivot_col, col]] = H[:, [col, pivot_col]]
            perm[[pivot_col, col]] = perm[[col, pivot_col]]
        # eliminate 1s in column `col` from all OTHER rows
        for r in range(M):
            if r != row and H[r, col] == 1:
                H[r] ^= H[row]
        col -= 1

    # H should now be [A | I_M]
    K = N - M
    A = H[:, :K].copy()
    # sanity
    assert np.array_equal(H[:, K:], np.eye(M, dtype=np.uint8)), \
        "systematic form failed"
    return H, A, perm


# ---------------------------------------------------------------------------
#  Public: build + encode + decode
# ---------------------------------------------------------------------------


def build_ldpc_code(seed: int = 0xDEADBEEF) -> LDPCCode:
    # Retry with seed nudges if H is rank-deficient on the chosen column set
    # (very rare but possible).
    for nudge in range(32):
        try:
            H = _build_H(seed + nudge)
            H_sys, A, perm = _gf2_systematic(H)
            break
        except RuntimeError:
            continue
    else:
        raise RuntimeError("failed to build full-rank LDPC")

    inv_perm = np.argsort(perm)

    # Adjacency lists from the ORIGINAL H (for BP on the original variable
    # ordering, which is what the channel delivers).
    var_to_checks = [np.where(H[:, v] == 1)[0] for v in range(N_INNER)]
    check_to_vars = [np.where(H[m, :] == 1)[0] for m in range(M_INNER)]

    # Store original H (pre-permutation) for BP.
    return LDPCCode(H=H, A=A, perm=perm, inv_perm=inv_perm,
                    var_to_checks=var_to_checks,
                    check_to_vars=check_to_vars)


def ldpc_encode(payload: np.ndarray, code: LDPCCode) -> np.ndarray:
    """
    Systematic encode:
      codeword_sys[:K] = payload
      codeword_sys[K:] = (A @ payload) mod 2
      codeword[inv_perm[i]] = codeword_sys[i]  (equivalently apply inv_perm)
    H_sys was built from H by column permutation `perm`, i.e.
      H[:, perm] = H_sys.  So H @ x = 0 iff H_sys @ x[perm] = 0.
    Thus original codeword x satisfies  x[perm] = codeword_sys,
    i.e.  x = codeword_sys[inv_perm].
    """
    assert len(payload) == K_INNER
    parity = (code.A @ payload) % 2
    codeword_sys = np.concatenate([payload, parity]).astype(np.uint8)
    codeword = codeword_sys[code.inv_perm]
    # sanity in debug builds
    # assert ((code.H @ codeword) % 2 == 0).all()
    return codeword


def ldpc_decode_bp(llr_in: np.ndarray, code: LDPCCode,
                   max_iters: int = 25,
                   scale: float = 0.75) -> np.ndarray:
    """
    Flooding min-sum BP decoder (scaled).

      m_v->c  : variable-to-check messages    (N x max_dv)
      m_c->v  : check-to-variable messages    (M x max_dc)

    Returns the K-bit systematic payload (first K positions in permuted order).
    """
    N = N_INNER
    M = M_INNER
    H = code.H
    v2c_idx = code.var_to_checks    # list of length N
    c2v_idx = code.check_to_vars    # list of length M

    # Message storage: since graph is regular (3, 6), we can use dense arrays.
    msg_v2c = np.zeros((N, COL_W), dtype=np.float64)
    msg_c2v = np.zeros((M, ROW_W), dtype=np.float64)

    # For each variable v, and each of its checks: what slot in that check's
    # c2v array corresponds to v?  Same for the reverse.
    # Precompute maps so we can route messages cleanly.
    v_slot_in_check = np.zeros((N, COL_W), dtype=np.int32)
    c_slot_in_var = np.zeros((M, ROW_W), dtype=np.int32)
    for v in range(N):
        for j, c in enumerate(v2c_idx[v]):
            # find v's position in c2v_idx[c]
            pos = int(np.where(c2v_idx[c] == v)[0][0])
            v_slot_in_check[v, j] = pos
    for c in range(M):
        for k, v in enumerate(c2v_idx[c]):
            pos = int(np.where(v2c_idx[v] == c)[0][0])
            c_slot_in_var[c, k] = pos

    # Initialize v->c messages = channel LLR
    for v in range(N):
        msg_v2c[v, :] = llr_in[v]

    hard = np.zeros(N, dtype=np.uint8)

    for it in range(max_iters):
        # Check update: min-sum on each check's incoming messages.
        # Gather incoming v->c messages into m_c[M, dc] ordering by c2v_idx.
        m_in = np.zeros((M, ROW_W), dtype=np.float64)
        for c in range(M):
            for k, v in enumerate(c2v_idx[c]):
                m_in[c, k] = msg_v2c[v, c_slot_in_var[c, k]]
        # For each check, the outgoing to v_k excludes input k.
        # Sign: product of sign(m_in[:, except k]); magnitude: min.
        signs = np.where(m_in < 0, -1.0, 1.0)
        abs_m = np.abs(m_in)

        # min, 2nd-min trick for "min excluding one"
        min1 = np.min(abs_m, axis=1, keepdims=True)            # (M, 1)
        # "2nd min" = min over abs_m masked at min1-position; we do it by
        # argmin.
        amin = np.argmin(abs_m, axis=1)                        # (M,)
        tmp = abs_m.copy()
        tmp[np.arange(M), amin] = np.inf
        min2 = np.min(tmp, axis=1, keepdims=True)              # (M, 1)

        # total sign per row = product of signs
        sign_prod = np.prod(signs, axis=1, keepdims=True)      # (M, 1)

        # outgoing magnitude for slot k: min2 if k == amin else min1
        out_mag = np.tile(min1, (1, ROW_W))
        out_mag[np.arange(M), amin] = min2.ravel()

        # outgoing sign excluding slot k: sign_prod / signs[:, k]
        out_sign = sign_prod / signs                           # (M, dc)

        msg_c2v = scale * out_sign * out_mag

        # Variable update: each v_j sums channel LLR + all c->v except the one
        # it's sending back.
        total_v = np.full(N, 0.0)
        # sum of incoming c->v per variable
        sum_in = np.zeros(N, dtype=np.float64)
        for v in range(N):
            s = llr_in[v]
            for j, c in enumerate(v2c_idx[v]):
                s += msg_c2v[c, v_slot_in_check[v, j]]
            sum_in[v] = s

        # Hard decision on sum_in
        hard = (sum_in < 0.0).astype(np.uint8)

        # Early stop when parity is satisfied.
        if ((H @ hard) % 2 == 0).all():
            break

        # Outgoing v->c = sum_in - specific c->v message
        for v in range(N):
            for j, c in enumerate(v2c_idx[v]):
                msg_v2c[v, j] = sum_in[v] - msg_c2v[c, v_slot_in_check[v, j]]

    # Return systematic payload: in permuted (systematic) order, payload is
    # codeword_sys[:K] = hard[perm][:K].
    hard_sys = hard[code.perm]
    return hard_sys[:K_INNER]


# ---------------------------------------------------------------------------
#  Self-test
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    code = build_ldpc_code(seed=0xDEADBEEF)
    print(f"H shape: {code.H.shape}  col-w/row-w = "
          f"{int(code.H.sum(axis=0)[0])}/{int(code.H.sum(axis=1)[0])}")

    rng = np.random.default_rng(0)
    # Noiseless: ldpc_encode -> high-LLR -> decode should recover.
    fails = 0
    for _ in range(64):
        pay = rng.integers(0, 2, size=K_INNER, dtype=np.uint8)
        x = ldpc_encode(pay, code)
        assert ((code.H @ x) % 2 == 0).all(), "codeword fails parity"
        llr = np.where(x == 0, 20.0, -20.0)
        pay_hat = ldpc_decode_bp(llr, code, max_iters=5)
        if not np.array_equal(pay, pay_hat):
            fails += 1
    print(f"noiseless round-trip: {64 - fails}/64 PASS")
