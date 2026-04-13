"""
HTS-HFC v2 — Tensor FEC architecture
=====================================

Replaces the 1-D Polar(N=512) inner code with an 8 x 64 matrix of 8 INDEPENDENT
short Polar(N=64, K=10) codes, then ARX128-permutes the 512 matrix bits across
the transmission and rate-matches to 688 via permuted repetition.

Why this is novel / M4F-friendly:
  * Small row kernels (N=64, depth 6) are tiny -> 8 trees can be decoded in
    SIMD parallel on Cortex-M4F bit-sliced registers (conceptually one 32-bit
    register per depth layer, 8 trees per 8-lane u8 group).
  * Column axis (length 8) carries an ARX128 fractal permutation so a burst
    jam on N chips ends up distributed across all 8 row codes, preventing a
    single row from taking the full damage -- "holographic" error diffusion.
  * Outer CRC16 over full 80-bit payload still validates.

Rate accounting (matches hfc_v2_sim):
  payload K_PAYLOAD  = 80  (64 info + 16 CRC)
  inner bits         = 8 * 64 = 512
  coded bits         = 688   (permuted repetition 512 -> 688)
  overall rate R     = 64/688 = 0.0930

Decoder: vectorized SC on all 8 rows in one pass (axis-0 broadcast).
"""

from __future__ import annotations

import argparse
import math
import sys
import time
from dataclasses import dataclass

import numpy as np

import hfc_v2_sim as H


# ---------------------------------------------------------------------------
#  Tensor dimensions
# ---------------------------------------------------------------------------

ROWS = 8
N_ROW = 64
K_ROW = 10                # Plain mode: ROWS * K_ROW = K_PAYLOAD = 80
N_MATRIX = ROWS * N_ROW   # 512 inner bits

# Cross-parity (holographic) mode (only valid when ROWS == 8):
#   7 INFO rows of Polar(64, K_ROW_XP=12)  -> 7*12 = 84 info slots
#     (we pad payload to 84 with 4 zero bits)
#   1 PARITY row: column-wise XOR of the 7 info rows' x-sides (not a Polar
#   codeword); provides 64 extra parity equations (SPC on each column).
INFO_ROWS_XP = 7
K_ROW_XP = 12


def configure_tensor(n_row: int) -> None:
    """
    Reconfigure tensor dims so that ROWS*N_ROW = 512 and ROWS*K_ROW = 80.

    Valid N_ROW: 32 (16x5), 64 (8x10), 128 (4x20), 256 (2x40).
    """
    global ROWS, N_ROW, K_ROW, N_MATRIX
    if 512 % n_row != 0:
        raise ValueError(f"N_ROW={n_row} must divide 512")
    rows = 512 // n_row
    if H.K_PAYLOAD % rows != 0:
        raise ValueError(f"K_PAYLOAD={H.K_PAYLOAD} not divisible by ROWS={rows}")
    ROWS = rows
    N_ROW = n_row
    K_ROW = H.K_PAYLOAD // rows
    N_MATRIX = ROWS * N_ROW
    assert N_MATRIX == 512
    assert ROWS * K_ROW == H.K_PAYLOAD


# ---------------------------------------------------------------------------
#  Row Polar(64, 10) frozen-bit selection (Bhattacharyya at design SNR)
# ---------------------------------------------------------------------------

def build_row_frozen(design_ebn0_db: float, k_row: int = K_ROW):
    z = H.bhattacharyya_polar(N_ROW, design_ebn0_db)
    order = np.argsort(z)
    info_positions = np.sort(order[:k_row])
    frozen = np.ones(N_ROW, dtype=bool)
    frozen[info_positions] = False
    return frozen, info_positions


# ---------------------------------------------------------------------------
#  Polar encode/decode primitives (operates on an (ROWS, N_ROW) batch)
# ---------------------------------------------------------------------------

def polar_encode_batch(u_batch: np.ndarray) -> np.ndarray:
    """In-place Arikan butterfly over axis=1 for a (B, N) batch."""
    x = u_batch.copy().astype(np.uint8)
    n = x.shape[1]
    stride = 1
    while stride < n:
        for i in range(0, n, 2 * stride):
            x[:, i:i + stride] ^= x[:, i + stride:i + 2 * stride]
        stride *= 2
    return x


def _f(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """min-sum f operation: sign(a)*sign(b)*min(|a|,|b|)."""
    sa = np.where(a >= 0, 1.0, -1.0)
    sb = np.where(b >= 0, 1.0, -1.0)
    return sa * sb * np.minimum(np.abs(a), np.abs(b))


def _g(a: np.ndarray, b: np.ndarray, u: np.ndarray) -> np.ndarray:
    """g operation: b + (1 - 2u)*a."""
    return b + (1.0 - 2.0 * u.astype(np.float64)) * a


def sc_decode_batch(llr_batch: np.ndarray, frozen: np.ndarray,
                    u_out: np.ndarray, pos: int = 0) -> np.ndarray:
    """
    Recursive batched SC over axis=1.

      llr_batch : (B, N)  channel LLRs
      frozen    : (N_ROW,) frozen flags  (shared across batch)
      u_out     : (B, N_ROW) filled on leaf visits
      pos       : start column in u_out / frozen that this subtree owns

    Returns the partial sum array of shape (B, N) -- the x-side encoding of
    the decisions in this subtree.
    """
    B, N = llr_batch.shape
    if N == 1:
        if frozen[pos]:
            u_out[:, pos] = 0
            return np.zeros((B, 1), dtype=np.uint8)
        bits = (llr_batch[:, 0] < 0).astype(np.uint8)
        u_out[:, pos] = bits
        return bits[:, None]

    h = N // 2
    llr_l = _f(llr_batch[:, :h], llr_batch[:, h:])
    s_l = sc_decode_batch(llr_l, frozen, u_out, pos)
    llr_r = _g(llr_batch[:, :h], llr_batch[:, h:], s_l)
    s_r = sc_decode_batch(llr_r, frozen, u_out, pos + h)
    return np.concatenate([s_l ^ s_r, s_r], axis=1)


# ---------------------------------------------------------------------------
#  ARX128-keyed tensor permutation (512 bits) + permuted repetition (512->688)
# ---------------------------------------------------------------------------

def build_tensor_permutation(seed: int) -> np.ndarray:
    """Fisher-Yates shuffle of [0..511] using ARX128 -- fractal inter-row mix."""
    rng = H.ARX128(seed)
    perm = np.arange(N_MATRIX, dtype=np.int32)
    for i in range(N_MATRIX - 1, 0, -1):
        j = rng.step() % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return perm


def build_tensor_repetition(seed: int) -> np.ndarray:
    """
    Balanced permuted repetition from N_MATRIX=512 to N_CODED=688 using ARX128.

    Returns an int array of shape (N_CODED,) where out[i] = matrix index whose
    value is placed at coded position i.
    """
    rng = H.ARX128(seed ^ 0xA5A5A5A5)
    low = H.N_CODED // N_MATRIX            # = 1
    n_high = H.N_CODED - low * N_MATRIX     # = 176  (=688-512)

    order = np.arange(N_MATRIX, dtype=np.int32)
    for i in range(N_MATRIX - 1, 0, -1):
        j = rng.step() % (i + 1)
        order[i], order[j] = order[j], order[i]
    high_set = set(order[:n_high].tolist())

    pool = np.empty(H.N_CODED, dtype=np.int32)
    k = 0
    for idx in range(N_MATRIX):
        r = low + (1 if idx in high_set else 0)
        pool[k:k + r] = idx
        k += r
    for i in range(H.N_CODED - 1, 0, -1):
        j = rng.step() % (i + 1)
        pool[i], pool[j] = pool[j], pool[i]
    return pool


# ---------------------------------------------------------------------------
#  Codec
# ---------------------------------------------------------------------------

@dataclass
class TensorCodec:
    frozen: np.ndarray              # (N_ROW,) bool  — row-level frozen
    info_positions: np.ndarray      # (K,) int       — row-level info slots
    tensor_perm: np.ndarray         # (N_MATRIX,) int
    tensor_inv_perm: np.ndarray     # (N_MATRIX,) int
    rep_map: np.ndarray             # (N_CODED,) int
    mode: str = "plain"             # "plain" (8x10) or "xparity" (7x12+SPC)
    spc_iters: int = 0              # SPC-BP iters for xparity mode

    @classmethod
    def build(cls, seed: int = 0xDEADBEEF,
              design_ebn0_db: float = 2.5,
              mode: str = "plain",
              spc_iters: int = 1) -> "TensorCodec":
        if mode == "plain":
            k_row = K_ROW
        elif mode == "xparity":
            k_row = K_ROW_XP
        else:
            raise ValueError(f"unknown mode: {mode}")
        frozen, info_positions = build_row_frozen(design_ebn0_db, k_row)
        tensor_perm = build_tensor_permutation(seed)
        tensor_inv_perm = np.argsort(tensor_perm).astype(np.int32)
        rep_map = build_tensor_repetition(seed)
        return cls(frozen=frozen, info_positions=info_positions,
                   tensor_perm=tensor_perm, tensor_inv_perm=tensor_inv_perm,
                   rep_map=rep_map,
                   mode=mode, spc_iters=spc_iters)


# ---------------------------------------------------------------------------
#  Encode / Decode
# ---------------------------------------------------------------------------

def tensor_encode(info: np.ndarray, codec: TensorCodec) -> np.ndarray:
    """info (K_INFO=64) -> 688 coded bits."""
    crc = H.crc16_ccitt(info)
    payload = np.concatenate([info, crc]).astype(np.uint8)   # 80 bits

    if codec.mode == "plain":
        payload_rows = payload.reshape(ROWS, K_ROW)
        u_batch = np.zeros((ROWS, N_ROW), dtype=np.uint8)
        u_batch[:, codec.info_positions] = payload_rows
        x_batch = polar_encode_batch(u_batch)   # (8, 64)

    elif codec.mode == "xparity":
        # Pad payload 80 -> 84 with 4 zero bits, distribute across 7 info rows.
        padded = np.concatenate([payload,
                                 np.zeros(INFO_ROWS_XP * K_ROW_XP - len(payload),
                                          dtype=np.uint8)])
        payload_rows = padded.reshape(INFO_ROWS_XP, K_ROW_XP)
        u_info = np.zeros((INFO_ROWS_XP, N_ROW), dtype=np.uint8)
        u_info[:, codec.info_positions] = payload_rows
        x_info = polar_encode_batch(u_info)        # (7, 64)
        x_parity = np.bitwise_xor.reduce(x_info, axis=0)  # (64,) column XOR
        x_batch = np.vstack([x_info, x_parity[None, :]])   # (8, 64)

    else:
        raise ValueError(codec.mode)

    matrix_bits = x_batch.reshape(N_MATRIX)
    permuted = matrix_bits[codec.tensor_perm]
    coded = permuted[codec.rep_map]
    return coded


def _column_spc_update(llr_batch: np.ndarray) -> np.ndarray:
    """
    One round of SPC-BP on each column (length-ROWS single-parity-check code).

    For each column c and row r, the extrinsic LLR is:
      L_ext[r, c] = prod_{k != r} sign(L[k, c]) * min_{k != r} |L[k, c]|

    Returns: new LLR batch = input + extrinsic   (shape (ROWS, N_ROW))
    """
    # Per-column signs/abs
    signs = np.where(llr_batch >= 0, 1.0, -1.0)          # (R, N)
    absL = np.abs(llr_batch)                              # (R, N)
    prod_sign = np.prod(signs, axis=0, keepdims=True)     # (1, N)
    # min and 2nd-min excluding one row, computed via argmin trick
    amin = np.argmin(absL, axis=0)                        # (N,)
    min1 = np.min(absL, axis=0, keepdims=True)            # (1, N)
    tmp = absL.copy()
    tmp[amin, np.arange(tmp.shape[1])] = np.inf
    min2 = np.min(tmp, axis=0, keepdims=True)             # (1, N)

    R = llr_batch.shape[0]
    # outgoing magnitude to row r: min2 if r == amin else min1
    out_mag = np.broadcast_to(min1, llr_batch.shape).copy()
    rows = np.arange(R)[:, None]                          # for shape bcast
    mask = (rows == amin[None, :])                        # (R, N)
    out_mag = np.where(mask, np.broadcast_to(min2, llr_batch.shape), out_mag)
    # outgoing sign = prod_sign / signs[r]
    out_sign = prod_sign / signs
    L_ext = out_sign * out_mag
    return llr_batch + L_ext


def tensor_decode(rx_llr: np.ndarray, codec: TensorCodec) -> tuple:
    """
    Returns (info_hat, crc_ok).
    """
    permuted_llr = np.zeros(N_MATRIX, dtype=np.float64)
    np.add.at(permuted_llr, codec.rep_map, rx_llr)
    matrix_llr = permuted_llr[codec.tensor_inv_perm]
    llr_batch = matrix_llr.reshape(ROWS, N_ROW).copy()

    if codec.mode == "xparity":
        # Pre-process LLRs with SPC-BP across the 8-row column SPC code(s).
        for _ in range(codec.spc_iters):
            llr_batch = _column_spc_update(llr_batch)
        # After BP, SC-decode only the 7 INFO rows.
        info_llr = llr_batch[:INFO_ROWS_XP]
        u_hat = np.zeros((INFO_ROWS_XP, N_ROW), dtype=np.uint8)
        sc_decode_batch(info_llr, codec.frozen, u_hat, pos=0)
        payload_rows = u_hat[:, codec.info_positions]
        padded = payload_rows.reshape(-1)       # 7*12 = 84 bits
        payload = padded[:H.K_PAYLOAD]          # strip 4-bit pad
    else:
        u_hat = np.zeros((ROWS, N_ROW), dtype=np.uint8)
        sc_decode_batch(llr_batch, codec.frozen, u_hat, pos=0)
        payload_rows = u_hat[:, codec.info_positions]
        payload = payload_rows.reshape(-1)      # 80 bits

    info_hat = payload[:H.K_INFO]
    crc_hat = payload[H.K_INFO:]
    crc_ok = np.array_equal(H.crc16_ccitt(info_hat), crc_hat)
    return info_hat, crc_ok


# ---------------------------------------------------------------------------
#  Self-test + AWGN sweep
# ---------------------------------------------------------------------------

def selftest_noiseless(codec: TensorCodec, n_trials: int = 64) -> None:
    rng = np.random.default_rng(0)
    fails = 0
    for _ in range(n_trials):
        info = rng.integers(0, 2, size=H.K_INFO, dtype=np.uint8)
        coded = tensor_encode(info, codec)
        llr = np.where(coded == 0, 20.0, -20.0)
        info_hat, ok = tensor_decode(llr, codec)
        if not (ok and np.array_equal(info_hat, info)):
            fails += 1
    print(f"  [selftest] tensor noiseless round-trip ... "
          f"{'PASS' if fails == 0 else 'FAIL'}  "
          f"({n_trials - fails}/{n_trials})")


def run_point(ebn0_db: float, trials: int, codec: TensorCodec,
              seed: int) -> dict:
    rng = np.random.default_rng(seed)
    rate = H.K_INFO / H.N_CODED

    errs_blk = 0
    errs_bit = 0
    crc_fail = 0
    crc_fp = 0
    dec_time = 0.0

    for _ in range(trials):
        info = rng.integers(0, 2, size=H.K_INFO, dtype=np.uint8)
        coded = tensor_encode(info, codec)
        llr = H.awgn_bpsk(coded, ebn0_db, rate, rng)

        t0 = time.perf_counter()
        info_hat, ok = tensor_decode(llr, codec)
        dec_time += time.perf_counter() - t0

        truth_ok = np.array_equal(info_hat, info)
        if ok:
            if not truth_ok:
                crc_fp += 1
                errs_blk += 1
                errs_bit += int(np.sum(info_hat != info))
        else:
            crc_fail += 1
            if not truth_ok:
                errs_blk += 1
                errs_bit += int(np.sum(info_hat != info))

    return dict(
        ebno=ebn0_db,
        trials=trials,
        bler=errs_blk / trials,
        ber=errs_bit / (trials * H.K_INFO),
        crc_fail_rate=crc_fail / trials,
        crc_fp_rate=(crc_fp / (trials - crc_fail))
                     if (trials - crc_fail) else 0.0,
        decode_ms_avg=1000.0 * dec_time / trials,
    )


# ---------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=400)
    ap.add_argument("--seed", type=int, default=0xDEADBEEF)
    ap.add_argument("--design-db", type=float, default=2.5)
    ap.add_argument("--ebno-list", type=str, default="2.0,2.5,3.0,3.5")
    ap.add_argument("--ebno", type=float, default=None)
    ap.add_argument("--n-row", type=int, default=64,
                    choices=[32, 64, 128, 256],
                    help="row Polar length (matrix stays 512 total)")
    ap.add_argument("--mode", choices=["plain", "xparity"], default="plain",
                    help="plain = ROWS*Polar(N_ROW,K_ROW); "
                         "xparity = 7+1 column-SPC (N_ROW=64 only)")
    ap.add_argument("--spc-iters", type=int, default=1,
                    help="SPC-BP iteration count (xparity mode only)")
    args = ap.parse_args()

    if args.ebno is not None:
        pts = [args.ebno]
    else:
        pts = [float(s) for s in args.ebno_list.split(",")]

    configure_tensor(args.n_row)
    if args.mode == "xparity" and N_ROW != 64:
        raise SystemExit("xparity mode requires --n-row 64")

    codec = TensorCodec.build(seed=args.seed, design_ebn0_db=args.design_db,
                              mode=args.mode, spc_iters=args.spc_iters)

    print("=" * 60)
    if args.mode == "plain":
        print(f" HTS-HFC v2 Tensor FEC "
              f"({ROWS} x Polar({N_ROW},{K_ROW}) + ARX128 mix + rep688)")
    else:
        print(f" HTS-HFC v2 Tensor FEC xparity "
              f"(7 x Polar(64,12) + col-SPC + BP{args.spc_iters} + rep688)")
    print(f" K_INFO={H.K_INFO}  K_PAYLOAD={H.K_PAYLOAD}  "
          f"N_MATRIX={N_MATRIX}  N_CODED={H.N_CODED}")
    print(f" rate = {H.K_INFO}/{H.N_CODED} = {H.K_INFO / H.N_CODED:.4f}")
    print("=" * 60)
    selftest_noiseless(codec)

    print(f"\n  {'Eb/N0':>7} {'BLER':>10} {'BER':>12} {'CRC_fail':>9} "
          f"{'CRC_FP':>8} {'ms':>7}")
    for eb in pts:
        r = run_point(eb, args.trials, codec,
                      seed=0xC0FFEE + int(eb * 100))
        print(f"  {r['ebno']:>7.2f} {r['bler']:>10.4f} {r['ber']:>12.4e} "
              f"{r['crc_fail_rate']:>9.4f} {r['crc_fp_rate']:>8.4f} "
              f"{r['decode_ms_avg']:>7.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
