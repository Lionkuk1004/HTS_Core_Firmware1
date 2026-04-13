"""
LDPC baseline at same info rate (80 bits -> 688 chips) for apples-to-apples
comparison vs Polar / HoloTurbo.

Uses the existing (3,6)-regular Gallager LDPC(160, 80) kernel and extends to
688 chips via ARX128 permuted repetition (same expansion mechanism as the
Polar path). This gives an identical overall code rate and channel input
statistics so BLER differences reflect ONLY the inner code choice.
"""
from __future__ import annotations

import argparse
import math
import sys
import time

import numpy as np

import hfc_v2_sim as base
import hfc_v2_ldpc as ldpc


def build_ldpc_masks(n_inner: int, n_coded: int,
                     seed: int = 0xDEADBEEF) -> np.ndarray:
    """ARX128 balanced permuted-repetition map n_coded -> n_inner."""
    arx = base.ARX128(seed)
    low = n_coded // n_inner
    n_high = n_coded - low * n_inner
    order = np.arange(n_inner, dtype=np.int32)
    for i in range(n_inner - 1, 0, -1):
        j = arx.step() % (i + 1)
        order[i], order[j] = order[j], order[i]
    pool = np.empty(n_coded, dtype=np.int32)
    k = 0
    for idx in range(n_inner):
        reps = low + (1 if idx in order[:n_high] else 0)
        pool[k:k + reps] = idx
        k += reps
    for i in range(n_coded - 1, 0, -1):
        j = arx.step() % (i + 1)
        pool[i], pool[j] = pool[j], pool[i]
    return pool


def encode(info: np.ndarray, code, masks: np.ndarray) -> np.ndarray:
    crc = base.crc16_ccitt(info)
    payload = np.concatenate([info, crc]).astype(np.uint8)
    cw = ldpc.ldpc_encode(payload, code)         # 160 bits
    return cw[masks]                             # 688 chips


def decode(rx_llr: np.ndarray, code, masks: np.ndarray,
           bp_iters: int = 25):
    inner_llr = np.zeros(ldpc.N_INNER, dtype=np.float64)
    np.add.at(inner_llr, masks, rx_llr)
    pay_hat = ldpc.ldpc_decode_bp(inner_llr, code, max_iters=bp_iters)
    info = pay_hat[:base.K_INFO]
    crc_rx = pay_hat[base.K_INFO:]
    crc_calc = base.crc16_ccitt(info)
    ok = np.array_equal(crc_rx, crc_calc)
    return ok, info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ebno", type=float, default=2.3)
    ap.add_argument("--trials", type=int, default=1500)
    ap.add_argument("--bp-iters", type=int, default=25)
    ap.add_argument("--sweep", action="store_true")
    args = ap.parse_args()

    code = ldpc.build_ldpc_code(seed=0xDEADBEEF)
    masks = build_ldpc_masks(ldpc.N_INNER, base.N_CODED, seed=0xDEADBEEF)

    print(f"=== LDPC(160, 80) + ARX rep -> 688 chips, BP iters={args.bp_iters} ===")
    print()

    # Noiseless sanity
    rng = np.random.default_rng(1)
    s_ok = 0
    for _ in range(16):
        info = rng.integers(0, 2, size=base.K_INFO, dtype=np.uint8)
        coded = encode(info, code, masks)
        llr = np.where(coded == 0, 20.0, -20.0)
        ok, hat = decode(llr, code, masks, bp_iters=args.bp_iters)
        if ok and np.array_equal(info, hat):
            s_ok += 1
    print(f"  Noiseless sanity: {s_ok}/16")
    print()

    pts = ([1.75, 2.0, 2.15, 2.3, 2.5, 2.75, 3.0]
           if args.sweep else [args.ebno])
    print(f"{'Eb/N0':>7} {'BLER':>10} {'BER':>12} {'ms':>8}")
    print("-" * 42)
    for eb in pts:
        rng = np.random.default_rng(0xC0FFEE + int(eb * 1000))
        errs_b = 0
        errs_i = 0
        t_total = 0.0
        rate = base.K_INFO / base.N_CODED
        for t in range(args.trials):
            info = rng.integers(0, 2, size=base.K_INFO, dtype=np.uint8)
            coded = encode(info, code, masks)
            llr = base.awgn_bpsk(coded, eb, rate, rng)
            t0 = time.perf_counter()
            ok, hat = decode(llr, code, masks, bp_iters=args.bp_iters)
            t_total += time.perf_counter() - t0
            if not np.array_equal(info, hat):
                errs_b += 1
                errs_i += int(np.sum(info != hat))
        print(f"{eb:>7.2f} {errs_b/args.trials:>10.4f} "
              f"{errs_i/(args.trials*base.K_INFO):>12.4e} "
              f"{1000*t_total/args.trials:>8.2f}")


if __name__ == "__main__":
    sys.exit(main())
