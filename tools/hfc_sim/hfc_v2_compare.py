"""
HTS-HFC v2 Architecture Comparison
==================================

Runs three inner-code architectures through the same outer pipeline
(CRC-16 -> inner code -> ARX128 permuted repetition to N_CODED=688 ->
BPSK/AWGN -> matched-filter LLR combine -> CRC-aided decoder) and
compares BLER / BER / decode time across matched Eb/N0 points.

  (A) Polar N=256, SCL L=4, rep ~2.7x
  (B) Polar N=512, SCL L=4, rep ~1.34x
  (C) Gallager (3,6)-regular LDPC (160, 80), BP min-sum 25 iters, rep ~4.3x
  (baseline: Polar N=128, SCL L=4, rep ~5.4x)

For (A) and (B) we reuse hfc_v2_sim.py directly via configure_dimensions().
For (C) we import a separate LDPC kernel from hfc_v2_ldpc.py and swap the
inner code.
"""

from __future__ import annotations

import argparse
import math
import sys
import time

import numpy as np

import hfc_v2_sim as H
import hfc_v2_ldpc as L


# ---------------------------------------------------------------------------
#  Unified runner: (name, prepare_codec, encode_fn, decode_fn)
# ---------------------------------------------------------------------------


def _run_polar(n_polar: int, list_size: int, trials: int,
               ebno_points: list[float], seed: int) -> list[dict]:
    """Reuse hfc_v2_sim.run_point with the given inner Polar length."""
    H.configure_dimensions(n_polar)
    codec = H.Codec.build(seed=seed, target_ebn0_db=2.5)
    results = []
    for eb in ebno_points:
        r = H.run_point(eb, trials, codec,
                        seed=0xC0FFEE + int(eb * 100),
                        L=list_size)
        results.append(r)
    return results


def _run_ldpc(trials: int, ebno_points: list[float], seed: int,
              bp_iters: int) -> list[dict]:
    """Run the LDPC(160,80) pipeline with 4.3x permuted repetition to 688."""
    # Fix overall code dims on H (so repetition map matches N_CODED=688).
    H.configure_dimensions(L.N_INNER)        # N_INNER = 160
    masks = H.build_fractal_masks(seed=seed)
    code = L.build_ldpc_code(seed=seed)
    results = []
    for eb in ebno_points:
        r = _run_ldpc_point(eb, trials, code, masks,
                            seed=0xC0FFEE + int(eb * 100),
                            bp_iters=bp_iters)
        results.append(r)
    return results


def _run_ldpc_point(ebn0_db: float, trials: int, code, masks: np.ndarray,
                    seed: int, bp_iters: int) -> dict:
    rng = np.random.default_rng(seed)
    rate = H.K_INFO / H.N_CODED

    errs_blk = 0
    errs_bit = 0
    crc_fail = 0
    crc_fp = 0
    dec_time = 0.0
    rank_hist = [0]  # LDPC has no list; single decoder output

    for _ in range(trials):
        info = rng.integers(0, 2, size=H.K_INFO, dtype=np.uint8)
        # Build 80-bit payload = info || CRC16.
        crc = H.crc16_ccitt(info)
        payload = np.concatenate([info, crc]).astype(np.uint8)
        # LDPC systematic encode -> N_INNER coded bits.
        x = L.ldpc_encode(payload, code)
        # Permuted repetition to 688.
        coded = x[masks]
        # Channel.
        llr = H.awgn_bpsk(coded, ebn0_db, rate, rng)
        # Combine.
        combined = np.zeros(L.N_INNER, dtype=np.float64)
        np.add.at(combined, masks, llr)

        t0 = time.perf_counter()
        payload_hat = L.ldpc_decode_bp(combined, code, max_iters=bp_iters)
        dec_time += time.perf_counter() - t0

        rx_info = payload_hat[:H.K_INFO]
        rx_crc  = payload_hat[H.K_INFO:]
        ok = np.array_equal(H.crc16_ccitt(rx_info), rx_crc)

        truth_ok = np.array_equal(rx_info, info)
        if ok:
            rank_hist[0] += 1
            if not truth_ok:
                crc_fp += 1
                errs_blk += 1
                errs_bit += int(np.sum(rx_info != info))
        else:
            crc_fail += 1
            if not truth_ok:
                errs_blk += 1
                errs_bit += int(np.sum(rx_info != info))

    return dict(
        ebno=ebn0_db,
        trials=trials,
        bler=errs_blk / trials,
        ber=errs_bit / (trials * H.K_INFO),
        crc_fail_rate=crc_fail / trials,
        crc_fp_rate=(crc_fp / (trials - crc_fail)) if (trials - crc_fail) else 0.0,
        rank_hist=rank_hist,
        decode_ms_avg=1000.0 * dec_time / trials,
    )


# ---------------------------------------------------------------------------
#  Pretty-print
# ---------------------------------------------------------------------------


def print_results(title: str, results: list[dict]) -> None:
    print(f"\n[{title}]")
    print(f"  {'Eb/N0':>7} {'BLER':>10} {'BER':>12} {'CRC_fail':>9} "
          f"{'CRC_FP':>8} {'ms':>7}")
    for r in results:
        print(f"  {r['ebno']:>7.2f} {r['bler']:>10.4f} {r['ber']:>12.4e} "
              f"{r['crc_fail_rate']:>9.4f} {r['crc_fp_rate']:>8.4f} "
              f"{r['decode_ms_avg']:>7.2f}")


def summary_table(all_results: dict[str, list[dict]], pts: list[float]) -> None:
    print("\n" + "=" * 70)
    print(" SUMMARY — BLER by architecture")
    print("=" * 70)
    header = ["Eb/N0"] + list(all_results.keys())
    widths = [8] + [18] * len(all_results)
    print(" ".join(f"{h:>{w}}" for h, w in zip(header, widths)))
    print(" ".join("-" * w for w in widths))
    for i, eb in enumerate(pts):
        row = [f"{eb:.2f}"]
        for name in all_results:
            r = all_results[name][i]
            row.append(f"{r['bler']:.4f}   ({r['decode_ms_avg']:.1f} ms)")
        print(" ".join(f"{v:>{w}}" for v, w in zip(row, widths)))


# ---------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=400)
    ap.add_argument("--seed", type=int, default=0xDEADBEEF)
    ap.add_argument("--bp-iters", type=int, default=25,
                    help="LDPC BP iteration count (default 25)")
    ap.add_argument("--ebno-list", type=str, default="2.0,2.5,3.0,3.5,4.0")
    ap.add_argument("--skip", type=str, default="",
                    help="comma list of variants to skip: baseline,A,B,C")
    args = ap.parse_args()

    pts = [float(s) for s in args.ebno_list.split(",")]
    skip = set(s.strip() for s in args.skip.split(",") if s.strip())

    all_results: dict[str, list[dict]] = {}

    print("=" * 70)
    print(f" HTS-HFC v2 architecture shoot-out "
          f"(trials={args.trials}/pt, pts={pts})")
    print("=" * 70)

    if "baseline" not in skip:
        print("\n[baseline] Polar N=128, SCL L=4 ...", flush=True)
        r = _run_polar(128, 4, args.trials, pts, args.seed)
        all_results["base-P128"] = r
        print_results("baseline  Polar N=128  L=4", r)

    if "A" not in skip:
        print("\n[A] Polar N=256, SCL L=4 ...", flush=True)
        r = _run_polar(256, 4, args.trials, pts, args.seed)
        all_results["A-P256"] = r
        print_results("(A) Polar N=256  L=4", r)

    if "B" not in skip:
        print("\n[B] Polar N=512, SCL L=4 ...", flush=True)
        r = _run_polar(512, 4, args.trials, pts, args.seed)
        all_results["B-P512"] = r
        print_results("(B) Polar N=512  L=4", r)

    if "C" not in skip:
        print(f"\n[C] LDPC(160,80) (3,6)-regular, BP {args.bp_iters} iters ...",
              flush=True)
        r = _run_ldpc(args.trials, pts, args.seed, args.bp_iters)
        all_results["C-LDPC160"] = r
        print_results("(C) LDPC(160,80) BP", r)

    summary_table(all_results, pts)

    # Pick the winner at each SNR, by BLER.
    print("\nBest per Eb/N0 (lowest BLER):")
    for i, eb in enumerate(pts):
        best = min(all_results.items(), key=lambda kv: kv[1][i]['bler'])
        print(f"  {eb:.2f} dB : {best[0]}  BLER={best[1][i]['bler']:.4f}  "
              f"(ms={best[1][i]['decode_ms_avg']:.1f})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
