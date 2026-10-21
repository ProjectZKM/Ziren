#!/usr/bin/env python3
"""Evaluate a terminal schedule with pinned ethereum/soundcalc (PCS model only).

The native implementation commits oracles at explicit rates. soundcalc normally
derives a fixed-domain-shift schedule, so this adapter replaces those derived
rates with the rates actually consumed by native stacked WHIR. This is not an
end-to-end soundness certificate or a quantum security estimator.
"""
import argparse
import json
import math
import subprocess
import sys
from pathlib import Path

SOUNDCALC_COMMIT = "2af5e7dfc01e4aef1bc0e544a3b75c1940b1dded"
KEYS = {"folds", "queried_log_inv_rates", "johnson_m", "component_target_bits",
        "query_grinding_bits", "folding_grinding_bits", "batching_grinding_bits",
        "ood_samples"}


def validate(p, degree):
    if set(p) != KEYS:
        raise ValueError("parameter keys must match the strict native schema")
    folds, rates = p["folds"], p["queried_log_inv_rates"]
    if not folds or len(folds) != len(rates) or sum(folds) >= degree:
        raise ValueError("one actual queried rate per fold; retain final variables")
    remaining, previous = degree, 0
    for k, rate in zip(folds, rates):
        if type(k) is not int or not 1 <= k <= 8:
            raise ValueError("folds must be integers in 1..8")
        if type(rate) is not int or not max(1, previous) <= rate <= 24:
            raise ValueError("queried rates must be positive and nondecreasing")
        if remaining + rate - k > 24:
            raise ValueError("interleaved DFT height exceeds KoalaBear two-adicity")
        remaining -= k
        previous = rate
    if (type(p["johnson_m"]) is not int or not 1 <= p["johnson_m"] <= 64
            or type(p["ood_samples"]) is not int or p["ood_samples"] < 2):
        raise ValueError("retain Johnson m in 1..64 and at least two OOD samples")
    if not math.isfinite(p["component_target_bits"]) or p["component_target_bits"] < 106:
        raise ValueError("native query component target is at least 106 bits")
    for key in ("query_grinding_bits", "folding_grinding_bits", "batching_grinding_bits"):
        if type(p[key]) is not int or not 0 <= p[key] <= 28:
            raise ValueError("base-field witness grinding must be in 0..28")


def evaluate(p, degree, stripes, WHIR, WHIRConfig, field, regime_type):
    validate(p, degree)
    folds, rates = p["folds"], p["queried_log_inv_rates"]
    m, grind = p["johnson_m"], p["query_grinding_bits"]
    b = [rate / 2 - math.log2(1 + 1 / (2 * m)) for rate in rates]
    if min(b) <= 0:
        raise ValueError("Johnson agreement bound must be below one")
    queries = [math.ceil((p["component_target_bits"] - grind) / x) for x in b]
    n = len(folds)
    cfg = WHIRConfig(
        hash_size_bits=256, log_inv_rate=rates[0], num_iterations=n,
        folding_factors=folds, field=field, log_degree=degree, batch_size=stripes,
        power_batching=True, grinding_batching_phase=p["batching_grinding_bits"],
        constraint_degree=3,
        grinding_bits_folding=[[p["folding_grinding_bits"]] * k for k in folds],
        num_queries=queries, grinding_bits_queries=[grind] * n,
        num_ood_samples=[p["ood_samples"]] * (n - 1), grinding_bits_ood=[0] * (n - 1))
    w = WHIR(cfg)
    # Last entry is a shape placeholder: the last fold does not commit again.
    w.log_inv_rates = rates + [rates[-1]]
    regime = regime_type(field, explicit_m=m)
    errors = {"batching": w._get_batching_error(regime), "final_queries": w._epsilon_final(regime)}
    for i, k in enumerate(folds):
        for j in range(1, k + 1):
            errors[f"fold_{i}_{j}"] = w._epsilon_fold(i, j, regime)
        if i:
            errors[f"ood_{i}"] = w._epsilon_out(i, regime)
            errors[f"shift_queries_{i}"] = w._epsilon_shift(i, regime)
    return {
        "parameters": p, "log_stacking_height": degree, "batch_stripes": stripes,
        "actual_queries": queries, "final_poly_log_degree": degree - sum(folds),
        "pcs_union_bits": -math.log2(sum(errors.values())),
        "component_error_bits": {k: -math.log2(v) for k, v in errors.items()},
        "first_oracle_cell_bytes": stripes * (1 << (degree + rates[0])) * 4,
        "scope": "WHIR PCS model under the native Johnson-bound assumptions; excludes the remaining machine/Fiat-Shamir security argument; not a quantum security certificate",
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--soundcalc", type=Path, required=True)
    ap.add_argument("--parameters", type=Path, required=True)
    ap.add_argument("--log-degree", type=int, default=21)
    ap.add_argument("--batch-stripes", type=int, required=True,
                    help="actual trusted fixture stripe count, not an arbitrary optimistic value")
    ap.add_argument("--native-vector", type=Path,
                    help="optional authenticated whir.json export; cross-check actual query/path geometry")
    ap.add_argument("--out", type=Path, required=True, help="local report outside the source tree")
    a = ap.parse_args()
    if a.batch_stripes < 1 or not 2 <= a.log_degree <= 24:
        ap.error("positive stripe count and log-degree 2..24 required")
    actual = subprocess.check_output(["git", "-C", str(a.soundcalc), "rev-parse", "HEAD"], text=True).strip()
    if actual != SOUNDCALC_COMMIT:
        ap.error(f"soundcalc must be pinned to {SOUNDCALC_COMMIT}; found {actual}")
    dirty = subprocess.check_output(["git", "-C", str(a.soundcalc), "status", "--porcelain", "--untracked-files=no"], text=True)
    if dirty:
        ap.error("soundcalc tracked files must be unchanged")
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(a.soundcalc.resolve()))
    from soundcalc.pcs.whir import WHIR, WHIRConfig
    from soundcalc.common.fields import KOALABEAR_4
    from soundcalc.proxgaps.johnson_bound import JohnsonBoundRegime
    selected = json.loads(a.parameters.read_text())
    report = evaluate(selected, a.log_degree, a.batch_stripes,
                      WHIR, WHIRConfig, KOALABEAR_4, JohnsonBoundRegime)
    if a.native_vector:
        native = json.loads(a.native_vector.read_text())
        groups = native["proof"]["openings"]
        if sum(native["stripes"]) != a.batch_stripes or len(groups) != len(selected["folds"]):
            raise ValueError("model batch/round geometry differs from the authenticated native export")
        remaining = a.log_degree
        for i, (k, rate, count, group) in enumerate(zip(
                selected["folds"], selected["queried_log_inv_rates"], report["actual_queries"], groups)):
            openings = count * (len(native["roots"]) if i == 0 else 1)
            height = remaining + rate - k
            if len(group) != openings or any(len(leaf["path"]) != height for leaf in group):
                raise ValueError(f"actual native query count/oracle height differs in phase {i}")
            remaining -= k
        report["native_query_and_domain_geometry_checked"] = True
    # The historical final count of 14 was solved at an uncommitted rate.
    # Evaluate its corrected 19-query form as the equal-budget comparator.
    if a.log_degree == 21:
        baseline = dict(selected, folds=[2, 6, 6], queried_log_inv_rates=[3, 6, 9],
                        johnson_m=6, component_target_bits=106.0,
                        query_grinding_bits=26, folding_grinding_bits=27,
                        batching_grinding_bits=27, ood_samples=2)
        comparator = evaluate(baseline, 21, a.batch_stripes,
                              WHIR, WHIRConfig, KOALABEAR_4, JohnsonBoundRegime)
        report["corrected_baseline_pcs_union_bits"] = comparator["pcs_union_bits"]
        report["meets_corrected_baseline_pcs_budget"] = report["pcs_union_bits"] >= comparator["pcs_union_bits"]
    report["soundcalc_commit"] = actual
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if report.get("meets_corrected_baseline_pcs_budget") is False:
        raise SystemExit("selected schedule falls below the corrected baseline PCS budget")


if __name__ == "__main__":
    main()
