#!/usr/bin/env python3
"""Run with PYTHONPATH pointing to soundcalc PR 91 at the revision below."""
import hashlib
import json
import math
import subprocess
import sys
import tomllib
from pathlib import Path

import soundcalc
from soundcalc.proxgaps.johnson_bound import JohnsonBoundRegime
from soundcalc.proxgaps.unique_decoding import UniqueDecodingRegime
from soundcalc.zkvms.zkvm import zkVM

HERE = Path(__file__).resolve().parent
REVISION = "d683f29183d8e831fb0bd8fdb8c39ce8598e43ab"


def union(bits):
    return -math.log2(sum(2.0 ** -b for b in bits))


def main():
    checkout = Path(soundcalc.__file__).resolve().parents[1]
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True).strip() == REVISION
    assert not subprocess.check_output(["git", "diff", "--", "soundcalc"], cwd=checkout)
    config_path = HERE / "soundness.toml"
    config = tomllib.loads(config_path.read_text())
    census = tomllib.loads((HERE / "soundness-census.toml").read_text())
    result = {"ziren_revision": "cf0b3742", "soundcalc_revision": REVISION,
              "profile_digest": census["all_rings"]["transcript_profile_digest"],
              "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
              "census_sha256": hashlib.sha256((HERE / "soundness-census.toml").read_bytes()).hexdigest(), "stages": {}}
    for circuit, inputs in zip(zkVM.load_from_toml(config_path).get_circuits(), config["circuits"]):
        name = circuit.get_name()
        observed = census[name]
        assert inputs["trace_length"] == 1 << census["verifier_bounds"]["max_log_row_count"]
        assert inputs["lookups"][0]["rows_L"] == inputs["trace_length"]
        assert inputs["dense_batch"] == census["verifier_bounds"][name + "_dense_batch"]
        for key in ("trace_columns", "num_constraints", "air_max_degree"):
            assert inputs[key] == observed[key], (name, key)
        for key in ("num_lookups_M", "num_columns_S"):
            assert inputs["lookups"][0][key] == observed[key], (name, key)
        schedule = observed["schedule"]
        assert inputs["folding_factors"] == schedule["folding_factors"]
        assert inputs["num_queries"] == schedule["num_queries"] + [schedule["final_queries"]]
        assert inputs["grinding_bits_queries"] == schedule["grinding_bits_queries"] + [schedule["final_grinding_bits"]]
        assert inputs["whir_log_inv_rates"] == schedule["committed_log_inv_rates"] + [schedule["final_log_inv_rate"]]
        assert inputs["grinding_batching_phase"] == schedule["grinding_batching_phase"]
        assert inputs["grinding_bits_folding"] == [
            [g] * k for g, k in zip(schedule["grinding_bits_folding"], schedule["folding_factors"])]
        assert inputs["lookups"][0]["grinding_bits_lookup"] == census["all_rings"]["grinding_bits_lookup"]
        # The loader's JaggedCircuit defaults to UDR. Select the dense WHIR
        # regime explicitly; the algebraic reduction, zerocheck and lookup
        # terms are field-size bounds and do not depend on decoding radius.
        components = next(iter(circuit.get_security_levels().values()))
        components.pop("total")
        regime = UniqueDecodingRegime(circuit.field) if name == "core" else JohnsonBoundRegime(circuit.field, explicit_m=inputs["explicit_m"])
        components.update(circuit.pcs.get_pcs_security_levels(regime))
        # soundcalc's `fin` already accounts for the final query phase.
        # Include it once, in the query group, with both shift phases.
        groups = {"Query phases": union([v for k, v in components.items() if k.startswith("Shift(") or k == "fin"]),
                  "Folding rounds": union([v for k, v in components.items() if k.startswith("fold(")]),
                  "LogUp-GKR": components["logup-gkr"], "Batching": components["batching"],
                  "Zerocheck": components["zerocheck"], "Reduction to the dense polynomial": components["reduce to dense PCS"],
                  "Out-of-domain samples": union([v for k, v in components.items() if k.startswith("OOD(")])}
        assert math.isclose(union(groups.values()), union(components.values()), abs_tol=1e-12)
        result["stages"][name] = {"regime": regime.identifier(), "components_floored_bits": components,
                                  "groups_bits": groups, "union_bits": union(components.values())}
    core, root = (result["stages"][n]["union_bits"] for n in ("core", "compress"))
    result["one_core_plus_root_bits"] = union([core, root])
    # An explicit example, rather than an exact census of a measured tree.
    result["example_tree"] = {"core_schedule_proofs": 149, "compress_schedule_proofs": 1,
                              "union_bits": union([core] * 149 + [root])}
    (HERE / "soundness-results.json").write_text(json.dumps(result, indent=2) + "\n")
    lines = ["# Reproduced interactive soundness", "", f"Ziren `{result['ziren_revision']}`; soundcalc `{REVISION}`.",
             f"Transcript profile `{result['profile_digest']}`.", "", "Component errors are floored to integer bits by soundcalc, then summed.",
             "The final-query term (`fin`) is included once. No wrap or Fiat–Shamir bound is claimed here.", "",
             "| Component group | Core | Compress root |", "| --- | ---: | ---: |"]
    for group in result["stages"]["core"]["groups_bits"]:
        lines.append(f"| {group} | {result['stages']['core']['groups_bits'][group]:.2f} | {result['stages']['compress']['groups_bits'][group]:.2f} |")
    lines += [f"| **Union over the stage** | **{core:.2f}** | **{root:.2f}** |", "",
              f"One core proof plus one root: {result['one_core_plus_root_bits']:.2f} bits.",
              f"Example with 149 core-schedule proofs and one root: {result['example_tree']['union_bits']:.2f} bits.", "",
              "Individual components and exact input hashes are in `soundness-results.json`.", ""]
    (HERE / "soundness-report.md").write_text("\n".join(lines))
    print("\n".join(lines))


if __name__ == "__main__":
    main()
