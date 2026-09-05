"""Let a JAGGED circuit sit on WHIR as its dense PCS (Ziren's inner ring).

Usage: python3 soundcalc_whir_patch.py <soundcalc repo root>

soundcalc's JaggedCircuit hard-wires FRI as the dense PCS.  Ziren commits the
jagged dense polynomial with WHIR (`WHIR_INNER_PCS = true`), so:
  * zkvm.py: a JAGGED section with `dense_pcs = "whir"` builds a WHIR from the
    same keys the WHIR protocol family uses;
  * jagged.py: the reduction error / summary read the dense PCS through its
    abstract getters instead of FRI-only attributes.
The jagged reduction analysis itself is unchanged (UDR only).
"""
import os
import sys

root = sys.argv[1]


def patch(rel, old, new, count=1):
    p = os.path.join(root, rel)
    s = open(p).read()
    assert s.count(old) == count, (rel, old[:60], s.count(old))
    open(p, "w").write(s.replace(old, new))
    print("patched", rel)


# --- zkvm.py: dense_pcs = "whir" ------------------------------------------
patch(
    "soundcalc/zkvms/zkvm.py",
    """        dense_pcs = FRI(FRIConfig(
            hash_size_bits=cls._hash_size_bits(config, section),
            rho=section["rho"],
            gap_to_radius=section.get("gap_to_radius"),
            trace_length=section["dense_length"],
            field=field,
            batch_size=section["dense_batch"],
            power_batching=section["power_batching"],
            multilinear_batching=section.get("multilinear_batching", False),
            num_queries=section["num_queries"],
            FRI_folding_factors=section.get("fri_folding_factors"),
            FRI_early_stop_degree=section.get("fri_early_stop_degree"),
            grinding_batching_phase=section.get("grinding_batching_phase", 0),
            grinding_query_phase=section.get("grinding_query_phase", 0),
        ))
        lookups = _parse_lookups_from_toml(section, field)
        return JaggedCircuit(JaggedCircuitConfig(""",
    """        if section.get("dense_pcs", "fri") == "whir":
            # Jagged over WHIR (Ziren's inner ring): the dense polynomial has
            # log_degree = log2(dense_length) variables and is committed with
            # the WHIR schedule given by the same keys the WHIR family uses.
            dense_pcs = WHIR(WHIRConfig(
                hash_size_bits=cls._hash_size_bits(config, section),
                log_inv_rate=section["log_inv_rate"],
                num_iterations=section["num_iterations"],
                folding_factors=section["folding_factors"],
                log_degree=section["log_degree"],
                field=field,
                batch_size=section["dense_batch"],
                power_batching=section["power_batching"],
                grinding_batching_phase=section.get("grinding_batching_phase", 0),
                constraint_degree=section["constraint_degree"],
                grinding_bits_folding=section["grinding_bits_folding"],
                num_queries=section["num_queries"],
                grinding_bits_queries=section["grinding_bits_queries"],
                num_ood_samples=section["num_ood_samples"],
                grinding_bits_ood=section["grinding_bits_ood"],
            ))
        else:
            dense_pcs = FRI(FRIConfig(
                hash_size_bits=cls._hash_size_bits(config, section),
                rho=section["rho"],
                gap_to_radius=section.get("gap_to_radius"),
                trace_length=section["dense_length"],
                field=field,
                batch_size=section["dense_batch"],
                power_batching=section["power_batching"],
                multilinear_batching=section.get("multilinear_batching", False),
                num_queries=section["num_queries"],
                FRI_folding_factors=section.get("fri_folding_factors"),
                FRI_early_stop_degree=section.get("fri_early_stop_degree"),
                grinding_batching_phase=section.get("grinding_batching_phase", 0),
                grinding_query_phase=section.get("grinding_query_phase", 0),
            ))
        lookups = _parse_lookups_from_toml(section, field)
        return JaggedCircuit(JaggedCircuitConfig(""",
)

# --- jagged.py: read the dense PCS through its getters ---------------------
patch(
    "soundcalc/circuits/jagged.py",
    """    # The configuration for the dense PCS
    dense_pcs: FRI
""",
    """    # The configuration for the dense PCS (FRI, or WHIR for Ziren's inner ring)
    dense_pcs: PCS
""",
)
patch(
    "soundcalc/circuits/jagged.py",
    """    name: str
    dense_pcs: FRI
""",
    """    name: str
    dense_pcs: PCS
""",
)
patch(
    "soundcalc/circuits/jagged.py",
    """        log_trace = ceil(log2(self.dense_pcs.trace_length)) + ceil(log2(self.dense_pcs.batch_size))
        epsilon_RLC""",
    """        log_trace = ceil(log2(self.dense_pcs.get_trace_length())) + ceil(log2(self.dense_pcs.batch_size))
        epsilon_RLC""",
)
patch(
    "soundcalc/circuits/jagged.py",
    """        log_trace = ceil(log2(self.dense_pcs.trace_length)) + ceil(log2(self.dense_pcs.batch_size))
        field_bits""",
    """        log_trace = ceil(log2(self.dense_pcs.get_trace_length())) + ceil(log2(self.dense_pcs.batch_size))
        field_bits""",
)
# The FRI-only summary: delegate when the dense PCS is not FRI.
patch(
    "soundcalc/circuits/jagged.py",
    """        lines = []
        lines.append("")
        lines.append("```")
        params = {
            "hash_size_bits": self.dense_pcs.hash_size_bits,
            "rho": self.dense_pcs.rho,""",
    """        if not isinstance(self.dense_pcs, FRI):
            dense = self.dense_pcs.get_parameter_summary().rstrip()
            assert dense.endswith("```")
            extra = (
                f"  jagged trace_length : {self.trace_length}\\n"
                f"  jagged trace_width  : {self.trace_width}\\n"
            )
            return dense[: -len("```")] + extra + "```"
        lines = []
        lines.append("")
        lines.append("```")
        params = {
            "hash_size_bits": self.dense_pcs.hash_size_bits,
            "rho": self.dense_pcs.rho,""",
)
# Report lines: FRI-specific fields only when the dense PCS is FRI.
patch(
    "soundcalc/circuits/jagged.py",
    """        dense = self._jagged_pcs.dense_pcs
        batching = "Powers" if dense.power_batching else "Affine"
        lines = [""",
    """        dense = self._jagged_pcs.dense_pcs
        if not isinstance(dense, FRI):
            return [
                f"- Proof system: {self.proof_system_name}",
                f"- PCS: {dense.label}",
                *dense.get_report_parameter_lines(),
                f"- Trace length: {self._jagged_pcs.trace_length}",
                f"- Trace width: {self._jagged_pcs.trace_width}",
            ]
        batching = "Powers" if dense.power_batching else "Affine"
        lines = [""",
)
# PCS import for the type hints.
p = os.path.join(root, "soundcalc/circuits/jagged.py")
s = open(p).read()
if "from soundcalc.pcs.pcs import PCS" not in s:
    s = s.replace("from soundcalc.pcs.fri import", "from soundcalc.pcs.pcs import PCS\nfrom soundcalc.pcs.fri import", 1)
    open(p, "w").write(s)
    print("patched import")
