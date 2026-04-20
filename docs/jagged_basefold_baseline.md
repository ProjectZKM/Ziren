# Jagged PCS + BaseFold Performance Baseline

Captured 2026-04-19 on feat/upgrade-plonky3 (commit aee5467).

Production build with `basefold` feature; prover emits real
BaseFold proofs via `prove_jagged_basefold_dispatch`; host verifier
accepts them via the `whir_mode` short-circuit branch.

| Example | Cycles | e2e Wall | Throughput | Proof Size |
|---|---|---|---|---|
| fibonacci | 8,288 | 8.28 s | 1.00 kHz | 4.97 MB |
| keccak-precompile | 16,153 | 19.54 s | 0.83 kHz | 7.80 MB |

Both examples prove-and-verify successfully.  Aggregation /
recursion-circuit paths not exercised by these examples (single-
shard proof-and-verify only).

## Notes

- Fibonacci: 8 `commit_deferred_proofs` syscalls + 1 `sha_compress` +
  1 `sha_extend` — minimal non-arithmetic surface.
- Keccak: 1 `keccak_sponge` syscall dominates; 2 `sha_compress` +
  2 `sha_extend` for input handling.
- Proof size scales ~1.57x between the two examples (4.97→7.80 MB)
  for ~1.95x cycle ratio — proof size is more a function of shard
  count / chip count than raw cycle count.

## Post-LogUp-GKR-recursion landing (commit 26bfec3)

Re-measured after the recursion verifier started binding the
LogUp-GKR soundness chain (root → layered descent → leaf claim)
inside the recursion circuit.  Adds zero-cost overhead at the
host-prover-verify level (the new code lives behind the
`StarkVerifier::verify_shard` recursion path, not the host
verifier path).

| Example | e2e Wall | Δ vs baseline |
|---|---|---|
| fibonacci | 8.60 s | +0.32 s (+4%, within noise) |
| keccak-precompile | 18.97 s | -0.57 s (-3%, within noise) |

Both examples continue to prove-and-verify successfully.

## Post-zerocheck-binding landing (commit a2ca1e3)

Re-measured after both LogUp-GKR and zerocheck soundness chains
became bound inside the recursion circuit (chips with
permutation_width > 0 get empty zerocheck placeholders matching
the prover's pattern; the rest get full log_degree-rounds binding).

| Example | e2e Wall | Δ vs baseline |
|---|---|---|
| fibonacci | 8.34 s | +0.06 s (+1%, within noise) |
| keccak-precompile | 19.44 s | -0.10 s (-1%, within noise) |

Performance stable across 3 measurement rounds throughout the
session.  The new in-circuit verification only fires inside the
recursion circuit's `StarkVerifier::verify_shard`, not the host
verify path that these examples test.
