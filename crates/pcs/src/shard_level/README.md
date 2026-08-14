# Shard-Level Proof Pipeline

This module implements the shard-level proof shape — one
`LogupGkrProof` + one `PartialSumcheckProof` + one jagged-PCS
opening per shard, instead of per-chip proof lists.

Always-on (no feature gate). The `BasefoldShardProof` rides as the
payload field on `ShardProof<SC>`; a shard proof without one is
malformed and the verifier rejects it — there is no other verify
path.

## Module map

| Module | Purpose |
|---|---|
| `types` | Pure data: `LogupGkrProof`, `PartialSumcheckProof`, `LogUpEvaluations`, `ChipEvaluation`, `LogUpGkrOutput`, `LogupGkrRoundProof`, `UnivariatePolynomial` |
| `shard_proof` | Host-side `BasefoldShardProof<F, EF>` |
| `logup_gkr_prover` | Trace-MLE evaluation helpers for the LogUp-GKR openings |
| `zerocheck_prover` | Shard-level zerocheck prover (per-chip lazy `ZeroCheckPoly`, claims chained to the GKR openings) |
| `zerocheck_poly` | The per-chip `ZeroCheckPoly` round machinery (`VirtualGeq`, eq-root reconstruction) |
| `sumcheck_poly` | Generic sumcheck driver `reduce_sumcheck_to_evaluation` + the sumcheck-poly traits |
| `row_gkr/` | Row-only LogUp-GKR backend — `layer.rs`, `first_layer.rs`, `transition.rs`, `extract.rs`, `build.rs`, `round.rs`, `top_level.rs` |
| `prover` | Top-level orchestrator `prove_shard_with_data` + the commit builder `commit_traces` |
| `verifier` | Host-side `BasefoldShardVerifier` with 4-phase verification |

## Pipeline (prover → verifier)

```
                       shard traces + VK
                            │
                            ▼
  ┌──────────────────────────────────────────────────┐
  │ prove_shard_with_data (host)                     │
  │   commit: consume commit()'s retained jagged     │
  │           commitment (or build via commit_traces)│
  │   Phase 1: transcript prologue                   │
  │   Phase 2: LogUp-GKR sumcheck (row_gkr backend)  │
  │   Phase 3: zerocheck sumcheck                    │
  │   Phase 4: jagged-PCS opening                    │
  │   Output: BasefoldShardProof<F, EF>              │
  └──────────────────────────────────────────────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼                           ▼
  ┌─────────────────────┐      ┌────────────────────────────┐
  │ Host verification   │      │ In-circuit verification    │
  │ BasefoldShard-      │      │ recursion-circuit          │
  │ Verifier (this mod) │      │ BasefoldShardVerifier      │
  └─────────────────────┘      └────────────────────────────┘
```

The host and in-circuit verifiers are kept in lockstep by running
the same 4 phases in the same challenger ordering.

## Entry points

The driver is dispatched through the prover itself
(`MachineProver::prove_shard_with_data` on `CpuProver`, with
`commit_multilinears` / `prove_trusted_evaluations` as the
`StarkGpuProver` override seams).  Both rings (inner
KoalaBear/Poseidon2 and the outer BN254 wrap) prove through this
pipeline; the per-ring jagged open is dispatched statically via
`BasefoldRing::prove_jagged_open`.

The recursion-circuit counterpart lives at
`crates/recursion/circuit/src/shard_level_witness.rs` (host→circuit
lift) and `crates/recursion/circuit/src/shard_basefold.rs`
(in-circuit `BasefoldShardVerifier`).

## Phase implementation

| Phase | Host | In-circuit |
|---|---|---|
| 1 — transcript prologue | `verifier.rs` | `shard_basefold.rs` |
| 2 — LogUp-GKR sumcheck | `verify_logup_gkr_host` | `verify_logup_gkr` |
| 3 — zerocheck | `verify_zerocheck_host` (incl. the constraint-RLC hard check via the host `BasefoldConstraintFolder`) | `BasefoldZerocheckVerifier` |
| 4 — jagged-PCS opening | `verify_jagged_pcs_host` | `verify_trusted_evaluations` |

## Test coverage

- `row_gkr`: unit tests on layer types, first-layer generation,
  transitions, extraction, sumcheck rounds, build orchestrator
  (`prove_gkr_round_*`, etc.)
- `verifier`: unit tests for construction, error display
- `shard_proof`: rmp round-trip, empty/large pv-count, fold-orientation
- Recursion smoke: `build_normalize_basefold_program_*` in
  `crates/recursion/circuit/src/machine/basefold_programs.rs`
  exercises the full in-circuit pipeline against a real
  `prove_shard_with_data`-emitted proof.
