# Shard-Level Proof Pipeline

This module implements the shard-level proof shape — one
`LogupGkrProof` + one `PartialSumcheckProof` + one jagged-PCS
opening per shard, instead of Ziren's legacy per-chip lists.

**Status: structurally complete end-to-end.** Enabled by default
via the `shard-level-proof` Cargo feature (`default = ["shard-level-proof"]`
as of task #21).  Production cutover coexists with the legacy
per-chip path via a dual-path compat shim on `ShardProof<SC>`; see
"Cutover model" below.

## Module map

| Module | Purpose |
|---|---|
| `types` | Pure data: `LogupGkrProof`, `PartialSumcheckProof`, `LogUpEvaluations`, `ChipEvaluation`, `LogUpGkrOutput`, `LogupGkrRoundProof`, `UnivariatePolynomial` |
| `shard_proof` | Host-side `BasefoldShardProof<F, EF>` — the 6-field shard proof |
| `logup_gkr_prover` | Legacy (fraction-tree) per-chip LogUp-GKR prover + helpers; kept for interop |
| `zerocheck_prover` | Shard-level zerocheck prover + helpers |
| `row_gkr/` | Row-only LogUp-GKR backend — `layer.rs`, `first_layer.rs`, `transition.rs`, `extract.rs`, `build.rs`, `round.rs`, `top_level.rs` (30 unit tests) |
| `prover` | Top-level orchestrator `prove_shard_to_basefold` + opt-in SDK wiring `try_prove_shard_to_basefold_boxed` |
| `verifier` | Host-side `BasefoldShardVerifier` with 4-phase verification |

## Pipeline (prover → verifier)

```
                       shard traces + VK
                            │
                            ▼
  ┌──────────────────────────────────────────────────┐
  │ prove_shard_to_basefold (host)                   │
  │   Phase 1: transcript prologue                   │
  │   Phase 2: LogUp-GKR sumcheck (row_gkr backend)  │
  │   Phase 3: zerocheck sumcheck                    │
  │   Phase 4: jagged-PCS opening (LbChallenger)     │
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

## Cutover model (task #28)

`ShardProof<SC>` carries a new feature-gated field:

```rust
#[cfg(feature = "shard-level-proof")]
#[serde(default)]
pub basefold_shard_proof: Option<Box<BasefoldShardProof<Val<SC>, Challenge<SC>>>>,
```

- **Legacy path**: `basefold_shard_proof = None`; `zerocheck_proofs`
  / `logup_gkr_proofs` / `logup_row_openings` / `late_binding_proofs`
  carry the per-chip proofs.  `StarkVerifier::verify_shard` runs
  the legacy verifier.
- **Shard-level path**: `basefold_shard_proof = Some(_)`; verifier
  dispatches to `BasefoldShardVerifier::verify_shard`.

**Prover opt-in**: set `ZIREN_SHARD_LEVEL_BASEFOLD=1` to populate
`basefold_shard_proof` alongside the legacy fields (non-destructive
— both coexist in the envelope).  Gated on `SC == KoalaBearPoseidon2`
via runtime `TypeId::of::<SC::Challenger>()` check.

## Usage

Default build already includes `shard-level-proof`:

```rust
use zkm_stark::shard_level::prover::prove_shard_to_basefold;
use zkm_stark::shard_level::verifier::BasefoldShardVerifier;

// Prove
let proof = prove_shard_to_basefold::<SC, A>(
    &chips,
    &preprocessed_traces,
    &main_traces,
    main_commitment,
    public_values,
    &mut challenger,
);
// proof: BasefoldShardProof<F, EF>

// Verify
let verifier = BasefoldShardVerifier::production_default();
verifier.verify_shard::<SC, A>(
    &vk,
    &chips,
    &proof,
    &mut challenger,
    num_pv_elts,
)?;
```

The recursion-circuit counterpart lives at
`crates/recursion/circuit/src/shard_level_witness.rs` (host→circuit
lift) and `crates/recursion/circuit/src/shard_basefold.rs`
(in-circuit `BasefoldShardVerifier`).

## Phase implementation status

| Phase | Host | In-circuit |
|---|---|---|
| 1 — transcript prologue | ✅ `verifier.rs` | ✅ `shard_basefold.rs` |
| 2 — LogUp-GKR sumcheck | ✅ `verify_logup_gkr_host` | ✅ `verify_logup_gkr` |
| 3 — zerocheck | ✅ structural (sumcheck + shape); constraint-folder identity deferred | ✅ `BasefoldZerocheckVerifier` |
| 4 — jagged-PCS opening | ✅ delegates to `verify_jagged_basefold` | ✅ `verify_trusted_evaluations` |

**Phase 3 deferred**: `BasefoldConstraintFolder` host port — needed
for the cross-chip RLC identity check (step 4g–5 of the in-circuit
version) and GKR sum-modification identity (step 6–7).  The sumcheck
itself + all shape invariants + transcript binding are fully
verified.  Structural smoke is green; full cryptographic soundness
requires this port.

## Test coverage

- `row_gkr`: 30 unit tests (layer types, first-layer generation,
  transitions, extraction, sumcheck rounds, build orchestrator)
- `verifier`: 4 unit tests (construction, error display)
- Recursion smoke: `build_normalize_basefold_program_compiles_dummy_witness`
  at `crates/recursion/circuit/src/machine/basefold_programs.rs:385`
  exercises the full in-circuit pipeline against a real
  `prove_shard_to_basefold`-emitted proof.

## Related tasks

- #18-#22: Initial scope — host types, prover orchestration,
  recursion machine ports.
- #23: End-to-end smoke test (green).
- #24: Row-only GKR backend port (closed the protocol-mismatch documented
  in `docs/task_23_blocker.md`).
- #25: zerocheck permutation short-circuit + jagged-PCS single-chip
  fixes.
- #26/#27: Real jagged-PCS bytes emission + lift adapter.
- #28: SDK cutover — dual-path compat shim, prover populator,
  verifier dispatch.
- #29/#30/#31: Host verifier phases 2/3/4.
- **Pending #13**: retire legacy per-chip `ShardProof` fields once
  the shard-level path is validated on production workloads.
