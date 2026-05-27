# Shard-Level Proof Pipeline

This module implements the shard-level proof shape — one
`LogupGkrProof` + one `PartialSumcheckProof` + one jagged-PCS
opening per shard, instead of Ziren's legacy per-chip lists.

Always-on for KoalaBear MIPS shards (no feature gate). The
`BasefoldShardProof` rides as a side-channel field on
`ShardProof<SC>`; the verifier dispatches to
`BasefoldShardVerifier::verify_shard` when it's populated and falls
through to the legacy STARK path otherwise.

## Module map

| Module | Purpose |
|---|---|
| `types` | Pure data: `LogupGkrProof`, `PartialSumcheckProof`, `LogUpEvaluations`, `ChipEvaluation`, `LogUpGkrOutput`, `LogupGkrRoundProof`, `UnivariatePolynomial` |
| `shard_proof` | Host-side `BasefoldShardProof<F, EF>` |
| `logup_gkr_prover` | Legacy (fraction-tree) per-chip LogUp-GKR prover + helpers; kept for interop |
| `zerocheck_prover` | Shard-level zerocheck prover + helpers (lambda-RLC of per-chip C-tables, sumcheck driver, optional GPU batched pre-pass) |
| `row_gkr/` | Row-only LogUp-GKR backend — `layer.rs`, `first_layer.rs`, `transition.rs`, `extract.rs`, `build.rs`, `round.rs`, `top_level.rs` |
| `prover` | Top-level orchestrator `prove_shard_to_basefold` + SDK wiring `try_prove_shard_to_basefold_boxed` |
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

## Cutover model

`ShardProof<SC>` carries the side-channel field unconditionally:

```rust
#[serde(default)]
pub basefold_shard_proof: Option<Box<BasefoldShardProof<Val<SC>, Challenge<SC>>>>,
```

- **KoalaBear MIPS shards**: `basefold_shard_proof = Some(_)`; the
  verifier dispatches to `BasefoldShardVerifier::verify_shard`.
- **Compress / non-KoalaBear configs**: `basefold_shard_proof = None`;
  `Verifier::verify_shard` runs the legacy STARK code path. Those
  proofs aren't BaseFold shard proofs and the legacy verifier is the
  correct one for them.

KoalaBear gating is via runtime `TypeId::of::<SC::Challenger>()`
check inside `try_prove_shard_to_basefold_boxed`.

## Usage

```rust
use zkm_stark::shard_level::prover::prove_shard_to_basefold;
use zkm_stark::shard_level::shard_proof::FoldOrientation;
use zkm_stark::shard_level::verifier::BasefoldShardVerifier;

// Prove
let proof = prove_shard_to_basefold::<SC, A>(
    &chips,
    &preprocessed_traces,
    &main_traces,
    main_commitment,
    public_values,
    max_log_row_count,
    &mut challenger,
    None,                  // device_traces: host-only here
    FoldOrientation::Msb,
);
// proof: BasefoldShardProof<F, EF>

// Verify
let verifier = BasefoldShardVerifier::production_default();
verifier.verify_shard::<SC, A>(&vk, &chips, &proof, &mut challenger, num_pv_elts)?;
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

- `row_gkr`: unit tests on layer types, first-layer generation,
  transitions, extraction, sumcheck rounds, build orchestrator
  (`prove_gkr_round_*`, etc.)
- `verifier`: unit tests for construction, error display
- `shard_proof`: rmp round-trip, empty/large pv-count, fold-orientation
- Recursion smoke: `build_normalize_basefold_program_*` in
  `crates/recursion/circuit/src/machine/basefold_programs.rs`
  exercises the full in-circuit pipeline against a real
  `prove_shard_to_basefold`-emitted proof.
