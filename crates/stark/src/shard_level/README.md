# SP1-style Shard-Level Proof Pipeline (Parallel Codebase)

This module hosts the SP1-style shard-level proof shape — one
`LogupGkrProof` + one `PartialSumcheckProof` per shard, instead
of Ziren's default per-chip lists.  Default-off via the
`shard-level-proof` Cargo feature.

## Module map

| Module | Purpose |
|---|---|
| `types` | Pure data: `LogupGkrProof`, `PartialSumcheckProof`, `LogUpEvaluations`, `ChipEvaluation`, `LogUpGkrOutput`, `LogupGkrRoundProof`, `UnivariatePolynomial` |
| `shard_proof` | Host-side `BasefoldShardProof<F, EF>` — the SP1-shape 6-field proof |
| `logup_gkr_prover` | Shard-level LogUp-GKR prover + helpers (`aggregate_chip_leaves`, `evaluate_trace_columns_at_point`, `prove_shard_logup_gkr`, `ziren_layer_to_sp1_round`) |
| `zerocheck_prover` | Shard-level zerocheck prover + helpers (`combine_two_tables`, `pad_chip_table`, `samples_to_monomial_degree_2`, `prove_shard_zerocheck`) |
| `prover` | Top-level orchestrator `prove_shard_to_basefold` — the SP1-style assembly entry point |

## Usage

Enable the feature in your `Cargo.toml`:

```toml
zkm-stark = { ..., features = ["shard-level-proof"] }
```

Construct a proof:

```rust
use zkm_stark::shard_level::prover::prove_shard_to_basefold;

let proof = prove_shard_to_basefold::<SC, A>(
    &chips,
    &preprocessed_traces,
    &main_traces,
    main_commitment,
    public_values,
    &mut challenger,
);
// proof: BasefoldShardProof<F, EF>
```

The recursion-circuit-side counterpart lives at
`crates/recursion/circuit/src/shard_level_witness.rs` and bridges
the host-side proof into the in-circuit
`BasefoldShardProofVariable`.

## Status

All four recursion machine stages have parallel SP1-style
verifiers under the same feature flag:

- `crates/recursion/circuit/src/machine/compress_basefold.rs`
- `crates/recursion/circuit/src/machine/deferred_basefold.rs`
- `crates/recursion/circuit/src/machine/wrap_basefold.rs`
- `crates/recursion/circuit/src/machine/core_basefold.rs`

Each calls `BasefoldShardVerifier::verify_shard` end-to-end on
the new proof shape.

See `docs/sp1_shard_proof_port_status.md` for the complete
60-iteration build log and pending follow-ups.
