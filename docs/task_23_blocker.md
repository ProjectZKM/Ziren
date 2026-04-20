# Task #23 — Architectural blocker: Ziren-GKR vs SP1-GKR shape mismatch

## TL;DR

The recursion verifier (ported from SP1) and the Ziren shard-level
LogUp-GKR prover speak **different protocols**, not just different
serialisations.  Bridging them requires either a protocol rewrite of
Ziren's GKR backend OR a verifier protocol rewrite — neither is a
"few-line fix".

## Symptom

```
thread '...build_normalize_basefold_program_compiles_dummy_witness' panicked at
  crates/recursion/circuit/src/logup_gkr.rs:105
  assertion `left == right` failed: mle eval vector size must be 2^point.dimension
    left: 1
   right: 16   // = 2^(log_num_interactions + 1) for the AddSub chip
```

## Root cause

The recursion verifier expects `circuit_output.numerator/denominator` to
be MLEs of size `2^(num_interaction_variables + 1)`:

- `crates/recursion/circuit/src/logup_gkr.rs:355` —
  `let initial_num_variables = chip_metadata.log_num_interactions + 1;`
- `crates/recursion/circuit/src/logup_gkr.rs:357` —
  `sample_point::<C, FC>(builder, challenger, initial_num_variables);`
- `crates/recursion/circuit/src/logup_gkr.rs:362` —
  `evaluate_mle_ext::<C>(builder, numerator, &eval_point)` →
  asserts `numerator.len() == 1 << eval_point.len()`.

This is a faithful port of SP1's verifier, where `numerator` is the
**input layer** of the GKR circuit (the layer immediately above the
root), not the root itself.

Ziren's prover, however, emits only the root:

```rust
// crates/stark/src/shard_level/logup_gkr_prover.rs:286-290
LogupGkrProof {
    circuit_output: LogUpGkrOutput {
        numerator: vec![inner_proof.root.0],     // length 1
        denominator: vec![inner_proof.root.1],   // length 1
    },
    ...
}
```

Why?  Ziren's underlying GKR (`crates/stark/src/logup_gkr.rs`) was
designed for the per-chip protocol — it reduces *all* `2^k` leaves
to a single `(numerator, denominator)` root pair via a binary
fraction-sum tree.

SP1's GKR (`/tmp/sp1/crates/hypercube/src/logup_gkr/cpu.rs:78-133`)
reduces only the **row dimension** — it stops when
`num_row_variables == 1`, leaving the **interaction dimension**
(`num_interaction_variables`) intact in the output.  The output is a
length-`2^(num_interaction_variables + 1)` MLE where each entry
corresponds to one of the per-interaction (numerator, denominator)
fractions summed across all rows.

## Why the dummy proof can't paper over this

The recursion verifier samples
`initial_num_variables = log_num_interactions + 1` extension-field
challenges (`logup_gkr.rs:357`) and evaluates the `numerator` /
`denominator` MLE at those `2^4 = 16` points.  Hand-padding the proof's
`circuit_output` to length 16 would silently break protocol soundness:
the entries beyond index 0 would be unconstrained zeros that the
verifier still folds into the per-round GKR sumcheck.

A real proof of correct shape requires the prover to actually
**stop the GKR reduction at row_vars=1**, exposing the interaction-
dimension MLE.  That is a backend-level change, not a serialisation
change.

## Resolution paths

### (A) Port SP1's GKR backend into Ziren stark crate
- **Files:** `crates/stark/src/logup_gkr.rs`, `crates/stark/src/shard_level/logup_gkr_prover.rs`.
- **Work:** ~886 LOC across SP1's
  `logup_gkr/{cpu.rs, execution.rs, prover.rs, proof.rs}`, **plus**
  the slop_* dependencies the port pulls in (see below).
- **Hidden cost:** SP1's GKR backend is built on
  `slop_multilinear::{Mle, PaddedMle, Point}` and
  `slop_sumcheck::reduce_sumcheck_to_evaluation` — neither is
  available in Ziren stark crate.  Ziren has its own `Mle` shape
  (`crates/stark/src/basefold/mle.rs`) and sumcheck
  (`crates/stark/src/zerocheck_prover.rs`) with different APIs.
  Realistic options:
   - (A.1) port the slop_* deps used by the GKR backend (~2-3k LOC,
     1-2 weeks); OR
   - (A.2) rewrite the SP1 GKR algorithm against Ziren's existing
     MLE/sumcheck APIs (~700-1000 LOC of judgement-dense
     translation, 5-7 days).
- **Risk:** Touches the LogUp-GKR algorithm itself.  Wider blast
  radius — also affects per-chip and per-shard provers in the legacy
  path.
- **Effort:** 1-2 weeks (A.1) or 5-7 days (A.2).

### (B) Adapt the recursion verifier to expect Ziren's root-only output
- **Files:** `crates/recursion/circuit/src/logup_gkr.rs:340-470`.
- **Work:** Reframe `verify_logup_gkr` to consume a single
  `(numerator, denominator)` root pair plus a sequence of bottom-up
  per-layer reductions ending at the leaves (Ziren's existing
  `LogUpGkrLayerProof` shape).
- **Risk:** Inverts the SP1 round-proof orientation; breaks the
  existing port's shape contract; requires re-deriving the GKR
  challenges in Ziren's order.
- **Effort:** 3-5 days.

### (C) Drop shard-level recursion entirely; ship per-chip path
- **Status:** Currently in production (default behaviour).  The
  shard-level path is gated behind `--features shard-level-proof`
  and never enabled by default.
- **Effort:** 0 days for this iteration; tasks #21/#13 become
  permanently deferred rather than blocked.

## Recommendation

**Path (A.2)** — rewrite SP1's GKR algorithm against Ziren's existing
MLE/sumcheck APIs (5-7 days, ~700-1000 LOC).  Reasons:
1. Ziren has already committed to SP1's verifier shape (the recursion
   circuit is ported wholesale — `core_basefold.rs`, `compress_basefold.rs`,
   `deferred_basefold.rs`, `wrap_basefold.rs`).  Diverging the
   prover side strands those ports.
2. The existing verifier port is the larger and harder code — keeping
   it stable preserves the work already done.
3. (A.1) — porting all the slop_* dependencies — is 2-3× the work
   for marginal API correspondence benefit; Ziren's MLE/sumcheck
   types already cover the surface SP1's GKR uses.
4. (B) — inverting the verifier port — risks losing soundness
   guarantees from the SP1 protocol audit; (A.2) preserves them.

### Concrete A.2 work breakdown

1. **Layer types** (1 day): port `LogUpGkrCpuLayer<F, EF>`,
   `InteractionLayer<F, EF>`, `GkrCircuitLayer<F, EF>`,
   `LogupGkrCpuCircuit<F, EF>` — using Ziren's `Vec<Vec<EF>>` /
   `Vec<EF>` instead of `PaddedMle`/`Arc<Mle>`.  Translate
   `num_row_variables` × `num_interaction_variables` indexing.
2. **First-layer generator** (1.5 days): port
   `generate_first_layer` from
   `/tmp/sp1/crates/hypercube/src/logup_gkr/execution.rs:110-382`
   — rewrites `(numerator_0, numerator_1, denominator_0, denominator_1)`
   from raw chip interactions + traces.  Pads each chip's table to
   the shared `(num_row_variables, num_interaction_variables)` shape.
3. **Layer transition** (1 day): port `layer_transition` — halves
   the row dimension by combining adjacent row pairs via the
   fraction-sum operation.  Keeps interaction dimension intact.
4. **Output extraction** (0.5 day): port `extract_outputs` from
   `execution.rs:39-108` — interleaves the four
   `(numerator_0/1, denominator_0/1)` MLEs into a single
   `2^(num_interaction_variables+1)`-length output MLE pair.
5. **Per-round sumcheck** (1.5 days): port `prove_gkr_round` from
   `cpu.rs:151-227` — wraps Ziren's `prove_sumcheck` from
   `crates/stark/src/zerocheck_prover.rs` to consume a
   `LogupRoundPolynomial` shape with the eq_row × eq_interaction
   product structure.
6. **Top-level prove** (0.5 day): rewrite
   `prove_shard_logup_gkr` (`logup_gkr_prover.rs:190-295`) to
   call the new pipeline instead of `prove_logup_gkr_inner`.
7. **Smoke test re-enable + integration** (0.5-1 day): drop the
   `#[ignore]` from `build_normalize_basefold_program_compiles_dummy_witness`
   and iterate against any remaining mismatches.

## Status

- Smoke test (`build_normalize_basefold_program_compiles_dummy_witness`)
  is `#[ignore]`d with the diagnosis pinned in its docstring.
- Real-fixture path (`produce_real_basefold_shard_proof`) is wired
  through `prove_shard_to_basefold` and exercises the current
  prover/verifier mismatch immediately.
- Tasks #21 (default-on) and #13 (legacy retire) remain blocked
  behind this resolution.
