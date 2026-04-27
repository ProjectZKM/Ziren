# Phase 2 Gate 3 Analysis — recursive_stacked_pcs batch_dim mismatch

Scoped analysis of the compose-tree shape blocker discovered Apr 24.  Documents the precise failure mode, the code sites, and candidate fix shapes for the next focused session.

## Failure symptom

`collect_basefold_vks --workload-dir /data/stephen/ziren-shape-bin --workload fibonacci-1k` (4 shards) under Phase 2 v2 + META #59 Phase A-D panics at:

```
thread '<unnamed>' panicked at crates/recursion/circuit/src/logup_gkr.rs:105:5:
assertion `left == right` failed: mle eval vector size must be 2^point.dimension
  left: 1024
  right: 512
```

Called from `recursive_stacked_pcs.rs:156` via `evaluate_mle_ext(&batch_evals_flat, batch_point)`.

## Code sites

### Verifier (recursion circuit)

`crates/recursion/circuit/src/recursive_stacked_pcs.rs:95-157` — `verify_untrusted_evaluation`:

```rust
let stack_dim = self.log_stacking_height as usize;
let mut padded_point: Vec<Ext<C::F, C::EF>> = point.to_vec();
if padded_point.len() < stack_dim {
    // TODO(D2 cutover): unsound zero-pad
    while padded_point.len() < stack_dim {
        padded_point.push(builder.constant(C::EF::ZERO));
    }
}
let total_dim = padded_point.len();
let batch_dim = total_dim - stack_dim;
let (batch_point, stack_point) = padded_point.split_at(batch_dim);

let batch_evals_flat: Vec<Ext<C::F, C::EF>> = proof
    .batch_evaluations
    .iter()
    .flatten()
    .copied()
    .collect();
assert_eq!(batch_evals_flat.len(), 1 << batch_dim);  // FAILS HERE

let expected_evaluation =
    evaluate_mle_ext::<C>(builder, &batch_evals_flat, batch_point);
```

### Prover (stark stacked PCS)

`crates/stark/src/basefold/stacked.rs:174-184` — `round_batch_evaluations`:

```rust
pub fn round_batch_evaluations(
    &self,
    stack_point: &[EF],
    prover_data: &StackedBasefoldProverData<F, MT>,
) -> Vec<EF> {
    prover_data
        .interleaved_mles
        .iter()
        .flat_map(|mle| mle.eval_at::<EF>(stack_point))
        .collect()
}
```

Called at line 224-227:

```rust
let batch_evaluations: Vec<Vec<EF>> = prover_data
    .iter()
    .map(|d| self.round_batch_evaluations(&stack_point, d))
    .collect();
```

So `batch_evaluations.len() = prover_data.len()` (number of rounds) and each inner Vec has length = sum over `interleaved_mles[round]` of `mle.eval_at(stack_point).len()`.

**Total `batch_evals_flat.len()` = Σ over rounds of (Σ over interleaved_mles in round of len(mle.eval_at))**

## Invariant expected by assertion

`batch_evals_flat.len() == 2^batch_dim` where `batch_dim = padded_point.len() - stack_dim`.

For single-shard workloads where `point.len() < stack_dim`, `padded_point = stack_dim` (via zero-pad) → `batch_dim = 0` → expected `batch_evals_flat.len() = 1`.  Yet we see length > 1 even for small workloads — suggests the zero-pad path isn't what we think, OR point.len() ≥ stack_dim on multi-shard.

For multi-shard fib-1k (4 shards) observed: batch_evals_flat.len()=1024, batch_dim=9 → expected 512.  Reality is 2× expected.

## Root-cause hypotheses (ranked)

### H1 (most likely): the prover's `point` for shard-level proofs doesn't match what stacked PCS expects

The comment at line 118-125 says:
> shard-level basefold prover currently emits a sumcheck point of length = log2(actual_trace_cells), not log_total_area.  When point.len() < log_stacking_height, pad with zero-extension Ext values ... unsound

The prover at `crates/stark/src/basefold_late_binding.rs` / `crates/stark/src/basefold/prover.rs` emits the sumcheck point at the basefold opening level (1 point per opening call).  The stacked PCS wrapping adds the `stack_point` prefix.

**If prover computes `point` as log2(actual_cells)** but **stacked PCS expects `point.len() = log_total_area = log_row + log_col`**, then for any workload with nonzero log_col, the split gives wrong batch_dim.

### H2: interleaving factor off by 1

`interleave_multilinears_with_fixed_rate(batch_size, multilinears, log_stacking_height)` may produce twice as many interleaved_mles as expected, doubling the batch_evaluations per round.  Could be an off-by-one in `batch_size` vs `log_stacking_height` interpretation.

### H3: multi-shard stacking adds a shard-selector dimension not accounted for

When compose tree aggregates N shards, the aggregated commitment may implicitly add `log2(N)` dims to the batch axis.  The verifier doesn't account for this.

## Candidate fixes (each needs protocol review)

### Fix A (cleanest): align prover point dimension with verifier expectation
- Modify `prove_trusted_evaluation` in `stacked.rs` to compute `eval_point` of length `log_total_area`
- `log_total_area = log_row + log_col` where `log_col = ceil(log2(max_cols_across_mles))`
- Verifier removes the unsound zero-pad
- Soundness: the point must be sampled from the challenger for EVERY coordinate; the zero-pad isn't sound

### Fix B (verifier-side): compute batch_dim from batch_evals_flat.len()
- Replace `let batch_dim = total_dim - stack_dim;` with `let batch_dim = (batch_evals_flat.len().trailing_zeros()) as usize;`
- Require `batch_evals_flat.len().is_power_of_two()` (keep the assertion in that form)
- Derive `batch_point` by splitting `padded_point` at the correct offset
- Still unsound if prover emits wrong point dim

### Fix C (soundness-safe): audit the prover's Fiat-Shamir and derive actual log_total_area
- Check `crates/stark/src/basefold/stacked.rs:prove_trusted_evaluation` for correct challenger sampling at `log_total_area` coords
- If prover samples fewer coords than log_total_area, fix prover; verifier then works without padding
- **This is the proper fix — the unsound pad is a warning that the protocol is incomplete.**

## Validation plan (post-fix)

1. `cargo test -p zkm-prover -- test_e2e_compress_fibonacci --ignored` — single-shard still passes (Phase 1 green)
2. `cargo run --bin collect_basefold_vks -- --workload-dir /data/stephen/ziren-shape-bin --workload fibonacci-1k` — multi-shard basefold path completes without panic
3. Update `write_basefold_vk_map.rs::HASHES[1]` with the new multi-shard cluster hash
4. Regen `vk_map.bin` with v-comment cache bust (see `project_meta_59_apr24_plumbing.md` gotcha)
5. `VERIFY_VK=true` test against both single-shard and multi-shard

## Estimated effort

- Fix A + validation: 1-2 days (requires SP1 upstream comparison for reference)
- Fix B + validation: 0.5 day (unsound; only for debugging)
- Fix C + validation: 1-3 days (deep protocol audit but the correct long-term answer)

## Why Apr 24 auto-mode didn't attempt these

Auto-mode rule: don't modify soundness-critical code without protocol-design review.  The unsound zero-pad comment on line 122 explicitly flags this area as needing protocol work.  Fix B is superficially tempting but papers over a soundness hole.  Fix A/C are the correct paths but require expertise that auto-mode doesn't have access to without human-in-the-loop review.

## Apr 24 — Attempted Fix B and Fix A, both reverted

### Fix B attempt (recursive_stacked_pcs.rs, infer batch_dim from batch_evals_flat.len())
**Result**: Phase 1 stayed GREEN (154.19s VERIFY_VK=true) but multi-shard STILL FAILED at a different site: `recursive_jagged_pcs.rs:227`'s `evaluate_mle_ext(&column_claims, &z_col)` (column_claims.len()=1024 vs 2^z_col.len()=512).  Fix B bypassed the first assertion but the same root cause (mismatched dim between flattened per-round evals and single-round sample point) fires at a deeper call site.

### Fix A extension attempt (recursive_jagged_pcs.rs, extend num_col_variables by log2(num_rounds))
**Result**: BROKE Phase 1.  Sampling additional challenger bits at `z_col` changes the Fiat-Shamir transcript; the prover wasn't similarly modified → transcript desync → downstream proof verification fails.  Cannot be done verifier-side alone.

### Conclusion
Both symptom sites need a coordinated prover+verifier change (Fix A or Fix C from the candidate list).  The prover-side change must emit the right dimension at the right transcript point; the verifier-side must sample matching challenges.  **This is strictly a 2-sided protocol change — verifier-only patches create transcript desync that breaks even the single-shard case.**

The proper fix path: study SP1's `/tmp/sp1/crates/recursion/circuit/src/basefold/{stacked,jagged}.rs` + corresponding prover side to see how the per-round jagged-PCS composes with stacked PCS transcript.

## SP1 upstream comparison (Apr 24 after clone)

SP1 source cloned to `/tmp/sp1`.  Key findings:

### SP1's `jagged/verifier.rs` — identical num_col_variables formula

SP1's `crates/recursion/circuit/src/jagged/verifier.rs:70`:
```rust
let num_col_variables = (params.col_prefix_sums.len() - 1).next_power_of_two().ilog2();
```

Ziren's `recursive_jagged_pcs.rs:179` uses the SAME formula.  So the computation is matched.

### SP1's `stacked.rs` — NO zero-pad on point

SP1's `crates/recursion/circuit/src/basefold/stacked.rs:38-39`:
```rust
let (batch_point, stack_point) =
    point.split_at(point.dimension() - self.log_stacking_height as usize);
```

**SP1 does NOT zero-pad the point.**  It ASSUMES `point.dimension() >= log_stacking_height`.  Ziren's zero-pad is a band-aid for prover-side shortcoming.

### SP1 invariant: prover ensures `1 << point.dimension() == total_data_length`

SP1's `stacked.rs:110-111` (test):
```rust
let total_number_of_variables = total_data_length.next_power_of_two().ilog2();
assert_eq!(1 << total_number_of_variables, total_data_length);
```

The prover EXPLICITLY asserts that the committed data is a power-of-two length, and the point dimension = log2(length).

### Fix target (now precise)

The prover's `params.col_prefix_sums` in Ziren must cover ALL columns across ALL rounds when doing multi-shard composition — so that:
- `num_cols = params.col_prefix_sums.len() - 1` = total columns across all shards
- column_claims (flattened per-round) has length = num_cols_after_zero_pad
- num_col_variables = log2(next_pow2(num_cols_total))
- z_col samples num_col_variables challenges
- column_claims.len() after pad = 2^num_col_variables

**Location to fix** (prover side): wherever `JaggedLittlePolynomialVerifierParams` (Ziren: `crates/stark/src/basefold/jagged_per_chip/poly.rs:95+`) is constructed for the multi-shard case.  The `col_prefix_sums` must be CUMULATIVE across all rounds, not per-round.

**Corresponding Ziren site to audit**:
- `crates/stark/src/basefold_late_binding.rs` — produces the proof for multi-round
- `crates/stark/src/basefold/jagged_per_chip/mod.rs::prove_jagged_basefold*` — check params construction
- Prover must assemble `col_prefix_sums` concatenated across shards

### Recommended fix (Apr 24 v13, next session)

1. In `prove_jagged_basefold_dispatch` (`basefold_late_binding.rs:544`): when processing multi-round (multi-shard) input, construct `col_prefix_sums` by concatenating per-shard prefix sums (with shard_0's offset carried through to shard_1's starting point).
2. Ensure prover's point sampling uses `log2(total_area_across_shards)` coords, not `log2(single_shard_area)`.
3. Remove the verifier's unsound zero-pad at `recursive_stacked_pcs.rs:128-133` (no longer needed).
4. Verifier asserts `point.dimension() >= log_stacking_height` hard (matches SP1).

Each step should be tested under VERIFY_VK=true with cache-bust comment bump.

## Apr 24 late: deeper finding — PER-SHARD failure, not multi-shard aggregation

Running multi-shard fib-1k with the v9 diagnostic confirms the assertion fires at `logup_gkr.rs:105` (called from `recursive_jagged_pcs.rs:227`) with `column_claims.len()=1024 vs 2^z_col.len()=512`.

**Critical observation**: this is PER-SHARD verification.  The compose tree verifies each shard independently.  The failing assertion is inside ONE shard's basefold verifier, not the compose aggregation.

So the real problem is:
- `test_fib_workload` (single shard, 3549 cycles): column_claims.len() happens to equal 2^num_col_variables → passes
- `ziren-shape-bin/fibonacci-1k` shards (larger): column_claims.len() > 2^num_col_variables → fails

Specifically: for the failing shard, `num_col_variables = (params.col_prefix_sums.len() - 1).next_power_of_two().ilog2() = 9`, but after flattening + per-round zero-pad + next-pow-2 pad, column_claims.len() = 1024 = 2^10.

**Root cause is now per-shard**: `params.col_prefix_sums` doesn't reflect the actual column count after the per-round zero-column padding added at lines 212-217.  Specifically, line 215 adds `num_added` zero columns per round.  These zero columns increase `column_claims.len()` but aren't counted in `params.col_prefix_sums.len() - 1`.

### Narrow v13 fix (less scope than full protocol rewrite)

Adjust `num_col_variables` to account for zero-column padding:

```rust
let num_cols = params.col_prefix_sums.len() - 1;
let num_rounds = column_counts.len();
// Each round adds 1 zero column (per the padding convention).
let num_cols_with_padding = num_cols + num_rounds;
let num_col_variables = num_cols_with_padding.next_power_of_two().trailing_zeros() as usize;
```

But wait — this changes Fiat-Shamir (`z_col` sampled with different count).  Prover must match.  Check SP1's upstream `jagged.rs` — do they add `+ num_rounds` to num_cols?

Looking at SP1 `jagged.rs:70`:
```rust
let num_col_variables = (params.col_prefix_sums.len() - 1).next_power_of_two().ilog2();
```

**Same as Ziren**.  So SP1 doesn't adjust for zero-column padding either.

**Therefore**: SP1's prover must construct `params.col_prefix_sums` with the zero columns ALREADY INCLUDED.  Ziren's prover does NOT include them.  That's the protocol-level divergence.

### Final v13 fix (narrower than initially scoped)

In Ziren's prover (`crates/stark/src/basefold/jagged_per_chip/...`): when constructing `JaggedLittlePolynomialProverParams`, include the per-round zero-column padding in the flat row_counts vector before building prefix sums.  This makes `params.col_prefix_sums.len() - 1 = num_cols + num_rounds`, matching the verifier's expected z_col dim after the per-round zero-column insertion.

This is a prover-side change ONLY — verifier stays exactly as SP1.  No Fiat-Shamir change.  Contained to `JaggedLittlePolynomialProverParams::new` (or its caller) to include zero-column row counts.

Estimated effort: **2-4 hours** (narrower than previous 0.5-3 days estimate now that root cause is precise).

## Call chain to the failing assertion (Apr 24 trace)

```
recursion_program_basefold  (compose tree calls this per shard)
  → verify_core_basefold  (core_basefold.rs)
    → BasefoldShardVerifier::verify_shard  (via shard_basefold.rs)
      → BasefoldShardVerifier phase 4 (jagged PCS opening)
        → RecursiveJaggedPcsVerifier::verify_trusted_evaluations
          → RecursiveStackedPcsVerifier::verify_untrusted_evaluation  ← ASSERTION FAILS HERE
            → evaluate_mle_ext  (recursive_stacked_pcs.rs:156 → logup_gkr.rs:105)
```

The `evaluation_point` passed at `recursive_jagged_pcs.rs:284` is
`sumcheck_proof.point_and_eval.0.clone()` — the sumcheck's reduction
point.  Its length depends on the sumcheck tree's total variable count,
which for multi-shard workloads must match what the stacked PCS expects.

## References

- SP1 upstream (reference implementation):
  - `/tmp/sp1/crates/recursion/circuit/src/basefold/stacked.rs:27-58` — verify_untrusted_evaluation
  - `/tmp/sp1/crates/recursion/circuit/src/sumcheck/mod.rs:56-62` — evaluate_mle_ext
  - `/tmp/sp1/crates/recursion/circuit/src/basefold/jagged.rs` — RecursiveJaggedPcsVerifier reference
- Ziren sites to audit in Fix A:
  - `crates/recursion/circuit/src/recursive_jagged_pcs.rs:282-291` — call site
  - `crates/recursion/circuit/src/recursive_stacked_pcs.rs:118-152` — the unsound pad + assertion
  - `crates/stark/src/basefold/stacked.rs:202-243` — prover's prove_trusted_evaluation
  - `crates/stark/src/basefold/jagged_per_chip/mod.rs:95+` — per-chip sumcheck reduction
- Ziren docs:
  - `docs/meta_59_design.md` — the coordinated prover+verifier Phase C swap (analogous pattern for cumulative_sums)
  - `docs/d2_phased_results_apr24.md` — session context
