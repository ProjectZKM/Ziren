## Task #22 Implementation Plan

### Goal

Replace placeholder/skeleton bodies in the recursion-circuit basefold verifiers so the shard-level path runs end-to-end. Unblocks #21 (flip default) and indirectly #13 (retire legacy).

### Files & current state

| File | Lines | Status | Priority |
|---|---|---|---|
| `crates/recursion/circuit/src/machine/compress_basefold.rs` | 811 | ~80% done, 2 placeholder closures at lines 733 + 757 | P0 (largest payoff — body is real; just closures missing) |
| `crates/recursion/circuit/src/machine/core_basefold.rs` | 168 | skeleton only | P1 |
| `crates/recursion/circuit/src/machine/deferred_basefold.rs` | 175 | skeleton only | P1 |
| `crates/recursion/circuit/src/machine/wrap_basefold.rs` | 164 | skeleton only | P2 |

### Subtask 22.1 — Replace `placeholder_jagged_evaluator_fn`

**File:** `compress_basefold.rs:757`

**Current:** Returns `(zero_ext, vec![])` — structurally correct, soundness-broken.

**Target:** A closure that drives the in-circuit jagged-eval sumcheck, mirroring host `verify_jagged_reduction` at `crates/stark/src/jagged_sumcheck.rs:546`.

**Composition:**

```
closure(builder, meta, z_row, z_index, z_eval, proof, challenger) -> (jagged_eval, prefix_sum_felts)
   1. For each round in proof.sumcheck_rounds:
        observe round.evals[0..3] into challenger
        assert round.evals[0] + round.evals[1] == current_claim
        r_i := challenger.sample_ext(builder)
        current_claim := eval_round_poly_in_circuit([p0,p1,p2], r_i)
        z_star.push(r_i)
   2. Build weight-table evaluation w_at_z_star using emit_branching_program_eval
      (from jagged_eval_primitives.rs:145)
      — one call per (chip, packing) tuple, accumulated into a single Ext
   3. Assert current_claim == proof.q_at_z * w_at_z_star
   4. Compute prefix_sum_felts via emit_prefix_sum_check
      (from jagged_eval_primitives.rs:208) over merged_prefix_sum bits + z_star
   5. jagged_eval := proof.q_at_z  (extension value flowing out)
   6. Return (jagged_eval, prefix_sum_felts)
```

**Primitive dependencies (all present):**
- `crate::jagged_eval_primitives::emit_branching_program_eval` — `:145`
- `crate::jagged_eval_primitives::emit_prefix_sum_check` — `:208`
- In-circuit 3-point univariate interpolation at `r_i` — write a helper `eval_round_poly_in_circuit`

**Risk:** Correct ordering of challenger observe/sample calls. Must exactly match the host `verify_jagged_reduction` ordering or transcript drift → proof rejection.

**Validation:** port the existing host-side `verify_jagged_reduction` test fixtures to the circuit. Generate a real jagged-PCS proof host-side, feed into the circuit, assert the closure returns the same `(q_at_z, prefix_sum_felts)` the host computed.

### Subtask 22.2 — Audit `noop_eval_public_values_fn` — CONCLUDED

**Audit result:** The no-op is **correct for the Compose stage** (compress_basefold.rs) but Ziren doesn't use the EVPV closure pattern for per-shard public-values consistency anyway — the legacy Normalize equivalent (`core.rs`, 601 LOC) asserts shard-to-shard consistency **inline**, directly against `shard_proof.public_values` interpreted as `PublicValues<Word<Felt>, Felt>`:

- `initial_shard / current_shard` chain
- `initial_execution_shard / current_execution_shard` chain
- `start_pc / current_pc` evolution
- `previous_init_addr_bits / previous_finalize_addr_bits`
- `exit_code`, `committed_value_digest`, `deferred_proofs_digest` accumulation
- `assert_complete` on last shard

**Action for #22:**
- Leave `noop_eval_public_values_fn` as-is for `compress_basefold.rs` (Compose stage — input proofs already validated).
- For `core_basefold.rs` (Normalize stage): port the inline shard-consistency assertions from `crates/recursion/circuit/src/machine/core.rs:176-330` verbatim. The closure pattern is not the right abstraction here — Ziren inlines.

This audit removes a fake dependency from 22.3/22.4/22.5: they do NOT need a new EVPV closure, they need to port inline assertions.

### Subtask 22.3 — Fill `core_basefold.rs` body

Port from `compress_basefold.rs::verify_compress_basefold`, pruning the per-input loop (Normalize verifies ONE shard) and the pubvals aggregation accumulator (first shard, nothing to aggregate). Wire the real EVPV closure from 22.2.

### Subtask 22.4 — Fill `deferred_basefold.rs` body

Port from `core_basefold.rs` (once done), adding deferred-specific constraints:
- `reconstruct_deferred_digest` update identity
- `num_deferred_proofs` counter increment

Reference legacy `crates/recursion/circuit/src/machine/deferred.rs:43-237`.

### Subtask 22.5 — Fill `wrap_basefold.rs` body

Final stage. Takes a Shrink output, verifies VK is in the allowed set via merkle proof (same as legacy `wrap.rs:22-94`), emits the field-wrapping pubvals.

### Subtask 22.6 — Tests + feature-flag smoke run

- Adapt existing tests under `--features shard-level-proof` to use basefold witness types.
- Run fibonacci + keccak shard-level prove + recurse end-to-end.
- Compare public values between per-chip and shard-level paths on identical inputs.

### Dependency graph inside #22

```
22.1 (jagged evaluator) ──┐
22.2 (EVPV audit) ────────┤
                          ├──> 22.3 (core_basefold body)
                          │        │
                          │        ├──> 22.4 (deferred_basefold body)
                          │        └──> 22.5 (wrap_basefold body)
                          │
                          └──> 22.6 (end-to-end smoke) depends on all above
```

### Estimated effort

- 22.1: 2-3 days (port + transcript-order debugging)
- 22.2: 0.5 day (audit + doc update)
- 22.3: 2-3 days
- 22.4: 1-2 days
- 22.5: 1 day
- 22.6: 1-2 days

**Total:** 8-12 working days for #22 alone.

Once #22 lands, #21 is a trivial ~1-day config flip + legacy-path compat shim removal.

---

## Status update (post-body-port session)

Subtasks 22.1-22.5 all landed and compile clean under `--features shard-level-proof`:

- `2ffc315` — 22.1 real jagged-evaluator closure in compress_basefold.rs
- `c82055e` — 22.2 EVPV audit + wire real closure into core/compress call sites
- `02d4db5` — 22.3 core_basefold body (full shard-consistency chain port)
- `fda59e8` — 22.4 deferred_basefold body
- `488bb59` — 22.5 wrap_basefold body

**Only 22.6 remains** — end-to-end smoke test feeding a real shard proof through the pipeline. Scoped as a separate effort because it needs:

1. A host-side shard-level proof to use as fixture. Generated via `zkm_stark::shard_level::prove_shard_to_basefold` — exists but has no known test caller yet.
2. Recursion-compiler-level executor run to verify the program compiles + runs. Pattern in existing `compress_basefold::tests` but those are construction smoke tests, not aggregation smoke tests.
3. Witnessable plumbing for each new `ZKM*BasefoldWitnessValues` → `ZKM*BasefoldWitnessVariable` (tuple-shape input is already supported by existing `shard_level_witness`; new stage-specific fields need additions).

Recommend filing 22.6 as its own task once #21 is unblocked and CI can be wired.

### Task #23 first-byte triage (post-session)

A `#[ignore]`d construction smoke test landed in
`crates/recursion/circuit/src/machine/basefold_programs.rs::tests::
build_normalize_basefold_program_compiles_dummy_witness`.  Running it
identifies the precise structural hole:

```
panic at crates/recursion/circuit/src/logup_gkr.rs:105
  assertion `left == right` failed: mle eval vector size must be 2^point.dimension
    left: 0
   right: 2
```

Translation: `LogupGkrProof::dummy()` returns an empty
`logup_evaluations.chip_openings` map.  The recursion verifier's
`logup_gkr` step expects each chip's preprocessed/main MLE eval
slice to have `2^layer_dimension` entries.  An empty proof has
zero entries where the verifier expects at least 2.

**Concrete next step for #23**:

1. Write a `dummy_basefold_shard_proof(machine, shape) -> BasefoldShardProof` helper
   in `crates/recursion/circuit/src/dummy_basefold.rs` (new module),
   modelled on `dummy_vk_and_shard_proof` (`crates/recursion/circuit/src/stark.rs:91`).
   Must populate:
   - `logup_gkr_proof.logup_evaluations.chip_openings` with one entry per chip in the shape,
     each `ChipEvaluation { main_trace_evaluations, preprocessed_trace_evaluations }` sized to
     match the chip's layer dimensions (zeros are fine for shape-correctness).
   - `logup_gkr_proof.round_proofs` with one entry per chip.
   - `zerocheck_proof` with `log_degree` rounds, each `[InnerChallenge; 4]` zeros.
   - `opened_values.chips` populated via `dummy_opened_values` (already in stark.rs).
   - `evaluation_proof: Vec<u8>` via the dummy jagged-PCS-bundle wire format.
2. Replace `BasefoldShardProof::empty()` in `dummy_core_basefold_witness` with
   the new helper.  Remove the `#[ignore]`.
3. Repeat for `dummy_compress_basefold_witness`, `dummy_deferred_basefold_witness`,
   `dummy_wrap_basefold_witness`.
4. Add an executor smoke run that compiles the program *and* runs it
   on the dummy witness via `RecursionExecutor::run`.

### Status update — real-fixture path landed; uncovers next-byte blocker

Replaced `BasefoldShardProof::empty()` in `dummy_core_basefold_witness`
with `produce_real_basefold_shard_proof(machine)` — drives Ziren's
real `zkm_stark::shard_level::prove_shard_to_basefold` against a
single zero-filled AddSub trace.  This eliminates the cascade of
hand-built structural fields and gets the verifier deep into its
soundness assertions.

**Next-byte blocker uncovered** (filed inline in test docstring):

```
panic at crates/recursion/circuit/src/logup_gkr.rs:105
  assertion `left == right` failed: mle eval vector size must be 2^point.dimension
    left: 1
   right: 16   // = 2^(log_num_interactions+1) for AddSub
```

Cause: `prove_shard_logup_gkr` (Ziren) emits the GKR **root** as
`circuit_output.numerator/denominator` (length 1), but SP1's
verifier protocol expects the GKR circuit's **input layer**
(length `2^(num_interaction_variables+1)`).  Confirmed against
SP1 prover at `/tmp/sp1/crates/hypercube/src/logup_gkr/prover.rs:147-159`.

**Concrete fix** (own task — not for #23):
1. In `crates/stark/src/shard_level/logup_gkr_prover.rs`, after
   `prove_logup_gkr_inner` returns, serialise the input-layer MLEs
   instead of `inner_proof.root.{0,1}`.
2. Re-run `build_normalize_basefold_program_compiles_dummy_witness`
   to find the next blocker.

Test currently `#[ignore]`d with the diagnosis pinned in the
docstring so the next person can pick it up.
