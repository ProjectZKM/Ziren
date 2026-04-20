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

### Subtask 22.2 — Audit `noop_eval_public_values_fn`

**File:** `compress_basefold.rs:733`

**Current comment's argument:** "Compress public-values are already constraint-checked at production time of each input proof."

**The question:** Is this sound? The recursion circuit verifies that each input proof is valid; once the FRI/Basefold opening proof is verified, the public values claimed by that proof are bound. But the *semantic* constraints on public values (e.g., pc_next == pc + 4, halt flag monotonicity) are part of the AIR, not the PCS opening. Those checks are in the AIR of the proving program that produced the proof. If the Compress program accepts any public values that came out of a valid FRI opening, it's correct — the inner proof already enforced the AIR constraints.

**Conclusion:** The no-op is likely correct under the "trusted input proofs" model. But: (a) Normalize is the leaf, not Compress — Normalize needs to constrain-check public values itself. (b) The comment should be moved into `compress_basefold.rs` and a real (non-noop) EVPV should land in `core_basefold.rs` for the Normalize role.

**Action:**
- Leave `noop_eval_public_values_fn` as-is for Compose/Compress (batching recursion) since input proofs are already verified.
- Port a real `recursion_public_values_eval_fn` into `core_basefold.rs` mirroring the legacy `core.rs` public-values constraints.

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
