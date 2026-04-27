# META #59 — Basefold Verifier Real-Value Coordinated Swap

## ✅ Apr 24 progress — Phase 1 plumbing landed

Two host-side fields added without shifting the basefold normalize program AST (Phase 1 STILL GREEN at 154.68s VERIFY_VK=true):

1. **`ChipEvaluation.log_degree: u8`** (`crates/stark/src/shard_level/types.rs:94`)
   - Populated by `prove_shard_to_basefold` (and `row_gkr/top_level.rs`) from real per-chip `log2(main_trace.height())`
   - Witnessable impl in `shard_level_witness.rs:114` plumbs it to the recursion-circuit witness type
   - Currently NOT consumed by the verifier (zero placeholders still in `degree_bits`)

2. **`BasefoldShardProof.chip_cumulative_sums: BTreeMap<String, ChipCumulativeSums<F, EF>>`** (`crates/stark/src/shard_level/shard_proof.rs:75`)
   - New `ChipCumulativeSums<F, EF> { local: EF, global: SepticDigest<F> }` struct
   - Stored sibling to `opened_values` to avoid propagating `F` generic into LogUp-GKR types
   - Currently empty in `prove_shard_to_basefold` — verifier falls back to zero placeholders

Both fields are **inert** until the verifier-side substitution lands.  Compress_vk hash unchanged (verified by `collect_basefold_vks` fib_workload run before/after).  `vk_map.bin` (88B, 2 keys) still valid.

## What this unblocks

The plumbing means the **next** META #59 step (computing real values + verifier-side switch) can land without prerequisite type-system surgery — the data carrier is in place.

## Remaining META #59 work

### Phase 2 — populate real values
- In `prove_shard_to_basefold`, iterate chips and compute `(local_cumulative_sum, global_cumulative_sum)` per chip:
  - `local_cumulative_sum`: from `permutation::generate_permutation_trace(...).1` (returns `EF` per chip)
  - `global_cumulative_sum`: from main trace's last 14 values (matches legacy at `prover.rs:497-501`) when `chip.commit_scope() != LookupScope::Local`; else `SepticDigest::zero()`
- Insert into `chip_cumulative_sums` map keyed by chip name

### Phase 3 — verifier-side swap (the load-bearing change)
- `build_opened_values_from_chip_openings` (`shard_proof_variable_lift.rs:234`) currently constructs zero `local_cumulative_sum`/`global_cumulative_sum`
- Change call sites in `core_basefold.rs`, `compress_basefold.rs`, `deferred_basefold.rs`, `wrap_basefold.rs` to pass the per-shard `chip_cumulative_sums` map (read via Witnessable from BasefoldShardProof)
- Replace zero allocations at lines 277-281 with reads from the new param
- Risk: shifts compress_vk hash → vk_map.bin must be regenerated
- Validation: collect_basefold_vks → write_basefold_vk_map → re-run VERIFY_VK=true

### Phase 4 — repeat for log_degree (Swap 4 in original design)
- Use `chip_log_heights` (already populated) to compute real `degree_bits` instead of zero placeholder at `shard_proof_variable_lift.rs:266-268`
- Highest-risk swap; per-chip `is_real` audit needed first

---

## Original design doc (reference)


Design doc for coordinated removal of the load-bearing placeholders in the
basefold recursion verifier.  Captures the *why* of the AST-fragility wall
and the *what* of the reciprocal change set required for each placeholder.

## Background

Phase 1 D2 cutover (`test_e2e_compress_fibonacci` under
`ZIREN_USE_BASEFOLD=1 VERIFY_VK=true`) is **GREEN** today (Apr 24, 157s)
**only because the prover and verifier agree on a set of zero/empty
placeholder values that bypass several real protocol invariants**.  The
placeholders are:

| # | Placeholder | Site | Real value |
|---|---|---|---|
| P1 | `degree_bits = [0; max_log_row_count+1]` | `shard_proof_variable_lift.rs:266` | per-chip `log_height` bit decomposition |
| P2 | `local_cumulative_sum = ZERO` | `shard_proof_variable_lift.rs:277` | LogUp-GKR layer 0 output for that chip |
| P3 | `global_cumulative_sum = SepticDigest::zero` | `shard_proof_variable_lift.rs:278-281` | proof.global_cumulative_sum |
| P4 | `preprocessed_commit = [ZERO; 8]` | `shard_proof_variable_lift.rs:178-179` | `vk.commitment` (needs `SC::DigestVariable → [Felt; 8]` extraction) |
| P5 | `enable_untrusted_programs = ZERO` | `shard_proof_variable_lift.rs:180` | flag from VK metadata (currently absent on legacy VK) |
| P6 | `chip_height_bits = []` | `basefold_programs.rs:59` | per-shard per-chip height bits |
| P7 | `chip_log_heights_per_shard = []` | `core_basefold.rs:128` (param) | per-shard `BTreeMap<chip_name, log_height>` |

Each substitution attempted in isolation has regressed the Test::Compress
green baseline.  The root cause is that the verifier transcript and
constraint AST were tuned to the placeholder values and any real-value
substitution shifts the basefold normalize program's compress_vk hash AND
breaks the verifier-side equation balance.

## The protocol invariant being violated

The placeholder behavior survives because, for the **fibonacci-1k** workload:

1. The prover's basefold zerocheck pads every chip's hypercube table to
   `max_log_row_count` rows (`zerocheck_prover.rs:215-228`), filling padded
   rows with all-zero `Challenge::ZERO` entries.

2. The verifier formula at `zerocheck.rs:516-536`:
   ```
   constraint_eval = eval_constraints_basefold(opening, alpha, pubs)
                   - padded_row_adjustment(chip, opening, alpha, pubs) * geq_val
   geq_val         = full_geq(degree_bits, proof_point_extended)
   ```
   With `degree_bits = [0; n]`, `geq_val = 0`, so the padded-row
   subtraction is identically zero and `constraint_eval` reduces to
   `eval_constraints_basefold(...)` evaluated at the sumcheck point.

3. Because every chip in the FIBONACCI cluster has constraints that all
   factor through an `is_real` selector that is itself zero on padded
   rows, evaluating the AIR on the multilinear-eval'd (mostly-zero)
   point produces the right value WITHOUT the padded-row correction.

4. `local_cumulative_sum = ZERO` survives because the LogUp-GKR layer
   output for FIBONACCI's permutation-free chips IS zero (line 174-177
   of `zerocheck_prover.rs` skips chips with `permutation_width() > 0`,
   and FIBONACCI's chips that DO have permutation also have zero net
   cumulative sum at the shard level).

5. `global_cumulative_sum = ZERO` survives because the test path doesn't
   exercise the bn254-wrap stage that would actually consume it for
   range-check / interaction validation (Test::Compress stops at
   compress, not shrink/wrap).

6. `preprocessed_commit = ZERO` survives because the verifier's
   transcript observation of preprocessed_commit doesn't propagate into
   any opening-point check — the recursion VK's actual preprocessed
   commitment is independently embedded via `vk.commitment` upstream.

In short: **the placeholders happen to be cryptographically equivalent
for the FIBONACCI test workload, but are not in general**.  Any workload
with non-zero LogUp cumulative sums, non-uniform chip heights, or
preprocessed-commit-dependent constraints will fail.

## Reciprocal swap order (minimum-coupling first)

These swaps must each be paired with the matching prover-side or
verifier-side change.  Listed in roughly increasing risk:

### Swap 1: P3 (global_cumulative_sum) — pure plumbing
**Prover-side**: NOT yet correct — needs work.
- Verified Apr 24: `BasefoldShardProof` (`crates/stark/src/shard_level/shard_proof.rs:52`) does NOT carry `global_cumulative_sum`. The legacy `ChipOpenedValues` (`crates/stark/src/types.rs:87`) DOES carry it (`global_cumulative_sum: SepticDigest<F>` and `local_cumulative_sum: EF`).
- The basefold path uses `ChipEvaluation` (`crates/stark/src/shard_level/types.rs`) which has only `main_trace_evaluations + preprocessed_trace_evaluations` — NO cumulative sums.
- **Concrete prover-side change needed**: extend `ChipEvaluation` to add `global_cumulative_sum: SepticDigest<F>` and `local_cumulative_sum: EF`, populate them in `prove_shard_to_basefold` from the LogUp-GKR layer 0 output, then thread through `BasefoldShardProof.opened_values`.

**Verifier-side**: change
`build_opened_values_from_chip_openings::<C>(...)` to read from a new
parameter `global_sum: &SepticDigestVariable<C>` instead of constructing
zeros at line 278-281.

**Risk**: low — changes circuit shape (SepticDigest = 14 felts read vs 14
felts constructed-as-constant-zero).  AST shape difference may shift VK
hash.  Run collect_basefold_vks before/after to capture and update
write_basefold_vk_map.rs.

**Test sanity**: VERIFY_VK=true Test::Compress should still pass because
fibonacci's actual global_sum IS zero (memory note `project_d2_cutover_green.md`).

### Swap 2: P2 (local_cumulative_sum)
**Prover-side**: each chip's local_cumulative_sum must be carried in
`ChipEvaluation` (it already is — see
`crates/stark/src/shard_level/types.rs::ChipEvaluation`).  Verify the
field is populated by the LogUp-GKR layer 0 host code; trace through
`prove_shard_to_basefold` to confirm.

**Verifier-side**: change line 277 of shard_proof_variable_lift.rs to
read `opening.local_cumulative_sum.into()` instead of `zero_ext`.

**Risk**: low for fibonacci (local sums are zero), but high for any
LogUp-using workload.  Validate against keccak/sha2 once #57 OOM is
resolved.

### Swap 3: P4 + P5 (preprocessed_commit + enable_untrusted)
**Prover-side**: `BasefoldVerifyingKey` already carries `commitment:
[F; 8]` and `enable_untrusted_programs: F`.  Verify the basefold VK type
exposes these.

**Verifier-side**: in `build_basefold_verifying_key_variable`, replace
zero allocations at lines 178-180 with reads from `vk.commitment` and
`vk.enable_untrusted_programs`.  Requires adding a `DigestVariable: Into<[Felt; 8]>`
trait bound on `SC`, which the current code attempted and regressed.

**Risk**: medium-high — adding the trait bound shifts the recursion VK's
compile-time generic bounds, which may shift the normalize program AST.
Solution: bound the addition behind a feature flag or thread the new
parameters in via a new helper that mirrors but does not modify the
existing function.

### Swap 4: P1 + P6 + P7 (degree_bits / chip_height_bits / chip_log_heights)
**This is the load-bearing swap that all prior attempts have regressed.**

**Prover-side**:
- `BasefoldShardProof.chip_log_heights: BTreeMap<String, u8>` is already
  populated by `prove_shard_to_basefold` (per the memory `project_d2_cutover_green.md`).
- The `padded_row_adjustment` formula REQUIRES the prover's padded rows
  to evaluate to exactly the all-zero value via the AIR.  This is true
  for chips that gate ALL constraints behind an `is_real` selector
  whose value is 0 on padded rows.
- For chips that don't follow this pattern (e.g., constraints with
  unconditional terms), padded rows would contribute non-zero adjustment
  that the all-zero `padded_row_adjustment` doesn't capture.  These
  chips need either a refactor to the is_real pattern OR a different
  padded_row representation in the constraint folder.

**Verifier-side**:
- Replace `degree_bits = [0; n]` at line 266-268 with bit-decomposition
  of `chip_log_height` from a new parameter.
- Replace `empty_chip_height_bits` with a real builder that decomposes
  per-chip log_height from `BasefoldShardProof.chip_log_heights`.
- Update `verify_core_basefold` and `compress_basefold` callers to
  thread the real heights from `input.shard_proofs[i].chip_log_heights`.

**Risk**: HIGH.  Will:
- Shift the basefold normalize program's compress_vk hash
- Break VERIFY_VK=true unless vk_map.bin is regenerated
- Potentially expose chips whose constraint pattern isn't is_real-gated

**Validation**:
1. After landing, run collect_basefold_vks against fibonacci-1k to
   capture the new compress_vk hash.
2. Update `write_basefold_vk_map.rs::HASHES` with the new hash.
3. Run write_basefold_vk_map to regenerate vk_map.bin.
4. Re-run Test::Compress with VERIFY_VK=true.
5. Run Test::All on fibonacci to exercise the full pipeline.
6. Run on a multi-shard workload (sha2-100kb) — but only after #57 OOM
   is resolved, otherwise multi-shard will OOM-kill before reaching the
   verifier.

## Implementation strategy

Per the AST fragility constraint, **do all swaps in one atomic PR**:

1. Add the new code paths (real-value-capable verifier helpers) alongside
   the old ones, gated behind a `BASEFOLD_REAL_VALUES` cfg or a runtime
   `ZIREN_BASEFOLD_REAL=1` env var.
2. Verify the placeholder path still works (VERIFY_VK=true GREEN with the
   gate off).
3. Switch the gate to "real" in test_e2e_prover and validate.
4. Once green with real values, delete the placeholder path and the gate.
5. Regenerate vk_map.bin and update write_basefold_vk_map.rs.

This keeps the red/green check observable at every step and avoids the
single-step swap that has regressed every prior attempt.

## Estimated effort

- Swap 1 (global_sum): 2-4 hours implementation + 30min validation
- Swap 2 (local_sum): 2-4 hours implementation + 30min validation
- Swap 3 (preprocessed_commit + enable_untrusted): 1-2 days (trait bound
  threading is the hard part)
- Swap 4 (degree_bits): 2-3 days (needs prover-side audit of every chip
  for is_real gating; potentially refactor non-conforming chips)
- Total: ~1 working week of focused effort with periodic full-test runs

## Out of scope for this design

- Multi-shard verifier path (#48) — depends on swap 4 landing
- Compose tree real values — depends on multi-shard #48
- VK map expansion to all collect.sh workloads (#55) — depends on #48 + #57

## Risks not yet mitigated

- **AST fragility on the gate itself**: even adding a guarded branch may
  shift the basefold normalize program AST.  Mitigation: gate must be
  *runtime* env var not compile-time cfg, AND any new code must not be
  reachable from the basefold compress program at compilation time.
  Verify by comparing pre/post compress_vk hash after adding the gate
  before any actual swap.

- **`is_real` selector audit**: must enumerate every chip used in the
  FIBONACCI cluster, then keccak cluster, etc. and confirm constraint
  gating.  If any chip has unconditional constraints, the
  padded_row_adjustment formula must be extended (e.g., compute the
  adjustment per-chip-pattern rather than assuming zero-row ⇒ zero
  result).

- **Compose tree shape vs single-shard shape**: the compose program's
  verifier may interact with the placeholder values differently from
  the normalize program's verifier; need separate validation for each.
