# In-Circuit BaseFold Verifier Port — Roadmap

This document tracks the in-progress rewrite of the recursion-circuit
shard verifier to align with the post-BaseFold proof shape.  The
motivation, current state, and module-by-module porting plan live
here; the source tree carries only finished or actively-in-progress
modules.

## Why a rewrite

The legacy [`crate::stark::StarkVerifier::verify_shard`] in
`crates/recursion/circuit/src/stark.rs` was designed for the
4-batch pre-BaseFold proof shape (preprocessed + main + permutation
+ quotient).  After the BaseFold migration, the production prover at
`crates/stark/src/prover.rs:715-783` emits a 2-batch shape with
`permutation_commit = None`, `quotient_commit = None`, and empty
permutation/quotient opened values; the soundness work moved those
roles into a sumcheck-based binding (zerocheck + LogUp-GKR) and
folded the quotient terms into the FRI commit.

The current verifier handles this via defensive `is_some()` guards
inside `verify_shard`.  The pragmatic path (committed in `cb42dda`)
is to make the dummy-proof generator emit the same 2-batch shape, at
which point the existing guards correctly skip the per/quot PCS-mat
construction.  This works (12/12 recursion-circuit tests green;
production aggregation runs end-to-end), but the verifier
architecture is still organised around the legacy shape.

A clean rewrite reorganises the verifier into the four-phase IOP
structure that the BaseFold proof actually carries:

1. **Phase 1 — public values + main commit + chip metadata observe**
2. **Phase 2 — LogUp-GKR sumcheck verification**
3. **Phase 3 — zerocheck sumcheck verification**
4. **Phase 4 — jagged-PCS opening verification** (which internally
   drives a recursive BaseFold verifier on the stacked stripes)

The legacy `is_some()` shims, the dummy-shape adapter in
[`crate::stark::dummy_vk_and_shard_proof`], and the
`opening_proof: FriProofVariable` field on the existing
[`crate::stark::ShardProofVariable`] all retire when this lands.

## Source mapping

Reference implementation: SP1's recursion-circuit verifier under
`/tmp/sp1/crates/recursion/circuit/src/`.  The Ziren port replaces
SP1-specific abstractions (`slop_*` crates, `IopCtx`,
`SP1FieldConfigVariable<C>`) with the existing Ziren conventions
(`p3_*` crates, [`crate::CircuitConfig`],
[`crate::KoalaBearFriParametersVariable`]).

### Module mapping

| Reference module | LOC | Ziren target | Status |
|---|---:|---|---|
| `shard.rs` | 548 | new `shard_basefold.rs` | TODO |
| `basefold/mod.rs` | 660 | extend [`crate::basefold_verifier`] | partial — host-shape emit done |
| `basefold/stacked.rs` | 244 | new `basefold/stacked.rs` | TODO |
| `basefold/tcs.rs` | 211 | new `basefold/tcs.rs` | TODO |
| `basefold/merkle_tree.rs` | 107 | overlap with [`crate::merkle_tree`] | partial |
| `basefold/witness.rs` | 192 | new `basefold/witness.rs` | TODO |
| `basefold/whir.rs` | 951 | n/a (Ziren removed WHIR per E1) | SKIP |
| `jagged/mod.rs` | 6 | new `jagged_circuit/mod.rs` | TODO |
| `jagged/verifier.rs` | 487 | new `jagged_circuit/verifier.rs` | TODO |
| `jagged/jagged_eval.rs` | 405 | new `jagged_circuit/jagged_eval.rs` | TODO |
| `jagged/witness.rs` | 126 | new `jagged_circuit/witness.rs` | TODO |
| `logup_gkr.rs` | 377 | new `logup_gkr.rs` | TODO |
| `zerocheck.rs` | 436 | new `zerocheck.rs` | TODO |
| `sumcheck/mod.rs` | 312 | new `sumcheck.rs` | TODO |
| `sumcheck/witness.rs` | 56 | merge with above | TODO |
| `dummy/*.rs` | ~300 | new `dummy_basefold.rs` | TODO |
| `symbolic.rs` | ~200 | new `symbolic.rs` | TODO |
| `utils.rs` | ~150 | merge into [`crate::utils`] | TODO |

**Net-new code estimate:** ~3,200 lines after subtracting WHIR
(skipped) and the overlap with the existing
[`crate::basefold_verifier`] host-shape verifier.

### Foundational types — landed

| Module | Status | Notes |
|---|---|---|
| [`crate::univariate::UnivariatePolynomial`] | LANDED | Coefficient-form univariate, `eval_at_point` (Horner), `eval_one_plus_eval_zero` (sumcheck identity), `interpolate`, `random_linear_combination` |
| [`crate::partial_sumcheck::PartialSumcheckProof`] | LANDED | Transcript carrier for sumcheck IOPs; depends on `UnivariatePolynomial` |

### External crate dependency map

The reference uses the `slop_*` crate family extensively.  These
types appear throughout the verifier; Ziren equivalents listed.

| Reference type / function | Reference source | Ziren equivalent |
|---|---|---|
| `slop_sumcheck::PartialSumcheckProof<K>` | `slop/crates/sumcheck/src/proof.rs:8` | [`crate::partial_sumcheck::PartialSumcheckProof`] (LANDED) |
| `slop_algebra::UnivariatePolynomial<K>` | `slop/crates/algebra/src/univariate.rs:7` | [`crate::univariate::UnivariatePolynomial`] (LANDED) |
| `slop_multilinear::Mle` / `MleEval` | `slop/crates/multilinear/` | [`zkm_stark::basefold::mle::Mle`] |
| `slop_multilinear::Point` | same | `Vec<EF>` |
| `slop_multilinear::partial_lagrange_blocking` | same | [`zkm_stark::basefold::jagged_per_chip::poly::partial_lagrange_lsb`] |
| `slop_alloc::{Buffer, buffer}` | `slop/crates/alloc/` | `Vec` directly |
| `slop_tensor::{Tensor, Dimensions}` | `slop/crates/tensor/` | [`p3_matrix::dense::RowMajorMatrix`] |
| `slop_challenger::IopCtx` | `slop/crates/challenger/` | trait-bridge to [`crate::CircuitConfig`] |
| `slop_commit::{Message, Rounds}` | `slop/crates/commit/` | `Vec` |

### Trait-bridge work

The reference verifier abstracts everything over
`IopCtx + SP1FieldConfigVariable<C> + Poseidon2SP1FieldHasherVariable<C>`.
Ziren uses
`CircuitConfig: Config + KoalaBearFriParametersVariable<C: CircuitConfig<F = KoalaBear>>`.

The Ziren stack is KoalaBear-specialised; the reference is
field-generic.  The port specialises to KoalaBear at every site that
takes a generic `SP1FieldConfigVariable<C>` parameter.

## Recommended porting order

1. **`UnivariatePolynomial`** + **`PartialSumcheckProof`** —
   foundational data types.  ✅ LANDED.
2. **`sumcheck::verify_sumcheck`** (~120 LOC of the reference
   `sumcheck/mod.rs`) — depends only on the above + `CircuitConfig`.
3. **`zerocheck::RecursiveZerocheckVerifier`** (~436 LOC) —
   depends on `verify_sumcheck`.
4. **`logup_gkr::RecursiveLogUpGkrVerifier`** (~377 LOC) —
   depends on `verify_sumcheck`.
5. **`jagged_circuit::verifier`** (~487 LOC) +
   `jagged_circuit::jagged_eval` (~405 LOC) —
   depends on sumcheck + the existing
   [`crate::basefold_verifier`] host-shape verifier.
6. **`basefold::stacked`** + **`basefold::tcs`** +
   **`basefold::witness`** — extend [`crate::basefold_verifier`].
7. **`shard_basefold::RecursiveShardVerifier`** (~548 LOC) —
   orchestrator that ties it all together.  Replaces the legacy
   [`crate::stark::StarkVerifier::verify_shard`].
8. **`dummy_basefold`** + test fixture rewrite — remove the
   pragmatic `is_some()` adapter shims.

   **Step 9 status (afe22da+)**: `dummy_basefold_shard_proof_variable`
   landed in `crate::shard_basefold` — produces a structurally-
   valid in-circuit `BasefoldShardProofVariable` from a
   `BasefoldProofShape` config (chip count, max log row count,
   round counts, etc.).  Sufficient for shape-driven circuit
   compilation tests and witness-stream layout work; not yet a
   "honest dummy" that passes verification (full verification
   needs the FRI query phase + jagged-eval sub-protocol that
   land in follow-up steps).

   **`is_some()` shim retirement** is a separate cleanup that
   touches the legacy verifier path's live callers (the prover,
   the host verifier, build_compress_vks, the shape-cluster
   dedup logic).  Plan:

   1. Switch `examples/aggregation/host` to the BaseFold shard
      verifier when phase 2/3/4 wiring lands in
      `BasefoldShardVerifier::verify_shard`.
   2. Switch the prover's commitment emit path to always emit
      `permutation_commit = None`, `quotient_commit = None`
      (and rename the field to `auxiliary_commits: Vec` so the
      "is None" branch becomes `is_empty()`).
   3. Delete the `if permutation_commit.is_some()` and `if
      quotient_commit.is_some()` blocks in
      `crate::stark::dummy_vk_and_shard_proof` (legacy
      compatibility path) and `zkm_stark::verifier` (live
      verifier path).
   4. Delete `RecursiveVerifierConstraintFolder` (legacy 4-batch
      folder) and `StarkVerifier::verify_shard` once no caller
      remains.

   Estimate: ~600-1000 LOC delta across 5 files, ~3-5 careful
   iterations.  Independent of E4 — requires the BaseFold
   verifier to be wire-complete first.

## Iteration economics

Realistic per-iteration progress: 200-400 lines of careful port +
test compile cycle.  Total port is ~16-25 iterations of focused
agent context.

## Why this isn't done yet

The pragmatic 3-fix at [`crate::stark::dummy_vk_and_shard_proof`]
+ [`crate::stark::dummy_opened_values`] resolved the immediate
test failure that motivated the rewrite request.  That fix is
shipped (commit `cb42dda`).  The architectural rewrite is real
technical debt but **not blocking any production functionality**:

- `examples/aggregation/host` runs end-to-end through the compress
  + aggregate recursion path (validated 2026-04-18: 17:54 wall,
  54.6 GB peak; only the gnark BN254 wrap fails due to stale
  Groth16 keys, separate ceremony).
- The recursion-circuit test suite is 12/12 green, plus 5/5 for
  the new foundational types.
- The legacy verifier's `is_some()` guards are functionally
  equivalent to the reference's modular shape — they just aren't
  laid out in that shape.

Future iterations can use this document as the porting checklist.
