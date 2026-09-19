# ZR-23 / ZR-24: the outer ring's binds

The outer (wrap/BN254) ring reached the audit with its preprocessed round
unbound in three separate ways. This file states each bind, where it now lives,
and what is deliberately left out.

## The layout both rings share

A shard proof opens rounds in commit order, main LAST:

```text
    rounds        = [preceding.., main]
    chip_infos    = [prep real | prep pad | main real | main pad]
    y_per_chip[i] ↔ chip_infos[i] ↔ opened_values (prep.local / main.local)
```

`preceding_commits` are the raw roots of the rounds before the last;
`component_polynomials_query_openings_and_proofs` follows the same order. Both
non-outer callers build the key-side pair from the verifying key
(`compress_basefold.rs:344`, `wrap_basefold.rs:256`); the `OuterBundle` arm was
the one that got nothing, which is the root of all three findings below.

## ZR-24 — ordering

`lift_jagged_basefold_bundle_outer` synthesised

```text
    original_commitments = [main_root, 0, 0, ..]
```

so `component_openings[0]`, which belongs to the first PRECEDING round, was
Merkle-verified against `main_root`: activating component verification rejected
honest proofs at the first `HV::assert_digest_eq`, and disabling the later
query-chain equality changed nothing because the mismatch is upstream of it.

FIXED: the lift now witnesses `[preceding.., main]` in opening order, and the
outer witness reader/writer carry the component openings (they were dropped as
`Vec::new()`, which is what made the query-chain binding in `basefold_verifier.rs`
inert).

## ZR-23 bind #2 — the preceding root is the KEY's

The roots above arrive from the PROOF. On their own they let a prover open a
preprocessed round of its own choosing. Bound on both sides now:

* IN-CIRCUIT — `vk_preprocessed_cap`, threaded from `verify_wrap_basefold_core`
  through `FieldHasherVariable::vk_outer_cap` (`Some` only on the ring that
  produces an `OuterBundle`) into the lift, which asserts
  `original_commitments[0] == vk.commitment`.
* HOST — `BasefoldRing::vk_commit_is_preceding_root`, in the outer branch of
  `verify_jagged_pcs_host`, which used `vk` for nothing at all before.

A plain equality is the right comparison here, and not an approximation of the
inner bind:

```text
    outer  commit_root = commit.original_commitment                (raw)
    inner  commit_root = compress([raw, hash(row/col counts)])     (geometry-mixed)
```

so the inner ring must re-derive the mix to compare and the outer has no mix to
undo. Answered per ring through a trait method rather than by relabelling
`Com<SC>` at the call site, because `Com<SC>` and the BaseFold commitment type
coincide only on the outer ring — a fact each implementor knows concretely and
no caller can establish.

LEFT OUT, deliberately: this pins the round's ROOT, not its ROW COUNTS. The
inner ring gets geometry free because the counts are hashed into its key digest;
the outer key has no counts in it, so pinning outer geometry the same way means
mixing counts into `commit_root` for this ring — a verifying-key format change,
hence new Groth16 artifacts. The root bind costs one BN254 equality and no
ceremony. The chip COUNT and the per-chip WIDTHS are pinned from the machine
(`prep_chip_dims`), so what stays proof-claimed is the row counts alone.

Why the bind was skipped: `jagged_hash_bind_in_circuit()` returns false for this
ring and `commit_root` returns the raw root, both justified by "the wrap machine
also opens a single round, so there is no preceding round whose geometry would
need pinning here", with the note "if the wrap ever grows a preprocessed opening
round, it needs its own BN254 bind". That premise is false and the same module
contradicts it: `outer_prep_precompute` exists "so the preprocessed round can be
OPENED", every recursion chip has a nonzero `preprocessed_width`, and
`wrap_basefold.rs` therefore builds `column_counts_by_round = [prep, main]`. The
wrap machine opens TWO rounds; the deferred conditional was already live.

## ZR-23 bind #3 — the column claims are the openings

`verify_jagged_basefold_inner_generic` had no `opened_main` parameter, so on the
outer ring the zerocheck (which consumes `opened_values`) and the jagged phase
(which consumes `bundle.y_per_chip`) were two independent checks over two
unrelated sets of column claims.

FIXED: `cross_bind_openings`, extracted from the inner ring's
`verify_one_jagged_group` so both rings check the SAME identity. With
`w_k = eq(z_col, k)` over the flattened column index, `k` running as
`verify_jagged_reduction` walks it,

```text
    Σ_k w_k·open_k  =  Σ_k w_k·y_k ,
```

whose right-hand side is bit-for-bit the `t` the reduction takes as its round-0
claim, so this is exactly "the openings generate the claimed sum". The MLE form
is not a weakening of an element-wise compare: under the `rev(zeta)` orientation
the two vectors need not agree element-wise while their `z_col`-MLEs do, and it
is the MLE identity the circuit asserts (`recursive_jagged_pcs.rs:247`).

The outer branch's `chip_infos` are named `chip{i}` positionally, so the
alignment is rebuilt from `round_counts[r].len()` real chips plus
`padding_heights[r].len()` single-column padding groups per round, rounds in
commit order. A rebuild that does not cover the groups the verifier weighs is a
rejection, not a fallback to the unbound path.

## Cost

Host-side binds (#2 host, #3) cost no constraints. In-circuit, activating
component verification measured 31,874,392 constraints — 95.0% of the 2^25
ceiling, against 84.5% with the openings dropped.

The ptau supports it. `powersOfTau28_hez_final_25.ptau` is truncated, but only
past section 12: the monomial sections are COMPLETE —

```text
    tauG1       67,108,863 / 67,108,863 points   → domain 2^25
    tauG2       33,554,432 / 33,554,432
    alphaTauG1  33,554,432 / 33,554,432
    betaTauG1   33,554,432 / 33,554,432
    section 13   5.4% present (a Lagrange table gnark does not read)
```

so 31,874,392 < 2^25 = 33,554,432 fits, with 1.68M constraints of headroom.
That headroom, not the truncation, is the thing to watch: the next change to the
outer circuit's shape has 5% to spend, and there is no 2^26 ptau to move to.
