# ZR-23 / ZR-24: what the outer ring is still missing, and the exact blocker

Status: ZR-24's ordering is fixed on `fix/zr24-commitment-order` but sources its
roots from the PROOF, so it repairs completeness only. ZR-23's second and third
binds are open. This file records where the sound pattern already exists in this
repository, the one call site that does not use it, and the open question that
stops it being a mechanical change.

## The sound pattern already exists

The INNER lift is the reference. `shard_level_witness.rs:2146`:

```rust
assert_eq!(preceding_commitments.len() + 1, num_rounds, ...);
let mut original_commitments = Vec::with_capacity(num_rounds);
original_commitments.extend(preceding_commitments.iter().map(|(raw, _)| *raw));
original_commitments.push(preread_commit_root);          // main LAST
// modified_commitments likewise: preceding's KEY digest, then the witnessed main
```

with the comment that says why it is sound: *"the preceding rounds' commitments
come from the caller (the verifying key)"*, and the hash-bind then
*"re-derives `compress([raw, hash(counts)])` and asserts it equals this, which is
what pins that round's geometry to the key."*

So the pair is `(raw root the BaseFold open binds against, digest the KEY
holds)`, and the hash-bind ties one to the other. Sourcing the roots from the
proof — which is what `fix/zr24-commitment-order` currently does — gets the
ORDER right and leaves the vector proof-controlled.

Both non-outer callers build that pair from the key:

- `machine/compress_basefold.rs:344` —
  `vec![(preprocessed_round.raw_commit, basefold_vk_pre.preprocessed_commit)]`
- `machine/wrap_basefold.rs:256`     — the same expression

## The one call site that drops it

`wrap_basefold.rs` passes `&preceding_commitments` to the `WhirBundle` arm
(line 307) and the `Bundle` arm (line 368), and **not** to the `OuterBundle`
arm (line ~333), which calls `lift_outer_bundle_dispatch` without it. The outer
lift consequently had no key-side data at all and synthesised
`[main_root, zero, zero, ..]`.

That single omission is the root of both findings:

- ZR-24: `component_openings[0]` (a preceding round) authenticated against
  `main_root`, so activating component verification rejects honest proofs.
- ZR-23 bind #2: no preceding root is ever re-bound to `vk.commit`.

The minimal fix is therefore to thread the pair that already exists into
`lift_outer_bundle_dispatch` (one parameter, one method, two impls) and use it
exactly as the inner lift does.

## The blocker: two digest representations

This is why it is not a mechanical change, and it needs someone who knows the
wrap commit scheme:

| | type |
|---|---|
| `preceding_commitments` on the wrap path | `([Felt<C::F>; 8], [Felt<C::F>; 8])` |
| `original_commitments` in the outer lift  | `[Var<C::N>; 1]` — a BN254 1-cap |

The outer BaseFold Merkle-verifies leaves against BN254 caps, while the
verifying key carries 8-felt KoalaBear digests. The open question is whether the
outer proof's PREPROCESSED round is BN254-committed at all:

- if it is, the key needs to expose (or the circuit derive) its 1-cap form, and
  the hash-bind has to be done in the BN254 hasher;
- if it is not, then the preceding round on this ring is inner-shaped and the
  representations have to be reconciled before either bind means anything.

Until that is settled, `original_commitments` on the outer ring is either
proof-controlled (today, after the ordering fix) or wrong (before it).

## Also unresolved, and independent

ZR-23 bind #3: the outer branch of `verify_jagged_pcs_host` receives
`opened_values` but never compares `bundle.y_per_chip` against
`opened_values.chips[].main.local`, so the jagged reduction and zerocheck can be
driven by two different sets of column claims. The inner cross-bind at
`shard_level/verifier.rs:990-1059` is the reference.

## Cost, unchanged

Activating component verification measured 31,874,392 constraints — 95.0% of the
2^25 ceiling, against 84.5% with the openings dropped. Headroom 15.5% -> 5.0% on
a truncated ptau. Closing ZR-24 still needs the headroom decision regardless of
which representation question above is answered.
