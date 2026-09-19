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

## The representation question, RESOLVED

The previous revision of this file recorded "whether the outer proof's
PREPROCESSED round is BN254-committed" as a blocker needing someone who knows
the wrap commit scheme. It does not: the code answers it, and the answer is
**yes — the outer preprocessed round is BN254-committed, a 1-cap, exactly like
the main round.** There is no per-round ring split to reconcile.

Evidence:

1. The outer ring has ONE Merkle scheme for every round.
   `recursion/core/src/stark/config.rs:16` sets `DIGEST_SIZE = 1`, and `:30`
   defines the only val-Mmcs the ring has:
   ```rust
   pub type OuterValMmcs = MerkleTreeMmcs<KoalaBear, Bn254, OuterHash, OuterCompress, 2, DIGEST_SIZE>;
   ```
   with `:288` naming its commitment type outright:
   `OuterValMmcs::Commitment = Hash<KoalaBear, Bn254, 1>`.

2. The outer lift's own parameter is `bundle: &JaggedBasefoldBundleGeneric<OuterValMmcs>`
   (`shard_level_witness.rs:1283`). The bundle is generic over ONE Mmcs, so
   `bundle.preceding_commits` — the raw roots of every round before the last —
   are that same BN254 1-cap. The preceding round is not inner-shaped.

3. The two representations are ALREADY reconciled in the tree, in both
   directions. `KoalaBearPoseidon2Outer::vk_preprocessed_commit_felts`
   (`recursion/circuit/src/lib.rs:842`) is the in-circuit twin of host
   `BasefoldRing::digest_felts`: it projects the BN254 1-cap to 8 KoalaBear
   felts as `split_32(commitment[0], 4)` zero-padded to 8. The inner impl
   (`lib.rs:772`) is the identity. So `[Felt;8]` and the 1-cap are already
   interconvertible in-circuit, and the wrap path's uniform `[Felt;8]`
   `preceding_commitments` type is a consequence of that projection, not
   evidence that the outer round is felt-committed.

4. The key-side 1-cap is already in scope at the call site that needs it.
   `verify_wrap_basefold_core` takes `vk_legacy: VerifyingKeyVariable<C, SC>`,
   whose `commitment` is `SC::DigestVariable` — the BN254 1-cap on the outer
   instantiation. Nothing has to be added to the verifying key; the outer lift
   simply is not handed it.

5. The round count is genuinely 2, so none of this is vacuous. Every recursion
   chip implements `preprocessed_width` (`recursion/core/src/chips/`:
   `alu_base.rs:89`, `alu_ext.rs:81`, `select.rs:54`, `ext2felt.rs:83`,
   `public_values.rs:77`, `mem/constant.rs:55`, `mem/variable.rs:56`,
   `poseidon2_wide/trace.rs:174`), so `prep_widths` in `wrap_basefold.rs` is
   non-empty, `column_counts_by_round.len() == 2`, and
   `preceding_commits.len() == 1`. The `[main_root, zero]` vector really does
   authenticate the preprocessed round's opening against the main root.

What this changes: the fix is representable today as a pair of
`SC::DigestVariable` values — `(bundle.preceding_commits[i]` for the raw side,
`vk_legacy.commitment` for the key side) — threaded into
`lift_outer_bundle_dispatch`. It does not need a ceremony decision, a key
format change, or a new witness field for the ROOTS.

## What is still genuinely open

Not the representation, but the bind MECHANISM:

- The inner path's comments describe the pin as re-deriving
  `compress([raw, hash(counts)])` and asserting it equals the key-held
  `modified_commitments` entry. Whether that assertion actually exists in the
  circuit, what the host stores in the key (raw root vs geometry-mixed digest),
  and whether the outer ring executes it at all, must be established before
  writing the outer bind — the outer lift's comment claims the BN254 bind
  happens "inside the registered outer jagged-verify hook", and that claim needs
  checking rather than trusting. Getting this wrong either rejects honest proofs
  or provides false assurance, and neither is visible without a gnark build.
- The cost decision below is unchanged and remains the release blocker.

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
