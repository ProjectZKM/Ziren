# Global Lookup PoC

## Issue

`GlobalLookupOperation` is intended to prove that each global interaction tuple

- `message[0..6]`
- `is_send` / `is_receive`
- `kind`

is mapped to a specific elliptic-curve point, and that `GlobalChip` accumulates those points into
the shard's global digest.

The honest trace generator does this in
[global_lookup.rs](./../operations/global_lookup.rs) by computing:

- `x_start = message + (kind << 16)`
- `point = lift_x(x_start)`
- negate the point for sends

The AIR, however, does not constrain the witness point to equal that map-to-curve output. It only
checks that the witness point is:

- on the curve,
- sign-correct for send vs receive,
- accompanied by a small offset witness and range-check witness.

So the prover can keep the tuple columns honest while substituting a different valid point witness.

## Attack Shape

The intended invalid interaction set is:

1. `send(A)`
2. `receive(B)`

with `A != B`.

If the lookup relation were sound, the accumulated digest would be:

- `-Map(A) + Map(B)`

which should not cancel in general.

The forged proof instead uses a third message `C` and supplies the witness points:

1. row 0 witness: `-Map(C)`
2. row 1 witness: `+Map(C)`

while leaving the visible row tuples unchanged as `send(A), receive(B)`.

Because `-Map(C) + Map(C) = 0`, the forged accumulation columns can be made internally consistent
and the final global digest is zero.

## What The Test Does

The PoC test in [mod.rs](./mod.rs) builds a tiny machine with three chips:

1. `DummyGlobalSender`
   Emits the honest global tuples `send(A), receive(B)`.

2. `DummyU16Range`
   Satisfies the `U16Range` byte lookup required by `GlobalLookupOperation`.

3. `Global`
   The real `GlobalChip` under test.

The test then:

1. builds an honest record with two mismatched tuples,
2. finds a forged message `C` whose send/receive points cancel cleanly,
3. generates honest traces for every chip,
4. overwrites only the `Global` main trace with a forged one,
5. proves the shard and verifies it.

## Why This Demonstrates The Bug

The verified shard proof has:

- honest tuple columns seen by the lookup system: `send(A), receive(B)`
- forged witness point columns used by `GlobalChip`: `-Map(C), +Map(C)`

The proof still verifies and the final global cumulative sum is zero.

That means the system accepted a proof whose visible interaction multiset is not balanced under the
intended semantics.

This is exactly the missing constraint:

- the AIR proves that the tuple exists,
- and it proves that some valid signed curve point exists,
- but it never proves that the point came from that tuple.

## Scope

This PoC is a focused chip-level forged-proof demonstration. It is not yet a full forged zkVM
execution proof. The point of the test is narrower and sufficient:

- it shows that the current `GlobalLookupOperation` AIR admits a false statement.
