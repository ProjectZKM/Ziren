# ZR-28 / ZR-29: the doubling gap and the grind that was not performed

Two findings that share a shape: a check the accounting assumed was happening,
and a case the polynomials silently admitted.

## ZR-29 — the wrap LogUp-GKR grind was a no-op

`ziren.soundcalc.toml` credits every ring, wrap included, with

```text
    grinding_bits_lookup = 16
```

while the wrap ring performed none of it. `GkrGrind::gkr_grind` returned
`F::ZERO` without observing anything for a non-inner challenger, the host's
`gkr_check_witness` accepted unconditionally, and the circuit's
`MultiField32ChallengerVariable::gkr_check_witness` was an explicit no-op. Under
the additive PoW accounting, removing an unperformed 16-bit grind leaves wrap at
roughly 96 bits against a stated target of 100.

The split rested on one premise, stated in the code:

> the Outer challenger is not a `GrindingChallenger`, so a hard bound would
> break the wrap path

which is false. The wrap BaseFold open grinds `pow_bits = 22` through exactly
that trait, and `verify_jagged_pcs_host` already requires
`SC::Challenger: GrindingChallenger<Witness = JaggedVal>`. The outer ring could
grind the whole time.

FIXED: the grind is performed and checked on every ring — `gkr_grind` /
`gkr_check_witness` in `logup_gkr.rs` now call `GrindingChallenger` directly, and
the circuit's no-op override is deleted so the outer ring takes the trait default
(observe, sample `nb_bits`, assert zero). The `GkrGrind` trait is removed rather
than left with both arms live, so the split cannot return by accident. The 16
bits are now earned rather than credited.

Grinding is DETERMINISTIC (smallest-index witness), not p3's `find_any`: the
witness is observed into the challenger, so a nondeterministic one makes every
downstream alpha/beta vary run to run.

SP1 comparison: SP1 performs and constrains this grind on its BN254/gnark
transcript — `MultiField32ChallengerVariable::check_witness` observes, samples,
and asserts the bits are zero, lowering to a real `ToBinary` in the Groth16
circuit. It uses 12 bits where we use 16. This was a Ziren-only gap.

## ZR-28 — the chord identities collapse on doubling

> STATUS: DEFERRED, not fixed. The repair below was written, gated on CPU, and
> then REVERTED after it broke every leaf on GPU. The reason is recorded under
> "The device tracegen gap" at the end of this section: the fix adds a witness
> column, and the `Global` trace is generated on DEVICE by CUDA kernels that do
> not know about it. The analysis stands; the landing needs the device half.

For running sum `P1`, event point `P2`, claimed next sum `P3`, the AIR asserts

```text
    Cx = (x1 + x2 + x3)(x2 - x1)^2 - (y2 - y1)^2      unconditionally
    Cy = (y1 + y3)(x2 - x1) - (y2 - y1)(x1 - x3)      when is_real
```

Both carry the factor `(x2 - x1)`. At `P2 == P1` both coordinate differences
vanish, so `Cx = Cy = 0` for EVERY `P3`, and the only surviving restriction is
that `P3` is on the curve. The honest generator meanwhile takes a correct
doubling branch, so native witness generation computes the right point while the
AIR would accept an arbitrary on-curve successor at the same event.

The neighbouring exceptional case is NOT a gap: at `P2 == -P1`,
`Cx = -4y1^2`, nonzero whenever `y1 != 0`, and `y1 == 0` collapses into
`P2 == P1`. Both points being on-curve, `x2 == x1` forces `y2 ∈ {y1, -y1}`, so
there is no third case.

FIXED, as the report's second option: witness `(x2 - x1)^{-1}` per accumulation
step and require

```text
    is_real * ((x2 - x1) * inv - 1) = 0
```

which makes `x2 != x1` a constraint instead of an assumption. Cost: 7 columns
(`denominator_inv`, one `SepticBlock`), degree 3 — `(x2 - x1)` and `inv` are
degree 1, their septic product 2, the `is_real` gate adds one — the same cap
`sum_checker_x` already sits at, so the quotient degree is unchanged. The column
is placed between `initial_digest` and `cumulative_sum` because the struct must
stay at the end of the main trace with `cumulative_sum` last, and
`initial_digest` must stay at `GLOBAL_INITIAL_DIGEST_POS`.

### Why this rejects no honest trace

- `P2 == -P1` is already rejected by the existing `Cx`, so the inverse forbids
  nothing that was previously provable there.
- The accumulator starts at the fixed offset `D`, and both `D` and `-D` have
  their `y[6]` inside the exception band `lift_x` skips
  (`D.y[6] = 1064053343`, `(-D).y[6] = 1066653090`, band
  `(1056964608, 1073741825)`), so row 0 can be neither a doubling nor a
  `P + (-P)`. This is the offset-point argument, and it covers row 0 only.
- The point at infinity cannot be represented at all: the trace columns are
  `SepticCurve` with no infinity flag, and `SepticCurveComplete::point()`
  panics on it. The running sum reaching infinity is already a hard prover
  failure, not something this change introduces.
- What remains is a true doubling at `i >= 1`, i.e. the running sum exactly
  equalling the next event point. Today that succeeds via `double()`; with this
  change it fails to prove. That is a completeness regression of probability on
  the order of `2^-197`, strictly smaller than the infinity panic the codebase
  already accepts, and it converts a silent soundness hole into a loud prover
  failure.

### The residual assumption, stated

This pins the LOCAL denominator. It does not prove the running sum never
collides with a reachable encoded point; it makes such a trace unprovable rather
than silently unconstrained. Reaching the case still requires finding a
sub-multiset `A` of a shard's event points and an event `e ∉ A` with
`Σ_{a∈A} a + D = enc(e)` — a k-sum instance of the same shape as the digest
assumption stated in the paper.

The barrier differs from SP1's, and that is worth being explicit about. SP1
HASHES the message to the curve with a Poseidon2 permutation constrained
in-circuit, so reaching the gap needs a preimage. Ziren MAPS the message to `x`
(`lift_x` searches a 1-byte offset, no hashing), so given a target x-coordinate
the message is read off by inversion; only the shape and bus-balance constraints
on reachable messages stand in the way.

SP1 comparison: SP1's `eval_accumulation` has the IDENTICAL gap — unconditional
`sum_checker_x`, `is_real`-gated `sum_checker_y`, no inverse witness, no doubling
branch. Ziren is already stricter in one respect: it asserts both running digests
are on-curve, which SP1 omits, so at a doubling row SP1's next digest is
completely unconstrained while Ziren's is confined to the curve. This fix puts
Ziren ahead rather than level.

### Two follow-ups this surfaced

1. `add_curve_v2` (`recursion/compiler/src/circuit/builder.rs`) hints the sum and
   asserts only the two checkers, with NO on-curve check on the hinted result —
   weaker than the Global chip at the same coincidence. Adding the curve equation
   is zero columns and seven constraints.
2. The paper's claim that "a trace that reaches one fails the addition
   identities" (`docs/paper/sections/04_air.tex`) is half wrong: true for the
   identity case, false for doubling, where both checkers vanish identically. The
   offset-point sentence also reads as covering the whole trace when it
   establishes row 0. Not edited here — the paper is under review.

### The device tracegen gap

The repair adds a witness column, and that is what makes it a cross-repo change
rather than a local one. `GlobalChip` has a `DeviceAir` implementation in
`ziren-gpu` (`core/src/tracegen/core.rs`): the trace is produced on device by
`core_global_generate_trace_round_1` and `..._round_2`, and the matrix is
memset to zero and sized from `BaseAir::width`. Widening the chip therefore
yields seven ZERO columns on GPU while the host tracegen fills them correctly,
so on every real row

```text
    is_real·((x2 - x1)·inv - 1) = is_real·(0 - 1) != 0
```

the zerocheck quotient does not divide, and every recursion leaf fails with
"attempted to perform extension field division". Measured: 24 leaf failures, 0
vk denials, all three blocks of the deploy window.

Landing ZR-28 therefore requires `core_global_generate_trace_round_2` to compute
the septic inverse and write those columns, matching `populate_real`.

WHY NO GATE CAUGHT IT: every gate was the CPU prover on fibonacci. The host
tracegen fills the column, so the constraint was satisfied there, and fibonacci
barely populates the `Global` unit in the first place. Neither condition
exercises the device path. A core-AIR change needs a RETH BLOCK ON THE GPU as
its gate; nothing less reaches the code that broke.

## Cross-repo consequence

ZR-28 changes the Global chip's main width (58 -> 65), so the checked-in CUDA
zerocheck kernels in `ziren-gpu` go stale. The `zc_air_fingerprint` guard covers
width, so it will refuse the compiled path and fall back to the interpreter —
correct but slow. `gen_zc_kernels` must be rerun and `--check` gated, or the
device computes a quotient for constraints the prover no longer has, which is
the failure that shipped twice before.
