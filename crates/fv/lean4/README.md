# ZirenDet — the Lean 4 half of the formal-verification flow

This Lake project holds the machine-checked part of Ziren's verification collateral. It
answers two questions that testing alone cannot:

1. **Is each chip's constraint system deterministic?** Given everything a row receives from
   other tables, are the values it produces for other tables *forced* by its constraints? A
   chip that is not deterministic admits two satisfying rows with the same inputs and
   different outputs, which means a malicious prover can choose the output.
2. **Does the emulator implement MIPS32r2?** An executable Lean model of the ISA is replayed
   against the same oracle vectors the Rust emulator is checked against, so the oracle, the
   emulator and the model must agree on every vector.

The first is generated from the circuits by the sibling crate
[`crates/fv/picus`](../picus); the second is generated from the specification vectors in
`crates/core/executor/tests/spec_vectors`. Nothing here is written by hand except the
prelude, the tactic and the ISA model.

## Why determinism is the right property

Determinism is weaker than functional correctness and much easier to discharge, but it is
what closes the gap that soundness leaves open. An accepting proof implies a *satisfying*
trace. Determinism says a satisfying trace is *unique* given the entry state and the program
image (Theorem "trace uniqueness" in the paper, §5.6): the bus arguments chain the rows, and
determinism of each chip propagates the uniqueness along the chain. Since an honest execution
produces one satisfying trace, uniqueness means it is the only one, and therefore that the
proved output is the emulator's output.

The notion is Picus's, adapted to the interaction language: a row's **inputs** are the tuples
it receives, the instruction it fetches, and the previous values of the addresses it reads;
its **outputs** are the tuples it sends and the new values it writes. Note the polarity — a
program fetch and a previous memory value are *sends* on the bus but *inputs* to the row.

## Layout

| Path | Origin | What it is |
|---|---|---|
| `ZirenDet/Lib.lean` | hand-written | The field `F = ZMod (2^31 - 2^24 + 1)`, the lifting lemmas from `F` to bounded integers, and the `picus_det` tactic. |
| `ZirenDet/Safe.lean` | hand-written | `picus_safe`, a wrapper that catches any runtime failure of the automation and admits the goal, so a generated file always elaborates. |
| `ZirenDet/Basic.lean` | generated | The prelude every generated chip file imports. |
| `ZirenDet/Chips/*.lean` | generated (64 files) | One file per chip; inside, one *module* per opcode selector, each with its determinism theorem. |
| `ZirenDet/Isa.lean` | hand-written | Executable MIPS32r2 semantics: `decode`, `step`, `run`. Little-endian, delay slots, `$zero` sink, separate `HI`/`LO`. |
| `ZirenDet/IsaVectors.lean` | generated | 770 specification vectors replayed through `Isa.run`, each `by native_decide`. |
| `ZirenDet/IsaDecode.lean` | generated | 2275 decodings of real instruction words checked against the emulator's decoder output. |
| `ZirenDet/Bridge/*.lean` | hand-written | The *functional* direction: this chip computes *that* ISA function. One worked example (`AddSub`), still open. |

## What a generated theorem looks like

For every module `M` (a chip specialised to one opcode selector) the file defines a witness
structure `M.W` with one field per column, the predicate `M.constraints`, the projections
`M.inputs` / `M.outputs` / `M.assumed`, and:

```lean
theorem M.deterministic
    (h_Aux : ∀ i o o', Aux.rel i o → Aux.rel i o' → o = o')   -- one per byte-table helper
    (w w' : W) (hw : constraints w) (hw' : constraints w')
    (hin : inputs w = inputs w') (hassume : assumed w = assumed w') :
    outputs w = outputs w'
```

Byte-table operations are `opaque rel`s, so their determinism enters as a *hypothesis* of the
caller rather than an axiom. Columns are named after their provenance
(`in_mem_read_0_val`, `out_mem_write_2_val`, `in_program_op_a_0`), which is what makes the
bridge theorems readable.

## How the automation closes a goal

`picus_det` lifts the statement out of the field. Each column is replaced by an integer
carrying the bound its range fact gives — a bit, a byte, a 16-bit limb, or `[0, p)` when
nothing constrains it — every field equation becomes an exact integer equation once its slack
is shown to vanish under those bounds, and the residue is linear arithmetic over bounded
integers for `omega`. Between the lift and the decision it replays Picus's propagation loop
inside the proof assistant: prove one pair of corresponding columns equal, substitute, resolve
selector bits to constants, and case-split only on selector bits already known to agree.

`picus_safe` wraps every call. A heartbeat overrun or a recursion-depth overflow is caught,
the state is restored and the goal is admitted, so an expensive chip degrades to an open
obligation instead of breaking the build. The budget is an option, in the same thousands unit
as `maxHeartbeats`:

```lean
set_option picus.safeHeartbeats 40000000   -- what the generator emits
```

Set it lower to fail fast while iterating on the tactic. Setting it too low silently converts
every theorem into a `sorry`, so check the count after changing it.

## Building

**Builds run on the GPU box, never on the dev host.** Mathlib plus 64 generated files is tens
of gigabytes of elaboration; individual chip files have peaked above 200 GB of resident
memory, so run them where there is room and watch the machine.

```bash
# from the repo root
rsync -a --exclude .lake crates/fv/lean4/ ant-5090-2:/mnt_zkm/stephen/lean4/

ssh ant-5090-2 'export ELAN_HOME=/mnt_zkm/stephen/.elan \
                       PATH=/mnt_zkm/stephen/.elan/bin:$PATH \
                       XDG_CACHE_HOME=/mnt_zkm/stephen/.cache
                cd /mnt_zkm/stephen/lean4 && lake build 2>&1 | tee build.log'
```

`ELAN_HOME` and `XDG_CACHE_HOME` matter: a non-interactive shell has no toolchain on its
`PATH`, and without them `lake` re-downloads the toolchain onto the box's nearly full root
filesystem.

To work on one chip, build its module alone — the files are independent:

```bash
lake build ZirenDet.Chips.AddSub
```

Kill a runaway file by explicit PID (`ps -o pid,rss,args -C lean --sort=-rss`). Never
`pkill -f lean` on the box: the pattern matches the ssh session running it, and it will take
down the other files with it.

## Reading the result

Every theorem statement compiles; an unproved one carries an explicit `sorry` and surfaces as
a warning. The census is therefore a grep over the build log:

```bash
grep -c "declaration uses 'sorry'" build.log        # open obligations
grep -n  "declaration uses 'sorry'" build.log       # and where they are
```

Open obligations fall into a few families, and the family matters more than the count:

- **Integer units** whose constraints multiply by `2^24` or `2^32` and are only meaningful
  modulo `p` — multiply, the conditional moves, the memory-argument units. The integer lifting
  does not model these, so the tactic cannot close them as written.
- **Accelerator units** above the size threshold: the same theorem at one to five thousand
  conjuncts.
- **Comparison case-splits** introduced by the byte-table summaries, which the tactic does not
  yet handle.
- **Timeouts**, admitted by `picus_safe`.

An open obligation is not a known bug. It is an unchecked claim, and the four families above
say which kind of work would close it.

## Regenerating

The three generated groups have three separate generators. Regenerate after any change to the
corresponding source of truth.

```bash
# 1. chip determinism theorems, after any AIR change
cargo run -p zkm-picus -- --all --format lean --lean-out-dir crates/fv/lean4

# 2. ISA conformance vectors, after adding instructions or vectors
#    SPEC_LEAN_PER_INSTRUCTION defaults to 2; use 10 for the full 770-example set
SPEC_LEAN_PER_INSTRUCTION=10 python3 crates/core/executor/tests/spec_vectors/gen_lean.py
python3 crates/core/executor/tests/spec_vectors/gen_decode.py
```

Both write into `ZirenDet/`, and both overwrite. Diff before committing: a silently truncated
vector set looks exactly like a successful run.

## Known limits

- **Determinism, not correctness.** A closed theorem says the chip has *one* behaviour, not
  that it is the *right* one. The `Bridge/` files state the right-behaviour direction against
  `ZirenDet.Isa`; only the `AddSub` example exists, and it is still `sorry`. Completing the
  bridge for every chip is what would turn the flow into machine-checked functional
  correctness of the arithmetisation.
- **The trace-uniqueness theorem is on paper.** The per-chip theorems here are its premises.
  The two bus lemmas and the induction that composes them are written in the paper (§5), not
  in Lean.
- **The recursion machine is out of scope.** Nothing here covers the leaf, compose, shrink or
  wrap programs.
- **The ISA model is checked, not proved.** `Isa.lean` agrees with the oracle on 770 vectors
  and with the emulator's decoder on 2275 words. That is conformance evidence, not a proof
  that the model is the specification.
