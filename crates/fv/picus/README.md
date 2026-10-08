# Determinism extraction (Picus + Lean 4)

`zkm-picus` turns every chip of the MIPS machine into a set of *determinism modules* and writes
them as

- `*.picus` programs for the Picus solver, and
- Lean 4 files whose theorems state the same obligations, to be checked (and proved) in Lean.

A module is deterministic when its outputs are a function of its inputs.  For an AIR that means:
given everything a row receives from other tables, the values it produces for other tables are
forced by its constraints.

## Pipeline

1. `MipsAir::<KoalaBear>::chips()` supplies the chips; `--chip NAME` (repeatable), `--all`, or
   `--list`.
2. [`PicusBuilder`](src/picus_builder.rs) evaluates the chip's AIR once.  Its `Expr` type is
   Plonky3's `SymbolicExpression<KoalaBear>`, so the builder is an ordinary `AirBuilder` +
   `MessageBuilder` that records `assert_zero` polynomials and `send` / `receive` lookups.
3. [`lower`](src/lower.rs) turns the recorded symbolic trees into Picus expressions over a fixed
   variable numbering (main column `i` is variable `i`), memoizing shared sub-trees and binding
   sub-trees larger than `--reify-threshold` to fresh variables.
4. The interface is derived from the lookups (see the table in `picus_builder.rs`): program
   fetches, memory reads, the received CPU / precompile state and syscall arguments are inputs;
   memory writes, the sent state, syscall calls and global sends are outputs.  Byte-table lookups
   become range / bit constraints or calls to abstract helper modules (`byte_and`, …).
5. One module is emitted per `#[picus(selector)]` column, specialized with that selector at one,
   the others at zero and `is_real` at one (`Chip__is_xxx`); a chip without selectors gets one
   module.  A `top` module proves the selector shape (boolean, mutually exclusive, or a partition
   of the real rows when the chip declares `selectors_partition_real_rows`).
   Two more obligations cover the lookup multiplicities, because a determinism theorem takes
   every lookup of the row as a fact about that row, and the lookup argument only justifies that
   reading when no row sends with a negative multiplicity: a `padding` module, specialized with
   `is_real = 0` and every selector at zero, has the postcondition `m = 0` for every lookup
   multiplicity `m` (a padding row takes part in no bus and no table), and every real-row module
   has the postcondition `bit(m)` for each of its non-constant multiplicities.  A chip with
   neither `is_real` nor selectors gets no `padding` module.
6. `--format picus|lean|both` writes `<picus-out-dir>/<Chip>.picus` and
   `<lean-out-dir>/ZirenDet/Chips/<Chip>.lean` (plus `ZirenDet.lean` and the prelude
   `ZirenDet/Basic.lean`).

Every chip is a single-row AIR today (cross-row sequencing lives on lookup buses: `State`,
`GlobalAccumulation`, `PrecompileChain`, …), so one extraction phase suffices; the old
`FirstRow` / `Transition` / `LastRow` phases and the Instruction-bus opcode routing are gone.

## Annotations

Annotations are metadata on the column struct; they never change the AIR.

```rust
use zkm_derive::{AlignedBorrow, PicusAnnotations};
use zkm_pcs::PicusInfo;

#[derive(AlignedBorrow, PicusAnnotations, Default, Clone, Copy)]
#[repr(C)]
pub struct AddSubCols<T> {
    #[picus(input)]
    pub pc: T,
    pub next_pc: T,
    #[picus(selector)]
    pub is_add: T,
    #[picus(selector)]
    pub is_sub: T,
    pub frame: RTypeFrameCols<T>,
}
```

and on the chip:

```rust
fn picus_info(&self) -> PicusInfo {
    AddSubCols::<u8>::picus_info()
}
```

- `#[picus(selector)]` — an opcode / row-type flag; one specialized module per selector.
- `#[picus(input)]` / `#[picus(output)]` — add a column to the interface on top of what the
  lookups imply.  Most chips need none: the interface is inferred.
- A field named `is_real` is detected automatically and specialized to one.
- `#[picus(transition_input)]` / `#[picus(transition_output)]` are accepted for compatibility
  with the multi-row history; with single-row chips they have no effect.
- `#[derive(PicusProjection)]` describes a semantic slice of a larger witness layout for
  operation summaries (see `PicusProjectionInfo`); no chip uses it after the sub-AIRs were
  inlined.

Chip-level hooks on `MachineAir`: `selectors_partition_real_rows()` (stronger `top` contract) and
`picus_selector_specialization_allowed(name)` (skip impossible selector values).

## Usage

```bash
cargo run -p zkm-picus -- --list
cargo run -p zkm-picus -- --chip AddSub --picus-out-dir picus_out --lean-out-dir crates/fv/lean4
cargo run -p zkm-picus -- --all --format lean --lean-out-dir crates/fv/lean4
```

Options: `--assume-selectors-deterministic`, `--shrcarry-summary abstract|precise`,
`--column-output-mode interactions-only|all-non-inputs-are-outputs`, `--reify-threshold N`
(0 disables), `--keep-padding` (do not specialize `is_real = 1`).

## Triage

`--analyze` runs the propagation engine on every module and prints one `ANALYZE` line per
determinism module, then for the multiplicity obligations:

```
PADDING SysLinux proved 0/42 assumed 0
PADDING-UNPROVED SysLinux send.byte[0] decode_brk_50: stuck (1 unknown)
MULTBITS Bitwise__is_and proved 0/4 assumed 4
MULTBITS-ASSUMED Bitwise__is_and send.byte[0] lookup_gate_2 if bus inputs frame_14 are bits
```

`PADDING` counts the multiplicities proved zero on a padding row, `MULTBITS` those proved bits
on a real row; each is tried first by the engine (the expression bound to a fresh output with no
inputs, so its value must follow from the constraints), then by cases on the variables the
constraints bound to `{0, 1}`, re-specializing the constraints under each case so a flag that
is a bit only under a gate is found once the gate is set.  `ASSUMED` lines are multiplicities
that are bits if an input the row receives from another table is one (an opcode flag of the
program table): a hypothesis of the statement, not a hole.  `UNPROVED` lines name the
multiplicity by its column; an unconstrained one there is a free lookup multiplicity, which is
how the `SysLinux` padding rows were found to carry `has_comparison` and the decode flags.

## Lean

`--format lean` writes into [`crates/fv/lean4`](../lean4), a Lake project pinned to Mathlib
`v4.33.1`. For every module `M` the generated file contains a witness structure `M.W`,
`M.constraints`, `M.inputs`, `M.outputs`, `M.assumed`, the relation `M.rel`, and a theorem
`M.deterministic` saying that two satisfying rows agreeing on their inputs agree on their
outputs, and `M.postconditions` for the multiplicity bits; the `padding` module's
`postconditions` theorem states that every multiplicity is zero on a padding row.  A
postcondition is a fact about one witness, so its proof projects the few conjuncts that reach its
columns out of `constraints w` and closes with `grind`, splitting the goal's bits when needed; a
multiplicity that is a bit only because a bus input is one takes that as a hypothesis
(`hbit_vN`), the same assumption the triage reports as `ASSUMED`.  Determinism
of the abstract byte-table helpers enters as a hypothesis, never an axiom, and the closing
tactic leaves a `sorry` when it cannot finish, so files always elaborate and open obligations
are the `declaration uses 'sorry'` warnings.

That project's [README](../lean4/README.md) covers the theorem shape, the proof automation,
how to build it on the GPU box, and how to read the open obligations. Builds never run on the
dev host.

## Adding a chip

1. Make sure `MipsAir::chips()` includes it and `name()` is stable.
2. Derive `PicusAnnotations` on its column struct, mark selectors, add `picus_info()`.
3. Run the extractor on it and read the module interface in the `.picus` file (inputs first,
   then outputs); if a value the chip is responsible for is missing, annotate it as
   `#[picus(output)]`.
4. If the AIR uses a new lookup kind, add its direction to `Emitter::handle_lookup`.
