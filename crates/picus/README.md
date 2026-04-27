# Picus Extraction Guide

This crate translates machine AIR chips into Picus modules.

## Methodology

The translator follows this pipeline:

1. Select one chip from `MipsAir::<Felt>::chips()` using `--chip`.
2. Evaluate that chip with `PicusBuilder`, which records constraints and lookup interactions.
3. Recursively materialize deferred sub-chip calls into auxiliary modules.
4. Build selector-specialized modules by partial-evaluating the base module with one selector enabled.
5. Emit a `top` module with selector postconditions (bit constraints and one-hot upper bound).
6. Serialize a `*.picus` program to disk.

Relevant entry points:

- CLI + orchestration: `crates/picus/src/main.rs`
- AIR-to-Picus builder logic: `crates/picus/src/picus_builder.rs`
- Picus AST / serialization: `crates/picus/src/pcl/`
- Instruction opcode routing spec: `crates/picus/src/opcode_spec.rs`

## Picus Annotations

Picus annotations are metadata on AIR column structs. They do not change the AIR
semantics or the trace; they only tell the extractor which columns should become
Picus module inputs, outputs, transition state, or selectors.

In the common case, Picus can infer a useful module interface directly from
lookup interactions such as instruction, memory, syscall, and global messages.
That is often enough for chips whose observable behavior is already exposed by
those interactions.

However, interaction-based inference is not always sufficient. In particular,
chips that enforce important semantics across rows can carry state that never
appears directly in an interaction payload. For those chips, Picus annotations
tell the extractor which columns are part of the semantic interface and which
columns should be treated as carried transition state.

The metadata is collected by deriving `PicusAnnotations` on the column struct and
then returning `Cols::<u8>::picus_info()` from the chip's `picus_info()` method.

Supported annotations:

- `#[picus(input)]`
  - Marks the current-row field as a Picus module input.
  - Use this when the extracted module should treat the field as externally supplied
    state for the current row.

- `#[picus(output)]`
  - Marks the current-row field as a Picus module output.
  - Use this when the field is a current-row result you want visible at the Picus
    interface.

- `#[picus(transition_input)]`
  - Marks the current-row field as incoming carried state for transition-capable phases.
  - In practice this means the field is exposed as an input for phases that reason
    about cross-row behavior (`FirstRow`, `Transition`, `Boundary`, `LastRow`).

- `#[picus(transition_output)]`
  - Marks the immediate successor row's version of the field as an output in phases
    that expose successor state (`FirstRow` and `Transition`).
  - Use this when the next-row value is semantically important and you want Picus to
    check determinism of that successor state.

- `#[picus(selector)]`
  - Marks a field as a selector column.
  - The extractor uses selector columns to build selector-specialized modules and
    the optional `top` module that constrains selector shape.

Rule of thumb:

- Start by relying on interaction-driven inference; do not annotate columns just
  because they exist.
- Use `input` / `output` for values that are meaningful on the current row by
  themselves.
- Use `transition_input` / `transition_output` for state that is intentionally
  carried from one row to the next.
- If a field is both incoming carried state and outgoing successor state, mark it
  with both `transition_input` and `transition_output`.
- Do not mark a field as transition state just because it appears in a transition
  constraint. Mark it only when it is part of the semantic row-to-row interface of
  the chip.
- Be conservative with `transition_output`: exporting next-row values makes Picus
  check determinism of that successor state. If the next-row value is padding-only,
  phase-local, or intentionally existential, do not expose it.

Concrete example:

- In `BooleanCircuitGarble`, `delta` and `checks` are carried across gate rows, so
  they are marked with `#[picus(transition_input, transition_output)]`.
- That tells Picus to treat the current row's `delta` / `checks` as inputs and the
  immediate next row's `delta` / `checks` as outputs in the phases where successor
  state is part of the interface.

## OpcodeSpec

`OpcodeSpec` defines how instruction lookups are routed during extraction.

When `PicusBuilder` sees an instruction `send` interaction, it reads the opcode value
from the message payload and calls `spec_for(opcode)`. The resulting spec tells the
extractor:

- `chip`: which opcode-specific chip module should be called.
- `selector`: which selector should be enabled when partially evaluating that chip.
- `arg_to_colname`: how lookup payload slots map onto the target chip columns.

Current use site:

- `MessageBuilder::send` for `LookupKind::Instruction` in `crates/picus/src/picus_builder.rs`.

Why this matters:

- If an opcode is missing in `spec_for`, extraction will panic on that opcode.
- If the `chip` or `selector` is wrong, the generated Picus calls target the wrong module/path.
- If index-to-column mappings are wrong, arguments are wired to incorrect columns.

Rule of thumb:

- Update `opcode_spec.rs` whenever you introduce a new opcode interaction pattern or rename a
  target chip selector/column used by an existing mapping.

## Usage

Run from repository root.

Build:

```bash
cargo build -p zkm-picus
```

Generate a Picus file for one chip:

```bash
cargo run -p zkm-picus -- --chip Branch
```

Useful options:

- `--chip <NAME>`: chip to extract (required).
- `--picus-out-dir <DIR>`: output directory (default: `picus_out`).
- `--assume-selectors-deterministic`: add deterministic assumptions for selector outputs in the top module.
- `PICUS_OUT_DIR=<DIR>`: environment override for output directory.

Example with explicit output directory:

```bash
cargo run -p zkm-picus -- --chip AddSub --picus-out-dir crates/picus/picus_out
```

Output file shape:

- `<OUT_DIR>/<ChipName>.picus`
- Example: `crates/picus/picus_out/Branch.picus`

## Running Picus in AH

After extraction, you can run Picus on the generated file in AH.

Typical flow:

1. Generate the `.picus` file locally (for example `Branch.picus`).
2. Open AH and upload the generated `.picus` file.
3. Run Picus in AH against that uploaded file.
4. Inspect the verification/checking results in AH.

Practical tip:

- If you are iterating quickly, keep a stable output directory (for example
  `crates/picus/picus_out`) so each new extraction is easy to upload and compare.

## Adding Support for a New Chip

This example assumes you added a new machine chip named `MyChip` in `zkm-core-machine`.

1. Expose the chip in the machine chip list.
- Ensure `MipsAir::<Felt>::chips()` includes `MyChip`.
- Ensure the chip has a stable `name()`; this is what `--chip` matches.

2. Ensure the chip has Picus metadata.
- Derive/provide `PicusInfo` metadata for column naming, row I/O, transition state, and selectors.
- Mark selector columns for case-splitting.
- Mark current-row inputs/outputs only when they are intended to be part of the extracted module interface.
- Mark transition inputs/outputs only for fields that are semantically carried across rows.

Example (from `AddSubCols`):

```rust
use zkm_derive::{AlignedBorrow, PicusAnnotations};

#[derive(AlignedBorrow, PicusAnnotations, Default, Clone, Copy)]
#[repr(C)]
pub struct AddSubCols<T> {
    pub pc: T,
    pub next_pc: T,
    pub add_operation: AddOperation<T>,
    pub operand_1: Word<T>,
    pub operand_2: Word<T>,

    #[picus(selector)]
    pub is_add: T,
    #[picus(selector)]
    pub is_sub: T,
}
```

This annotation pattern is what allows extraction to discover selector columns and produce
selector-specialized Picus modules. If the chip also carries row-to-row state, annotate those
fields with `transition_input` / `transition_output` as needed.

Also implement `picus_info` on the chip. For example, here is what needs to be added for the `AddSub` chip. 

```rust
fn picus_info(&self) -> PicusInfo {
    AddSubCols::<u8>::picus_info()
}
```

Without this, the extractor cannot retrieve selector/column metadata for that chip.

3. Ensure the AIR is compatible with extraction.
- The translator replays `chip.air.eval(builder)` using `PicusBuilder`.
- Interactions that go through builder methods (e.g. instruction/ALU/memory sends, assertions) must be expressible in Picus.

4. Add opcode mapping only if needed.
- If your chip emits instruction-style interactions via `send_instruction`/`receive_instruction`, update:
  - `crates/picus/src/opcode_spec.rs`
  - Add/adjust `spec_for(Opcode::...)` entries so opcode -> chip/selector/argument mapping is correct.

5. Run extraction and inspect output.

```bash
cargo run -p zkm-picus -- --chip MyChip --picus-out-dir crates/picus/picus_out
```

6. Validate generated modules.
- Check the generated file for:
  - expected module names (`MyChip` and any aux modules),
  - selector-specialized modules,
  - top-level selector constraints.

## Troubleshooting

- `Chip name must be provided!`
  - Pass `--chip <NAME>`.
- `No chip found named ...`
  - Verify the exact `name()` string exposed by the chip.
- `PicusBuilder needs at least one selector to be enabled!`
  - Ensure the chip exports selector metadata in `PicusInfo`.
