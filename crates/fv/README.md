# `fv` — formal verification of the Ziren machine

Two components, one flow.

| Component | Language | What it does |
|---|---|---|
| [`picus/`](picus) | Rust (`zkm-picus`) | Reads every chip's AIR and emits determinism obligations, as `.picus` programs for the Picus solver and as Lean 4 files. |
| [`lean4/`](lean4) | Lean 4 + Mathlib (`ZirenDet`) | Discharges those obligations, and holds the executable MIPS32r2 model checked against the emulator's specification vectors. |

The extractor is run from the repository root; the Lean project is built on the GPU box.
Start with [`lean4/README.md`](lean4/README.md) for what the theorems say and why, and
[`picus/README.md`](picus/README.md) for how they are produced.
