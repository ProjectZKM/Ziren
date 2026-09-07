# Ziren 2.0 paper sources

LaTeX sources for the Ziren 2.0 paper. The paper is organised along four
layers -- ISA, AIR, PCS, IOPP -- and describes the system as deployed on
the `feat/upgrade-plonky3` lineage (jagged commitment over WHIR, shard-level
LogUp-GKR and zerocheck, instruction frames, septic-curve global digest).

Sections (`sections/`):

| file | content |
|---|---|
| `01_introduction` | overview along the four layers, contributions |
| `02_preliminaries` | field, MLE/sumcheck, (constrained) Reed--Solomon codes, hashing, lookups |
| `03_isa` | MIPS32r2 guest, delay slots, syscalls/precompiles, clock and shards, executor |
| `04_air` | chip set, instruction frame, register/memory argument, global digest, LogUp-GKR, zerocheck |
| `05_pcs` | dense packing, stacking, jagged reduction and branching program |
| `06_iopp` | WHIR protocol, interleaved commitment, production schedule, soundness, proof size |
| `07_recursion` | leaves, compose tree, shrink/wrap, vk allowlist |
| `08_performance` | single-card census and measured levers |
| `09_related_work`, `10_conclusion` | |

`sections/old/` holds the previous migration-narrative draft for reference;
it is not built.

Build: `make` (pdflatex + bibtex). Parameters quoted in the paper come from
`crates/pcs/src/whir/jagged.rs` (`core_whir_config`) and
`docs/soundness/ziren.soundcalc-report.md`; re-check both when the schedule
changes.

Authoring conventions: section content lives in `sections/`, only `main.tex`
contains `\input{}`; natbib `\citep{}`; math macros (`\F`, `\EF`, `\KB`,
`\WHIR`, `\Jagged`, `\LogUp`, `\Poseidon`, `\Ziren`, `\Zirenver`, `\eqf`,
`\RS`, `\CRS`, `\Fold`) are defined in `main.tex`.
