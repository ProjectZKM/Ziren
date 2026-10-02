# Ziren 2.0 paper sources

LaTeX sources for the Ziren 2.0 paper. The paper is organised along four
layers -- ISA, AIR, PCS, IOPP -- and describes the system as deployed on
the `feat/upgrade-plonky3` lineage (jagged commitment over WHIR, shard-level
LogUp-GKR and zerocheck, instruction frames, septic-curve global digest).

Sections (`sections/`), in reading order. The architecture follows Jolt
(ePrint 2023/1217), with devices from the jagged-PCS paper (theorems with completeness/soundness/efficiency), Cairo (formal step function, limb lemma, "stricter than the relation" list), RISC Zero (verifier checklist, departures from reference analyses), Ceno (displayed block relation), OpenVM (adapter comparison, bus invariants) and Nexus (evaluation questions): background and approach, preliminaries with formal
definitions, an overview of the ISA and the approach, the shared building
blocks and the cost of one row, per-family instruction sections with uniform
tables, "putting it all together", then the back end, recursion, verification,
and a cost estimate before the measurements.

| file | content |
|---|---|
| `01_introduction` | background, the approach, costs, auditable soundness, technical overview (one row worked through), related work, scope |
| `02_preliminaries` | field and MLEs, argument and PCS definitions, codes, hashing, lookups and memory checking, chips/buses/determinism |
| `03_isa` | overview of MIPS32 and the approach: machine state and instruction format, step-transition figure, chips, memory checking, program formatting, syscalls, shards, execution relation, statement |
| `04_air` | instruction frame and buses: words and padding, preprocessed/byte tables, frame, memory argument, global digest and its security, trace uniqueness, cost of a row |
| `045_base` | chips for the base instruction set, family by family |
| `046_ext` | multiplication, division, bit manipulation and system calls |
| `037_argument` | putting it all together: parameters, syntax, bus argument (LogUp-GKR), constraint argument (zerocheck), shard protocol |
| `05_pcs` | dense packing, stacking, jagged reduction and branching program |
| `06_iopp` | WHIR protocol, interleaved commitment, schedule, soundness, proof size |
| `07_recursion` | leaves, compose tree, shrink/wrap, vk allowlist |
| `075_verification` | trusted base, conformance, extracted determinism, defects |
| `08_performance` | per-instruction cost estimate, then the measurements |
| `09_conclusion` | conclusion |
| appendices | `appendix_units` (frame and chips), `appendix_isa`, `appendix_prior` (results imported from prior work, by number), `033_executor`, `035_ipcore` (system boundary), `appendix_ipcore` (interfaces, defects), `appendix_levers` |

`sections/old/` holds the previous migration-narrative draft for reference;
it is not built.

Build: `make` (pdflatex + bibtex). Parameters quoted in the paper come from
`crates/pcs/src/whir/jagged.rs` (`core_whir_config`) and
`docs/soundness/ziren.soundcalc-report.md`; re-check both when the schedule
changes. In that report, `total` is the minimum component level. The paper
therefore cites the separately composed union-bound subtotal and keeps the
Fiat--Shamir query factor and digest term explicit.

Authoring conventions: section content lives in `sections/`, only `ziren-mips32-gpu.tex`
contains `\input{}`; natbib `\citep{}`; math macros (`\F`, `\EF`, `\KB`,
`\WHIR`, `\Jagged`, `\LogUp`, `\Poseidon`, `\Ziren`, `\Zirenver`, `\eqf`,
`\RS`, `\CRS`, `\Fold`) are defined in `ziren-mips32-gpu.tex`.
