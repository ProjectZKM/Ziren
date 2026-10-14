# Ziren 2.0 paper sources

LaTeX sources for the Ziren 2.0 paper. The paper is organised along four
layers -- ISA, AIR, PCS, IOPP -- and describes the system as deployed on
the `feat/upgrade-plonky3` lineage (jagged commitment over WHIR, shard-level
LogUp-GKR and zerocheck, instruction frames, septic-curve global digest).

Sections (`sections/`), in reading order. The architecture follows Jolt
(ePrint 2023/1217), with devices from the jagged-PCS paper (theorems with completeness/soundness/efficiency), Cairo (formal step function, limb lemma, "stricter than the relation" list), RISC Zero (verifier checklist, departures from reference analyses), Ceno (displayed block relation), OpenVM (adapter comparison, bus invariants) and Nexus (evaluation questions): background and approach, preliminaries with formal
definitions, an overview of the ISA and the approach, the shared building
blocks and the cost of one row, per-family instruction sections with uniform
tables, then the back end, verification,
and a cost estimate before the measurements.

| file | content |
|---|---|
| `01_introduction` | background, the approach, costs, auditable soundness, technical overview (one row worked through), related work, scope |
| `02_preliminaries` | field and MLEs, argument and PCS definitions, codes, hashing, lookups and memory checking, chips/buses/determinism |
| `03_architecture` | architecture: Ziren up to the compressed proof (figure, Algorithm 1, execution, shard and block protocols, parameters), then applications (shrink, then wrap for on-chain or binary/narrow for garbled verification) |
| `03_isa` | MIPS32 and the execution relation: machine state and instruction format, step-transition figure, program formatting, shards, execution relation, statement |
| `04_air` | instruction frame and buses: words and padding, preprocessed/byte tables, frame, memory argument, global digest and its security, trace uniqueness, cost of a row |
| `045_base` | chips for the base instruction set, family by family |
| `046_ext` | multiplication, division, bit manipulation and system calls |
| `05_pcs` | dense packing, stacking, jagged reduction and branching program |
| `06_iopp` | WHIR protocol, interleaved commitment, schedule, soundness, proof size |
| `065_security` | security relation, soundness accounting, compose and root checks, verifying-key binding and cross-shard digest |
| `075_verification` | trusted base, conformance, extracted determinism, defects |
| `08_performance` | per-instruction cost estimate, then the measurements |
| `09_conclusion` | conclusion |
| appendices | `appendix_units` (frame and chips), `appendix_isa`, `appendix_prior` (results imported from prior work, by number) |

`sections/old/` holds the previous migration-narrative draft for reference;
it is not built.

Build: `make` (pdflatex + bibtex). Protocol parameters come from
`crates/pcs/src/whir/jagged.rs`. Matching soundness inputs, the machine census,
component report and reproduction script are retained as local validation evidence
and are not included in this repository.
The report uses the current core and Johnson-bound root schedules, sums the
floored component errors and counts the final-query term once. It reproduces
the soundness table's stage bounds of 100.74 and 101.10 bits. The Fiat–Shamir query factor
and unquantified binding and digest terms remain separate.

The local evidence also includes the allowlist-enabled compressed-proof benchmark:
290,643 bytes and 25.2 ms median native verification over five warm runs.

Authoring conventions: section content lives in `sections/`, only `ziren-mips32-gpu.tex`
contains `\input{}`; natbib `\citep{}`; math macros (`\F`, `\EF`, `\KB`,
`\WHIR`, `\Jagged`, `\LogUp`, `\Poseidon`, `\Ziren`, `\Zirenver`, `\eqf`,
`\RS`, `\CRS`, `\Fold`) are defined in `ziren-mips32-gpu.tex`.
