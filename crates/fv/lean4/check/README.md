# Checking the chip determinism theorems

A generated chip file is up to tens of megabytes of one theorem, and Lean elaborates a declaration
on one thread with a local context every tactic pays for. These scripts check such a file as many
small modules built in parallel, without changing what is proved: every rewrite only restates or
regroups a proof, and Lean re-checks every module, so a wrong rewrite is an error, never a gap.

```bash
cargo build -r -p zkm-picus
SNIPPET_TOOLS=/path/to/snippets/tools crates/fv/lean4/check/regen_all.sh /scratch/regen
export LEAN_PROJECT=/path/to/lake/project   # its `lake env` provides Mathlib and ZirenDet
crates/fv/lean4/check/check.py /scratch/regen/ZirenDet/Chips/MiscInstrs.lean /scratch/misc SpMisc
```

| File | Role |
|---|---|
| `regen_all.sh OUT` | Regenerates every chip file: base files, the gadget snippets generated from them by the recipes in `$SNIPPET_TOOLS/recipes.tsv`, then the chip files with those snippets. Byte-identical between runs. |
| `check.py FILE ROOT PREFIX` | Splits the file (`split.py`), applies each pass of its `PASSES` table to the modules it matches, and runs `make`. `--no-build` stops before `make`. |
| `split.py` | Prelude module for definitions no theorem depends on; theorems in chunk modules by dependency level, packed to about 40 KB, each importing exactly the chunks it uses; a `Makefile` and `Check.lean`, which prints `#print axioms` for every `deterministic`. |
| `lift_steps.py` | Moves the top-level `have` steps of one theorem into lemmas in their own modules. |
| `flat_gadget.py` | Rewrites a snippet's `gadget_det` or `row_spec` so its constraint conjuncts are projected where used instead of opened as hypotheses. |
| `flat_det.py` | Rewrites a generated `deterministic` so neither witness is split into its fields: each step lemma gets an adapter that restates it over projections of the whole witnesses. |
| `leanmod.py` | Shared plumbing: reading and writing modules, locating a theorem, adding modules to the `Makefile`. |
| `run_mod.sh` | Elaborates one module under a memory gate (`MIN_FREE` GB) and a time cap (`MOD_TIMEOUT`, 1800 s), logging `START`/`END` with `rc`, `sorry`, open-step and error counts to `progress.log`. |

A chip is closed when `Check` prints only `propext`, `Classical.choice` and `Quot.sound` for every
`deterministic`, and every `END` line in `progress.log` shows `rc=0 sorry=0`.
