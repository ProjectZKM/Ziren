#!/bin/bash
# regen_all.sh OUT: regenerate every chip's determinism file from this checkout.
#
# 1. `zkm-picus --all` without snippets writes the base chip files (OUT/base).
# 2. Each generated gadget snippet is produced from its chip's base file by the family generator
#    of snippets/tools into OUT/snippets, over a copy of the snippets kept in snippets/ (the
#    hand-written ones); the recipes are $tools/recipes.tsv (snippet, chip, module, generator,
#    arguments), kept with the generators.  The generators are not in the
#    repository: take snippets/tools from the archived snapshot, or point SNIPPET_TOOLS at it.
# 3. `zkm-picus --all` with those snippets writes the chip files (OUT/ZirenDet/Chips), CloClz
#    with `--shrcarry-summary precise`, which its snippet is written for.
#
# The output is deterministic: the same checkout gives byte-identical files.  Check each file
# with check.sh.  Build `zkm-picus` first (`cargo build -r -p zkm-picus`).
set -eu
out=$(realpath -m "$1")
here=$(cd "$(dirname "$0")" && pwd)
lean4=$(dirname "$here")
repo=$(cd "$lean4/../../.." && pwd)
picus=${PICUS:-$repo/target/release/zkm-picus}
tools=${SNIPPET_TOOLS:-$lean4/snippets/tools}
[ -d "$tools" ] || { echo "snippet generators not found at $tools (set SNIPPET_TOOLS)"; exit 2; }
export PICUS_BUDGET_S=${PICUS_BUDGET_S:-1800}
rm -rf "$out/base" "$out/modules" "$out/snippets" "$out/ZirenDet" "$out/ZirenDet.lean"
mkdir -p "$out/base" "$out/modules" "$out/snippets" "$out/empty"

run_picus() {
  local snip=$1 dest=$2
  (cd "$repo" && PICUS_SNIPPET_DIR=$snip "$picus" --all --format lean --derive --derive-diagnose \
    --lean-out-dir "$dest" > "$dest.log" 2>&1)
  (cd "$repo" && PICUS_SNIPPET_DIR=$snip "$picus" --chip CloClz --shrcarry-summary precise \
    --format lean --derive --derive-diagnose --lean-out-dir "$dest" >> "$dest.log" 2>&1)
}

module() {
  python3 - "$1" "$2" "$3" <<'EOF'
import sys
src, mod, out = sys.argv[1:4]
L = open(src).read().split("\n")
outer = next(i for i, l in enumerate(L) if l.startswith("namespace ZirenDet.Chips."))
a = L.index(f"namespace {mod}")
b = next(i for i in range(a, len(L)) if L[i] == f"end {mod}")
close = [l for l in L if l.startswith("end ZirenDet.Chips.")]
open(out, "w").write("\n".join(L[:outer + 1] + [""] + L[a:b + 1] + [""] + close) + "\n")
EOF
}

echo "base chip files"
run_picus "$out/empty" "$out/base"

echo "generated snippets"
cp "$lean4"/snippets/*.lean "$out/snippets/"
while read -r snip chip mod gen extra; do
  [ -z "$snip" ] || [ "${snip#\#}" != "$snip" ] && continue
  module "$out/base/ZirenDet/Chips/$chip.lean" "$mod" "$out/modules/$mod.lean"
  (cd "$tools" && python3 "$gen" "$out/modules/$mod.lean" $extra "$out/snippets/$snip.lean" \
    > "$out/modules/$snip.log" 2>&1) || { echo "generator failed: $snip"; exit 1; }
done < "$tools/recipes.tsv"

echo "chip files"
run_picus "$out/snippets" "$out"
echo "$(ls "$out/ZirenDet/Chips" | wc -l) chip files in $out/ZirenDet/Chips"
