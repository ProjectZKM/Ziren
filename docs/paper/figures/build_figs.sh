#!/usr/bin/env bash
# Compile every figures/*.tex as a standalone PDF (+ 300 dpi PNG) into figures/out/,
# using the paper's own preamble so macros and fonts match the text.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p figures/out
# preamble = main.tex between \documentclass and \title, minus page/hyperlink packages
sed -n '/\\documentclass/,/\\title/p' main.tex | sed '1d;$d' \
  | sed '/\\hypersetup{/,/^}/d' \
  | grep -vE 'geometry|hyperref|natbib' \
  > figures/out/_preamble.tex
for f in figures/*.tex; do
  n=$(basename "$f" .tex)
  cat > "figures/out/_$n.tex" <<W
\documentclass[border=3pt]{standalone}
\input{figures/out/_preamble}
\begin{document}
\input{$f}
\end{document}
W
  pdflatex -interaction=nonstopmode -halt-on-error -output-directory=figures/out -jobname="$n" "figures/out/_$n.tex" >/dev/null \
    || { echo "FAILED $n (see figures/out/$n.log)"; continue; }
  pdftoppm -r 300 -png -singlefile "figures/out/$n.pdf" "figures/out/$n"
  echo "built figures/out/$n.pdf figures/out/$n.png"
done
rm -f figures/out/_*.tex figures/out/*.aux figures/out/*.log
