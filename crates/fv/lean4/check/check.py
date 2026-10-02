#!/usr/bin/env python3
"""check.py [--no-build] CHIPFILE OUTROOT PREFIX: check one generated chip file in parallel modules.

`split.py` cuts the file into a prelude and dependency-ordered chunk modules; the passes of
`PASSES` then rewrite the modules they match, in order; `make` builds every module with
`run_mod.sh`, one lean process per module, ending with `Check`, which prints the axioms of each
`deterministic`.  A pass only restates or regroups a proof, and Lean re-checks every module, so a
wrong rewrite is an error, never a gap.  See README.md."""
import glob
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# A pass rewrites every chunk module `C*.lean` that holds a theorem matching `theorem` (and, if
# given, a line matching `guard`; with `alone`, no other theorem).  `args` is filled per module
# with {root} {prefix} {mod} {thm} {file}; with `backup` the module is first copied to
# `{file}.preflat`; a pass that fails leaves the module as generated.
PASSES = [
    dict(script="lift_steps.py", theorem=r"^theorem ([A-Za-z0-9_]*_int|op_identity)$", alone=True,
         args="{root} {prefix} {mod} {thm} 4"),
    dict(script="flat_gadget.py", theorem=r"^theorem (gadget_det)", guard=r"^  have c[0-9]*g := And\.",
         backup=True, args="{file}.preflat {file}"),
    dict(script="flat_gadget.py", theorem=r"^theorem (row_spec)", guard=r"^  obtain ⟨c0g, ",
         backup=True, args="{file}.preflat {file} row_spec"),
    dict(script="flat_det.py", theorem=r"^theorem (deterministic)", args="{root} {prefix} {mod}"),
]


def run(script, args):
    return subprocess.run([sys.executable, os.path.join(HERE, script)] + args).returncode


def main(argv):
    build = "--no-build" not in argv
    file, root, prefix = [a for a in argv if a != "--no-build"]
    if run("split.py", [file, root, prefix]):
        return 3
    shutil.copy(os.path.join(HERE, "run_mod.sh"), os.path.join(root, "run_mod.sh"))
    for p in PASSES:
        for path in sorted(glob.glob(os.path.join(root, prefix, "C*.lean"))):
            text = open(path, encoding="utf-8").read()
            names = re.findall(p["theorem"], text, re.M)
            if not names or ("guard" in p and not re.search(p["guard"], text, re.M)):
                continue
            if p.get("alone") and len(re.findall(r"^theorem", text, re.M)) != 1:
                continue
            if p.get("backup"):
                shutil.copy(path, path + ".preflat")
            mod = os.path.basename(path)[:-5]
            if run(p["script"], p["args"].format(root=root, prefix=prefix, mod=mod, thm=names[0], file=path).split()):
                print(f"{p['script']}: {mod} kept as generated")
    if build:
        return subprocess.run(["make", "-C", root, "-k", f"-j{os.environ.get('JOBS', '12')}", "all"]).returncode
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
