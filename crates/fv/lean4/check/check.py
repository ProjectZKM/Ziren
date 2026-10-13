#!/usr/bin/env python3
"""check.py [--no-build] CHIPFILE OUTROOT PREFIX: check one generated chip file in parallel modules.

`split.py` cuts the file into a prelude and dependency-ordered chunk modules; the passes of
`PASSES` then rewrite the modules they match, in order; `make` builds every module with
`run_mod.sh`, one lean process per module, ending with `Check`, which prints the axioms of each
`deterministic`.  A pass only restates or regroups a proof, and Lean re-checks every module, so a
wrong rewrite is an error, never a gap.  See README.md."""
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ALLOWED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}
AXIOMS = re.compile(r"'([^']+)'\s+depends on axioms:\s*\[([^\]]*)\]", re.S)
NO_AXIOMS = re.compile(r"'([^']+)'\s+does not depend on any axioms")


def validate(text, expected=None):
    if re.search(r"declaration uses ['‘`]sorry|sorryAx|PICUS_OPEN|goal admitted|: error", text):
        raise ValueError("Lean output contains an admitted obligation or an error")
    if expected is None:
        return
    found = {}
    for name, axioms in AXIOMS.findall(text):
        if name in found:
            raise ValueError(f"duplicate axiom report: {name}")
        found[name] = {a.strip() for a in axioms.split(",") if a.strip()}
    for name in NO_AXIOMS.findall(text):
        if name in found:
            raise ValueError(f"duplicate axiom report: {name}")
        found[name] = set()
    if set(found) != set(expected) or len(expected) != len(set(expected)):
        raise ValueError("axiom reports do not match the extracted theorem inventory")
    for name, axioms in found.items():
        if axioms - ALLOWED_AXIOMS:
            raise ValueError(f"{name}: unexpected axioms {sorted(axioms - ALLOWED_AXIOMS)}")
    if not re.search(r'^"?PICUS_FILE_DONE"?$', text, re.M):
        raise ValueError("missing completed axiom-check marker")
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


def prepare_proof_cache(root, prefix, identity):
    """Discard compiled modules unless their library/compiler identity is recorded and current."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    stamp = root / ".lean-cache.json"
    expected = {"schema": 1, "prefix": prefix, "inputs": identity}
    try:
        previous = json.loads(stamp.read_text())
    except (OSError, ValueError):
        previous = None
    if identity is None or previous != expected:
        for module in (root / prefix).glob("*.olean*"):
            module.unlink()
        for module in (root / prefix).glob("*.ilean"):
            module.unlink()
    if identity is None:
        stamp.unlink(missing_ok=True)
    else:
        stamp.write_text(json.dumps(expected, sort_keys=True) + "\n")


def main(argv):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from coverage import lean_library_digest, pipeline_digest, verify_lean_project

    build = "--no-build" not in argv
    file, root, prefix = [a for a in argv if a != "--no-build"]
    receipt = Path(root, "closure.json")
    receipt.unlink(missing_ok=True)
    identity = None
    cache_identity = None
    first = Path(file).read_text().splitlines()[0]
    if first.startswith("-- ZIREN_COVERAGE "):
        identity = json.loads(first[len("-- ZIREN_COVERAGE "):])
        try:
            if identity["pipeline_sha256"] != pipeline_digest():
                raise ValueError("generated source uses a different proof pipeline")
            if build:
                project = os.environ["LEAN_PROJECT"]
                verify_lean_project(project)
                if subprocess.run(["lake", "build", "ZirenDet"], cwd=project).returncode:
                    return 1
                compiler = subprocess.run(["lake", "env", "lean", "--version"], cwd=project,
                                          check=True, capture_output=True, text=True).stdout.strip()
                cache_identity = {"library_sha256": lean_library_digest(), "compiler": compiler,
                                  "project": str(Path(project).resolve())}
        except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as exc:
            print(f"proof closure failed: {exc}", file=sys.stderr)
            return 1
    if build:
        prepare_proof_cache(root, prefix, cache_identity)
    if run("split.py", [file, root, prefix]):
        return 3
    for script in ("run_mod.sh", "check.py"):
        src = Path(HERE, script)
        dest = Path(root, script)
        if not dest.exists() or dest.read_bytes() != src.read_bytes():
            shutil.copy(src, dest)
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
        rc = subprocess.run(["make", "-C", root, "-k", f"-j{os.environ.get('JOBS', '12')}", "all"]).returncode
        if rc:
            return rc
        inventory = json.loads(Path(root, "inventory.json").read_text())
        try:
            for module in Path(root, prefix).glob("*.lean"):
                validate(Path(root, "logs", module.stem + ".out").read_text(),
                         inventory["theorems"] if module.stem == "Check" else None)
            validate(Path(root, "logs", "Check.out").read_text(), inventory["theorems"])
            if hashlib.sha256(Path(file).read_bytes()).hexdigest() != inventory["source_sha256"]:
                raise ValueError("source changed during checking")
            if identity:
                if identity["pipeline_sha256"] != pipeline_digest():
                    raise ValueError("proof pipeline changed during checking")
                verify_lean_project(os.environ["LEAN_PROJECT"])
                if cache_identity["library_sha256"] != lean_library_digest():
                    raise ValueError("Lean library changed during checking")
                inventory["pipeline_sha256"] = identity["pipeline_sha256"]
        except (ValueError, OSError) as exc:
            print(f"proof closure failed: {exc}", file=sys.stderr)
            return 1
        receipt.write_text(json.dumps(inventory, indent=2) + "\n")
        return 0
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--validate-log":
        try:
            expected = json.loads(Path(sys.argv[3]).read_text())["theorems"] if len(sys.argv) > 3 else None
            validate(Path(sys.argv[2]).read_text(), expected)
        except (ValueError, OSError) as exc:
            sys.exit(f"proof closure failed: {exc}")
    else:
        sys.exit(main(sys.argv[1:]))
