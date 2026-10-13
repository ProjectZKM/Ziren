#!/usr/bin/env python3
"""Fail closed on Lean diagnostics and on the transitive axioms of every theorem."""
import json
import re
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


def main():
    expected = json.loads(Path(sys.argv[2]).read_text())["theorems"] if len(sys.argv) > 2 else None
    try:
        validate(Path(sys.argv[1]).read_text(), expected)
    except ValueError as exc:
        sys.exit(f"proof closure failed: {exc}")


if __name__ == "__main__":
    main()
