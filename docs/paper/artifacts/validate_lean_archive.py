#!/usr/bin/env python3
"""Audit archive hashes, theorem receipts and current-AIR contract equality."""
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def contracts(path):
    """Compare every non-proof declaration and each public determinism type.

    Derivation hints may change proof terms without changing the AIR relation.
    Keep the namespaces and all definitions, including gadget relations, so a
    matching theorem name alone cannot justify reusing a checker receipt.
    """
    text = path.read_text()
    starts = list(re.finditer(r"^(?:namespace |end |(?:noncomputable )?(?:def|abbrev|structure|opaque|instance|inductive|class|axiom|theorem|lemma)\b)", text, re.M))
    result = []
    for i, match in enumerate(starts):
        declaration = text[match.start():starts[i + 1].start() if i + 1 < len(starts) else len(text)].strip()
        if declaration.startswith(("namespace ", "end ")):
            result.append(declaration.splitlines()[0])
        elif declaration.startswith(("theorem ", "lemma ")):
            if declaration.startswith("theorem deterministic"):
                result.append(declaration.split(":= by", 1)[0].strip())
        else:
            result.append(declaration)
    assert any(s.startswith("theorem deterministic") for s in result), path
    return result


def main():
    root = Path(sys.argv[1]).resolve()
    manifest = json.loads((root / "manifest.json").read_text())
    for relative, expected in manifest["files_sha256"].items():
        assert digest(root / relative) == expected, relative
    checker_path = root / "source/crates/fv/lean4/check/check.py"
    spec = importlib.util.spec_from_file_location("checker", checker_path)
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    modules = theorems = 0
    for name, entry in manifest["chips"].items():
        checked = root / "checked-generated" / (name + ".lean")
        current = root / "generated" / (name + ".lean")
        folder = root / "checks" / name
        receipt = json.loads((folder / "closure.json").read_text())
        assert receipt["source_sha256"] == digest(checked), name
        cache = json.loads((folder / ".lean-cache.json").read_text())
        assert cache["inputs"]["library_sha256"] == checker.lean_library_digest(), name
        if "lean_inputs" in receipt:
            assert receipt["lean_inputs"] == cache["inputs"], name
        assert receipt["theorems"] == entry["theorems"], name
        assert contracts(checked) == contracts(current), name
        checker.validate((root / "fresh-axioms" / (name + ".out")).read_text(), receipt["theorems"])
        prefix = entry["module_prefix"]
        sources = list((folder / prefix).glob("*.lean"))
        assert len(sources) == entry["modules"], name
        for source in sources:
            checker.validate((folder / "logs" / (source.stem + ".out")).read_text(),
                             receipt["theorems"] if source.stem == "Check" else None)
        modules += len(sources)
        theorems += len(receipt["theorems"])
    assert (len(manifest["chips"]), theorems, modules) == (57, 104, manifest["modules"])
    print(f"Validated {len(manifest['chips'])} chips, {theorems} theorems, {modules} modules; current-AIR contracts match checked proofs.")


if __name__ == "__main__":
    main()
