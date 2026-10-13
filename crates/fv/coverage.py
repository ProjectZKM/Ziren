#!/usr/bin/env python3
"""Bind determinism coverage to AIR fingerprints and checked generated proof files.

snapshot leaves new or changed AIRs pending and preserves unchanged receipts; check rejects drift;
record promotes a chip only from a strict checker receipt for its stamped source.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

FV = Path(__file__).resolve().parent
REPO = FV.parents[1]
MANIFEST = FV / "coverage.json"
EXCLUDED = {"Program": "preprocessed table", "Byte": "preprocessed table",
            "Range": "preprocessed table", "ShaExtendControl": "opaque SHA-256 helper",
            "ShaCompressControl": "opaque SHA-256 helper"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate_proof_evidence(name, entry):
    source = entry.get("source_sha256")
    theorems = entry.get("theorems")
    if not isinstance(source, str) or not re.fullmatch(r"[0-9a-f]{64}", source):
        raise ValueError(f"{name}: invalid checked source hash")
    if (not isinstance(theorems, list) or not theorems
            or any(not isinstance(t, str) or not re.fullmatch(
                rf"ZirenDet\.Chips\.{re.escape(name)}\.[A-Za-z_][A-Za-z0-9_]*"
                r"(?:\.[A-Za-z_][A-Za-z0-9_]*)*\.deterministic", t)
                   for t in theorems)
            or len(set(theorems)) != len(theorems)):
        raise ValueError(f"{name}: invalid determinism theorem inventory")


def lean_project_inputs():
    reference = FV / "lean4"
    paths = [p for p in reference.glob("ZirenDet/**/*.lean")
             if "Chips" not in p.parts and p.name != "Chips.lean"]
    return paths + [reference / name for name in
                    ("ZirenDet.lean", "lean-toolchain", "lake-manifest.json", "lakefile.toml")]


def lean_library_digest():
    """Semantic build inputs that compiled chip proofs must never outlive."""
    h = hashlib.sha256()
    for p in sorted(lean_project_inputs()):
        for data in (p.relative_to(FV / "lean4").as_posix().encode(), p.read_bytes()):
            h.update(len(data).to_bytes(8, "little"))
            h.update(data)
    return h.hexdigest()


def snippet_tools_digest(directory):
    directory = Path(directory)
    paths = [p for p in directory.rglob("*") if p.is_file()
             and "__pycache__" not in p.parts
             and (p.suffix in {".py", ".lean", ".tmpl", ".tac", ".tsv", ".txt"}
                  or p.name == "README")]
    h = hashlib.sha256()
    for p in sorted(paths):
        for data in (p.relative_to(directory).as_posix().encode(), p.read_bytes()):
            h.update(len(data).to_bytes(8, "little"))
            h.update(data)
    return h.hexdigest()


def snippet_tools_pin():
    pin = json.loads((FV / "coverage.json").read_text()).get("snippet_tools_sha256")
    if not isinstance(pin, str) or not re.fullmatch(r"[0-9a-f]{64}", pin):
        raise ValueError("coverage.json has no valid external generator fingerprint")
    return pin


def pipeline_digest():
    # Include the lowering, proof generators, gadget lemmas, checker and dependency pins.
    paths = set(FV.glob("picus/src/**/*.rs")) | set(lean_project_inputs())
    paths |= set(FV.glob("lean4/snippets/**/*.py")) | set(FV.glob("lean4/snippets/**/*.lean"))
    paths |= {p for p in FV.glob("lean4/snippets/**/*") if p.suffix in {".tmpl", ".tac", ".tsv", ".txt"}}
    paths |= set(FV.glob("lean4/check/*.py")) | set(FV.glob("lean4/check/*.sh"))
    paths |= {FV / "coverage.py",
              FV / "lean4/lean-toolchain", FV / "lean4/lake-manifest.json",
              FV / "lean4/lakefile.toml", FV / "picus/Cargo.toml", REPO / "Cargo.lock",
              REPO / "Cargo.toml", REPO / "rust-toolchain.toml"}
    tools = FV / "lean4/snippets/tools"
    paths = [p for p in paths if "Chips" not in p.parts and p.name != "Chips.lean"
             and not p.is_relative_to(tools)]
    h = hashlib.sha256()
    for p in sorted(paths):
        for data in (p.relative_to(REPO).as_posix().encode(), p.read_bytes()):
            h.update(len(data).to_bytes(8, "little"))
            h.update(data)
    h.update(b"external-snippet-tools\0")
    h.update(bytes.fromhex(snippet_tools_pin()))
    return h.hexdigest()


def verify_snippet_tools(directory):
    """Check external generators against the inputs pinned by the proof pipeline."""
    if snippet_tools_digest(directory) != snippet_tools_pin():
        raise ValueError("external snippet generators differ from coverage.json")


def load_fingerprints(path):
    data = json.loads(Path(path).read_text())
    if not data or any(not re.fullmatch(r"[0-9a-f]{64}", v) for v in data.values()):
        raise ValueError("invalid AIR fingerprint inventory")
    return data


def verify_lean_project(project):
    """A receipt must use the Lean definitions and dependency pins fingerprinted here."""
    reference = FV / "lean4"
    for path in lean_project_inputs():
        actual = Path(project) / path.relative_to(reference)
        if not actual.exists() or actual.read_bytes() != path.read_bytes():
            raise ValueError(f"Lean project differs from fingerprinted library: {actual}")


def check_manifest(manifest, current, require_closed=False):
    if manifest["schema"] != 1 or manifest["pipeline_sha256"] != pipeline_digest():
        raise ValueError("proof pipeline changed: regenerate and recheck coverage")
    if manifest.get("snippet_tools_sha256") != snippet_tools_pin():
        raise ValueError("external generator fingerprint changed")
    entries = manifest["chips"]
    if set(entries) != set(current):
        raise ValueError("machine chip inventory changed")
    stale = [name for name in current if entries[name]["air_sha256"] != current[name]]
    if stale:
        raise ValueError("constraints or extraction interface changed: " + ", ".join(stale))
    for name, entry in entries.items():
        state = entry["status"]
        if state == "excluded":
            if name not in EXCLUDED or EXCLUDED[name] != entry.get("reason"):
                raise ValueError(f"{name}: invalid exclusion")
        elif state == "closed":
            if name in EXCLUDED:
                raise ValueError(f"{name}: excluded chip cannot have closed coverage")
            validate_proof_evidence(name, entry)
        elif state != "pending":
            raise ValueError(f"{name}: invalid coverage status")
        elif require_closed:
            raise ValueError(f"{name}: current constraints have no checked proof receipt")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["snapshot", "check", "stamp", "record", "verify-tools"])
    parser.add_argument("fingerprints", metavar="INPUT",
                        help="AIR fingerprint JSON, or external tools directory for verify-tools")
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--require-closed", action="store_true")
    args = parser.parse_args()
    if args.action == "verify-tools":
        verify_snippet_tools(args.fingerprints)
        print("External snippet generators match the pinned inputs")
        return
    current = load_fingerprints(args.fingerprints)
    digest = pipeline_digest()
    if args.action == "snapshot":
        previous = json.loads(args.manifest.read_text()) if args.manifest.exists() else None
        manifest = {"schema": 1, "pipeline_sha256": digest,
                    "snippet_tools_sha256": snippet_tools_pin(), "chips": {
            name: {"air_sha256": value, "status": "excluded" if name in EXCLUDED else "pending",
                   **({"reason": EXCLUDED[name]} if name in EXCLUDED else {})}
            for name, value in sorted(current.items())}}
        if previous and previous.get("schema") == 1 and previous.get("pipeline_sha256") == digest:
            for name, entry in previous["chips"].items():
                if name in current and entry["air_sha256"] == current[name]:
                    manifest["chips"][name] = entry
            check_manifest(manifest, current)
    elif args.action == "stamp":
        if not args.source:
            parser.error("stamp needs --source")
        name = args.source.stem
        body = args.source.read_text()
        first, body = body.split("\n", 1)
        if not first.startswith("-- ZIREN_AIR "):
            raise ValueError("stamp requires a newly extracted file with an AIR identity")
        identity = json.loads(first[len("-- ZIREN_AIR "):])
        expected = {"chip": name, "air_sha256": current[name],
                    "assume_selectors_deterministic": False, "keep_padding": False,
                    "column_output_mode": "InteractionsOnly", "reify_threshold": 128,
                    "shrcarry_summary": "Precise" if name == "CloClz" else "Abstract",
                    "body_sha256": sha(body.encode())}
        if identity != expected:
            raise ValueError("generated file does not match current AIR")
        header = "-- ZIREN_COVERAGE " + json.dumps({"chip": name, "air_sha256": current[name],
                                                "pipeline_sha256": digest,
                                                "body_sha256": sha(body.encode())}, sort_keys=True)
        args.source.write_text(header + "\n" + body)
        return
    else:
        manifest = json.loads(args.manifest.read_text())
        check_manifest(manifest, current, args.require_closed)
        if args.action == "check":
            closed = sum(e["status"] == "closed" for e in manifest["chips"].values())
            print(f"AIR inventory matches: {len(current)} chips, {closed} checked closed")
            return
        if not args.source or not args.receipt:
            parser.error("record needs --source and --receipt")
        header, body = args.source.read_text().split("\n", 1)
        if not header.startswith("-- ZIREN_COVERAGE "):
            raise ValueError("proof source is not stamped by the current extraction")
        identity = json.loads(header[len("-- ZIREN_COVERAGE "):])
        name = identity["chip"]
        if identity != {"chip": name, "air_sha256": current[name], "pipeline_sha256": digest,
                        "body_sha256": sha(body.encode())}:
            raise ValueError("proof source describes different constraints or proof pipeline")
        receipt = json.loads(args.receipt.read_text())
        if receipt.get("pipeline_sha256") != digest:
            raise ValueError("closure receipt used a different or unchecked proof pipeline")
        validate_proof_evidence(name, receipt)
        if receipt["source_sha256"] != sha(args.source.read_bytes()):
            raise ValueError("closure receipt does not match the generated proof source")
        if name in EXCLUDED or any(not t.startswith(f"ZirenDet.Chips.{name}.")
                                   or not t.endswith(".deterministic") for t in receipt["theorems"]):
            raise ValueError("closure receipt has an invalid chip theorem inventory")
        manifest["chips"][name] = {"air_sha256": current[name], "status": "closed",
                                   "source_sha256": receipt["source_sha256"],
                                   "theorems": receipt["theorems"]}
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError) as exc:
        sys.exit(f"coverage check failed: {exc}")
