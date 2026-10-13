import copy
import unittest
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import coverage
from coverage import check_manifest, pipeline_digest, sha, verify_snippet_tools


class CoverageTests(unittest.TestCase):
    def test_external_tools_are_optional_for_ci_but_pinned_for_regeneration(self):
        with tempfile.TemporaryDirectory() as directory:
            fv = Path(directory) / "crates/fv"
            fv.mkdir(parents=True)
            (fv / "coverage.py").write_text("# checker\n")
            lean = fv / "lean4"
            lean.mkdir()
            for name in ("lean-toolchain", "lake-manifest.json", "lakefile.toml"):
                (lean / name).write_text("pin\n")
            picus = fv / "picus"
            picus.mkdir()
            (picus / "Cargo.toml").write_text("pin\n")
            repo = fv.parents[1]
            for name in ("Cargo.lock", "Cargo.toml", "rust-toolchain.toml"):
                (repo / name).write_text("pin\n")
            snippets = lean / "snippets"
            snippets.mkdir()
            lock = snippets / "tools.lock.json"
            lock.write_text(json.dumps({"schema": 1, "files": {"gen.py": sha(b"# generator\n")}}))
            tools = snippets / "tools"
            with patch.object(coverage, "FV", fv), patch.object(coverage, "REPO", repo):
                absent = pipeline_digest()
                with self.assertRaises(ValueError):
                    verify_snippet_tools(tools)
                tools.mkdir()
                generator = tools / "gen.py"
                generator.write_text("# generator\n")
                self.assertEqual(absent, pipeline_digest())
                verify_snippet_tools(tools)
                generator.write_text("# changed\n")
                with self.assertRaises(ValueError):
                    verify_snippet_tools(tools)
                generator.write_text("# generator\n")
                (tools / "unlisted.py").write_text("# extra input\n")
                with self.assertRaises(ValueError):
                    verify_snippet_tools(tools)
                lock.write_text(json.dumps({"schema": 1, "files": {"gen.py": sha(b"# changed\n")}}))
                self.assertNotEqual(absent, pipeline_digest())

    def setUp(self):
        self.current = {"AddSub": "a" * 64, "Byte": "b" * 64}
        self.manifest = {"schema": 1, "pipeline_sha256": pipeline_digest(), "chips": {
            "AddSub": {"air_sha256": "a" * 64, "status": "pending"},
            "Byte": {"air_sha256": "b" * 64, "status": "excluded", "reason": "preprocessed table"}}}

    def test_pending_is_not_closed_coverage(self):
        check_manifest(self.manifest, self.current)
        with self.assertRaises(ValueError):
            check_manifest(self.manifest, self.current, require_closed=True)

    def test_rejects_constraint_inventory_pipeline_and_exclusion_drift(self):
        for mutation in ["constraint", "inventory", "pipeline", "exclusion", "evidence"]:
            manifest, current = copy.deepcopy(self.manifest), dict(self.current)
            if mutation == "constraint":
                current["AddSub"] = "c" * 64
            elif mutation == "inventory":
                current["NewChip"] = "d" * 64
            elif mutation == "pipeline":
                manifest["pipeline_sha256"] = "e" * 64
            elif mutation == "exclusion":
                manifest["chips"]["AddSub"].update(status="excluded", reason="preprocessed table")
            else:
                manifest["chips"]["AddSub"]["status"] = "closed"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                check_manifest(manifest, current)

    def test_stamp_rejects_edited_source_and_unsupported_extraction_options(self):
        body = "namespace ZirenDet.Chips.AddSub\nend ZirenDet.Chips.AddSub\n"
        identity = {"chip": "AddSub", "air_sha256": "a" * 64,
                    "assume_selectors_deterministic": False, "keep_padding": False,
                    "column_output_mode": "InteractionsOnly", "reify_threshold": 128,
                    "shrcarry_summary": "Abstract", "body_sha256": sha(body.encode())}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fingerprints = root / "fingerprints.json"
            fingerprints.write_text(json.dumps(self.current))
            source = root / "AddSub.lean"
            for modified in [body + "-- changed\n", body]:
                if modified == body:
                    identity["assume_selectors_deterministic"] = True
                source.write_text("-- ZIREN_AIR " + json.dumps(identity) + "\n" + modified)
                result = subprocess.run([sys.executable, str(Path(__file__).with_name("coverage.py")),
                                         "stamp", str(fingerprints), "--source", str(source)],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
