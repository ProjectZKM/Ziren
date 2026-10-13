import unittest
import os
import shutil
import subprocess
import tempfile
import hashlib
from pathlib import Path

from closure import validate
from check import prepare_proof_cache


class ClosureTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("LEAN_CHECK_BIN"), "set LEAN_CHECK_BIN for kernel regression")
    def test_changed_library_cannot_reuse_an_axiom_free_stale_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proofs = root / "Proof"
            proofs.mkdir()
            dependency = root / "Dep.lean"
            source = proofs / "M.lean"
            source.write_text("import Dep\ntheorem deterministic : premise := by trivial\n")
            lean = os.environ["LEAN_CHECK_BIN"]
            env = {**os.environ, "LEAN_PATH": directory}

            def compile_file(source, output):
                return subprocess.run([lean, "-o", str(output), str(source)], cwd=root,
                                      env=env, capture_output=True, text=True)

            def cache_key():
                return {"library_sha256": hashlib.sha256(dependency.read_bytes()).hexdigest(),
                        "project": directory,
                        "compiler": subprocess.check_output([lean, "--version"], text=True).strip()}

            dependency.write_text("def premise : Prop := True\n")
            self.assertEqual(compile_file(dependency, root / "Dep.olean").returncode, 0)
            prepare_proof_cache(root, "Proof", cache_key())
            artifact = proofs / "M.olean"
            self.assertEqual(compile_file(source, artifact).returncode, 0)
            prepare_proof_cache(root, "Proof", cache_key())
            self.assertTrue(artifact.exists())
            dependency.write_text("def premise : Prop := False\n")
            self.assertEqual(compile_file(dependency, root / "Dep.olean").returncode, 0)
            prepare_proof_cache(root, "Proof", cache_key())
            self.assertFalse(artifact.exists())
            # Re-elaboration rejects the proof that a bare axiom audit would still accept.
            result = compile_file(source, artifact)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_library_and_compiler_changes_invalidate_compiled_proofs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proofs = root / "Proof"
            proofs.mkdir()
            source = proofs / "M.lean"
            source.write_text("theorem deterministic : True := by trivial\n")
            artifact = proofs / "M.olean"
            key = {"library_sha256": "a" * 64, "compiler": "Lean 4", "project": directory}
            # Unrecorded artifacts cannot establish which library was used.
            artifact.write_bytes(b"unknown build")
            prepare_proof_cache(root, "Proof", key)
            self.assertFalse(artifact.exists())
            artifact.write_bytes(b"checked build")
            prepare_proof_cache(root, "Proof", key)
            self.assertTrue(artifact.exists())
            for mutation in ({"library_sha256": "b" * 64}, {"compiler": "Lean 5"}):
                updated = {**key, **mutation}
                prepare_proof_cache(root, "Proof", updated)
                self.assertFalse(artifact.exists())
                self.assertTrue(source.exists())
                key = updated
                artifact.write_bytes(b"checked build")
            # Unstamped sources get a fresh build rather than an unverifiable cache.
            prepare_proof_cache(root, "Proof", None)
            self.assertFalse(artifact.exists())

    def test_closed_theorems(self):
        validate("'M.deterministic' depends on axioms: [propext, Classical.choice,\n Quot.sound]"
                 + '\n"PICUS_FILE_DONE"', ["M.deterministic"])
        validate("'M.deterministic' does not depend on any axioms\n\"PICUS_FILE_DONE\"",
                 ["M.deterministic"])

    def test_rejects_admissions_and_imported_axioms(self):
        for text in ["warning: declaration uses 'sorry'", "warning: declaration uses `sorry`",
                     "PICUS_OPEN", "goal admitted",
                     "'M.deterministic' depends on axioms: [sorryAx]",
                     "'M.deterministic' depends on axioms: [My.unchecked_fact]\n\"PICUS_FILE_DONE\""]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                validate(text, ["M.deterministic"])

    def test_rejects_missing_duplicate_or_incomplete_reports(self):
        report = "'M.deterministic' depends on axioms: [propext]"
        for text, expected in [(report, ["M.deterministic"]),
                               ('"PICUS_FILE_DONE"', ["M.deterministic"]),
                               (report + report + '\n"PICUS_FILE_DONE"', ["M.deterministic"]),
                               (report + '\n"PICUS_FILE_DONE"', ["Other.deterministic"])]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                validate(text, expected)

    def test_runner_rejects_successful_elaboration_with_sorry(self):
        # Lean returns zero for admitted declarations. Exercise that exact runner boundary.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            here = Path(__file__).resolve().parent
            for script in ("run_mod.sh", "closure.py"):
                shutil.copy(here / script, root / script)
            (root / "Proof").mkdir()
            (root / "Proof/M.lean").write_text("")
            (root / "Proof/M.olean").write_text("uncertified artifact")
            (root / "bin").mkdir()
            lake = root / "bin/lake"
            lake.write_text("#!/bin/sh\necho 'warning: declaration uses `sorry`'\nexit 0\n")
            lake.chmod(0o755)
            env = {**os.environ, "PATH": str(root / "bin") + ":" + os.environ["PATH"],
                   "LEAN_PROJECT": str(root), "MIN_FREE": "0"}
            result = subprocess.run(["bash", str(root / "run_mod.sh"), "Proof", "M"],
                                    env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "Proof/M.olean").exists())


if __name__ == "__main__":
    unittest.main()
