import unittest
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from closure import validate


class ClosureTests(unittest.TestCase):
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
