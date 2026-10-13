"""Kernel regression for removing a simp-only hypothesis while flattening constraints."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class FlatGadgetTests(unittest.TestCase):
    def check_rewrite(self, source):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original, flattened = root / "Original.lean", root / "Flattened.lean"
            original.write_text(source)
            lean = os.environ["LEAN_CHECK_BIN"]
            for command in ([lean, str(original)],
                            [sys.executable, str(Path(__file__).with_name("flat_gadget.py")),
                             str(original), str(flattened)],
                            [lean, str(flattened)]):
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn("declaration uses", result.stdout + result.stderr)

    @unittest.skipUnless(os.environ.get("LEAN_CHECK_BIN"), "set LEAN_CHECK_BIN for kernel regression")
    def test_context_normalization_preserves_constraint_hypotheses(self):
        source = """import Lean
namespace FlatRegression
structure W where
  v : Nat
def constraints_0 (w : W) : Prop := True ∧ 0 + w.v = 1
def constraints (w : W) : Prop := constraints_0 w ∧ True
theorem gadget_det (w : W) (hw : constraints w) : w.v = 1 := by
  obtain ⟨c0g, c2g⟩ := hw; obtain ⟨c0, c1⟩ := c0g
  simp only [Nat.zero_add] at *
  exact c1
end FlatRegression
"""
        self.check_rewrite(source)

    @unittest.skipUnless(os.environ.get("LEAN_CHECK_BIN"), "set LEAN_CHECK_BIN for kernel regression")
    def test_witness_projections_are_reduced_before_substitution(self):
        self.check_rewrite("""import Lean
namespace FlatRegression
structure W where
  v0 : Nat
  v1 : Nat
def constraints_0 (w : W) : Prop := w.v1 = w.v0 ∧ True
def constraints (w : W) : Prop := constraints_0 w ∧ True
theorem gadget_det (w : W) (hw : constraints w) : w.v1 = w.v0 := by
  obtain ⟨x0, x1⟩ := w
  obtain ⟨c0g, c2g⟩ := hw; obtain ⟨c0, c1⟩ := c0g
  dsimp only at *
  have h := c0
  subst h
  rfl
end FlatRegression
""")


if __name__ == "__main__":
    unittest.main()
