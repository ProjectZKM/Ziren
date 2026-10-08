/-
  Hand-written proof of `postconditions` for the `padding` module of `CloClz` (built with
  `--shrcarry-summary precise`): a padding row has `is_bb_zero = 0` (`v10`).  With
  `is_real = 0` the shift gadget's gate is `is_srl = −is_bb_zero`, so `is_bb_zero = 1` would
  force `a[0] = 32` (`v2`) and the eight shift-amount bits `v56 … v63` to sum, weighted by
  `2^i`, to `31 − 32 = −1`, which no byte reaches.  The generator uses this proof only when the
  statement below is exactly the generated one.
-/
theorem postconditions (w : W) (hw : constraints w) :
    ((0 : F) - w.v10) = 0 := by
  obtain ⟨h0, h1⟩ := hw
  simp only [constraints_0] at h0
  simp only [constraints_1] at h1
  obtain ⟨-, -, -, -, b10, -, -, c7, c8, -⟩ := h0
  obtain ⟨-, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, b56, b57, b58, b59, b60, b61, b62, b63, -⟩ := h1
  rcases mul_eq_zero.mp b10 with h | h
  · simp [h]
  · exfalso
    have h1 : w.v10 = 1 := sub_eq_zero.mp h
    rw [h1, one_mul] at c7
    have h2 : w.v2 = 32 := sub_eq_zero.mp c7
    rw [h1, h2] at c8
    have bit : ∀ x : F, x * (x - 1) = 0 → x = 0 ∨ x = 1 := fun x hx => by
      rcases mul_eq_zero.mp hx with e | e
      · exact Or.inl e
      · exact Or.inr (sub_eq_zero.mp e)
    rcases bit _ b56 with e56 | e56 <;> rcases bit _ b57 with e57 | e57 <;>
      rcases bit _ b58 with e58 | e58 <;> rcases bit _ b59 with e59 | e59 <;>
      rcases bit _ b60 with e60 | e60 <;> rcases bit _ b61 with e61 | e61 <;>
      rcases bit _ b62 with e62 | e62 <;> rcases bit _ b63 with e63 | e63 <;>
      rw [e56, e57, e58, e59, e60, e61, e62, e63] at c8 <;> revert c8 <;> decide
