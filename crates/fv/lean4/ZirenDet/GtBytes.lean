import ZirenDet.Basic

/-!
# Byte-wise strict comparison

`GtColsBytes` flags the first byte from the top where the two words differ (or none), selects
that byte of each word, and looks up both strict comparisons of the selected bytes.  The result
is then `a > b`, read top byte first, whatever flag the witness chose: `gt_bytes_result`, and for
two witnesses over the same words `gt_bytes_det`.
-/

namespace ZirenDet.GtBytes

open ZirenDet

theorem bit_of {x : F} (h : x * (x - 1) = 0) : x = 0 ∨ x = 1 := by
  rcases mul_eq_zero.mp h with h | h
  · exact Or.inl h
  · exact Or.inr (sub_eq_zero.mp h)

/-- `a > b` on four bytes read top first, by the bytes' values. -/
def gtLex (a0 a1 a2 a3 b0 b1 b2 b3 : F) : Prop :=
  b3.val < a3.val ∨ (a3 = b3 ∧ b2.val < a2.val) ∨ (a3 = b3 ∧ a2 = b2 ∧ b1.val < a1.val) ∨
    (a3 = b3 ∧ a2 = b2 ∧ a1 = b1 ∧ b0.val < a0.val)

/-- With the flag at byte `k`, the two lookups force `a_k ≠ b_k` and `r = [b_k < a_k]`. -/
theorem pick {r ak bk : F} (hr : r * (r - 1) = 0) (l1 : r = 1 ↔ bk.val < ak.val)
    (l2 : (1 - r) = 1 ↔ ak.val < bk.val) : ak ≠ bk ∧ (r = 1 ↔ bk.val < ak.val) := by
  refine ⟨fun e => ?_, l1⟩
  subst e
  rcases bit_of hr with rfl | rfl
  · exact lt_irrefl _ (l2.mp (by ring))
  · exact lt_irrefl _ (l1.mp rfl)

/-- `GtColsBytes`: one flag at the first differing byte from the top (or none), the compared
bytes selected by it, and the two strict comparisons fix the result as `a > b`. -/
theorem gt_bytes_result (a0 a1 a2 a3 b0 b1 b2 b3 f0 f1 f2 f3 h ac bc r : F)
    (hf0 : f0 * (f0 - 1) = 0) (hf1 : f1 * (f1 - 1) = 0) (hf2 : f2 * (f2 - 1) = 0)
    (hf3 : f3 * (f3 - 1) = 0) (hh : h = f0 + f1 + f2 + f3) (hhb : h * (h - 1) = 0)
    (e3 : (f3 - 1) * (a3 - b3) = 0) (e2 : (f3 + f2 - 1) * (a2 - b2) = 0)
    (e1 : (f3 + f2 + f1 - 1) * (a1 - b1) = 0) (e0 : (f3 + f2 + f1 + f0 - 1) * (a0 - b0) = 0)
    (hac : ac = a3 * f3 + a2 * f2 + a1 * f1 + a0 * f0)
    (hbc : bc = b3 * f3 + b2 * f2 + b1 * f1 + b0 * f0) (hr : r * (r - 1) = 0)
    (l1 : r = 1 ↔ bc.val < ac.val) (l2 : (1 - r) * h = 1 ↔ (ac * h).val < (bc * h).val) :
    r = 1 ↔ gtLex a0 a1 a2 a3 b0 b1 b2 b3 := by
  have n2 : (2 : F) ≠ 0 := by decide
  have n3 : (3 : F) ≠ 0 := by decide
  have n4 : (4 : F) ≠ 0 := by decide
  have n1 : (-1 : F) ≠ 0 := by decide
  have eq_of : ∀ {x y : F}, (-1 : F) * (x - y) = 0 → x = y := fun hxy => by
    rcases mul_eq_zero.mp hxy with h | h
    · exact absurd h n1
    · exact sub_eq_zero.mp h
  unfold gtLex
  subst hh hac hbc
  rcases bit_of hf0 with rfl | rfl <;> rcases bit_of hf1 with rfl | rfl <;>
    rcases bit_of hf2 with rfl | rfl <;> rcases bit_of hf3 with rfl | rfl <;>
    norm_num at hhb e0 e1 e2 e3 l1 l2 ⊢
  all_goals first
    | exact absurd hhb (by decide)
    | ((try (rw [sub_eq_zero] at e0; subst e0))
       (try (rw [sub_eq_zero] at e1; subst e1))
       (try (rw [sub_eq_zero] at e2; subst e2))
       (try (rw [sub_eq_zero] at e3; subst e3))
       rcases bit_of hr with rfl | rfl <;> (try norm_num at l1 l2 ⊢) <;>
         (try simp only [← (ZMod.val_injective KB).eq_iff]) <;> first | omega | exact absurd rfl l1)

/-- Two witnesses of `GtColsBytes` over the same words have the same result.  The lookups are
taken in the chip's gated form, with the gate `1`. -/
theorem gt_bytes_det (a0 a1 a2 a3 b0 b1 b2 b3 f0 f1 f2 f3 h ac bc r f0' f1' f2' f3' h' ac' bc' r' : F)
    (hf0 : f0 * (f0 - 1) = 0) (hf1 : f1 * (f1 - 1) = 0) (hf2 : f2 * (f2 - 1) = 0)
    (hf3 : f3 * (f3 - 1) = 0) (hh : h = f0 + f1 + f2 + f3) (hhb : h * (h - 1) = 0)
    (e3 : (f3 - 1) * (a3 - b3) = 0) (e2 : (f3 + f2 - 1) * (a2 - b2) = 0)
    (e1 : (f3 + f2 + f1 - 1) * (a1 - b1) = 0) (e0 : (f3 + f2 + f1 + f0 - 1) * (a0 - b0) = 0)
    (hac : ac = a3 * f3 + a2 * f2 + a1 * f1 + a0 * f0)
    (hbc : bc = b3 * f3 + b2 * f2 + b1 * f1 + b0 * f0) (hr : r * (r - 1) = 0)
    (l1 : r * 1 - 1 = 0 ↔ (bc * 1).val < (ac * 1).val)
    (l2 : (1 - r) * h - 1 = 0 ↔ (ac * h).val < (bc * h).val)
    (hf0' : f0' * (f0' - 1) = 0) (hf1' : f1' * (f1' - 1) = 0) (hf2' : f2' * (f2' - 1) = 0)
    (hf3' : f3' * (f3' - 1) = 0) (hh' : h' = f0' + f1' + f2' + f3') (hhb' : h' * (h' - 1) = 0)
    (e3' : (f3' - 1) * (a3 - b3) = 0) (e2' : (f3' + f2' - 1) * (a2 - b2) = 0)
    (e1' : (f3' + f2' + f1' - 1) * (a1 - b1) = 0)
    (e0' : (f3' + f2' + f1' + f0' - 1) * (a0 - b0) = 0)
    (hac' : ac' = a3 * f3' + a2 * f2' + a1 * f1' + a0 * f0')
    (hbc' : bc' = b3 * f3' + b2 * f2' + b1 * f1' + b0 * f0') (hr' : r' * (r' - 1) = 0)
    (l1' : r' * 1 - 1 = 0 ↔ (bc' * 1).val < (ac' * 1).val)
    (l2' : (1 - r') * h' - 1 = 0 ↔ (ac' * h').val < (bc' * h').val) : r' = r := by
  have g := gt_bytes_result a0 a1 a2 a3 b0 b1 b2 b3 f0 f1 f2 f3 h ac bc r hf0 hf1 hf2 hf3 hh hhb
    e3 e2 e1 e0 hac hbc hr (by simpa only [mul_one, sub_eq_zero] using l1)
    (by simpa only [sub_eq_zero] using l2)
  have g' := gt_bytes_result a0 a1 a2 a3 b0 b1 b2 b3 f0' f1' f2' f3' h' ac' bc' r' hf0' hf1' hf2'
    hf3' hh' hhb' e3' e2' e1' e0' hac' hbc' hr' (by simpa only [mul_one, sub_eq_zero] using l1')
    (by simpa only [sub_eq_zero] using l2')
  rcases bit_of hr with rfl | rfl <;> rcases bit_of hr' with rfl | rfl
  · rfl
  · exact absurd (g.mpr (g'.mp rfl)) (by decide)
  · exact absurd (g'.mpr (g.mp rfl)) (by decide)
  · rfl

end ZirenDet.GtBytes
