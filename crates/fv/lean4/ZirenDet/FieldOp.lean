import ZirenDet.DivRem
open ZirenDet
set_option maxHeartbeats 0
set_option linter.unusedVariables false

/-!
# Field operations on byte limbs

A field-operation gadget constrains, coefficient by coefficient, a polynomial identity
`V(X) = W(X)·(X − 256)` over the base field, where `V` is built from the limbs of the operands,
the result, the carry and the modulus.  Every coefficient is small, so the identity holds over
the integers, and `X = 256` gives the operation modulo the modulus.  The less-than gadget pins
the result below the modulus, which makes it the canonical residue.
-/

/-- Lifts one coefficient row `h : (E : F) = 0` over integer casts to `E = 0` over the
integers: the products are bounded, so `|E| < p`, and the bound is linear in them.  A row whose
products are not of two columns (a selector times a sum) is expanded first. -/
syntax "fieldop_row " ident : tactic
macro_rules
  | `(tactic| fieldop_row $h:ident) =>
    `(tactic| (
        (try casesm* _ ∧ _)
        (try simp only [ZirenDet.castF_one, ZirenDet.castF_zero, ZirenDet.castF_ofNat, ZirenDet.castF_add,
               ZirenDet.castF_sub, ZirenDet.castF_mul, ZirenDet.castF_neg] at $h:ident)
        obtain ⟨m, hm⟩ := ZirenDet.cast_eq_iff_dvd.mp $h
        first
          | ((try picus_prod_bounds)
             have hlo : -2130706433 < 2130706433 * m := by linarith
             have hhi : 2130706433 * m < 2130706433 := by linarith
             have hm0 : m = 0 := by omega
             subst hm0
             linarith)
          | (ring_nf at hm
             (try picus_prod_bounds)
             have hlo : -2130706433 < 2130706433 * m := by linarith
             have hhi : 2130706433 * m < 2130706433 := by linarith
             have hm0 : m = 0 := by omega
             subst hm0
             linarith)))

namespace ZirenDet.FieldOp

/-- The value of little-endian byte limbs. -/
def ev : List ℤ → ℤ
  | [] => 0
  | a :: l => a + 256 * ev l

theorem ev_nonneg : ∀ (l : List ℤ), (∀ x ∈ l, 0 ≤ x ∧ x ≤ 255) → 0 ≤ ev l
  | [], _ => le_refl 0
  | a :: l, h => by
      have ha := h a (by simp)
      have hl := ev_nonneg l (fun x hx => h x (by simp [hx]))
      simp only [ev]
      omega

/-- Byte limbs are determined by their value. -/
theorem ev_inj : ∀ (l l' : List ℤ), l.length = l'.length →
    (∀ x ∈ l, 0 ≤ x ∧ x ≤ 255) → (∀ x ∈ l', 0 ≤ x ∧ x ≤ 255) → ev l = ev l' → l = l'
  | [], [], _, _, _, _ => rfl
  | a :: l, b :: l', hlen, h, h', he => by
      simp only [ev] at he
      have ha := h a (by simp)
      have hb := h' b (by simp)
      have e1 : a = b := by omega
      have e2 : ev l = ev l' := by omega
      subst e1
      have := ev_inj l l' (by simpa using hlen) (fun x hx => h x (by simp [hx]))
        (fun x hx => h' x (by simp [hx])) e2
      rw [this]
  | [], _ :: _, hlen, _, _, _ => by simp at hlen
  | _ :: _, [], hlen, _, _, _ => by simp at hlen

/-- Two canonical residues of one value are equal. -/
theorem residue_unique {R R' X M : ℤ} (h0 : 0 ≤ R) (h1 : R < M) (h0' : 0 ≤ R') (h1' : R' < M)
    (h : R ≡ X [ZMOD M]) (h' : R' ≡ X [ZMOD M]) : R = R' :=
  ZirenDet.Gadgets.canonical_unique h0 h1 h0' h1' (h.trans h'.symm)

/-- Two values below `M` that agree modulo `M` are equal. -/
theorem eq_of_cast_eq {M : ℕ} {R R' : ℤ} (h0 : 0 ≤ R) (h1 : R < (M : ℤ)) (h0' : 0 ≤ R')
    (h1' : R' < (M : ℤ)) (h : ((R : ℤ) : ZMod M) = ((R' : ℤ) : ZMod M)) : R = R' :=
  ZirenDet.Gadgets.canonical_unique h0 h1 h0' h1' ((ZMod.intCast_eq_intCast_iff R R' M).mp h)

/-- A multiple of the modulus vanishes modulo it. -/
theorem cast_eq_zero_of_eq_mul {M : ℕ} {X K : ℤ} (h : X = K * (M : ℤ)) :
    ((X : ℤ) : ZMod M) = 0 :=
  (ZMod.intCast_zmod_eq_zero_iff_dvd X M).mpr ⟨K, by rw [h]; ring⟩

/-- A column is the cast of its value. -/
theorem cast_val (x : F) : ((((x.val : ℕ) : ℤ)) : F) = x := by
  rw [Int.cast_natCast]
  exact ZMod.natCast_zmod_val x

/-- A bit column, read as an integer. -/
theorem bit_cases {x : F} (h : x.val ≤ 1) :
    ((x.val : ℕ) : ℤ) = 0 ∨ ((x.val : ℕ) : ℤ) = 1 := by
  omega

/-- A byte column, read as an integer. -/
theorem byte_range {x : F} (h : x.val ≤ 255) :
    0 ≤ ((x.val : ℕ) : ℤ) ∧ ((x.val : ℕ) : ℤ) ≤ 255 :=
  ⟨by positivity, by exact_mod_cast h⟩

/-- The selection `(L − (1 − S))·(a − b) = 0` with equal bits `L = S` forces `b = a`. -/
theorem sel_same {L S a b : F} (hL : L * (L - 1) = 0) (hLS : L = S)
    (h : (L - (1 - S)) * (a - b) = 0) : b = a := by
  subst hLS
  linear_combination (-(2 * L - 1)) * h + 4 * (a - b) * hL

/-- The selection `(L − S)·(a − b) = 0` with distinct bits `L ≠ S` forces `b = a`. -/
theorem sel_diff {L S a b : F} (hLS : L ≠ S)
    (h : (L - S) * (a - b) = 0) : b = a := by
  have hn : L - S ≠ 0 := sub_ne_zero.mpr hLS
  have := (mul_eq_zero.mp h).resolve_left hn
  linear_combination -this

/-- Equal bit values lift to equal field elements. -/
theorem eq_of_val_cast {x y : F} (h : ((x.val : ℕ) : ℤ) = ((y.val : ℕ) : ℤ)) : x = y :=
  ZMod.val_injective _ (by exact_mod_cast h)

/-- A bit whose value is one is one. -/
theorem eq_one_of_val {x : F} (h : ((x.val : ℕ) : ℤ) = 1) : x = 1 :=
  ZMod.val_injective _ (by rw [ZMod.val_one]; exact_mod_cast h)

/-- A bit whose value is zero is zero. -/
theorem eq_zero_of_val {x : F} (h : ((x.val : ℕ) : ℤ) = 0) : x = 0 :=
  ZMod.val_injective _ (by rw [ZMod.val_zero]; exact_mod_cast h)

/-- The selection `S·(a − b) = 0` with `S = 1` forces `b = a`. -/
theorem sel_one {S a b : F} (hS : S = 1) (h : S * (a - b) = 0) : b = a := by
  subst hS
  linear_combination -h

/-- The selection `(S − 1)·(a − b) = 0` with `S = 0` forces `b = a`. -/
theorem sel_zero {S a b : F} (hS : S = 0) (h : (S - 1) * (a - b) = 0) : b = a := by
  subst hS
  linear_combination h

/-- Two bits summing to one have values summing to one. -/
theorem sum_bits_one {a b : F} (ha : a * (a - 1) = 0) (hb : b * (b - 1) = 0) (h : (a + b) - 1 = 0) :
    ((a.val : ℕ) : ℤ) + ((b.val : ℕ) : ℤ) = 1 := by
  rcases ZirenDet.bit_cases ha with rfl | rfl <;> rcases ZirenDet.bit_cases hb with rfl | rfl <;>
    simp only [ZMod.val_zero, ZMod.val_one, Nat.cast_zero, Nat.cast_one, zero_add, add_zero] <;>
    simp at h

end ZirenDet.FieldOp
