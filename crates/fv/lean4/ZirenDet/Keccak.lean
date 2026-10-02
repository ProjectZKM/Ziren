import ZirenDet.Replay

/-!
# Keccak round gadget

The keccak-f round AIR on one row (`p3_keccak_air` columns) encodes θ through bits `a'`, `c`,
`c'` with `a = Σ 2ᵏ·xor3(a', c, c')` limb by limb and `Σ_y a'[y] − c' ∈ {0, 2, 4}` per column.
Over bits these force `c` to be the column parity of the input bits, so the whole round is a
function of the input limbs and the round index.
-/

namespace ZirenDet.Keccak

open ZirenDet

/-- `xor` of two bits as the AIR writes it. -/
def xorF (a b : F) : F := a + b - a * (b + b)

/-- `xor3(a, b, c) = xor(a, xor(b, c))`. -/
def xor3F (a b c : F) : F := xorF a (xorF b c)

/-- A field element that is a bit. -/
def bitF (x : F) : Prop := x = 0 ∨ x = 1

theorem bitF_of {x : F} (h : x * (x - 1) = 0) : bitF x := ZirenDet.bit_cases h

theorem xor3F_bit {a b c : F} (ha : bitF a) (hb : bitF b) (hc : bitF c) : bitF (xor3F a b c) := by
  unfold bitF at *
  rcases ha with rfl | rfl <;> rcases hb with rfl | rfl <;> rcases hc with rfl | rfl <;>
    decide +kernel

/-- Parity of five bits, as nested `xor`. -/
def par5 (s0 s1 s2 s3 s4 : F) : F := xorF s0 (xorF s1 (xorF s2 (xorF s3 s4)))

/-- θ's column: from `Σ a'ᵧ − c' ∈ {0,2,4}` the bit `c` is the parity of `xor3(a'ᵧ, c, c')`. -/
theorem column_parity {a0 a1 a2 a3 a4 c c' : F}
    (h0 : bitF a0) (h1 : bitF a1) (h2 : bitF a2) (h3 : bitF a3) (h4 : bitF a4)
    (hc : bitF c) (hc' : bitF c')
    (hd : (a0 + a1 + a2 + a3 + a4 - c') * (a0 + a1 + a2 + a3 + a4 - c' - 2) *
      (a0 + a1 + a2 + a3 + a4 - c' - 4) = 0) :
    c = par5 (xor3F a0 c c') (xor3F a1 c c') (xor3F a2 c c') (xor3F a3 c c') (xor3F a4 c c') := by
  unfold bitF at *
  rcases h0 with rfl | rfl <;> rcases h1 with rfl | rfl <;> rcases h2 with rfl | rfl <;>
    rcases h3 with rfl | rfl <;> rcases h4 with rfl | rfl <;> rcases hc with rfl | rfl <;>
    rcases hc' with rfl | rfl <;> revert hd <;> decide +kernel

/-- Undoing `xor3` with known `c`, `c'`. -/
theorem xor3F_cancel {a a' c c' : F} (ha : bitF a) (ha' : bitF a') (hc : bitF c) (hc' : bitF c')
    (h : xor3F a c c' = xor3F a' c c') : a = a' := by
  unfold bitF at *
  rcases ha with rfl | rfl <;> rcases ha' with rfl | rfl <;> rcases hc with rfl | rfl <;>
    rcases hc' with rfl | rfl <;> revert h <;> decide +kernel

/-- Little-endian binary reading of a list of integers. -/
def evb : List ℤ → ℤ
  | [] => 0
  | a :: l => a + 2 * evb l

theorem evb_nonneg : ∀ (l : List ℤ), (∀ x ∈ l, 0 ≤ x ∧ x ≤ 1) → 0 ≤ evb l
  | [], _ => by simp [evb]
  | a :: l, h => by
      have ha := h a (by simp)
      have := evb_nonneg l (fun x hx => h x (by simp [hx]))
      simp only [evb]
      omega

/-- Binary digits are unique. -/
theorem evb_inj : ∀ (l l' : List ℤ), l.length = l'.length →
    (∀ x ∈ l, 0 ≤ x ∧ x ≤ 1) → (∀ x ∈ l', 0 ≤ x ∧ x ≤ 1) → evb l = evb l' → l = l'
  | [], [], _, _, _, _ => rfl
  | a :: l, b :: l', hlen, h, h', he => by
      simp only [evb] at he
      have ha := h a (by simp)
      have hb := h' b (by simp)
      have e1 : a = b := by omega
      have e2 : evb l = evb l' := by omega
      subst e1
      have := evb_inj l l' (by simpa using hlen) (fun x hx => h x (by simp [hx]))
        (fun x hx => h' x (by simp [hx])) e2
      rw [this]
  | [], _ :: _, hlen, _, _, _ => by simp at hlen
  | _ :: _, [], hlen, _, _, _ => by simp at hlen

/-- A bit's value is `0` or `1`. -/
theorem bitF_val {x : F} (h : bitF x) : 0 ≤ ((x.val : ℕ) : ℤ) ∧ ((x.val : ℕ) : ℤ) ≤ 1 := by
  rcases h with rfl | rfl <;>
    simp only [ZMod.val_zero, ZMod.val_one, Nat.cast_zero, Nat.cast_one] <;> norm_num

/-- A bit is the cast of its value. -/
theorem bitF_cast {x : F} : x = (((x.val : ℕ) : ℤ) : F) := by
  rw [Int.cast_natCast]; exact (ZMod.natCast_zmod_val x).symm

end ZirenDet.Keccak
