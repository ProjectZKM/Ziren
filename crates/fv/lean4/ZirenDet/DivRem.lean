import ZirenDet.Replay
import ZirenDet.Gadgets
open ZirenDet
set_option maxHeartbeats 0
set_option linter.unusedVariables false
set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false
set_option linter.unreachableTactic false

/-!
# The division chip's arithmetic (hand-maintained)

The rows of `DivRemChip` say, over the integers, that `b = q · c + r` with `|r| < |c|` and `r`
of the sign of `b`, for the signed or unsigned reading its selectors fix.  Each lemma lifts
one group of constraints: the statement is over integers `n` whose casts `(n : F)` are the
columns, so a row's byte columns enter as their values.
-/

namespace ZirenDet.DivRem

/-- Pulls casts to the top, bounds the products and turns every field equation into an
integer equation. -/
syntax "divrem_lift" : tactic
macro_rules
  | `(tactic| divrem_lift) =>
    `(tactic| (
        (try casesm* _ ∧ _)
        (try simp only [ZirenDet.castF_one, ZirenDet.castF_zero, ZirenDet.castF_ofNat, ZirenDet.castF_add,
               ZirenDet.castF_sub, ZirenDet.castF_mul, ZirenDet.castF_neg] at *)
        (try picus_prod_bounds)
        picus_eqs))

/-- A comparison of two column values, read on their integer lifts. -/
theorem lt_of_val_lt {a b : ℤ} (h : ((a : ℤ) : F).val < ((b : ℤ) : F).val)
    (ha : 0 ≤ a ∧ a < 2130706433) (hb : 0 ≤ b ∧ b < 2130706433) : a < b := by
  simp only [ZirenDet.val_cast] at h
  omega

/-- The is-zero gadget: `z` is one exactly when `x` is zero. -/
theorem iszero_spec {x z inv : F} (h1 : (1 - inv * x) - z = 0) (h2 : z * x = 0) :
    (z = 1 ∧ x = 0) ∨ (z = 0 ∧ x ≠ 0) := by
  by_cases hx : x = 0
  · left
    subst hx
    exact ⟨by linear_combination -h1, rfl⟩
  · right
    rcases mul_eq_zero.mp h2 with hz | hz
    · exact ⟨hz, hx⟩
    · exact absurd hz hx

/-- A byte column equals a byte constant only if its value does. -/
theorem byte_eq_of_cast {n k : ℤ} (hn : 0 ≤ n ∧ n ≤ 255) (hk : 0 ≤ k ∧ k ≤ 255)
    (h : ((n : ℤ) : F) - ((k : ℤ) : F) = 0) : n = k := by
  have h' : ((n : ℤ) : F) = ((k : ℤ) : F) := sub_eq_zero.mp h
  exact ZirenDet.Gadgets.cast_inj_small h' (by rw [abs_lt]; omega) (by rw [abs_lt]; omega)

/-- The is-zero gadget on a byte column compared with a byte constant. -/
theorem iszero_byte {n k : ℤ} {z inv : F} (hn : 0 ≤ n ∧ n ≤ 255) (hk : 0 ≤ k ∧ k ≤ 255)
    (h1 : (1 - inv * (((n : ℤ) : F) - ((k : ℤ) : F))) - z = 0)
    (h2 : z * (((n : ℤ) : F) - ((k : ℤ) : F)) = 0) :
    (z = 1 ∧ n = k) ∨ (z = 0 ∧ n ≠ k) := by
  rcases iszero_spec h1 h2 with ⟨hz, hx⟩ | ⟨hz, hx⟩
  · exact Or.inl ⟨hz, byte_eq_of_cast hn hk hx⟩
  · refine Or.inr ⟨hz, fun h => hx ?_⟩
    rw [h, sub_self]

/-- A little-endian word of four bytes. -/
def w4 (a0 a1 a2 a3 : ℤ) : ℤ := a0 + 256 * a1 + 65536 * a2 + 16777216 * a3

/-- The eight rows of the byte product: the low 64 bits of `q · c` are `m`. -/
theorem product_rows (q0 q1 q2 q3 q4 q5 q6 q7 c0 c1 c2 c3 c4 c5 c6 c7 m0 m1 m2 m3 m4 m5 m6 m7 k0 k1 k2 k3 k4 k5 k6 k7 : ℤ)
    (hq0 : 0 ≤ q0 ∧ q0 ≤ 255) (hq1 : 0 ≤ q1 ∧ q1 ≤ 255) (hq2 : 0 ≤ q2 ∧ q2 ≤ 255) (hq3 : 0 ≤ q3 ∧ q3 ≤ 255) (hq4 : 0 ≤ q4 ∧ q4 ≤ 255) (hq5 : 0 ≤ q5 ∧ q5 ≤ 255) (hq6 : 0 ≤ q6 ∧ q6 ≤ 255) (hq7 : 0 ≤ q7 ∧ q7 ≤ 255)
    (hc0 : 0 ≤ c0 ∧ c0 ≤ 255) (hc1 : 0 ≤ c1 ∧ c1 ≤ 255) (hc2 : 0 ≤ c2 ∧ c2 ≤ 255) (hc3 : 0 ≤ c3 ∧ c3 ≤ 255) (hc4 : 0 ≤ c4 ∧ c4 ≤ 255) (hc5 : 0 ≤ c5 ∧ c5 ≤ 255) (hc6 : 0 ≤ c6 ∧ c6 ≤ 255) (hc7 : 0 ≤ c7 ∧ c7 ≤ 255)
    (hm0 : 0 ≤ m0 ∧ m0 ≤ 255) (hm1 : 0 ≤ m1 ∧ m1 ≤ 255) (hm2 : 0 ≤ m2 ∧ m2 ≤ 255) (hm3 : 0 ≤ m3 ∧ m3 ≤ 255) (hm4 : 0 ≤ m4 ∧ m4 ≤ 255) (hm5 : 0 ≤ m5 ∧ m5 ≤ 255) (hm6 : 0 ≤ m6 ∧ m6 ≤ 255) (hm7 : 0 ≤ m7 ∧ m7 ≤ 255)
    (hk0 : 0 ≤ k0 ∧ k0 ≤ 65535) (hk1 : 0 ≤ k1 ∧ k1 ≤ 65535) (hk2 : 0 ≤ k2 ∧ k2 ≤ 65535) (hk3 : 0 ≤ k3 ∧ k3 ≤ 65535) (hk4 : 0 ≤ k4 ∧ k4 ≤ 65535) (hk5 : 0 ≤ k5 ∧ k5 ≤ 65535) (hk6 : 0 ≤ k6 ∧ k6 ≤ 65535) (hk7 : 0 ≤ k7 ∧ k7 ≤ 65535)
    
(e0 : (q0 : F) * (c0 : F) = (k0 : F) * 256 + (m0 : F))    (e1 : (m1 : F) - (k0 : F) + (k1 : F) * 256 = (q0 : F) * (c1 : F) + (q1 : F) * (c0 : F))    (e2 : (m2 : F) - (k1 : F) + (k2 : F) * 256 = (q0 : F) * (c2 : F) + (q1 : F) * (c1 : F) + (q2 : F) * (c0 : F))    (e3 : (m3 : F) - (k2 : F) + (k3 : F) * 256 = (q0 : F) * (c3 : F) + (q1 : F) * (c2 : F) + (q2 : F) * (c1 : F) + (q3 : F) * (c0 : F))    (e4 : (m4 : F) - (k3 : F) + (k4 : F) * 256 = (q0 : F) * (c4 : F) + (q1 : F) * (c3 : F) + (q2 : F) * (c2 : F) + (q3 : F) * (c1 : F) + (q4 : F) * (c0 : F))    (e5 : (m5 : F) - (k4 : F) + (k5 : F) * 256 = (q0 : F) * (c5 : F) + (q1 : F) * (c4 : F) + (q2 : F) * (c3 : F) + (q3 : F) * (c2 : F) + (q4 : F) * (c1 : F) + (q5 : F) * (c0 : F))    (e6 : (m6 : F) - (k5 : F) + (k6 : F) * 256 = (q0 : F) * (c6 : F) + (q1 : F) * (c5 : F) + (q2 : F) * (c4 : F) + (q3 : F) * (c3 : F) + (q4 : F) * (c2 : F) + (q5 : F) * (c1 : F) + (q6 : F) * (c0 : F))    (e7 : (m7 : F) - (k6 : F) + (k7 : F) * 256 = (q0 : F) * (c7 : F) + (q1 : F) * (c6 : F) + (q2 : F) * (c5 : F) + (q3 : F) * (c4 : F) + (q4 : F) * (c3 : F) + (q5 : F) * (c2 : F) + (q6 : F) * (c1 : F) + (q7 : F) * (c0 : F)) :
    1 * m0 + 256 * m1 + 65536 * m2 + 16777216 * m3 + 4294967296 * m4 + 1099511627776 * m5 + 281474976710656 * m6 + 72057594037927936 * m7 + 18446744073709551616 * k7 =
      1 * (q0 * c0) + 256 * (q0 * c1 + q1 * c0) + 65536 * (q0 * c2 + q1 * c1 + q2 * c0) + 16777216 * (q0 * c3 + q1 * c2 + q2 * c1 + q3 * c0) + 4294967296 * (q0 * c4 + q1 * c3 + q2 * c2 + q3 * c1 + q4 * c0) + 1099511627776 * (q0 * c5 + q1 * c4 + q2 * c3 + q3 * c2 + q4 * c1 + q5 * c0) + 281474976710656 * (q0 * c6 + q1 * c5 + q2 * c4 + q3 * c3 + q4 * c2 + q5 * c1 + q6 * c0) + 72057594037927936 * (q0 * c7 + q1 * c6 + q2 * c5 + q3 * c4 + q4 * c3 + q5 * c2 + q6 * c1 + q7 * c0) := by
  divrem_lift
  omega

/-- The low four rows of `b = m + r`: bytewise addition with carries `t`. -/
theorem sum_low (b0 b1 b2 b3 m0 m1 m2 m3 r0 r1 r2 r3 t0 t1 t2 t3 : ℤ)
    (hb0 : 0 ≤ b0 ∧ b0 ≤ 255) (hb1 : 0 ≤ b1 ∧ b1 ≤ 255) (hb2 : 0 ≤ b2 ∧ b2 ≤ 255) (hb3 : 0 ≤ b3 ∧ b3 ≤ 255)
    (hm0 : 0 ≤ m0 ∧ m0 ≤ 255) (hm1 : 0 ≤ m1 ∧ m1 ≤ 255) (hm2 : 0 ≤ m2 ∧ m2 ≤ 255) (hm3 : 0 ≤ m3 ∧ m3 ≤ 255)
    (hr0 : 0 ≤ r0 ∧ r0 ≤ 255) (hr1 : 0 ≤ r1 ∧ r1 ≤ 255) (hr2 : 0 ≤ r2 ∧ r2 ≤ 255) (hr3 : 0 ≤ r3 ∧ r3 ≤ 255)
    (ht0 : 0 ≤ t0 ∧ t0 ≤ 1) (ht1 : 0 ≤ t1 ∧ t1 ≤ 1) (ht2 : 0 ≤ t2 ∧ t2 ≤ 1) (ht3 : 0 ≤ t3 ∧ t3 ≤ 1)
    (e0 : (b0 : F) = (m0 : F) + (r0 : F) - (t0 : F) * 256)
    (e1 : (b1 : F) = (m1 : F) + (r1 : F) - (t1 : F) * 256 + (t0 : F))
    (e2 : (b2 : F) = (m2 : F) + (r2 : F) - (t2 : F) * 256 + (t1 : F))
    (e3 : (b3 : F) = (m3 : F) + (r3 : F) - (t3 : F) * 256 + (t2 : F)) :
    w4 b0 b1 b2 b3 + 4294967296 * t3 = w4 m0 m1 m2 m3 + w4 r0 r1 r2 r3 := by
  simp only [w4]
  divrem_lift
  omega

/-- The high four rows: the upper half of `m + r` is the sign extension of `b`, or zero on
the overflow row (`ov`).  `g` is the sign extension's bit, `sb · (1 − ov)`. -/
theorem sum_high (m4 m5 m6 m7 sr sb ov t3 t4 t5 t6 t7 : ℤ)
    (hm4 : 0 ≤ m4 ∧ m4 ≤ 255) (hm5 : 0 ≤ m5 ∧ m5 ≤ 255) (hm6 : 0 ≤ m6 ∧ m6 ≤ 255) (hm7 : 0 ≤ m7 ∧ m7 ≤ 255)
    (hsr : 0 ≤ sr ∧ sr ≤ 1) (hsb : 0 ≤ sb ∧ sb ≤ 1) (hov : 0 ≤ ov ∧ ov ≤ 1)
    (ht3 : 0 ≤ t3 ∧ t3 ≤ 1) (ht4 : 0 ≤ t4 ∧ t4 ≤ 1) (ht5 : 0 ≤ t5 ∧ t5 ≤ 1) (ht6 : 0 ≤ t6 ∧ t6 ≤ 1) (ht7 : 0 ≤ t7 ∧ t7 ≤ 1)
    (g4a : (1 - (ov : F)) * ((sb : F) * (((m4 : F) + (sr : F) * 255 - (t4 : F) * 256 + (t3 : F)) - 255)) = 0)
    (g4b : (1 - (ov : F)) * ((1 - (sb : F)) * ((m4 : F) + (sr : F) * 255 - (t4 : F) * 256 + (t3 : F))) = 0)
    (g4c : (ov : F) * ((m4 : F) + (sr : F) * 255 - (t4 : F) * 256 + (t3 : F)) = 0)
    (g5a : (1 - (ov : F)) * ((sb : F) * (((m5 : F) + (sr : F) * 255 - (t5 : F) * 256 + (t4 : F)) - 255)) = 0)
    (g5b : (1 - (ov : F)) * ((1 - (sb : F)) * ((m5 : F) + (sr : F) * 255 - (t5 : F) * 256 + (t4 : F))) = 0)
    (g5c : (ov : F) * ((m5 : F) + (sr : F) * 255 - (t5 : F) * 256 + (t4 : F)) = 0)
    (g6a : (1 - (ov : F)) * ((sb : F) * (((m6 : F) + (sr : F) * 255 - (t6 : F) * 256 + (t5 : F)) - 255)) = 0)
    (g6b : (1 - (ov : F)) * ((1 - (sb : F)) * ((m6 : F) + (sr : F) * 255 - (t6 : F) * 256 + (t5 : F))) = 0)
    (g6c : (ov : F) * ((m6 : F) + (sr : F) * 255 - (t6 : F) * 256 + (t5 : F)) = 0)
    (g7a : (1 - (ov : F)) * ((sb : F) * (((m7 : F) + (sr : F) * 255 - (t7 : F) * 256 + (t6 : F)) - 255)) = 0)
    (g7b : (1 - (ov : F)) * ((1 - (sb : F)) * ((m7 : F) + (sr : F) * 255 - (t7 : F) * 256 + (t6 : F))) = 0)
    (g7c : (ov : F) * ((m7 : F) + (sr : F) * 255 - (t7 : F) * 256 + (t6 : F)) = 0) :
    w4 m4 m5 m6 m7 + 4294967295 * sr + t3 = 4294967295 * (sb * (1 - ov)) + 4294967296 * t7 := by
  simp only [w4]
  have ho : ov = 0 ∨ ov = 1 := by omega
  have hs : sb = 0 ∨ sb = 1 := by omega
  rcases ho with rfl | rfl <;> rcases hs with rfl | rfl <;>
    simp only [Int.cast_zero, Int.cast_one, sub_zero, sub_self, one_mul, zero_mul, mul_zero,
      mul_one] at * <;>
    (divrem_lift; omega)

/-- The rows together, as a congruence between signed readings: `q · c + r ≡ t (mod 2⁶⁴)`,
where a word with sign bit `s` reads `w − 2³² s`. -/
theorem signed_congruence (q0 q1 q2 q3 sq c0 c1 c2 c3 sc m0 m1 m2 m3 m4 m5 m6 m7 : ℤ)
    (r0 r1 r2 r3 sr b0 b1 b2 b3 g k7 t3 t7 : ℤ)
    (hP : 1 * m0 + 256 * m1 + 65536 * m2 + 16777216 * m3 + 4294967296 * m4 + 1099511627776 * m5 + 281474976710656 * m6 + 72057594037927936 * m7 + 18446744073709551616 * k7 =
      1 * (q0 * c0) + 256 * (q0 * c1 + q1 * c0) + 65536 * (q0 * c2 + q1 * c1 + q2 * c0) + 16777216 * (q0 * c3 + q1 * c2 + q2 * c1 + q3 * c0) + 4294967296 * (q0 * (255 * sc) + q1 * c3 + q2 * c2 + q3 * c1 + (255 * sq) * c0) + 1099511627776 * (q0 * (255 * sc) + q1 * (255 * sc) + q2 * c3 + q3 * c2 + (255 * sq) * c1 + (255 * sq) * c0) + 281474976710656 * (q0 * (255 * sc) + q1 * (255 * sc) + q2 * (255 * sc) + q3 * c3 + (255 * sq) * c2 + (255 * sq) * c1 + (255 * sq) * c0) + 72057594037927936 * (q0 * (255 * sc) + q1 * (255 * sc) + q2 * (255 * sc) + q3 * (255 * sc) + (255 * sq) * c3 + (255 * sq) * c2 + (255 * sq) * c1 + (255 * sq) * c0))
    (hS1 : w4 b0 b1 b2 b3 + 4294967296 * t3 = w4 m0 m1 m2 m3 + w4 r0 r1 r2 r3)
    (hS2 : w4 m4 m5 m6 m7 + 4294967295 * sr + t3 = 4294967295 * g + 4294967296 * t7) :
    ∃ H : ℤ, (w4 q0 q1 q2 q3 - 4294967296 * sq) * (w4 c0 c1 c2 c3 - 4294967296 * sc)
        + (w4 r0 r1 r2 r3 - 4294967296 * sr)
      = (w4 b0 b1 b2 b3 - 4294967296 * g) + 18446744073709551616 * H := by
  refine ⟨g + t7 - sr + k7 + (1 * (q1 * (255 * sc)) + 1 * (q2 * (255 * sc)) + 256 * (q2 * (255 * sc)) + 1 * (q3 * (255 * sc)) + 256 * (q3 * (255 * sc)) + 65536 * (q3 * (255 * sc)) + 1 * ((255 * sq) * (255 * sc)) + 256 * ((255 * sq) * (255 * sc)) + 65536 * ((255 * sq) * (255 * sc)) + 16777216 * ((255 * sq) * (255 * sc)) + 1 * ((255 * sq) * c3) + 256 * ((255 * sq) * (255 * sc)) + 65536 * ((255 * sq) * (255 * sc)) + 16777216 * ((255 * sq) * (255 * sc)) + 4294967296 * ((255 * sq) * (255 * sc)) + 1 * ((255 * sq) * c2) + 256 * ((255 * sq) * c3) + 65536 * ((255 * sq) * (255 * sc)) + 16777216 * ((255 * sq) * (255 * sc)) + 4294967296 * ((255 * sq) * (255 * sc)) + 1099511627776 * ((255 * sq) * (255 * sc)) + 1 * ((255 * sq) * c1) + 256 * ((255 * sq) * c2) + 65536 * ((255 * sq) * c3) + 16777216 * ((255 * sq) * (255 * sc)) + 4294967296 * ((255 * sq) * (255 * sc)) + 1099511627776 * ((255 * sq) * (255 * sc)) + 281474976710656 * ((255 * sq) * (255 * sc)))
      - sq * (1 * c0 + 256 * c1 + 65536 * c2 + 16777216 * c3 + 4294967296 * (255 * sc) + 1099511627776 * (255 * sc) + 281474976710656 * (255 * sc) + 72057594037927936 * (255 * sc)) - sc * (1 * q0 + 256 * q1 + 65536 * q2 + 16777216 * q3 + 4294967296 * (255 * sq) + 1099511627776 * (255 * sq) + 281474976710656 * (255 * sq) + 72057594037927936 * (255 * sq)) + 18446744073709551616 * (sq * sc), ?_⟩
  simp only [w4] at *
  linear_combination (-1 : ℤ) * hP - hS1 + 4294967296 * hS2

/-- A congruence modulo `2⁶⁴` between signed 32-bit quantities is an equality. -/
theorem congruence_eq {Q C R T H : ℤ} (h : Q * C + R = T + 18446744073709551616 * H)
    (hQ : |Q| ≤ 2147483648) (hC : |C| ≤ 2147483648)
    (hR : |R| ≤ 4294967296) (hT : |T| ≤ 4294967296) : Q * C + R = T := by
  have hp : |Q * C| ≤ 2147483648 * 2147483648 := by
    rw [abs_mul]; exact mul_le_mul hQ hC (abs_nonneg _) (by norm_num)
  have h1 := abs_le.mp hp
  have h2 := abs_le.mp hR
  have h3 := abs_le.mp hT
  have : H = 0 := by omega
  subst this
  omega

/-- The sign bit of a 32-bit word. -/
def sgn (X : ℤ) : ℤ := if 2147483648 ≤ X then 1 else 0

/-- The signed reading of a 32-bit word when `sg = 1`, the unsigned one when `sg = 0`. -/
def rd (sg X : ℤ) : ℤ := X - 4294967296 * (sg * sgn X)

/-- The dividend a row divides: the reading of `B`, except on the one overflowing signed
division, `−2³¹ / −1`, where the row divides `2³¹`. -/
def target (sg B C : ℤ) : ℤ :=
  if sg = 1 ∧ B = 2147483648 ∧ C = 4294967295 then B else rd sg B

/-- What a row of the division chip says of its words `B`, `C`, `Q`, `R`. -/
def Spec (sg B C Q R : ℤ) : Prop :=
  rd sg Q * rd sg C + rd sg R = target sg B C ∧
    (rd sg R).natAbs < (rd sg C).natAbs ∧ 0 ≤ rd sg R * target sg B C

/-- The reading of a word is injective. -/
theorem rd_inj {sg X Y : ℤ} (hsg : sg = 0 ∨ sg = 1) (hX : 0 ≤ X ∧ X < 4294967296)
    (hY : 0 ≤ Y ∧ Y < 4294967296) (h : rd sg X = rd sg Y) : X = Y := by
  simp only [rd, sgn] at h
  rcases hsg with rfl | rfl <;> split_ifs at h <;> omega

/-- Quotient and remainder are functions of dividend and divisor. -/
theorem spec_unique {sg B C Q R Q' R' : ℤ} (hsg : sg = 0 ∨ sg = 1)
    (hQ : 0 ≤ Q ∧ Q < 4294967296) (hR : 0 ≤ R ∧ R < 4294967296)
    (hQ' : 0 ≤ Q' ∧ Q' < 4294967296) (hR' : 0 ≤ R' ∧ R' < 4294967296)
    (h : Spec sg B C Q R) (h' : Spec sg B C Q' R') : Q = Q' ∧ R = R' := by
  obtain ⟨e, l, s⟩ := h
  obtain ⟨e', l', s'⟩ := h'
  have hc : rd sg C ≠ 0 := by
    intro h0
    rw [h0] at l
    simp at l
  have a : |rd sg R| < |rd sg C| := by
    rw [Int.abs_eq_natAbs, Int.abs_eq_natAbs]
    exact_mod_cast l
  have a' : |rd sg R'| < |rd sg C| := by
    rw [Int.abs_eq_natAbs, Int.abs_eq_natAbs]
    exact_mod_cast l'
  obtain ⟨hq, hr⟩ :=
    ZirenDet.Gadgets.divrem_unique hc e.symm e'.symm a a' s s'
  exact ⟨rd_inj hsg hQ hQ' hq, rd_inj hsg hR hR' hr⟩

/-- A word of four bytes is below `2³²`. -/
theorem w4_range {a0 a1 a2 a3 : ℤ} (h0 : 0 ≤ a0 ∧ a0 ≤ 255) (h1 : 0 ≤ a1 ∧ a1 ≤ 255)
    (h2 : 0 ≤ a2 ∧ a2 ≤ 255) (h3 : 0 ≤ a3 ∧ a3 ≤ 255) :
    0 ≤ w4 a0 a1 a2 a3 ∧ w4 a0 a1 a2 a3 < 4294967296 := by
  simp only [w4]; omega

/-- Equal words have equal bytes. -/
theorem w4_inj {a0 a1 a2 a3 b0 b1 b2 b3 : ℤ} (h0 : 0 ≤ a0 ∧ a0 ≤ 255) (h1 : 0 ≤ a1 ∧ a1 ≤ 255)
    (h2 : 0 ≤ a2 ∧ a2 ≤ 255) (h3 : 0 ≤ a3 ∧ a3 ≤ 255) (k0 : 0 ≤ b0 ∧ b0 ≤ 255)
    (k1 : 0 ≤ b1 ∧ b1 ≤ 255) (k2 : 0 ≤ b2 ∧ b2 ≤ 255) (k3 : 0 ≤ b3 ∧ b3 ≤ 255)
    (h : w4 a0 a1 a2 a3 = w4 b0 b1 b2 b3) : a0 = b0 ∧ a1 = b1 ∧ a2 = b2 ∧ a3 = b3 := by
  simp only [w4] at h; omega

/-- The sign bit of a word whose top byte is `128 s + l` with `l ≤ 127` is `s`. -/
theorem sgn_of_msb {a0 a1 a2 a3 s l : ℤ} (h0 : 0 ≤ a0 ∧ a0 ≤ 255) (h1 : 0 ≤ a1 ∧ a1 ≤ 255)
    (h2 : 0 ≤ a2 ∧ a2 ≤ 255) (hs : 0 ≤ s ∧ s ≤ 1) (hl : 0 ≤ l ∧ l ≤ 127)
    (h : a3 = 128 * s + l) : sgn (w4 a0 a1 a2 a3) = s := by
  simp only [sgn, w4]; split_ifs <;> omega

/-- The signed row: the chip's equation, bound and sign condition give the specification. -/
theorem spec_signed {b0 b1 b2 b3 c0 c1 c2 c3 q0 q1 q2 q3 r0 r1 r2 r3 : ℤ}
    {sq sc sr sb ov lq lc lr lb : ℤ}
    (hb0 : 0 ≤ b0 ∧ b0 ≤ 255) (hb1 : 0 ≤ b1 ∧ b1 ≤ 255) (hb2 : 0 ≤ b2 ∧ b2 ≤ 255)
    (hc0 : 0 ≤ c0 ∧ c0 ≤ 255) (hc1 : 0 ≤ c1 ∧ c1 ≤ 255) (hc2 : 0 ≤ c2 ∧ c2 ≤ 255)
    (hq0 : 0 ≤ q0 ∧ q0 ≤ 255) (hq1 : 0 ≤ q1 ∧ q1 ≤ 255) (hq2 : 0 ≤ q2 ∧ q2 ≤ 255)
    (hr0 : 0 ≤ r0 ∧ r0 ≤ 255) (hr1 : 0 ≤ r1 ∧ r1 ≤ 255) (hr2 : 0 ≤ r2 ∧ r2 ≤ 255)
    (hsq : 0 ≤ sq ∧ sq ≤ 1) (hsc : 0 ≤ sc ∧ sc ≤ 1) (hsr : 0 ≤ sr ∧ sr ≤ 1)
    (hsb : 0 ≤ sb ∧ sb ≤ 1) (hov : 0 ≤ ov ∧ ov ≤ 1)
    (hlq : 0 ≤ lq ∧ lq ≤ 127) (hlc : 0 ≤ lc ∧ lc ≤ 127) (hlr : 0 ≤ lr ∧ lr ≤ 127)
    (hlb : 0 ≤ lb ∧ lb ≤ 127)
    (mq : q3 = 128 * sq + lq) (mc : c3 = 128 * sc + lc) (mr : r3 = 128 * sr + lr)
    (mb : b3 = 128 * sb + lb)
    (heq : (w4 q0 q1 q2 q3 - 4294967296 * sq) * (w4 c0 c1 c2 c3 - 4294967296 * sc)
        + (w4 r0 r1 r2 r3 - 4294967296 * sr) = w4 b0 b1 b2 b3 - 4294967296 * (sb * (1 - ov)))
    (hlt : (w4 r0 r1 r2 r3 - 4294967296 * sr).natAbs < (w4 c0 c1 c2 c3 - 4294967296 * sc).natAbs)
    (hovf : (ov = 1 ∧ (b0 = 0 ∧ b1 = 0 ∧ b2 = 0 ∧ b3 = 128) ∧
        (c0 = 255 ∧ c1 = 255 ∧ c2 = 255 ∧ c3 = 255)) ∨
      (ov = 0 ∧ ¬((b0 = 0 ∧ b1 = 0 ∧ b2 = 0 ∧ b3 = 128) ∧
        (c0 = 255 ∧ c1 = 255 ∧ c2 = 255 ∧ c3 = 255))))
    (hs1 : sr = 1 → sb = 1) (hs2 : sb = 1 → sr = 0 → r0 + r1 + r2 + r3 = 0) :
    Spec 1 (w4 b0 b1 b2 b3) (w4 c0 c1 c2 c3) (w4 q0 q1 q2 q3) (w4 r0 r1 r2 r3) := by
  have hb3 : 0 ≤ b3 ∧ b3 ≤ 255 := by omega
  have hc3 : 0 ≤ c3 ∧ c3 ≤ 255 := by omega
  have hq3 : 0 ≤ q3 ∧ q3 ≤ 255 := by omega
  have hr3 : 0 ≤ r3 ∧ r3 ≤ 255 := by omega
  have eq := sgn_of_msb hq0 hq1 hq2 hsq hlq mq
  have ec := sgn_of_msb hc0 hc1 hc2 hsc hlc mc
  have er := sgn_of_msb hr0 hr1 hr2 hsr hlr mr
  have eb := sgn_of_msb hb0 hb1 hb2 hsb hlb mb
  have hT : target 1 (w4 b0 b1 b2 b3) (w4 c0 c1 c2 c3)
      = w4 b0 b1 b2 b3 - 4294967296 * (sb * (1 - ov)) := by
    simp only [target, rd, eb, one_mul]
    rcases hovf with ⟨rfl, hb, hc⟩ | ⟨rfl, hn⟩
    · rw [if_pos]
      · ring
      · obtain ⟨rfl, rfl, rfl, rfl⟩ := hb
        obtain ⟨rfl, rfl, rfl, rfl⟩ := hc
        simp [w4]
    · rw [if_neg]
      · ring
      · rintro ⟨-, hB, hC⟩
        apply hn
        simp only [w4] at hB hC
        refine ⟨⟨?_, ?_, ?_, ?_⟩, ⟨?_, ?_, ?_, ?_⟩⟩ <;> omega
  refine ⟨?_, ?_, ?_⟩
  · simp only [rd, eq, ec, er, one_mul, hT]
    exact heq
  · simp only [rd, ec, er, one_mul]
    exact hlt
  · simp only [rd, er, one_mul, hT]
    have hR : w4 r0 r1 r2 r3 - 4294967296 * sr ≥ 0 ∨ w4 r0 r1 r2 r3 - 4294967296 * sr < 0 := by
      omega
    rcases hovf with ⟨rfl, hb, hc⟩ | ⟨rfl, hn⟩
    · obtain ⟨rfl, rfl, rfl, rfl⟩ := hb
      obtain ⟨rfl, rfl, rfl, rfl⟩ := hc
      have hsc1 : sc = 1 := by omega
      subst hsc1
      have : w4 r0 r1 r2 r3 - 4294967296 * sr = 0 := by
        simp only [w4] at hlt ⊢
        omega
      rw [this, zero_mul]
    · have hs : sr = 0 ∨ sr = 1 := by omega
      have hb : sb = 0 ∨ sb = 1 := by omega
      rcases hs with rfl | rfl <;> rcases hb with rfl | rfl
      · apply mul_nonneg <;> (simp only [w4]; omega)
      · have := hs2 rfl rfl
        have : w4 r0 r1 r2 r3 = 0 := by simp only [w4]; omega
        simp [this]
      · have := hs1 rfl
        omega
      · apply mul_nonneg_of_nonpos_of_nonpos <;> (simp only [w4]; omega)

/-- A congruence modulo `2⁶⁴` between unsigned 32-bit quantities is an equality. -/
theorem congruence_eq_unsigned {Q C R T H : ℤ} (h : Q * C + R = T + 18446744073709551616 * H)
    (hQ : 0 ≤ Q ∧ Q ≤ 4294967295) (hC : 0 ≤ C ∧ C ≤ 4294967295)
    (hR : 0 ≤ R ∧ R ≤ 4294967295) (hT : 0 ≤ T ∧ T ≤ 4294967295) : Q * C + R = T := by
  have h0 : 0 ≤ Q * C := mul_nonneg hQ.1 hC.1
  have h1 : Q * C ≤ 4294967295 * 4294967295 := mul_le_mul hQ.2 hC.2 hC.1 (by norm_num)
  have : H = 0 := by omega
  subst this
  omega

/-- The unsigned row: the chip's equation and bound give the specification. -/
theorem spec_unsigned {B C Q R : ℤ} (hB : 0 ≤ B) (hR : 0 ≤ R) (heq : Q * C + R = B)
    (hlt : R.natAbs < C.natAbs) : Spec 0 B C Q R := by
  have e : ∀ X : ℤ, rd 0 X = X := fun X => by simp [rd]
  have t : target 0 B C = B := by simp [target, e]
  refine ⟨?_, ?_, ?_⟩
  · rw [e, e, e, t]; exact heq
  · rw [e, e]; exact hlt
  · rw [e, t]; exact mul_nonneg hR hB

end ZirenDet.DivRem
