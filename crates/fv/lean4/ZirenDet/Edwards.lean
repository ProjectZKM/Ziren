import ZirenDet.Pratt
import ZirenDet.Primes

/-!
# Edwards addition denominators

The twisted Edwards sum divides by `1 ± d·x₁y₁x₂y₂`.  When the numerator of the quotient
vanishes, the denominator does not, because `d` (for `x₃`) and `−d` (for `y₃`) are not squares;
so a result `r` with `r·(1 ± d·x₁y₁x₂y₂) = numerator` is unique for any inputs, on the curve
or not.
-/

namespace ZirenDet.Edwards

variable {K : Type*} [Field K]

/-- `d·u² = 1` makes `d` the square of `u⁻¹`. -/
theorem isSquare_of_mul_sq {d u : K} (h : d * u ^ 2 = 1) : IsSquare d := by
  have hu : u ≠ 0 := by
    rintro rfl
    simp at h
  exact ⟨u⁻¹, by field_simp; linear_combination h⟩

/-- The `x₃` denominator: `x₁y₂ + x₂y₁ = 0` and `1 + d·x₁y₁·x₂y₂ = 0` make `d` a square. -/
theorem x_den_ne {d x1 y1 x2 y2 : K} (hd : ¬ IsSquare d) (hA : x1 * y2 + x2 * y1 = 0) :
    1 + d * (x1 * y1) * (x2 * y2) ≠ 0 := by
  intro h
  have hu : d * (x2 * y1) ^ 2 = 1 := by
    have e : x1 * y2 = -(x2 * y1) := by linear_combination hA
    linear_combination (-1 : K) * h + (d * x2 * y1) * e
  exact hd (isSquare_of_mul_sq hu)

/-- The `y₃` denominator: `y₁y₂ + x₁x₂ = 0` and `1 − d·x₁y₁·x₂y₂ = 0` make `−d` a square. -/
theorem y_den_ne {d x1 y1 x2 y2 : K} (hd : ¬ IsSquare (-d)) (hB : y1 * y2 + x1 * x2 = 0) :
    1 - d * (x1 * y1) * (x2 * y2) ≠ 0 := by
  intro h
  have hu : (-d) * (x1 * x2) ^ 2 = 1 := by
    have e : y1 * y2 = -(x1 * x2) := by linear_combination hB
    linear_combination (-1 : K) * h + (-(d * x1 * x2)) * e
  exact hd (isSquare_of_mul_sq hu)

/-- A quotient by a nonzero denominator is unique. -/
theorem quot_unique {r r' den a : K} (hden : den ≠ 0) (h : r * den = a) (h' : r' * den = a) :
    r = r' :=
  mul_right_cancel₀ hden (h.trans h'.symm)

/-- The Ed25519 prime as a `Fact`, for the field structure on `ZMod p`. -/
theorem ed25519_fact : Fact (Nat.Prime 57896044618658097711785492504343953926634992332820282019728792003956564819949) := ⟨ZirenDet.Primes.ed25519_p⟩

attribute [local instance] ed25519_fact

/-- The Ed25519 curve constant `d` is not a square modulo `p` (Euler's criterion). -/
theorem ed25519_d_nonsq : ¬ IsSquare (37095705934669439343138083508754565189542113879843219016388785533085940283555 : ZMod 57896044618658097711785492504343953926634992332820282019728792003956564819949) := by
  have h := ZirenDet.Pratt.not_square_of_cert 57896044618658097711785492504343953926634992332820282019728792003956564819949 37095705934669439343138083508754565189542113879843219016388785533085940283555
    (by decide +kernel) (by decide +kernel) (by decide +kernel)
  simpa using h

/-- `−d` is not a square modulo `p` either. -/
theorem ed25519_neg_d_nonsq : ¬ IsSquare (-(37095705934669439343138083508754565189542113879843219016388785533085940283555 : ZMod 57896044618658097711785492504343953926634992332820282019728792003956564819949)) := by
  have h := ZirenDet.Pratt.not_square_of_cert 57896044618658097711785492504343953926634992332820282019728792003956564819949 20800338683988658368647408995589388737092878452977063003340006470870624536394
    (by decide +kernel) (by decide +kernel) (by decide +kernel)
  have e : ((20800338683988658368647408995589388737092878452977063003340006470870624536394 : ℕ) : ZMod 57896044618658097711785492504343953926634992332820282019728792003956564819949) = -(37095705934669439343138083508754565189542113879843219016388785533085940283555 : ZMod 57896044618658097711785492504343953926634992332820282019728792003956564819949) := by
    rw [eq_neg_iff_add_eq_zero]
    have : (20800338683988658368647408995589388737092878452977063003340006470870624536394 : ℕ) + 37095705934669439343138083508754565189542113879843219016388785533085940283555 = 57896044618658097711785492504343953926634992332820282019728792003956564819949 := by norm_num
    exact_mod_cast (congrArg (fun n : ℕ => (n : ZMod 57896044618658097711785492504343953926634992332820282019728792003956564819949)) this).trans (ZMod.natCast_self _)
  rwa [e] at h

end ZirenDet.Edwards
