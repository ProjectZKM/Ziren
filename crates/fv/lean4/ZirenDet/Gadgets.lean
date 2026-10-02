import Mathlib

/-!
# Gadget summaries (hand-maintained)

The determinism analyser (`zkm-picus --analyze`) reads a gadget the AIR marks with
`MessageBuilder::annotate` as one step, tagged with the lemma below that justifies it, instead of
re-deriving the gadget inside every chip.  The field gadgets determine a *residue*: `result` is
fixed modulo `m` by the operation and pinned to a value only by a `FieldLtCols` check.

| analyser tag          | lemma                                   |
|-----------------------|-----------------------------------------|
| `residue_of_value`    | (a function of its arguments)           |
| `field_op` (+,−,·)    | `limb_vanishing`, `field_op_residue`    |
| `field_op_div`        | … and `field_div_residue` (`b ≢ 0`)     |
| `field_mul_add`       | `limb_vanishing`, `field_op_residue`    |
| `field_inner_product` | `limb_vanishing`, `field_op_residue`    |
| `field_den`           | … and `field_div_residue` (`1 ± b ≢ 0`) |
| `field_lt_canonical`  | `canonical_unique`                      |
| `field_sqrt_unique`   | `sqrt_unique`                           |
| `sqrt_choice_lsb`     | `sqrt_unique` (parity = sign)           |
| `sqrt_choice_lex`     | `sqrt_pair`, `lex_choice_unique`        |
| `divrem_unique`       | `divrem_unique`; the chip also owes the |
|                       | overflow row `−2³¹ / −1` (`q = b, r = 0`)|
| `leading_one_unique`  | `msb_unique`, `msb_ne_zero`             |
| `gt_bytes_unique`     | `first_diff_unique`                     |
| `septic_sqrt_sign`    | `Septic.sq_unique`, `y6_recv`/`y6_send` |
| `septic_chord`        | `Septic.chord_unique`                   |
| `residue_transfer`    | (`m₁ = m₂` in the branch)               |
| `canonical_by_width`  | `bytes_lt_width`, `canonical_unique`    |

`limb_vanishing` is the step from the AIR's field constraints to an integer identity: the vanishing
polynomial `V = a ∘ b − r − c·m` (limbs of `2^8`) is constrained coefficientwise equal to
`(w − off)·(X − 2^8)` in `F`; when every coefficient on both sides is small the equalities hold
over `ℤ`, and evaluating at `2^8` gives `V(2^8) = 0`, that is `a ∘ b = r + c·m` over `ℤ`.

What each chip still owes is the bridge from its own constraints to a lemma's hypotheses (the limb
and carry bookkeeping `picus_det` already does); the lemmas here are proved once, `sorry`-free.
-/

namespace ZirenDet.Gadgets

/-- The KoalaBear prime. -/
abbrev KB : ℕ := 2130706433

/-- Two integers below `KB / 2` in magnitude that are equal in `ZMod KB` are equal. -/
theorem cast_inj_small {a b : ℤ} (h : ((a : ℤ) : ZMod KB) = ((b : ℤ) : ZMod KB))
    (ha : |a| < 1065353216) (hb : |b| < 1065353216) : a = b := by
  rw [ZMod.intCast_eq_intCast_iff_dvd_sub] at h
  obtain ⟨k, hk⟩ := h
  have h1 := abs_lt.mp ha
  have h2 := abs_lt.mp hb
  have : k = 0 := by
    by_contra hne
    rcases lt_or_gt_of_ne hne with hlt | hgt
    · have : k ≤ -1 := by omega
      push_cast at hk
      nlinarith
    · have : 1 ≤ k := by omega
      push_cast at hk
      nlinarith
  subst this
  push_cast at hk
  linarith

/-- A polynomial with the root factor `X − r` vanishes at `r`. -/
theorem root_eval_zero (q : Polynomial ℤ) (r : ℤ) :
    (q * (Polynomial.X - Polynomial.C r)).eval r = 0 := by
  simp

/-- **Limb vanishing.**  If the vanishing polynomial equals `q · (X − r)` coefficientwise over `ℤ`
(each coefficient identity lifted from `F` by `cast_inj_small`), it vanishes at `r`. -/
theorem limb_vanishing (v q : Polynomial ℤ) (r : ℤ)
    (h : ∀ i, v.coeff i = (q * (Polynomial.X - Polynomial.C r)).coeff i) : v.eval r = 0 := by
  have : v = q * (Polynomial.X - Polynomial.C r) := Polynomial.ext h
  rw [this]
  exact root_eval_zero q r

/-- `a ∘ b = r + c · m` over `ℤ` fixes `r` modulo `m`. -/
theorem field_op_residue {x r c m : ℤ} (h : x - r - c * m = 0) : r ≡ x [ZMOD m] :=
  (Int.modEq_iff_dvd.mpr ⟨c, by linarith⟩)

/-- Division: `r · b ≡ a` with `b` a unit modulo `m` fixes `r` modulo `m`. -/
theorem field_div_residue {r₁ r₂ a b m : ℤ} (hcop : IsCoprime b m)
    (h₁ : r₁ * b ≡ a [ZMOD m]) (h₂ : r₂ * b ≡ a [ZMOD m]) : r₁ ≡ r₂ [ZMOD m] := by
  have h := h₁.trans h₂.symm
  rw [Int.modEq_iff_dvd] at h ⊢
  have : m ∣ (r₂ - r₁) * b := by rw [sub_mul]; exact h
  exact hcop.symm.dvd_of_dvd_mul_right this

/-- **Canonical form.**  Two residues in `[0, m)` that agree modulo `m` are equal. -/
theorem canonical_unique {r₁ r₂ m : ℤ} (h₁ : 0 ≤ r₁) (h₁' : r₁ < m) (h₂ : 0 ≤ r₂) (h₂' : r₂ < m)
    (h : r₁ ≡ r₂ [ZMOD m]) : r₁ = r₂ := by
  have e₁ : r₁ % m = r₁ := Int.emod_eq_of_lt h₁ h₁'
  have e₂ : r₂ % m = r₂ := Int.emod_eq_of_lt h₂ h₂'
  rw [← e₁, ← e₂]
  exact h

/-- **Square root.**  Modulo an odd prime `p`, two roots in `[0, p)` of the same square and the
same parity are equal. -/
theorem sqrt_unique {s₁ s₂ p : ℤ} (hp : Prime p) (hodd : p % 2 = 1)
    (h₁ : 0 ≤ s₁) (h₁' : s₁ < p) (h₂ : 0 ≤ s₂) (h₂' : s₂ < p)
    (hsq : s₁ ^ 2 ≡ s₂ ^ 2 [ZMOD p]) (hpar : s₁ % 2 = s₂ % 2) : s₁ = s₂ := by
  have hd : p ∣ (s₁ - s₂) * (s₁ + s₂) := by
    have := (Int.modEq_iff_dvd.mp hsq.symm)
    have e : s₁ ^ 2 - s₂ ^ 2 = (s₁ - s₂) * (s₁ + s₂) := by ring
    rw [← e]
    exact this
  rcases hp.dvd_or_dvd hd with hm | hs
  · obtain ⟨k, hk⟩ := hm
    have : k = 0 := by
      by_contra hne
      rcases lt_or_gt_of_ne hne with hlt | hgt
      · nlinarith
      · nlinarith
    subst this
    linarith
  · obtain ⟨k, hk⟩ := hs
    have hk01 : k = 0 ∨ k = 1 := by
      have hk0 : 0 ≤ k := by
        by_contra hneg
        push Not at hneg
        nlinarith
      have hk1 : k ≤ 1 := by
        by_contra hgt
        push Not at hgt
        nlinarith
      omega
    rcases hk01 with rfl | rfl
    · linarith
    · omega

/-- Modulo a prime `p`, two roots in `[0, p)` of the same square are equal or sum to `p`. -/
theorem sqrt_pair {s₁ s₂ p : ℤ} (hp : Prime p)
    (h₁ : 0 ≤ s₁) (h₁' : s₁ < p) (h₂ : 0 ≤ s₂) (h₂' : s₂ < p)
    (hsq : s₁ ^ 2 ≡ s₂ ^ 2 [ZMOD p]) : s₁ = s₂ ∨ s₁ + s₂ = p := by
  have hd : p ∣ (s₁ - s₂) * (s₁ + s₂) := by
    have := (Int.modEq_iff_dvd.mp hsq.symm)
    have e : s₁ ^ 2 - s₂ ^ 2 = (s₁ - s₂) * (s₁ + s₂) := by ring
    rw [← e]
    exact this
  rcases hp.dvd_or_dvd hd with hm | hs
  · obtain ⟨k, hk⟩ := hm
    have : k = 0 := by
      by_contra hne
      rcases lt_or_gt_of_ne hne with hlt | hgt
      · nlinarith
      · nlinarith
    subst this
    left
    linarith
  · obtain ⟨k, hk⟩ := hs
    have hk0 : 0 ≤ k := by
      by_contra hneg
      push Not at hneg
      nlinarith
    have hk1 : k ≤ 1 := by
      by_contra hgt
      push Not at hgt
      nlinarith
    rcases (show k = 0 ∨ k = 1 by omega) with rfl | rfl
    · left
      linarith
    · right
      linarith

/-- **Lexicographic choice.**  Two roots of the same square modulo a prime `p`, each strictly
below its own negation `p − y` (the sign bit's choice; the other sign is symmetric), are
equal. -/
theorem lex_choice_unique {y₁ y₂ p : ℤ} (hp : Prime p)
    (h₁ : 0 ≤ y₁) (h₁' : y₁ < p) (h₂ : 0 ≤ y₂) (h₂' : y₂ < p)
    (hsq : y₁ ^ 2 ≡ y₂ ^ 2 [ZMOD p]) (hc₁ : y₁ < p - y₁) (hc₂ : y₂ < p - y₂) : y₁ = y₂ := by
  rcases sqrt_pair hp h₁ h₁' h₂ h₂' hsq with h | h
  · exact h
  · omega

/-- A multiple of `c` smaller than `c` in magnitude is zero. -/
theorem mul_abs_lt_abs {k c : ℤ} (hc : c ≠ 0) (h : |k * c| < |c|) : k = 0 := by
  rw [abs_mul] at h
  have hc' : 0 < |c| := abs_pos.mpr hc
  have : |k| < 1 := by
    by_contra hk
    push Not at hk
    nlinarith
  have := abs_lt.mp this
  omega

/-- **Division.**  `b = q·c + r` with `|r| < |c|` and `r` of the sign of `b` (or zero) fixes
`q` and `r`. -/
theorem divrem_unique {b c q₁ r₁ q₂ r₂ : ℤ} (hc : c ≠ 0)
    (h₁ : b = q₁ * c + r₁) (h₂ : b = q₂ * c + r₂)
    (hr₁ : |r₁| < |c|) (hr₂ : |r₂| < |c|)
    (hs₁ : 0 ≤ r₁ * b) (hs₂ : 0 ≤ r₂ * b) : q₁ = q₂ ∧ r₁ = r₂ := by
  have hd : (q₁ - q₂) * c = r₂ - r₁ := by linarith
  have hlt : |r₂ - r₁| < |c| := by
    have a₁ := abs_lt.mp hr₁
    have a₂ := abs_lt.mp hr₂
    rcases lt_trichotomy b 0 with hb | hb | hb
    · have : r₁ ≤ 0 := by nlinarith
      have : r₂ ≤ 0 := by nlinarith
      rw [abs_lt]; constructor <;> linarith
    · subst hb
      have e₁ : |q₁ * c| < |c| := by rw [show q₁ * c = -r₁ by linarith, abs_neg]; exact hr₁
      have e₂ : |q₂ * c| < |c| := by rw [show q₂ * c = -r₂ by linarith, abs_neg]; exact hr₂
      have hq1 := mul_abs_lt_abs hc e₁
      have hq2 := mul_abs_lt_abs hc e₂
      have : r₁ = 0 := by rw [hq1] at h₁; linarith
      have : r₂ = 0 := by rw [hq2] at h₂; linarith
      rw [show r₂ - r₁ = 0 by linarith, abs_zero]
      exact abs_pos.mpr hc
    · have : 0 ≤ r₁ := by nlinarith
      have : 0 ≤ r₂ := by nlinarith
      rw [abs_lt]; constructor <;> linarith
  have hq : q₁ - q₂ = 0 := mul_abs_lt_abs hc (by rw [hd]; exact hlt)
  constructor
  · linarith
  · have : q₁ = q₂ := by linarith
    subst this
    linarith

/-- **Leading one.**  Two shifts that both leave exactly `1` are the same shift. -/
theorem msb_unique {n s₁ s₂ : ℕ} (h₁ : n / 2 ^ s₁ = 1) (h₂ : n / 2 ^ s₂ = 1) : s₁ = s₂ := by
  have b₁ := (Nat.div_eq_iff (by positivity : 0 < 2 ^ s₁)).mp h₁
  have b₂ := (Nat.div_eq_iff (by positivity : 0 < 2 ^ s₂)).mp h₂
  by_contra hne
  rcases lt_or_gt_of_ne hne with hlt | hgt
  · have : 2 ^ (s₁ + 1) ≤ 2 ^ s₂ := Nat.pow_le_pow_right (by norm_num) hlt
    rw [pow_succ] at this
    have p₁ : 0 < 2 ^ s₁ := by positivity
    have p₂ : 0 < 2 ^ s₂ := by positivity
    generalize 2 ^ s₁ = a at *
    generalize 2 ^ s₂ = b at *
    omega
  · have : 2 ^ (s₂ + 1) ≤ 2 ^ s₁ := Nat.pow_le_pow_right (by norm_num) hgt
    rw [pow_succ] at this
    have p₁ : 0 < 2 ^ s₁ := by positivity
    have p₂ : 0 < 2 ^ s₂ := by positivity
    generalize 2 ^ s₁ = a at *
    generalize 2 ^ s₂ = b at *
    omega

/-- A shift that leaves `1` saw a nonzero word, so the zero flag and the shift case exclude each
other. -/
theorem msb_ne_zero {n s : ℕ} (h : n / 2 ^ s = 1) : n ≠ 0 := by
  rintro rfl
  simp at h

/-- **First difference.**  Two positions below `n`, each a differing byte with every byte above it
equal, are the same position: `GtColsBytes`'s flag, and with it `result`, is unique. -/
theorem first_diff_unique {n k₁ k₂ : ℕ} {a b : ℕ → ℕ}
    (h₁ : ∀ j, k₁ < j → j < n → a j = b j) (h₂ : ∀ j, k₂ < j → j < n → a j = b j)
    (hk₁ : k₁ < n) (hk₂ : k₂ < n) (d₁ : a k₁ ≠ b k₁) (d₂ : a k₂ ≠ b k₂) : k₁ = k₂ := by
  by_contra hne
  rcases lt_or_gt_of_ne hne with h | h
  · exact d₂ (h₁ k₂ h hk₂)
  · exact d₁ (h₂ k₁ h hk₁)

/-- **Width.**  `n` byte limbs are below `256^n`, the bound `canonical_by_width` hands to
`canonical_unique` when the modulus is `2^(8n)`. -/
theorem bytes_lt_width (l : List ℕ) (hl : ∀ x ∈ l, x < 256) :
    Nat.ofDigits 256 l < 256 ^ l.length :=
  Nat.ofDigits_lt_base_pow_length (by norm_num) hl

end ZirenDet.Gadgets
