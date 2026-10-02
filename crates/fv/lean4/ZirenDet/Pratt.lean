import Mathlib

/-!
# Primality certificates

`lucas_primality` proves `p` prime from a witness `a` of order `p − 1` and the prime factors of
`p − 1`.  The powers are computed by `pm`, square-and-multiply on natural numbers, which the kernel
evaluates with its accelerated arithmetic, so a certificate for a 384-bit prime is checked by
`decide` in a fraction of a second.
-/

namespace ZirenDet.Pratt

/-- `pm m k b e acc = acc · b ^ e mod m` when `e < 2 ^ k` (square and multiply, `k` rounds). -/
def pm (m : ℕ) : ℕ → ℕ → ℕ → ℕ → ℕ
  | 0, _, _, acc => acc
  | k + 1, b, e, acc =>
    if e = 0 then acc else pm m k (b * b % m) (e / 2) (if e % 2 = 1 then acc * b % m else acc)

theorem pm_spec (m : ℕ) : ∀ k b e acc, e < 2 ^ k → pm m k b e acc % m = acc * b ^ e % m
  | 0, b, e, acc, h => by
    have : e = 0 := by simpa using h
    subst this
    simp [pm]
  | k + 1, b, e, acc, h => by
    by_cases he : e = 0
    · subst he
      simp [pm]
    have hk : e / 2 < 2 ^ k := by
      rw [pow_succ] at h
      omega
    have ih := pm_spec m k (b * b % m) (e / 2) (if e % 2 = 1 then acc * b % m else acc) hk
    simp only [pm, he, if_false]
    rw [ih]
    have hsplit : b ^ e = (b * b) ^ (e / 2) * b ^ (e % 2) := by
      rw [← pow_two, ← pow_mul, ← pow_add]
      congr 1
      omega
    rw [hsplit]
    rcases Nat.mod_two_eq_zero_or_one e with h2 | h2
    · rw [if_neg (by omega), h2, pow_zero, mul_one]
      exact Nat.ModEq.mul_left _ (Nat.ModEq.pow _ (Nat.mod_modEq _ _))
    · rw [if_pos h2, h2, pow_one]
      have := Nat.ModEq.mul (Nat.mod_modEq (acc * b) m) (Nat.ModEq.pow (e / 2) (Nat.mod_modEq (b * b) m))
      rw [show acc * ((b * b) ^ (e / 2) * b) = acc * b * (b * b) ^ (e / 2) by ring]
      exact this

/-- A prime dividing a product of prime powers is one of the primes. -/
theorem mem_of_dvd_prod {q : ℕ} (hq : q.Prime) :
    ∀ (fs : List (ℕ × ℕ)), (∀ f ∈ fs, f.1.Prime) → q ∣ (fs.map fun f => f.1 ^ f.2).prod →
      ∃ f ∈ fs, q = f.1
  | [], _, h => by
    simp only [List.map_nil, List.prod_nil, Nat.dvd_one] at h
    exact absurd h hq.one_lt.ne'
  | f :: fs, hp, h => by
    simp only [List.map_cons, List.prod_cons] at h
    rcases (Nat.Prime.dvd_mul hq).mp h with h1 | h2
    · have := (Nat.prime_dvd_prime_iff_eq hq (hp f (by simp))).mp (hq.dvd_of_dvd_pow h1)
      exact ⟨f, by simp, this⟩
    · obtain ⟨g, hg, e⟩ := mem_of_dvd_prod hq fs (fun g hg => hp g (by simp [hg])) h2
      exact ⟨g, by simp [hg], e⟩

/-- Lucas' test with a factorization of `p − 1` and powers computed by `pm`. -/
theorem prime_of_cert (p a : ℕ) (fs : List (ℕ × ℕ)) (h1 : 1 < p) (hk : p - 1 < 2 ^ 400)
    (hprod : (fs.map fun f => f.1 ^ f.2).prod = p - 1)
    (hprimes : ∀ f ∈ fs, f.1.Prime)
    (hpow : pm p 400 a (p - 1) 1 % p = 1)
    (hq : ∀ f ∈ fs, pm p 400 a ((p - 1) / f.1) 1 % p ≠ 1) : p.Prime := by
  have hcast : ∀ e, e < 2 ^ 400 → ((a : ZMod p) ^ e = 1 ↔ pm p 400 a e 1 % p = 1) := by
    intro e he
    rw [pm_spec p 400 a e 1 he, one_mul, ← Nat.cast_pow]
    rw [show (1 : ZMod p) = ((1 : ℕ) : ZMod p) by simp, ZMod.natCast_eq_natCast_iff']
    rw [Nat.one_mod_eq_one.mpr (by omega)]
  apply lucas_primality p (a : ZMod p)
  · exact (hcast (p - 1) hk).mpr hpow
  · intro q hqp hdvd
    obtain ⟨f, hf, rfl⟩ := mem_of_dvd_prod hqp fs hprimes (hprod ▸ hdvd)
    intro hc
    exact hq f hf ((hcast _ (lt_of_le_of_lt (Nat.div_le_self _ _) hk)).mp hc)

/-- Euler's criterion as a certificate: `d` is not a square modulo the odd prime `p` when
`d ^ (p / 2) ≢ 1`, the power computed by `pm`. -/
theorem not_square_of_cert (p d : ℕ) [hp : Fact p.Prime] (hk : p / 2 < 2 ^ 400)
    (hd : d % p ≠ 0) (hpow : pm p 400 d (p / 2) 1 % p ≠ 1) : ¬ IsSquare (d : ZMod p) := by
  have hne : (d : ZMod p) ≠ 0 := by
    rw [Ne, ZMod.natCast_eq_zero_iff]
    exact fun h => hd (Nat.mod_eq_zero_of_dvd h)
  rw [ZMod.euler_criterion p hne]
  intro h1
  apply hpow
  rw [pm_spec p 400 d (p / 2) 1 hk, one_mul, ← ZMod.val_natCast, Nat.cast_pow, h1, ZMod.val_one]

end ZirenDet.Pratt
