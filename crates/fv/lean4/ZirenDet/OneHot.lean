import ZirenDet.Basic

/-!
# One-hot bit vectors

A one-hot vector of bits is determined by any weighted sum of it with distinct weights: the
replay closes a positional one-hot step with `onehot_lin_det`, or `onehot2_lin_det` when the
position reads two one-hot groups at once.
-/

namespace ZirenDet.OneHot

open ZirenDet

/-- A vector of bits over `F` summing to one has exactly one nonzero entry. -/
theorem onehot_single {n : ℕ} (hn : n < KB) (b : Fin n → F) (hb : ∀ i, b i * (b i - 1) = 0)
    (hs : ∑ i, b i = 1) : ∃ k, ∀ i, b i = if i = k then 1 else 0 := by
  have h01 : ∀ i, b i = 0 ∨ b i = 1 := fun i => by
    rcases mul_eq_zero.mp (hb i) with h | h
    · exact Or.inl h
    · exact Or.inr (sub_eq_zero.mp h)
  classical
  set S := Finset.univ.filter (fun i => b i = 1) with hS
  have hsum : ∑ i, b i = (S.card : F) := by
    rw [Finset.card_eq_sum_ones, Nat.cast_sum, Finset.sum_filter]
    refine Finset.sum_congr rfl fun i _ => ?_
    rcases h01 i with h | h <;> simp [h]
  have hcard : S.card = 1 := by
    have h1 : ((S.card : ℕ) : F) = ((1 : ℕ) : F) := by rw [← hsum, hs, Nat.cast_one]
    have hle : S.card ≤ n := (Finset.card_le_univ S).trans (by simp)
    have := congrArg ZMod.val h1
    rwa [ZMod.val_natCast, ZMod.val_natCast, Nat.mod_eq_of_lt (by omega),
      Nat.mod_eq_of_lt (by norm_num [KB])] at this
  obtain ⟨k, hk⟩ := Finset.card_eq_one.mp hcard
  refine ⟨k, fun i => ?_⟩
  by_cases hik : i = k
  · subst hik
    have : i ∈ S := by rw [hk]; exact Finset.mem_singleton_self i
    simpa [hS] using this
  · rw [if_neg hik]
    rcases h01 i with h | h
    · exact h
    · have : i ∈ S := by simp [hS, h]
      rw [hk, Finset.mem_singleton] at this
      exact absurd this hik

/-- Two one-hot bit vectors with the same weighted sum under distinct weights are equal. -/
theorem onehot_lin_det {n : ℕ} (hn : n < KB) (c : Fin n → F) (hc : Function.Injective c)
    (b b' : Fin n → F) (hb : ∀ i, b i * (b i - 1) = 0) (hs : ∑ i, b i = 1)
    (hb' : ∀ i, b' i * (b' i - 1) = 0) (hs' : ∑ i, b' i = 1)
    (hl : ∑ i, c i * b i = ∑ i, c i * b' i) : b = b' := by
  classical
  obtain ⟨k, hk⟩ := onehot_single hn b hb hs
  obtain ⟨k', hk'⟩ := onehot_single hn b' hb' hs'
  have e : ∀ (m : Fin n) (d : Fin n → F), (∀ i, d i = if i = m then 1 else 0) →
      ∑ i, c i * d i = c m := fun m d hd => by
    simp only [hd, mul_ite, mul_one, mul_zero, Finset.sum_ite_eq', Finset.mem_univ, if_true]
  rw [e k b hk, e k' b' hk'] at hl
  have hkk := hc hl
  subst hkk
  funext i
  rw [hk i, hk' i]

/-- Two one-hot bit vectors `b`, `z` read through one linear form `Σ c_i b_i + Σ d_j z_j` whose
pair sums `c_i + d_j` are distinct: both vectors are determined by the value of the form (a row
position `Σ i·octet_i + Σ 8j·cycle_j`). -/
theorem onehot2_lin_det {n m : ℕ} (hn : n < KB) (hm : m < KB) (c : Fin n → F) (d : Fin m → F)
    (hcd : ∀ i j i' j', c i + d j = c i' + d j' → i = i' ∧ j = j')
    (b b' : Fin n → F) (z z' : Fin m → F)
    (hb : ∀ i, b i * (b i - 1) = 0) (hs : ∑ i, b i = 1)
    (hz : ∀ j, z j * (z j - 1) = 0) (ht : ∑ j, z j = 1)
    (hb' : ∀ i, b' i * (b' i - 1) = 0) (hs' : ∑ i, b' i = 1)
    (hz' : ∀ j, z' j * (z' j - 1) = 0) (ht' : ∑ j, z' j = 1)
    (hl : ∑ i, c i * b i + ∑ j, d j * z j = ∑ i, c i * b' i + ∑ j, d j * z' j) :
    b = b' ∧ z = z' := by
  classical
  obtain ⟨k, hk⟩ := onehot_single hn b hb hs
  obtain ⟨l, hl0⟩ := onehot_single hm z hz ht
  obtain ⟨k', hk'⟩ := onehot_single hn b' hb' hs'
  obtain ⟨l', hl0'⟩ := onehot_single hm z' hz' ht'
  have e : ∀ {p : ℕ} (w : Fin p → F) (q : Fin p) (v : Fin p → F),
      (∀ i, v i = if i = q then 1 else 0) → ∑ i, w i * v i = w q := fun w q v hv => by
    simp only [hv, mul_ite, mul_one, mul_zero, Finset.sum_ite_eq', Finset.mem_univ, if_true]
  rw [e c k b hk, e d l z hl0, e c k' b' hk', e d l' z' hl0'] at hl
  obtain ⟨rfl, rfl⟩ := hcd _ _ _ _ hl
  exact ⟨funext fun i => by rw [hk i, hk' i], funext fun j => by rw [hl0 j, hl0' j]⟩

end ZirenDet.OneHot
