  have hz : sr = 0 ∧ sc = 0 := by
    clear * - e1 e2 hsr hsc
    refine ⟨?_, ?_⟩ <;> (divrem_lift; omega)
  obtain ⟨rfl, rfl⟩ := hz
  clear e1 e2
  subst e92
  have h149 : x149 = 1 := by linear_combination -e123
  subst h149
  subst e124 e125
  have h63 : x63 = 1 := by linear_combination -e130
  subst h63
  have h52 : x52 = 1 := by linear_combination e150 - e131
  have hlt := e241.mp (by rw [h52]; ring)
  clear e241 e240 e128 e129 e130 e131 e150 e149 e126 e127 e231 e232 e236 e237 e229 e230 e234 e235
  subst h52
  rcases bit_cases e138 with h | h <;> subst h <;>
    rcases bit_cases e132 with h | h <;> subst h <;>
    rcases bit_cases e133 with h | h <;> subst h <;>
    rcases bit_cases e134 with h | h <;> subst h <;>
    rcases bit_cases e135 with h | h <;> subst h <;>
    simp only [Int.cast_zero, Int.cast_one, zero_sub, sub_zero, sub_self, zero_mul, mul_zero,
      one_mul, mul_one, zero_add, add_zero, neg_mul, neg_eq_zero, sub_eq_zero, one_ne_zero,
      zero_ne_one, ZMod.val_zero, lt_self_iff_false] at * <;>
    (try subst_vars) <;>
    (first
      | done
      | (norm_num at *; done)
      | (exfalso; revert e137; decide)
      | (picus_name_all
         (try picus_generalize)
         (try simp only [add_mul_inv_pull c256_ne, sub_mul_inv_pull c256_ne, mul_inv_add_pull c256_ne,
                mul_inv_sub_pull c256_ne] at *)
         (try simp only [gen_mul_inv c256_ne] at *)
         (try picus_bits)
         (try casesm* _ ∧ _)
         picus_prep
         (try (replace hlt := lt_of_val_lt hlt (by omega) (by omega)))
         (try simp only [w4, ZirenDet.val_cast] at *)
         omega))
