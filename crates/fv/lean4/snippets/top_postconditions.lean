/-
  Hand-written proof of `postconditions` for the `top` module of `ShaCompress`: the three
  selector flags are bits and at most one is set.  The ten cycle flags `v13 … v22` are one-hot
  (bits summing to one, `constraints_0`), `v248` is a bit, and the selectors are
  `v245 = v13·v248`, `v246 = (v14 + … + v21)·v248`, `v247 = v22·v248`, so their sum is `v248`.
  The generator uses this proof only when the statement below is exactly the generated one.
-/
theorem postconditions (w : W) (hw : constraints w) :
    (w.v245 * (w.v245 - (1 : F))) = 0 ∧
    (w.v246 * (w.v246 - (1 : F))) = 0 ∧
    (w.v247 * (w.v247 - (1 : F))) = 0 ∧
    (((w.v245 + w.v246) + w.v247)).val < 2 := by
  obtain ⟨-, -, -, -, -, -, -, -, -, b13, b14, b15, b16, b17, b18, b19, b20, b21, b22, hs, -, h245, h246, h247, b248, -⟩ := hw.1
  have e245 : w.v245 = w.v13 * w.v248 := sub_eq_zero.mp h245
  have e246 : w.v246 = (w.v14 + w.v15 + w.v16 + w.v17 + w.v18 + w.v19 + w.v20 + w.v21) * w.v248 := sub_eq_zero.mp h246
  have e247 : w.v247 = w.v22 * w.v248 := sub_eq_zero.mp h247
  obtain ⟨k, hk⟩ := ZirenDet.OneHot.onehot_single (n := 10) (by norm_num [KB])
    ![w.v13, w.v14, w.v15, w.v16, w.v17, w.v18, w.v19, w.v20, w.v21, w.v22]
    (by intro i; fin_cases i <;> assumption)
    (by simp only [Fin.sum_univ_succ, Fin.sum_univ_zero, Matrix.cons_val_zero, Matrix.cons_val_succ]; linear_combination hs)
  have h13 : w.v13 = if (0 : Fin 10) = k then 1 else 0 := hk 0
  have h14 : w.v14 = if (1 : Fin 10) = k then 1 else 0 := hk 1
  have h15 : w.v15 = if (2 : Fin 10) = k then 1 else 0 := hk 2
  have h16 : w.v16 = if (3 : Fin 10) = k then 1 else 0 := hk 3
  have h17 : w.v17 = if (4 : Fin 10) = k then 1 else 0 := hk 4
  have h18 : w.v18 = if (5 : Fin 10) = k then 1 else 0 := hk 5
  have h19 : w.v19 = if (6 : Fin 10) = k then 1 else 0 := hk 6
  have h20 : w.v20 = if (7 : Fin 10) = k then 1 else 0 := hk 7
  have h21 : w.v21 = if (8 : Fin 10) = k then 1 else 0 := hk 8
  have h22 : w.v22 = if (9 : Fin 10) = k then 1 else 0 := hk 9
  have hb : w.v248 = 0 ∨ w.v248 = 1 := by
    rcases mul_eq_zero.mp b248 with h | h
    · exact Or.inl h
    · exact Or.inr (sub_eq_zero.mp h)
  rw [e245, e246, e247]
  fin_cases k <;>
    simp (config := { decide := true }) only [ite_true, ite_false] at h13 h14 h15 h16 h17 h18 h19 h20 h21 h22 <;>
    rcases hb with hb | hb <;>
    simp [h13, h14, h15, h16, h17, h18, h19, h20, h21, h22, hb, ZMod.val_one]

/- MiscInstrs, module top: selector flags v424 … v431: each is a bit, and their sum S has S*(S-1) = 0. -/
theorem postconditions (w : W) (hw : constraints w) :
    (w.v424 * (w.v424 - (1 : F))) = 0 ∧
    (w.v425 * (w.v425 - (1 : F))) = 0 ∧
    (w.v426 * (w.v426 - (1 : F))) = 0 ∧
    (w.v427 * (w.v427 - (1 : F))) = 0 ∧
    (w.v428 * (w.v428 - (1 : F))) = 0 ∧
    (w.v429 * (w.v429 - (1 : F))) = 0 ∧
    (w.v430 * (w.v430 - (1 : F))) = 0 ∧
    (w.v431 * (w.v431 - (1 : F))) = 0 ∧
    ((((((((w.v424 + w.v425) + w.v426) + w.v427) + w.v428) + w.v429) + w.v430) + w.v431)).val < 2 := by
  refine ⟨(And.left (And.left (hw))), (And.left (And.right (And.left (hw)))), (And.left (And.right (And.right (And.left (hw))))), (And.left (And.right (And.right (And.right (And.left (hw)))))), (And.left (And.right (And.right (And.right (And.right (And.left (hw))))))), (And.left (And.right (And.right (And.right (And.right (And.right (And.left (hw)))))))), (And.left (And.right (And.right (And.right (And.right (And.right (And.right (And.left (hw))))))))), (And.left (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.left (hw)))))))))), ?_⟩
  rcases ZirenDet.bit_cases (And.left (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.left (hw))))))))))) with h | h <;> rw [h] <;> simp [ZMod.val_one]

/- Bls12381FpOpAssign, module top: selector flags v3, v5 are bits and v3 + v4 + v5 = 1 with v4 a bit, so v3 + v5 = 1 - v4 is 0 or 1. -/
theorem postconditions (w : W) (hw : constraints w) :
    (w.v3 * (w.v3 - (1 : F))) = 0 ∧
    (w.v5 * (w.v5 - (1 : F))) = 0 ∧
    ((w.v3 + w.v5)).val < 2 := by
  refine ⟨(And.left (And.left (hw))), (And.left (And.right (And.right (And.left (hw))))), ?_⟩
  have hs : w.v3 + w.v5 = 1 - w.v4 := by linear_combination (And.left (And.right (And.right (And.right (And.left (hw))))))
  rw [hs]
  rcases ZirenDet.bit_cases (And.left (And.right (And.left (hw)))) with h | h <;> rw [h] <;> simp [ZMod.val_one]

/- CloClz, module top: v64 is a bit (conjunct 4 of `constraints_2`, the module's third chunk). -/
theorem postconditions (w : W) (hw : constraints w) :
    (w.v64 * (w.v64 - (1 : F))) = 0 ∧
    (w.v64).val < 2 := by
  have h := And.left (And.right (And.right (And.right (And.right (And.right (And.right (hw)))))))
  refine ⟨h, ?_⟩
  rcases ZirenDet.bit_cases h with h' | h' <;> rw [h'] <;> simp [ZMod.val_one]

/- AddSub and AddSubImm (same statement and layout), module top: v4 at constraints_0[0], v5 at constraints_0[1]; their sum is a bit, constraints_0[2]. -/
theorem postconditions (w : W) (hw : constraints w) :
    (w.v4 * (w.v4 - (1 : F))) = 0 ∧
    (w.v5 * (w.v5 - (1 : F))) = 0 ∧
    ((w.v4 + w.v5)).val < 2 := by
  refine ⟨And.left (hw), And.left (And.right (hw)), ?_⟩
  rcases ZirenDet.bit_cases (And.left (And.right (And.right (hw)))) with h | h <;> rw [h] <;> simp [ZMod.val_one]

/- DivRem, module top: v86 at constraints_3[20], v87 at constraints_3[21], v88 at constraints_3[22], v89 at constraints_3[23]; their sum is a bit, constraints_0[19]. -/
theorem postconditions (w : W) (hw : constraints w) :
    (w.v86 * (w.v86 - (1 : F))) = 0 ∧
    (w.v87 * (w.v87 - (1 : F))) = 0 ∧
    (w.v88 * (w.v88 - (1 : F))) = 0 ∧
    (w.v89 * (w.v89 - (1 : F))) = 0 ∧
    ((((w.v86 + w.v87) + w.v88) + w.v89)).val < 2 := by
  refine ⟨And.left (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.left (And.right (And.right (And.right (hw))))))))))))))))))))))))), And.left (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.left (And.right (And.right (And.right (hw)))))))))))))))))))))))))), And.left (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.left (And.right (And.right (And.right (hw))))))))))))))))))))))))))), And.left (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.left (And.right (And.right (And.right (hw)))))))))))))))))))))))))))), ?_⟩
  rcases ZirenDet.bit_cases (And.left (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.right (And.left (hw)))))))))))))))))))))) with h | h <;> rw [h] <;> simp [ZMod.val_one]

/- LoadNarrow, module top: v46 at constraints_0[0], v47 at constraints_0[1], v48 at constraints_0[2], v49 at constraints_0[3]; their sum is a bit, constraints_0[4]. -/
theorem postconditions (w : W) (hw : constraints w) :
    (w.v46 * (w.v46 - (1 : F))) = 0 ∧
    (w.v47 * (w.v47 - (1 : F))) = 0 ∧
    (w.v48 * (w.v48 - (1 : F))) = 0 ∧
    (w.v49 * (w.v49 - (1 : F))) = 0 ∧
    ((((w.v46 + w.v47) + w.v48) + w.v49)).val < 2 := by
  refine ⟨And.left (And.left (hw)), And.left (And.right (And.left (hw))), And.left (And.right (And.right (And.left (hw)))), And.left (And.right (And.right (And.right (And.left (hw))))), ?_⟩
  rcases ZirenDet.bit_cases (And.left (And.right (And.right (And.right (And.right (And.left (hw))))))) with h | h <;> rw [h] <;> simp [ZMod.val_one]

/- LoadWord, module top: v46 at constraints_0[0], v47 at constraints_0[1]; their sum is a bit, constraints_0[2]. -/
theorem postconditions (w : W) (hw : constraints w) :
    (w.v46 * (w.v46 - (1 : F))) = 0 ∧
    (w.v47 * (w.v47 - (1 : F))) = 0 ∧
    ((w.v46 + w.v47)).val < 2 := by
  refine ⟨And.left (hw), And.left (And.right (hw)), ?_⟩
  rcases ZirenDet.bit_cases (And.left (And.right (And.right (hw)))) with h | h <;> rw [h] <;> simp [ZMod.val_one]

/- MemoryUnaligned, module top: v50 at constraints_0[0], v51 at constraints_0[1], v52 at constraints_0[2], v53 at constraints_0[3]; their sum is a bit, constraints_0[4]. -/
theorem postconditions (w : W) (hw : constraints w) :
    (w.v50 * (w.v50 - (1 : F))) = 0 ∧
    (w.v51 * (w.v51 - (1 : F))) = 0 ∧
    (w.v52 * (w.v52 - (1 : F))) = 0 ∧
    (w.v53 * (w.v53 - (1 : F))) = 0 ∧
    ((((w.v50 + w.v51) + w.v52) + w.v53)).val < 2 := by
  refine ⟨And.left (And.left (hw)), And.left (And.right (And.left (hw))), And.left (And.right (And.right (And.left (hw)))), And.left (And.right (And.right (And.right (And.left (hw))))), ?_⟩
  rcases ZirenDet.bit_cases (And.left (And.right (And.right (And.right (And.right (And.left (hw))))))) with h | h <;> rw [h] <;> simp [ZMod.val_one]
