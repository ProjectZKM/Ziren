
/-- The operand after the optional complement, as a natural number. -/
def bbVal (w : W) : ℕ := w.v6.val + 256 * w.v7.val + 65536 * w.v8.val + 16777216 * w.v9.val

/-- The row satisfies the leading-one specification. -/
theorem row_spec (w : W) (hw : constraints w) :
    ZirenDet.LeadingOne.Spec w.v10 w.v2 (bbVal w) := by
  %OPEN_W%
  %OPEN_HW%
  simp only [bbVal]
  rcases ZirenDet.bit_cases c16 with hz | hz <;> subst hz
  · simp only [sub_zero, one_mul, mul_one] at *
    exact Or.inr ⟨rfl, ZirenDet.LeadingOne.nonzero_spec x2 x6 x7 x8 x9 x56 x57 x58 x59 x60 x61 x62 x63 x11 x12 x13 x14 x15 x16 x17 x18 x19 x20 x21 x22 x23 x24 x25 x26 x27 x47 x48 x49 x50 x51 x39 x40 x41 x42 x43 x31 x32 x33 x34
      c20 c99 c82 c83 c84 c85 c86 c87 c88 c89 c21 c22 c23 c24 c25 c26 c27 c28 c29 c30 c31 c32 c33 c34 c35 c36 c37 c38 c39 c43 c44 c45 c46 c47 c50 c51 c52 c53 c54 c56 c57 c58 c59 c60 c68 c67 c66 c65 c90 c91 c92 c93 ⟨c212, c213, c214, c215, c216, c217, c218, c219⟩ ⟨c200, c201, c202, c203, c204, c205, c206, c207⟩ ⟨c188, c189, c190, c191, c192, c193, c194, c195⟩ ⟨c176, c177, c178, c179, c180, c181, c182, c183⟩ ⟨c164, c165, c166, c167, c168, c169, c170, c171⟩ c94 c95 c96 c97 c220 c221 c222 c223 c224 c244 c245 c246 c247 c248 c236 c237 c238 c239 c240⟩
  · simp only [one_mul] at *
    exact ZirenDet.LeadingOne.zero_spec x2 x6 x7 x8 x9 c17 c18 c19 c94 c95 c96 c97

/-- The gadget's outputs are determined by the row's inputs. -/
theorem gadget_det (w w' : W) (hw : constraints w) (hw' : constraints w')
    (hin : inputs w = inputs w') : w.v2 = w'.v2 ∧ w.v10 = w'.v10 := by
  have h := row_spec w hw
  have h' := row_spec w' hw'
  have hb : bbVal w = bbVal w' := by
    clear h h'
    %OPEN_W%
    %OPEN_W'%
    %OPEN_HW%
    %OPEN_HW'%
    have i9 := congrArg (·[9]?) hin
    have i10 := congrArg (·[10]?) hin
    have i11 := congrArg (·[11]?) hin
    have i12 := congrArg (·[12]?) hin
    simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i9 i10 i11 i12
    have e6 : x6 = y6 := by linear_combination i9 - c0 + d0
    have e7 : x7 = y7 := by linear_combination i10 - c1 + d1
    have e8 : x8 = y8 := by linear_combination i11 - c2 + d2
    have e9 : x9 = y9 := by linear_combination i12 - c3 + d3
    simp only [bbVal, e6, e7, e8, e9]
  rw [hb] at h
  exact ZirenDet.LeadingOne.spec_unique h h'
