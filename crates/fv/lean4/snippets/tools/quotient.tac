  have hq4 : 0 ≤ 255 * sq ∧ 255 * sq ≤ 255 := by omega
  have hc4 : 0 ≤ 255 * sx ∧ 255 * sx ≤ 255 := by omega
  have hP := product_rows q0 q1 q2 q3 (255 * sq) (255 * sq) (255 * sq) (255 * sq)
    dv0 dv1 dv2 dv3 (255 * sx) (255 * sx) (255 * sx) (255 * sx) m0 m1 m2 m3 m4 m5 m6 m7
    kk0 kk1 kk2 kk3 kk4 kk5 kk6 kk7 hq0 hq1 hq2 hq3 hq4 hq4 hq4 hq4 hdv0 hdv1 hdv2 hdv3 hc4 hc4 hc4 hc4
    hm0 hm1 hm2 hm3 hm4 hm5 hm6 hm7 hkk0 hkk1 hkk2 hkk3 hkk4 hkk5 hkk6 hkk7
    (by push_cast; linear_combination e7) (by push_cast; linear_combination e8)
    (by push_cast; linear_combination e9) (by push_cast; linear_combination e10)
    (by push_cast; linear_combination e11) (by push_cast; linear_combination e12)
    (by push_cast; linear_combination e13) (by push_cast; linear_combination e14)
  have hS1 := sum_low b0 b1 b2 b3 m0 m1 m2 m3 r0 r1 r2 r3 t0 t1 t2 t3 hb0 hb1 hb2 hb3
    hm0 hm1 hm2 hm3 hr0 hr1 hr2 hr3 ht0 ht1 ht2 ht3
    (by linear_combination e56) (by linear_combination e57) (by linear_combination e58)
    (by linear_combination e59)
  have hS2 := sum_high m4 m5 m6 m7 sr sb ov t3 t4 t5 t6 t7 hm4 hm5 hm6 hm7 hsr hsb hov
    ht3 ht4 ht5 ht6 ht7
    (by linear_combination e60) (by linear_combination e61) (by linear_combination e62)
    (by linear_combination e63) (by linear_combination e64) (by linear_combination e65)
    (by linear_combination e66) (by linear_combination e67) (by linear_combination e68)
    (by linear_combination e69) (by linear_combination e70) (by linear_combination e71)
  obtain ⟨H, hH⟩ := signed_congruence q0 q1 q2 q3 sq dv0 dv1 dv2 dv3 sx m0 m1 m2 m3 m4 m5 m6 m7
    r0 r1 r2 r3 sr b0 b1 b2 b3 (sb * (1 - ov)) kk7 t3 t7 hP hS1 hS2
  have hg : 0 ≤ sb * (1 - ov) ∧ sb * (1 - ov) ≤ 1 := by
    have ho : ov = 0 ∨ ov = 1 := by omega
    rcases ho with rfl | rfl <;> omega
  have hmsb : sq = msq ∧ q3 = 128 * msq + lq ∧ sx = msc ∧ dv3 = 128 * msc + lc := by
    clear hP hS1 hS2 hH
    clear * - e3 e4 e184 e187 hq3 hdv3 hsq hsx hmsq hmsc hlq hlc
    refine ⟨?_, ?_, ?_, ?_⟩ <;> (divrem_lift; omega)
  refine congruence_eq hH ?_ ?_ ?_ ?_ <;>
    (clear hH hP hS1 hS2; simp only [w4]; rw [abs_le]; omega)
