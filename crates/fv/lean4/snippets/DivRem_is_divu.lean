section DivRemGadget
open ZirenDet.DivRem

theorem quotient_eq
    (q0 q1 q2 q3 r0 r1 r2 r3 kk0 kk1 kk2 kk3 kk4 kk5 kk6 kk7 m0 m1 m2 m3 m4 m5 m6 m7 sq sx t0 t1 t2 t3 t4 t5 t6 t7 b0 b1 b2 b3 dv0 dv1 dv2 dv3 ov sb sr sc : ℤ)
    (hq0 : 0 ≤ q0 ∧ q0 ≤ 255)
    (hq1 : 0 ≤ q1 ∧ q1 ≤ 255)
    (hq2 : 0 ≤ q2 ∧ q2 ≤ 255)
    (hq3 : 0 ≤ q3 ∧ q3 ≤ 255)
    (hr0 : 0 ≤ r0 ∧ r0 ≤ 255)
    (hr1 : 0 ≤ r1 ∧ r1 ≤ 255)
    (hr2 : 0 ≤ r2 ∧ r2 ≤ 255)
    (hr3 : 0 ≤ r3 ∧ r3 ≤ 255)
    (hkk0 : 0 ≤ kk0 ∧ kk0 ≤ 65535)
    (hkk1 : 0 ≤ kk1 ∧ kk1 ≤ 65535)
    (hkk2 : 0 ≤ kk2 ∧ kk2 ≤ 65535)
    (hkk3 : 0 ≤ kk3 ∧ kk3 ≤ 65535)
    (hkk4 : 0 ≤ kk4 ∧ kk4 ≤ 65535)
    (hkk5 : 0 ≤ kk5 ∧ kk5 ≤ 65535)
    (hkk6 : 0 ≤ kk6 ∧ kk6 ≤ 65535)
    (hkk7 : 0 ≤ kk7 ∧ kk7 ≤ 65535)
    (hm0 : 0 ≤ m0 ∧ m0 ≤ 255)
    (hm1 : 0 ≤ m1 ∧ m1 ≤ 255)
    (hm2 : 0 ≤ m2 ∧ m2 ≤ 255)
    (hm3 : 0 ≤ m3 ∧ m3 ≤ 255)
    (hm4 : 0 ≤ m4 ∧ m4 ≤ 255)
    (hm5 : 0 ≤ m5 ∧ m5 ≤ 255)
    (hm6 : 0 ≤ m6 ∧ m6 ≤ 255)
    (hm7 : 0 ≤ m7 ∧ m7 ≤ 255)
    (hsq : 0 ≤ sq ∧ sq ≤ 1)
    (hsx : 0 ≤ sx ∧ sx ≤ 1)
    (ht0 : 0 ≤ t0 ∧ t0 ≤ 1)
    (ht1 : 0 ≤ t1 ∧ t1 ≤ 1)
    (ht2 : 0 ≤ t2 ∧ t2 ≤ 1)
    (ht3 : 0 ≤ t3 ∧ t3 ≤ 1)
    (ht4 : 0 ≤ t4 ∧ t4 ≤ 1)
    (ht5 : 0 ≤ t5 ∧ t5 ≤ 1)
    (ht6 : 0 ≤ t6 ∧ t6 ≤ 1)
    (ht7 : 0 ≤ t7 ∧ t7 ≤ 1)
    (hb0 : 0 ≤ b0 ∧ b0 ≤ 255)
    (hb1 : 0 ≤ b1 ∧ b1 ≤ 255)
    (hb2 : 0 ≤ b2 ∧ b2 ≤ 255)
    (hb3 : 0 ≤ b3 ∧ b3 ≤ 255)
    (hdv0 : 0 ≤ dv0 ∧ dv0 ≤ 255)
    (hdv1 : 0 ≤ dv1 ∧ dv1 ≤ 255)
    (hdv2 : 0 ≤ dv2 ∧ dv2 ≤ 255)
    (hdv3 : 0 ≤ dv3 ∧ dv3 ≤ 255)
    (hov : 0 ≤ ov ∧ ov ≤ 1)
    (hsb : 0 ≤ sb ∧ sb ≤ 1)
    (hsr : 0 ≤ sr ∧ sr ≤ 1)
    (hsc : 0 ≤ sc ∧ sc ≤ 1)
    (e0 : ((0 : F) - (sb : F)) = 0)
    (e1 : ((0 : F) - (sr : F)) = 0)
    (e3 : (sq : F) = 0)
    (e4 : (sx : F) = 0)
    (e55 : (ov : F) = 0)
    (e7 : (((q0 : F) * (dv0 : F)) - (((kk0 : F) * (256 : F)) + (m0 : F))) = 0)
    (e8 : ((((m1 : F) - (kk0 : F)) + ((kk1 : F) * (256 : F))) - (((q0 : F) * (dv1 : F)) + ((q1 : F) * (dv0 : F)))) = 0)
    (e9 : ((((m2 : F) - (kk1 : F)) + ((kk2 : F) * (256 : F))) - ((((q0 : F) * (dv2 : F)) + ((q1 : F) * (dv1 : F))) + ((q2 : F) * (dv0 : F)))) = 0)
    (e10 : ((((m3 : F) - (kk2 : F)) + ((kk3 : F) * (256 : F))) - (((((q0 : F) * (dv3 : F)) + ((q1 : F) * (dv2 : F))) + ((q2 : F) * (dv1 : F))) + ((q3 : F) * (dv0 : F)))) = 0)
    (e11 : ((((m4 : F) - (kk3 : F)) + ((kk4 : F) * (256 : F))) - ((((((q0 : F) * ((sx : F) * (255 : F))) + ((q1 : F) * (dv3 : F))) + ((q2 : F) * (dv2 : F))) + ((q3 : F) * (dv1 : F))) + (((sq : F) * (255 : F)) * (dv0 : F)))) = 0)
    (e12 : ((((m5 : F) - (kk4 : F)) + ((kk5 : F) * (256 : F))) - (((((((q0 : F) * ((sx : F) * (255 : F))) + ((q1 : F) * ((sx : F) * (255 : F)))) + ((q2 : F) * (dv3 : F))) + ((q3 : F) * (dv2 : F))) + (((sq : F) * (255 : F)) * (dv1 : F))) + (((sq : F) * (255 : F)) * (dv0 : F)))) = 0)
    (e13 : ((((m6 : F) - (kk5 : F)) + ((kk6 : F) * (256 : F))) - ((((((((q0 : F) * ((sx : F) * (255 : F))) + ((q1 : F) * ((sx : F) * (255 : F)))) + ((q2 : F) * ((sx : F) * (255 : F)))) + ((q3 : F) * (dv3 : F))) + (((sq : F) * (255 : F)) * (dv2 : F))) + (((sq : F) * (255 : F)) * (dv1 : F))) + (((sq : F) * (255 : F)) * (dv0 : F)))) = 0)
    (e14 : ((((m7 : F) - (kk6 : F)) + ((kk7 : F) * (256 : F))) - (((((((((q0 : F) * ((sx : F) * (255 : F))) + ((q1 : F) * ((sx : F) * (255 : F)))) + ((q2 : F) * ((sx : F) * (255 : F)))) + ((q3 : F) * ((sx : F) * (255 : F)))) + (((sq : F) * (255 : F)) * (dv3 : F))) + (((sq : F) * (255 : F)) * (dv2 : F))) + (((sq : F) * (255 : F)) * (dv1 : F))) + (((sq : F) * (255 : F)) * (dv0 : F)))) = 0)
    (e56 : ((b0 : F) - (((m0 : F) + (r0 : F)) - ((t0 : F) * (256 : F)))) = 0)
    (e57 : ((b1 : F) - ((((m1 : F) + (r1 : F)) - ((t1 : F) * (256 : F))) + (t0 : F))) = 0)
    (e58 : ((b2 : F) - ((((m2 : F) + (r2 : F)) - ((t2 : F) * (256 : F))) + (t1 : F))) = 0)
    (e59 : ((b3 : F) - ((((m3 : F) + (r3 : F)) - ((t3 : F) * (256 : F))) + (t2 : F))) = 0)
    (e60 : (((1 : F) - (ov : F)) * ((sb : F) * (((((m4 : F) + ((sr : F) * (255 : F))) - ((t4 : F) * (256 : F))) + (t3 : F)) - (255 : F)))) = 0)
    (e61 : (((1 : F) - (ov : F)) * (((1 : F) - (sb : F)) * ((((m4 : F) + ((sr : F) * (255 : F))) - ((t4 : F) * (256 : F))) + (t3 : F)))) = 0)
    (e62 : ((ov : F) * ((((m4 : F) + ((sr : F) * (255 : F))) - ((t4 : F) * (256 : F))) + (t3 : F))) = 0)
    (e63 : (((1 : F) - (ov : F)) * ((sb : F) * (((((m5 : F) + ((sr : F) * (255 : F))) - ((t5 : F) * (256 : F))) + (t4 : F)) - (255 : F)))) = 0)
    (e64 : (((1 : F) - (ov : F)) * (((1 : F) - (sb : F)) * ((((m5 : F) + ((sr : F) * (255 : F))) - ((t5 : F) * (256 : F))) + (t4 : F)))) = 0)
    (e65 : ((ov : F) * ((((m5 : F) + ((sr : F) * (255 : F))) - ((t5 : F) * (256 : F))) + (t4 : F))) = 0)
    (e66 : (((1 : F) - (ov : F)) * ((sb : F) * (((((m6 : F) + ((sr : F) * (255 : F))) - ((t6 : F) * (256 : F))) + (t5 : F)) - (255 : F)))) = 0)
    (e67 : (((1 : F) - (ov : F)) * (((1 : F) - (sb : F)) * ((((m6 : F) + ((sr : F) * (255 : F))) - ((t6 : F) * (256 : F))) + (t5 : F)))) = 0)
    (e68 : ((ov : F) * ((((m6 : F) + ((sr : F) * (255 : F))) - ((t6 : F) * (256 : F))) + (t5 : F))) = 0)
    (e69 : (((1 : F) - (ov : F)) * ((sb : F) * (((((m7 : F) + ((sr : F) * (255 : F))) - ((t7 : F) * (256 : F))) + (t6 : F)) - (255 : F)))) = 0)
    (e70 : (((1 : F) - (ov : F)) * (((1 : F) - (sb : F)) * ((((m7 : F) + ((sr : F) * (255 : F))) - ((t7 : F) * (256 : F))) + (t6 : F)))) = 0)
    (e71 : ((ov : F) * ((((m7 : F) + ((sr : F) * (255 : F))) - ((t7 : F) * (256 : F))) + (t6 : F))) = 0)
    : w4 q0 q1 q2 q3 * w4 dv0 dv1 dv2 dv3 + w4 r0 r1 r2 r3 = w4 b0 b1 b2 b3 := by
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
  have hz : sq = 0 ∧ sx = 0 ∧ sr = 0 ∧ sb = 0 ∧ ov = 0 := by
    clear hP hS1 hS2 hH
    clear * - e0 e1 e3 e4 e55 hsq hsx hsr hsb hov
    refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> (divrem_lift; omega)
  obtain ⟨rfl, rfl, rfl, rfl, rfl⟩ := hz
  simp only [mul_zero, sub_zero, zero_mul] at hH
  refine congruence_eq_unsigned hH ?_ ?_ ?_ ?_ <;>
    (clear hH hP hS1 hS2; simp only [w4]; omega)



theorem rem_bound
    (r0 r1 r2 r3 dv0 dv1 dv2 dv3 sr sc : ℤ)
    (x10 x11 x12 x13 x14 x15 x16 x17 x18 x19 x20 x21 x42 x43 x44 x45 x46 x47 x48 x49 x50 x51 x52 x53 x54 x55 x56 x57 x58 x59 x60 x61 x62 x63 x64 x65 x66 x85 x149 x562 x563 : F)
    (hr0 : 0 ≤ r0 ∧ r0 ≤ 255)
    (hr1 : 0 ≤ r1 ∧ r1 ≤ 255)
    (hr2 : 0 ≤ r2 ∧ r2 ≤ 255)
    (hr3 : 0 ≤ r3 ∧ r3 ≤ 255)
    (hdv0 : 0 ≤ dv0 ∧ dv0 ≤ 255)
    (hdv1 : 0 ≤ dv1 ∧ dv1 ≤ 255)
    (hdv2 : 0 ≤ dv2 ∧ dv2 ≤ 255)
    (hdv3 : 0 ≤ dv3 ∧ dv3 ≤ 255)
    (hsr : 0 ≤ sr ∧ sr ≤ 1)
    (hsc : 0 ≤ sc ∧ sc ≤ 1)
    (e1 : ((0 : F) - (sr : F)) = 0)
    (e2 : ((0 : F) - (sc : F)) = 0)
    (e92 : x85 = 0)
    (e93 : (((sc : F) - (1 : F)) * ((dv0 : F) - x14)) = 0)
    (e94 : (((sr : F) - (1 : F)) * ((r0 : F) - x10)) = 0)
    (e95 : (((sc : F) - (1 : F)) * ((dv1 : F) - x15)) = 0)
    (e96 : (((sr : F) - (1 : F)) * ((r1 : F) - x11)) = 0)
    (e97 : (((sc : F) - (1 : F)) * ((dv2 : F) - x16)) = 0)
    (e98 : (((sr : F) - (1 : F)) * ((r2 : F) - x12)) = 0)
    (e99 : (((sc : F) - (1 : F)) * ((dv3 : F) - x17)) = 0)
    (e100 : (((sr : F) - (1 : F)) * ((r3 : F) - x13)) = 0)
    (e101 : ((sc : F) * (((((dv0 : F) + x14) - x42) * ((256 : F)⁻¹)) * (((((dv0 : F) + x14) - x42) * ((256 : F)⁻¹)) - (1 : F)))) = 0)
    (e102 : ((sc : F) * ((((((dv1 : F) + x15) - x43) + ((((dv0 : F) + x14) - x42) * ((256 : F)⁻¹))) * ((256 : F)⁻¹)) * ((((((dv1 : F) + x15) - x43) + ((((dv0 : F) + x14) - x42) * ((256 : F)⁻¹))) * ((256 : F)⁻¹)) - (1 : F)))) = 0)
    (e103 : ((sc : F) * ((((((dv2 : F) + x16) - x44) + (((((dv1 : F) + x15) - x43) + ((((dv0 : F) + x14) - x42) * ((256 : F)⁻¹))) * ((256 : F)⁻¹))) * ((256 : F)⁻¹)) * ((((((dv2 : F) + x16) - x44) + (((((dv1 : F) + x15) - x43) + ((((dv0 : F) + x14) - x42) * ((256 : F)⁻¹))) * ((256 : F)⁻¹))) * ((256 : F)⁻¹)) - (1 : F)))) = 0)
    (e104 : ((sc : F) * ((((((dv3 : F) + x17) - x45) + (((((dv2 : F) + x16) - x44) + (((((dv1 : F) + x15) - x43) + ((((dv0 : F) + x14) - x42) * ((256 : F)⁻¹))) * ((256 : F)⁻¹))) * ((256 : F)⁻¹))) * ((256 : F)⁻¹)) * ((((((dv3 : F) + x17) - x45) + (((((dv2 : F) + x16) - x44) + (((((dv1 : F) + x15) - x43) + ((((dv0 : F) + x14) - x42) * ((256 : F)⁻¹))) * ((256 : F)⁻¹))) * ((256 : F)⁻¹))) * ((256 : F)⁻¹)) - (1 : F)))) = 0)
    (e105 : ((sc : F) * ((sc : F) * ((sc : F) - (1 : F)))) = 0)
    (e106 : ((sc : F) * x42) = 0)
    (e107 : ((sc : F) * x43) = 0)
    (e108 : ((sc : F) * x44) = 0)
    (e109 : ((sc : F) * x45) = 0)
    (e110 : ((sr : F) * (((((r0 : F) + x10) - x46) * ((256 : F)⁻¹)) * (((((r0 : F) + x10) - x46) * ((256 : F)⁻¹)) - (1 : F)))) = 0)
    (e111 : ((sr : F) * ((((((r1 : F) + x11) - x47) + ((((r0 : F) + x10) - x46) * ((256 : F)⁻¹))) * ((256 : F)⁻¹)) * ((((((r1 : F) + x11) - x47) + ((((r0 : F) + x10) - x46) * ((256 : F)⁻¹))) * ((256 : F)⁻¹)) - (1 : F)))) = 0)
    (e112 : ((sr : F) * ((((((r2 : F) + x12) - x48) + (((((r1 : F) + x11) - x47) + ((((r0 : F) + x10) - x46) * ((256 : F)⁻¹))) * ((256 : F)⁻¹))) * ((256 : F)⁻¹)) * ((((((r2 : F) + x12) - x48) + (((((r1 : F) + x11) - x47) + ((((r0 : F) + x10) - x46) * ((256 : F)⁻¹))) * ((256 : F)⁻¹))) * ((256 : F)⁻¹)) - (1 : F)))) = 0)
    (e113 : ((sr : F) * ((((((r3 : F) + x13) - x49) + (((((r2 : F) + x12) - x48) + (((((r1 : F) + x11) - x47) + ((((r0 : F) + x10) - x46) * ((256 : F)⁻¹))) * ((256 : F)⁻¹))) * ((256 : F)⁻¹))) * ((256 : F)⁻¹)) * ((((((r3 : F) + x13) - x49) + (((((r2 : F) + x12) - x48) + (((((r1 : F) + x11) - x47) + ((((r0 : F) + x10) - x46) * ((256 : F)⁻¹))) * ((256 : F)⁻¹))) * ((256 : F)⁻¹))) * ((256 : F)⁻¹)) - (1 : F)))) = 0)
    (e114 : ((sr : F) * ((sr : F) * ((sr : F) - (1 : F)))) = 0)
    (e115 : ((sr : F) * x46) = 0)
    (e116 : ((sr : F) * x47) = 0)
    (e117 : ((sr : F) * x48) = 0)
    (e118 : ((sr : F) * x49) = 0)
    (e119 : (x18 - (x85 + (((1 : F) - x85) * x14))) = 0)
    (e120 : (x19 - (((1 : F) - x85) * x15)) = 0)
    (e121 : (x20 - (((1 : F) - x85) * x16)) = 0)
    (e122 : (x21 - (((1 : F) - x85) * x17)) = 0)
    (e123 : (((1 : F) - x85) - x149) = 0)
    (e124 : x64 = 0)
    (e125 : x65 = 0)
    (e126 : (x61 - ((x13 - x50) * ((128 : F)⁻¹))) = 0)
    (e127 : (x62 - ((x21 - x51) * ((128 : F)⁻¹))) = 0)
    (e128 : (x63 * (x63 - (1 : F))) = 0)
    (e129 : (x63 * (x64 - x65)) = 0)
    (e130 : (x149 * ((x63 - (1 : F)) * ((x64 + x65) - (1 : F)))) = 0)
    (e131 : (x66 - ((x64 * ((1 : F) - x65)) + (x63 * x52))) = 0)
    (e132 : (x54 * (x54 - (1 : F))) = 0)
    (e133 : (x55 * (x55 - (1 : F))) = 0)
    (e134 : (x56 * (x56 - (1 : F))) = 0)
    (e135 : (x57 * (x57 - (1 : F))) = 0)
    (e136 : ((((x54 + x55) + x56) + x57) * ((((x54 + x55) + x56) + x57) - (1 : F))) = 0)
    (e137 : (x149 * (((1 : F) - x53) - (((x54 + x55) + x56) + x57))) = 0)
    (e138 : (x53 * (x53 - (1 : F))) = 0)
    (e139 : ((x57 - (1 : F)) * ((x13 * x149) - (x21 * x149))) = 0)
    (e140 : (x53 * x57) = 0)
    (e141 : (((x57 + x56) - (1 : F)) * (x12 - x20)) = 0)
    (e142 : (x53 * (x57 + x56)) = 0)
    (e143 : ((((x57 + x56) + x55) - (1 : F)) * (x11 - x19)) = 0)
    (e144 : (x53 * ((x57 + x56) + x55)) = 0)
    (e145 : (((((x57 + x56) + x55) + x54) - (1 : F)) * (x10 - x18)) = 0)
    (e146 : (x53 * (((x57 + x56) + x55) + x54)) = 0)
    (e147 : (x59 - (((((x13 * x149) * x57) + (x12 * x56)) + (x11 * x55)) + (x10 * x54))) = 0)
    (e148 : (x60 - (((((x21 * x149) * x57) + (x20 * x56)) + (x19 * x55)) + (x18 * x54))) = 0)
    (e149 : ((x53 - (1 : F)) * ((x58 * (x59 - x60)) - x149)) = 0)
    (e150 : (x149 * (x66 - (1 : F))) = 0)
    (e208 : ((x14 * (sc : F))).val ≤ 255)
    (e209 : ((x15 * (sc : F))).val ≤ 255)
    (e210 : ((x16 * (sc : F))).val ≤ 255)
    (e211 : ((x17 * (sc : F))).val ≤ 255)
    (e212 : ((x42 * (sc : F))).val ≤ 255)
    (e213 : ((x43 * (sc : F))).val ≤ 255)
    (e214 : ((x44 * (sc : F))).val ≤ 255)
    (e215 : ((x45 * (sc : F))).val ≤ 255)
    (e220 : ((x10 * (sr : F))).val ≤ 255)
    (e221 : ((x11 * (sr : F))).val ≤ 255)
    (e222 : ((x12 * (sr : F))).val ≤ 255)
    (e223 : ((x13 * (sr : F))).val ≤ 255)
    (e224 : ((x46 * (sr : F))).val ≤ 255)
    (e225 : ((x47 * (sr : F))).val ≤ 255)
    (e226 : ((x48 * (sr : F))).val ≤ 255)
    (e227 : ((x49 * (sr : F))).val ≤ 255)
    (e228 : ((x13 * x149)).val ≤ 255)
    (e229 : ((x50 * x149)).val ≤ 255)
    (e230 : ((x50 * x149)).val < 128)
    (e231 : ((x149 * x562) * (x562 - (1 : F))) = 0)
    (e232 : (x149 * (x13 - ((x562 * (128 : F)) + x50))) = 0)
    (e233 : ((x21 * x149)).val ≤ 255)
    (e234 : ((x51 * x149)).val ≤ 255)
    (e235 : ((x51 * x149)).val < 128)
    (e236 : ((x149 * x563) * (x563 - (1 : F))) = 0)
    (e237 : (x149 * (x21 - ((x563 * (128 : F)) + x51))) = 0)
    (e238 : ((x59 * x149)).val ≤ 255)
    (e239 : ((x60 * x149)).val ≤ 255)
    (e240 : ((x149 * x52) * (x52 - (1 : F))) = 0)
    (e241 : (((x52 * x149) - (1 : F)) = 0 ↔ ((x59 * x149)).val < ((x60 * x149)).val))
    : (w4 r0 r1 r2 r3).natAbs < (w4 dv0 dv1 dv2 dv3).natAbs := by
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



/-- The row satisfies the division specification on its words. -/
theorem row_spec (w : W) (hw : constraints w) :
    ZirenDet.DivRem.Spec 0 (ZirenDet.DivRem.w4 ((w.v108.val : ℕ) : ℤ) ((w.v109.val : ℕ) : ℤ) ((w.v110.val : ℕ) : ℤ) ((w.v111.val : ℕ) : ℤ)) (ZirenDet.DivRem.w4 ((w.v114.val : ℕ) : ℤ) ((w.v115.val : ℕ) : ℤ) ((w.v116.val : ℕ) : ℤ) ((w.v117.val : ℕ) : ℤ))
      (ZirenDet.DivRem.w4 ((w.v2.val : ℕ) : ℤ) ((w.v3.val : ℕ) : ℤ) ((w.v4.val : ℕ) : ℤ) ((w.v5.val : ℕ) : ℤ)) (ZirenDet.DivRem.w4 ((w.v6.val : ℕ) : ℤ) ((w.v7.val : ℕ) : ℤ) ((w.v8.val : ℕ) : ℤ) ((w.v9.val : ℕ) : ℤ)) := by
  %OPEN_W%
  %OPEN_HW%
  obtain ⟨q0, hq0a, hq0b, rfl⟩ := ZirenDet.lift_le x2 c251
  have hq0 : 0 ≤ q0 ∧ q0 ≤ 255 := ⟨hq0a, by exact_mod_cast hq0b⟩
  obtain ⟨q1, hq1a, hq1b, rfl⟩ := ZirenDet.lift_le x3 c252
  have hq1 : 0 ≤ q1 ∧ q1 ≤ 255 := ⟨hq1a, by exact_mod_cast hq1b⟩
  obtain ⟨q2, hq2a, hq2b, rfl⟩ := ZirenDet.lift_le x4 c253
  have hq2 : 0 ≤ q2 ∧ q2 ≤ 255 := ⟨hq2a, by exact_mod_cast hq2b⟩
  obtain ⟨q3, hq3a, hq3b, rfl⟩ := ZirenDet.lift_le x5 c254
  have hq3 : 0 ≤ q3 ∧ q3 ≤ 255 := ⟨hq3a, by exact_mod_cast hq3b⟩
  obtain ⟨r0, hr0a, hr0b, rfl⟩ := ZirenDet.lift_le x6 c255
  have hr0 : 0 ≤ r0 ∧ r0 ≤ 255 := ⟨hr0a, by exact_mod_cast hr0b⟩
  obtain ⟨r1, hr1a, hr1b, rfl⟩ := ZirenDet.lift_le x7 c256
  have hr1 : 0 ≤ r1 ∧ r1 ≤ 255 := ⟨hr1a, by exact_mod_cast hr1b⟩
  obtain ⟨r2, hr2a, hr2b, rfl⟩ := ZirenDet.lift_le x8 c257
  have hr2 : 0 ≤ r2 ∧ r2 ≤ 255 := ⟨hr2a, by exact_mod_cast hr2b⟩
  obtain ⟨r3, hr3a, hr3b, rfl⟩ := ZirenDet.lift_le x9 c258
  have hr3 : 0 ≤ r3 ∧ r3 ≤ 255 := ⟨hr3a, by exact_mod_cast hr3b⟩
  obtain ⟨kk0, hkk0a, hkk0b, rfl⟩ := ZirenDet.lift_le x22 c188
  have hkk0 : 0 ≤ kk0 ∧ kk0 ≤ 65535 := ⟨hkk0a, by exact_mod_cast hkk0b⟩
  obtain ⟨kk1, hkk1a, hkk1b, rfl⟩ := ZirenDet.lift_le x23 c189
  have hkk1 : 0 ≤ kk1 ∧ kk1 ≤ 65535 := ⟨hkk1a, by exact_mod_cast hkk1b⟩
  obtain ⟨kk2, hkk2a, hkk2b, rfl⟩ := ZirenDet.lift_le x24 c190
  have hkk2 : 0 ≤ kk2 ∧ kk2 ≤ 65535 := ⟨hkk2a, by exact_mod_cast hkk2b⟩
  obtain ⟨kk3, hkk3a, hkk3b, rfl⟩ := ZirenDet.lift_le x25 c191
  have hkk3 : 0 ≤ kk3 ∧ kk3 ≤ 65535 := ⟨hkk3a, by exact_mod_cast hkk3b⟩
  obtain ⟨kk4, hkk4a, hkk4b, rfl⟩ := ZirenDet.lift_le x26 c192
  have hkk4 : 0 ≤ kk4 ∧ kk4 ≤ 65535 := ⟨hkk4a, by exact_mod_cast hkk4b⟩
  obtain ⟨kk5, hkk5a, hkk5b, rfl⟩ := ZirenDet.lift_le x27 c193
  have hkk5 : 0 ≤ kk5 ∧ kk5 ≤ 65535 := ⟨hkk5a, by exact_mod_cast hkk5b⟩
  obtain ⟨kk6, hkk6a, hkk6b, rfl⟩ := ZirenDet.lift_le x28 c194
  have hkk6 : 0 ≤ kk6 ∧ kk6 ≤ 65535 := ⟨hkk6a, by exact_mod_cast hkk6b⟩
  obtain ⟨kk7, hkk7a, hkk7b, rfl⟩ := ZirenDet.lift_le x29 c195
  have hkk7 : 0 ≤ kk7 ∧ kk7 ≤ 65535 := ⟨hkk7a, by exact_mod_cast hkk7b⟩
  obtain ⟨m0, hm0a, hm0b, rfl⟩ := ZirenDet.lift_le x30 c196
  have hm0 : 0 ≤ m0 ∧ m0 ≤ 255 := ⟨hm0a, by exact_mod_cast hm0b⟩
  obtain ⟨m1, hm1a, hm1b, rfl⟩ := ZirenDet.lift_le x31 c197
  have hm1 : 0 ≤ m1 ∧ m1 ≤ 255 := ⟨hm1a, by exact_mod_cast hm1b⟩
  obtain ⟨m2, hm2a, hm2b, rfl⟩ := ZirenDet.lift_le x32 c198
  have hm2 : 0 ≤ m2 ∧ m2 ≤ 255 := ⟨hm2a, by exact_mod_cast hm2b⟩
  obtain ⟨m3, hm3a, hm3b, rfl⟩ := ZirenDet.lift_le x33 c199
  have hm3 : 0 ≤ m3 ∧ m3 ≤ 255 := ⟨hm3a, by exact_mod_cast hm3b⟩
  obtain ⟨m4, hm4a, hm4b, rfl⟩ := ZirenDet.lift_le x34 c200
  have hm4 : 0 ≤ m4 ∧ m4 ≤ 255 := ⟨hm4a, by exact_mod_cast hm4b⟩
  obtain ⟨m5, hm5a, hm5b, rfl⟩ := ZirenDet.lift_le x35 c201
  have hm5 : 0 ≤ m5 ∧ m5 ≤ 255 := ⟨hm5a, by exact_mod_cast hm5b⟩
  obtain ⟨m6, hm6a, hm6b, rfl⟩ := ZirenDet.lift_le x36 c202
  have hm6 : 0 ≤ m6 ∧ m6 ≤ 255 := ⟨hm6a, by exact_mod_cast hm6b⟩
  obtain ⟨m7, hm7a, hm7b, rfl⟩ := ZirenDet.lift_le x37 c203
  have hm7 : 0 ≤ m7 ∧ m7 ≤ 255 := ⟨hm7a, by exact_mod_cast hm7b⟩
  obtain ⟨sq, hsqa, hsqb, rfl⟩ := ZirenDet.lift_le x40 (ZirenDet.bit_val_le c17)
  have hsq : 0 ≤ sq ∧ sq ≤ 1 := ⟨hsqa, by exact_mod_cast hsqb⟩
  obtain ⟨sx, hsxa, hsxb, rfl⟩ := ZirenDet.lift_le x41 (ZirenDet.bit_val_le c18)
  have hsx : 0 ≤ sx ∧ sx ≤ 1 := ⟨hsxa, by exact_mod_cast hsxb⟩
  obtain ⟨t0, ht0a, ht0b, rfl⟩ := ZirenDet.lift_le x67 (ZirenDet.bit_val_le c151)
  have ht0 : 0 ≤ t0 ∧ t0 ≤ 1 := ⟨ht0a, by exact_mod_cast ht0b⟩
  obtain ⟨t1, ht1a, ht1b, rfl⟩ := ZirenDet.lift_le x68 (ZirenDet.bit_val_le c152)
  have ht1 : 0 ≤ t1 ∧ t1 ≤ 1 := ⟨ht1a, by exact_mod_cast ht1b⟩
  obtain ⟨t2, ht2a, ht2b, rfl⟩ := ZirenDet.lift_le x69 (ZirenDet.bit_val_le c153)
  have ht2 : 0 ≤ t2 ∧ t2 ≤ 1 := ⟨ht2a, by exact_mod_cast ht2b⟩
  obtain ⟨t3, ht3a, ht3b, rfl⟩ := ZirenDet.lift_le x70 (ZirenDet.bit_val_le c154)
  have ht3 : 0 ≤ t3 ∧ t3 ≤ 1 := ⟨ht3a, by exact_mod_cast ht3b⟩
  obtain ⟨t4, ht4a, ht4b, rfl⟩ := ZirenDet.lift_le x71 (ZirenDet.bit_val_le c155)
  have ht4 : 0 ≤ t4 ∧ t4 ≤ 1 := ⟨ht4a, by exact_mod_cast ht4b⟩
  obtain ⟨t5, ht5a, ht5b, rfl⟩ := ZirenDet.lift_le x72 (ZirenDet.bit_val_le c156)
  have ht5 : 0 ≤ t5 ∧ t5 ≤ 1 := ⟨ht5a, by exact_mod_cast ht5b⟩
  obtain ⟨t6, ht6a, ht6b, rfl⟩ := ZirenDet.lift_le x73 (ZirenDet.bit_val_le c157)
  have ht6 : 0 ≤ t6 ∧ t6 ≤ 1 := ⟨ht6a, by exact_mod_cast ht6b⟩
  obtain ⟨t7, ht7a, ht7b, rfl⟩ := ZirenDet.lift_le x74 (ZirenDet.bit_val_le c158)
  have ht7 : 0 ≤ t7 ∧ t7 ≤ 1 := ⟨ht7a, by exact_mod_cast ht7b⟩
  obtain ⟨b0, hb0a, hb0b, rfl⟩ := ZirenDet.lift_le x108 c264
  have hb0 : 0 ≤ b0 ∧ b0 ≤ 255 := ⟨hb0a, by exact_mod_cast hb0b⟩
  obtain ⟨b1, hb1a, hb1b, rfl⟩ := ZirenDet.lift_le x109 c265
  have hb1 : 0 ≤ b1 ∧ b1 ≤ 255 := ⟨hb1a, by exact_mod_cast hb1b⟩
  obtain ⟨b2, hb2a, hb2b, rfl⟩ := ZirenDet.lift_le x110 c266
  have hb2 : 0 ≤ b2 ∧ b2 ≤ 255 := ⟨hb2a, by exact_mod_cast hb2b⟩
  obtain ⟨b3, hb3a, hb3b, rfl⟩ := ZirenDet.lift_le x111 c267
  have hb3 : 0 ≤ b3 ∧ b3 ≤ 255 := ⟨hb3a, by exact_mod_cast hb3b⟩
  obtain ⟨dv0, hdv0a, hdv0b, rfl⟩ := ZirenDet.lift_le x114 c270
  have hdv0 : 0 ≤ dv0 ∧ dv0 ≤ 255 := ⟨hdv0a, by exact_mod_cast hdv0b⟩
  obtain ⟨dv1, hdv1a, hdv1b, rfl⟩ := ZirenDet.lift_le x115 c271
  have hdv1 : 0 ≤ dv1 ∧ dv1 ≤ 255 := ⟨hdv1a, by exact_mod_cast hdv1b⟩
  obtain ⟨dv2, hdv2a, hdv2b, rfl⟩ := ZirenDet.lift_le x116 c272
  have hdv2 : 0 ≤ dv2 ∧ dv2 ≤ 255 := ⟨hdv2a, by exact_mod_cast hdv2b⟩
  obtain ⟨dv3, hdv3a, hdv3b, rfl⟩ := ZirenDet.lift_le x117 c273
  have hdv3 : 0 ≤ dv3 ∧ dv3 ≤ 255 := ⟨hdv3a, by exact_mod_cast hdv3b⟩
  obtain ⟨ov, hova, hovb, rfl⟩ := ZirenDet.lift_le x120 (ZirenDet.bit_val_le c159)
  have hov : 0 ≤ ov ∧ ov ≤ 1 := ⟨hova, by exact_mod_cast hovb⟩
  obtain ⟨sb, hsba, hsbb, rfl⟩ := ZirenDet.lift_le x146 (ZirenDet.bit_val_le c163)
  have hsb : 0 ≤ sb ∧ sb ≤ 1 := ⟨hsba, by exact_mod_cast hsbb⟩
  obtain ⟨sr, hsra, hsrb, rfl⟩ := ZirenDet.lift_le x147 (ZirenDet.bit_val_le c164)
  have hsr : 0 ≤ sr ∧ sr ≤ 1 := ⟨hsra, by exact_mod_cast hsrb⟩
  obtain ⟨sc, hsca, hscb, rfl⟩ := ZirenDet.lift_le x148 (ZirenDet.bit_val_le c165)
  have hsc : 0 ≤ sc ∧ sc ≤ 1 := ⟨hsca, by exact_mod_cast hscb⟩
  have hq := quotient_eq q0 q1 q2 q3 r0 r1 r2 r3 kk0 kk1 kk2 kk3 kk4 kk5 kk6 kk7 m0 m1 m2 m3 m4 m5 m6 m7 sq sx t0 t1 t2 t3 t4 t5 t6 t7 b0 b1 b2 b3 dv0 dv1 dv2 dv3 ov sb sr sc hq0 hq1 hq2 hq3 hr0 hr1 hr2 hr3 hkk0 hkk1 hkk2 hkk3 hkk4 hkk5 hkk6 hkk7 hm0 hm1 hm2 hm3 hm4 hm5 hm6 hm7 hsq hsx ht0 ht1 ht2 ht3 ht4 ht5 ht6 ht7 hb0 hb1 hb2 hb3 hdv0 hdv1 hdv2 hdv3 hov hsb hsr hsc c0 c1 c3 c4 c55 c7 c8 c9 c10 c11 c12 c13 c14 c56 c57 c58 c59 c60 c61 c62 c63 c64 c65 c66 c67 c68 c69 c70 c71
  have hr := rem_bound r0 r1 r2 r3 dv0 dv1 dv2 dv3 sr sc x10 x11 x12 x13 x14 x15 x16 x17 x18 x19 x20 x21 x42 x43 x44 x45 x46 x47 x48 x49 x50 x51 x52 x53 x54 x55 x56 x57 x58 x59 x60 x61 x62 x63 x64 x65 x66 x85 x149 x572 x573 hr0 hr1 hr2 hr3 hdv0 hdv1 hdv2 hdv3 hsr hsc c1 c2 c92 c93 c94 c95 c96 c97 c98 c99 c100 c101 c102 c103 c104 c105 c106 c107 c108 c109 c110 c111 c112 c113 c114 c115 c116 c117 c118 c119 c120 c121 c122 c123 c124 c125 c126 c127 c128 c129 c130 c131 c132 c133 c134 c135 c136 c137 c138 c139 c140 c141 c142 c143 c144 c145 c146 c147 c148 c149 c150 c208 c209 c210 c211 c212 c213 c214 c215 c220 c221 c222 c223 c224 c225 c226 c227 c228 c229 c230 c231 c232 c233 c234 c235 c236 c237 c238 c239 c240 c241
  have vb0 : ((ZMod.val (((b0 : ℤ) : F)) : ℕ) : ℤ) = b0 := by
    rw [ZirenDet.val_cast]; omega
  have vb1 : ((ZMod.val (((b1 : ℤ) : F)) : ℕ) : ℤ) = b1 := by
    rw [ZirenDet.val_cast]; omega
  have vb2 : ((ZMod.val (((b2 : ℤ) : F)) : ℕ) : ℤ) = b2 := by
    rw [ZirenDet.val_cast]; omega
  have vb3 : ((ZMod.val (((b3 : ℤ) : F)) : ℕ) : ℤ) = b3 := by
    rw [ZirenDet.val_cast]; omega
  have vdv0 : ((ZMod.val (((dv0 : ℤ) : F)) : ℕ) : ℤ) = dv0 := by
    rw [ZirenDet.val_cast]; omega
  have vdv1 : ((ZMod.val (((dv1 : ℤ) : F)) : ℕ) : ℤ) = dv1 := by
    rw [ZirenDet.val_cast]; omega
  have vdv2 : ((ZMod.val (((dv2 : ℤ) : F)) : ℕ) : ℤ) = dv2 := by
    rw [ZirenDet.val_cast]; omega
  have vdv3 : ((ZMod.val (((dv3 : ℤ) : F)) : ℕ) : ℤ) = dv3 := by
    rw [ZirenDet.val_cast]; omega
  have vq0 : ((ZMod.val (((q0 : ℤ) : F)) : ℕ) : ℤ) = q0 := by
    rw [ZirenDet.val_cast]; omega
  have vq1 : ((ZMod.val (((q1 : ℤ) : F)) : ℕ) : ℤ) = q1 := by
    rw [ZirenDet.val_cast]; omega
  have vq2 : ((ZMod.val (((q2 : ℤ) : F)) : ℕ) : ℤ) = q2 := by
    rw [ZirenDet.val_cast]; omega
  have vq3 : ((ZMod.val (((q3 : ℤ) : F)) : ℕ) : ℤ) = q3 := by
    rw [ZirenDet.val_cast]; omega
  have vr0 : ((ZMod.val (((r0 : ℤ) : F)) : ℕ) : ℤ) = r0 := by
    rw [ZirenDet.val_cast]; omega
  have vr1 : ((ZMod.val (((r1 : ℤ) : F)) : ℕ) : ℤ) = r1 := by
    rw [ZirenDet.val_cast]; omega
  have vr2 : ((ZMod.val (((r2 : ℤ) : F)) : ℕ) : ℤ) = r2 := by
    rw [ZirenDet.val_cast]; omega
  have vr3 : ((ZMod.val (((r3 : ℤ) : F)) : ℕ) : ℤ) = r3 := by
    rw [ZirenDet.val_cast]; omega
  simp only [vb0, vb1, vb2, vb3, vdv0, vdv1, vdv2, vdv3, vq0, vq1, vq2, vq3, vr0, vr1, vr2, vr3]
  exact ZirenDet.DivRem.spec_unsigned (ZirenDet.DivRem.w4_range hb0 hb1 hb2 hb3).1
    (ZirenDet.DivRem.w4_range hr0 hr1 hr2 hr3).1 hq hr

/-- The byte ranges of quotient and remainder. -/
theorem row_ranges (w : W) (hw : constraints w) :
    w.v2.val ≤ 255 ∧ w.v3.val ≤ 255 ∧ w.v4.val ≤ 255 ∧ w.v5.val ≤ 255 ∧ w.v6.val ≤ 255 ∧ w.v7.val ≤ 255 ∧ w.v8.val ≤ 255 ∧ w.v9.val ≤ 255 := by
  %OPEN_W%
  %OPEN_HW%
  exact ⟨c251, c252, c253, c254, c255, c256, c257, c258⟩

/-- Quotient and remainder are determined by the row's inputs. -/
theorem gadget_det (w w' : W) (hw : constraints w) (hw' : constraints w')
    (hin : inputs w = inputs w') :
    w.v2 = w'.v2 ∧ w.v3 = w'.v3 ∧ w.v4 = w'.v4 ∧ w.v5 = w'.v5 ∧ w.v6 = w'.v6 ∧ w.v7 = w'.v7 ∧ w.v8 = w'.v8 ∧ w.v9 = w'.v9 := by
  have h := row_spec w hw
  have h' := row_spec w' hw'
  obtain ⟨a2, a3, a4, a5, a6, a7, a8, a9⟩ := row_ranges w hw
  obtain ⟨a2', a3', a4', a5', a6', a7', a8', a9'⟩ := row_ranges w' hw'
  have i108 : w.v108 = w'.v108 := by
    have t := congrArg (·[6]?) hin
    simpa only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] using t
  have i109 : w.v109 = w'.v109 := by
    have t := congrArg (·[7]?) hin
    simpa only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] using t
  have i110 : w.v110 = w'.v110 := by
    have t := congrArg (·[8]?) hin
    simpa only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] using t
  have i111 : w.v111 = w'.v111 := by
    have t := congrArg (·[9]?) hin
    simpa only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] using t
  have i114 : w.v114 = w'.v114 := by
    have t := congrArg (·[10]?) hin
    simpa only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] using t
  have i115 : w.v115 = w'.v115 := by
    have t := congrArg (·[11]?) hin
    simpa only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] using t
  have i116 : w.v116 = w'.v116 := by
    have t := congrArg (·[12]?) hin
    simpa only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] using t
  have i117 : w.v117 = w'.v117 := by
    have t := congrArg (·[13]?) hin
    simpa only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] using t
  simp only [i108, i109, i110, i111, i114, i115, i116, i117] at h
  have rg : ∀ {x : F}, x.val ≤ 255 → 0 ≤ ((x.val : ℕ) : ℤ) ∧ ((x.val : ℕ) : ℤ) ≤ 255 :=
    fun hx => ⟨by positivity, by exact_mod_cast hx⟩
  obtain ⟨hQ, hR⟩ := ZirenDet.DivRem.spec_unique (sg := 0) (by decide)
    (ZirenDet.DivRem.w4_range (rg a2) (rg a3) (rg a4) (rg a5))
    (ZirenDet.DivRem.w4_range (rg a6) (rg a7) (rg a8) (rg a9))
    (ZirenDet.DivRem.w4_range (rg a2') (rg a3') (rg a4') (rg a5'))
    (ZirenDet.DivRem.w4_range (rg a6') (rg a7') (rg a8') (rg a9')) h h'
  obtain ⟨e2, e3, e4, e5⟩ := ZirenDet.DivRem.w4_inj (rg a2) (rg a3) (rg a4) (rg a5)
    (rg a2') (rg a3') (rg a4') (rg a5') hQ
  obtain ⟨e6, e7, e8, e9⟩ := ZirenDet.DivRem.w4_inj (rg a6) (rg a7) (rg a8) (rg a9)
    (rg a6') (rg a7') (rg a8') (rg a9') hR
  exact ⟨ZMod.val_injective _ (by exact_mod_cast e2), ZMod.val_injective _ (by exact_mod_cast e3), ZMod.val_injective _ (by exact_mod_cast e4), ZMod.val_injective _ (by exact_mod_cast e5), ZMod.val_injective _ (by exact_mod_cast e6), ZMod.val_injective _ (by exact_mod_cast e7), ZMod.val_injective _ (by exact_mod_cast e8), ZMod.val_injective _ (by exact_mod_cast e9)⟩

end DivRemGadget
