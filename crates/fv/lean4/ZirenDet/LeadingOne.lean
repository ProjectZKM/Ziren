import ZirenDet.Replay
open ZirenDet
set_option maxHeartbeats 0
set_option linter.unusedVariables false
set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false
set_option linter.unreachableTactic false

namespace ZirenDet.LeadingOne

theorem n2_ne : (2 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n3_ne : (3 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n4_ne : (4 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n5_ne : (5 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n6_ne : (6 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n7_ne : (7 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n8_ne : (8 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n9_ne : (9 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n10_ne : (10 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n11_ne : (11 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n12_ne : (12 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n13_ne : (13 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n14_ne : (14 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n15_ne : (15 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n16_ne : (16 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n17_ne : (17 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n18_ne : (18 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n19_ne : (19 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n20_ne : (20 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n21_ne : (21 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n22_ne : (22 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n23_ne : (23 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n24_ne : (24 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n25_ne : (25 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n26_ne : (26 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n27_ne : (27 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n28_ne : (28 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n29_ne : (29 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n30_ne : (30 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n31_ne : (31 : F) = 0 ↔ False := ⟨by decide, False.elim⟩
theorem n32_ne : (32 : F) = 0 ↔ False := ⟨by decide, False.elim⟩

theorem val0 : ZMod.val (0 : F) = 0 := by decide
theorem val1 : ZMod.val (1 : F) = 1 := by decide
theorem val2 : ZMod.val (2 : F) = 2 := by decide
theorem val3 : ZMod.val (3 : F) = 3 := by decide
theorem val4 : ZMod.val (4 : F) = 4 := by decide
theorem val5 : ZMod.val (5 : F) = 5 := by decide
theorem val6 : ZMod.val (6 : F) = 6 := by decide
theorem val7 : ZMod.val (7 : F) = 7 := by decide
theorem val8 : ZMod.val (8 : F) = 8 := by decide
theorem val9 : ZMod.val (9 : F) = 9 := by decide
theorem val10 : ZMod.val (10 : F) = 10 := by decide
theorem val11 : ZMod.val (11 : F) = 11 := by decide
theorem val12 : ZMod.val (12 : F) = 12 := by decide
theorem val13 : ZMod.val (13 : F) = 13 := by decide
theorem val14 : ZMod.val (14 : F) = 14 := by decide
theorem val15 : ZMod.val (15 : F) = 15 := by decide
theorem val16 : ZMod.val (16 : F) = 16 := by decide
theorem val17 : ZMod.val (17 : F) = 17 := by decide
theorem val18 : ZMod.val (18 : F) = 18 := by decide
theorem val19 : ZMod.val (19 : F) = 19 := by decide
theorem val20 : ZMod.val (20 : F) = 20 := by decide
theorem val21 : ZMod.val (21 : F) = 21 := by decide
theorem val22 : ZMod.val (22 : F) = 22 := by decide
theorem val23 : ZMod.val (23 : F) = 23 := by decide
theorem val24 : ZMod.val (24 : F) = 24 := by decide
theorem val25 : ZMod.val (25 : F) = 25 := by decide
theorem val26 : ZMod.val (26 : F) = 26 := by decide
theorem val27 : ZMod.val (27 : F) = 27 := by decide
theorem val28 : ZMod.val (28 : F) = 28 := by decide
theorem val29 : ZMod.val (29 : F) = 29 := by decide
theorem val30 : ZMod.val (30 : F) = 30 := by decide
theorem val31 : ZMod.val (31 : F) = 31 := by decide

/-- One byte of a right shift by `t < 8` bits, as the byte table gives it. -/
def Shr (t B O K : F) : Prop :=
  (t = 0 → (O - B = 0 ∧ K = 0)) ∧
  (t - 1 = 0 → (B - (O * 2 + K) = 0 ∧ K.val < 2)) ∧
  (t - 2 = 0 → (B - (O * 4 + K) = 0 ∧ K.val < 4)) ∧
  (t - 3 = 0 → (B - (O * 8 + K) = 0 ∧ K.val < 8)) ∧
  (t - 4 = 0 → (B - (O * 16 + K) = 0 ∧ K.val < 16)) ∧
  (t - 5 = 0 → (B - (O * 32 + K) = 0 ∧ K.val < 32)) ∧
  (t - 6 = 0 → (B - (O * 64 + K) = 0 ∧ K.val < 64)) ∧
  (t - 7 = 0 → (B - (O * 128 + K) = 0 ∧ K.val < 128))

/-- Normalizes a context in which the shift bits have been replaced by constants. -/
syntax "clz_norm" : tactic
macro_rules
  | `(tactic| clz_norm) =>
    `(tactic| (
        (try norm_num at *)
        (try simp only [n2_ne, n3_ne, n4_ne, n5_ne, n6_ne, n7_ne, n8_ne, n9_ne, n10_ne, n11_ne, n12_ne, n13_ne, n14_ne, n15_ne, n16_ne, n17_ne, n18_ne, n19_ne, n20_ne, n21_ne, n22_ne, n23_ne, n24_ne, n25_ne, n26_ne, n27_ne, n28_ne, n29_ne, n30_ne, n31_ne, n32_ne, false_imp_iff, true_imp_iff, imp_false, not_true_eq_false,
               forall_const, mul_eq_zero, or_false, false_or, sub_eq_zero, one_ne_zero] at *)))

/-- The non-zero branch of the leading-one gadget: a word shifted right by `31 - a` bits is
`1` exactly when its leading one is at position `31 - a`. -/
theorem shifted_one (d b0 b1 b2 b3 s0 s1 s2 s3 s4 s5 s6 s7 : F)
    (m0 m1 m2 m3 m4 m5 m6 m7 n0 n1 n2 n3 : F)
    (B0 B1 B2 B3 B4 O0 O1 O2 O3 O4 K0 K1 K2 K3 K4 R0 R1 R2 R3 : F)
    (hs : s0 + s1 * 2 + s2 * 4 + s3 * 8 + s4 * 16 + s5 * 32 + s6 * 64 + s7 * 128 - d = 0)
    (hd : d.val ≤ 31)
    (bs0 : s0 * (s0 - 1) = 0) (bs1 : s1 * (s1 - 1) = 0) (bs2 : s2 * (s2 - 1) = 0)
    (bs3 : s3 * (s3 - 1) = 0) (bs4 : s4 * (s4 - 1) = 0) (bs5 : s5 * (s5 - 1) = 0)
    (bs6 : s6 * (s6 - 1) = 0) (bs7 : s7 * (s7 - 1) = 0)
    (hm0 : m0 * (s0 + s1 * 2 + s2 * 4) = 0) (hm1 : m1 * (s0 + s1 * 2 + s2 * 4 - 1) = 0)
    (hm2 : m2 * (s0 + s1 * 2 + s2 * 4 - 2) = 0) (hm3 : m3 * (s0 + s1 * 2 + s2 * 4 - 3) = 0)
    (hm4 : m4 * (s0 + s1 * 2 + s2 * 4 - 4) = 0) (hm5 : m5 * (s0 + s1 * 2 + s2 * 4 - 5) = 0)
    (hm6 : m6 * (s0 + s1 * 2 + s2 * 4 - 6) = 0) (hm7 : m7 * (s0 + s1 * 2 + s2 * 4 - 7) = 0)
    (hm : m0 + m1 + m2 + m3 + m4 + m5 + m6 + m7 - 1 = 0)
    (hn0 : n0 * (s3 + s4 * 2) = 0) (hn1 : n1 * (s3 + s4 * 2 - 1) = 0)
    (hn2 : n2 * (s3 + s4 * 2 - 2) = 0) (hn3 : n3 * (s3 + s4 * 2 - 3) = 0)
    (hn : n0 + n1 + n2 + n3 - 1 = 0)
    (p00 : n0 * (B0 - b0) = 0) (p01 : n0 * (B1 - b1) = 0) (p02 : n0 * (B2 - b2) = 0)
    (p03 : n0 * (B3 - b3) = 0) (p04 : n0 * B4 = 0)
    (p10 : n1 * (B0 - b1) = 0) (p11 : n1 * (B1 - b2) = 0) (p12 : n1 * (B2 - b3) = 0)
    (p13 : n1 * B3 = 0) (p14 : n1 * B4 = 0)
    (p20 : n2 * (B0 - b2) = 0) (p21 : n2 * (B1 - b3) = 0) (p22 : n2 * B2 = 0)
    (p23 : n2 * B3 = 0) (p24 : n2 * B4 = 0)
    (p30 : n3 * (B0 - b3) = 0) (p31 : n3 * B1 = 0) (p32 : n3 * B2 = 0)
    (p33 : n3 * B3 = 0) (p34 : n3 * B4 = 0)
    (r0 : O0 + K1 * (m0 * 256 + m1 * 128 + m2 * 64 + m3 * 32 + m4 * 16 + m5 * 8 + m6 * 4 + m7 * 2) - R0 = 0)
    (r1 : O1 + K2 * (m0 * 256 + m1 * 128 + m2 * 64 + m3 * 32 + m4 * 16 + m5 * 8 + m6 * 4 + m7 * 2) - R1 = 0)
    (r2 : O2 + K3 * (m0 * 256 + m1 * 128 + m2 * 64 + m3 * 32 + m4 * 16 + m5 * 8 + m6 * 4 + m7 * 2) - R2 = 0)
    (r3 : O3 + K4 * (m0 * 256 + m1 * 128 + m2 * 64 + m3 * 32 + m4 * 16 + m5 * 8 + m6 * 4 + m7 * 2) - R3 = 0)
    (e0 : R0 - 1 = 0) (e1 : R1 = 0) (e2 : R2 = 0) (e3 : R3 = 0)
    (h0 : Shr (s0 + s1 * 2 + s2 * 4) B0 O0 K0) (h1 : Shr (s0 + s1 * 2 + s2 * 4) B1 O1 K1)
    (h2 : Shr (s0 + s1 * 2 + s2 * 4) B2 O2 K2) (h3 : Shr (s0 + s1 * 2 + s2 * 4) B3 O3 K3)
    (h4 : Shr (s0 + s1 * 2 + s2 * 4) B4 O4 K4)
    (vb0 : b0.val ≤ 255) (vb1 : b1.val ≤ 255) (vb2 : b2.val ≤ 255) (vb3 : b3.val ≤ 255)
    (vB0 : B0.val ≤ 255) (vB1 : B1.val ≤ 255) (vB2 : B2.val ≤ 255) (vB3 : B3.val ≤ 255) (vB4 : B4.val ≤ 255)
    (vO0 : O0.val ≤ 255) (vO1 : O1.val ≤ 255) (vO2 : O2.val ≤ 255) (vO3 : O3.val ≤ 255) (vO4 : O4.val ≤ 255)
    (vK0 : K0.val ≤ 255) (vK1 : K1.val ≤ 255) (vK2 : K2.val ≤ 255) (vK3 : K3.val ≤ 255) (vK4 : K4.val ≤ 255) :
    (d.val = 0 → 1 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 2) ∧
      (d.val = 1 → 2 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 4) ∧
      (d.val = 2 → 4 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 8) ∧
      (d.val = 3 → 8 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 16) ∧
      (d.val = 4 → 16 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 32) ∧
      (d.val = 5 → 32 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 64) ∧
      (d.val = 6 → 64 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 128) ∧
      (d.val = 7 → 128 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 256) ∧
      (d.val = 8 → 256 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 512) ∧
      (d.val = 9 → 512 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 1024) ∧
      (d.val = 10 → 1024 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 2048) ∧
      (d.val = 11 → 2048 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 4096) ∧
      (d.val = 12 → 4096 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 8192) ∧
      (d.val = 13 → 8192 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 16384) ∧
      (d.val = 14 → 16384 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 32768) ∧
      (d.val = 15 → 32768 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 65536) ∧
      (d.val = 16 → 65536 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 131072) ∧
      (d.val = 17 → 131072 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 262144) ∧
      (d.val = 18 → 262144 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 524288) ∧
      (d.val = 19 → 524288 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 1048576) ∧
      (d.val = 20 → 1048576 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 2097152) ∧
      (d.val = 21 → 2097152 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 4194304) ∧
      (d.val = 22 → 4194304 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 8388608) ∧
      (d.val = 23 → 8388608 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 16777216) ∧
      (d.val = 24 → 16777216 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 33554432) ∧
      (d.val = 25 → 33554432 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 67108864) ∧
      (d.val = 26 → 67108864 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 134217728) ∧
      (d.val = 27 → 134217728 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 268435456) ∧
      (d.val = 28 → 268435456 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 536870912) ∧
      (d.val = 29 → 536870912 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 1073741824) ∧
      (d.val = 30 → 1073741824 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 2147483648) ∧
      (d.val = 31 → 2147483648 ≤ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ∧ b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val < 4294967296) := by
  have hhi : s5 = 0 ∧ s6 = 0 ∧ s7 = 0 := by
    clear * - hs hd bs0 bs1 bs2 bs3 bs4 bs5 bs6 bs7
    picus_bits
    refine ⟨?_, ?_, ?_⟩ <;> picus_finish
  obtain ⟨z5, z6, z7⟩ := hhi
  subst z5 z6 z7
  clear bs5 bs6 bs7
  simp only [Shr] at h0 h1 h2 h3 h4
  obtain ⟨h00, h01, h02, h03, h04, h05, h06, h07⟩ := h0
  obtain ⟨h10, h11, h12, h13, h14, h15, h16, h17⟩ := h1
  obtain ⟨h20, h21, h22, h23, h24, h25, h26, h27⟩ := h2
  obtain ⟨h30, h31, h32, h33, h34, h35, h36, h37⟩ := h3
  obtain ⟨h40, h41, h42, h43, h44, h45, h46, h47⟩ := h4
  rcases bit_cases bs0 with e | e <;> subst e <;>
  rcases bit_cases bs1 with e | e <;> subst e <;>
  rcases bit_cases bs2 with e | e <;> subst e <;>
  rcases bit_cases bs3 with e | e <;> subst e <;>
  rcases bit_cases bs4 with e | e <;> subst e <;>
  clz_norm
  all_goals (
    (try subst_vars)
    clz_norm
    (try subst_vars)
    clz_norm
    (try simp only [val0, val1, val2, val3, val4, val5, val6, val7, val8, val9, val10, val11, val12, val13, val14, val15, val16, val17, val18, val19, val20, val21, val22, val23, val24, val25, val26, val27, val28, val29, val30, val31] at *)
    (try norm_num at *)
    (try casesm* _ ∧ _)
    clear vK0 vK1 vK2 vK3 vK4
    picus_prep
    (try simp only [ZirenDet.val_cast] at *)
    omega)

/-- The non-zero branch in the chip's own terms. -/
theorem nonzero_spec (a b0 b1 b2 b3 s0 s1 s2 s3 s4 s5 s6 s7 : F)
    (m0 m1 m2 m3 m4 m5 m6 m7 n0 n1 n2 n3 : F)
    (B0 B1 B2 B3 B4 O0 O1 O2 O3 O4 K0 K1 K2 K3 K4 R0 R1 R2 R3 : F)
    (hs : s0 + s1 * 2 + s2 * 4 + s3 * 8 + s4 * 16 + s5 * 32 + s6 * 64 + s7 * 128 - (31 - a) = 0)
    (ha : a.val < 33)
    (bs0 : s0 * (s0 - 1) = 0) (bs1 : s1 * (s1 - 1) = 0) (bs2 : s2 * (s2 - 1) = 0)
    (bs3 : s3 * (s3 - 1) = 0) (bs4 : s4 * (s4 - 1) = 0) (bs5 : s5 * (s5 - 1) = 0)
    (bs6 : s6 * (s6 - 1) = 0) (bs7 : s7 * (s7 - 1) = 0)
    (hm0 : m0 * (s0 + s1 * 2 + s2 * 4) = 0) (hm1 : m1 * (s0 + s1 * 2 + s2 * 4 - 1) = 0)
    (hm2 : m2 * (s0 + s1 * 2 + s2 * 4 - 2) = 0) (hm3 : m3 * (s0 + s1 * 2 + s2 * 4 - 3) = 0)
    (hm4 : m4 * (s0 + s1 * 2 + s2 * 4 - 4) = 0) (hm5 : m5 * (s0 + s1 * 2 + s2 * 4 - 5) = 0)
    (hm6 : m6 * (s0 + s1 * 2 + s2 * 4 - 6) = 0) (hm7 : m7 * (s0 + s1 * 2 + s2 * 4 - 7) = 0)
    (hm : m0 + m1 + m2 + m3 + m4 + m5 + m6 + m7 - 1 = 0)
    (hn0 : n0 * (s3 + s4 * 2) = 0) (hn1 : n1 * (s3 + s4 * 2 - 1) = 0)
    (hn2 : n2 * (s3 + s4 * 2 - 2) = 0) (hn3 : n3 * (s3 + s4 * 2 - 3) = 0)
    (hn : n0 + n1 + n2 + n3 - 1 = 0)
    (p00 : n0 * (B0 - b0) = 0) (p01 : n0 * (B1 - b1) = 0) (p02 : n0 * (B2 - b2) = 0)
    (p03 : n0 * (B3 - b3) = 0) (p04 : n0 * B4 = 0)
    (p10 : n1 * (B0 - b1) = 0) (p11 : n1 * (B1 - b2) = 0) (p12 : n1 * (B2 - b3) = 0)
    (p13 : n1 * B3 = 0) (p14 : n1 * B4 = 0)
    (p20 : n2 * (B0 - b2) = 0) (p21 : n2 * (B1 - b3) = 0) (p22 : n2 * B2 = 0)
    (p23 : n2 * B3 = 0) (p24 : n2 * B4 = 0)
    (p30 : n3 * (B0 - b3) = 0) (p31 : n3 * B1 = 0) (p32 : n3 * B2 = 0)
    (p33 : n3 * B3 = 0) (p34 : n3 * B4 = 0)
    (r0 : O0 + K1 * (m0 * 256 + m1 * 128 + m2 * 64 + m3 * 32 + m4 * 16 + m5 * 8 + m6 * 4 + m7 * 2) - R0 = 0)
    (r1 : O1 + K2 * (m0 * 256 + m1 * 128 + m2 * 64 + m3 * 32 + m4 * 16 + m5 * 8 + m6 * 4 + m7 * 2) - R1 = 0)
    (r2 : O2 + K3 * (m0 * 256 + m1 * 128 + m2 * 64 + m3 * 32 + m4 * 16 + m5 * 8 + m6 * 4 + m7 * 2) - R2 = 0)
    (r3 : O3 + K4 * (m0 * 256 + m1 * 128 + m2 * 64 + m3 * 32 + m4 * 16 + m5 * 8 + m6 * 4 + m7 * 2) - R3 = 0)
    (e0 : R0 - 1 = 0) (e1 : R1 = 0) (e2 : R2 = 0) (e3 : R3 = 0)
    (h0 : Shr (s0 + s1 * 2 + s2 * 4) B0 O0 K0) (h1 : Shr (s0 + s1 * 2 + s2 * 4) B1 O1 K1)
    (h2 : Shr (s0 + s1 * 2 + s2 * 4) B2 O2 K2) (h3 : Shr (s0 + s1 * 2 + s2 * 4) B3 O3 K3)
    (h4 : Shr (s0 + s1 * 2 + s2 * 4) B4 O4 K4)
    (vb0 : b0.val ≤ 255) (vb1 : b1.val ≤ 255) (vb2 : b2.val ≤ 255) (vb3 : b3.val ≤ 255)
    (vB0 : B0.val ≤ 255) (vB1 : B1.val ≤ 255) (vB2 : B2.val ≤ 255) (vB3 : B3.val ≤ 255) (vB4 : B4.val ≤ 255)
    (vO0 : O0.val ≤ 255) (vO1 : O1.val ≤ 255) (vO2 : O2.val ≤ 255) (vO3 : O3.val ≤ 255) (vO4 : O4.val ≤ 255)
    (vK0 : K0.val ≤ 255) (vK1 : K1.val ≤ 255) (vK2 : K2.val ≤ 255) (vK3 : K3.val ≤ 255) (vK4 : K4.val ≤ 255) :
    b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val ≠ 0 ∧ (31 - a).val = Nat.log2 (b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val) := by
  have hd : (31 - a).val ≤ 31 := by
    clear * - hs ha bs0 bs1 bs2 bs3 bs4 bs5 bs6 bs7
    picus_bits
    picus_prep
    (try simp only [ZirenDet.val_cast] at *)
    omega
  have h := shifted_one (31 - a) b0 b1 b2 b3 s0 s1 s2 s3 s4 s5 s6 s7 m0 m1 m2 m3 m4 m5 m6 m7 n0 n1 n2 n3 B0 B1 B2 B3 B4 O0 O1 O2 O3 O4 K0 K1 K2 K3 K4 R0 R1 R2 R3 hs hd bs0 bs1 bs2 bs3 bs4 bs5 bs6 bs7 hm0 hm1 hm2 hm3 hm4 hm5 hm6 hm7 hm hn0 hn1 hn2 hn3 hn p00 p01 p02 p03 p04 p10 p11 p12 p13 p14 p20 p21 p22 p23 p24 p30 p31 p32 p33 p34 r0 r1 r2 r3 e0 e1 e2 e3 h0 h1 h2 h3 h4 vb0 vb1 vb2 vb3 vB0 vB1 vB2 vB3 vB4 vO0 vO1 vO2 vO3 vO4 vK0 vK1 vK2 vK3 vK4
  generalize (b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val) = N at h ⊢
  generalize hk : (31 - a).val = k at h hd ⊢
  clear * - h hd
  interval_cases k <;> norm_num at h <;>
    (refine ⟨by omega, ?_⟩; symm; rw [Nat.log2_eq_iff (by omega)]; omega)

/-- What the gadget says of a row: either the word is zero and the count is 32, or the word
is non-zero and `31 - a` is the position of its leading one. -/
def Spec (z a : F) (N : ℕ) : Prop :=
  (z = 1 ∧ a = 32 ∧ N = 0) ∨ (z = 0 ∧ N ≠ 0 ∧ (31 - a).val = Nat.log2 N)

/-- The zero branch: a word of three bytes that is zero in the field is zero.  The top byte is
constrained separately, because a four-byte word can equal the field's characteristic. -/
theorem zero_spec (a b0 b1 b2 b3 : F) (hw : b0 + b1 * 256 + b2 * 65536 + b3 * 16777216 = 0)
    (h3 : b3 = 0) (ha : a - 32 = 0)
    (vb0 : b0.val ≤ 255) (vb1 : b1.val ≤ 255) (vb2 : b2.val ≤ 255) (vb3 : b3.val ≤ 255) :
    Spec 1 a (b0.val + 256 * b1.val + 65536 * b2.val + 16777216 * b3.val) := by
  refine Or.inl ⟨rfl, sub_eq_zero.mp ha, ?_⟩
  clear ha
  subst h3
  simp only [ZMod.val_zero, mul_zero, zero_mul, add_zero] at *
  picus_prep
  (try simp only [ZirenDet.val_cast] at *)
  omega

/-- The count and the zero flag are functions of the word. -/
theorem spec_unique {z z' a a' : F} {N : ℕ} (h : Spec z a N) (h' : Spec z' a' N) :
    a = a' ∧ z = z' := by
  rcases h with ⟨hz, ha, hN⟩ | ⟨hz, hN, hl⟩ <;> rcases h' with ⟨hz', ha', hN'⟩ | ⟨hz', hN', hl'⟩
  · exact ⟨ha.trans ha'.symm, hz.trans hz'.symm⟩
  · exact absurd hN hN'
  · exact absurd hN' hN
  · refine ⟨?_, hz.trans hz'.symm⟩
    have e : (31 - a) = (31 - a') := ZMod.val_injective _ (hl.trans hl'.symm)
    linear_combination -e

end ZirenDet.LeadingOne
