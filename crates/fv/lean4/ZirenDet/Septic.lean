import ZirenDet.Basic

/-!
# The septic extension of the Global chip

The Global chip adds its messages as points of `y² = x³ + 3z·x − 3` over the septic extension
`F[z]/(z⁷ + 2z − 8)` (`zkm_pcs::septic_extension`), an element being its 7 coordinates.  `sm`
is the AIR's product on coordinates and `φ` maps coordinates into `AdjoinRoot fpoly`, an
injective map that turns `sm` into the ring product.

* `chord_unique`: the chord identities with a witnessed inverse of `x₂ − x₁` fix `p₁ + p₂`; this
  needs only a commutative ring.
* `fpoly_irreducible`: a root `s` of a factor of degree `e ≤ 3` would satisfy `s^(p^e) = s`,
  but `z^(p^e) − z` is a unit for `e = 1, 2, 3` (certificates `cert1`–`cert3`, checked by the
  kernel from explicit square-and-multiply chains), so `AdjoinRoot fpoly` is a field.
* `sq_unique`: two coordinate vectors with the same square are equal up to sign; `y6_recv` and
  `y6_send` rule out the sign flip under the chip's range checks on `y₆`.
-/

namespace ZirenDet.Septic

open Polynomial

/-- Septic coordinates. -/
abbrev V := Fin 7 → F

/-- The AIR's product: the schoolbook product reduced by `z⁷ = 8 − 2z`. -/
def sm (a b : V) : V :=
  ![a 0 * b 0 + 8 * (a 1 * b 6 + a 2 * b 5 + a 3 * b 4 + a 4 * b 3 + a 5 * b 2 + a 6 * b 1),
    a 0 * b 1 + a 1 * b 0 + 8 * (a 2 * b 6 + a 3 * b 5 + a 4 * b 4 + a 5 * b 3 + a 6 * b 2) - 2 * (a 1 * b 6 + a 2 * b 5 + a 3 * b 4 + a 4 * b 3 + a 5 * b 2 + a 6 * b 1),
    a 0 * b 2 + a 1 * b 1 + a 2 * b 0 + 8 * (a 3 * b 6 + a 4 * b 5 + a 5 * b 4 + a 6 * b 3) - 2 * (a 2 * b 6 + a 3 * b 5 + a 4 * b 4 + a 5 * b 3 + a 6 * b 2),
    a 0 * b 3 + a 1 * b 2 + a 2 * b 1 + a 3 * b 0 + 8 * (a 4 * b 6 + a 5 * b 5 + a 6 * b 4) - 2 * (a 3 * b 6 + a 4 * b 5 + a 5 * b 4 + a 6 * b 3),
    a 0 * b 4 + a 1 * b 3 + a 2 * b 2 + a 3 * b 1 + a 4 * b 0 + 8 * (a 5 * b 6 + a 6 * b 5) - 2 * (a 4 * b 6 + a 5 * b 5 + a 6 * b 4),
    a 0 * b 5 + a 1 * b 4 + a 2 * b 3 + a 3 * b 2 + a 4 * b 1 + a 5 * b 0 + 8 * (a 6 * b 6) - 2 * (a 5 * b 6 + a 6 * b 5),
    a 0 * b 6 + a 1 * b 5 + a 2 * b 4 + a 3 * b 3 + a 4 * b 2 + a 5 * b 1 + a 6 * b 0 - 2 * (a 6 * b 6)]
/-- The unit. -/
def one : V := ![1, 0, 0, 0, 0, 0, 0]

/-- The generator `z`. -/
def Xv : V := ![0, 1, 0, 0, 0, 0, 0]

/-- The curve's right-hand side `x³ + 3z·x − 3`, as the AIR computes it. -/
def cv (x : V) : V := sm (sm x x) x + sm x ![0, 3, 0, 0, 0, 0, 0] - ![3, 0, 0, 0, 0, 0, 0]

theorem V_ext {a b : V} (h0 : a 0 = b 0) (h1 : a 1 = b 1) (h2 : a 2 = b 2) (h3 : a 3 = b 3)
    (h4 : a 4 = b 4) (h5 : a 5 = b 5) (h6 : a 6 = b 6) : a = b := by
  funext k
  fin_cases k <;> assumption

theorem V_components {a0 a1 a2 a3 a4 a5 a6 b0 b1 b2 b3 b4 b5 b6 : F}
    (h : (![a0, a1, a2, a3, a4, a5, a6] : V) = ![b0, b1, b2, b3, b4, b5, b6]) :
    a0 = b0 ∧ a1 = b1 ∧ a2 = b2 ∧ a3 = b3 ∧ a4 = b4 ∧ a5 = b5 ∧ a6 = b6 :=
  ⟨congrFun h 0, congrFun h 1, congrFun h 2, congrFun h 3, congrFun h 4, congrFun h 5,
    congrFun h 6⟩

/-- The modulus `z⁷ + 2z − 8`. -/
noncomputable def fpoly : F[X] := X ^ 7 + C 2 * X - C 8

theorem fpoly_natDegree : fpoly.natDegree = 7 := by
  unfold fpoly
  compute_degree!

theorem fpoly_monic : fpoly.Monic := by
  unfold fpoly
  monicity!

local notation "S" => AdjoinRoot fpoly
local notation "r" => AdjoinRoot.root fpoly
local notation "ι" => AdjoinRoot.of fpoly

theorem hr : r ^ 7 + 2 * r - 8 = 0 := by
  have h : AdjoinRoot.mk fpoly (X ^ 7 + C 2 * X - C 8) = 0 := AdjoinRoot.mk_self
  simp only [map_sub, map_add, map_mul, map_pow, AdjoinRoot.mk_X, AdjoinRoot.mk_C,
    map_ofNat] at h
  exact h

/-- Coordinates as an element of `AdjoinRoot fpoly`. -/
noncomputable def φ (a : V) : S :=
  ι (a 0) + ι (a 1) * r + ι (a 2) * r ^ 2 + ι (a 3) * r ^ 3 + ι (a 4) * r ^ 4 +
    ι (a 5) * r ^ 5 + ι (a 6) * r ^ 6

theorem φ_sm (a b : V) : φ (sm a b) = φ a * φ b := by
  simp only [φ, sm, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one,
    map_add, map_sub, map_mul, map_ofNat]
  linear_combination (-((ι (a 1) * ι (b 6) + ι (a 2) * ι (b 5) + ι (a 3) * ι (b 4) + ι (a 4) * ι (b 3) + ι (a 5) * ι (b 2) + ι (a 6) * ι (b 1)) * r ^ 0 + (ι (a 2) * ι (b 6) + ι (a 3) * ι (b 5) + ι (a 4) * ι (b 4) + ι (a 5) * ι (b 3) + ι (a 6) * ι (b 2)) * r ^ 1 + (ι (a 3) * ι (b 6) + ι (a 4) * ι (b 5) + ι (a 5) * ι (b 4) + ι (a 6) * ι (b 3)) * r ^ 2 + (ι (a 4) * ι (b 6) + ι (a 5) * ι (b 5) + ι (a 6) * ι (b 4)) * r ^ 3 + (ι (a 5) * ι (b 6) + ι (a 6) * ι (b 5)) * r ^ 4 + (ι (a 6) * ι (b 6)) * r ^ 5)) * hr

theorem φ_add (a b : V) : φ (a + b) = φ a + φ b := by
  simp only [φ, Pi.add_apply, map_add]; ring

theorem φ_sub (a b : V) : φ (a - b) = φ a - φ b := by
  simp only [φ, Pi.sub_apply, map_sub]; ring

theorem φ_neg (a : V) : φ (-a) = -φ a := by
  simp only [φ, Pi.neg_apply, map_neg]; ring

theorem φ_one : φ one = 1 := by
  simp [φ, one]

theorem φ_X : φ Xv = r := by
  simp [φ, Xv]

/-- Coordinates as a polynomial of degree below 7. -/
noncomputable def poly (a : V) : F[X] :=
  C (a 0) + C (a 1) * X + C (a 2) * X ^ 2 + C (a 3) * X ^ 3 + C (a 4) * X ^ 4 +
    C (a 5) * X ^ 5 + C (a 6) * X ^ 6

theorem φ_mk (a : V) : φ a = AdjoinRoot.mk fpoly (poly a) := by
  simp only [φ, poly, map_add, map_mul, map_pow, AdjoinRoot.mk_C, AdjoinRoot.mk_X]

theorem φ_inj {a b : V} (h : φ a = φ b) : a = b := by
  rw [φ_mk, φ_mk, AdjoinRoot.mk_eq_mk] at h
  have hz : poly a - poly b = 0 := by
    apply eq_zero_of_dvd_of_natDegree_lt h
    rw [fpoly_natDegree]
    have : (poly a - poly b).natDegree ≤ 6 := by
      unfold poly
      compute_degree
    omega
  have hc : ∀ k : ℕ, (poly a - poly b).coeff k = 0 := fun k => by rw [hz, coeff_zero]
  refine V_ext ?_ ?_ ?_ ?_ ?_ ?_ ?_
  · simpa [poly, coeff_X_pow, coeff_C, coeff_X, sub_eq_zero] using hc 0
  · simpa [poly, coeff_X_pow, coeff_C, coeff_X, sub_eq_zero] using hc 1
  · simpa [poly, coeff_X_pow, coeff_C, coeff_X, sub_eq_zero] using hc 2
  · simpa [poly, coeff_X_pow, coeff_C, coeff_X, sub_eq_zero] using hc 3
  · simpa [poly, coeff_X_pow, coeff_C, coeff_X, sub_eq_zero] using hc 4
  · simpa [poly, coeff_X_pow, coeff_C, coeff_X, sub_eq_zero] using hc 5
  · simpa [poly, coeff_X_pow, coeff_C, coeff_X, sub_eq_zero] using hc 6

/-! ### Chord addition -/

/-- The chord identities of `p₁ + p₂ = p₃`, with a witnessed inverse `i` of `x₂ − x₁`, fix
`p₃`: `x₃ = (y₂ − y₁)² i² − x₁ − x₂` and `y₃ = (y₂ − y₁)(x₁ − x₃) i − y₁`. -/
theorem chord_unique {x1 y1 x2 y2 x3 y3 i x3' y3' i' : V}
    (hx : sm (x1 + x2 + x3) (sm (x2 - x1) (x2 - x1)) = sm (y2 - y1) (y2 - y1))
    (hy : sm (y1 + y3) (x2 - x1) = sm (y2 - y1) (x1 - x3)) (hi : sm (x2 - x1) i = one)
    (hx' : sm (x1 + x2 + x3') (sm (x2 - x1) (x2 - x1)) = sm (y2 - y1) (y2 - y1))
    (hy' : sm (y1 + y3') (x2 - x1) = sm (y2 - y1) (x1 - x3')) (hi' : sm (x2 - x1) i' = one) :
    x3 = x3' ∧ y3 = y3' := by
  have ex := congrArg φ hx
  have ey := congrArg φ hy
  have ei := congrArg φ hi
  have ex' := congrArg φ hx'
  have ey' := congrArg φ hy'
  have ei' := congrArg φ hi'
  simp only [φ_sm, φ_add, φ_sub, φ_one] at ex ey ei ex' ey' ei'
  have hI : φ i = φ i' := by linear_combination φ i' * ei - φ i * ei'
  have h3 : φ x3 = φ x3' := by
    linear_combination (φ i) ^ 2 * ex - (φ i) ^ 2 * ex' -
      (φ x3 - φ x3') * ((φ x2 - φ x1) * φ i + 1) * ei
  have hx3 := φ_inj h3
  subst hx3
  refine ⟨rfl, φ_inj ?_⟩
  linear_combination φ i * ey - φ i * ey' - (φ y3 - φ y3') * ei

/-! ### `z⁷ + 2z − 8` is irreducible -/

theorem chain_sq {b A B : V} {n m : ℕ} (hA : φ A = φ b ^ n) (h : sm A A = B) (hm : 2 * n = m) :
    φ B = φ b ^ m := by
  rw [← h, φ_sm, hA, ← hm]; ring

theorem chain_mul {b A B : V} {n m : ℕ} (hA : φ A = φ b ^ n) (h : sm A b = B) (hm : n + 1 = m) :
    φ B = φ b ^ m := by
  rw [← h, φ_sm, hA, ← hm]; ring

def R1 : V := ![587483156, 843070426, 856916903, 802055410, 1274370027, 839777993, 1763169463]

def Vc1 : V := ![268453403, 614337225, 1757428311, 1502274737, 1518171548, 2007194352, 1636226050]

theorem pow1 : φ R1 = r ^ KB := by
  have k1_0 : φ Xv = φ Xv ^ 1 := (pow_one _).symm
  have k1_1 : φ ![0, 0, 1, 0, 0, 0, 0] = φ Xv ^ 2 :=
    chain_sq k1_0 (by decide +kernel) rfl
  have k1_2 : φ ![0, 0, 0, 1, 0, 0, 0] = φ Xv ^ 3 :=
    chain_mul k1_1 (by decide +kernel) rfl
  have k1_3 : φ ![0, 0, 0, 0, 0, 0, 1] = φ Xv ^ 6 :=
    chain_sq k1_2 (by decide +kernel) rfl
  have k1_4 : φ ![8, 2130706431, 0, 0, 0, 0, 0] = φ Xv ^ 7 :=
    chain_mul k1_3 (by decide +kernel) rfl
  have k1_5 : φ ![64, 2130706401, 4, 0, 0, 0, 0] = φ Xv ^ 14 :=
    chain_sq k1_4 (by decide +kernel) rfl
  have k1_6 : φ ![0, 64, 2130706401, 4, 0, 0, 0] = φ Xv ^ 15 :=
    chain_mul k1_5 (by decide +kernel) rfl
  have k1_7 : φ ![0, 0, 4096, 2130702337, 1536, 2130706177, 16] = φ Xv ^ 30 :=
    chain_sq k1_6 (by decide +kernel) rfl
  have k1_8 : φ ![128, 2130706401, 0, 4096, 2130702337, 1536, 2130706177] = φ Xv ^ 31 :=
    chain_mul k1_7 (by decide +kernel) rfl
  have k1_9 : φ ![1862418433, 301948928, 1954546689, 66060288, 2114191361, 2752512, 16482304] = φ Xv ^ 62 :=
    chain_sq k1_8 (by decide +kernel) rfl
  have k1_10 : φ ![131858432, 1829453825, 301948928, 1954546689, 66060288, 2114191361, 2752512] = φ Xv ^ 63 :=
    chain_mul k1_9 (by decide +kernel) rfl
  have k1_11 : φ ![1196641216, 1855873807, 312085434, 923921791, 1057787129, 607409499, 247970159] = φ Xv ^ 126 :=
    chain_sq k1_10 (by decide +kernel) rfl
  have k1_12 : φ ![1983761272, 700700898, 1855873807, 312085434, 923921791, 1057787129, 607409499] = φ Xv ^ 127 :=
    chain_mul k1_11 (by decide +kernel) rfl
  have k1_13 : φ ![958657333, 1227598991, 716118863, 1665824491, 1764195096, 469111504, 894275455] = φ Xv ^ 254 :=
    chain_sq k1_12 (by decide +kernel) rfl
  have k1_14 : φ ![960399572, 855840465, 252622824, 2026399647, 653814813, 1079769727, 1797709434] = φ Xv ^ 508 :=
    chain_sq k1_13 (by decide +kernel) rfl
  have k1_15 : φ ![1758863851, 1739412983, 262898681, 633145621, 1587283178, 1652626080, 1941636727] = φ Xv ^ 1016 :=
    chain_sq k1_14 (by decide +kernel) rfl
  have k1_16 : φ ![2097384158, 1697997718, 1669452240, 1868516746, 1073396937, 1858637344, 966114172] = φ Xv ^ 2032 :=
    chain_sq k1_15 (by decide +kernel) rfl
  have k1_17 : φ ![529413726, 309607232, 1596809728, 480050892, 2061647601, 1421687055, 858370123] = φ Xv ^ 4064 :=
    chain_sq k1_16 (by decide +kernel) rfl
  have k1_18 : φ ![1640910354, 257871304, 157425518, 1224528147, 2051917639, 689710398, 797331520] = φ Xv ^ 8128 :=
    chain_sq k1_17 (by decide +kernel) rfl
  have k1_19 : φ ![711540660, 557025088, 1449123056, 361787807, 1071995540, 134191580, 1789278292] = φ Xv ^ 16256 :=
    chain_sq k1_18 (by decide +kernel) rfl
  have k1_20 : φ ![1900239890, 164358236, 434992950, 756541482, 2087919147, 170620119, 1265741471] = φ Xv ^ 32512 :=
    chain_sq k1_19 (by decide +kernel) rfl
  have k1_21 : φ ![854908894, 488506719, 2098918889, 1089432208, 1238140161, 1298727417, 1354674624] = φ Xv ^ 65024 :=
    chain_sq k1_20 (by decide +kernel) rfl
  have k1_22 : φ ![1276012687, 1844546694, 1085301293, 1556520102, 1706536945, 1533385771, 1208512888] = φ Xv ^ 130048 :=
    chain_sq k1_21 (by decide +kernel) rfl
  have k1_23 : φ ![255305049, 1725168334, 1385022763, 1693635292, 843319439, 12395772, 1130705045] = φ Xv ^ 260096 :=
    chain_sq k1_22 (by decide +kernel) rfl
  have k1_24 : φ ![1629576265, 762744215, 619245154, 685164555, 776829642, 17216766, 1329300044] = φ Xv ^ 520192 :=
    chain_sq k1_23 (by decide +kernel) rfl
  have k1_25 : φ ![579859130, 1883574264, 1861690289, 692660998, 238194600, 1531639151, 508004338] = φ Xv ^ 1040384 :=
    chain_sq k1_24 (by decide +kernel) rfl
  have k1_26 : φ ![1277825145, 757064733, 469081717, 995869470, 1020207928, 961803305, 1923639452] = φ Xv ^ 2080768 :=
    chain_sq k1_25 (by decide +kernel) rfl
  have k1_27 : φ ![179008692, 1639286815, 1702383367, 217301671, 255828432, 1853098900, 144583034] = φ Xv ^ 4161536 :=
    chain_sq k1_26 (by decide +kernel) rfl
  have k1_28 : φ ![922802337, 123315698, 1395866062, 1860786277, 352270012, 1073409978, 1434762321] = φ Xv ^ 8323072 :=
    chain_sq k1_27 (by decide +kernel) rfl
  have k1_29 : φ ![2030190434, 170967556, 1124812629, 1980584183, 110572074, 1872907107, 807097400] = φ Xv ^ 16646144 :=
    chain_sq k1_28 (by decide +kernel) rfl
  have k1_30 : φ ![1929794872, 1980285871, 818826043, 132473026, 1473509868, 381764358, 157047993] = φ Xv ^ 33292288 :=
    chain_sq k1_29 (by decide +kernel) rfl
  have k1_31 : φ ![598428881, 539877632, 914390440, 1454062147, 1454172937, 683398638, 1778281110] = φ Xv ^ 66584576 :=
    chain_sq k1_30 (by decide +kernel) rfl
  have k1_32 : φ ![1095328, 1044028982, 1158636753, 512278715, 409055934, 1188809672, 590502154] = φ Xv ^ 133169152 :=
    chain_sq k1_31 (by decide +kernel) rfl
  have k1_33 : φ ![1551124671, 1500189630, 1861424840, 697040927, 1858507636, 1419045545, 391280139] = φ Xv ^ 266338304 :=
    chain_sq k1_32 (by decide +kernel) rfl
  have k1_34 : φ ![1428340873, 1423814217, 1090059029, 2080783366, 320882369, 29813258, 733502069] = φ Xv ^ 532676608 :=
    chain_sq k1_33 (by decide +kernel) rfl
  have k1_35 : φ ![1368141727, 1664404751, 1084263335, 371348744, 1378238089, 934014890, 1868784272] = φ Xv ^ 1065353216 :=
    chain_sq k1_34 (by decide +kernel) rfl
  have k1_36 : φ ![989941215, 856916903, 802055410, 1274370027, 839777993, 1763169463, 1138788611] = φ Xv ^ 2130706432 :=
    chain_sq k1_35 (by decide +kernel) rfl
  have k1_37 : φ ![587483156, 843070426, 856916903, 802055410, 1274370027, 839777993, 1763169463] = φ Xv ^ 2130706433 :=
    chain_mul k1_36 (by decide +kernel) rfl
  have e : φ R1 = φ Xv ^ KB := k1_37
  rw [e, φ_X]

theorem cert1 : φ Vc1 * (r ^ KB ^ 1 - r) = 1 := by
  rw [pow_one, ← pow1, ← φ_X, ← φ_sub, ← φ_sm,
    (by decide +kernel : sm Vc1 (R1 - Xv) = one), φ_one]

def R2 : V := ![850855402, 83752463, 578907183, 1077461187, 841195559, 707516819, 141214579]

def Vc2 : V := ![928419092, 1579399489, 537637549, 1228154929, 351082122, 1611848766, 1953516734]

theorem pow2 : φ R2 = r ^ KB ^ 2 := by
  have k2_0 : φ R1 = φ R1 ^ 1 := (pow_one _).symm
  have k2_1 : φ ![1211185764, 536911287, 1786731555, 1891857573, 591969516, 550155966, 706525029] = φ R1 ^ 2 :=
    chain_sq k2_0 (by decide +kernel) rfl
  have k2_2 : φ ![926148950, 97341948, 1328592391, 2024338901, 1053611575, 858809194, 895371293] = φ R1 ^ 3 :=
    chain_mul k2_1 (by decide +kernel) rfl
  have k2_3 : φ ![448462982, 1809047550, 1873051132, 1563342685, 638206204, 1034022669, 616721146] = φ R1 ^ 6 :=
    chain_sq k2_2 (by decide +kernel) rfl
  have k2_4 : φ ![955740129, 444565581, 416872627, 526595613, 1712672812, 451150447, 735073940] = φ R1 ^ 7 :=
    chain_mul k2_3 (by decide +kernel) rfl
  have k2_5 : φ ![960227159, 737868712, 1032649654, 1078015069, 2071459427, 896205284, 1803044558] = φ R1 ^ 14 :=
    chain_sq k2_4 (by decide +kernel) rfl
  have k2_6 : φ ![414866903, 942704511, 850935163, 1020165941, 779204093, 1223321622, 64446824] = φ R1 ^ 15 :=
    chain_mul k2_5 (by decide +kernel) rfl
  have k2_7 : φ ![905073978, 3202771, 261492675, 139232814, 1559603936, 1651903603, 1593313053] = φ R1 ^ 30 :=
    chain_sq k2_6 (by decide +kernel) rfl
  have k2_8 : φ ![983860468, 1699383971, 700925579, 507344360, 494040375, 464869868, 1994389231] = φ R1 ^ 31 :=
    chain_mul k2_7 (by decide +kernel) rfl
  have k2_9 : φ ![1292153522, 1931057799, 479615537, 962028451, 2118769316, 2049448191, 1992093075] = φ R1 ^ 62 :=
    chain_sq k2_8 (by decide +kernel) rfl
  have k2_10 : φ ![1881503774, 311423022, 1357003131, 697142381, 2118840228, 889715650, 2088732178] = φ R1 ^ 63 :=
    chain_mul k2_9 (by decide +kernel) rfl
  have k2_11 : φ ![369073641, 1953046657, 1392605349, 1261590220, 895034223, 667528005, 653016754] = φ R1 ^ 126 :=
    chain_sq k2_10 (by decide +kernel) rfl
  have k2_12 : φ ![546444822, 896508181, 947191754, 356109417, 380370091, 506484504, 124092642] = φ R1 ^ 127 :=
    chain_mul k2_11 (by decide +kernel) rfl
  have k2_13 : φ ![523501564, 1331895569, 233719185, 231577623, 998366549, 313062973, 1173111198] = φ R1 ^ 254 :=
    chain_sq k2_12 (by decide +kernel) rfl
  have k2_14 : φ ![379364599, 117981516, 1927817324, 2023855145, 194745074, 716563975, 1281213497] = φ R1 ^ 508 :=
    chain_sq k2_13 (by decide +kernel) rfl
  have k2_15 : φ ![208042214, 512199585, 114107157, 1914630859, 514869058, 651269497, 149196425] = φ R1 ^ 1016 :=
    chain_sq k2_14 (by decide +kernel) rfl
  have k2_16 : φ ![1475721371, 1397528719, 999473745, 2098825133, 922853576, 210871261, 70800938] = φ R1 ^ 2032 :=
    chain_sq k2_15 (by decide +kernel) rfl
  have k2_17 : φ ![1734085036, 709964082, 1726466160, 207363301, 1660856467, 1107610937, 1205977315] = φ R1 ^ 4064 :=
    chain_sq k2_16 (by decide +kernel) rfl
  have k2_18 : φ ![1189008908, 1892248040, 578657737, 883023201, 1088266082, 1966138367, 888840082] = φ R1 ^ 8128 :=
    chain_sq k2_17 (by decide +kernel) rfl
  have k2_19 : φ ![1328948559, 259755513, 540681345, 274021258, 413171992, 1876547652, 551403075] = φ R1 ^ 16256 :=
    chain_sq k2_18 (by decide +kernel) rfl
  have k2_20 : φ ![913132349, 531158595, 1975394850, 1057333636, 1328379734, 1493371407, 1222605347] = φ R1 ^ 32512 :=
    chain_sq k2_19 (by decide +kernel) rfl
  have k2_21 : φ ![2074950484, 1875045323, 1126510620, 1284933288, 1138141352, 44893884, 1001012335] = φ R1 ^ 65024 :=
    chain_sq k2_20 (by decide +kernel) rfl
  have k2_22 : φ ![319963349, 1065969418, 201981051, 2052478778, 945459950, 39424000, 295699702] = φ R1 ^ 130048 :=
    chain_sq k2_21 (by decide +kernel) rfl
  have k2_23 : φ ![1235648373, 1110070968, 1240794960, 2034722705, 649284951, 584140040, 1702571984] = φ R1 ^ 260096 :=
    chain_sq k2_22 (by decide +kernel) rfl
  have k2_24 : φ ![1784843183, 281102279, 55408167, 2119153990, 1050531750, 269919153, 1064754674] = φ R1 ^ 520192 :=
    chain_sq k2_23 (by decide +kernel) rfl
  have k2_25 : φ ![1749010517, 541848813, 767143068, 1764686804, 682038591, 235805230, 1722685922] = φ R1 ^ 1040384 :=
    chain_sq k2_24 (by decide +kernel) rfl
  have k2_26 : φ ![278526396, 43273660, 1687417411, 1594285041, 1068279368, 791439180, 1873391790] = φ R1 ^ 2080768 :=
    chain_sq k2_25 (by decide +kernel) rfl
  have k2_27 : φ ![612885799, 1860875954, 2083119226, 2047490416, 420399599, 486447104, 1640590099] = φ R1 ^ 4161536 :=
    chain_sq k2_26 (by decide +kernel) rfl
  have k2_28 : φ ![1588167913, 1806591743, 1834593639, 1173476788, 140239090, 442749147, 402421285] = φ R1 ^ 8323072 :=
    chain_sq k2_27 (by decide +kernel) rfl
  have k2_29 : φ ![284549495, 928407561, 822753739, 1557229056, 620415673, 1873281642, 1386836677] = φ R1 ^ 16646144 :=
    chain_sq k2_28 (by decide +kernel) rfl
  have k2_30 : φ ![303347090, 583415144, 1518841657, 1322850499, 1567192659, 1846383450, 983875481] = φ R1 ^ 33292288 :=
    chain_sq k2_29 (by decide +kernel) rfl
  have k2_31 : φ ![952710727, 1347078493, 298776972, 2101091549, 809825737, 1199723170, 209356826] = φ R1 ^ 66584576 :=
    chain_sq k2_30 (by decide +kernel) rfl
  have k2_32 : φ ![1108005659, 558699424, 1941644585, 618651561, 1484856831, 1750356019, 348405500] = φ R1 ^ 133169152 :=
    chain_sq k2_31 (by decide +kernel) rfl
  have k2_33 : φ ![1475234995, 412130311, 587851192, 1601357254, 1761185308, 2055761002, 1057246639] = φ R1 ^ 266338304 :=
    chain_sq k2_32 (by decide +kernel) rfl
  have k2_34 : φ ![1537105640, 748530398, 1679797327, 489509510, 1741480823, 1319783479, 2039860269] = φ R1 ^ 532676608 :=
    chain_sq k2_33 (by decide +kernel) rfl
  have k2_35 : φ ![967768621, 2129486428, 37260704, 366503609, 1912704022, 888193537, 569880077] = φ R1 ^ 1065353216 :=
    chain_sq k2_34 (by decide +kernel) rfl
  have k2_36 : φ ![1663779939, 960414758, 1680893292, 1969561784, 1080276528, 536598085, 1531861200] = φ R1 ^ 2130706432 :=
    chain_sq k2_35 (by decide +kernel) rfl
  have k2_37 : φ ![850855402, 83752463, 578907183, 1077461187, 841195559, 707516819, 141214579] = φ R1 ^ 2130706433 :=
    chain_mul k2_36 (by decide +kernel) rfl
  have e : φ R2 = φ R1 ^ KB := k2_37
  rw [e, pow1, ← pow_mul, sq]

theorem cert2 : φ Vc2 * (r ^ KB ^ 2 - r) = 1 := by
  rw [← pow2, ← φ_X, ← φ_sub, ← φ_sm,
    (by decide +kernel : sm Vc2 (R2 - Xv) = one), φ_one]

def R3 : V := ![1996121346, 112849387, 2056262381, 184311178, 496842357, 1409948961, 99050902]

def Vc3 : V := ![910368081, 2002108443, 429533547, 14676990, 884749806, 577307950, 641950681]

theorem pow3 : φ R3 = r ^ KB ^ 3 := by
  have k3_0 : φ R2 = φ R2 ^ 1 := (pow_one _).symm
  have k3_1 : φ ![836146895, 2043859405, 2072756292, 685210173, 510761813, 193547797, 310193486] = φ R2 ^ 2 :=
    chain_sq k3_0 (by decide +kernel) rfl
  have k3_2 : φ ![1605797233, 989471584, 1210699680, 1003960530, 1444517609, 759580625, 1114273922] = φ R2 ^ 3 :=
    chain_mul k3_1 (by decide +kernel) rfl
  have k3_3 : φ ![688846502, 1836380477, 172054673, 688169080, 187745906, 414105003, 756944866] = φ R2 ^ 6 :=
    chain_sq k3_2 (by decide +kernel) rfl
  have k3_4 : φ ![428995637, 1963201507, 972892067, 2106490492, 448315315, 715672795, 1848277275] = φ R2 ^ 7 :=
    chain_mul k3_3 (by decide +kernel) rfl
  have k3_5 : φ ![1685691976, 1233945938, 419527477, 222679203, 693266560, 1571423743, 983320282] = φ R2 ^ 14 :=
    chain_sq k3_4 (by decide +kernel) rfl
  have k3_6 : φ ![29931092, 1443616699, 1133134284, 2040384593, 656079536, 1642447185, 1437930759] = φ R2 ^ 15 :=
    chain_mul k3_5 (by decide +kernel) rfl
  have k3_7 : φ ![1472485921, 1728043490, 1104216827, 224450537, 571972348, 1077364866, 1036509006] = φ R2 ^ 30 :=
    chain_sq k3_6 (by decide +kernel) rfl
  have k3_8 : φ ![231281285, 1319218567, 1150884907, 82611638, 532663261, 839075835, 1732943577] = φ R2 ^ 31 :=
    chain_mul k3_7 (by decide +kernel) rfl
  have k3_9 : φ ![1026723967, 1332619668, 239640248, 568323021, 1913651515, 632987706, 594347082] = φ R2 ^ 62 :=
    chain_sq k3_8 (by decide +kernel) rfl
  have k3_10 : φ ![1854550886, 801644156, 609070750, 557734614, 1997880289, 1190447550, 2073009660] = φ R2 ^ 63 :=
    chain_mul k3_9 (by decide +kernel) rfl
  have k3_11 : φ ![59638967, 1869415582, 422782740, 1945751146, 27027047, 1474150133, 827630933] = φ R2 ^ 126 :=
    chain_sq k3_10 (by decide +kernel) rfl
  have k3_12 : φ ![64327853, 387750016, 1336650463, 1493336912, 1881710003, 1562751978, 1796005307] = φ R2 ^ 127 :=
    chain_mul k3_11 (by decide +kernel) rfl
  have k3_13 : φ ![1230443798, 48836997, 258514318, 1160969559, 650067998, 2128055550, 1230376429] = φ R2 ^ 254 :=
    chain_sq k3_12 (by decide +kernel) rfl
  have k3_14 : φ ![800732418, 1641950634, 1050934186, 1154746990, 1646084894, 261544068, 1349452522] = φ R2 ^ 508 :=
    chain_sq k3_13 (by decide +kernel) rfl
  have k3_15 : φ ![1032708512, 1941831542, 2115187365, 1890584154, 1638842430, 989785529, 1695604982] = φ R2 ^ 1016 :=
    chain_sq k3_14 (by decide +kernel) rfl
  have k3_16 : φ ![435717644, 1916531846, 2062731006, 1650362871, 1748193420, 611046925, 1062161922] = φ R2 ^ 2032 :=
    chain_sq k3_15 (by decide +kernel) rfl
  have k3_17 : φ ![761942343, 2028990486, 1369302526, 558559982, 93266778, 1849764906, 461335208] = φ R2 ^ 4064 :=
    chain_sq k3_16 (by decide +kernel) rfl
  have k3_18 : φ ![1357250202, 1670676078, 172242140, 1677947599, 1932686936, 1746846722, 631863098] = φ R2 ^ 8128 :=
    chain_sq k3_17 (by decide +kernel) rfl
  have k3_19 : φ ![1679934900, 804229380, 1399511729, 1983583693, 1715148864, 798781426, 223468499] = φ R2 ^ 16256 :=
    chain_sq k3_18 (by decide +kernel) rfl
  have k3_20 : φ ![1243137513, 1801163099, 67476960, 1496581907, 1625473733, 2038317525, 2125343837] = φ R2 ^ 32512 :=
    chain_sq k3_19 (by decide +kernel) rfl
  have k3_21 : φ ![287655506, 1259005505, 1257960766, 1733324684, 741432159, 807856099, 1734012292] = φ R2 ^ 65024 :=
    chain_sq k3_20 (by decide +kernel) rfl
  have k3_22 : φ ![416675036, 1041483539, 1561085971, 229378497, 1903089407, 265356768, 884791461] = φ R2 ^ 130048 :=
    chain_sq k3_21 (by decide +kernel) rfl
  have k3_23 : φ ![29358029, 472356667, 1531779998, 1888765631, 236967579, 1083674347, 288667139] = φ R2 ^ 260096 :=
    chain_sq k3_22 (by decide +kernel) rfl
  have k3_24 : φ ![206308931, 698797138, 1219067451, 132093375, 1894913739, 85378275, 143943027] = φ R2 ^ 520192 :=
    chain_sq k3_23 (by decide +kernel) rfl
  have k3_25 : φ ![1910562229, 1377571343, 773425993, 288882763, 752181970, 1354307738, 1106688943] = φ R2 ^ 1040384 :=
    chain_sq k3_24 (by decide +kernel) rfl
  have k3_26 : φ ![2080418996, 445213954, 458015168, 1863236152, 1609133154, 2001611392, 83553896] = φ R2 ^ 2080768 :=
    chain_sq k3_25 (by decide +kernel) rfl
  have k3_27 : φ ![1876364130, 1698875022, 1188449295, 736994642, 570770709, 1148204726, 69353823] = φ R2 ^ 4161536 :=
    chain_sq k3_26 (by decide +kernel) rfl
  have k3_28 : φ ![1988217309, 1597332271, 1080477487, 1507080103, 400870503, 1738030952, 2056254388] = φ R2 ^ 8323072 :=
    chain_sq k3_27 (by decide +kernel) rfl
  have k3_29 : φ ![918792882, 1400261010, 1989290494, 1058087787, 230265597, 1234027398, 869017639] = φ R2 ^ 16646144 :=
    chain_sq k3_28 (by decide +kernel) rfl
  have k3_30 : φ ![1968497023, 1329378683, 780585803, 1853185722, 712393643, 902040103, 712300856] = φ R2 ^ 33292288 :=
    chain_sq k3_29 (by decide +kernel) rfl
  have k3_31 : φ ![91046272, 308605381, 1284940722, 226131307, 1748963792, 857261155, 1304749052] = φ R2 ^ 66584576 :=
    chain_sq k3_30 (by decide +kernel) rfl
  have k3_32 : φ ![1522943803, 1171417762, 1873155803, 467667519, 179606809, 1102486871, 2010923706] = φ R2 ^ 133169152 :=
    chain_sq k3_31 (by decide +kernel) rfl
  have k3_33 : φ ![1830785176, 1344364113, 1023729627, 1823013104, 82487657, 600951535, 731974303] = φ R2 ^ 266338304 :=
    chain_sq k3_32 (by decide +kernel) rfl
  have k3_34 : φ ![1210935735, 623363830, 906417590, 1778174993, 802706022, 336298466, 961800144] = φ R2 ^ 532676608 :=
    chain_sq k3_33 (by decide +kernel) rfl
  have k3_35 : φ ![1689146399, 1496211107, 864182772, 1818480284, 1521641714, 2009299192, 635566042] = φ R2 ^ 1065353216 :=
    chain_sq k3_34 (by decide +kernel) rfl
  have k3_36 : φ ![1425158479, 854999600, 190367005, 2079562321, 2006961296, 543846588, 2102900826] = φ R2 ^ 2130706432 :=
    chain_sq k3_35 (by decide +kernel) rfl
  have k3_37 : φ ![1996121346, 112849387, 2056262381, 184311178, 496842357, 1409948961, 99050902] = φ R2 ^ 2130706433 :=
    chain_mul k3_36 (by decide +kernel) rfl
  have e : φ R3 = φ R2 ^ KB := k3_37
  rw [e, pow2, ← pow_mul]
  congr 1

theorem cert3 : φ Vc3 * (r ^ KB ^ 3 - r) = 1 := by
  rw [← pow3, ← φ_X, ← φ_sub, ← φ_sm,
    (by decide +kernel : sm Vc3 (R3 - Xv) = one), φ_one]


theorem small_factor (h : ¬ Irreducible fpoly) :
    ∃ g : F[X], Irreducible g ∧ g ∣ fpoly ∧ g.natDegree ≤ 3 := by
  have hf0 : fpoly ≠ 0 := fpoly_monic.ne_zero
  have hnu : ¬ IsUnit fpoly := fun hu => by
    have := natDegree_eq_zero_of_isUnit hu
    rw [fpoly_natDegree] at this
    omega
  rw [irreducible_iff] at h
  push Not at h
  obtain ⟨a, b, hab, ha, hb⟩ := h hnu
  have ha0 : a ≠ 0 := by
    rintro rfl
    exact hf0 (by rw [hab, zero_mul])
  have hb0 : b ≠ 0 := by
    rintro rfl
    exact hf0 (by rw [hab, mul_zero])
  have hdeg : a.natDegree + b.natDegree = 7 := by
    rw [← natDegree_mul ha0 hb0, ← hab, fpoly_natDegree]
  have pick : ∀ c : F[X], c ∣ fpoly → c ≠ 0 → ¬ IsUnit c → c.natDegree ≤ 3 →
      ∃ g : F[X], Irreducible g ∧ g ∣ fpoly ∧ g.natDegree ≤ 3 := by
    intro c hc hc0 hcu hcd
    obtain ⟨g, hg, hgc⟩ := WfDvdMonoid.exists_irreducible_factor hcu hc0
    exact ⟨g, hg, hgc.trans hc, (natDegree_le_of_dvd hgc hc0).trans hcd⟩
  rcases le_or_gt a.natDegree 3 with h3 | h3
  · exact pick a ⟨b, hab⟩ ha0 ha h3
  · exact pick b ⟨a, by rw [hab, mul_comm]⟩ hb0 hb (by omega)

theorem fpoly_irreducible : Irreducible fpoly := by
  by_contra hred
  obtain ⟨g, hg, hgf, hg3⟩ := small_factor hred
  have : Fact (Irreducible g) := ⟨hg⟩
  have hg0 : g ≠ 0 := hg.ne_zero
  have hg1 : 0 < g.natDegree :=
    natDegree_pos_iff_degree_pos.mpr (degree_pos_of_irreducible hg)
  let pb := AdjoinRoot.powerBasis hg0
  haveI : Module.Finite F (AdjoinRoot g) := pb.finite
  haveI : Finite (AdjoinRoot g) := Module.finite_of_finite F
  letI : Fintype (AdjoinRoot g) := Fintype.ofFinite _
  have hcard : Fintype.card (AdjoinRoot g) = KB ^ g.natDegree := by
    rw [Module.card_eq_pow_finrank (K := F), ZMod.card, pb.finrank, AdjoinRoot.powerBasis_dim]
  have hfrob : AdjoinRoot.root g ^ KB ^ g.natDegree = AdjoinRoot.root g := by
    rw [← hcard]
    exact FiniteField.pow_card _
  have kill : ∀ (v : V) (e : ℕ), φ v * (r ^ KB ^ e - r) = 1 → e = g.natDegree → False := by
    intro v e hv he
    have h := congrArg (AdjoinRoot.algHomOfDvd F fpoly g hgf) hv
    rw [map_mul, map_sub, map_pow, AdjoinRoot.algHomOfDvd_root, map_one, he, hfrob, sub_self,
      mul_zero] at h
    exact zero_ne_one h
  obtain hd | hd | hd : g.natDegree = 1 ∨ g.natDegree = 2 ∨ g.natDegree = 3 := by omega
  · exact kill _ 1 cert1 hd.symm
  · exact kill _ 2 cert2 hd.symm
  · exact kill _ 3 cert3 hd.symm

instance : Fact (Irreducible fpoly) := ⟨fpoly_irreducible⟩

/-! ### Square roots and their sign -/

/-- In the field `AdjoinRoot fpoly`, equal squares mean equal up to sign. -/
theorem sq_unique {y y' : V} (h : sm y y = sm y' y') : y = y' ∨ y = -y' := by
  have h2 : φ y ^ 2 = φ y' ^ 2 := by rw [sq, sq, ← φ_sm, ← φ_sm, h]
  rcases sq_eq_sq_iff_eq_or_eq_neg.mp h2 with h3 | h3
  · exact Or.inl (φ_inj h3)
  · exact Or.inr (φ_inj (by rw [h3, φ_neg]))

/-- A receive row's `y₆ = 1 + t`, `t < 63·2²⁴`, and its negation are never both of that form. -/
theorem y6_recv {a b lo mid top lo' mid' top' : F}
    (ha : a = 1 + ((lo + mid * 65536) + top * 16777216))
    (hb : b = 1 + ((lo' + mid' * 65536) + top' * 16777216))
    (hl : lo.val ≤ 65535) (hm : mid.val ≤ 255) (ht : top.val < 63)
    (hl' : lo'.val ≤ 65535) (hm' : mid'.val ≤ 255) (ht' : top'.val < 63) (hab : a = -b) :
    False := by
  have key : ((2 + lo.val + mid.val * 65536 + top.val * 16777216 + lo'.val + mid'.val * 65536 +
      top'.val * 16777216 : ℕ) : F) = 0 := by
    push_cast
    simp only [ZMod.natCast_zmod_val]
    linear_combination hab - ha - hb
  rw [ZMod.natCast_eq_zero_iff] at key
  obtain ⟨k, hk⟩ := key
  have hk' : 2 + lo.val + mid.val * 65536 + top.val * 16777216 + lo'.val + mid'.val * 65536 +
      top'.val * 16777216 = 2130706433 * k := hk
  have hs : 2 + lo.val + mid.val * 65536 + top.val * 16777216 + lo'.val + mid'.val * 65536 +
      top'.val * 16777216 ≤ 2113929216 := by omega
  rw [hk'] at hs
  have hk0 : k = 0 := by omega
  subst hk0
  omega

/-- A send row's `y₆ = 2³⁰ + 1 + t`, `t < 63·2²⁴`, and its negation are never both of that
form (`2³⁰ + 1 ≡ −1056964608`). -/
theorem y6_send {a b lo mid top lo' mid' top' : F}
    (ha : a = -1056964608 + ((lo + mid * 65536) + top * 16777216))
    (hb : b = -1056964608 + ((lo' + mid' * 65536) + top' * 16777216))
    (hl : lo.val ≤ 65535) (hm : mid.val ≤ 255) (ht : top.val < 63)
    (hl' : lo'.val ≤ 65535) (hm' : mid'.val ≤ 255) (ht' : top'.val < 63) (hab : a = -b) :
    False := by
  have hK : (4261412866 : F) = 0 := by decide
  have key : ((2147483650 + lo.val + mid.val * 65536 + top.val * 16777216 + lo'.val +
      mid'.val * 65536 + top'.val * 16777216 : ℕ) : F) = 0 := by
    push_cast
    simp only [ZMod.natCast_zmod_val]
    linear_combination hab - ha - hb + hK
  rw [ZMod.natCast_eq_zero_iff] at key
  obtain ⟨k, hk⟩ := key
  have hk' : 2147483650 + lo.val + mid.val * 65536 + top.val * 16777216 + lo'.val +
      mid'.val * 65536 + top'.val * 16777216 = 2130706433 * k := hk
  have hs : 2147483650 + lo.val + mid.val * 65536 + top.val * 16777216 + lo'.val +
      mid'.val * 65536 + top'.val * 16777216 ≤ 4261412864 := by omega
  have hs' : 2147483650 ≤ 2147483650 + lo.val + mid.val * 65536 + top.val * 16777216 + lo'.val +
      mid'.val * 65536 + top'.val * 16777216 := by omega
  rw [hk'] at hs hs'
  omega

end ZirenDet.Septic
