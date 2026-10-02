import ZirenDet.Pratt

namespace ZirenDet.Primes

theorem prime_cb6d77 : Nat.Prime 13331831 :=
  ZirenDet.Pratt.prime_of_cert 13331831 13 [(2, 1), (5, 1), (971, 1), (1373, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_267f72148d98cd9 : Nat.Prime 173378833005251801 :=
  ZirenDet.Pratt.prime_of_cert 173378833005251801 6 [(2, 3), (5, 2), (2621, 1), (24809, 1), (13331831, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · exact prime_cb6d77)
    (by decide +kernel) (by decide +kernel)

theorem prime_4b0b9f59a0a545761c9 : Nat.Prime 22149492674086928081353 :=
  ZirenDet.Pratt.prime_of_cert 22149492674086928081353 5 [(2, 3), (3, 1), (5323, 1), (173378833005251801, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · exact prime_267f72148d98cd9)
    (by decide +kernel) (by decide +kernel)

theorem prime_1c245bc19c3dfa0c4ab7 : Nat.Prime 132896956044521568488119 :=
  ZirenDet.Pratt.prime_of_cert 132896956044521568488119 6 [(2, 1), (3, 1), (22149492674086928081353, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl
      · norm_num
      · norm_num
      · exact prime_4b0b9f59a0a545761c9)
    (by decide +kernel) (by decide +kernel)

theorem prime_1269fd : Nat.Prime 1206781 :=
  ZirenDet.Pratt.prime_of_cert 1206781 10 [(2, 2), (3, 1), (5, 1), (20113, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_6e7bef : Nat.Prime 7240687 :=
  ZirenDet.Pratt.prime_of_cert 7240687 3 [(2, 1), (3, 1), (1206781, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl
      · norm_num
      · norm_num
      · exact prime_1269fd)
    (by decide +kernel) (by decide +kernel)

theorem prime_669b171 : Nat.Prime 107590001 :=
  ZirenDet.Pratt.prime_of_cert 107590001 3 [(2, 4), (5, 4), (7, 1), (29, 1), (53, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_c03a94b2d3e64419a05cd8ccbf987069 : Nat.Prime 255515944373312847190720520512484175977 :=
  ZirenDet.Pratt.prime_of_cert 255515944373312847190720520512484175977 3 [(2, 3), (7, 2), (11, 1), (1627, 1), (2657, 1), (4423, 1), (41201, 1), (96557, 1), (7240687, 1), (107590001, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · exact prime_6e7bef
      · exact prime_669b171)
    (by decide +kernel) (by decide +kernel)

theorem prime_1db8260e5e3b460a46a0088fccf6a3a5936d75d89a776d4c0da4f338aafb : Nat.Prime 205115282021455665897114700593932402728804164701536103180137503955397371 :=
  ZirenDet.Pratt.prime_of_cert 205115282021455665897114700593932402728804164701536103180137503955397371 10 [(2, 1), (3, 1), (5, 1), (29, 2), (31, 1), (7723, 1), (132896956044521568488119, 1), (255515944373312847190720520512484175977, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · exact prime_1c245bc19c3dfa0c4ab7
      · exact prime_c03a94b2d3e64419a05cd8ccbf987069)
    (by decide +kernel) (by decide +kernel)

theorem prime_fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f : Nat.Prime 115792089237316195423570985008687907853269984665640564039457584007908834671663 :=
  ZirenDet.Pratt.prime_of_cert 115792089237316195423570985008687907853269984665640564039457584007908834671663 3 [(2, 1), (3, 1), (7, 1), (13441, 1), (205115282021455665897114700593932402728804164701536103180137503955397371, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · exact prime_1db8260e5e3b460a46a0088fccf6a3a5936d75d89a776d4c0da4f338aafb)
    (by decide +kernel) (by decide +kernel)

theorem prime_663d81 : Nat.Prime 6700417 :=
  ZirenDet.Pratt.prime_of_cert 6700417 5 [(2, 7), (3, 1), (17449, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_c29ba0f : Nat.Prime 204061199 :=
  ZirenDet.Pratt.prime_of_cert 204061199 11 [(2, 1), (11, 1), (23, 1), (107, 1), (3769, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_7fb6219d9 : Nat.Prime 34282281433 :=
  ZirenDet.Pratt.prime_of_cert 34282281433 17 [(2, 3), (3, 1), (7, 1), (204061199, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · exact prime_c29ba0f)
    (by decide +kernel) (by decide +kernel)

theorem prime_f76c8ffcb : Nat.Prime 66417393611 :=
  ZirenDet.Pratt.prime_of_cert 66417393611 6 [(2, 1), (5, 1), (53, 1), (173, 1), (197, 1), (3677, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_a44e179dccf : Nat.Prime 11290956913871 :=
  ZirenDet.Pratt.prime_of_cert 11290956913871 13 [(2, 1), (5, 1), (17, 1), (66417393611, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · exact prime_f76c8ffcb)
    (by decide +kernel) (by decide +kernel)

theorem prime_a3b2bf8c32ceaf : Nat.Prime 46076956964474543 :=
  ZirenDet.Pratt.prime_of_cert 46076956964474543 5 [(2, 1), (23, 1), (18169, 1), (78283, 1), (704251, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_22b559b5c816ae00f2378e18df38c5410ed597 : Nat.Prime 774023187263532362759620327192479577272145303 :=
  ZirenDet.Pratt.prime_of_cert 774023187263532362759620327192479577272145303 3 [(2, 1), (3, 2), (2411, 1), (34282281433, 1), (11290956913871, 1), (46076956964474543, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · exact prime_7fb6219d9
      · exact prime_a44e179dccf
      · exact prime_a3b2bf8c32ceaf)
    (by decide +kernel) (by decide +kernel)

theorem prime_926d1276e41fae13fdda5f78edb7802a76951509 : Nat.Prime 835945042244614951780389953367877943453916927241 :=
  ZirenDet.Pratt.prime_of_cert 835945042244614951780389953367877943453916927241 11 [(2, 3), (3, 3), (5, 1), (774023187263532362759620327192479577272145303, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · exact prime_22b559b5c816ae00f2378e18df38c5410ed597)
    (by decide +kernel) (by decide +kernel)

theorem prime_ffffffff00000001000000000000000000000000ffffffffffffffffffffffff : Nat.Prime 115792089210356248762697446949407573530086143415290314195533631308867097853951 :=
  ZirenDet.Pratt.prime_of_cert 115792089210356248762697446949407573530086143415290314195533631308867097853951 6 [(2, 1), (3, 1), (5, 2), (17, 1), (257, 1), (641, 1), (1531, 1), (65537, 1), (490463, 1), (6700417, 1), (835945042244614951780389953367877943453916927241, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · exact prime_663d81
      · exact prime_926d1276e41fae13fdda5f78edb7802a76951509)
    (by decide +kernel) (by decide +kernel)

theorem prime_320238b : Nat.Prime 52437899 :=
  ZirenDet.Pratt.prime_of_cert 52437899 2 [(2, 1), (43, 1), (609743, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_86efec3ddad : Nat.Prime 9272813673901 :=
  ZirenDet.Pratt.prime_of_cert 9272813673901 2 [(2, 2), (3, 1), (5, 2), (7, 1), (7577, 1), (582767, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_6da2eff241c91 : Nat.Prime 1928745244171409 :=
  ZirenDet.Pratt.prime_of_cert 1928745244171409 3 [(2, 4), (13, 1), (9272813673901, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl
      · norm_num
      · norm_num
      · exact prime_86efec3ddad)
    (by decide +kernel) (by decide +kernel)

theorem prime_64bffaff5ef403f5 : Nat.Prime 7259797099061183477 :=
  ZirenDet.Pratt.prime_of_cert 7259797099061183477 2 [(2, 2), (941, 1), (1928745244171409, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl
      · norm_num
      · norm_num
      · exact prime_6da2eff241c91)
    (by decide +kernel) (by decide +kernel)

theorem prime_8c1af90b200b5580b5 : Nat.Prime 2584487767265781317813 :=
  ZirenDet.Pratt.prime_of_cert 2584487767265781317813 2 [(2, 2), (89, 1), (7259797099061183477, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl
      · norm_num
      · norm_num
      · exact prime_64bffaff5ef403f5)
    (by decide +kernel) (by decide +kernel)

theorem prime_19bd81 : Nat.Prime 1686913 :=
  ZirenDet.Pratt.prime_of_cert 1686913 10 [(2, 7), (3, 1), (23, 1), (191, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_1c5ac01b : Nat.Prime 475709467 :=
  ZirenDet.Pratt.prime_of_cert 475709467 2 [(2, 1), (3, 1), (47, 1), (1686913, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · exact prime_19bd81)
    (by decide +kernel) (by decide +kernel)

theorem prime_3742528d : Nat.Prime 927093389 :=
  ZirenDet.Pratt.prime_of_cert 927093389 3 [(2, 2), (13, 1), (409, 1), (43591, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_3b0272e751e1 : Nat.Prime 64881703735777 :=
  ZirenDet.Pratt.prime_of_cert 64881703735777 5 [(2, 5), (3, 7), (927093389, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl
      · norm_num
      · norm_num
      · exact prime_3742528d)
    (by decide +kernel) (by decide +kernel)

theorem prime_13a0cd91d5e79f74fdf3 : Nat.Prime 92691255082156974996979 :=
  ZirenDet.Pratt.prime_of_cert 92691255082156974996979 3 [(2, 1), (3, 1), (31, 1), (467, 1), (16447, 1), (64881703735777, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · exact prime_3b0272e751e1)
    (by decide +kernel) (by decide +kernel)

theorem prime_30ff19f : Nat.Prime 51376543 :=
  ZirenDet.Pratt.prime_of_cert 51376543 3 [(2, 1), (3, 1), (7, 1), (151, 1), (8101, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_a2af041ef : Nat.Prime 43670061551 :=
  ZirenDet.Pratt.prime_of_cert 43670061551 7 [(2, 1), (5, 2), (17, 1), (51376543, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · exact prime_30ff19f)
    (by decide +kernel) (by decide +kernel)

theorem prime_30c3a1c05 : Nat.Prime 13090036741 :=
  ZirenDet.Pratt.prime_of_cert 13090036741 10 [(2, 2), (3, 1), (5, 1), (11, 1), (47, 1), (421987, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_cf107c4885c1f60d4d : Nat.Prime 3819663927398918131021 :=
  ZirenDet.Pratt.prime_of_cert 3819663927398918131021 6 [(2, 2), (3, 2), (5, 1), (19, 1), (113, 1), (755057, 1), (13090036741, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · exact prime_30c3a1c05)
    (by decide +kernel) (by decide +kernel)

theorem prime_d8b7e8de605a60610129ea5e2033cf : Nat.Prime 1125266252156850182658904441386709967 :=
  ZirenDet.Pratt.prime_of_cert 1125266252156850182658904441386709967 5 [(2, 1), (3373, 1), (43670061551, 1), (3819663927398918131021, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · exact prime_a2af041ef
      · exact prime_cf107c4885c1f60d4d)
    (by decide +kernel) (by decide +kernel)

theorem prime_24940de9050250a366a091851a9a9b1c0b6ebd56195f3b017baa5e86063 : Nat.Prime 15778400344354997994418419698270088123916926905054652752758194827714659 :=
  ZirenDet.Pratt.prime_of_cert 15778400344354997994418419698270088123916926905054652752758194827714659 2 [(2, 1), (3, 1), (53, 1), (475709467, 1), (92691255082156974996979, 1), (1125266252156850182658904441386709967, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · exact prime_1c5ac01b
      · exact prime_13a0cd91d5e79f74fdf3
      · exact prime_d8b7e8de605a60610129ea5e2033cf)
    (by decide +kernel) (by decide +kernel)

theorem prime_1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab : Nat.Prime 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787 :=
  ZirenDet.Pratt.prime_of_cert 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787 2 [(2, 1), (3, 2), (11, 1), (23, 1), (47, 1), (10177, 1), (859267, 1), (52437899, 1), (2584487767265781317813, 1), (15778400344354997994418419698270088123916926905054652752758194827714659, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · exact prime_320238b
      · exact prime_8c1af90b200b5580b5
      · exact prime_24940de9050250a366a091851a9a9b1c0b6ebd56195f3b017baa5e86063)
    (by decide +kernel) (by decide +kernel)

theorem prime_1d583d : Nat.Prime 1923133 :=
  ZirenDet.Pratt.prime_of_cert 1923133 2 [(2, 2), (3, 1), (43, 1), (3727, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_70d382ab8b9939 : Nat.Prime 31757755568855353 :=
  ZirenDet.Pratt.prime_of_cert 31757755568855353 10 [(2, 3), (3, 1), (31, 1), (107, 1), (223, 1), (4153, 1), (430751, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_a54d83af : Nat.Prime 2773320623 :=
  ZirenDet.Pratt.prime_of_cert 2773320623 5 [(2, 1), (2437, 1), (569003, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_10c9df5fc7 : Nat.Prime 72106336199 :=
  ZirenDet.Pratt.prime_of_cert 72106336199 7 [(2, 1), (13, 1), (2773320623, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl
      · norm_num
      · norm_num
      · exact prime_a54d83af)
    (by decide +kernel) (by decide +kernel)

theorem prime_82d4b5 : Nat.Prime 8574133 :=
  ZirenDet.Pratt.prime_of_cert 8574133 2 [(2, 2), (3, 1), (7, 1), (103, 1), (991, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_6d1cafa129d0b : Nat.Prime 1919519569386763 :=
  ZirenDet.Pratt.prime_of_cert 1919519569386763 2 [(2, 1), (3, 1), (7, 1), (19, 1), (47, 2), (127, 1), (8574133, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · exact prime_82d4b5)
    (by decide +kernel) (by decide +kernel)

theorem prime_e87c2a477b815a1793787395b23e1 : Nat.Prime 75445702479781427272750846543864801 :=
  ZirenDet.Pratt.prime_of_cert 75445702479781427272750846543864801 7 [(2, 5), (3, 2), (5, 2), (75707, 1), (72106336199, 1), (1919519569386763, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · exact prime_10c9df5fc7
      · exact prime_6d1cafa129d0b)
    (by decide +kernel) (by decide +kernel)

theorem prime_abaf8c6b094fd0f32c2ccabab864dbecd99144679c1adf804898fb2042b : Nat.Prime 74058212732561358302231226437062788676166966415465897661863160754340907 :=
  ZirenDet.Pratt.prime_of_cert 74058212732561358302231226437062788676166966415465897661863160754340907 2 [(2, 1), (3, 1), (353, 1), (57467, 1), (132049, 1), (1923133, 1), (31757755568855353, 1), (75445702479781427272750846543864801, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · exact prime_1d583d
      · exact prime_70d382ab8b9939
      · exact prime_e87c2a477b815a1793787395b23e1)
    (by decide +kernel) (by decide +kernel)

theorem prime_7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed : Nat.Prime 57896044618658097711785492504343953926634992332820282019728792003956564819949 :=
  ZirenDet.Pratt.prime_of_cert 57896044618658097711785492504343953926634992332820282019728792003956564819949 2 [(2, 2), (3, 1), (65147, 1), (74058212732561358302231226437062788676166966415465897661863160754340907, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · exact prime_abaf8c6b094fd0f32c2ccabab864dbecd99144679c1adf804898fb2042b)
    (by decide +kernel) (by decide +kernel)

theorem prime_1831fb5f : Nat.Prime 405928799 :=
  ZirenDet.Pratt.prime_of_cert 405928799 22 [(2, 1), (11, 1), (3691, 1), (4999, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_2ab6cbdc9 : Nat.Prime 11465965001 :=
  ZirenDet.Pratt.prime_of_cert 11465965001 3 [(2, 3), (5, 4), (7, 1), (327599, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_1c48c9 : Nat.Prime 1853641 :=
  ZirenDet.Pratt.prime_of_cert 1853641 17 [(2, 3), (3, 2), (5, 1), (19, 1), (271, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_459ca7 : Nat.Prime 4562087 :=
  ZirenDet.Pratt.prime_of_cert 4562087 5 [(2, 1), (17, 1), (109, 1), (1231, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_a52615f : Nat.Prime 173171039 :=
  ZirenDet.Pratt.prime_of_cert 173171039 13 [(2, 1), (73, 1), (89, 1), (13327, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_4b538c03 : Nat.Prime 1263766531 :=
  ZirenDet.Pratt.prime_of_cert 1263766531 10 [(2, 1), (3, 1), (5, 1), (13, 1), (911, 1), (3557, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_83d235055 : Nat.Prime 35385462869 :=
  ZirenDet.Pratt.prime_of_cert 35385462869 2 [(2, 2), (7, 1), (1263766531, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl
      · norm_num
      · norm_num
      · exact prime_4b538c03)
    (by decide +kernel) (by decide +kernel)

theorem prime_8d057ad4a4eb7 : Nat.Prime 2480874801745591 :=
  ZirenDet.Pratt.prime_of_cert 2480874801745591 6 [(2, 1), (3, 2), (5, 1), (19, 1), (41, 1), (35385462869, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · exact prime_83d235055)
    (by decide +kernel) (by decide +kernel)

theorem prime_2775dec4d2fd445d02a32aa0f59b66aa11 : Nat.Prime 13427688667394608761327070753331941386769 :=
  ZirenDet.Pratt.prime_of_cert 13427688667394608761327070753331941386769 17 [(2, 4), (3, 1), (7, 1), (11, 1), (1853641, 1), (4562087, 1), (173171039, 1), (2480874801745591, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · exact prime_1c48c9
      · exact prime_459ca7
      · exact prime_a52615f
      · exact prime_8d057ad4a4eb7)
    (by decide +kernel) (by decide +kernel)

theorem prime_30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47 : Nat.Prime 21888242871839275222246405745257275088696311157297823662689037894645226208583 :=
  ZirenDet.Pratt.prime_of_cert 21888242871839275222246405745257275088696311157297823662689037894645226208583 3 [(2, 1), (3, 2), (13, 1), (29, 1), (67, 1), (229, 1), (311, 1), (983, 1), (11003, 1), (405928799, 1), (11465965001, 1), (13427688667394608761327070753331941386769, 1)] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · norm_num
      · exact prime_1831fb5f
      · exact prime_2ab6cbdc9
      · exact prime_2775dec4d2fd445d02a32aa0f59b66aa11)
    (by decide +kernel) (by decide +kernel)

theorem secp256k1_p : Nat.Prime 115792089237316195423570985008687907853269984665640564039457584007908834671663 := prime_fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f

theorem secp256r1_p : Nat.Prime 115792089210356248762697446949407573530086143415290314195533631308867097853951 := prime_ffffffff00000001000000000000000000000000ffffffffffffffffffffffff

theorem bls12_381_p : Nat.Prime 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787 := prime_1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

theorem ed25519_p : Nat.Prime 57896044618658097711785492504343953926634992332820282019728792003956564819949 := prime_7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed

theorem bn254_p : Nat.Prime 21888242871839275222246405745257275088696311157297823662689037894645226208583 := prime_30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47

end ZirenDet.Primes
