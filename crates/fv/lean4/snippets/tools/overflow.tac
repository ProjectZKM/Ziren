  have z1 := iszero_byte (n := b0) (k := 0) (z := x122) (inv := x121) (by omega) (by omega) (by push_cast; linear_combination e19) (by push_cast; linear_combination e21)
  have z2 := iszero_byte (n := b1) (k := 0) (z := x124) (inv := x123) (by omega) (by omega) (by push_cast; linear_combination e22) (by push_cast; linear_combination e24)
  have z3 := iszero_byte (n := b2) (k := 0) (z := x126) (inv := x125) (by omega) (by omega) (by push_cast; linear_combination e25) (by push_cast; linear_combination e27)
  have z4 := iszero_byte (n := b3) (k := 128) (z := x128) (inv := x127) (by omega) (by omega) (by push_cast; linear_combination e28) (by push_cast; linear_combination e30)
  have z5 := iszero_byte (n := dv0) (k := 255) (z := x133) (inv := x132) (by omega) (by omega) (by push_cast; linear_combination e37) (by push_cast; linear_combination e39)
  have z6 := iszero_byte (n := dv1) (k := 255) (z := x135) (inv := x134) (by omega) (by omega) (by push_cast; linear_combination e40) (by push_cast; linear_combination e42)
  have z7 := iszero_byte (n := dv2) (k := 255) (z := x137) (inv := x136) (by omega) (by omega) (by push_cast; linear_combination e43) (by push_cast; linear_combination e45)
  have z8 := iszero_byte (n := dv3) (k := 255) (z := x139) (inv := x138) (by omega) (by omega) (by push_cast; linear_combination e46) (by push_cast; linear_combination e48)
  clear e19 e21 e22 e24 e25 e27 e28 e30 e37 e39 e40 e42 e43 e45 e46 e48
  obtain rfl : x129 = x122 * x124 := by linear_combination e34
  obtain rfl : x130 = x126 * x128 := by linear_combination e35
  obtain rfl : x131 = x122 * x124 * (x126 * x128) := by linear_combination e36
  obtain rfl : x140 = x133 * x135 := by linear_combination e52
  obtain rfl : x141 = x137 * x139 := by linear_combination e53
  obtain rfl : x142 = x133 * x135 * (x137 * x139) := by linear_combination e54
  clear e34 e35 e36 e52 e53 e54
  rcases z1 with ⟨rfl, h1⟩ | ⟨rfl, h1⟩ <;> rcases z2 with ⟨rfl, h2⟩ | ⟨rfl, h2⟩ <;>
    rcases z3 with ⟨rfl, h3⟩ | ⟨rfl, h3⟩ <;> rcases z4 with ⟨rfl, h4⟩ | ⟨rfl, h4⟩ <;>
    rcases z5 with ⟨rfl, h5⟩ | ⟨rfl, h5⟩ <;> rcases z6 with ⟨rfl, h6⟩ | ⟨rfl, h6⟩ <;>
    rcases z7 with ⟨rfl, h7⟩ | ⟨rfl, h7⟩ <;> rcases z8 with ⟨rfl, h8⟩ | ⟨rfl, h8⟩ <;>
    simp only [mul_one, mul_zero, zero_mul, one_mul, sub_zero] at e55 <;>
    (divrem_lift; omega)
