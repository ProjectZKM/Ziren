/-- The added point's `x`. -/
def gX (w : W) : ZirenDet.Septic.V := ![w.v2, w.v3, w.v4, w.v5, w.v6, w.v7, w.v8]

/-- The added point's `y`. -/
def gY (w : W) : ZirenDet.Septic.V := ![w.v9, w.v10, w.v11, w.v12, w.v13, w.v14, w.v15]

/-- The digest received, `x`. -/
def gX1 (w : W) : ZirenDet.Septic.V := ![w.v22, w.v23, w.v24, w.v25, w.v26, w.v27, w.v28]

/-- The digest received, `y`. -/
def gY1 (w : W) : ZirenDet.Septic.V := ![w.v29, w.v30, w.v31, w.v32, w.v33, w.v34, w.v35]

/-- The witnessed inverse of `x − x₁`. -/
def gI (w : W) : ZirenDet.Septic.V := ![w.v36, w.v37, w.v38, w.v39, w.v40, w.v41, w.v42]

/-- The digest sent, `x`. -/
def gX3 (w : W) : ZirenDet.Septic.V := ![w.v43, w.v44, w.v45, w.v46, w.v47, w.v48, w.v49]

/-- The digest sent, `y`. -/
def gY3 (w : W) : ZirenDet.Septic.V := ![w.v50, w.v51, w.v52, w.v53, w.v54, w.v55, w.v56]

/-- The row's septic facts: `y² = x³ + 3zx − 3` for the added point, the chord identities of
the digest step and the inverse, with the `y₆` range and the reified inputs of `x[0]`, `x[6]`. -/
theorem row_spec (w : W) (hw : constraints w) :
    ZirenDet.Septic.sm (gY w) (gY w) = ZirenDet.Septic.cv (gX w) ∧
    ZirenDet.Septic.sm (gX1 w + gX w + gX3 w) (ZirenDet.Septic.sm (gX w - gX1 w) (gX w - gX1 w)) =
      ZirenDet.Septic.sm (gY w - gY1 w) (gY w - gY1 w) ∧
    ZirenDet.Septic.sm (gY1 w + gY3 w) (gX w - gX1 w) = ZirenDet.Septic.sm (gY w - gY1 w) (gX1 w - gX3 w) ∧
    ZirenDet.Septic.sm (gX w - gX1 w) (gI w) = ZirenDet.Septic.one ∧
    (w.v8 - ((((w.v8 - w.v1) * ((256 : F)⁻¹)) * (256 : F)) + w.v1)) = 0 ∧
    (w.v15 - ((-1056964608 : F) + ((w.v16 + (w.v17 * (65536 : F))) + (w.v18 * (16777216 : F))))) = 0 ∧
    (w.v16).val ≤ 65535 ∧
    (w.v17).val ≤ 255 ∧
    (w.v18).val < 63 ∧
    (w.v532 - (w.v2 - (w.v0 * (65536 : F)))) = 0 ∧
    (w.v533 - ((w.v8 - w.v1) * ((256 : F)⁻¹))) = 0 := by
  %OPEN_W%
  %OPEN_HW%
  dsimp only at *
  have s441 := sub_eq_zero.mp c50
  subst s441
  have s442 := sub_eq_zero.mp c51
  subst s442
  have s443 := sub_eq_zero.mp c52
  subst s443
  have s444 := sub_eq_zero.mp c53
  subst s444
  have s445 := sub_eq_zero.mp c54
  subst s445
  have s446 := sub_eq_zero.mp c55
  subst s446
  have s447 := sub_eq_zero.mp c56
  subst s447
  have s448 := sub_eq_zero.mp c57
  subst s448
  have s449 := sub_eq_zero.mp c58
  subst s449
  have s450 := sub_eq_zero.mp c59
  subst s450
  have s451 := sub_eq_zero.mp c60
  subst s451
  have s452 := sub_eq_zero.mp c61
  subst s452
  have s453 := sub_eq_zero.mp c62
  subst s453
  have s454 := sub_eq_zero.mp c63
  subst s454
  have s455 := sub_eq_zero.mp c64
  subst s455
  have s456 := sub_eq_zero.mp c65
  subst s456
  have s457 := sub_eq_zero.mp c66
  subst s457
  have s458 := sub_eq_zero.mp c67
  subst s458
  have s459 := sub_eq_zero.mp c68
  subst s459
  have s460 := sub_eq_zero.mp c69
  subst s460
  have s461 := sub_eq_zero.mp c70
  subst s461
  have s462 := sub_eq_zero.mp c71
  subst s462
  have s463 := sub_eq_zero.mp c72
  subst s463
  have s464 := sub_eq_zero.mp c73
  subst s464
  have s465 := sub_eq_zero.mp c74
  subst s465
  have s466 := sub_eq_zero.mp c75
  subst s466
  have s467 := sub_eq_zero.mp c76
  subst s467
  have s468 := sub_eq_zero.mp c77
  subst s468
  have s469 := sub_eq_zero.mp c78
  subst s469
  have s470 := sub_eq_zero.mp c79
  subst s470
  have s471 := sub_eq_zero.mp c80
  subst s471
  have s472 := sub_eq_zero.mp c81
  subst s472
  have s473 := sub_eq_zero.mp c82
  subst s473
  have s474 := sub_eq_zero.mp c83
  subst s474
  have s475 := sub_eq_zero.mp c84
  subst s475
  have s476 := sub_eq_zero.mp c85
  subst s476
  have s477 := sub_eq_zero.mp c86
  subst s477
  have s478 := sub_eq_zero.mp c87
  subst s478
  have s479 := sub_eq_zero.mp c88
  subst s479
  have s480 := sub_eq_zero.mp c89
  subst s480
  have s481 := sub_eq_zero.mp c90
  subst s481
  have s482 := sub_eq_zero.mp c91
  subst s482
  have s483 := sub_eq_zero.mp c92
  subst s483
  have s484 := sub_eq_zero.mp c93
  subst s484
  have s485 := sub_eq_zero.mp c94
  subst s485
  have s486 := sub_eq_zero.mp c95
  subst s486
  have s487 := sub_eq_zero.mp c96
  subst s487
  have s488 := sub_eq_zero.mp c97
  subst s488
  have s489 := sub_eq_zero.mp c98
  subst s489
  have s490 := sub_eq_zero.mp c99
  subst s490
  have s491 := sub_eq_zero.mp c100
  subst s491
  have s492 := sub_eq_zero.mp c101
  subst s492
  have s493 := sub_eq_zero.mp c102
  subst s493
  have s494 := sub_eq_zero.mp c103
  subst s494
  have s495 := sub_eq_zero.mp c104
  subst s495
  have s496 := sub_eq_zero.mp c105
  subst s496
  have s497 := sub_eq_zero.mp c106
  subst s497
  have s498 := sub_eq_zero.mp c107
  subst s498
  have s499 := sub_eq_zero.mp c108
  subst s499
  have s500 := sub_eq_zero.mp c109
  subst s500
  have s501 := sub_eq_zero.mp c110
  subst s501
  have s502 := sub_eq_zero.mp c111
  subst s502
  have s503 := sub_eq_zero.mp c112
  subst s503
  have s504 := sub_eq_zero.mp c113
  subst s504
  have s505 := sub_eq_zero.mp c114
  subst s505
  have s506 := sub_eq_zero.mp c115
  subst s506
  have s507 := sub_eq_zero.mp c116
  subst s507
  have s508 := sub_eq_zero.mp c117
  subst s508
  have s509 := sub_eq_zero.mp c118
  subst s509
  have s510 := sub_eq_zero.mp c119
  subst s510
  have s511 := sub_eq_zero.mp c120
  subst s511
  have s512 := sub_eq_zero.mp c121
  subst s512
  have s513 := sub_eq_zero.mp c122
  subst s513
  have s514 := sub_eq_zero.mp c123
  subst s514
  have s515 := sub_eq_zero.mp c124
  subst s515
  have s516 := sub_eq_zero.mp c125
  subst s516
  have s517 := sub_eq_zero.mp c126
  subst s517
  have s518 := sub_eq_zero.mp c127
  subst s518
  have s519 := sub_eq_zero.mp c128
  subst s519
  have s520 := sub_eq_zero.mp c129
  subst s520
  have s521 := sub_eq_zero.mp c130
  subst s521
  have s522 := sub_eq_zero.mp c131
  subst s522
  have s523 := sub_eq_zero.mp c132
  subst s523
  have s524 := sub_eq_zero.mp c133
  subst s524
  have s525 := sub_eq_zero.mp c134
  subst s525
  have s526 := sub_eq_zero.mp c135
  subst s526
  have s527 := sub_eq_zero.mp c136
  subst s527
  have s528 := sub_eq_zero.mp c137
  subst s528
  have s529 := sub_eq_zero.mp c138
  subst s529
  have s530 := sub_eq_zero.mp c139
  subst s530
  refine ⟨?_, ?_, ?_, ?_, c6, c14, c141, c142, c145, c147, c148⟩
  · refine ZirenDet.Septic.V_ext ?_ ?_ ?_ ?_ ?_ ?_ ?_
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c7
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c8
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c9
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c10
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c11
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c12
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c13
  · refine ZirenDet.Septic.V_ext ?_ ?_ ?_ ?_ ?_ ?_ ?_
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c29
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c30
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c31
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c32
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c33
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c34
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c35
  · refine ZirenDet.Septic.V_ext ?_ ?_ ?_ ?_ ?_ ?_ ?_
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c36
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c37
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c38
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c39
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c40
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c41
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c42
  · refine ZirenDet.Septic.V_ext ?_ ?_ ?_ ?_ ?_ ?_ ?_
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c43
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c44
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c45
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c46
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c47
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c48
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c49

/-- The added point's `y` and the digest sent are determined by the row's inputs. -/
theorem gadget_det (w w' : W) (hw : constraints w) (hw' : constraints w')
    (hin : inputs w = inputs w') : w.v9 = w'.v9 ∧ w.v10 = w'.v10 ∧ w.v11 = w'.v11 ∧ w.v12 = w'.v12 ∧ w.v13 = w'.v13 ∧ w.v14 = w'.v14 ∧ w.v15 = w'.v15 ∧ w.v43 = w'.v43 ∧ w.v44 = w'.v44 ∧ w.v45 = w'.v45 ∧ w.v46 = w'.v46 ∧ w.v47 = w'.v47 ∧ w.v48 = w'.v48 ∧ w.v49 = w'.v49 ∧ w.v50 = w'.v50 ∧ w.v51 = w'.v51 ∧ w.v52 = w'.v52 ∧ w.v53 = w'.v53 ∧ w.v54 = w'.v54 ∧ w.v55 = w'.v55 ∧ w.v56 = w'.v56 := by
  obtain ⟨L, SX, SY, DI, T6, R, H16, H17, H18, E439, E440⟩ := row_spec w hw
  obtain ⟨L', SX', SY', DI', T6', R', H16', H17', H18', E439', E440'⟩ := row_spec w' hw'
  have i0 := congrArg (·[0]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i0
  have i1 := congrArg (·[1]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i1
  have i2 := congrArg (·[2]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i2
  have i3 := congrArg (·[3]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i3
  have i4 := congrArg (·[4]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i4
  have i5 := congrArg (·[5]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i5
  have i6 := congrArg (·[6]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i6
  have i7 := congrArg (·[7]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i7
  have i8 := congrArg (·[8]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i8
  have i9 := congrArg (·[9]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i9
  have i10 := congrArg (·[10]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i10
  have i11 := congrArg (·[11]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i11
  have i12 := congrArg (·[12]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i12
  have i13 := congrArg (·[13]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i13
  have i14 := congrArg (·[14]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i14
  have i15 := congrArg (·[15]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i15
  have i16 := congrArg (·[16]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i16
  have i17 := congrArg (·[17]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i17
  have i18 := congrArg (·[18]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i18
  have i19 := congrArg (·[19]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i19
  have i20 := congrArg (·[20]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i20
  have i21 := congrArg (·[21]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i21
  have i22 := congrArg (·[22]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i22
  have i23 := congrArg (·[23]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i23
  have hX : gX w = gX w' := by
    refine ZirenDet.Septic.V_ext ?_ ?_ ?_ ?_ ?_ ?_ ?_ <;> simp only [gX, gX1, gY1, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
    · linear_combination -E439 + E439' + i0 + 65536 * i7
    · exact i1
    · exact i2
    · exact i3
    · exact i4
    · exact i5
    · linear_combination T6 - T6' - 256 * E440 + 256 * E440' + 256 * i6 + i23
  have hgX1 : gX1 w = gX1 w' := by
    refine ZirenDet.Septic.V_ext ?_ ?_ ?_ ?_ ?_ ?_ ?_ <;> simp only [gX, gX1, gY1, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
    · exact i9
    · exact i10
    · exact i11
    · exact i12
    · exact i13
    · exact i14
    · exact i15
  have hgY1 : gY1 w = gY1 w' := by
    refine ZirenDet.Septic.V_ext ?_ ?_ ?_ ?_ ?_ ?_ ?_ <;> simp only [gX, gX1, gY1, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
    · exact i16
    · exact i17
    · exact i18
    · exact i19
    · exact i20
    · exact i21
    · exact i22
  have hsq : ZirenDet.Septic.sm (gY w) (gY w) = ZirenDet.Septic.sm (gY w') (gY w') := by rw [L, L', hX]
  have hY : gY w = gY w' := by
    rcases ZirenDet.Septic.sq_unique hsq with h | h
    · exact h
    · exfalso
      have h6 : w.v15 = -w'.v15 := congrFun h 6
      have ha : w.v15 = (-1056964608 : F) + ((w.v16 + (w.v17 * (65536 : F))) + (w.v18 * (16777216 : F))) := sub_eq_zero.mp R
      have hb : w'.v15 = (-1056964608 : F) + ((w'.v16 + (w'.v17 * (65536 : F))) + (w'.v18 * (16777216 : F))) := sub_eq_zero.mp R'
      exact ZirenDet.Septic.y6_send ha hb H16 H17 H18 H16' H17' H18' h6
  rw [← hX, ← hY, ← hgX1, ← hgY1] at SX'
  rw [← hX, ← hY, ← hgX1, ← hgY1] at SY'
  rw [← hX, ← hgX1] at DI'
  obtain ⟨h3x, h3y⟩ := ZirenDet.Septic.chord_unique SX SY DI SX' SY' DI'
  have hYc : (![w.v9, w.v10, w.v11, w.v12, w.v13, w.v14, w.v15] : ZirenDet.Septic.V) = ![w'.v9, w'.v10, w'.v11, w'.v12, w'.v13, w'.v14, w'.v15] := hY
  obtain ⟨a9, a10, a11, a12, a13, a14, a15⟩ := ZirenDet.Septic.V_components hYc
  have h3xc : (![w.v43, w.v44, w.v45, w.v46, w.v47, w.v48, w.v49] : ZirenDet.Septic.V) = ![w'.v43, w'.v44, w'.v45, w'.v46, w'.v47, w'.v48, w'.v49] := h3x
  obtain ⟨a43, a44, a45, a46, a47, a48, a49⟩ := ZirenDet.Septic.V_components h3xc
  have h3yc : (![w.v50, w.v51, w.v52, w.v53, w.v54, w.v55, w.v56] : ZirenDet.Septic.V) = ![w'.v50, w'.v51, w'.v52, w'.v53, w'.v54, w'.v55, w'.v56] := h3y
  obtain ⟨a50, a51, a52, a53, a54, a55, a56⟩ := ZirenDet.Septic.V_components h3yc
  exact ⟨a9, a10, a11, a12, a13, a14, a15, a43, a44, a45, a46, a47, a48, a49, a50, a51, a52, a53, a54, a55, a56⟩
