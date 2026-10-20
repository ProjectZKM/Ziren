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
    (w.v15 - ((1 : F) + ((w.v16 + (w.v17 * (65536 : F))) + (w.v18 * (16777216 : F))))) = 0 ∧
    (w.v16).val ≤ 65535 ∧
    (w.v17).val ≤ 255 ∧
    (w.v18).val < 63 ∧
    (w.v439 - (w.v2 - (w.v0 * (65536 : F)))) = 0 ∧
    (w.v440 - ((w.v8 - w.v1) * ((256 : F)⁻¹))) = 0 := by
  %OPEN_W%
  %OPEN_HW%
  dsimp only at *
  have s348 := sub_eq_zero.mp c50
  subst s348
  have s349 := sub_eq_zero.mp c51
  subst s349
  have s350 := sub_eq_zero.mp c52
  subst s350
  have s351 := sub_eq_zero.mp c53
  subst s351
  have s352 := sub_eq_zero.mp c54
  subst s352
  have s353 := sub_eq_zero.mp c55
  subst s353
  have s354 := sub_eq_zero.mp c56
  subst s354
  have s355 := sub_eq_zero.mp c57
  subst s355
  have s356 := sub_eq_zero.mp c58
  subst s356
  have s357 := sub_eq_zero.mp c59
  subst s357
  have s358 := sub_eq_zero.mp c60
  subst s358
  have s359 := sub_eq_zero.mp c61
  subst s359
  have s360 := sub_eq_zero.mp c62
  subst s360
  have s361 := sub_eq_zero.mp c63
  subst s361
  have s362 := sub_eq_zero.mp c64
  subst s362
  have s363 := sub_eq_zero.mp c65
  subst s363
  have s364 := sub_eq_zero.mp c66
  subst s364
  have s365 := sub_eq_zero.mp c67
  subst s365
  have s366 := sub_eq_zero.mp c68
  subst s366
  have s367 := sub_eq_zero.mp c69
  subst s367
  have s368 := sub_eq_zero.mp c70
  subst s368
  have s369 := sub_eq_zero.mp c71
  subst s369
  have s370 := sub_eq_zero.mp c72
  subst s370
  have s371 := sub_eq_zero.mp c73
  subst s371
  have s372 := sub_eq_zero.mp c74
  subst s372
  have s373 := sub_eq_zero.mp c75
  subst s373
  have s374 := sub_eq_zero.mp c76
  subst s374
  have s375 := sub_eq_zero.mp c77
  subst s375
  have s376 := sub_eq_zero.mp c78
  subst s376
  have s377 := sub_eq_zero.mp c79
  subst s377
  have s378 := sub_eq_zero.mp c80
  subst s378
  have s379 := sub_eq_zero.mp c81
  subst s379
  have s380 := sub_eq_zero.mp c82
  subst s380
  have s381 := sub_eq_zero.mp c83
  subst s381
  have s382 := sub_eq_zero.mp c84
  subst s382
  have s383 := sub_eq_zero.mp c85
  subst s383
  have s384 := sub_eq_zero.mp c86
  subst s384
  have s385 := sub_eq_zero.mp c87
  subst s385
  have s386 := sub_eq_zero.mp c88
  subst s386
  have s387 := sub_eq_zero.mp c89
  subst s387
  have s388 := sub_eq_zero.mp c90
  subst s388
  have s389 := sub_eq_zero.mp c91
  subst s389
  have s390 := sub_eq_zero.mp c92
  subst s390
  have s391 := sub_eq_zero.mp c93
  subst s391
  have s392 := sub_eq_zero.mp c94
  subst s392
  have s393 := sub_eq_zero.mp c95
  subst s393
  have s394 := sub_eq_zero.mp c96
  subst s394
  have s395 := sub_eq_zero.mp c97
  subst s395
  have s396 := sub_eq_zero.mp c98
  subst s396
  have s397 := sub_eq_zero.mp c99
  subst s397
  have s398 := sub_eq_zero.mp c100
  subst s398
  have s399 := sub_eq_zero.mp c101
  subst s399
  have s400 := sub_eq_zero.mp c102
  subst s400
  have s401 := sub_eq_zero.mp c103
  subst s401
  have s402 := sub_eq_zero.mp c104
  subst s402
  have s403 := sub_eq_zero.mp c105
  subst s403
  have s404 := sub_eq_zero.mp c106
  subst s404
  have s405 := sub_eq_zero.mp c107
  subst s405
  have s406 := sub_eq_zero.mp c108
  subst s406
  have s407 := sub_eq_zero.mp c109
  subst s407
  have s408 := sub_eq_zero.mp c110
  subst s408
  have s409 := sub_eq_zero.mp c111
  subst s409
  have s410 := sub_eq_zero.mp c112
  subst s410
  have s411 := sub_eq_zero.mp c113
  subst s411
  have s412 := sub_eq_zero.mp c114
  subst s412
  have s413 := sub_eq_zero.mp c115
  subst s413
  have s414 := sub_eq_zero.mp c116
  subst s414
  have s415 := sub_eq_zero.mp c117
  subst s415
  have s416 := sub_eq_zero.mp c118
  subst s416
  have s417 := sub_eq_zero.mp c119
  subst s417
  have s418 := sub_eq_zero.mp c120
  subst s418
  have s419 := sub_eq_zero.mp c121
  subst s419
  have s420 := sub_eq_zero.mp c122
  subst s420
  have s421 := sub_eq_zero.mp c123
  subst s421
  have s422 := sub_eq_zero.mp c124
  subst s422
  have s423 := sub_eq_zero.mp c125
  subst s423
  have s424 := sub_eq_zero.mp c126
  subst s424
  have s425 := sub_eq_zero.mp c127
  subst s425
  have s426 := sub_eq_zero.mp c128
  subst s426
  have s427 := sub_eq_zero.mp c129
  subst s427
  have s428 := sub_eq_zero.mp c130
  subst s428
  have s429 := sub_eq_zero.mp c131
  subst s429
  have s430 := sub_eq_zero.mp c132
  subst s430
  have s431 := sub_eq_zero.mp c133
  subst s431
  have s432 := sub_eq_zero.mp c134
  subst s432
  have s433 := sub_eq_zero.mp c135
  subst s433
  have s434 := sub_eq_zero.mp c136
  subst s434
  have s435 := sub_eq_zero.mp c137
  subst s435
  have s436 := sub_eq_zero.mp c138
  subst s436
  have s437 := sub_eq_zero.mp c139
  subst s437
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
      have ha : w.v15 = (1 : F) + ((w.v16 + (w.v17 * (65536 : F))) + (w.v18 * (16777216 : F))) := sub_eq_zero.mp R
      have hb : w'.v15 = (1 : F) + ((w'.v16 + (w'.v17 * (65536 : F))) + (w'.v18 * (16777216 : F))) := sub_eq_zero.mp R'
      exact ZirenDet.Septic.y6_recv ha hb H16 H17 H18 H16' H17' H18' h6
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
