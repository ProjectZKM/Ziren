/-! ### The septic point and its chord addition (`ZirenDet/Septic.lean`) -/

/-- The added point's `x`. -/
def gX (w : W) : ZirenDet.Septic.V := ![w.v9, w.v10, w.v11, w.v12, w.v13, w.v14, w.v15]

/-- The added point's `y`. -/
def gY (w : W) : ZirenDet.Septic.V := ![w.v16, w.v17, w.v18, w.v19, w.v20, w.v21, w.v22]

/-- The digest received, `x`. -/
def gX1 (w : W) : ZirenDet.Septic.V := ![w.v30, w.v31, w.v32, w.v33, w.v34, w.v35, w.v36]

/-- The digest received, `y`. -/
def gY1 (w : W) : ZirenDet.Septic.V := ![w.v37, w.v38, w.v39, w.v40, w.v41, w.v42, w.v43]

/-- The witnessed inverse of `x − x₁`. -/
def gI (w : W) : ZirenDet.Septic.V := ![w.v44, w.v45, w.v46, w.v47, w.v48, w.v49, w.v50]

/-- The digest sent, `x`. -/
def gX3 (w : W) : ZirenDet.Septic.V := ![w.v51, w.v52, w.v53, w.v54, w.v55, w.v56, w.v57]

/-- The digest sent, `y`. -/
def gY3 (w : W) : ZirenDet.Septic.V := ![w.v58, w.v59, w.v60, w.v61, w.v62, w.v63, w.v64]

/-- The row's septic facts: `y² = x³ + 3zx − 3` for the added point, the chord identities of
the digest step and the inverse, with the flags, the `y₆` ranges and `x` from the message. -/
theorem row_spec (w : W) (hw : constraints w) :
    ZirenDet.Septic.sm (gY w) (gY w) = ZirenDet.Septic.cv (gX w) ∧
    ZirenDet.Septic.sm (gX1 w + gX w + gX3 w) (ZirenDet.Septic.sm (gX w - gX1 w) (gX w - gX1 w)) =
      ZirenDet.Septic.sm (gY w - gY1 w) (gY w - gY1 w) ∧
    ZirenDet.Septic.sm (gY1 w + gY3 w) (gX w - gX1 w) = ZirenDet.Septic.sm (gY w - gY1 w) (gX1 w - gX3 w) ∧
    ZirenDet.Septic.sm (gX w - gX1 w) (gI w) = ZirenDet.Septic.one ∧
    (w.v27 * (w.v27 - (1 : F))) = 0 ∧
    (w.v26 * (w.v26 - (1 : F))) = 0 ∧
    ((w.v27 + w.v26) - (1 : F)) = 0 ∧
    (w.v26 * (w.v22 - ((1 : F) + ((w.v23 + (w.v24 * (65536 : F))) + (w.v25 * (16777216 : F)))))) = 0 ∧
    (w.v27 * (w.v22 - ((-1056964608 : F) + ((w.v23 + (w.v24 * (65536 : F))) + (w.v25 * (16777216 : F)))))) = 0 ∧
    (w.v23).val ≤ 65535 ∧
    (w.v24).val ≤ 255 ∧
    (w.v25).val < 63 ∧
    (w.v9 - (w.v0 + (w.v7 * (65536 : F)))) = 0 ∧
    (w.v10 - w.v1) = 0 ∧
    (w.v11 - w.v2) = 0 ∧
    (w.v12 - w.v3) = 0 ∧
    (w.v13 - w.v4) = 0 ∧
    (w.v14 - w.v5) = 0 ∧
    (w.v15 - ((w.v6 * (256 : F)) + w.v8)) = 0 := by
  %OPEN_W%
  %OPEN_HW%
  dsimp only at *
  have s364 := sub_eq_zero.mp c54
  subst s364
  have s365 := sub_eq_zero.mp c55
  subst s365
  have s366 := sub_eq_zero.mp c56
  subst s366
  have s367 := sub_eq_zero.mp c57
  subst s367
  have s368 := sub_eq_zero.mp c58
  subst s368
  have s369 := sub_eq_zero.mp c59
  subst s369
  have s370 := sub_eq_zero.mp c60
  subst s370
  have s371 := sub_eq_zero.mp c61
  subst s371
  have s372 := sub_eq_zero.mp c62
  subst s372
  have s373 := sub_eq_zero.mp c63
  subst s373
  have s374 := sub_eq_zero.mp c64
  subst s374
  have s375 := sub_eq_zero.mp c65
  subst s375
  have s376 := sub_eq_zero.mp c66
  subst s376
  have s377 := sub_eq_zero.mp c67
  subst s377
  have s378 := sub_eq_zero.mp c68
  subst s378
  have s379 := sub_eq_zero.mp c69
  subst s379
  have s380 := sub_eq_zero.mp c70
  subst s380
  have s381 := sub_eq_zero.mp c71
  subst s381
  have s382 := sub_eq_zero.mp c72
  subst s382
  have s383 := sub_eq_zero.mp c73
  subst s383
  have s384 := sub_eq_zero.mp c74
  subst s384
  have s385 := sub_eq_zero.mp c75
  subst s385
  have s386 := sub_eq_zero.mp c76
  subst s386
  have s387 := sub_eq_zero.mp c77
  subst s387
  have s388 := sub_eq_zero.mp c78
  subst s388
  have s389 := sub_eq_zero.mp c79
  subst s389
  have s390 := sub_eq_zero.mp c80
  subst s390
  have s391 := sub_eq_zero.mp c81
  subst s391
  have s392 := sub_eq_zero.mp c82
  subst s392
  have s393 := sub_eq_zero.mp c83
  subst s393
  have s394 := sub_eq_zero.mp c84
  subst s394
  have s395 := sub_eq_zero.mp c85
  subst s395
  have s396 := sub_eq_zero.mp c86
  subst s396
  have s397 := sub_eq_zero.mp c87
  subst s397
  have s398 := sub_eq_zero.mp c88
  subst s398
  have s399 := sub_eq_zero.mp c89
  subst s399
  have s400 := sub_eq_zero.mp c90
  subst s400
  have s401 := sub_eq_zero.mp c91
  subst s401
  have s402 := sub_eq_zero.mp c92
  subst s402
  have s403 := sub_eq_zero.mp c93
  subst s403
  have s404 := sub_eq_zero.mp c94
  subst s404
  have s405 := sub_eq_zero.mp c95
  subst s405
  have s406 := sub_eq_zero.mp c96
  subst s406
  have s407 := sub_eq_zero.mp c97
  subst s407
  have s408 := sub_eq_zero.mp c98
  subst s408
  have s409 := sub_eq_zero.mp c99
  subst s409
  have s410 := sub_eq_zero.mp c100
  subst s410
  have s411 := sub_eq_zero.mp c101
  subst s411
  have s412 := sub_eq_zero.mp c102
  subst s412
  have s413 := sub_eq_zero.mp c103
  subst s413
  have s414 := sub_eq_zero.mp c104
  subst s414
  have s415 := sub_eq_zero.mp c105
  subst s415
  have s416 := sub_eq_zero.mp c106
  subst s416
  have s417 := sub_eq_zero.mp c107
  subst s417
  have s418 := sub_eq_zero.mp c108
  subst s418
  have s419 := sub_eq_zero.mp c109
  subst s419
  have s420 := sub_eq_zero.mp c110
  subst s420
  have s421 := sub_eq_zero.mp c111
  subst s421
  have s422 := sub_eq_zero.mp c112
  subst s422
  have s423 := sub_eq_zero.mp c113
  subst s423
  have s424 := sub_eq_zero.mp c114
  subst s424
  have s425 := sub_eq_zero.mp c115
  subst s425
  have s426 := sub_eq_zero.mp c116
  subst s426
  have s427 := sub_eq_zero.mp c117
  subst s427
  have s428 := sub_eq_zero.mp c118
  subst s428
  have s429 := sub_eq_zero.mp c119
  subst s429
  have s430 := sub_eq_zero.mp c120
  subst s430
  have s431 := sub_eq_zero.mp c121
  subst s431
  have s432 := sub_eq_zero.mp c122
  subst s432
  have s433 := sub_eq_zero.mp c123
  subst s433
  have s434 := sub_eq_zero.mp c124
  subst s434
  have s435 := sub_eq_zero.mp c125
  subst s435
  have s436 := sub_eq_zero.mp c126
  subst s436
  have s437 := sub_eq_zero.mp c127
  subst s437
  have s438 := sub_eq_zero.mp c128
  subst s438
  have s439 := sub_eq_zero.mp c129
  subst s439
  have s440 := sub_eq_zero.mp c130
  subst s440
  have s441 := sub_eq_zero.mp c131
  subst s441
  have s442 := sub_eq_zero.mp c132
  subst s442
  have s443 := sub_eq_zero.mp c133
  subst s443
  have s444 := sub_eq_zero.mp c134
  subst s444
  have s445 := sub_eq_zero.mp c135
  subst s445
  have s446 := sub_eq_zero.mp c136
  subst s446
  have s447 := sub_eq_zero.mp c137
  subst s447
  have s448 := sub_eq_zero.mp c138
  subst s448
  have s449 := sub_eq_zero.mp c139
  subst s449
  have s450 := sub_eq_zero.mp c140
  subst s450
  have s451 := sub_eq_zero.mp c141
  subst s451
  have s452 := sub_eq_zero.mp c142
  subst s452
  have s453 := sub_eq_zero.mp c143
  subst s453
  have s454 := sub_eq_zero.mp c150
  subst s454
  refine ⟨?_, ?_, ?_, ?_, c0, c1, c2, c17, c18, c145, c146, c149, c3, c4, c5, c6, c7, c8, c9⟩
  · refine ZirenDet.Septic.V_ext ?_ ?_ ?_ ?_ ?_ ?_ ?_
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c10
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c11
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c12
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c13
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c14
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c15
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c16
  · refine ZirenDet.Septic.V_ext ?_ ?_ ?_ ?_ ?_ ?_ ?_
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c33
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c34
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c35
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c36
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c37
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c38
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c39
  · refine ZirenDet.Septic.V_ext ?_ ?_ ?_ ?_ ?_ ?_ ?_
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c40
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c41
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c42
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c43
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c44
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c45
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c46
  · refine ZirenDet.Septic.V_ext ?_ ?_ ?_ ?_ ?_ ?_ ?_
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c47
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c48
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c49
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c50
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c51
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c52
    · simp only [ZirenDet.Septic.sm, ZirenDet.Septic.cv, ZirenDet.Septic.one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
      linear_combination c53

/-- The added point's `y` and the digest sent are determined by the row's inputs. -/
theorem gadget_det (w w' : W) (hw : constraints w) (hw' : constraints w')
    (hin : inputs w = inputs w') : w.v16 = w'.v16 ∧ w.v17 = w'.v17 ∧ w.v18 = w'.v18 ∧ w.v19 = w'.v19 ∧ w.v20 = w'.v20 ∧ w.v21 = w'.v21 ∧ w.v22 = w'.v22 ∧ w.v51 = w'.v51 ∧ w.v52 = w'.v52 ∧ w.v53 = w'.v53 ∧ w.v54 = w'.v54 ∧ w.v55 = w'.v55 ∧ w.v56 = w'.v56 ∧ w.v57 = w'.v57 ∧ w.v58 = w'.v58 ∧ w.v59 = w'.v59 ∧ w.v60 = w'.v60 ∧ w.v61 = w'.v61 ∧ w.v62 = w'.v62 ∧ w.v63 = w'.v63 ∧ w.v64 = w'.v64 := by
  obtain ⟨L, SX, SY, DI, B27, B26, FS, R26, R27, H23, H24, H25, E9, E10, E11, E12, E13, E14, E15⟩ := row_spec w hw
  obtain ⟨L', SX', SY', DI', B27', B26', FS', R26', R27', H23', H24', H25', E9', E10', E11', E12', E13', E14', E15'⟩ := row_spec w' hw'
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
  have i27 := congrArg (·[7]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i27
  have i26 := congrArg (·[8]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i26
  have i7 := congrArg (·[9]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i7
  have i29 := congrArg (·[10]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i29
  have i30 := congrArg (·[11]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i30
  have i31 := congrArg (·[12]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i31
  have i32 := congrArg (·[13]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i32
  have i33 := congrArg (·[14]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i33
  have i34 := congrArg (·[15]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i34
  have i35 := congrArg (·[16]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i35
  have i36 := congrArg (·[17]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i36
  have i37 := congrArg (·[18]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i37
  have i38 := congrArg (·[19]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i38
  have i39 := congrArg (·[20]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i39
  have i40 := congrArg (·[21]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i40
  have i41 := congrArg (·[22]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i41
  have i42 := congrArg (·[23]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i42
  have i43 := congrArg (·[24]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i43
  have i8 := congrArg (·[25]?) hin
  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at i8
  have hX : gX w = gX w' := by
    refine ZirenDet.Septic.V_ext ?_ ?_ ?_ ?_ ?_ ?_ ?_ <;> simp only [gX, gX1, gY1, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
    · linear_combination E9 - E9' + i0 + 65536 * i7
    · linear_combination E10 - E10' + i1
    · linear_combination E11 - E11' + i2
    · linear_combination E12 - E12' + i3
    · linear_combination E13 - E13' + i4
    · linear_combination E14 - E14' + i5
    · linear_combination E15 - E15' + 256 * i6 + i8
  have hgX1 : gX1 w = gX1 w' := by
    refine ZirenDet.Septic.V_ext ?_ ?_ ?_ ?_ ?_ ?_ ?_ <;> simp only [gX, gX1, gY1, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
    · exact i30
    · exact i31
    · exact i32
    · exact i33
    · exact i34
    · exact i35
    · exact i36
  have hgY1 : gY1 w = gY1 w' := by
    refine ZirenDet.Septic.V_ext ?_ ?_ ?_ ?_ ?_ ?_ ?_ <;> simp only [gX, gX1, gY1, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]
    · exact i37
    · exact i38
    · exact i39
    · exact i40
    · exact i41
    · exact i42
    · exact i43
  have hsq : ZirenDet.Septic.sm (gY w) (gY w) = ZirenDet.Septic.sm (gY w') (gY w') := by rw [L, L', hX]
  have hY : gY w = gY w' := by
    rcases ZirenDet.Septic.sq_unique hsq with h | h
    · exact h
    · exfalso
      have h6 : w.v22 = -w'.v22 := congrFun h 6
      rcases mul_eq_zero.mp B26 with h26 | h26
      · have h26' : w'.v26 = 0 := by rw [← i26]; exact h26
        have h27 : w.v27 = 1 := by linear_combination FS - h26
        have h27' : w'.v27 = 1 := by linear_combination FS' - h26'
        have ha : w.v22 = (-1056964608 : F) + ((w.v23 + (w.v24 * (65536 : F))) + (w.v25 * (16777216 : F))) := by
          rw [h27, one_mul, sub_eq_zero] at R27; exact R27
        have hb : w'.v22 = (-1056964608 : F) + ((w'.v23 + (w'.v24 * (65536 : F))) + (w'.v25 * (16777216 : F))) := by
          rw [h27', one_mul, sub_eq_zero] at R27'; exact R27'
        exact ZirenDet.Septic.y6_send ha hb H23 H24 H25 H23' H24' H25' h6
      · have h26 : w.v26 = 1 := sub_eq_zero.mp h26
        have h26' : w'.v26 = 1 := by rw [← i26]; exact h26
        have ha : w.v22 = (1 : F) + ((w.v23 + (w.v24 * (65536 : F))) + (w.v25 * (16777216 : F))) := by
          rw [h26, one_mul, sub_eq_zero] at R26; exact R26
        have hb : w'.v22 = (1 : F) + ((w'.v23 + (w'.v24 * (65536 : F))) + (w'.v25 * (16777216 : F))) := by
          rw [h26', one_mul, sub_eq_zero] at R26'; exact R26'
        exact ZirenDet.Septic.y6_recv ha hb H23 H24 H25 H23' H24' H25' h6
  rw [← hX, ← hY, ← hgX1, ← hgY1] at SX'
  rw [← hX, ← hY, ← hgX1, ← hgY1] at SY'
  rw [← hX, ← hgX1] at DI'
  obtain ⟨h3x, h3y⟩ := ZirenDet.Septic.chord_unique SX SY DI SX' SY' DI'
  have hYc : (![w.v16, w.v17, w.v18, w.v19, w.v20, w.v21, w.v22] : ZirenDet.Septic.V) = ![w'.v16, w'.v17, w'.v18, w'.v19, w'.v20, w'.v21, w'.v22] := hY
  obtain ⟨a16, a17, a18, a19, a20, a21, a22⟩ := ZirenDet.Septic.V_components hYc
  have h3xc : (![w.v51, w.v52, w.v53, w.v54, w.v55, w.v56, w.v57] : ZirenDet.Septic.V) = ![w'.v51, w'.v52, w'.v53, w'.v54, w'.v55, w'.v56, w'.v57] := h3x
  obtain ⟨a51, a52, a53, a54, a55, a56, a57⟩ := ZirenDet.Septic.V_components h3xc
  have h3yc : (![w.v58, w.v59, w.v60, w.v61, w.v62, w.v63, w.v64] : ZirenDet.Septic.V) = ![w'.v58, w'.v59, w'.v60, w'.v61, w'.v62, w'.v63, w'.v64] := h3y
  obtain ⟨a58, a59, a60, a61, a62, a63, a64⟩ := ZirenDet.Septic.V_components h3yc
  exact ⟨a16, a17, a18, a19, a20, a21, a22, a51, a52, a53, a54, a55, a56, a57, a58, a59, a60, a61, a62, a63, a64⟩
