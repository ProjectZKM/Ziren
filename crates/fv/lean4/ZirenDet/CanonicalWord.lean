import ZirenDet.Replay
open ZirenDet
set_option maxHeartbeats 0
set_option linter.unusedVariables false

/-!
# Canonical words

The range checker of a word (`KoalaBearWordRangeChecker`) admits the byte strings whose value
is below `p = 127·2²⁴ + 1`.  Two admitted strings with the same field value are the same
string, and their flags agree.
-/

namespace ZirenDet.CanonicalWord

/-- A byte ranged under two gates that sum to one is a byte. -/
theorem gated_bound {b g : F} (h1 : (b * g).val ≤ 255) (h0 : (b * (1 - g)).val ≤ 255)
    (hg : g * (g - 1) = 0) : b.val ≤ 255 := by
  rcases ZirenDet.bit_cases hg with rfl | rfl
  · simpa using h0
  · simpa using h1

/-- [`gated_bound`] with the gates in the other order. -/
theorem gated_bound' {b g : F} (h0 : (b * (1 - g)).val ≤ 255) (h1 : (b * g).val ≤ 255)
    (hg : g * (g - 1) = 0) : b.val ≤ 255 :=
  gated_bound h1 h0 hg

/-- One admitted byte string, on integers: the top byte is below 127, or it is 127 and the low
bytes vanish. -/
theorem side {a0 a1 a2 a3 z : F} (h0 : a0.val ≤ 255) (h1 : a1.val ≤ 255) (h2 : a2.val ≤ 255)
    (hz : z * (z - 1) = 0) (ht : z * (a3 - 127) = 0) (hl : z * (a0 + a1 + a2) = 0)
    (hr : (a3 * (1 - z)).val < 127) :
    ∃ n0 n1 n2 n3 : ℤ, a0 = (n0 : F) ∧ a1 = (n1 : F) ∧ a2 = (n2 : F) ∧ a3 = (n3 : F) ∧
      0 ≤ n0 ∧ n0 ≤ 255 ∧ 0 ≤ n1 ∧ n1 ≤ 255 ∧ 0 ≤ n2 ∧ n2 ≤ 255 ∧ 0 ≤ n3 ∧
      ((z = 0 ∧ n3 < 127) ∨ (z = 1 ∧ n3 = 127 ∧ n0 = 0 ∧ n1 = 0 ∧ n2 = 0)) := by
  obtain ⟨n0, p0, q0, rfl⟩ := ZirenDet.lift_le a0 h0
  obtain ⟨n1, p1, q1, rfl⟩ := ZirenDet.lift_le a1 h1
  obtain ⟨n2, p2, q2, rfl⟩ := ZirenDet.lift_le a2 h2
  have q0' : n0 ≤ 255 := by exact_mod_cast q0
  have q1' : n1 ≤ 255 := by exact_mod_cast q1
  have q2' : n2 ≤ 255 := by exact_mod_cast q2
  rcases ZirenDet.bit_cases hz with rfl | rfl
  · simp only [sub_zero, mul_one] at hr
    obtain ⟨n3, p3, q3, rfl⟩ := ZirenDet.lift_lt a3 hr
    exact ⟨n0, n1, n2, n3, rfl, rfl, rfl, rfl, p0, q0', p1, q1', p2, q2', p3,
      Or.inl ⟨rfl, by exact_mod_cast q3⟩⟩
  · simp only [one_mul] at ht hl
    have e3 : a3 = ((127 : ℤ) : F) := by
      have : a3 = 127 := by linear_combination ht
      rw [this]; norm_cast
    have hs : (((n0 + n1 + n2 : ℤ)) : F) = ((0 : ℤ) : F) := by
      push_cast; linear_combination hl
    obtain ⟨k, hk⟩ := ZirenDet.cast_eq_iff_dvd.mp hs
    refine ⟨n0, n1, n2, 127, rfl, rfl, rfl, e3, p0, q0', p1, q1', p2, q2', by norm_num,
      Or.inr ⟨rfl, rfl, ?_, ?_, ?_⟩⟩ <;> omega

/-- Two admitted byte strings of one field value are equal, flags included. -/
theorem inj {a0 a1 a2 a3 za c0 c1 c2 c3 zc : F}
    (ha0 : a0.val ≤ 255) (ha1 : a1.val ≤ 255) (ha2 : a2.val ≤ 255)
    (hza : za * (za - 1) = 0) (hta : za * (a3 - 127) = 0) (hla : za * (a0 + a1 + a2) = 0)
    (hra : (a3 * (1 - za)).val < 127)
    (hc0 : c0.val ≤ 255) (hc1 : c1.val ≤ 255) (hc2 : c2.val ≤ 255)
    (hzc : zc * (zc - 1) = 0) (htc : zc * (c3 - 127) = 0) (hlc : zc * (c0 + c1 + c2) = 0)
    (hrc : (c3 * (1 - zc)).val < 127)
    (hw : a0 + a1 * 256 + a2 * 65536 + a3 * 16777216 = c0 + c1 * 256 + c2 * 65536 + c3 * 16777216) :
    a0 = c0 ∧ a1 = c1 ∧ a2 = c2 ∧ a3 = c3 ∧ za = zc := by
  obtain ⟨n0, n1, n2, n3, rfl, rfl, rfl, rfl, _, _, _, _, _, _, _, sa⟩ :=
    side ha0 ha1 ha2 hza hta hla hra
  obtain ⟨m0, m1, m2, m3, rfl, rfl, rfl, rfl, _, _, _, _, _, _, _, sc⟩ :=
    side hc0 hc1 hc2 hzc htc hlc hrc
  have hw' : (((n0 + n1 * 256 + n2 * 65536 + n3 * 16777216 : ℤ)) : F)
      = ((m0 + m1 * 256 + m2 * 65536 + m3 * 16777216 : ℤ) : F) := by
    push_cast; linear_combination hw
  obtain ⟨k, hk⟩ := ZirenDet.cast_eq_iff_dvd.mp hw'
  have hk' : k = -1 ∨ k = 0 ∨ k = 1 := by
    rcases sa with ⟨_, _⟩ | ⟨_, _, _, _, _⟩ <;> rcases sc with ⟨_, _⟩ | ⟨_, _, _, _, _⟩ <;> omega
  rcases sa with ⟨rfl, _⟩ | ⟨rfl, _, _, _, _⟩ <;> rcases sc with ⟨rfl, _⟩ | ⟨rfl, _, _, _, _⟩ <;>
    rcases hk' with rfl | rfl | rfl <;>
    first
      | (exfalso; omega)
      | (have e0 : n0 = m0 := by omega
         have e1 : n1 = m1 := by omega
         have e2 : n2 = m2 := by omega
         have e3 : n3 = m3 := by omega
         subst e0 e1 e2 e3
         exact ⟨rfl, rfl, rfl, rfl, rfl⟩)

end ZirenDet.CanonicalWord

/-- A byte bound, read off the context or off two gated ranges. -/
syntax "picus_cw_bound" : tactic
macro_rules
  | `(tactic| picus_cw_bound) =>
    `(tactic| first
        | assumption
        | exact ZirenDet.CanonicalWord.gated_bound' (by assumption) (by assumption) (by assumption)
        | exact ZirenDet.CanonicalWord.gated_bound (by assumption) (by assumption) (by assumption))

open Lean Elab Tactic Meta in
/-- Closes `y = x` when both are the same byte (or the flag) of two range-checked words with
one field value: finds the two checkers in the context, proves the words equal as a linear
combination of two hypotheses that mention their top bytes, and applies
[`ZirenDet.CanonicalWord.inj`]. -/
elab "picus_canonical_word" : tactic => withMainContext do
  let goal ← getMainGoal
  let some (_, lhs, rhs) := (← instantiateMVars (← goal.getType)).eq? | throwError "not an equation"
  let mut tops : Array (Expr × Expr) := #[]
  let mut lows : Array (Expr × Expr × Expr × Expr) := #[]
  for d in ← getLCtx do
    if d.isImplementationDetail then continue
    let ty ← instantiateMVars d.type
    let some (_, l, r) := ty.eq? | continue
    unless r.nat? == some 0 do continue
    let (``HMul.hMul, #[_, _, _, _, z, t]) := l.getAppFnArgs | continue
    match t.getAppFnArgs with
    | (``HSub.hSub, #[_, _, _, _, b3, c]) =>
      if c.nat? == some 127 then tops := tops.push (z, b3)
    | (``HAdd.hAdd, #[_, _, _, _, s, b2]) =>
      if let (``HAdd.hAdd, #[_, _, _, _, b0, b1]) := s.getAppFnArgs then
        lows := lows.push (z, b0, b1, b2)
    | _ => pure ()
  let mut words : Array (Array Expr) := #[]
  for (z, b3) in tops do
    for (z', b0, b1, b2) in lows do
      if z == z' then words := words.push #[b0, b1, b2, b3, z]
  for wa in words do
    for wc in words do
      for i in [0:5] do
        unless wa[i]! == lhs && wc[i]! == rhs do continue
        let synA ← wa.mapM fun e => Term.exprToSyntax e
        let synC ← wc.mapM fun e => Term.exprToSyntax e
        let a0 := synA[0]!
        let a1 := synA[1]!
        let a2 := synA[2]!
        let a3 := synA[3]!
        let za := synA[4]!
        let c0 := synC[0]!
        let c1 := synC[1]!
        let c2 := synC[2]!
        let c3 := synC[3]!
        let zc := synC[4]!
        let mut eqs : Array Name := #[]
        for d in ← getLCtx do
          if d.isImplementationDetail then continue
          let ty ← instantiateMVars d.type
          if ty.eq?.isNone then continue
          if (ty.find? fun e => e.nat? == some 16777216).isSome &&
              (ty.find? fun e => e == wa[3]! || e == wc[3]!).isSome then
            eqs := eqs.push d.userName
        let stmt ← `($a0 + $a1 * 256 + $a2 * 65536 + $a3 * 16777216
          = $c0 + $c1 * 256 + $c2 * 65536 + $c3 * 16777216)
        let saved ← saveState
        for h₁ in eqs do
          for h₂ in eqs do
            if h₁ == h₂ then continue
            if (← getUnsolvedGoals).isEmpty then return
            try withoutRecover do
              evalTactic (← `(tactic| have hcw_w : $stmt := by
                linear_combination $(mkIdent h₁):ident - $(mkIdent h₂):ident))
              evalTactic (← `(tactic| have hcw := ZirenDet.CanonicalWord.inj
                (a0 := $a0) (a1 := $a1) (a2 := $a2) (a3 := $a3) (za := $za)
                (c0 := $c0) (c1 := $c1) (c2 := $c2) (c3 := $c3) (zc := $zc)
                (by picus_cw_bound) (by picus_cw_bound) (by picus_cw_bound)
                (by assumption) (by assumption) (by assumption) (by assumption)
                (by picus_cw_bound) (by picus_cw_bound) (by picus_cw_bound)
                (by assumption) (by assumption) (by assumption) (by assumption) hcw_w))
              evalTactic (← `(tactic| first
                | exact hcw.1
                | exact hcw.2.1
                | exact hcw.2.2.1
                | exact hcw.2.2.2.1
                | exact hcw.2.2.2.2))
            catch _ => saved.restore
  if (← getUnsolvedGoals).isEmpty then return
  throwError "picus_canonical_word: no pair of range-checked words found"
