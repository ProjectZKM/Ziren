import ZirenDet.Replay
open ZirenDet
set_option maxHeartbeats 0
set_option linter.unusedVariables false

/-!
# Canonical limb pairs

The memory tables hold an address as two limbs `lo`, `hi`, each range-checked to 16 bits,
with `0x7F00 − hi` range-checked to 16 bits and `lo·(1 − t·(0x7F00 − hi)) = 0` for a witness
`t`.  The high limb is then at most `0x7F00` and the low limb vanishes there, so the integer
`lo + 2¹⁶·hi` is at most `127·2²⁴ = p − 1`.  Two admitted pairs with the same field value are
the same pair.
-/

namespace ZirenDet.CanonicalLimbs

/-- One admitted pair, on integers: the high limb is below `0x7F00`, or it is `0x7F00` and the
low limb vanishes. -/
theorem side {lo hi t : F} (hl : lo.val ≤ 65535) (hh : hi.val ≤ 65535)
    (hd : ((32512 : F) - hi).val ≤ 65535) (hz : lo * (1 - t * ((32512 : F) - hi)) = 0) :
    ∃ n0 n1 : ℤ, lo = (n0 : F) ∧ hi = (n1 : F) ∧ 0 ≤ n0 ∧ n0 ≤ 65535 ∧ 0 ≤ n1 ∧
      (n1 < 32512 ∨ (n1 = 32512 ∧ n0 = 0)) := by
  obtain ⟨n0, p0, q0, rfl⟩ := ZirenDet.lift_le lo hl
  obtain ⟨n1, p1, q1, rfl⟩ := ZirenDet.lift_le hi hh
  obtain ⟨d, pd, qd, hd'⟩ := ZirenDet.lift_le _ hd
  have q0' : n0 ≤ 65535 := by exact_mod_cast q0
  have q1' : n1 ≤ 65535 := by exact_mod_cast q1
  have qd' : d ≤ 65535 := by exact_mod_cast qd
  have hs : (((n1 + d : ℤ)) : F) = ((32512 : ℤ) : F) := by
    push_cast; linear_combination -hd'
  obtain ⟨k, hk⟩ := ZirenDet.cast_eq_iff_dvd.mp hs
  rcases lt_or_eq_of_le (show n1 ≤ 32512 by omega) with h | h
  · exact ⟨n0, n1, rfl, rfl, p0, q0', p1, Or.inl h⟩
  · have h1 : ((n1 : ℤ) : F) = (32512 : F) := by rw [h]; norm_cast
    have hlo : ((n0 : ℤ) : F) = ((0 : ℤ) : F) := by
      rw [h1] at hz
      push_cast
      linear_combination hz
    obtain ⟨k', hk'⟩ := ZirenDet.cast_eq_iff_dvd.mp hlo
    exact ⟨n0, n1, rfl, rfl, p0, q0', p1, Or.inr ⟨h, by omega⟩⟩

/-- Two admitted limb pairs of one field value are equal. -/
theorem inj {lo hi t lo' hi' t' : F}
    (hl : lo.val ≤ 65535) (hh : hi.val ≤ 65535) (hd : ((32512 : F) - hi).val ≤ 65535)
    (hz : lo * (1 - t * ((32512 : F) - hi)) = 0)
    (hl' : lo'.val ≤ 65535) (hh' : hi'.val ≤ 65535) (hd' : ((32512 : F) - hi').val ≤ 65535)
    (hz' : lo' * (1 - t' * ((32512 : F) - hi')) = 0)
    (hw : lo + hi * 65536 = lo' + hi' * 65536) :
    lo = lo' ∧ hi = hi' := by
  obtain ⟨n0, n1, rfl, rfl, p0, q0, p1, sa⟩ := side hl hh hd hz
  obtain ⟨m0, m1, rfl, rfl, r0, s0, r1, sc⟩ := side hl' hh' hd' hz'
  have hw' : (((n0 + n1 * 65536 : ℤ)) : F) = ((m0 + m1 * 65536 : ℤ) : F) := by
    push_cast; linear_combination hw
  obtain ⟨k, hk⟩ := ZirenDet.cast_eq_iff_dvd.mp hw'
  have bn : n0 + n1 * 65536 ≤ 2130706432 := by
    rcases sa with _ | ⟨_, _⟩ <;> omega
  have bm : m0 + m1 * 65536 ≤ 2130706432 := by
    rcases sc with _ | ⟨_, _⟩ <;> omega
  have hk0 : k = 0 := by omega
  subst hk0
  have e1 : n1 = m1 := by omega
  have e0 : n0 = m0 := by omega
  subst e0 e1
  exact ⟨rfl, rfl⟩

end ZirenDet.CanonicalLimbs

open Lean Elab Tactic Meta in
/-- Closes `y = x` when both are the same limb of two range-checked limb pairs with one field
value: finds the two pairs in the context with their range hypotheses, proves the values equal
as a linear combination of one or two hypotheses that mention their high limbs, and applies
[`ZirenDet.CanonicalLimbs.inj`].  Hypotheses are matched by their syntax and passed by name. -/
elab "picus_canonical_limbs" : tactic => withMainContext do
  let goal ← getMainGoal
  let some (_, lhs, rhs) := (← instantiateMVars (← goal.getType)).eq? | throwError "not an equation"
  let mut gates : Array (Array Expr) := #[]
  let mut ranges : Array (Expr × Expr) := #[]
  for d in ← getLCtx do
    if d.isImplementationDetail then continue
    let ty ← instantiateMVars d.type
    if let (``LE.le, #[_, _, a, b]) := ty.getAppFnArgs then
      if b.nat? == some 65535 then
        if let (``ZMod.val, #[_, x]) := a.getAppFnArgs then
          ranges := ranges.push (x, d.toExpr)
      continue
    let some (_, l, r) := ty.eq? | continue
    unless r.nat? == some 0 do continue
    let (``HMul.hMul, #[_, _, _, _, lo, g]) := l.getAppFnArgs | continue
    let (``HSub.hSub, #[_, _, _, _, one, m]) := g.getAppFnArgs | continue
    unless one.nat? == some 1 do continue
    let (``HMul.hMul, #[_, _, _, _, t, s]) := m.getAppFnArgs | continue
    let (``HSub.hSub, #[_, _, _, _, c, hi]) := s.getAppFnArgs | continue
    if c.nat? == some 32512 then gates := gates.push #[lo, hi, t, s, d.toExpr]
  let mut pairs : Array (Array Expr) := #[]
  for g in gates do
    let some (_, hl) := ranges.find? fun (x, _) => x == g[0]! | continue
    let some (_, hh) := ranges.find? fun (x, _) => x == g[1]! | continue
    let some (_, hd) := ranges.find? fun (x, _) => x == g[3]! | continue
    pairs := pairs.push #[g[0]!, g[1]!, g[2]!, hl, hh, hd, g[4]!]
  for pa in pairs do
    for pc in pairs do
      for i in [0:2] do
        unless pa[i]! == lhs && pc[i]! == rhs do continue
        let synA ← pa.mapM fun e => Term.exprToSyntax e
        let synC ← pc.mapM fun e => Term.exprToSyntax e
        let alo := synA[0]!
        let ahi := synA[1]!
        let at' := synA[2]!
        let ahl := synA[3]!
        let ahh := synA[4]!
        let ahd := synA[5]!
        let ahz := synA[6]!
        let clo := synC[0]!
        let chi := synC[1]!
        let ct := synC[2]!
        let chl := synC[3]!
        let chh := synC[4]!
        let chd := synC[5]!
        let chz := synC[6]!
        let mut eqs : Array Name := #[]
        for d in ← getLCtx do
          if d.isImplementationDetail then continue
          let ty ← instantiateMVars d.type
          if ty.eq?.isNone then continue
          if (ty.find? fun e => e.nat? == some 65536).isSome &&
              (ty.find? fun e => e == pa[1]! || e == pc[1]!).isSome then
            eqs := eqs.push d.userName
        let stmt ← `($alo + $ahi * 65536 = $clo + $chi * 65536)
        let saved ← saveState
        let finish : TacticM Unit := do
          evalTactic (← `(tactic| have hcl := ZirenDet.CanonicalLimbs.inj
            (lo := $alo) (hi := $ahi) (t := $at') (lo' := $clo) (hi' := $chi) (t' := $ct)
            $ahl $ahh $ahd $ahz $chl $chh $chd $chz hcl_w))
          evalTactic (← `(tactic| first | exact hcl.1 | exact hcl.2))
        for h₁ in eqs do
          for h₂ in eqs do
            if (← getUnsolvedGoals).isEmpty then return
            try withoutRecover do
              if h₁ == h₂ then
                evalTactic (← `(tactic| have hcl_w : $stmt := by
                  first
                    | linear_combination $(mkIdent h₁):ident
                    | linear_combination -$(mkIdent h₁):ident))
              else
                evalTactic (← `(tactic| have hcl_w : $stmt := by
                  linear_combination $(mkIdent h₁):ident - $(mkIdent h₂):ident))
              finish
            catch _ => saved.restore
  if (← getUnsolvedGoals).isEmpty then return
  throwError "picus_canonical_limbs: no pair of range-checked limb pairs found"
