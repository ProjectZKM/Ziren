import ZirenDet.Safe

/-!
# Tactics for replayed derivations (hand-maintained)

`zkm-picus --derive` writes each determined module's proof as the analyser's derivation: one
`have y_v = x_v` per determined variable, each closed on a context cleared down to the conjuncts
the step used.  `picus_local` is `picus_det` for such a context: the witnesses are already split
and the constraints already named, so it skips the unfolding and runs the bit, gate, lift and
integer stages on what is left.
-/

namespace ZirenDet

/-- Pulls an inverse out of a sum, `a + b / c = (a c + b) / c`; repeated, a nested carry
`((a − s) + ((a' − s') + b / 256) / 256) / 256` becomes one polynomial over `256⁻¹ ^ k`, which
[`gen_mul_inv`] and `mul_inv_eq_iff_eq_mul₀` then clear. -/
theorem add_mul_inv_pull {a b c : F} (hc : c ≠ 0) : a + b * c⁻¹ = (a * c + b) * c⁻¹ := by
  field_simp

/-- [`add_mul_inv_pull`] for a subtracted term. -/
theorem sub_mul_inv_pull {a b c : F} (hc : c ≠ 0) : a - b * c⁻¹ = (a * c - b) * c⁻¹ := by
  field_simp

/-- [`add_mul_inv_pull`] with the inverse term first. -/
theorem mul_inv_add_pull {a b c : F} (hc : c ≠ 0) : b * c⁻¹ + a = (b + a * c) * c⁻¹ := by
  field_simp

/-- [`add_mul_inv_pull`] with the inverse term first, subtracting. -/
theorem mul_inv_sub_pull {a b c : F} (hc : c ≠ 0) : b * c⁻¹ - a = (b - a * c) * c⁻¹ := by
  field_simp

/-- Moves an inverse across a generalized equation. -/
theorem gen_mul_inv {a d c : F} (hc : c ≠ 0) : Gen (a * c⁻¹) d ↔ Gen a (d * c) := by
  simp only [gen_iff]; exact mul_inv_eq_iff_eq_mul₀ hc

/-- Two generalized equations subtract. -/
theorem gen_sub {a b c d : F} (h₁ : Gen a b) (h₂ : Gen c d) : a - c = b - d := by
  rw [h₁.eq, h₂.eq]

/-- A bit constraint as a case split. -/
theorem bit_cases {k : F} (h : k * (k - 1) = 0) : k = 0 ∨ k = 1 := by
  rcases mul_eq_zero.mp h with h | h
  · exact Or.inl h
  · exact Or.inr (sub_eq_zero.mp h)

/-- `ZMod.val` of the cast of an integer already known to lie in `[0, p)`: no reduction is
left for `omega` to reason about. -/
theorem val_cast_small {a : ℤ} (h0 : 0 ≤ a) (h1 : a < 2130706433) :
    (((a : ℤ) : F)).val = a.toNat := by
  rw [ZirenDet.val_cast, Int.emod_eq_of_lt h0 h1]

end ZirenDet

open Lean Elab Tactic Meta in
/-- For every generalized equation of the first witness, subtracts its twin of the second
(the same expression with each `y…` read as `x…`) and normalizes the difference: the terms both
witnesses share cancel, so a carry `x₆ + x₂₁ − x₂₉ = 256 q` whose `x₆` is unbounded leaves
`y₂₉ − x₂₉ = 256 (q − q')` over bounded variables only. -/
elab "picus_gen_diff" : tactic => do
  let gens ← withMainContext do
    let mut out : Array (LocalDecl × String) := #[]
    for d in ← getLCtx do
      if d.isImplementationDetail then continue
      let ty ← instantiateMVars d.type
      if ty.isAppOfArity ``ZirenDet.Gen 2 then
        let fmt ← ppExpr ty.appFn!.appArg!
        out := out.push (d, (toString fmt).map fun ch => if ch == 'y' then 'x' else ch)
    pure out
  let mut k := 0
  for i in [0:gens.size] do
    for j in [i+1:gens.size] do
      let (d₁, s₁) := gens[i]!
      let (d₂, s₂) := gens[j]!
      if s₁ != s₂ then continue
      let name := Name.mkSimple s!"gdiff{k}"
      k := k + 1
      try
        withMainContext do
          let pf ← mkAppM ``ZirenDet.gen_sub #[d₂.toExpr, d₁.toExpr]
          let g ← getMainGoal
          let g ← g.assert name (← inferType pf) pf
          let (_, g) ← g.intro1P
          replaceMainGoal [g]
        evalTactic (← `(tactic| try ring_nf at $(mkIdent name):ident))
      catch _ => pure ()

open Lean Elab Tactic Meta in
/-- The field variables carrying a range hypothesis `x.val ≤ c` or `x.val < c`. -/
def boundedVars : TacticM (Std.HashSet FVarId) := withMainContext do
  let mut out : Std.HashSet FVarId := {}
  for d in ← getLCtx do
    if d.isImplementationDetail then continue
    let ty ← instantiateMVars d.type
    if ty.isAppOfArity ``LE.le 4 || ty.isAppOfArity ``LT.lt 4 then
      let lhs := ty.appFn!.appArg!
      if lhs.getAppFn.isConstOf ``ZMod.val then
        let x := lhs.appArg!
        if x.isFVar then out := out.insert x.fvarId!
  return out

open Lean Elab Tactic Meta in
/-- The unbounded field variables of an equation `e = 0` over `F`, or `none` for any other
hypothesis. -/
def unboundedOf (bounded : Std.HashSet FVarId) (ty : Expr) : MetaM (Option (Array FVarId)) := do
  unless ty.isAppOfArity ``ZirenDet.Gen 2 do
    let some (t, _, _) := ty.eq? | return none
    unless ← isDefEq t (mkConst ``ZirenDet.F) do return none
  let st := collectFVars {} ty
  let mut out := #[]
  for fv in st.fvarIds do
    if bounded.contains fv then continue
    if ← isDefEq (← fv.getType) (mkConst ``ZirenDet.F) then out := out.push fv
  return some out

open Lean Elab Tactic Meta in
/-- Adds `h₁ + h₂` and `h₁ − h₂`, normalized, for every two equations sharing an unbounded
variable (one that `picus_prep` would lift to all of `[0, p)`): a word `x₄₃ + 256 x₄₄ + …` both
witnesses read from the same input cancels, leaving an equation over bounded variables only. -/
elab "picus_pair_elim" : tactic => do
  let bounded ← boundedVars
  let eqs ← withMainContext do
    let mut out : Array (LocalDecl × Array FVarId) := #[]
    for d in ← getLCtx do
      if d.isImplementationDetail then continue
      if let some u ← unboundedOf bounded (← instantiateMVars d.type) then
        if !u.isEmpty then out := out.push (d, u)
    pure out
  let mut k := 0
  for i in [0:min eqs.size 24] do
    for j in [i+1:min eqs.size 24] do
      let (d₁, u₁) := eqs[i]!
      let (d₂, u₂) := eqs[j]!
      unless u₁.any u₂.contains do continue
      for op in [``HAdd.hAdd, ``HSub.hSub] do
        let name := Name.mkSimple s!"pelim{k}"
        k := k + 1
        try
          withMainContext do
            let F := mkConst ``ZirenDet.F
            let pf ← mkAppM ``congrArg₂ #[← mkAppOptM op #[F, F, F, none], d₁.toExpr, d₂.toExpr]
            let g ← getMainGoal
            let g ← g.assert name (← inferType pf) pf
            let (_, g) ← g.intro1P
            replaceMainGoal [g]
          evalTactic (← `(tactic| try ring_nf at $(mkIdent name):ident))
        catch _ => pure ()

open Lean Elab Tactic Meta in
/-- Clears every equation over `F` that still mentions an unbounded variable. -/
elab "picus_clear_unbounded" : tactic => do
  let bounded ← boundedVars
  let drop ← withMainContext do
    let mut out := #[]
    for d in ← getLCtx do
      if d.isImplementationDetail then continue
      if let some u ← unboundedOf bounded (← instantiateMVars d.type) then
        if !u.isEmpty then out := out.push d.fvarId
    pure out
  for fv in drop.reverse do
    try
      let g ← getMainGoal
      replaceMainGoal [← g.clear fv]
    catch _ => pure ()

open Lean Elab Tactic Meta in
/-- Clears every equation over `F` with a product of two non-constant factors (a gate or a
bit, whose range `picus_bits` has already recorded): the linear equations and the ranges are
what an integer finish reads, and the products only slow `omega` down. -/
elab "picus_clear_nonlinear" : tactic => do
  let drop ← withMainContext do
    let mut out := #[]
    for d in ← getLCtx do
      if d.isImplementationDetail then continue
      let ty ← instantiateMVars d.type
      let some (t, _, _) := ty.eq? | continue
      unless ← isDefEq t (mkConst ``ZirenDet.F) do continue
      let nonlinear := (ty.find? fun e =>
        e.isAppOfArity ``HMul.hMul 6 && e.appFn!.appArg!.hasFVar && e.appArg!.hasFVar).isSome
      if nonlinear then out := out.push d.fvarId
    pure out
  for fv in drop.reverse do
    try
      let g ← getMainGoal
      replaceMainGoal [← g.clear fv]
    catch _ => pure ()

open Lean Elab Tactic Meta in
/-- For a goal `a = b`, splits each side that has a bit hypothesis `v * (v - 1) = 0` into
`v = 0` and `v = 1` and substitutes: a bit fixed by exclusion (`v = 1` forces a column to a value
its range forbids) is then refuted branch by branch. -/
elab "picus_split_goal_bits" : tactic => do
  let hs ← withMainContext do
    let some (_, a, b) := (← instantiateMVars (← getMainTarget)).eq? | return #[]
    let mut out : Array Name := #[]
    for v in [a, b] do
      unless v.isFVar do continue
      for d in ← getLCtx do
        if d.isImplementationDetail then continue
        let ty ← instantiateMVars d.type
        let some (_, lhs, _) := ty.eq? | continue
        if lhs.isAppOfArity ``HMul.hMul 6 && lhs.appFn!.appArg! == v then
          let r := lhs.appArg!
          if r.isAppOfArity ``HSub.hSub 6 && r.appFn!.appArg! == v then
            out := out.push d.userName
            break
    pure out
  for h in hs do
    let hId := mkIdent h
    evalTactic (← `(tactic| all_goals (try (rcases ZirenDet.bit_cases $hId:ident with hb | hb <;> subst hb))))

open Lean Elab Tactic Meta in
/-- Splits the bits that gate a range: for a hypothesis `(a * g).val ≤ c` or
`(a * (1 - g)).val ≤ c` whose `a` has no range of its own and whose `g` is a bit, cases on
`g = 0 ∨ g = 1` and simplifies, so that one of the two gated ranges becomes `a.val ≤ c` (at most
four gates, sixteen goals). -/
elab "picus_split_range_gates" : tactic => do
  let bounded ← boundedVars
  let gates ← withMainContext do
    let lctx ← getLCtx
    let bitHyp (g : Expr) : MetaM (Option Name) := do
      for d in lctx do
        if d.isImplementationDetail then continue
        let ty ← instantiateMVars d.type
        let some (_, lhs, _) := ty.eq? | continue
        if lhs.isAppOfArity ``HMul.hMul 6 && lhs.appFn!.appArg! == g then
          let r := lhs.appArg!
          if r.isAppOfArity ``HSub.hSub 6 && r.appFn!.appArg! == g then return some d.userName
      return none
    let mut out : Array Name := #[]
    for d in lctx do
      if d.isImplementationDetail then continue
      let ty ← instantiateMVars d.type
      unless ty.isAppOfArity ``LE.le 4 || ty.isAppOfArity ``LT.lt 4 do continue
      let lhs := ty.appFn!.appArg!
      unless lhs.getAppFn.isConstOf ``ZMod.val do continue
      let prod := lhs.appArg!
      unless prod.isAppOfArity ``HMul.hMul 6 do continue
      let a := prod.appFn!.appArg!
      let g := prod.appArg!
      unless a.isFVar && !bounded.contains a.fvarId! do continue
      let g := if g.isAppOfArity ``HSub.hSub 6 then g.appArg! else g
      unless g.isFVar do continue
      if let some h ← bitHyp g then
        unless out.contains h do out := out.push h
    pure (out.extract 0 4)
  for h in gates do
    evalTactic (← `(tactic| all_goals (try (rcases ZirenDet.bit_cases $(mkIdent h):ident with hb | hb <;> subst hb))))
  unless gates.isEmpty do
    evalTactic (← `(tactic| all_goals (try simp only [mul_one, mul_zero, one_mul, zero_mul, sub_self,
      sub_zero, zero_sub, ZMod.val_zero, Nat.zero_le, zero_le] at *)))

open Lean Elab Tactic Meta in
/-- Splits up to `n` of the bits of the context (variables `v` with `v * (v - 1) = 0`) into
`v = 0` and `v = 1` and simplifies.  A word under the field's range checker is determined
case by case on its flag in each witness: both clear, both set, or one of each, which the
word's value contradicts. -/
elab "picus_split_bits " n:num : tactic => do
  let hs ← withMainContext do
    let mut seen : Array Expr := #[]
    let mut out : Array Name := #[]
    for d in ← getLCtx do
      if d.isImplementationDetail then continue
      let ty ← instantiateMVars d.type
      let some (_, lhs, _) := ty.eq? | continue
      unless lhs.isAppOfArity ``HMul.hMul 6 do continue
      let v := lhs.appFn!.appArg!
      let r := lhs.appArg!
      unless v.isFVar && r.isAppOfArity ``HSub.hSub 6 && r.appFn!.appArg! == v do continue
      if seen.contains v then continue
      seen := seen.push v
      out := out.push d.userName
    pure (out.extract 0 n.getNat)
  if hs.isEmpty then throwError "picus_split_bits: no bit in the context"
  for h in hs do
    evalTactic (← `(tactic| all_goals (try (rcases ZirenDet.bit_cases $(mkIdent h):ident with hb | hb <;> subst hb))))
  evalTactic (← `(tactic| all_goals (try simp only [mul_one, mul_zero, one_mul, zero_mul, sub_self,
    sub_zero, add_zero, zero_add, ZMod.val_zero, Nat.zero_le, zero_le] at *)))

open Lean Elab Tactic Meta in
/-- Closes `x = 0 ∨ x = 1` from a hypothesis that is literally `x · (x − 1) = 0`.  The match is
syntactic: `assumption` would try every large constraint up to unfolding and can exhaust the
recursion depth. -/
elab "picus_bit_hyp" : tactic => withMainContext do
  let goal ← getMainGoal
  let gty ← instantiateMVars (← goal.getType)
  let (``Or, #[l, _]) := gty.getAppFnArgs | throwError "picus_bit_hyp: not a disjunction"
  let some (_, x, _) := l.eq? | throwError "picus_bit_hyp: not an equation"
  for d in ← getLCtx do
    if d.isImplementationDetail then continue
    let ty ← instantiateMVars d.type
    let some (_, lhs, rhs) := ty.eq? | continue
    unless rhs.nat? == some 0 do continue
    let (``HMul.hMul, #[_, _, _, _, a, b]) := lhs.getAppFnArgs | continue
    let (``HSub.hSub, #[_, _, _, _, a', one]) := b.getAppFnArgs | continue
    unless a == x && a' == x && one.nat? == some 1 do continue
    goal.assign (← mkAppM ``ZirenDet.bit_cases #[d.toExpr])
    return
  throwError "picus_bit_hyp: no bit constraint"

open Lean Elab Tactic Meta in
/-- For every two equations `a = u`, `b = v` whose sides differ only in `y…` versus `x…`
variables, adds `a − b = u − v`, normalized. -/
elab "picus_gen_eqdiff" : tactic => do
  let eqs ← withMainContext do
    let mut out : Array (LocalDecl × String) := #[]
    for d in ← getLCtx do
      if d.isImplementationDetail then continue
      let ty ← instantiateMVars d.type
      let some (t, l, _) := ty.eq? | continue
      unless ← isDefEq t (mkConst ``ZirenDet.F) do continue
      if l.isFVar then continue
      let fmt ← ppExpr l
      out := out.push (d, (toString fmt).map fun ch => if ch == 'y' then 'x' else ch)
    pure out
  let mut k := 0
  for i in [0:eqs.size] do
    for j in [0:eqs.size] do
      if i == j then continue
      let (d₁, s₁) := eqs[i]!
      let (d₂, s₂) := eqs[j]!
      if s₁ != s₂ then continue
      let f₁ ← ppExpr (← instantiateMVars d₁.type)
      if !(toString f₁).contains 'y' then continue
      let name := Name.mkSimple s!"qd{k}"
      k := k + 1
      try
        evalTactic (← `(tactic| have $(mkIdent name):ident := congrArg₂ HSub.hSub $(mkIdent d₁.userName):ident $(mkIdent d₂.userName):ident))
      catch _ => pure ()
      evalTactic (← `(tactic| try ring_nf at $(mkIdent name):ident))

open Lean Elab Tactic Meta in
/-- Splits every bit constraint `a · (a − 1) = 0` whose `a` is an expression (a carry written
as `(sum) · 256⁻¹`) into `a = 0 ∨ a = 1`, then subtracts the two witnesses' copies of each such
equation: every two split equations are subtracted, so the terms both witnesses share cancel,
leaving the difference of the carried bytes as a multiple of 256, which the integer finish
bounds. -/
elab "picus_quad_bits" : tactic => do
  evalTactic (← `(tactic| try simp only [zero_sub, neg_eq_zero, sub_zero] at *))
  let hs ← withMainContext do
    let mut out : Array Name := #[]
    for d in ← getLCtx do
      if d.isImplementationDetail then continue
      let ty ← instantiateMVars d.type
      let some (_, l, r) := ty.eq? | continue
      unless r.nat? == some 0 do continue
      let (``HMul.hMul, #[_, _, _, _, a, b]) := l.getAppFnArgs | continue
      let (``HSub.hSub, #[_, _, _, _, a', one]) := b.getAppFnArgs | continue
      if a.isFVar || !(one.nat? == some 1) then continue
      unless ← isDefEq a a' do continue
      out := out.push d.userName
    pure out
  if hs.isEmpty then throwError "picus_quad_bits: no carry bit"
  let mut k := 0
  let mut names : Array Name := #[]
  for h in hs do
    let q := Name.mkSimple s!"qb{k}"
    k := k + 1
    evalTactic (← `(tactic| have $(mkIdent q):ident := ZirenDet.bit_cases $(mkIdent h):ident))
    evalTactic (← `(tactic| clear $(mkIdent h):ident))
    names := names.push q
  for q in names do
    evalTactic (← `(tactic| all_goals rcases $(mkIdent q):ident with $(mkIdent q):ident | $(mkIdent q):ident))
    evalTactic (← `(tactic| all_goals (try simp only [mul_inv_eq_iff_eq_mul₀ ZirenDet.two_ne,
      mul_inv_eq_iff_eq_mul₀ ZirenDet.c128_ne, mul_inv_eq_iff_eq_mul₀ ZirenDet.c256_ne,
      mul_inv_eq_iff_eq_mul₀ ZirenDet.c65536_ne, mul_inv_eq_iff_eq_mul₀ ZirenDet.c16777216_ne,
      zero_mul, one_mul] at $(mkIdent q):ident)))
  let mut d := 0
  for i in [0:names.size] do
    for j in [i+1:names.size] do
      let qd := mkIdent (Name.mkSimple s!"qd{d}")
      d := d + 1
      let a := mkIdent names[i]!
      let b := mkIdent names[j]!
      evalTactic (← `(tactic| all_goals (try (have $qd:ident := congrArg₂ HSub.hSub $a $b; ring_nf at $qd:ident))))

open Lean Elab Tactic Meta in
/-- Substitutes every variable a hypothesis defines (`x − E = 0` with `x` not in `E` and not
in the goal): a carry defined from its bits is bounded only through them. -/
elab "picus_subst_defs" : tactic => do
  for _ in [0:64] do
    let found ← withMainContext do
      let gty ← instantiateMVars (← (← getMainGoal).getType)
      let mut out : Option Name := none
      for d in ← getLCtx do
        if d.isImplementationDetail then continue
        let ty ← instantiateMVars d.type
        let some (_, a, b) := ty.eq? | continue
        unless b.nat? == some 0 do continue
        let (``HSub.hSub, #[_, _, _, _, x, e]) := a.getAppFnArgs | continue
        if x.isFVar && !gty.containsFVar x.fvarId! && !e.containsFVar x.fvarId! then
          out := some d.userName
          break
      pure out
    let some h := found | break
    try
      let hi := mkIdent h
      evalTactic (← `(tactic| replace $hi := sub_eq_zero.mp $hi))
      evalTactic (← `(tactic| subst $hi))
    catch _ => break

set_option hygiene false in
open Lean Elab Tactic Meta in
/-- `picus_pin_mul h x`: from `h`, whose normal form is `c · x = 0` or `x · c = 0` with `c` a
nonzero constant, introduces `hpin : x = 0`.  The shape is checked before any lemma is applied, so
a hypothesis that normalizes to `True` is skipped instead of producing an ill-typed term. -/
elab "picus_pin_mul " h:ident x:term : tactic => do
  evalTactic (← `(tactic| have hn := $h:ident))
  evalTactic (← `(tactic| ring_nf at hn))
  let ok ← withMainContext do
    let some d := (← getLCtx).findFromUserName? `hn | return false
    let ty ← instantiateMVars d.type
    let some (_, l, r) := ty.eq? | return false
    unless r.nat? == some 0 do return false
    let (``HMul.hMul, #[_, _, _, _, a, b]) := l.getAppFnArgs | return false
    return (a.isFVar && !b.hasFVar) || (b.isFVar && !a.hasFVar)
  unless ok do
    evalTactic (← `(tactic| clear hn))
    throwError "picus_pin_mul: not a constant multiple"
  evalTactic (← `(tactic| have hpin : $x = 0 := by
    rcases mul_eq_zero.mp hn with h0 | h0
    · first | exact h0 | exact absurd h0 (by decide)
    · first | exact h0 | exact absurd h0 (by decide)))
  evalTactic (← `(tactic| clear hn))

set_option hygiene false in
open Lean Elab Tactic Meta in
/-- `picus_pin_sum h x`: from `h`, whose normal form is `c + x = 0` with `c` a constant,
introduces `hpin : x = -c`. -/
elab "picus_pin_sum " h:ident x:term : tactic => do
  evalTactic (← `(tactic| have hn := $h:ident))
  evalTactic (← `(tactic| ring_nf at hn))
  let c ← withMainContext do
    let some d := (← getLCtx).findFromUserName? `hn | throwError "no hn"
    let ty ← instantiateMVars d.type
    let some (_, l, r) := ty.eq? | throwError "not an equation"
    unless r.nat? == some 0 do throwError "not a zero"
    let (``HAdd.hAdd, #[_, _, _, _, c, y]) := l.getAppFnArgs | throwError "not a sum"
    unless y.isFVar && !c.hasFVar do throwError "not constant plus variable"
    Term.exprToSyntax c
  evalTactic (← `(tactic| have hpin : $x = -$c := by linear_combination hn))
  evalTactic (← `(tactic| (try simp only [neg_neg] at hpin)))
  evalTactic (← `(tactic| clear hn))

set_option hygiene false in
open Lean Elab Tactic Meta in
/-- Substitutes every variable a hypothesis pins to a constant (`x − 1 = 0`, `0 − x = 0`,
`x = 0`), repeatedly: a selector that multiplies a carry constraint hides the carry from the
generalization until it is replaced by its value, and a gate defined from a selector
(`1 − s − g = 0`) becomes a constant once the selector is. -/
elab "picus_subst_consts" : tactic => do
  for _ in [0:4] do
    let hs ← withMainContext do
      let mut out : Array Name := #[]
      for d in ← getLCtx do
        if d.isImplementationDetail then continue
        let ty ← instantiateMVars d.type
        let some (_, a, b) := ty.eq? | continue
        let (l, r) :=
          if a.isAppOfArity ``HSub.hSub 6 && b.isAppOf ``OfNat.ofNat then (a.appFn!.appArg!, a.appArg!)
          else (a, b)
        let closed := fun (e : Expr) => !e.hasFVar && !e.hasMVar
        if (l.isFVar && closed r) || (r.isFVar && closed l) then out := out.push d.userName
      pure out
    let lin ← withMainContext do
      let mut out : Array (Name × Expr) := #[]
      for d in ← getLCtx do
        if d.isImplementationDetail then continue
        if hs.contains d.userName then continue
        let ty ← instantiateMVars d.type
        let some (t, a, b) := ty.eq? | continue
        unless ← isDefEq t (mkConst ``ZirenDet.F) do continue
        let vars := (collectFVars (collectFVars {} a) b).fvarIds
        unless vars.size == 1 do continue
        let nonlinear := (ty.find? fun e =>
          e.isAppOfArity ``HMul.hMul 6 && e.appFn!.appArg!.hasFVar && e.appArg!.hasFVar).isSome
        if !nonlinear then out := out.push (d.userName, mkFVar vars[0]!)
      pure out
    if hs.isEmpty && lin.isEmpty then break
    for h in hs do
      try
        evalTactic (← `(tactic| (try simp only [sub_eq_zero] at $(mkIdent h):ident); subst $(mkIdent h):ident))
      catch _ => pure ()
    let mut solved := !hs.isEmpty
    for (h, x) in lin do
      let hi := mkIdent h
      let done ← try
        withMainContext do
          let xs ← Term.exprToSyntax x
          withoutRecover do
            evalTactic (← `(tactic| first
              | have hpin : $xs = 0 := by linear_combination $hi:ident
              | have hpin : $xs = 0 := by linear_combination -$hi:ident
              | have hpin : $xs = 1 := by linear_combination $hi:ident
              | have hpin : $xs = 1 := by linear_combination -$hi:ident
              | picus_pin_mul $hi:ident $xs
              | picus_pin_sum $hi:ident $xs))
            evalTactic (← `(tactic| subst hpin))
        pure true
      catch _ => pure false
      solved := solved || done
    if !solved then break
    evalTactic (← `(tactic| try simp only [mul_zero, zero_mul, mul_one, one_mul, add_zero, zero_add,
      sub_zero, sub_self] at *))

/-- `picus_local` for a step whose two witnesses share unbounded terms: the carries are
generalized, each generalized equation is subtracted from its twin before any inverse is
cleared (so the shared part cancels at its own scale), and what still mentions an unbounded
variable is dropped before the integer finish (a carry `(a + b − s + E / 256) / 256`
whose lower part `E` both witnesses share). -/
syntax "picus_local_diff" : tactic
syntax "picus_local_diff_core" : tactic
syntax "picus_local_core" : tactic
set_option hygiene false in
macro_rules
  | `(tactic| picus_local_diff) =>
    `(tactic| (
        (try simp only [mul_zero, zero_mul, mul_one, one_mul, add_zero, zero_add, sub_zero,
               sub_self] at *)
        (try picus_subst_consts)
        all_goals picus_local_diff_core))

set_option hygiene false in
macro_rules
  | `(tactic| picus_local_diff_core) =>
    `(tactic| (
        (try simp only [mul_zero, zero_mul, mul_one, one_mul, add_zero, zero_add, sub_zero,
               sub_self] at *)
        picus_name_all
        (try picus_generalize)
        picus_gen_diff
        (try picus_bits)
        picus_clear_unbounded
        picus_finish))

open Lean Elab Tactic Meta in
/-- Turns every field equation between integer casts into an integer equation with its
multiple of the characteristic explicit, `b − a = p · k`.  Unlike `picus_eqs` it needs no
bound: an equation whose coefficients are large (`65536 · u + 2²⁴ · v = 0` over bytes) wraps
around, and `omega` finds `k` from the bounds of the variables. -/
elab "picus_eqs_dvd" : tactic => do
  let hs ← withMainContext do
    let mut out : Array Name := #[]
    for d in ← getLCtx do
      if d.isImplementationDetail then continue
      let ty ← instantiateMVars d.type
      let some (t, a, b) := ty.eq? | continue
      unless ← isDefEq t (mkConst ``ZirenDet.F) do continue
      if a.isAppOf ``Int.cast && b.isAppOf ``Int.cast then out := out.push d.userName
    pure out
  let mut i := 0
  for h in hs do
    let k := mkIdent (Name.mkSimple s!"kd{i}")
    let hk := mkIdent (Name.mkSimple s!"hkd{i}")
    i := i + 1
    try
      evalTactic (← `(tactic| obtain ⟨$k:ident, $hk:ident⟩ := ZirenDet.cast_eq_iff_dvd.mp $(mkIdent h):ident))
      evalTactic (← `(tactic| try clear $(mkIdent h):ident))
    catch _ => pure ()

open Lean Elab Tactic Meta in
/-- Splits every multiple `k` that `picus_eqs_dvd` introduced into its values `−2 … 2`.  A word
equation over bytes is below `2³² < 3p`, so no other multiple occurs; `omega` proves the
bound from the rational relaxation but does not enumerate the multiples by itself. -/
elab "picus_kd_cases" : tactic => do
  let ks ← withMainContext do
    let mut out : Array Name := #[]
    for d in ← getLCtx do
      if d.isImplementationDetail then continue
      if d.userName.toString.startsWith "kd" && d.type.isConstOf ``Int then
        out := out.push d.userName
    pure out
  for k in ks do
    let k := mkIdent k
    evalTactic (← `(tactic| all_goals (try (obtain rfl | rfl | rfl | rfl | rfl :
      $k = -2 ∨ $k = -1 ∨ $k = 0 ∨ $k = 1 ∨ $k = 2 := by omega))))

/-- The integer finish for equations that wrap around (see `picus_eqs_dvd`). -/
syntax "picus_finish_dvd" : tactic
macro_rules
  | `(tactic| picus_finish_dvd) =>
    `(tactic| (
        picus_clear_junk
        picus_lift
        (try simp only [ZirenDet.gen_iff] at *)
        (try simp only [ZirenDet.castF_one, ZirenDet.castF_zero, ZirenDet.castF_ofNat, ZirenDet.castF_add,
               ZirenDet.castF_sub, ZirenDet.castF_mul, ZirenDet.castF_neg, ZirenDet.castF_pow] at *)
        picus_eqs_dvd
        (try simp (disch := omega) only [ZirenDet.val_cast_small] at *)
        (try simp only [ZirenDet.val_cast] at *)
        first
          | omega
          | (rw [ZirenDet.cast_eq_iff_dvd]; refine ⟨0, ?_⟩; omega)
          | (picus_kd_cases; all_goals omega)
          | (rw [ZirenDet.cast_eq_iff_dvd]; refine ⟨0, ?_⟩; picus_kd_cases; all_goals omega)))

/-- `picus_det` on a context that is already split and focused. -/
syntax "picus_local" : tactic
set_option hygiene false in
macro_rules
  | `(tactic| picus_local) =>
    `(tactic| (
        (try simp only [mul_zero, zero_mul, mul_one, one_mul, add_zero, zero_add, sub_zero,
               sub_self] at *)
        (try picus_subst_consts)
        all_goals picus_local_core))

set_option hygiene false in
macro_rules
  | `(tactic| picus_local_core) =>
    `(tactic| (
        (try simp only [mul_zero, zero_mul, mul_one, one_mul, add_zero, zero_add, sub_zero,
               sub_self] at *)
        picus_name_all
        (try picus_generalize)
        (try simp only [ZirenDet.add_mul_inv_pull ZirenDet.two_ne, ZirenDet.sub_mul_inv_pull ZirenDet.two_ne, ZirenDet.mul_inv_add_pull ZirenDet.two_ne, ZirenDet.mul_inv_sub_pull ZirenDet.two_ne, ZirenDet.add_mul_inv_pull ZirenDet.c128_ne, ZirenDet.sub_mul_inv_pull ZirenDet.c128_ne, ZirenDet.mul_inv_add_pull ZirenDet.c128_ne, ZirenDet.mul_inv_sub_pull ZirenDet.c128_ne, ZirenDet.add_mul_inv_pull ZirenDet.c256_ne, ZirenDet.sub_mul_inv_pull ZirenDet.c256_ne, ZirenDet.mul_inv_add_pull ZirenDet.c256_ne, ZirenDet.mul_inv_sub_pull ZirenDet.c256_ne, ZirenDet.add_mul_inv_pull ZirenDet.c65536_ne, ZirenDet.sub_mul_inv_pull ZirenDet.c65536_ne, ZirenDet.mul_inv_add_pull ZirenDet.c65536_ne, ZirenDet.mul_inv_sub_pull ZirenDet.c65536_ne, ZirenDet.add_mul_inv_pull ZirenDet.c16777216_ne, ZirenDet.sub_mul_inv_pull ZirenDet.c16777216_ne, ZirenDet.mul_inv_add_pull ZirenDet.c16777216_ne, ZirenDet.mul_inv_sub_pull ZirenDet.c16777216_ne] at *)
        (try simp only [ZirenDet.gen_mul_inv ZirenDet.two_ne, ZirenDet.gen_mul_inv ZirenDet.c128_ne, ZirenDet.gen_mul_inv ZirenDet.c256_ne, ZirenDet.gen_mul_inv ZirenDet.c65536_ne, ZirenDet.gen_mul_inv ZirenDet.c16777216_ne] at *)
        (try picus_gen_diff)
        (try simp only [mul_inv_eq_iff_eq_mul₀ ZirenDet.two_ne, mul_inv_eq_iff_eq_mul₀ ZirenDet.c128_ne,
               mul_inv_eq_iff_eq_mul₀ ZirenDet.c256_ne, mul_inv_eq_iff_eq_mul₀ ZirenDet.c65536_ne,
               mul_inv_eq_iff_eq_mul₀ ZirenDet.c16777216_ne, sub_eq_zero] at *)
        (try subst_vars)
        (try simp only [mul_zero, zero_mul, mul_one, one_mul, add_zero, zero_add, sub_zero,
               sub_self] at *)
        (try picus_bits)
        (try picus_gates 2)
        all_goals (try picus_bits)
        all_goals (try picus_helpers)
        all_goals (try picus_prep)
        all_goals (try picus_solve)
        all_goals (try constructorm* _ ∧ _)
        all_goals picus_close))

open Lean Elab Tactic in
/-- Logs the goal a replayed derivation could not close (`PICUS_OPEN goal …`). -/
elab "picus_open_goal" : tactic => do
  logInfo m!"PICUS_OPEN goal {← getMainTarget}"

open Lean Elab Tactic in
/-- Runs `t` under its own `picus.safeHeartbeats` budget and turns any exception, a heartbeat
overrun included, into an ordinary failure, so an enclosing `first` falls through to the next
alternative with a fresh budget (a replay that cannot close must not starve its fallback). -/
elab "picus_budget " t:tactic : tactic => do
  let kilo := ZirenDet.Picus.picus.safeHeartbeats.get (← getOptions)
  let err ← tryCatchRuntimeEx
    (Core.withCurrHeartbeats <|
      withTheReader Core.Context (fun ctx => { ctx with maxHeartbeats := kilo * 1000 }) do
        evalTactic t
        pure none)
    (fun e => pure (some e))
  if let some e := err then
    throwError m!"picus_budget: {e.toMessageData}"

open Lean Elab Tactic in
/-- Runs one attempt `t` under a budget of `n` thousand heartbeats and turns an overrun (a
runtime exception `first` would not catch) into an ordinary failure, so a hopeless attempt
fails fast and the next alternative runs. -/
elab "picus_cap " n:num t:tactic : tactic => do
  let err ← tryCatchRuntimeEx
    (Core.withCurrHeartbeats <|
      withTheReader Core.Context (fun ctx => { ctx with maxHeartbeats := n.getNat * 1000 }) do
        evalTactic t
        pure none)
    (fun e => pure (some e))
  if let some e := err then
    throwError m!"picus_cap: {e.toMessageData}"
