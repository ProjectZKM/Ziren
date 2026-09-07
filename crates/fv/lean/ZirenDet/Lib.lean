import Mathlib

/-!
# Ziren determinism library (hand-maintained)

`ZirenDet/Basic.lean` (generated) re-exports this file.  It holds

* the KoalaBear field `F`,
* the lifting lemmas that move a bounded field element to an integer,
* `picus_det`, the closing tactic of every generated determinism / postcondition theorem.

## How `picus_det` works

1. **Structure.**  Split both witness records, unfold the generated definitions, turn
   `a - b = 0` into `a = b`, split conjunctions and substitute every variable that is
   defined by an equation (`subst_vars`).  Equal inputs are substituted the same way, so
   after this step the two witnesses share one copy of every input.
2. **Generalize.**  Every non-variable argument of a `ZMod.val` range fact and every
   non-variable bit expression `e * (e - 1) = 0` is bound to a fresh variable.
3. **Bits.**  `k * (k - 1) = 0` becomes `k.val ≤ 1`.
4. **Gates.**  Variables that appear as a bare factor of a product-equals-zero constraint
   (`op_a_0 * out = 0`, `(1 - op_a_0) * carry_check = 0`, …) are case-split on `= 0`.
5. **Helpers.**  Two calls of the same abstract helper on syntactically equal inputs give
   equal outputs (the theorem's `h_<helper>` hypothesis), which are substituted.
6. **Lift.**  Every field variable `x` with a range fact `x.val ≤ c` (or none) is replaced by
   `((n : ℤ) : F)` with `0 ≤ n ≤ c` (or `n < KB`); casts are pulled to the top of every
   term, `(a : F) = b` becomes `a % KB = b % KB`, `((a:ℤ):F).val` becomes `(a % KB).toNat`.
7. **Finish.**  Each output equality is closed by `rfl`, `ring1`, or `omega`.

Anything left over is closed by `sorry` so a generated file always elaborates and the open
obligation shows as a warning.
-/

namespace ZirenDet

/-- The KoalaBear prime `2^31 - 2^24 + 1`. -/
abbrev KB : ℕ := 2130706433

-- `KB` is prime; the `norm_num` certificate for a 31-bit prime needs a deeper kernel recursion
-- limit than the default (it checks in about 3 s).
set_option maxRecDepth 100000 in
instance : Fact (Nat.Prime KB) := ⟨by norm_num⟩

/-- The base field of every Ziren AIR. -/
abbrev F := ZMod KB

/-! ### Lifting lemmas -/

theorem lift_le (x : F) {c : ℕ} (h : x.val ≤ c) : ∃ n : ℤ, 0 ≤ n ∧ n ≤ c ∧ x = (n : F) :=
  ⟨x.val, by positivity, by exact_mod_cast h, by simp⟩

theorem lift_lt (x : F) {c : ℕ} (h : x.val < c) : ∃ n : ℤ, 0 ≤ n ∧ n < c ∧ x = (n : F) :=
  ⟨x.val, by positivity, by exact_mod_cast h, by simp⟩

theorem lift_any (x : F) : ∃ n : ℤ, 0 ≤ n ∧ n < 2130706433 ∧ x = (n : F) :=
  ⟨x.val, by positivity, by exact_mod_cast ZMod.val_lt x, by simp⟩

/-- Equality of two integer casts, as a congruence `omega` understands. -/
theorem cast_eq_iff_mod {a b : ℤ} :
    ((a : ℤ) : F) = ((b : ℤ) : F) ↔ a % 2130706433 = b % 2130706433 :=
  ZMod.intCast_eq_intCast_iff' a b KB

/-- Equality of two integer casts as a divisibility witness (the form `omega` handles best:
the slack `k` is eliminated exactly through a unit-coefficient variable). -/
theorem cast_eq_iff_dvd {a b : ℤ} :
    ((a : ℤ) : F) = ((b : ℤ) : F) ↔ ∃ k : ℤ, b - a = 2130706433 * k :=
  ZMod.intCast_eq_intCast_iff_dvd_sub a b KB

/-- `ZMod.val` of an integer cast, as an expression `omega` understands. -/
theorem val_cast (a : ℤ) : (((a : ℤ) : F)).val = (a % 2130706433).toNat := by
  have h := ZMod.val_intCast (n := KB) a
  have h2 : (((a : ℤ) : F)).val = (((a : ℤ) : F)).val := rfl
  have h3 : (((((a : ℤ) : F)).val : ℕ) : ℤ) = a % 2130706433 := h
  omega

/-- A generalization equation `E = q`, wrapped so that `subst_vars` does not undo it.  Unfolded
again by `picus_prep` once every variable has been lifted. -/
structure Gen (a b : F) : Prop where
  eq : a = b
theorem gen_intro {a b : F} (h : a = b) : Gen a b := ⟨h⟩
theorem gen_iff {a b : F} : Gen a b ↔ a = b := ⟨fun h => h.eq, fun h => ⟨h⟩⟩

/-- An unresolved slack equation `E = p * m`, hidden from `omega` (which loops on
`c * k = p * m` with a bounded `k`).  Unhidden as soon as the bounds of `E` prove `m = 0`. -/
structure Slack (E m : ℤ) : Prop where
  eq : E = 2130706433 * m

theorem slack_zero {E m : ℤ} (h : E = 2130706433 * m)
    (hb : -2130706433 < E ∧ E < 2130706433) : m = 0 := by
  have hd : (2130706433 : ℤ) ∣ E := ⟨m, h⟩
  have hE : E = 0 := Int.eq_zero_of_dvd_of_natAbs_lt_natAbs hd (by omega)
  rw [hE] at h
  rcases mul_eq_zero.mp h.symm with h0 | h0
  · exact absurd h0 (by norm_num)
  · exact h0

/-- A bit constraint gives a range fact. -/
theorem bit_val_le {k : F} (h : k * (k - 1) = 0) : k.val ≤ 1 := by
  rcases mul_eq_zero.mp h with h | h
  · subst h; simp
  · rw [sub_eq_zero] at h; subst h; decide

theorem bit_val_le' {k : F} (h : (k - 1) * k = 0) : k.val ≤ 1 :=
  bit_val_le (by rw [mul_comm]; exact h)

theorem bit_val_le'' {k : F} (h : k * (1 - k) = 0) : k.val ≤ 1 :=
  bit_val_le (by rw [← neg_sub, mul_neg, neg_eq_zero] at h; exact h)

/-! ### Powers of two are non-zero (for the inverse rewrites) -/

theorem bit_val_le''' {k : F} (h : (1 - k) * k = 0) : k.val ≤ 1 :=
  bit_val_le'' (by rw [mul_comm]; exact h)

theorem gate_left {a b : F} (ha : ¬ a = 0) : a * b = 0 ↔ b = 0 := by
  constructor
  · intro h; rcases mul_eq_zero.mp h with h | h
    · exact absurd h ha
    · exact h
  · intro h; rw [h, mul_zero]

theorem gate_right {a b : F} (hb : ¬ b = 0) : a * b = 0 ↔ a = 0 := by
  rw [mul_comm]; exact gate_left hb

/-! ### Casts pulled to the top of a term (restricted to `F`, so `simp` cannot loop) -/

theorem castF_add (a b : ℤ) : ((a : ℤ) : F) + ((b : ℤ) : F) = ((a + b : ℤ) : F) := (Int.cast_add a b).symm
theorem castF_sub (a b : ℤ) : ((a : ℤ) : F) - ((b : ℤ) : F) = ((a - b : ℤ) : F) := (Int.cast_sub a b).symm
theorem castF_mul (a b : ℤ) : ((a : ℤ) : F) * ((b : ℤ) : F) = ((a * b : ℤ) : F) := (Int.cast_mul a b).symm
theorem castF_neg (a : ℤ) : -((a : ℤ) : F) = ((-a : ℤ) : F) := (Int.cast_neg a).symm
theorem castF_pow (a : ℤ) (k : ℕ) : ((a : ℤ) : F) ^ k = ((a ^ k : ℤ) : F) := (Int.cast_pow a k).symm
theorem castF_one : (1 : F) = ((1 : ℤ) : F) := Int.cast_one.symm
theorem castF_zero : (0 : F) = ((0 : ℤ) : F) := Int.cast_zero.symm
theorem castF_ofNat (n : ℕ) [n.AtLeastTwo] : (OfNat.ofNat n : F) = ((OfNat.ofNat n : ℤ) : F) :=
  (Int.cast_ofNat n).symm

theorem two_ne : (2 : F) ≠ 0 := by decide
theorem four_ne : (4 : F) ≠ 0 := by decide
theorem eight_ne : (8 : F) ≠ 0 := by decide
theorem sixteen_ne : (16 : F) ≠ 0 := by decide
theorem c32_ne : (32 : F) ≠ 0 := by decide
theorem c64_ne : (64 : F) ≠ 0 := by decide
theorem c128_ne : (128 : F) ≠ 0 := by decide
theorem c256_ne : (256 : F) ≠ 0 := by decide
theorem c512_ne : (512 : F) ≠ 0 := by decide
theorem c1024_ne : (1024 : F) ≠ 0 := by decide
theorem c2048_ne : (2048 : F) ≠ 0 := by decide
theorem c4096_ne : (4096 : F) ≠ 0 := by decide
theorem c8192_ne : (8192 : F) ≠ 0 := by decide
theorem c16384_ne : (16384 : F) ≠ 0 := by decide
theorem c32768_ne : (32768 : F) ≠ 0 := by decide
theorem c65536_ne : (65536 : F) ≠ 0 := by decide
theorem c131072_ne : (131072 : F) ≠ 0 := by decide
theorem c262144_ne : (262144 : F) ≠ 0 := by decide
theorem c524288_ne : (524288 : F) ≠ 0 := by decide
theorem c1048576_ne : (1048576 : F) ≠ 0 := by decide
theorem c2097152_ne : (2097152 : F) ≠ 0 := by decide
theorem c4194304_ne : (4194304 : F) ≠ 0 := by decide
theorem c8388608_ne : (8388608 : F) ≠ 0 := by decide
theorem c16777216_ne : (16777216 : F) ≠ 0 := by decide

end ZirenDet

/-! ### The tactic -/

namespace ZirenDet.Picus

open Lean Elab Tactic Meta

/-- Debug trace: appends `msg` to the file named by `PICUS_TIMING` (the elaborator captures
stdout/stderr into the message log, so a file is the only unbuffered channel). -/
def dbgLog (msg : String) : IO Unit := do
  match ← IO.getEnv "PICUS_TIMING" with
  | some path =>
    if path.length > 1 then
      let h ← IO.FS.Handle.mk path .append
      h.putStrLn msg
      h.flush
  | none => pure ()

/-- Fresh accessible name with a numeric suffix. -/
def freshName (base : String) : TacticM Name := do
  let n ← mkFreshId
  return Name.mkSimple s!"{base}_{n.toString.replace "." "_"}"

/-- `e` is a numeral (`OfNat.ofNat`, `0`, `1`). -/
def isNumeral (e : Expr) : Bool :=
  e.isAppOfArity ``OfNat.ofNat 3 || e.isAppOfArity ``Zero.zero 2 || e.isAppOfArity ``One.one 2

/-- A subterm `ZMod.val e` whose argument is neither a variable nor a numeral. -/
def findValArg (ty : Expr) : Option Expr :=
  (ty.find? fun s =>
    s.isAppOfArity ``ZMod.val 2 && !(s.appArg!.isFVar) && !(isNumeral s.appArg!)).map (·.appArg!)

/-- If `s` is `e * (e - 1)`, `(e - 1) * e`, `e * (1 - e)` or `(1 - e) * e`, the bit `e`. -/
def bitOf (s : Expr) : Option Expr :=
  match s.getAppFnArgs with
  | (``HMul.hMul, #[_, _, _, _, a, b]) =>
    let isSubOf (x y : Expr) : Bool :=
      match x.getAppFnArgs with
      | (``HSub.hSub, #[_, _, _, _, x1, x2]) => (x1 == y && isNumeral x2) || (x2 == y && isNumeral x1)
      | _ => false
    if isSubOf b a then some a else if isSubOf a b then some b else none
  | _ => none

/-- A bit expression that is not a variable. -/
def findBitArg (ty : Expr) : Option Expr :=
  (ty.find? fun s => match bitOf s with | some e => !e.isFVar | none => false).bind bitOf

/-- Hypotheses of the main goal (non-auxiliary), with instantiated types. -/
def hyps : TacticM (Array (LocalDecl × Expr)) := withMainContext do
  let mut out := #[]
  for d in ← getLCtx do
    if d.isImplementationDetail then continue
    out := out.push (d, ← instantiateMVars d.type)
  return out

/-- Give every inaccessible hypothesis / variable an accessible name, so later steps can refer
to it by identifier (syntax built from synthetic metavariables does not `subst`). -/
def nameAllStep : TacticM Unit := withMainContext do
  let mut g ← getMainGoal
  for d in ← getLCtx do
    if d.isImplementationDetail then continue
    if d.userName.hasMacroScopes then
      let base := if (← isProp d.type) then "h" else "v"
      let n ← freshName base
      g ← g.rename d.fvarId n
  replaceMainGoal [g]

elab "picus_name_all" : tactic => nameAllStep

/-- Name the field variables introduced by the last `cases` (still inaccessible) `pfx_0`,
`pfx_1`, … in order, so the two witnesses pair up by index (`a_i` ↔ `b_i`). -/
def nameWorld (pfx : String) : TacticM Unit := withMainContext do
  let fType := mkConst ``ZirenDet.F
  let mut g ← getMainGoal
  let mut i := 0
  for d in ← getLCtx do
    if d.isImplementationDetail then continue
    if !d.userName.hasMacroScopes then continue
    if ← isDefEq d.type fType then
      g ← g.rename d.fvarId (Name.mkSimple s!"{pfx}_{i}")
      i := i + 1
  replaceMainGoal [g]

elab "picus_name_world " s:str : tactic => nameWorld s.getString

/-- One generalization step; `true` when something was generalized. -/
def generalizeStep : TacticM Bool := do
  let cand ← withMainContext do
    let mut cand : Option Expr := none
    for (_, ty) in ← hyps do
      match findValArg ty with
      | some e => cand := some e; break
      | none =>
        match findBitArg ty with
        | some e => cand := some e; break
        | none => pure ()
    pure cand
  match cand with
  | none => return false
  | some e =>
    let stx ← withMainContext (Term.exprToSyntax e)
    let q := mkIdent (← freshName "q")
    let hq := mkIdent (← freshName "hq")
    let hq2 := mkIdent (← freshName "hg")
    try
      evalTactic (← `(tactic| generalize $hq:ident : $stx = $q:ident at *))
      evalTactic (← `(tactic| try simp only [mul_inv_eq_iff_eq_mul₀ ZirenDet.two_ne,
        mul_inv_eq_iff_eq_mul₀ ZirenDet.c128_ne, mul_inv_eq_iff_eq_mul₀ ZirenDet.c256_ne,
        mul_inv_eq_iff_eq_mul₀ ZirenDet.c65536_ne, mul_inv_eq_iff_eq_mul₀ ZirenDet.c16777216_ne] at $hq:ident))
      evalTactic (← `(tactic| have $hq2:ident := ZirenDet.gen_intro $hq:ident))
      evalTactic (← `(tactic| clear $hq:ident))
      return true
    catch _ => return false

partial def generalizeLoop (fuel : Nat) : TacticM Unit := do
  if fuel = 0 then return
  if ← generalizeStep then generalizeLoop (fuel - 1)

elab "picus_generalize" : tactic => generalizeLoop 400

/-- Add `k.val ≤ 1` for every hypothesis `k * (k - 1) = 0` (and the variants). -/
def bitsStep : TacticM Unit := do
  let adds ← withMainContext do
    let mut adds : Array (Name × Expr) := #[]
    for (d, ty) in ← hyps do
      match ty.getAppFnArgs with
      | (``Eq, #[_, lhs, rhs]) =>
        if !(isNumeral rhs) then continue
        match lhs.getAppFnArgs with
        | (``HMul.hMul, #[_, _, _, _, a, b]) =>
          let sub (x : Expr) : Option (Expr × Expr) :=
            match x.getAppFnArgs with
            | (``HSub.hSub, #[_, _, _, _, x1, x2]) => some (x1, x2)
            | _ => none
          match sub b with
          | some (b1, b2) =>
            if b1 == a && isNumeral b2 then adds := adds.push (``ZirenDet.bit_val_le, d.toExpr)
            else if b2 == a && isNumeral b1 then adds := adds.push (``ZirenDet.bit_val_le'', d.toExpr)
          | none =>
            match sub a with
            | some (a1, a2) =>
              if a1 == b && isNumeral a2 then adds := adds.push (``ZirenDet.bit_val_le', d.toExpr)
              else if a2 == b && isNumeral a1 then adds := adds.push (``ZirenDet.bit_val_le''', d.toExpr)
            | none => pure ()
        | _ => pure ()
      | _ => pure ()
    pure adds
  for (lem, h) in adds do
    try
      withMainContext do
        let val ← mkAppM lem #[h]
        let ty ← inferType val
        let name ← freshName "hbit"
        let g ← getMainGoal
        let g ← g.assert name ty val
        let (_, g) ← g.intro1P
        replaceMainGoal [g]
    catch _ => pure ()

elab "picus_bits" : tactic => bitsStep

/-- Variables that occur as a bare factor of a product-equals-zero hypothesis (bit
constraints excluded), most frequent first. -/
def gateCandidates (exclude : Array FVarId) : TacticM (Array (FVarId × Nat)) := withMainContext do
  let mut counts : Std.HashMap FVarId Nat := {}
  for (_, ty) in ← hyps do
    match ty.getAppFnArgs with
    | (``Eq, #[_, lhs, rhs]) =>
      if !(isNumeral rhs) then continue
      if (bitOf lhs).isSome then continue
      match lhs.getAppFnArgs with
      | (``HMul.hMul, #[_, _, _, _, a, b]) =>
        if a.isFVar then counts := counts.insert a.fvarId! (counts.getD a.fvarId! 0 + 1)
        if b.isFVar then counts := counts.insert b.fvarId! (counts.getD b.fvarId! 0 + 1)
        match a.getAppFnArgs with
        | (``HSub.hSub, #[_, _, _, _, one, gv]) =>
          if isNumeral one && gv.isFVar then counts := counts.insert gv.fvarId! (counts.getD gv.fvarId! 0 + 1)
        | _ => pure ()
      | _ => pure ()
    | _ => pure ()
  let arr := counts.toArray.filter fun (fv, c) => !(exclude.contains fv) && c ≥ 2
  return arr.qsort (fun x y => x.2 > y.2)

/-- One gate split: `by_cases hg : g = 0`, then normalize both branches.  Returns the split
variable when a split happened (two goals remain). -/
def gateSplitOnce (exclude : Array FVarId) : TacticM (Option FVarId) := do
  let cands ← gateCandidates exclude
  match cands[0]? with
  | none => return none
  | some (fv, _) =>
    let stx := mkIdent (← withMainContext fv.getUserName)
    let hg := mkIdent (← freshName "hg")
    evalTactic (← `(tactic| by_cases $hg:ident : $stx = 0))
    let gs ← getGoals
    match gs with
    | [gpos, gneg] =>
      setGoals [gpos]
      evalTactic (← `(tactic| try subst $hg:ident))
      evalTactic (← `(tactic| try simp only [zero_mul, mul_zero, sub_zero, zero_sub, one_mul, mul_one, add_zero, zero_add, neg_zero, neg_neg, sub_self, and_true, true_and, sub_eq_zero, not_true_eq_false] at *))
      evalTactic (← `(tactic| try casesm* _ ∧ _))
      evalTactic (← `(tactic| try subst_vars))
      let gpos' ← getGoals
      setGoals [gneg]
      evalTactic (← `(tactic| try simp only [ZirenDet.gate_left $hg:ident, ZirenDet.gate_right $hg:ident, sub_eq_zero] at *))
      evalTactic (← `(tactic| try casesm* _ ∧ _))
      evalTactic (← `(tactic| try subst_vars))
      let gneg' ← getGoals
      setGoals (gpos' ++ gneg')
      return some fv
    | _ => return none

/-- Split on up to `n` gates (applied to every goal produced so far). -/
partial def gateSplits (n : Nat) (exclude : Array FVarId) : TacticM Unit := do
  if n = 0 then return
  let gs ← getGoals
  let mut out := #[]
  for g in gs do
    setGoals [g]
    let did ← try gateSplitOnce exclude catch _ => pure none
    match did with
    | some fv =>
      let sub ← getGoals
      -- the `g = 0` branch (first) keeps splitting; the `g ≠ 0` branch gets one more level
      let mut first := true
      for s in sub do
        setGoals [s]
        gateSplits (if first then n - 1 else min (n - 1) 1) (exclude.push fv)
        first := false
        out := out ++ (← getGoals).toArray
    | none =>
      out := out ++ (← getGoals).toArray
  setGoals out.toList

elab "picus_gates" n:num : tactic => do nameAllStep; gateSplits n.getNat #[]

/-- One helper-saturation step: for `hR : ∀ i o o', R i o → R i o' → o = o'` and two
hypotheses `R i o`, `R i o'` (same `i`, different `o`), add `o = o'`, split and substitute. -/
def helpersStep : TacticM Bool := do
  let (dets, calls) ← withMainContext do
    let mut dets : Array (Expr × Expr) := #[]
    let mut calls : Array (Expr × Expr × Expr × Expr) := #[]
    for (d, ty) in ← hyps do
      if ty.isForall then
        match ty with
        | .forallE _ _ (.forallE _ _ (.forallE _ _ (.forallE _ p1 _ _) _) _) _ =>
          let r := p1.getAppFn
          if r.isConst || r.isFVar then dets := dets.push (d.toExpr, r)
        | _ => pure ()
      else
        match ty.getAppFnArgs with
        | (_, #[i, o]) =>
          let r := ty.getAppFn
          if r.isConst && (`rel).isSuffixOf r.constName! then
            calls := calls.push (d.toExpr, r, i, o)
        | _ => pure ()
    pure (dets, calls)
  for (hdet, r) in dets do
    for (h1, r1, i1, o1) in calls do
      if r1 != r then continue
      for (h2, r2, i2, o2) in calls do
        if r2 != r then continue
        if h1 == h2 then continue
        if i1 != i2 then continue
        if o1 == o2 then continue
        let ok ← try
          withMainContext do
            let val := mkAppN hdet #[i1, o1, o2, h1, h2]
            let ty ← inferType val
            let name ← freshName "hrel"
            let g ← getMainGoal
            let g ← g.assert name ty val
            let (fv, g) ← g.intro1P
            replaceMainGoal [g]
            let hid := mkIdent (← g.withContext fv.getUserName)
            evalTactic (← `(tactic| try simp only [List.cons.injEq, List.nil_eq, and_true, true_and] at $hid:ident))
            evalTactic (← `(tactic| try casesm* _ ∧ _))
            evalTactic (← `(tactic| try subst_vars))
            pure true
          catch _ => pure false
        if ok then return true
  return false

partial def helpersLoop (fuel : Nat) : TacticM Unit := do
  if fuel = 0 then return
  if ← helpersStep then helpersLoop (fuel - 1)

elab "picus_helpers" : tactic => helpersLoop 200

/-- The best range bound of `x`: `(isLt, bound hypothesis)`. -/
def findBound (hs : Array (LocalDecl × Expr)) (x : FVarId) : Option (Bool × Expr) := Id.run do
  let mut best : Option (Bool × Expr × Nat) := none
  for (d, ty) in hs do
    let (isLt, args) := match ty.getAppFnArgs with
      | (``LE.le, #[_, _, a, b]) => (false, some (a, b))
      | (``LT.lt, #[_, _, a, b]) => (true, some (a, b))
      | _ => (false, none)
    match args with
    | some (a, b) =>
      if a.isAppOfArity ``ZMod.val 2 && a.appArg! == mkFVar x then
        match b.nat? with
        | some c =>
          let c' := if isLt then c else c + 1
          match best with
          | some (_, _, bc) => if c' < bc then best := some (isLt, d.toExpr, c')
          | none => best := some (isLt, d.toExpr, c')
        | none => pure ()
    | none => pure ()
  return best.map fun (l, h, _) => (l, h)

/-- One lifting step: replace one field variable by an integer cast with its bound. -/
def liftStep : TacticM Bool := do
  let fType := mkConst ``ZirenDet.F
  let target ← withMainContext do
    let mut target : Option (Name × Option (Bool × Name)) := none
    let hs ← hyps
    for d in ← getLCtx do
      if d.isImplementationDetail then continue
      if d.isLet then continue
      if d.userName.hasMacroScopes then continue
      if ← isDefEq d.type fType then
        let b ← match findBound hs d.fvarId with
          | some (l, hb) => pure (some (l, ← hb.fvarId!.getUserName))
          | none => pure none
        target := some (d.userName, b)
        break
    pure target
  match target with
  | none => return false
  | some (x, bound) =>
    let xs := mkIdent x
    let rflI := mkIdent `rfl
    let n := mkIdent (Name.mkSimple ("n" ++ x.toString))
    let h0 := mkIdent (← freshName "h0")
    let h1 := mkIdent (← freshName "h1")
    try
      match bound with
      | some (false, hb) =>
        let hbs := mkIdent hb
        evalTactic (← `(tactic| obtain ⟨$n:ident, $h0:ident, $h1:ident, $rflI:ident⟩ := ZirenDet.lift_le $xs $hbs))
      | some (true, hb) =>
        let hbs := mkIdent hb
        evalTactic (← `(tactic| obtain ⟨$n:ident, $h0:ident, $h1:ident, $rflI:ident⟩ := ZirenDet.lift_lt $xs $hbs))
      | none =>
        evalTactic (← `(tactic| obtain ⟨$n:ident, $h0:ident, $h1:ident, $rflI:ident⟩ := ZirenDet.lift_any $xs))
      match bound with
      | some (_, hb) => evalTactic (← `(tactic| try clear $(mkIdent hb):ident))
      | none => pure ()
      -- the variable must be gone now; otherwise stop (no progress possible)
      let still ← withMainContext do
        let lctx ← getLCtx
        pure (lctx.findFromUserName? x).isSome
      return !still
    catch _ => return false

partial def liftLoop (fuel : Nat) : TacticM Unit := do
  if fuel = 0 then return
  if ← liftStep then liftLoop (fuel - 1)

elab "picus_lift" : tactic => do nameAllStep; liftLoop 3000

/-- Free variables of an expression. -/
def fvarsOf (e : Expr) : FVarIdSet :=
  (Lean.CollectFVars.main e {}).fvarSet

/-- Strict pruning for a goal `m = 0`: keep only the hypotheses whose variables all occur in the
hypotheses that mention `m` (the equation and the bounds of its atoms); clear the rest. -/
def pruneStrict : TacticM Unit := withMainContext do
  let g ← getMainGoal
  let goalVars := fvarsOf (← instantiateMVars (← g.getType))
  let hs ← hyps
  let mut toClear : Array FVarId := #[]
  for (d, ty) in hs do
    if !(← isProp ty) then continue
    let fv := fvarsOf ty
    if fv.toList.all goalVars.contains then continue
    toClear := toClear.push d.fvarId
  let g ← g.tryClearMany toClear
  replaceMainGoal [g]

elab "picus_prune_strict" : tactic => pruneStrict

/-- Closure pruning for an output goal: keep the hypotheses connected to the goal's variables
through shared variables (transitively); clear the rest. -/
def pruneClosureDepth (depth : Nat) : TacticM Unit := withMainContext do
  let g ← getMainGoal
  let hs ← hyps
  let mut vars : FVarIdSet := fvarsOf (← instantiateMVars (← g.getType))
  let mut keep : Std.HashSet FVarId := {}
  let mut changed := true
  let mut fuel := depth
  while changed && fuel > 0 do
    changed := false
    fuel := fuel - 1
    for (d, ty) in hs do
      if keep.contains d.fvarId then continue
      if !(← isProp ty) then continue
      let fv := fvarsOf ty
      if fv.toList.any vars.contains then
        keep := keep.insert d.fvarId
        for v in fv.toList do
          if !(vars.contains v) then
            vars := vars.insert v
            changed := true
  let mut toClear : Array FVarId := #[]
  for (d, ty) in hs do
    if !(← isProp ty) then continue
    if keep.contains d.fvarId then continue
    toClear := toClear.push d.fvarId
  let g ← g.tryClearMany toClear
  replaceMainGoal [g]

def pruneClosure : TacticM Unit := pruneClosureDepth 200

elab "picus_prune_closure" : tactic => pruneClosure
elab "picus_prune_depth " n:num : tactic => pruneClosureDepth n.getNat

/-- `omega` with a heartbeat budget; an overrun fails like an ordinary tactic failure. -/
elab "picus_omega " n:num : tactic => do
  let ok ← tryCatchRuntimeEx
    (do
      Core.withCurrHeartbeats <|
        withTheReader Core.Context (fun ctx => { ctx with maxHeartbeats := n.getNat * 1000 })
          (evalTactic (← `(tactic| omega)))
      pure true)
    (fun _ => pure false)
  if !ok then throwError "picus_omega: failed or over budget"

/-- Given `hm : E = 2130706433 * m`, try to show `m = 0` from the bounds of `E` alone (never
handing `omega` the `p * m` term); on success substitute and simplify, otherwise hide the
equation as `Slack E m`.  A bit constraint `k * (k - 1)` is dropped instead (its bound is
already in context). -/
def resolveSlack (hmN mN : Name) : TacticM Unit := do
  let hm := mkIdent hmN
  let m := mkIdent mN
  let hb := mkIdent (← freshName "hb")
  let hm0 := mkIdent (← freshName "hm0")
  let hs := mkIdent (← freshName "hs")
  let (isBit, E) ← withMainContext do
    match (← getLCtx).findFromUserName? hmN with
    | some d =>
      let ty ← instantiateMVars d.type
      match ty.getAppFnArgs with
      | (``Eq, #[_, lhs, _]) => pure ((lhs.find? fun e => (bitOf e).isSome).isSome, some lhs)
      | _ => pure (false, none)
    | none => pure (false, none)
  match E with
  | none => pure ()
  | some E =>
    if isBit then
      evalTactic (← `(tactic| clear $hm:ident))
      return
    let Es ← withMainContext (Term.exprToSyntax E)
    let ok ← try
      evalTactic (← `(tactic| have $hb:ident : -2130706433 < $Es ∧ $Es < 2130706433 := by
        (picus_prune_strict; picus_omega 2000)))
      pure true
    catch _ => pure false
    if ok then
      evalTactic (← `(tactic| have $hm0:ident := ZirenDet.slack_zero $hm:ident $hb:ident))
      evalTactic (← `(tactic| clear $hb:ident))
      evalTactic (← `(tactic| subst $hm0:ident))
      evalTactic (← `(tactic| simp only [mul_zero] at $hm:ident))
    else
      evalTactic (← `(tactic| have $hs:ident := ZirenDet.Slack.mk $hm:ident))
      evalTactic (← `(tactic| clear $hm:ident))

/-- Retry every hidden slack equation (substitutions may have made its bound provable). -/
def slackStep : TacticM Bool := do
  let cands ← withMainContext do
    let mut out : Array (Name × Name) := #[]
    for (d, ty) in ← hyps do
      match ty.getAppFnArgs with
      | (``ZirenDet.Slack, #[_, mE]) =>
        if mE.isFVar then out := out.push (d.userName, ← mE.fvarId!.getUserName)
      | _ => pure ()
    pure out
  let mut progress := false
  for (hsN, mN) in cands do
    let hm := mkIdent (← freshName "hm")
    let ok ← try
      evalTactic (← `(tactic| have $hm:ident := ($(mkIdent hsN)).eq))
      evalTactic (← `(tactic| clear $(mkIdent hsN):ident))
      pure true
    catch _ => pure false
    if !ok then continue
    -- is it resolved now?
    resolveSlack hm.getId mN
    let still ← withMainContext do pure ((← getLCtx).findFromUserName? mN).isSome
    if !still then progress := true
  return progress

/-- One equation step: turn a field equality between integer casts into an exact integer
equation.  `(A : F) = B` gives `B - A = p * k`; `omega` (from the range bounds alone) shows
`k = 0`, so the hypothesis becomes `B - A = 0`.  When the bounds do not force `k = 0` (an
equation that really wraps modulo `p`) the slack form is kept. -/
def eqStep : TacticM Bool := do
  let target ← withMainContext do
    let mut t : Option Name := none
    for (d, ty) in ← hyps do
      if d.userName.hasMacroScopes then continue
      match ty.getAppFnArgs with
      | (``Eq, #[_, lhs, rhs]) =>
        if lhs.isAppOfArity ``Int.cast 3 && rhs.isAppOfArity ``Int.cast 3 then
          t := some d.userName
          break
      | _ => pure ()
    pure t
  match target with
  | none => return false
  | some h =>
    let hI := mkIdent h
    let m := mkIdent (← freshName "m")
    let hm := mkIdent (← freshName "hm")
    let hm0 := mkIdent (← freshName "hm0")
    try
      evalTactic (← `(tactic| obtain ⟨$m:ident, $hm:ident⟩ := ZirenDet.cast_eq_iff_dvd.mp $hI))
      evalTactic (← `(tactic| clear $hI:ident))
      resolveSlack hm.getId m.getId
      return true
    catch _ => return false

partial def eqLoop (fuel : Nat) : TacticM Unit := do
  if fuel = 0 then return
  if ← eqStep then eqLoop (fuel - 1)

elab "picus_eqs" : tactic => do nameAllStep; eqLoop 2000

/-! Bounds for products of two bounded non-negative integer variables: for every subterm
`a * b` (in `ℤ`) with `0 ≤ a`, `a ≤ A`, `0 ≤ b`, `b ≤ B` in context, add `0 ≤ a * b` and
`a * b ≤ A * B`.  `omega` treats `a * b` as an atom and needs these. -/

/-- All subterms `a * b : ℤ` with `a`, `b` free variables. -/
partial def collectProds (e : Expr) : Array (Expr × Expr) :=
  let here : Array (Expr × Expr) :=
    match e.getAppFnArgs with
    | (``HMul.hMul, #[t, _, _, _, a, b]) =>
      if t.isConstOf ``Int && a.isFVar && b.isFVar then #[(a, b)] else #[]
    | _ => #[]
  match e with
  | .app f a => here ++ collectProds f ++ collectProds a
  | .lam _ t b _ | .forallE _ t b _ => here ++ collectProds t ++ collectProds b
  | .letE _ t v b _ => here ++ collectProds t ++ collectProds v ++ collectProds b
  | .mdata _ b => here ++ collectProds b
  | .proj _ _ b => here ++ collectProds b
  | _ => here

/-- All subterms `a * b : ℤ`. -/
partial def collectProdsAny (e : Expr) : Array (Expr × Expr) :=
  let here : Array (Expr × Expr) :=
    match e.getAppFnArgs with
    | (``HMul.hMul, #[t, _, _, _, a, b]) => if t.isConstOf ``Int then #[(a, b)] else #[]
    | _ => #[]
  match e with
  | .app f a => here ++ collectProdsAny f ++ collectProdsAny a
  | .lam _ t b _ | .forallE _ t b _ => here ++ collectProdsAny t ++ collectProdsAny b
  | .letE _ t v b _ => here ++ collectProdsAny t ++ collectProdsAny v ++ collectProdsAny b
  | .mdata _ b => here ++ collectProdsAny b
  | .proj _ _ b => here ++ collectProdsAny b
  | _ => here

def prodBoundsStep : TacticM Unit := do
  let (prods, lower, upper) ← withMainContext do
    let hs ← hyps
    let mut prods : Array (Expr × Expr) := #[]
    let mut lower : Std.HashMap FVarId Expr := {}   -- a ↦ proof of 0 ≤ a
    let mut upper : Std.HashMap FVarId (Expr × Expr) := {}  -- a ↦ (A, proof of a ≤ A)
    let intTy := mkConst ``Int
    for (d, ty) in hs do
      match ty.getAppFnArgs with
      | (``LE.le, #[t, _, lo, hi]) =>
        if t == intTy then
          if hi.isFVar && (lo.int? == some 0 || lo.nat? == some 0) then
            lower := lower.insert hi.fvarId! d.toExpr
          if lo.isFVar && !hi.isFVar && !(hi.hasFVar) then
            upper := upper.insert lo.fvarId! (hi, d.toExpr)
      | _ => pure ()
      -- products
      for sub in collectProds ty do
        prods := prods.push sub
    pure (prods, lower, upper)
  let mut seen : Std.HashSet (FVarId × FVarId) := {}
  for (a, b) in prods do
    let key := (a.fvarId!, b.fvarId!)
    if seen.contains key then continue
    seen := seen.insert key
    match lower.get? a.fvarId!, lower.get? b.fvarId!, upper.get? a.fvarId!, upper.get? b.fvarId! with
    | some h0a, some h0b, some (_, hA), some (_, hB) =>
      try
        withMainContext do
          let nn ← mkAppM ``mul_nonneg #[h0a, h0b]
          let h0A ← mkAppM ``le_trans #[h0a, hA]
          let ub ← mkAppM ``mul_le_mul #[hA, hB, h0b, h0A]
          let g ← getMainGoal
          let g ← g.assert (← freshName "hp0") (← inferType nn) nn
          let (_, g) ← g.intro1P
          let g ← g.assert (← freshName "hp1") (← inferType ub) ub
          let (_, g) ← g.intro1P
          replaceMainGoal [g]
      catch _ => pure ()
    | _, _, _, _ => pure ()

elab "picus_prod_bounds" : tactic => prodBoundsStep

/-- Timing helper: logs `label` with the elapsed time when `PICUS_TIMING` is set. -/
def timed (label : String) (act : TacticM Unit) : TacticM Unit := do
  let on := (← IO.getEnv "PICUS_TIMING").isSome
  let t0 ← IO.monoMsNow
  act
  if on then
    let t1 ← IO.monoMsNow
    dbgLog s!"picus timing: {label} {t1 - t0} ms"

elab "picus_timed " l:str t:tactic : tactic => timed l.getString (evalTactic t)

/-! ### The integer solve loop (Picus-style propagation) -/

/-- Run `act` with its own heartbeat budget (in thousands, like `maxHeartbeats`), turning a
budget overrun into an ordinary failure. -/
def withBudget (kilo : Nat) (act : TacticM α) : TacticM α := do
  Core.withCurrHeartbeats <|
    withTheReader Core.Context (fun ctx => { ctx with maxHeartbeats := kilo * 1000 }) act

/-- Try to prove `ty` (a Prop) from the current context with `picus_prune_closure; omega`.
Returns the proof term, restoring the tactic state on failure. -/
def tryOmega (ty : Expr) (depth : Nat := 2) (kilo : Nat := 2000) : TacticM (Option Expr) := do
  let saved ← saveState
  let g ← getMainGoal
  let mv ← withMainContext (mkFreshExprMVar ty)
  let t0 ← IO.monoMsNow
  let on := (← IO.getEnv "PICUS_TIMING").isSome
  if on then dbgLog s!"picus tryOmega start: {← ppExpr ty}"
  let res ← tryCatchRuntimeEx
    (do
      setGoals [mv.mvarId!]
      pruneClosureDepth depth
      if (← IO.getEnv "PICUS_DUMP").isSome then
        dbgLog s!"picus goal dump:\n{← Meta.ppGoal (← getMainGoal)}"
      withBudget kilo (evalTactic (← `(tactic| omega)))
      let pf ← instantiateMVars mv
      pure (some pf))
    (fun _ => pure none)
  match res with
  | some pf =>
    setGoals [g]
    if on then dbgLog s!"picus tryOmega ok {(← IO.monoMsNow) - t0} ms: {← ppExpr ty}"
    return some pf
  | none =>
    saved.restore
    setGoals [g]
    if on then dbgLog s!"picus tryOmega fail {(← IO.monoMsNow) - t0} ms: {← ppExpr ty}"
    return none

/-- Names of the integer variables of the two worlds, paired by index. -/
def worldPairs : TacticM (Array (Name × Name)) := withMainContext do
  let lctx ← getLCtx
  let mut out := #[]
  for d in lctx do
    if d.isImplementationDetail then continue
    let n := d.userName.toString
    if n.startsWith "na_" then
      let bn := Name.mkSimple ("nb_" ++ n.drop 3)
      if (lctx.findFromUserName? bn).isSome then out := out.push (d.userName, bn)
  return out

def simpAfterSubst : TacticM Unit := do
  evalTactic (← `(tactic| try simp only [zero_mul, mul_zero, one_mul, mul_one, sub_zero, zero_sub,
    add_zero, zero_add, neg_zero, sub_self, mul_neg, neg_mul, neg_neg, Int.sub_self] at *))

/-- Propagation: for every pair `na_i`, `nb_i` still distinct, try `na_i = nb_i`; on success
substitute `nb_i` away.  Returns `true` on progress. -/
def propStep : TacticM Bool := do
  let mut progress := false
  let pairs ← worldPairs
  dbgLog s!"picus prop: {pairs.size} pairs"
  for (an, bn) in pairs do
    let ok ← withMainContext do
      let lctx ← getLCtx
      match lctx.findFromUserName? an, lctx.findFromUserName? bn with
      | some da, some db =>
        let ty ← mkEq (mkFVar da.fvarId) (mkFVar db.fvarId)
        match ← tryOmega ty with
        | some pf =>
          let g ← getMainGoal
          let g ← g.assert (← freshName "heq") ty pf
          let (_, g) ← g.intro1P
          replaceMainGoal [g]
          pure true
        | none => pure false
      | _, _ => pure false
    if ok then
      try
        evalTactic (← `(tactic| subst $(mkIdent bn):ident))
        progress := true
      catch _ => pure ()
  return progress

/-- Bits (`0 ≤ k`, `k ≤ 1`) that the context already determines: try `k = 0`, then `k = 1`;
substitute on success. -/
def bitVars : TacticM (Array Name) := withMainContext do
  let mut lows : Std.HashSet FVarId := {}
  let mut out := #[]
  let hs ← hyps
  for (_, ty) in hs do
    match ty.getAppFnArgs with
    | (``LE.le, #[_, _, lo, hi]) =>
      if hi.isFVar && (lo.int? == some 0 || lo.nat? == some 0) then lows := lows.insert hi.fvarId!
    | _ => pure ()
  for (_, ty) in hs do
    match ty.getAppFnArgs with
    | (``LE.le, #[_, _, lo, hi]) =>
      if lo.isFVar && lows.contains lo.fvarId! then
        let one := match hi.getAppFnArgs with
          | (``Nat.cast, #[_, _, n]) => n.nat? == some 1
          | _ => hi.int? == some 1 || hi.nat? == some 1
        if one then out := out.push (← lo.fvarId!.getUserName)
    | _ => pure ()
  return out

def constStep : TacticM Bool := do
  let mut progress := false
  let bits ← bitVars
  dbgLog s!"picus const: {bits.size} bits"
  for kn in bits do
    let ok ← withMainContext do
      match (← getLCtx).findFromUserName? kn with
      | some dk =>
        let k := mkFVar dk.fvarId
        let zero ← mkAppOptM ``OfNat.ofNat #[mkConst ``Int, mkRawNatLit 0, none]
        let one ← mkAppOptM ``OfNat.ofNat #[mkConst ``Int, mkRawNatLit 1, none]
        let tys := #[← mkEq k zero, ← mkEq k one]
        let mut done := false
        for ty in tys do
          if done then break
          match ← tryOmega ty with
          | some pf =>
            let g ← getMainGoal
            let g ← g.assert (← freshName "hk") ty pf
            let (_, g) ← g.intro1P
            replaceMainGoal [g]
            done := true
          | none => pure ()
        pure done
      | none => pure false
    if ok then
      try
        evalTactic (← `(tactic| subst $(mkIdent kn):ident))
        simpAfterSubst
        progress := true
      catch _ => pure ()
  return progress

/-- Bits that occur as a factor of a product in some hypothesis, most frequent first. -/
def bitGateCandidates (exclude : Array Name) : TacticM (Array (Name × Nat)) := withMainContext do
  let bits ← bitVars
  let lctx ← getLCtx
  let mut counts : Std.HashMap Name Nat := {}
  for (_, ty) in ← hyps do
    for (a, b) in collectProdsAny ty do
      -- a bit anywhere inside a factor (`k * E`, `x * (1 + k)`, …) makes the product
      -- non-linear for `omega`; splitting it linearizes the product
      for x in [a, b] do
        for fv in (fvarsOf x).toList do
          let n ← fv.getUserName
          if bits.contains n && !(exclude.contains n) then
            counts := counts.insert n (counts.getD n 0 + 1)
  let _ := lctx
  return counts.toArray.qsort (fun x y => x.2 > y.2)

/-- One bit split `k = 0 ∨ k = 1` on the most frequent product bit; both branches are normalized.
Returns the split variable. -/
def bitSplitOnce (exclude : Array Name) : TacticM (Option Name) := do
  let cands ← bitGateCandidates exclude
  match cands[0]? with
  | none => return none
  | some (kn, _) =>
    let k := mkIdent kn
    let hk := mkIdent (← freshName "hk")
    evalTactic (← `(tactic| by_cases $hk:ident : $k:ident = 0))
    match ← getGoals with
    | [gpos, gneg] =>
      setGoals [gpos]
      evalTactic (← `(tactic| subst $hk:ident))
      simpAfterSubst
      let gpos' ← getGoals
      setGoals [gneg]
      evalTactic (← `(tactic| have $hk:ident : $k:ident = 1 := by (picus_prune_depth 1; picus_omega 2000)))
      evalTactic (← `(tactic| subst $hk:ident))
      simpAfterSubst
      let gneg' ← getGoals
      setGoals (gpos' ++ gneg')
      return some kn
    | _ => return none

/-- Global cap on bit splits per `picus_solve` call. -/
initialize splitCounter : IO.Ref Nat ← IO.mkRef 0

/-- Start time of the current `picus_solve` call (ms) and its wall-clock budget. -/
initialize solveStart : IO.Ref Nat ← IO.mkRef 0

def solveBudgetMs : Nat := 600000

def overBudget : IO Bool := do
  let t0 ← solveStart.get
  return (← IO.monoMsNow) - t0 > solveBudgetMs

/-- The solve loop on one goal: propagate pairs and constants (re-running the slack
elimination), and when stuck split one shared bit; `budget` bounds the split depth. -/
partial def solveLoop (budget : Nat) (exclude : Array Name) : TacticM Unit := do
  let mut fuel := 50
  let on := (← IO.getEnv "PICUS_TIMING").isSome
  while fuel > 0 do
    fuel := fuel - 1
    if ← overBudget then break
    let t0 ← IO.monoMsNow
    let p0 ← try slackStep catch _ => pure false
    let p1 ← try propStep catch _ => pure false
    let p2 ← try constStep catch _ => pure false
    if on then dbgLog s!"picus round budget {budget}: slack {p0} prop {p1} const {p2} in {(← IO.monoMsNow) - t0} ms"
    if p0 || p1 || p2 then
      eqLoop 200
    else break
  if budget = 0 then return
  if (← splitCounter.get) ≥ 300 then return
  if ← overBudget then return
  let did ← try bitSplitOnce exclude catch _ => pure none
  match did with
  | none => return
  | some kn =>
    splitCounter.modify (· + 1)
    dbgLog s!"picus split #{← splitCounter.get} depth-budget {budget} on {kn} → {(← getGoals).length} goals"
    let gs ← getGoals
    let mut out := #[]
    for s in gs do
      setGoals [s]
      eqLoop 200
      solveLoop (budget - 1) (exclude.push kn)
      out := out ++ (← getGoals).toArray
    setGoals out.toList

elab "picus_solve" : tactic => do
  dbgLog "picus solve: start"
  splitCounter.set 0
  solveStart.set (← IO.monoMsNow)
  let gs ← getGoals
  let mut out := #[]
  for g in gs do
    setGoals [g]
    solveLoop 12 #[]
    out := out ++ (← getGoals).toArray
  setGoals out.toList

/-- Clear hypotheses `omega` cannot use (disjunctions, helper relations, ∀).  Keeps `↔`. -/
def clearJunk : TacticM Unit := do
  let toClear ← withMainContext do
    let mut toClear : Array FVarId := #[]
    for (d, ty) in ← hyps do
      if ty.isAppOfArity ``Or 2 || ty.isForall then toClear := toClear.push d.fvarId
      else
        let r := ty.getAppFn
        if r.isConst && (`rel).isSuffixOf r.constName! then toClear := toClear.push d.fvarId
    pure toClear
  for fv in toClear do
    try
      let g ← getMainGoal
      let g ← g.clear fv
      replaceMainGoal [g]
    catch _ => pure ()

elab "picus_clear_junk" : tactic => clearJunk

end ZirenDet.Picus

/-- Structural opening shared by every generated theorem. -/
syntax "picus_open" (" [" term,* "]")? : tactic
set_option hygiene false in
macro_rules
  | `(tactic| picus_open) => `(tactic| picus_open [constraints])
  | `(tactic| picus_open [$ts,*]) =>
    `(tactic| (
        (try intros)
        (try cases w)
        (try picus_name_world "a")
        (try cases w')
        (try picus_name_world "b")
        (try simp only [constraints, $[$ts:term],*, inputs, outputs, assumed, List.cons.injEq,
               List.nil_eq, and_true, true_and, sub_eq_zero, W.mk.injEq,
               mul_inv_eq_iff_eq_mul₀ ZirenDet.two_ne, mul_inv_eq_iff_eq_mul₀ ZirenDet.four_ne,
               mul_inv_eq_iff_eq_mul₀ ZirenDet.eight_ne, mul_inv_eq_iff_eq_mul₀ ZirenDet.sixteen_ne,
               mul_inv_eq_iff_eq_mul₀ ZirenDet.c32_ne, mul_inv_eq_iff_eq_mul₀ ZirenDet.c64_ne,
               mul_inv_eq_iff_eq_mul₀ ZirenDet.c128_ne, mul_inv_eq_iff_eq_mul₀ ZirenDet.c256_ne,
               mul_inv_eq_iff_eq_mul₀ ZirenDet.c512_ne, mul_inv_eq_iff_eq_mul₀ ZirenDet.c1024_ne,
               mul_inv_eq_iff_eq_mul₀ ZirenDet.c2048_ne, mul_inv_eq_iff_eq_mul₀ ZirenDet.c4096_ne,
               mul_inv_eq_iff_eq_mul₀ ZirenDet.c8192_ne, mul_inv_eq_iff_eq_mul₀ ZirenDet.c16384_ne,
               mul_inv_eq_iff_eq_mul₀ ZirenDet.c32768_ne, mul_inv_eq_iff_eq_mul₀ ZirenDet.c65536_ne,
               mul_inv_eq_iff_eq_mul₀ ZirenDet.c131072_ne, mul_inv_eq_iff_eq_mul₀ ZirenDet.c262144_ne,
               mul_inv_eq_iff_eq_mul₀ ZirenDet.c524288_ne, mul_inv_eq_iff_eq_mul₀ ZirenDet.c1048576_ne,
               mul_inv_eq_iff_eq_mul₀ ZirenDet.c2097152_ne, mul_inv_eq_iff_eq_mul₀ ZirenDet.c4194304_ne,
               mul_inv_eq_iff_eq_mul₀ ZirenDet.c8388608_ne, mul_inv_eq_iff_eq_mul₀ ZirenDet.c16777216_ne] at *)
        (try casesm* _ ∧ _)
        (try subst_vars)))

/-- The integer preparation of one branch: lift every field variable to an integer with its
bound, pull casts to the top, and make every equation an exact integer equation. -/
syntax "picus_prep" : tactic
macro_rules
  | `(tactic| picus_prep) =>
    `(tactic| (
        picus_clear_junk
        picus_lift
        (try simp only [ZirenDet.gen_iff] at *)
        (try simp only [ZirenDet.castF_one, ZirenDet.castF_zero, ZirenDet.castF_ofNat, ZirenDet.castF_add,
               ZirenDet.castF_sub, ZirenDet.castF_mul, ZirenDet.castF_neg, ZirenDet.castF_pow] at *)
        (try picus_prod_bounds)
        picus_eqs))

/-- Close one lifted goal. -/
syntax "picus_close" : tactic
macro_rules
  | `(tactic| picus_close) =>
    `(tactic| first | trivial | rfl
                    | (rw [ZirenDet.cast_eq_iff_dvd]; refine ⟨0, ?_⟩; picus_prune_closure; omega)
                    | (simp only [ZirenDet.val_cast]; picus_prune_closure; omega)
                    | (picus_prune_closure; omega))

/-- The integer finish for a single goal (prep + close). -/
syntax "picus_finish" : tactic
macro_rules
  | `(tactic| picus_finish) => `(tactic| (picus_prep; picus_close))

/-- Closing tactic for generated determinism / postcondition theorems. -/
syntax "picus_det" (" [" term,* "]")? : tactic
set_option hygiene false in
macro_rules
  | `(tactic| picus_det) => `(tactic| picus_det [constraints])
  | `(tactic| picus_det [$ts,*]) =>
    `(tactic| (
        picus_timed "open" (picus_open [$ts,*])
        picus_name_all
        picus_timed "generalize" (try picus_generalize)
        (try simp only [mul_inv_eq_iff_eq_mul₀ ZirenDet.two_ne, mul_inv_eq_iff_eq_mul₀ ZirenDet.c128_ne,
               mul_inv_eq_iff_eq_mul₀ ZirenDet.c256_ne, mul_inv_eq_iff_eq_mul₀ ZirenDet.c65536_ne,
               mul_inv_eq_iff_eq_mul₀ ZirenDet.c16777216_ne, sub_eq_zero] at *)
        (try subst_vars)
        (try picus_bits)
        picus_timed "gates" (try picus_gates 2)
        all_goals (try picus_bits)
        all_goals picus_timed "helpers" (try picus_helpers)
        all_goals picus_timed "prep" (try picus_prep)
        all_goals picus_timed "solve" (try picus_solve)
        all_goals (try constructorm* _ ∧ _)
        all_goals picus_timed "close" (first | picus_close | sorry)))
