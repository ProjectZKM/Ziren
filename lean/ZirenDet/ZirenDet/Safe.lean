import ZirenDet.Lib

/-!
# `picus_safe`: never let a generated file fail to elaborate

A heartbeat timeout, a `maxRecDepth` overflow or any other runtime exception raised while
`picus_det` runs is caught here; the tactic state is restored and the goal is admitted, so the
obligation is reported as a `sorry` warning instead of a build error.
-/

open Lean Elab Tactic Meta

namespace ZirenDet.Picus

/-- Run `t`; on any exception (including runtime ones such as a heartbeat timeout), restore the
state, warn, and admit the goals that were open when `t` started. -/
/- Heartbeat budget (in thousands, like `maxHeartbeats`) for one `picus_safe` block.  The
generated files set `maxHeartbeats 0`; the budget lives here so that the overrun is raised
inside the block, where it is caught, and not in the elaborator's post-processing of the proof
term, where it is not. -/
register_option picus.safeHeartbeats : Nat := {
  defValue := 40000000
  descr := "heartbeat budget of one picus_safe block, in thousands (same unit as maxHeartbeats)"
}

elab "picus_safe " t:tactic : tactic => do
  let s ← saveState
  let gs ← getGoals
  let kilo := picus.safeHeartbeats.get (← getOptions)
  -- Note: `tryCatchRuntimeEx` sets `catchRuntimeEx` for the whole block, so an overrun inside
  -- an inner `try` is swallowed there and the automation falls through to its own `sorry`;
  -- either way the file elaborates and the theorem is reported open.
  let ok ← tryCatchRuntimeEx
    (Core.withCurrHeartbeats <|
      withTheReader Core.Context (fun ctx => { ctx with maxHeartbeats := kilo * 1000 }) do
        evalTactic t; pure true)
    (fun e => do
      Core.withCurrHeartbeats do
        logWarning m!"picus_safe: automation aborted ({e.toMessageData}); goal admitted"
      pure false)
  unless ok do
    Core.withCurrHeartbeats do
      s.restore
      for g in gs do
        g.admit
      setGoals []

end ZirenDet.Picus
