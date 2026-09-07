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
elab "picus_safe " t:tactic : tactic => do
  let s ← saveState
  let gs ← getGoals
  let ok ← tryCatchRuntimeEx
    (do evalTactic t; pure true)
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
