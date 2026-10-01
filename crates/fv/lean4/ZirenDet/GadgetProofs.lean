import ZirenDet.LeadingOne
import ZirenDet.DivRem
import ZirenDet.CanonicalWord
import ZirenDet.FieldOp
import ZirenDet.Primes
import ZirenDet.Edwards
import ZirenDet.Keccak
import ZirenDet.OneHot
import ZirenDet.GtBytes
import ZirenDet.Septic

/-!
# Gadget proofs (hand-maintained)

The libraries the hand-written proofs of `snippets/` rest on.  A snippet is spliced into a
generated chip file before its determinism theorem and proves `gadget_det`, which the replayed
derivation uses at the steps the analyser took from a gadget summary.
-/
