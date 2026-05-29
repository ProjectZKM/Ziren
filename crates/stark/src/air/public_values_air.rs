//! Public-values AIR for the MIPS core machine (Option 2, local-only).
//!
//! Ziren historically had no core-machine public-values AIR: cross-row
//! relations were enforced with `when_transition` constraints and the
//! global cumulative sum was closed by summing each chip's last-row
//! digest in the verifier (`machine.rs`).  The local-only / SP1-hypercube
//! model instead pushes every cross-row relation onto a multiset-balanced
//! control-bus interaction whose two boundary endpoints are emitted here,
//! from the public values, by [`eval_public_values`].
//!
//! Mirrors SP1 `crates/core/executor/src/record.rs::eval_public_values`
//! (+ `eval_global_sum` / `eval_state` / `eval_global_memory_*`).  The
//! emitters here are evaluated by both the prover (when accumulating the
//! global LogUp sum) and the verifier (when checking the balance), so the
//! interaction kinds they use are exactly those for which
//! [`crate::lookup::LookupKind::appears_in_eval_public_values`] is true.
//!
//! NOTE (incremental): the `GlobalAccumulation` boundary is wired first
//! (it directly replaces the per-chip last-row digest sum).  The `State`
//! boundary (initial/final `(shard, clk, pc, next_pc)` — MIPS carries a
//! delay-slot `next_pc` lookahead, unlike SP1's `(clk, pc)`) and the
//! `MemoryGlobalInit/Finalize` boundaries follow.

use core::borrow::Borrow;
use core::iter::once;

use p3_field::PrimeCharacteristicRing;

use crate::air::{AirLookup, LookupScope, PublicValues, ZKMAirBuilder, ZKM_PROOF_NUM_PV_ELTS};
use crate::lookup::LookupKind;
use crate::septic_digest::SepticDigest;
use crate::Word;

/// Emit the public-values boundary interactions that close the local-only
/// control buses.  Called once per shard by the machine's interaction
/// accounting (prover) and the shard verifier (balance check).
pub fn eval_public_values<AB: ZKMAirBuilder>(builder: &mut AB) {
    let pv_slice: [AB::PublicVar; ZKM_PROOF_NUM_PV_ELTS] =
        core::array::from_fn(|i| builder.public_values()[i]);
    let pv: &PublicValues<Word<AB::PublicVar>, AB::PublicVar> = pv_slice.as_slice().borrow();

    eval_global_sum::<AB>(builder, pv);
    // TODO(Option 2): eval_state (State bus: initial/final (shard,clk,pc,next_pc))
    // and eval_global_memory_init/finalize follow, once the corresponding
    // chips are converted to receive/send chaining.
}

/// `GlobalAccumulation` boundary: anchor the running-digest chain.
///
/// The `GlobalChip` rows form a chain `receive(index, running) ->
/// send(index+1, running + point)`.  This sends the initial endpoint
/// `(0, ZERO_DIGEST)` (received by row 0) and receives the final endpoint
/// `(global_count, global_cumulative_sum)` (sent by the last row).  The
/// multiset balances iff the prover laid down a contiguous `index=0..N`
/// chain whose final digest equals the public `global_cumulative_sum` —
/// the local-only replacement for the verifier's per-chip last-row sum.
fn eval_global_sum<AB: ZKMAirBuilder>(
    builder: &mut AB,
    pv: &PublicValues<Word<AB::PublicVar>, AB::PublicVar>,
) {
    let initial = SepticDigest::<AB::Expr>::zero().0;
    let send_values: Vec<AB::Expr> = once(AB::Expr::ZERO)
        .chain(initial.x.0)
        .chain(initial.y.0)
        .collect();
    builder.send(
        AirLookup::new(send_values, AB::Expr::ONE, LookupKind::GlobalAccumulation),
        LookupScope::Local,
    );

    let recv_values: Vec<AB::Expr> = once(pv.global_count.into())
        .chain(pv.global_cumulative_sum.0.x.0.into_iter().map(Into::into))
        .chain(pv.global_cumulative_sum.0.y.0.into_iter().map(Into::into))
        .collect();
    builder.receive(
        AirLookup::new(recv_values, AB::Expr::ONE, LookupKind::GlobalAccumulation),
        LookupScope::Local,
    );
}
