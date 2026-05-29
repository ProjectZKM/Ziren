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
    eval_state::<AB>(builder, pv);
    eval_global_memory_init::<AB>(builder, pv);
    eval_global_memory_finalize::<AB>(builder, pv);
}

/// Recompose a 32-bit little-endian bit array into a single field element
/// (mod the field), matching `memory/global.rs`'s `prev_addr` recompose
/// (`Σ bit_i · 2^i`).  Addresses are carried as one field element + a
/// 32-bit decomposition; the `< 2^32` ordering is enforced by the bit
/// comparison, while this recompose is the field-element form used on the
/// `MemoryGlobal*Control` bus tuple.
fn addr_from_bits<AB: ZKMAirBuilder>(bits: &[AB::PublicVar; 32]) -> AB::Expr {
    let mut acc = AB::Expr::ZERO;
    for (i, bit) in bits.iter().enumerate() {
        acc += (*bit).into() * AB::Expr::from_u32(1u32 << i);
    }
    acc
}

/// `MemoryGlobalInitControl` boundary: anchor the global-memory-init
/// address-ordering chain.  The `MemoryGlobalChip` (Initialize) rows form
/// `receive(index, prev_addr, prev_valid) -> send(index+1, addr, is_comp)`
/// (sorted, strictly-increasing addresses).  This SENDs the chain head
/// `(0, previous_init_addr, 1)` [received by row 0 as its prev_addr] and
/// RECEIVEs the chain tail `(global_init_count, last_init_addr, 1)` [sent
/// by the last real row].  Tuple = [index, addr, valid] (3 values).
fn eval_global_memory_init<AB: ZKMAirBuilder>(
    builder: &mut AB,
    pv: &PublicValues<Word<AB::PublicVar>, AB::PublicVar>,
) {
    let prev_addr = addr_from_bits::<AB>(&pv.previous_init_addr_bits);
    let last_addr = addr_from_bits::<AB>(&pv.last_init_addr_bits);
    builder.send(
        AirLookup::new(
            vec![AB::Expr::ZERO, prev_addr, AB::Expr::ONE],
            AB::Expr::ONE,
            LookupKind::MemoryGlobalInitControl,
        ),
        LookupScope::Local,
    );
    builder.receive(
        AirLookup::new(
            vec![pv.global_init_count.into(), last_addr, AB::Expr::ONE],
            AB::Expr::ONE,
            LookupKind::MemoryGlobalInitControl,
        ),
        LookupScope::Local,
    );
}

/// `MemoryGlobalFinalizeControl` boundary: the finalize analogue of
/// [`eval_global_memory_init`] (`previous_finalize_addr` / `last_finalize_addr`
/// / `global_finalize_count`).
fn eval_global_memory_finalize<AB: ZKMAirBuilder>(
    builder: &mut AB,
    pv: &PublicValues<Word<AB::PublicVar>, AB::PublicVar>,
) {
    let prev_addr = addr_from_bits::<AB>(&pv.previous_finalize_addr_bits);
    let last_addr = addr_from_bits::<AB>(&pv.last_finalize_addr_bits);
    builder.send(
        AirLookup::new(
            vec![AB::Expr::ZERO, prev_addr, AB::Expr::ONE],
            AB::Expr::ONE,
            LookupKind::MemoryGlobalFinalizeControl,
        ),
        LookupScope::Local,
    );
    builder.receive(
        AirLookup::new(
            vec![pv.global_finalize_count.into(), last_addr, AB::Expr::ONE],
            AB::Expr::ONE,
            LookupKind::MemoryGlobalFinalizeControl,
        ),
        LookupScope::Local,
    );
}

/// `State` boundary: anchor the CPU `(shard, clk, pc, next_pc)` chain.
///
/// The Cpu rows form a chain `receive(state_i) -> send(state_{i+1})` (see
/// `cpu/air/mod.rs::eval`).  This SENDS the initial endpoint `(shard,
/// initial_timestamp, start_pc, start_next_pc)` (received by the first
/// real row) and RECEIVES the final endpoint `(shard, last_timestamp,
/// next_pc, next_next_pc)` (sent by the halting row).  The multiset
/// balances iff the prover laid a consistent CPU sequence whose endpoints
/// equal these public values — the local-only replacement for the legacy
/// `when_first_row`/`when_last_row` pc/clk boundary constraints.
///
/// MIPS note: the state is the 2-pc pair `(pc, next_pc)` (delay-slot
/// lookahead).  At halt the executor sets `next_pc = 0`, so the final
/// endpoint's `pc = next_pc (public) = 0`-region and its `next_pc =
/// next_next_pc (public)` come straight from the public values.  Review:
/// the executor must populate `start_next_pc`/`next_next_pc` to exactly
/// the first row's `next_pc` and the last row's `next_next_pc`.
fn eval_state<AB: ZKMAirBuilder>(
    builder: &mut AB,
    pv: &PublicValues<Word<AB::PublicVar>, AB::PublicVar>,
) {
    // Initial endpoint — sent here, received by the first real Cpu row.
    builder.send_state(pv.shard, pv.initial_timestamp, pv.start_pc, pv.start_next_pc, AB::Expr::ONE);
    // Final endpoint — received here, sent by the last (halting) Cpu row.
    builder.receive_state(pv.shard, pv.last_timestamp, pv.next_pc, pv.next_next_pc, AB::Expr::ONE);
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
