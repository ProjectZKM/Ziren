//! Public-values AIR for the MIPS core machine (local-only constraints).
//!
//! No chip constrains across rows.  Every cross-row relation is a
//! multiset-balanced control-bus chain `receive(s_i) → send(s_{i+1})`, and
//! [`eval_public_values`] emits the two boundary endpoints `(s_0, s_n)` of
//! each chain from the public values:
//!   * `GlobalAccumulation`: the global cumulative sum;
//!   * `State`: initial / final `(shard, clk, pc, next_pc)` (MIPS carries the
//!     delay-slot lookahead `next_pc`);
//!   * `MemoryGlobalInit/FinalizeControl`: the address-ordering chains.
//!
//! The prover (accumulating the global LogUp sum) and the verifier (checking
//! the balance) both evaluate these emitters, so the interaction kinds used
//! are exactly those with
//! [`crate::lookup::LookupKind::appears_in_eval_public_values`].

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
/// equal these public values; no `when_first_row` / `when_last_row`
/// boundary constraint is needed.
///
/// MIPS note: the state is the 2-pc pair `(pc, next_pc)` (delay-slot
/// lookahead).  At halt the executor sets `next_pc = 0`, so the final
/// endpoint's `pc = next_pc (public) = 0`-region and its `next_pc =
/// next_next_pc (public)` come straight from the public values.  The
/// executor must populate `start_next_pc`/`next_next_pc` to exactly
/// the first row's `next_pc` and the last row's `next_next_pc`.
///
/// The bus tuple's shard field is `execution_shard`, NOT `shard`: the Cpu
/// chip's own `shard` column is filled from
/// `input.public_values.execution_shard`, and the chain endpoints the Cpu AIR
/// emits use that column, so the boundary endpoints must use the same
/// quantity or the `State` multiset cannot close.  (`shard` counts every
/// shard, `execution_shard` only Cpu shards; they differ after the first
/// shard without a Cpu chip.)
///
/// On a non-Cpu shard the two endpoints below are the identical tuple (the
/// executor leaves `start_pc == next_pc` and the timestamps equal), so send
/// and receive cancel exactly and the choice of shard field is inert there.
fn eval_state<AB: ZKMAirBuilder>(
    builder: &mut AB,
    pv: &PublicValues<Word<AB::PublicVar>, AB::PublicVar>,
) {
    builder.send_state(
        pv.execution_shard,
        pv.initial_timestamp,
        pv.start_pc,
        pv.start_next_pc,
        AB::Expr::ONE,
    );
    builder.receive_state(
        pv.execution_shard,
        pv.last_timestamp,
        pv.next_pc,
        pv.next_next_pc,
        AB::Expr::ONE,
    );
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
    let send_values: Vec<AB::Expr> =
        once(AB::Expr::ZERO).chain(initial.x.0).chain(initial.y.0).collect();
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
