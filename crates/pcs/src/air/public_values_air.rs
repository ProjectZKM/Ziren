//! Public-values AIR for the MIPS core machine (local-only constraints).
//!
//! No chip constrains across rows.  Every cross-row relation is a
//! multiset-balanced control-bus chain `receive(s_i) → send(s_{i+1})`, and
//! [`eval_public_values`] emits the two boundary endpoints `(s_0, s_n)` of
//! each chain from the public values:
//!   * `State`: initial / final `(shard, clk, pc, next_pc)` (MIPS carries the
//!     delay-slot lookahead `next_pc`);
//!   * `MemoryGlobalInit/FinalizeControl`: the address-ordering chains.
//!
//! The prover (accumulating the global LogUp sum) and the verifier (checking
//! the balance) both evaluate these emitters, so the interaction kinds used
//! are exactly those with
//! [`crate::lookup::LookupKind::appears_in_eval_public_values`].

use core::borrow::Borrow;

use p3_field::PrimeCharacteristicRing;

use crate::air::{AirLookup, LookupScope, PublicValues, ZKMAirBuilder, ZKM_PROOF_NUM_PV_ELTS};
use crate::lookup::LookupKind;
use crate::Word;

/// Emit the public-values boundary interactions that close the local-only
/// control buses.  Called once per shard by the machine's interaction
/// accounting (prover) and the shard verifier (balance check).
pub fn eval_public_values<AB: ZKMAirBuilder>(builder: &mut AB) {
    let pv_slice: [AB::PublicVar; ZKM_PROOF_NUM_PV_ELTS] =
        core::array::from_fn(|i| builder.public_values()[i]);
    let pv: &PublicValues<Word<AB::PublicVar>, AB::PublicVar> = pv_slice.as_slice().borrow();

    eval_state::<AB>(builder, pv);
    eval_global_memory_init::<AB>(builder, pv);
    eval_global_memory_finalize::<AB>(builder, pv);
}

/// The two 16-bit limbs the 32 elements of an address spell: the sums
/// `Σ bit_i · 2^i` over the low and over the high 16 of them. They are the
/// `[addr_lo, addr_hi]` of a `MemoryGlobal*Control` tuple, the form
/// `memory/global.rs` holds an address in.
///
/// Nothing asserts the elements boolean. The sums of a shard's last address
/// equal the range-checked limbs of the last row of its table, or the sums
/// of its previous address when the table has no rows, and the verifier of
/// an execution equates the elements of a shard's previous address with
/// those of the shard before it.
fn addr_limbs_from_bits<AB: ZKMAirBuilder>(bits: &[AB::PublicVar; 32]) -> [AB::Expr; 2] {
    let (lo, hi) = bits.split_at(16);
    [lo, hi].map(|half| {
        let mut acc = AB::Expr::ZERO;
        for (i, bit) in half.iter().enumerate() {
            acc += (*bit).into() * AB::Expr::from_u32(1u32 << i);
        }
        acc
    })
}

/// `MemoryGlobalInitControl` boundary: anchor the global-memory-init
/// address-ordering chain.  The `MemoryGlobalChip` (Initialize) rows form
/// `receive(index, prev_addr_lo, prev_addr_hi, prev_valid) ->
/// send(index+1, addr_lo, addr_hi, is_comp)` (sorted, strictly-increasing
/// addresses).  This SENDs the chain head `(0, previous_init_addr, 1)`
/// [received by row 0 as its prev_addr] and RECEIVEs the chain tail
/// `(global_init_count, last_init_addr, 1)` [sent by the last real row].
/// Tuple = [index, addr_lo, addr_hi, valid] (4 values).
///
/// A shard without rows of the chip sends and receives one tuple each, so
/// its count is zero and the limbs of its last address are those of its
/// previous one: the chain passes through such a shard unchanged.
fn eval_global_memory_init<AB: ZKMAirBuilder>(
    builder: &mut AB,
    pv: &PublicValues<Word<AB::PublicVar>, AB::PublicVar>,
) {
    let [prev_lo, prev_hi] = addr_limbs_from_bits::<AB>(&pv.previous_init_addr_bits);
    let [last_lo, last_hi] = addr_limbs_from_bits::<AB>(&pv.last_init_addr_bits);
    builder.send(
        AirLookup::new(
            vec![AB::Expr::ZERO, prev_lo, prev_hi, AB::Expr::ONE],
            AB::Expr::ONE,
            LookupKind::MemoryGlobalInitControl,
        ),
        LookupScope::Local,
    );
    builder.receive(
        AirLookup::new(
            vec![pv.global_init_count.into(), last_lo, last_hi, AB::Expr::ONE],
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
    let [prev_lo, prev_hi] = addr_limbs_from_bits::<AB>(&pv.previous_finalize_addr_bits);
    let [last_lo, last_hi] = addr_limbs_from_bits::<AB>(&pv.last_finalize_addr_bits);
    builder.send(
        AirLookup::new(
            vec![AB::Expr::ZERO, prev_lo, prev_hi, AB::Expr::ONE],
            AB::Expr::ONE,
            LookupKind::MemoryGlobalFinalizeControl,
        ),
        LookupScope::Local,
    );
    builder.receive(
        AirLookup::new(
            vec![pv.global_finalize_count.into(), last_lo, last_hi, AB::Expr::ONE],
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
