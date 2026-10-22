use std::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use zkm_derive::PicusAnnotations;
use zkm_pcs::PicusInfo;

use itertools::Itertools;
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use zkm_core_executor::events::{ByteLookupEvent, ByteRecord, MemoryBumpEvent, MemoryReadRecord};
use zkm_core_executor::{ByteOpcode, ExecutionRecord, Program, NUM_REGISTERS};
use zkm_derive::AlignedBorrow;
use zkm_pcs::air::{MachineAir, ZKMAirBuilder};

use crate::{
    air::{MemoryAirBuilder, TIMESTAMP_HIGH_LIMB_BITS, TIMESTAMP_HIGH_LIMB_MASK},
    memory::MemoryReadCols,
    utils::{next_multiple_of_32, zeroed_f_vec},
    CoreChipError,
};

pub(crate) const NUM_MEMORY_BUMP_COLS: usize = size_of::<MemoryBumpCols<u8>>();

/// The columns of the `MemoryBump` chip.
///
/// One row per shadow read of a register at `(shard, clk)`: on the register's first touch in the
/// shard, advancing its memory-argument timestamp out of whatever earlier shard it was left in,
/// and before an access `2^16` or more clk ticks after the register's previous one.
#[derive(PicusAnnotations, AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryBumpCols<T> {
    /// The shadow read.  This is a *full* [`crate::memory::MemoryAccessCols`], i.e. it pays for
    /// the shard-vs-clk comparison — but exactly once per (register, shard) instead of once per
    /// register access.
    pub access: MemoryReadCols<T>,

    /// The shard the register is bumped into.
    pub shard: T,
    /// The clk of the shadow read, `clk_16bit_limb + clk_high_limb * 2^16`, range checked below
    /// `2^26` like an instruction's clk.
    pub clk_16bit_limb: T,
    pub clk_high_limb: T,

    /// The register address.  Constrained to be `< NUM_REGISTERS`.
    pub addr: T,

    /// Whether this is a real row.
    pub is_real: T,
}

/// A chip that bumps the memory-argument timestamp of a register with a shadow read.
///
/// Registers carry their `(shard, clk)` across shard boundaries, so the first access to a register
/// in a shard would have to compare *shards* rather than clks, and a register left untouched for a
/// long stretch would need a 26-bit clk difference.  Rather than pay for either on every register
/// access of every cycle, this chip re-reads the register one clk tick before such an access, with
/// the full shard-or-clk comparison of [`crate::memory::MemoryAccessCols`].  Its clk is range
/// checked below `2^26`, so the shadow read is an ordinary link of the register's access chain.
///
/// Consequently every register access proven anywhere in the machine has `prev_shard == shard`
/// and `clk - prev_clk - 1 < 2^16`, which is what lets [`crate::memory::RegisterAccessCols`] be
/// 5 columns with one byte lookup instead of 9 columns with two.
///
/// A shard has at most `NUM_REGISTERS` first-touch rows plus one gap row per register per `2^16`
/// clk ticks.
#[derive(Default)]
pub struct MemoryBumpChip {}

impl MemoryBumpChip {
    pub const fn new() -> Self {
        Self {}
    }
}

impl<F> BaseAir<F> for MemoryBumpChip {
    fn width(&self) -> usize {
        NUM_MEMORY_BUMP_COLS
    }
}

/// The byte lookups a single bump row emits, shared by `generate_dependencies` and
/// `generate_trace` so the two can never drift.
fn bump_row_blu_events(event: &MemoryBumpEvent, blu: &mut impl ByteRecord) {
    blu.add_u16_range_check(event.shard as u16);
    blu.add_u16_range_check((event.timestamp & 0xffff) as u16);
    blu.add_bit_range_check(
        ((event.timestamp >> 16) & TIMESTAMP_HIGH_LIMB_MASK) as u16,
        TIMESTAMP_HIGH_LIMB_BITS,
    );

    blu.add_byte_lookup_event(ByteLookupEvent {
        opcode: ByteOpcode::LTU,
        a1: 1,
        a2: 0,
        b: event.addr as u8,
        c: NUM_REGISTERS as u8,
    });
}

impl<F: PrimeField32> MachineAir<F> for MemoryBumpChip {
    type Record = ExecutionRecord;

    type Program = Program;

    type Error = CoreChipError;

    fn name(&self) -> String {
        "MemoryBump".to_string()
    }

    fn picus_info(&self) -> PicusInfo {
        MemoryBumpCols::<u8>::picus_info()
    }

    fn generate_dependencies(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> Result<(), Self::Error> {
        let blu_batches = input
            .bump_memory_events
            .chunks(1)
            .map(|events| {
                let mut blu: zkm_core_executor::events::ByteLookupMap = Default::default();
                for event in events {
                    bump_row_blu_events(event, &mut blu);
                    let mut cols = MemoryBumpCols::<F>::default();
                    cols.access.populate(read_record(event), &mut blu);
                }
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
        Ok(())
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = input.bump_memory_events.len();
        Some(next_multiple_of_32(
            nb_rows,
            None,
            <MemoryBumpChip as MachineAir<F>>::name(self).as_str(),
        ))
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        let events = &input.bump_memory_events;
        let padded_nb_rows = <MemoryBumpChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_MEMORY_BUMP_COLS);
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        values[..events.len() * NUM_MEMORY_BUMP_COLS]
            .par_chunks_mut(chunk_size * NUM_MEMORY_BUMP_COLS)
            .enumerate()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_MEMORY_BUMP_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let event = &events[idx];
                    let cols: &mut MemoryBumpCols<F> = row.borrow_mut();
                    let mut blu = Vec::new();
                    cols.access.populate(read_record(event), &mut blu);
                    cols.shard = F::from_u32(event.shard);
                    cols.clk_16bit_limb = F::from_u32(event.timestamp & 0xffff);
                    cols.clk_high_limb = F::from_u32(event.timestamp >> 16);
                    cols.addr = F::from_u32(event.addr);
                    cols.is_real = F::ONE;
                });
            });

        Ok(RowMajorMatrix::new(values, NUM_MEMORY_BUMP_COLS))
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.bump_memory_events.is_empty()
    }
}

/// The shadow read a bump event stands for: the register's value, re-read at `(shard, clk)`.
#[inline]
fn read_record(event: &MemoryBumpEvent) -> MemoryReadRecord {
    MemoryReadRecord {
        value: event.value,
        shard: event.shard,
        timestamp: event.timestamp,
        prev_shard: event.prev_shard,
        prev_timestamp: event.prev_timestamp,
    }
}

impl<AB> Air<AB> for MemoryBumpChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &MemoryBumpCols<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_real);

        builder.send_byte(
            AB::Expr::from_u8(ByteOpcode::U16Range as u8),
            local.shard,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            local.is_real,
        );

        builder.send_byte(
            AB::Expr::from_u8(ByteOpcode::LTU as u8),
            AB::Expr::ONE,
            local.addr,
            AB::Expr::from_u32(NUM_REGISTERS as u32),
            local.is_real,
        );

        builder.send_timestamp_range_checks(
            local.clk_16bit_limb,
            local.clk_high_limb,
            local.is_real,
        );
        builder.eval_memory_access(
            local.shard,
            local.clk_16bit_limb + local.clk_high_limb * AB::Expr::from_u32(1 << 16),
            local.addr,
            &local.access,
            local.is_real,
        );
    }
}
