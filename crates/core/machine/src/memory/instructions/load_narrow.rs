//! The sign/zero-extending narrow loads: `LB`, `LBU`, `LH`, `LHU`.
//!
//! These are the only memory opcodes that need the sign-extension gadget, and
//! the only loads whose result is narrower than a word.  Splitting them out
//! keeps the 5 sign/value columns off every other memory row.
//!
//! The sign extension itself is now done with byte constraints rather than a
//! `send_alu(SUB, ..)`: a negative narrow load simply fills the high bytes of
//! `op_a` with `0xFF`, so the `AddSub` dependency row the union chip emitted for
//! every negative `LB`/`LH` is gone as well.

use std::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord, MemInstrEvent},
    ByteOpcode, ExecutionRecord, Opcode, Program,
};
use zkm_derive::{AlignedBorrow, PicusAnnotations};
use zkm_pcs::{air::MachineAir, PicusInfo};

use crate::{
    air::{WordAirBuilder, ZKMCoreAirBuilder},
    memory::MemoryCols,
    utils::next_multiple_of_32,
    CoreChipError,
};

use super::common::{
    eval_memory_common, eval_offset_flags, generate_memory_trace, populate_offset_flags,
    receive_memory_instruction, MemoryInstrCommonCols,
};

pub const NUM_LOAD_NARROW_COLS: usize = size_of::<LoadNarrowColumns<u8>>();

/// A chip for the narrow (sub-word) load instructions.
#[derive(Default)]
pub struct LoadNarrowChip;

/// The column layout for `LB`, `LBU`, `LH`, `LHU`.
#[derive(AlignedBorrow, PicusAnnotations, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct LoadNarrowColumns<T> {
    /// The columns shared by all memory instructions.
    pub common: MemoryInstrCommonCols<T>,

    /// Whether this is a load byte instruction.
    #[picus(selector)]
    pub is_lb: T,
    /// Whether this is a load byte unsigned instruction.
    #[picus(selector)]
    pub is_lbu: T,
    /// Whether this is a load half instruction.
    #[picus(selector)]
    pub is_lh: T,
    /// Whether this is a load half unsigned instruction.
    #[picus(selector)]
    pub is_lhu: T,

    /// Whether the least significant two bits of the address are one.
    pub ls_bits_is_one: T,
    /// Whether the least significant two bits of the address are two.
    pub ls_bits_is_two: T,
    /// Whether the least significant two bits of the address are three.
    pub ls_bits_is_three: T,

    /// The low byte of the zero-extended loaded value.
    pub val_lo: T,
    /// The high byte of the zero-extended loaded value.  Zero for byte loads.
    pub val_hi: T,

    /// The most significant byte of the loaded value: `val_lo` for `LB`, `val_hi` for `LH`.
    pub most_sig_byte: T,
    /// The most significant bit of `most_sig_byte`.
    pub most_sig_bit: T,
}

impl<F> BaseAir<F> for LoadNarrowChip {
    fn width(&self) -> usize {
        NUM_LOAD_NARROW_COLS
    }
}

impl<AB> Air<AB> for LoadNarrowChip
where
    AB: ZKMCoreAirBuilder,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &LoadNarrowColumns<AB::Var> = (*local).borrow();
        let common = &local.common;

        // SAFETY: All selectors are checked to be boolean, and `is_real` — their sum — is
        // checked to be boolean too, so each real row has exactly one selector on.
        let is_real = local.is_lb + local.is_lbu + local.is_lh + local.is_lhu;
        builder.assert_bool(local.is_lb);
        builder.assert_bool(local.is_lbu);
        builder.assert_bool(local.is_lh);
        builder.assert_bool(local.is_lhu);
        builder.assert_bool(is_real.clone());

        eval_memory_common(builder, common, is_real.clone());

        let offset_is_zero = eval_offset_flags(
            builder,
            common.addr_ls_two_bits,
            local.ls_bits_is_one,
            local.ls_bits_is_two,
            local.ls_bits_is_three,
        );

        // Loads must not change the memory value.
        builder
            .when(is_real.clone())
            .assert_word_eq(*common.memory_access.value(), *common.memory_access.prev_value());

        // Half-word loads require the offset to be zero or two.
        builder
            .when(local.is_lh + local.is_lhu)
            .assert_zero(local.ls_bits_is_one + local.ls_bits_is_three);

        let mem_val = *common.memory_access.value();

        // The selected byte, for `LB`/`LBU`.
        let mem_byte = mem_val[0] * offset_is_zero.clone()
            + mem_val[1] * local.ls_bits_is_one
            + mem_val[2] * local.ls_bits_is_two
            + mem_val[3] * local.ls_bits_is_three;
        builder.when(local.is_lb + local.is_lbu).assert_eq(local.val_lo, mem_byte);
        builder.when(local.is_lb + local.is_lbu).assert_zero(local.val_hi);

        // The selected half word, for `LH`/`LHU`.
        let use_lower_half = offset_is_zero;
        let use_upper_half = local.ls_bits_is_two;
        builder.when(local.is_lh + local.is_lhu).assert_eq(
            local.val_lo,
            use_lower_half.clone() * mem_val[0] + use_upper_half * mem_val[2],
        );
        builder
            .when(local.is_lh + local.is_lhu)
            .assert_eq(local.val_hi, use_lower_half * mem_val[1] + use_upper_half * mem_val[3]);

        // The sign bit of the loaded value.  The lookup only fires for the signed
        // opcodes, so `most_sig_bit` is unconstrained on `LBU`/`LHU` rows — every use
        // below multiplies it by `is_lb + is_lh`, which is zero there.
        builder.send_byte(
            ByteOpcode::MSB.as_field::<AB::F>(),
            local.most_sig_bit,
            local.most_sig_byte,
            AB::Expr::ZERO,
            local.is_lb + local.is_lh,
        );
        builder.assert_eq(
            local.most_sig_byte,
            local.is_lb * local.val_lo + local.is_lh * local.val_hi,
        );

        // Sign extension without an `AddSub` dependency row: a negative narrow load
        // just fills the bytes above the loaded value with `0xFF`.
        let ff = AB::Expr::from_u8(0xFF);
        let neg = (local.is_lb + local.is_lh) * local.most_sig_bit;
        let neg_byte = local.is_lb * local.most_sig_bit;
        let op_a = common.op_a_value;
        builder.when(is_real.clone()).assert_eq(op_a[0], local.val_lo);
        builder
            .when(is_real.clone())
            .assert_eq(op_a[1], local.val_hi + ff.clone() * neg_byte);
        builder.when(is_real.clone()).assert_eq(op_a[2], ff.clone() * neg.clone());
        builder.when(is_real.clone()).assert_eq(op_a[3], ff * neg);

        let opcode = local.is_lb * Opcode::LB.as_field::<AB::F>()
            + local.is_lbu * Opcode::LBU.as_field::<AB::F>()
            + local.is_lh * Opcode::LH.as_field::<AB::F>()
            + local.is_lhu * Opcode::LHU.as_field::<AB::F>();

        // SAFETY: `op_a` is written by these opcodes, so `op_a_immutable = 0`.
        receive_memory_instruction(builder, common, opcode, AB::Expr::ZERO, is_real);
    }
}

impl LoadNarrowChip {
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &MemInstrEvent,
        cols: &mut LoadNarrowColumns<F>,
        blu: &mut impl ByteRecord,
    ) {
        let addr_ls_two_bits = cols.common.populate(event, blu);
        populate_offset_flags(
            addr_ls_two_bits,
            &mut cols.ls_bits_is_one,
            &mut cols.ls_bits_is_two,
            &mut cols.ls_bits_is_three,
        );

        let mem_value = event.mem_access.value();
        let (val_lo, val_hi) = match event.opcode {
            Opcode::LB | Opcode::LBU => {
                (mem_value.to_le_bytes()[addr_ls_two_bits as usize], 0u8)
            }
            Opcode::LH | Opcode::LHU => {
                let half = match (addr_ls_two_bits >> 1) % 2 {
                    0 => mem_value & 0x0000FFFF,
                    1 => (mem_value & 0xFFFF0000) >> 16,
                    _ => unreachable!(),
                };
                (half.to_le_bytes()[0], half.to_le_bytes()[1])
            }
            _ => unreachable!("LoadNarrowChip got {:?}", event.opcode),
        };
        cols.val_lo = F::from_u8(val_lo);
        cols.val_hi = F::from_u8(val_hi);

        if matches!(event.opcode, Opcode::LB | Opcode::LH) {
            let most_sig_byte = if matches!(event.opcode, Opcode::LB) { val_lo } else { val_hi };
            let most_sig_bit = most_sig_byte >> 7;
            cols.most_sig_byte = F::from_u8(most_sig_byte);
            cols.most_sig_bit = F::from_u8(most_sig_bit);
            blu.add_byte_lookup_event(ByteLookupEvent {
                opcode: ByteOpcode::MSB,
                a1: most_sig_bit as u16,
                a2: 0,
                b: most_sig_byte,
                c: 0,
            });
        }

        cols.is_lb = F::from_bool(matches!(event.opcode, Opcode::LB));
        cols.is_lbu = F::from_bool(matches!(event.opcode, Opcode::LBU));
        cols.is_lh = F::from_bool(matches!(event.opcode, Opcode::LH));
        cols.is_lhu = F::from_bool(matches!(event.opcode, Opcode::LHU));
    }
}

impl<F: PrimeField32> MachineAir<F> for LoadNarrowChip {
    type Record = ExecutionRecord;
    type Program = Program;
    type Error = CoreChipError;

    fn name(&self) -> String {
        "LoadNarrow".to_string()
    }

    fn picus_info(&self) -> PicusInfo {
        LoadNarrowColumns::<u8>::picus_info()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        Some(next_multiple_of_32(
            input.memory_load_narrow_events.len(),
            input.fixed_log2_rows::<F, _>(self),
            <Self as MachineAir<F>>::name(self).as_str(),
        ))
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        let padded_nb_rows = <Self as MachineAir<F>>::num_rows(self, input).unwrap();
        let (trace, blu_events) = generate_memory_trace(
            &input.memory_load_narrow_events,
            padded_nb_rows,
            NUM_LOAD_NARROW_COLS,
            |event, row, blu: &mut HashMap<ByteLookupEvent, usize>| {
                let cols: &mut LoadNarrowColumns<F> = row.borrow_mut();
                self.event_to_row(event, cols, blu);
            },
        );
        output.add_byte_lookup_events_from_maps(blu_events.iter().collect_vec());
        Ok(trace)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.memory_load_narrow_events.is_empty()
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}
