//! The word-aligned loads: `LW` and `LL`.
//!
//! These are the most frequent memory opcodes and the cheapest: the offset must
//! be zero, so the chip witnesses none of the offset flags, and the loaded value
//! *is* `op_a`, so there is no separate `unsigned_mem_val` word either.

use std::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord, MemInstrEvent},
    ExecutionRecord, Opcode, Program,
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
    assert_word_aligned, eval_memory_common, generate_memory_trace, receive_memory_instruction,
    MemoryInstrCommonCols,
};

pub const NUM_LOAD_WORD_COLS: usize = size_of::<LoadWordColumns<u8>>();

/// A chip for the word-aligned load instructions.
#[derive(Default)]
pub struct LoadWordChip;

/// The column layout for `LW` and `LL`.
#[derive(AlignedBorrow, PicusAnnotations, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct LoadWordColumns<T> {
    /// The columns shared by all memory instructions.
    pub common: MemoryInstrCommonCols<T>,

    /// Whether this is a load word instruction.
    #[picus(selector)]
    pub is_lw: T,
    /// Whether this is a load linked instruction.
    #[picus(selector)]
    pub is_ll: T,
}

impl<F> BaseAir<F> for LoadWordChip {
    fn width(&self) -> usize {
        NUM_LOAD_WORD_COLS
    }
}

impl<AB> Air<AB> for LoadWordChip
where
    AB: ZKMCoreAirBuilder,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &LoadWordColumns<AB::Var> = (*local).borrow();
        let common = &local.common;

        // SAFETY: both selectors are boolean and so is their sum, so each real row
        // has exactly one selector on.
        let is_real = local.is_lw + local.is_ll;
        builder.assert_bool(local.is_lw);
        builder.assert_bool(local.is_ll);
        builder.assert_bool(is_real.clone());

        eval_memory_common(builder, common, is_real.clone());
        assert_word_aligned(builder, common, is_real.clone());

        // Loads must not change the memory value.
        builder
            .when(is_real.clone())
            .assert_word_eq(*common.memory_access.value(), *common.memory_access.prev_value());

        // The full word is loaded into `op_a`.
        builder
            .when(is_real.clone())
            .assert_word_eq(*common.memory_access.value(), common.op_a_value);

        let opcode = local.is_lw * Opcode::LW.as_field::<AB::F>()
            + local.is_ll * Opcode::LL.as_field::<AB::F>();

        // SAFETY: `op_a` is written by these opcodes, so `op_a_immutable = 0`.
        receive_memory_instruction(builder, common, opcode, AB::Expr::ZERO, is_real);
    }
}

impl LoadWordChip {
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &MemInstrEvent,
        cols: &mut LoadWordColumns<F>,
        blu: &mut impl ByteRecord,
    ) {
        cols.common.populate(event, blu);
        cols.is_lw = F::from_bool(matches!(event.opcode, Opcode::LW));
        cols.is_ll = F::from_bool(matches!(event.opcode, Opcode::LL));
        debug_assert!(matches!(event.opcode, Opcode::LW | Opcode::LL));
    }
}

impl<F: PrimeField32> MachineAir<F> for LoadWordChip {
    type Record = ExecutionRecord;
    type Program = Program;
    type Error = CoreChipError;

    fn name(&self) -> String {
        "LoadWord".to_string()
    }

    fn picus_info(&self) -> PicusInfo {
        LoadWordColumns::<u8>::picus_info()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        Some(next_multiple_of_32(
            input.memory_load_word_events.len(),
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
            &input.memory_load_word_events,
            padded_nb_rows,
            NUM_LOAD_WORD_COLS,
            |event, row, blu: &mut HashMap<ByteLookupEvent, usize>| {
                let cols: &mut LoadWordColumns<F> = row.borrow_mut();
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
            !shard.memory_load_word_events.is_empty()
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}
