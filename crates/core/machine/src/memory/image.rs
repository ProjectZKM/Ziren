use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use zkm_core_executor::{ExecutionRecord, Program};
use zkm_derive::AlignedBorrow;
use zkm_pcs::{
    air::{AirLookup, LookupScope, MachineAir, ZKMAirBuilder},
    LookupKind, Word,
};

use crate::{
    utils::{next_power_of_two, pad_rows_fixed},
    CoreChipError,
};

/// The number of memory image columns.
pub const NUM_MEMORY_IMAGE_COLS: usize = size_of::<MemoryImageCols<u8>>();

/// One word of the program's memory image, as the first shard sends it.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct MemoryImageCols<T> {
    pub addr: T,
    pub value: Word<T>,
    pub is_real: T,
}

/// The program's memory image on the cross-shard memory bus.
///
/// The image is a preprocessed table ([`super::MemoryProgramChip`]), and a
/// global lookup reads committed main columns only. So the first shard copies
/// the image here: every row is received from the preprocessed table over a
/// local lookup, which makes the rows exactly the image, and sent as
/// `(0, 0, addr, value)`, the initial value of its address.
#[derive(Default)]
pub struct MemoryImageChip;

impl MemoryImageChip {
    pub const fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField32> MachineAir<F> for MemoryImageChip {
    type Record = ExecutionRecord;

    type Program = Program;

    type Error = CoreChipError;

    fn name(&self) -> String {
        "MemoryImage".to_string()
    }

    fn generate_dependencies(
        &self,
        _input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        let mut rows = input
            .program
            .image
            .iter()
            .map(|(&addr, &word)| {
                let mut row = [F::ZERO; NUM_MEMORY_IMAGE_COLS];
                let cols: &mut MemoryImageCols<F> = row.as_mut_slice().borrow_mut();
                cols.addr = F::from_u32(addr);
                cols.value = Word::from(word);
                cols.is_real = F::ONE;
                row
            })
            .collect::<Vec<_>>();
        pad_rows_fixed(
            &mut rows,
            || [F::ZERO; NUM_MEMORY_IMAGE_COLS],
            None,
            <MemoryImageChip as MachineAir<F>>::name(self).as_str(),
        );

        Ok(RowMajorMatrix::new(rows.into_iter().flatten().collect(), NUM_MEMORY_IMAGE_COLS))
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        Some(next_power_of_two(
            input.program.image.len(),
            None,
            <MemoryImageChip as MachineAir<F>>::name(self).as_str(),
        ))
    }

    fn included(&self, shard: &Self::Record) -> bool {
        shard.public_values.shard == 1 && !shard.program.image.is_empty()
    }
}

impl<F> BaseAir<F> for MemoryImageChip {
    fn width(&self) -> usize {
        NUM_MEMORY_IMAGE_COLS
    }
}

impl<AB> Air<AB> for MemoryImageChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: MemoryImageCols<AB::Var> = *(*local).borrow();

        builder.assert_bool(local.is_real);

        let mut word = vec![local.addr.into()];
        word.extend(local.value.map(Into::into));
        builder.receive(
            AirLookup::new(word.clone(), local.is_real.into(), LookupKind::MemoryImage),
            LookupScope::Local,
        );

        let mut values = vec![AB::Expr::ZERO, AB::Expr::ZERO];
        values.extend(word);
        builder.send(
            AirLookup::new(values, local.is_real.into(), LookupKind::Memory),
            LookupScope::Global,
        );
    }
}
