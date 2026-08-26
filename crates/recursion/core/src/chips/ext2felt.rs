use core::borrow::Borrow;
use instruction::HintExt2FeltsInstr;
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use std::{borrow::BorrowMut, marker::PhantomData};
use zkm_core_machine::utils::{next_power_of_two, pad_rows_fixed};
use zkm_derive::AlignedBorrow;
use zkm_pcs::air::MachineAir;

use crate::{builder::ZKMRecursionAirBuilder, *};

use super::mem::MemoryAccessCols;

/// Constrained ext-to-felts decomposition.
///
/// An `Ext` in recursion memory is one `Block` of `D` felts, but the felt
/// side of the ISA can only address whole blocks — so handing an extension
/// element's coordinates to felt consumers (Fiat-Shamir absorption, Merkle
/// digests) used to go through `HintExt2Felts`, whose outputs are
/// UNCONSTRAINED hint writes that every call site then re-bound with a
/// monomial reconstruction: ~14 ExtAlu rows per call, ~18K calls per leaf,
/// a quarter of the leaf's ExtAlu area spent restating "these felts are the
/// limbs of that block".
///
/// This chip states it as wiring instead: each row RECEIVES the input block
/// and SENDS its four limbs as single-felt blocks from the SAME value
/// columns.  There is no arithmetic constraint at all — sharing the columns
/// between the receive and the sends IS the decomposition — so the ~14-row
/// binding collapses to one 4-cell row.
///
/// The chip lives in the COMPRESS machine only.  `shrink_machine` and
/// `wrap_machine` keep the legacy chip set (their programs keep emitting
/// `HintExt2Felts` + the monomial re-binding, see `ext2felt_v2`), because the
/// shrink proof's structure is what the BN254 wrap R1CS — and through it the
/// gnark ceremony — is built over.
#[derive(Default)]
pub struct Ext2FeltChip<F> {
    _marker: PhantomData<F>,
}

pub const NUM_EXT2FELT_COLS: usize = core::mem::size_of::<Ext2FeltCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct Ext2FeltCols<F: Copy> {
    /// The input block's limbs — received as a block, sent limb-wise.
    pub values: Block<F>,
}

pub const NUM_EXT2FELT_PREPROCESSED_COLS: usize =
    core::mem::size_of::<Ext2FeltPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct Ext2FeltPreprocessedCols<F: Copy> {
    /// Address of the input extension element.
    pub input_addr: Address<F>,
    /// The input read fires only on real rows (padding receives nothing).
    pub is_real: F,
    /// Address and multiplicity of each output felt.
    pub accesses: [MemoryAccessCols<F>; D],
}

impl<F: Send + Sync> BaseAir<F> for Ext2FeltChip<F> {
    fn width(&self) -> usize {
        NUM_EXT2FELT_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for Ext2FeltChip<F> {
    type Record = crate::ExecutionRecord<F>;

    type Program = crate::RecursionProgram<F>;

    type Error = crate::RecursionChipError;

    fn name(&self) -> String {
        "Ext2Felt".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_EXT2FELT_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let instructions: Vec<&Instruction<F>> = program.iter_instructions().collect();
        let instrs = instructions
            .par_iter()
            .copied()
            .filter_map(|instruction| match instruction {
                Instruction::Ext2Felts(instr) => Some(instr),
                _ => None,
            })
            .collect::<Vec<_>>();

        let nb_rows = instrs.len();
        let padded_nb_rows = match program.fixed_log2_rows(self) {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(
                nb_rows,
                None,
                <Ext2FeltChip<F> as MachineAir<F>>::name(self).as_str(),
            ),
        };
        let mut values = vec![F::ZERO; padded_nb_rows * NUM_EXT2FELT_PREPROCESSED_COLS];

        let populate_len = instrs.len() * NUM_EXT2FELT_PREPROCESSED_COLS;
        values[..populate_len]
            .par_chunks_mut(NUM_EXT2FELT_PREPROCESSED_COLS)
            .zip_eq(instrs)
            .for_each(|(row, instr)| {
                let HintExt2FeltsInstr { output_addrs_mults, input_addr } = instr;
                let cols: &mut Ext2FeltPreprocessedCols<_> = row.borrow_mut();
                cols.input_addr = *input_addr;
                cols.is_real = F::ONE;
                for (access, &(addr, mult)) in
                    cols.accesses.iter_mut().zip(output_addrs_mults.iter())
                {
                    *access = MemoryAccessCols { addr, mult };
                }
            });

        Some(RowMajorMatrix::new(values, NUM_EXT2FELT_PREPROCESSED_COLS))
    }

    fn generate_dependencies(
        &self,
        _: &Self::Record,
        _: &mut Self::Record,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn generate_trace(
        &self,
        input: &Self::Record,
        _: &mut Self::Record,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        let mut rows = input
            .ext2felt_events
            .iter()
            .map(|event| {
                let mut row = [F::ZERO; NUM_EXT2FELT_COLS];
                let cols: &mut Ext2FeltCols<_> = row.as_mut_slice().borrow_mut();
                cols.values = event.inner;
                row
            })
            .collect::<Vec<_>>();

        pad_rows_fixed(
            &mut rows,
            || [F::ZERO; NUM_EXT2FELT_COLS],
            input.fixed_log2_rows(self),
            <Ext2FeltChip<F> as MachineAir<F>>::name(self).as_str(),
        );

        Ok(RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_EXT2FELT_COLS,
        ))
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB> Air<AB> for Ext2FeltChip<AB::F>
where
    AB: ZKMRecursionAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &Ext2FeltCols<AB::Var> = (*local).borrow();
        let prep = builder.preprocessed().clone();
        let prep_local = prep.current_slice();
        let prep_local: &Ext2FeltPreprocessedCols<AB::Var> = (*prep_local).borrow();

        // The decomposition is the column sharing: the block received here and
        // the four limbs sent below are the SAME trace cells.
        builder.receive_block(prep_local.input_addr, local.values, prep_local.is_real);
        for (i, access) in prep_local.accesses.iter().enumerate() {
            builder.send_single(access.addr, local.values.0[i], access.mult);
        }
    }
}
