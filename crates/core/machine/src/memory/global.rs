use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use std::array;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{FieldAlgebra, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use zkm_core_executor::events::{GlobalLookupEvent, MemoryInitializeFinalizeEvent};
use zkm_core_executor::{ExecutionRecord, Program};
use zkm_derive::{AlignedBorrow, PicusAnnotations};
use zkm_stark::{
    air::{
        AirLookup, BaseAirBuilder, LookupScope, MachineAir, PublicValues, ZKMAirBuilder,
        ZKM_PROOF_NUM_PV_ELTS,
    },
    LookupKind, PicusInfo, Word,
};

use crate::{
    operations::{AssertLtColsBits, IsZeroOperation, KoalaBearBitDecomposition},
    utils::next_power_of_two,
    CoreChipError,
};

use super::MemoryChipType;

/// A memory chip that can initialize or finalize values in memory.
pub struct MemoryGlobalChip {
    pub kind: MemoryChipType,
}

impl MemoryGlobalChip {
    /// Creates a new memory chip with a certain type.
    pub const fn new(kind: MemoryChipType) -> Self {
        Self { kind }
    }
}

impl<F> BaseAir<F> for MemoryGlobalChip {
    fn width(&self) -> usize {
        NUM_MEMORY_INIT_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for MemoryGlobalChip {
    type Record = ExecutionRecord;

    type Program = Program;

    type Error = CoreChipError;

    fn name(&self) -> String {
        match self.kind {
            MemoryChipType::Initialize => "MemoryGlobalInit".to_string(),
            MemoryChipType::Finalize => "MemoryGlobalFinalize".to_string(),
        }
    }

    fn picus_info(&self) -> zkm_stark::PicusInfo {
        MemoryInitCols::<u8>::picus_info()
    }

    fn generate_dependencies(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> Result<(), Self::Error> {
        let mut memory_events = match self.kind {
            MemoryChipType::Initialize => input.global_memory_initialize_events.clone(),
            MemoryChipType::Finalize => input.global_memory_finalize_events.clone(),
        };

        let is_receive = match self.kind {
            MemoryChipType::Initialize => false,
            MemoryChipType::Finalize => true,
        };

        memory_events.sort_by_key(|event| event.addr);

        let events = memory_events.into_iter().map(|event| {
            let lookup_shard = if is_receive { event.shard } else { 0 };
            let lookup_clk = if is_receive { event.timestamp } else { 0 };
            GlobalLookupEvent {
                message: [
                    lookup_shard,
                    lookup_clk,
                    event.addr,
                    (event.value & 255) as u32,
                    ((event.value >> 8) & 255) as u32,
                    ((event.value >> 16) & 255) as u32,
                    ((event.value >> 24) & 255) as u32,
                ],
                is_receive,
                kind: LookupKind::Memory as u8,
            }
        });
        output.global_lookup_events.extend(events);
        Ok(())
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let events = match self.kind {
            MemoryChipType::Initialize => &input.global_memory_initialize_events,
            MemoryChipType::Finalize => &input.global_memory_finalize_events,
        };
        let nb_rows = events.len();
        let size_log2 = input.fixed_log2_rows::<F, Self>(self);
        let padded_nb_rows = next_power_of_two(
            nb_rows,
            size_log2,
            <MemoryGlobalChip as MachineAir<F>>::name(self).as_str(),
        );
        Some(padded_nb_rows)
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        let mut memory_events = match self.kind {
            MemoryChipType::Initialize => input.global_memory_initialize_events.clone(),
            MemoryChipType::Finalize => input.global_memory_finalize_events.clone(),
        };

        let previous_addr_bits = match self.kind {
            MemoryChipType::Initialize => input.public_values.previous_init_addr_bits,
            MemoryChipType::Finalize => input.public_values.previous_finalize_addr_bits,
        };

        memory_events.sort_by_key(|event| event.addr);
        let mut rows: Vec<[F; NUM_MEMORY_INIT_COLS]> = memory_events
            .par_iter()
            .map(|event| {
                let MemoryInitializeFinalizeEvent { addr, value, shard, timestamp } =
                    event.to_owned();

                let mut row = [F::ZERO; NUM_MEMORY_INIT_COLS];
                let cols: &mut MemoryInitCols<F> = row.as_mut_slice().borrow_mut();
                cols.addr = F::from_canonical_u32(addr);
                cols.addr_bits.populate(addr);
                cols.shard = F::from_canonical_u32(shard);
                cols.timestamp = F::from_canonical_u32(timestamp);
                cols.value = array::from_fn(|i| F::from_canonical_u32((value >> i) & 1));
                cols.is_real = F::one();

                row
            })
            .collect::<Vec<_>>();

        for i in 0..memory_events.len() {
            let addr = memory_events[i].addr;
            let cols: &mut MemoryInitCols<F> = rows[i].as_mut_slice().borrow_mut();
            if i == 0 {
                let prev_addr = previous_addr_bits
                    .iter()
                    .enumerate()
                    .map(|(j, bit)| bit * (1 << j))
                    .sum::<u32>();
                cols.is_prev_addr_zero.populate(prev_addr);
                cols.is_first_comp = F::from_bool(prev_addr != 0);
                if prev_addr != 0 {
                    debug_assert!(prev_addr < addr, "prev_addr {prev_addr} < addr {addr}");
                    let addr_bits: [_; 32] = array::from_fn(|i| (addr >> i) & 1);
                    cols.lt_cols.populate(&previous_addr_bits, &addr_bits);
                }
            }
            if i != 0 {
                cols.is_next_comp = F::one();
                let previous_addr = memory_events[i - 1].addr;
                assert_ne!(previous_addr, addr);

                let addr_bits: [_; 32] = array::from_fn(|i| (addr >> i) & 1);
                let prev_addr_bits: [_; 32] = array::from_fn(|i| (previous_addr >> i) & 1);
                cols.lt_cols.populate(&prev_addr_bits, &addr_bits);
            }

            if i == memory_events.len() - 1 {
                cols.is_last_addr = F::ONE;
            }
        }

        // Pad the trace to a power of two depending on the proof shape in `input`.
        rows.resize(
            <MemoryGlobalChip as MachineAir<F>>::num_rows(self, input).unwrap(),
            [F::zero(); NUM_MEMORY_INIT_COLS],
        );

        Ok(RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_INIT_COLS,
        ))
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match self.kind {
                MemoryChipType::Initialize => !shard.global_memory_initialize_events.is_empty(),
                MemoryChipType::Finalize => !shard.global_memory_finalize_events.is_empty(),
            }
        }
    }

    fn commit_scope(&self) -> LookupScope {
        LookupScope::Local
    }
}

#[derive(AlignedBorrow, PicusAnnotations, Clone, Copy)]
#[repr(C)]
pub struct MemoryInitCols<T: Copy> {
    /// The shard number of the memory access.
    #[picus(input, transition_input)]
    pub shard: T,

    /// The timestamp of the memory access.
    #[picus(input, transition_input)]
    pub timestamp: T,

    /// The address of the memory access.
    #[picus(input, transition_input)]
    pub addr: T,

    /// Comparison assertions for address to be strictly increasing.
    pub lt_cols: AssertLtColsBits<T, 32>,

    /// A bit decomposition of `addr`.
    pub addr_bits: KoalaBearBitDecomposition<T>,

    /// The value of the memory access.
    #[picus(transition_input)]
    pub value: [T; 32],

    /// Whether the memory access is a real access.
    pub is_real: T,

    /// Whether or not we are making the assertion `addr < addr_next`.
    pub is_next_comp: T,

    /// A witness to assert whether or not we the previous address is zero.
    pub is_prev_addr_zero: IsZeroOperation<T>,

    /// Auxiliary column, equal to `(1 - is_prev_addr_zero.result) * is_first_row`.
    pub is_first_comp: T,

    /// A flag to indicate the last non-padded address. An auxiliary column needed for degree 3.
    pub is_last_addr: T,
}

pub(crate) const NUM_MEMORY_INIT_COLS: usize = size_of::<MemoryInitCols<u8>>();

impl<AB> Air<AB> for MemoryGlobalChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryInitCols<AB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &MemoryInitCols<AB::Var> = (*next).borrow();

        builder.assert_bool(local.is_real);
        for i in 0..32 {
            builder.assert_bool(local.value[i]);
        }
        // Canonicalize padded rows to the default zero trace shape so witness columns cannot
        // drift in extraction modules.
        builder.when_not(local.is_real).assert_zero(local.shard);
        builder.when_not(local.is_real).assert_zero(local.timestamp);
        builder.when_not(local.is_real).assert_zero(local.addr);
        builder.when_not(local.is_real).assert_zero(local.is_next_comp);
        for i in 0..32 {
            builder.when_not(local.is_real).assert_zero(local.value[i]);
            builder.when_not(local.is_real).assert_zero(local.addr_bits.bits[i]);
            builder.when_not(local.is_real).assert_zero(local.lt_cols.bit_flags[i]);
        }
        builder
            .when_not(local.is_real)
            .assert_zero(local.addr_bits.and_most_sig_byte_decomp_0_to_2);
        builder
            .when_not(local.is_real)
            .assert_zero(local.addr_bits.and_most_sig_byte_decomp_0_to_3);
        builder
            .when_not(local.is_real)
            .assert_zero(local.addr_bits.and_most_sig_byte_decomp_0_to_4);
        builder
            .when_not(local.is_real)
            .assert_zero(local.addr_bits.and_most_sig_byte_decomp_0_to_5);
        builder
            .when_not(local.is_real)
            .assert_zero(local.addr_bits.and_most_sig_byte_decomp_0_to_6);
        builder
            .when_not(local.is_real)
            .assert_zero(local.addr_bits.and_most_sig_byte_decomp_0_to_7);

        let mut byte1 = AB::Expr::zero();
        let mut byte2 = AB::Expr::zero();
        let mut byte3 = AB::Expr::zero();
        let mut byte4 = AB::Expr::zero();
        for i in 0..8 {
            byte1 = byte1.clone() + local.value[i].into() * AB::F::from_canonical_u8(1 << i);
            byte2 = byte2.clone() + local.value[i + 8].into() * AB::F::from_canonical_u8(1 << i);
            byte3 = byte3.clone() + local.value[i + 16].into() * AB::F::from_canonical_u8(1 << i);
            byte4 = byte4.clone() + local.value[i + 24].into() * AB::F::from_canonical_u8(1 << i);
        }
        let value = [byte1, byte2, byte3, byte4];

        if self.kind == MemoryChipType::Initialize {
            // Send the lookup to the global table.
            builder.send(
                AirLookup::new(
                    vec![
                        AB::Expr::zero(), // shard
                        AB::Expr::zero(), // timestamp
                        local.addr.into(),
                        value[0].clone(),
                        value[1].clone(),
                        value[2].clone(),
                        value[3].clone(),
                        local.is_real.into() * AB::Expr::one(),
                        local.is_real.into() * AB::Expr::zero(),
                        AB::Expr::from_canonical_u8(LookupKind::Memory as u8),
                    ],
                    local.is_real.into(),
                    LookupKind::Global,
                ),
                LookupScope::Local,
            );
        } else {
            // Send the lookup to the global table.
            builder.send(
                AirLookup::new(
                    vec![
                        local.shard.into(),
                        local.timestamp.into(),
                        local.addr.into(),
                        value[0].clone(),
                        value[1].clone(),
                        value[2].clone(),
                        value[3].clone(),
                        local.is_real.into() * AB::Expr::zero(),
                        local.is_real.into() * AB::Expr::one(),
                        AB::Expr::from_canonical_u8(LookupKind::Memory as u8),
                    ],
                    local.is_real.into(),
                    LookupKind::Global,
                ),
                LookupScope::Local,
            );
        }

        // Canonically decompose the address into bits so we can do comparisons.
        KoalaBearBitDecomposition::<AB::F>::range_check(
            builder,
            local.addr,
            local.addr_bits,
            local.is_real.into(),
        );

        // Assertion for increasing address. We need to make two types of less-than assertions,
        // first we need to assert that the addr < addr' when the next row is real. Then we need to
        // make assertions with regards to public values.
        //
        // If the chip is a `MemoryInit`:
        // - In the first row, we need to assert that previous_init_addr < addr.
        // - In the last real row, we need to assert that addr = last_init_addr.
        //
        // If the chip is a `MemoryFinalize`:
        // - In the first row, we need to assert that previous_finalize_addr < addr.
        // - In the last real row, we need to assert that addr = last_finalize_addr.

        // Assert that addr < addr' when the next row is real.
        //
        // Keep these constraints transition-scoped so boundary modules don't introduce unconstrained
        // `next`-row helper witnesses.
        {
            let mut transition = builder.when_transition();
            transition.assert_eq(next.is_next_comp, next.is_real);
            next.lt_cols.eval(
                &mut transition,
                &local.addr_bits.bits,
                &next.addr_bits.bits,
                next.is_next_comp,
            );
        }

        // Assert that the real rows are all padded to the top.
        builder.when_transition().when_not(local.is_real).assert_zero(next.is_real);

        // Make assertions for the initial comparison.

        // We want to constrain that the `addr` in the first row is larger than the previous
        // initialized/finalized address, unless the previous address is zero. Since the previous
        // address is either zero or constrained by a different shard, we know it's an element of
        // the field, so we can get an element from the bit decomposition with no concern for
        // overflow.

        let local_addr_bits = local.addr_bits.bits;

        let public_values_array: [AB::Expr; ZKM_PROOF_NUM_PV_ELTS] =
            array::from_fn(|i| builder.public_values()[i].into());
        let public_values: &PublicValues<Word<AB::Expr>, AB::Expr> =
            public_values_array.as_slice().borrow();

        let prev_addr_bits = match self.kind {
            MemoryChipType::Initialize => &public_values.previous_init_addr_bits,
            MemoryChipType::Finalize => &public_values.previous_finalize_addr_bits,
        };

        // Since the previous address is either zero or constrained by a different shard, we know
        // it's an element of the field, so we can get an element from the bit decomposition with
        // no concern for overflow.
        let prev_addr = prev_addr_bits
            .iter()
            .enumerate()
            .map(|(i, bit)| bit.clone() * AB::F::from_wrapped_u32(1 << i))
            .sum::<AB::Expr>();

        // Constrain the is_prev_addr_zero operation only in the first row.
        let is_first_row = builder.is_first_row();
        // Use the exact is-zero constraints inline instead of the summarized helper.
        // This keeps the first-row witness (`is_prev_addr_zero.inverse`) fully pinned
        // in extracted single-row Picus modules.
        let is_prev_zero = AB::Expr::one()
            - local.is_prev_addr_zero.inverse.into() * prev_addr.clone();
        builder
            .when(is_first_row.clone())
            .assert_eq(is_prev_zero, local.is_prev_addr_zero.result);
        builder
            .when(is_first_row.clone())
            .assert_bool(local.is_prev_addr_zero.result);
        builder
            .when(is_first_row)
            .when(local.is_prev_addr_zero.result)
            .assert_zero(prev_addr.clone());
        // Outside the first row, `is_prev_addr_zero` is a pure witness helper and should stay at
        // its default trace value. Constrain this through transition `next` columns so the single
        // row case does not accidentally force first-row helpers to zero in boundary extraction.
        builder
            .when_transition()
            .assert_zero(next.is_prev_addr_zero.inverse);
        builder
            .when_transition()
            .assert_zero(next.is_prev_addr_zero.result);

        // When prev_addr == 0 in the first row, canonicalize the helper witness to match trace
        // population (inverse = 0).
        builder
            .when_first_row()
            .when(local.is_prev_addr_zero.result)
            .assert_zero(local.is_prev_addr_zero.inverse);

        // Constrain the is_first_comp column.
        builder.assert_bool(local.is_first_comp);
        builder
            .when_first_row()
            .assert_eq(local.is_first_comp, AB::Expr::one() - local.is_prev_addr_zero.result);
        // In the degenerate single-row case, force the row to be the `%x0` address case.
        // This removes a Picus-only underconstrained branch where `addr` can drift without inputs.
        builder
            .when(builder.is_first_row() * builder.is_last_row())
            .assert_zero(local.is_first_comp);
        builder.when_transition().assert_zero(next.is_first_comp);
        // For all non-first real rows (`is_next_comp = 1` in this trace), first-row-only helper
        // columns must be zero.
        builder
            .when(local.is_next_comp)
            .assert_zero(local.is_prev_addr_zero.inverse);
        builder
            .when(local.is_next_comp)
            .assert_zero(local.is_prev_addr_zero.result);
        builder
            .when(local.is_next_comp)
            .assert_zero(local.is_first_comp);

        // Canonicalize local less-than helper flags when no local comparison is requested.
        // This is exactly the case `is_first_comp = 0` and `is_next_comp = 0`.
        let no_local_lt_check =
            (AB::Expr::one() - local.is_first_comp) * (AB::Expr::one() - local.is_next_comp);
        for flag in local.lt_cols.bit_flags.iter() {
            builder.assert_zero(no_local_lt_check.clone() * (*flag));
        }

        // Ensure at least one real row.
        builder.when_first_row().assert_one(local.is_real);

        // Constrain the inequality assertion in the first row.
        local.lt_cols.eval(builder, prev_addr_bits, &local_addr_bits, local.is_first_comp);

        // Insure that there are no duplicate initializations by assuring there is exactly one
        // initialization event of the zero address. This is done by assuring that when the previous
        // address is zero, then the first row address is also zero, and that the second row is also
        // real, and the less than comparison is being made.
        builder.when_first_row().when(local.is_prev_addr_zero.result).assert_zero(local.addr);
        builder.when_first_row().when(local.is_prev_addr_zero.result).assert_one(next.is_real);
        // Ensure that in the address zero case the comparison is being made so that there is an
        // address bigger than zero being committed to.
        builder.when_first_row().when(local.is_prev_addr_zero.result).assert_one(next.is_next_comp);

        // Make assertions for specific types of memory chips.

        if self.kind == MemoryChipType::Initialize {
            builder.when(local.is_real).assert_eq(local.timestamp, AB::F::ONE);
            builder.when(local.is_real).assert_eq(local.shard, AB::F::ONE);
        }

        // Constraints related to register %x0.

        // Register %x0 should always be 0. See 2.6 Load and Store Instruction on
        // P.18 of the MIPS spec.  To ensure that, we will constrain that the value is zero
        // whenever the `is_first_comp` flag is set to zero as well. This guarantees that the
        // presence of this flag asserts the initialization/finalization of %x0 to zero.
        //
        // **Remark**: it is up to the verifier to ensure that this flag is set to zero exactly
        // once, this can be constrained by the public values setting `previous_init_addr_bits` or
        // `previous_finalize_addr_bits` to zero.
        for i in 0..32 {
            builder.when_first_row().when_not(local.is_first_comp).assert_zero(local.value[i]);
        }

        // Make assertions for the final value. We need to connect the final valid address to the
        // corresponding `last_addr` value.
        let last_addr_bits = match self.kind {
            MemoryChipType::Initialize => &public_values.last_init_addr_bits,
            MemoryChipType::Finalize => &public_values.last_finalize_addr_bits,
        };
        // The last address is either:
        // - It's the last row and `is_real` is set to one.
        // - The flag `is_real` is set to one and the next `is_real` is set to zero.

        // Constrain the `is_last_addr` flag.
        builder.assert_bool(local.is_last_addr);
        builder.when_last_row().assert_eq(local.is_last_addr, local.is_real);
        builder
            .when_transition()
            .assert_eq(local.is_last_addr, local.is_real * (AB::Expr::one() - next.is_real));

        // Constrain the last address bits to be equal to the corresponding `last_addr_bits` value.
        for (local_bit, pub_bit) in local.addr_bits.bits.iter().zip(last_addr_bits.iter()) {
            builder.when_last_row().when(local.is_real).assert_eq(*local_bit, pub_bit.clone());
            builder
                .when_transition()
                .when(local.is_last_addr)
                .assert_eq(*local_bit, pub_bit.clone());
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::programs::tests::simple_program;
    use crate::{
        mips::MipsAir, syscall::precompiles::sha256::extend_tests::sha_extend_program,
        utils::setup_logger,
    };
    use p3_koala_bear::KoalaBear;
    use zkm_core_executor::Executor;
    use zkm_stark::{
        debug_lookups_with_all_chips, koala_bear_poseidon2::KoalaBearPoseidon2, StarkMachine,
        ZKMCoreOpts,
    };

    #[test]
    fn test_memory_generate_trace() {
        let program = simple_program();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        let shard = runtime.record.clone();

        let chip: MemoryGlobalChip = MemoryGlobalChip::new(MemoryChipType::Initialize);

        let trace: RowMajorMatrix<KoalaBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default()).unwrap();
        println!("{:?}", trace.values);

        let chip: MemoryGlobalChip = MemoryGlobalChip::new(MemoryChipType::Finalize);
        let trace: RowMajorMatrix<KoalaBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default()).unwrap();
        println!("{:?}", trace.values);

        for mem_event in shard.global_memory_finalize_events {
            println!("{mem_event:?}");
        }
    }

    #[test]
    fn test_memory_lookups() {
        setup_logger();
        let program = sha_extend_program();
        let program_clone = program.clone();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        let machine: StarkMachine<KoalaBearPoseidon2, MipsAir<KoalaBear>> =
            MipsAir::machine(KoalaBearPoseidon2::new());
        let (pkey, _) = machine.setup(&program_clone);
        let opts = ZKMCoreOpts::default();
        machine.generate_dependencies(&mut runtime.records, &opts, None).unwrap();

        let shards = runtime.records;
        for shard in shards.clone() {
            debug_lookups_with_all_chips::<KoalaBearPoseidon2, MipsAir<KoalaBear>>(
                &machine,
                &pkey,
                &[shard],
                vec![LookupKind::Memory],
                LookupScope::Local,
            );
        }
        debug_lookups_with_all_chips::<KoalaBearPoseidon2, MipsAir<KoalaBear>>(
            &machine,
            &pkey,
            &shards,
            vec![LookupKind::Memory],
            LookupScope::Global,
        );
    }

    #[test]
    fn test_byte_lookups() {
        setup_logger();
        let program = sha_extend_program();
        let program_clone = program.clone();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        let machine = MipsAir::machine(KoalaBearPoseidon2::new());
        let (pkey, _) = machine.setup(&program_clone);
        let opts = ZKMCoreOpts::default();
        machine.generate_dependencies(&mut runtime.records, &opts, None).unwrap();

        let shards = runtime.records;
        debug_lookups_with_all_chips::<KoalaBearPoseidon2, MipsAir<KoalaBear>>(
            &machine,
            &pkey,
            &shards,
            vec![LookupKind::Byte],
            LookupScope::Global,
        );
    }
}
