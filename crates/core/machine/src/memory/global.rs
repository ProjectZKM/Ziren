use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use std::array;
use zkm_derive::PicusAnnotations;
use zkm_pcs::PicusInfo;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use zkm_core_executor::events::{GlobalLookupEvent, MemoryInitializeFinalizeEvent};
use zkm_core_executor::{ExecutionRecord, Program};
use zkm_derive::AlignedBorrow;
use zkm_pcs::{
    air::{AirLookup, LookupScope, MachineAir, ZKMAirBuilder},
    LookupKind,
};

use crate::{
    operations::{AssertLtColsBits, IsZeroOperation, KoalaBearBitDecomposition},
    utils::{next_multiple_of_32, zeroed_f_vec},
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

    fn picus_info(&self) -> PicusInfo {
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
        let padded_nb_rows = next_multiple_of_32(
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
                cols.addr = F::from_u32(addr);
                cols.addr_bits.populate(addr);
                cols.shard = F::from_u32(shard);
                cols.timestamp = F::from_u32(timestamp);
                cols.value = array::from_fn(|i| F::from_u32((value >> i) & 1));
                cols.is_real = F::ONE;

                row
            })
            .collect::<Vec<_>>();

        let prev0_addr: u32 =
            previous_addr_bits.iter().enumerate().map(|(j, bit)| bit * (1 << j)).sum();
        let is_comp_vec: Vec<bool> = (0..memory_events.len())
            .map(|i| {
                let prev_addr = if i == 0 { prev0_addr } else { memory_events[i - 1].addr };
                !(i == 0 && prev_addr == 0)
            })
            .collect();

        rows.par_iter_mut().enumerate().for_each(|(i, row)| {
            let addr = memory_events[i].addr;
            let prev_addr = if i == 0 { prev0_addr } else { memory_events[i - 1].addr };
            let is_comp = is_comp_vec[i];
            let cols: &mut MemoryInitCols<F> = row.as_mut_slice().borrow_mut();
            cols.index = F::from_u32(i as u32);
            cols.prev_addr = F::from_u32(prev_addr);
            cols.prev_addr_bits.populate(prev_addr);
            cols.is_prev_addr_zero.populate(prev_addr);
            cols.is_index_zero.populate(i as u32);
            cols.is_comp = F::from_bool(is_comp);
            cols.prev_valid = F::from_bool(if i == 0 { true } else { is_comp_vec[i - 1] });
            if is_comp {
                debug_assert!(
                    prev_addr < addr,
                    "memory ordering: prev_addr {prev_addr} < addr {addr}"
                );
                let addr_bits: [_; 32] = array::from_fn(|k| (addr >> k) & 1);
                let prev_addr_bits_arr: [_; 32] = array::from_fn(|k| (prev_addr >> k) & 1);
                cols.lt_cols.populate(&prev_addr_bits_arr, &addr_bits);
            }
        });

        let padded_nb_rows = <MemoryGlobalChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let mut values = zeroed_f_vec::<F>(padded_nb_rows * NUM_MEMORY_INIT_COLS);
        let kept_rows = rows.len().min(padded_nb_rows);
        values[..kept_rows * NUM_MEMORY_INIT_COLS]
            .par_chunks_mut(NUM_MEMORY_INIT_COLS)
            .zip(rows[..kept_rows].par_iter())
            .for_each(|(dst, src)| dst.copy_from_slice(src));

        Ok(RowMajorMatrix::new(values, NUM_MEMORY_INIT_COLS))
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

#[derive(PicusAnnotations, AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct MemoryInitCols<T: Copy> {
    /// The shard number of the memory access.
    pub shard: T,

    /// The timestamp of the memory access.
    pub timestamp: T,

    /// The address of the memory access.
    pub addr: T,

    /// Option 2: running chain index for the `MemoryGlobal*Control` bus.
    pub index: T,

    /// Option 2: previous-row address, received via the bus (chained to
    /// the prior row's `addr`; the genesis row receives the prior shard's
    /// `previous_*_addr` from the public-values AIR).
    pub prev_addr: T,

    /// Bit decomposition of `prev_addr`, range-checked (gated `is_real`)
    /// so the local `prev_addr < addr` comparison is canonical.
    pub prev_addr_bits: KoalaBearBitDecomposition<T>,

    /// The bus `valid` flag received alongside `prev_addr` (equals the
    /// prior row's `is_comp`; `1` from the PV genesis endpoint).
    pub prev_valid: T,

    /// Comparison assertions for address to be strictly increasing.
    pub lt_cols: AssertLtColsBits<T, 32>,

    /// A bit decomposition of `addr`.
    pub addr_bits: KoalaBearBitDecomposition<T>,

    /// The value of the memory access.
    pub value: [T; 32],

    /// Whether the memory access is a real access.
    pub is_real: T,

    /// Whether this row asserts `prev_addr < addr` (equals `is_real`
    /// except for the unique genesis row `index==0 && prev_addr==0`).
    pub is_comp: T,

    /// A witness to assert whether or not the previous address is zero.
    pub is_prev_addr_zero: IsZeroOperation<T>,

    /// A witness to assert whether or not `index == 0` (genesis detection).
    pub is_index_zero: IsZeroOperation<T>,
}

pub(crate) const NUM_MEMORY_INIT_COLS: usize = size_of::<MemoryInitCols<u8>>();

impl<AB> Air<AB> for MemoryGlobalChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &MemoryInitCols<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_real);
        for i in 0..32 {
            builder.assert_bool(local.value[i]);
        }

        let mut byte1 = AB::Expr::ZERO;
        let mut byte2 = AB::Expr::ZERO;
        let mut byte3 = AB::Expr::ZERO;
        let mut byte4 = AB::Expr::ZERO;
        for i in 0..8 {
            byte1 = byte1.clone() + local.value[i].into() * AB::F::from_u8(1 << i);
            byte2 = byte2.clone() + local.value[i + 8].into() * AB::F::from_u8(1 << i);
            byte3 = byte3.clone() + local.value[i + 16].into() * AB::F::from_u8(1 << i);
            byte4 = byte4.clone() + local.value[i + 24].into() * AB::F::from_u8(1 << i);
        }
        let value = [byte1, byte2, byte3, byte4];

        if self.kind == MemoryChipType::Initialize {
            builder.send(
                AirLookup::new(
                    vec![
                        AB::Expr::ZERO,
                        AB::Expr::ZERO,
                        local.addr.into(),
                        value[0].clone(),
                        value[1].clone(),
                        value[2].clone(),
                        value[3].clone(),
                        local.is_real.into() * AB::Expr::ONE,
                        local.is_real.into() * AB::Expr::ZERO,
                        AB::Expr::from_u8(LookupKind::Memory as u8),
                    ],
                    local.is_real.into(),
                    LookupKind::Global,
                ),
                LookupScope::Local,
            );
        } else {
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
                        local.is_real.into() * AB::Expr::ZERO,
                        local.is_real.into() * AB::Expr::ONE,
                        AB::Expr::from_u8(LookupKind::Memory as u8),
                    ],
                    local.is_real.into(),
                    LookupKind::Global,
                ),
                LookupScope::Local,
            );
        }

        KoalaBearBitDecomposition::<AB::F>::range_check(
            builder,
            local.addr,
            local.addr_bits,
            local.is_real.into(),
        );

        KoalaBearBitDecomposition::<AB::F>::range_check(
            builder,
            local.prev_addr,
            local.prev_addr_bits,
            local.is_real.into(),
        );

        IsZeroOperation::<AB::F>::eval(
            builder,
            local.prev_addr.into(),
            local.is_prev_addr_zero,
            local.is_real.into(),
        );
        IsZeroOperation::<AB::F>::eval(
            builder,
            local.index.into(),
            local.is_index_zero,
            local.is_real.into(),
        );
        builder.assert_bool(local.is_comp);
        builder.assert_eq(
            local.is_comp,
            local.is_real.into()
                * (AB::Expr::ONE - local.is_prev_addr_zero.result * local.is_index_zero.result),
        );

        local.lt_cols.eval(
            builder,
            &local.prev_addr_bits.bits,
            &local.addr_bits.bits,
            local.is_comp,
        );

        let is_not_comp = local.is_real.into() - local.is_comp.into();
        builder.when(is_not_comp.clone()).assert_zero(local.addr);
        for i in 0..32 {
            builder.when(is_not_comp.clone()).assert_zero(local.value[i]);
        }

        let control_kind = match self.kind {
            MemoryChipType::Initialize => LookupKind::MemoryGlobalInitControl,
            MemoryChipType::Finalize => LookupKind::MemoryGlobalFinalizeControl,
        };
        builder.receive(
            AirLookup::new(
                vec![local.index.into(), local.prev_addr.into(), local.prev_valid.into()],
                local.is_real.into(),
                control_kind,
            ),
            LookupScope::Local,
        );
        builder.send(
            AirLookup::new(
                vec![local.index.into() + AB::Expr::ONE, local.addr.into(), local.is_comp.into()],
                local.is_real.into(),
                control_kind,
            ),
            LookupScope::Local,
        );

        if self.kind == MemoryChipType::Initialize {
            builder.when(local.is_real).assert_eq(local.timestamp, AB::F::ONE);
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
    use zkm_pcs::{
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
