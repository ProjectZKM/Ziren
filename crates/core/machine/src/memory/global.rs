use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use zkm_derive::PicusAnnotations;
use zkm_pcs::PicusInfo;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use zkm_core_executor::events::{ByteLookupMap, ByteRecord, MemoryInitializeFinalizeEvent};
use zkm_core_executor::{ByteOpcode, ExecutionRecord, Program};
use zkm_derive::AlignedBorrow;
use zkm_pcs::{
    air::{AirLookup, LookupScope, MachineAir, ZKMAirBuilder},
    LookupKind,
};

use crate::{
    air::WordAirBuilder,
    utils::{next_multiple_of_32, zeroed_f_vec},
    CoreChipError,
};

use super::MemoryChipType;

/// The high limb of the largest address, `0x7F000000`: the field's order less one.
pub(crate) const TOP_ADDR_HI: u32 = 0x7F00;

/// The low and the high 16 bits of an address.
const fn addr_limbs(addr: u32) -> [u32; 2] {
    [addr & 0xffff, addr >> 16]
}

/// How a row's address compares with the address before it: the previous address, which the
/// control bus gives the row, and the flags and difference the row derives from the two.
struct AddrComparison {
    prev_addr: u32,
    prev_valid: bool,
    is_comp: bool,
    hi_differs: bool,
    /// The difference of the limbs the comparison is decided by, as an integer that wraps.
    gap: u32,
}

impl AddrComparison {
    /// The comparison of row `index`, where `sorted` holds the table's events by address and
    /// `first_prev_addr` is the address the public values give row 0.
    fn new(sorted: &[MemoryInitializeFinalizeEvent], first_prev_addr: u32, index: usize) -> Self {
        let addr = sorted[index].addr;
        let prev_addr = if index == 0 { first_prev_addr } else { sorted[index - 1].addr };
        let [lo, hi] = addr_limbs(addr);
        let [prev_lo, prev_hi] = addr_limbs(prev_addr);
        let hi_differs = hi != prev_hi;
        Self {
            prev_addr,
            prev_valid: index != 1 || first_prev_addr != 0,
            is_comp: index != 0 || prev_addr != 0,
            hi_differs,
            gap: if hi_differs { hi.wrapping_sub(prev_hi) } else { lo.wrapping_sub(prev_lo) },
        }
    }
}

/// The byte lookups one row emits, shared by `generate_dependencies` and the constraints so
/// the two cannot drift: the value bytes in two pairs, both address limbs, the distance of the
/// high limb from [`TOP_ADDR_HI`], and on a compared row the gap less one.
fn row_blu_events(
    event: &MemoryInitializeFinalizeEvent,
    cmp: &AddrComparison,
    blu: &mut impl ByteRecord,
) {
    let [lo, hi] = addr_limbs(event.addr);
    blu.add_u8_range_checks(&event.value.to_le_bytes());
    blu.add_u16_range_check(lo as u16);
    blu.add_u16_range_check(hi as u16);
    blu.add_u16_range_check(TOP_ADDR_HI.wrapping_sub(hi) as u16);
    if cmp.is_comp {
        blu.add_u16_range_check(cmp.gap.wrapping_sub(1) as u16);
    }
}

/// A memory chip that can initialize or finalize values in memory.
///
/// A row holds one address as two 16-bit limbs and its value as four bytes. The table lists
/// its addresses in strictly increasing order, across the shards of an execution, so no
/// address is initialized or finalized twice. No constraint spans two rows: a row receives the
/// limbs of the address before it over the `MemoryGlobal{Init,Finalize}Control` bus and sends
/// its own, and the public values close the chain at both ends of a shard.
///
/// # One limb pair per address
///
/// The global memory message carries the address as one field element,
/// `addr[0] + 2^16 * addr[1]`. Both limbs are range-checked to 16 bits, the high limb is at
/// most [`TOP_ADDR_HI`], and at that high limb the low one is zero. The integer the limbs
/// spell is therefore below the field's order, and two rows with different limbs name
/// different field elements.
///
/// # The limbs a row receives are 16-bit limbs
///
/// The comparison of `prev_addr` with `addr` reads the limbs of `prev_addr` as integers below
/// `2^16`. This row does not range-check them. They are in range because of where they come
/// from:
///
/// * A row with `index > 0` receives the tuple the row with the index before it sent: the
///   indices of a table's real rows are `0, 1, 2, ...`, each once, as a row's index needs a
///   sender and the public values send index 0 alone. That sender range-checked the limbs as
///   its own address.
/// * The row with `index = 0` receives the two sums the public values spell from the 32
///   elements of the previous address. A shard without rows of this chip sends and receives
///   one tuple, so its two sums of the last address equal those of the previous one; a shard
///   with rows receives the limbs of its last row; and the verifier of an execution equates
///   the 32 elements of a shard's previous address with those of the shard before it, and
///   with zero for the first shard. The sums are therefore zero or the range-checked limbs of
///   the last row of an earlier shard.
///
/// # Which rows compare
///
/// A real row compares, `is_comp = 1`, unless `index`, `prev_addr[0]` and `prev_addr[1]` are
/// all zero. The one row that does not compare holds address zero with value zero. It is not
/// a table's last row, as the public values receive `is_comp = 1` from the last row, so the
/// last address of a shard with rows is above zero and no later shard has a row that does not
/// compare.
pub struct MemoryGlobalChip {
    pub kind: MemoryChipType,
}

impl MemoryGlobalChip {
    /// Creates a new memory chip with a certain type.
    pub const fn new(kind: MemoryChipType) -> Self {
        Self { kind }
    }

    /// The table's events by address, and the address the public values give its first
    /// row.
    fn sorted_events(&self, input: &ExecutionRecord) -> (Vec<MemoryInitializeFinalizeEvent>, u32) {
        let (mut events, previous_addr_bits) = match self.kind {
            MemoryChipType::Initialize => (
                input.global_memory_initialize_events.clone(),
                input.public_values.previous_init_addr_bits,
            ),
            MemoryChipType::Finalize => (
                input.global_memory_finalize_events.clone(),
                input.public_values.previous_finalize_addr_bits,
            ),
        };
        events.sort_by_key(|event| event.addr);
        let first_prev_addr =
            previous_addr_bits.iter().enumerate().map(|(j, bit)| bit * (1 << j)).sum();
        (events, first_prev_addr)
    }
}

impl<F> BaseAir<F> for MemoryGlobalChip {
    fn width(&self) -> usize {
        NUM_MEMORY_INIT_COLS
    }
}

/// The rows whose byte lookups one task counts.
const BLU_CHUNK_ROWS: usize = 1 << 16;

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
        let (events, first_prev_addr) = self.sorted_events(input);
        let maps = events
            .par_chunks(BLU_CHUNK_ROWS)
            .enumerate()
            .map(|(chunk, rows)| {
                let mut blu = ByteLookupMap::default();
                for (offset, event) in rows.iter().enumerate() {
                    let cmp = AddrComparison::new(
                        &events,
                        first_prev_addr,
                        chunk * BLU_CHUNK_ROWS + offset,
                    );
                    row_blu_events(event, &cmp, &mut blu);
                }
                blu
            })
            .collect::<Vec<_>>();
        output.add_byte_lookup_events_from_maps(maps.iter().collect());
        Ok(())
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let events = match self.kind {
            MemoryChipType::Initialize => &input.global_memory_initialize_events,
            MemoryChipType::Finalize => &input.global_memory_finalize_events,
        };
        let nb_rows = events.len();
        let padded_nb_rows = next_multiple_of_32(
            nb_rows,
            None,
            <MemoryGlobalChip as MachineAir<F>>::name(self).as_str(),
        );
        Some(padded_nb_rows)
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        let (events, first_prev_addr) = self.sorted_events(input);

        let padded_nb_rows = <MemoryGlobalChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let mut values = zeroed_f_vec::<F>(padded_nb_rows * NUM_MEMORY_INIT_COLS);
        values.par_chunks_mut(NUM_MEMORY_INIT_COLS).zip(events.par_iter()).enumerate().for_each(
            |(index, (row, event))| {
                let cmp = AddrComparison::new(&events, first_prev_addr, index);
                debug_assert!(
                    !cmp.is_comp || cmp.prev_addr < event.addr,
                    "memory ordering: prev_addr {} < addr {}",
                    cmp.prev_addr,
                    event.addr
                );
                let cols: &mut MemoryInitCols<F> = row.borrow_mut();
                cols.populate(event, &cmp, index);
            },
        );

        Ok(RowMajorMatrix::new(values, NUM_MEMORY_INIT_COLS))
    }

    fn included(&self, shard: &Self::Record) -> bool {
        match self.kind {
            MemoryChipType::Initialize => !shard.global_memory_initialize_events.is_empty(),
            MemoryChipType::Finalize => !shard.global_memory_finalize_events.is_empty(),
        }
    }
}

#[derive(PicusAnnotations, AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct MemoryInitCols<T: Copy> {
    /// The shard number of the memory access.
    pub shard: T,

    /// The timestamp of the memory access.
    pub timestamp: T,

    /// The address of the memory access: its low and its high 16 bits, each range-checked.
    pub addr: [T; 2],

    /// The inverse of [`TOP_ADDR_HI`] less `addr[1]`, which shows that the high limb is not
    /// the top one. A row cannot hold it at the top high limb, and its low limb is then zero.
    pub top_inv: T,

    /// The row's place in the chain of the `MemoryGlobal*Control` bus, from zero.
    pub index: T,

    /// The limbs of the address before this one, received from the bus: the address of the
    /// row before, or what the public values give the row with index zero. They are 16-bit
    /// limbs by the argument in [`MemoryGlobalChip`], which this row does not repeat.
    pub prev_addr: [T; 2],

    /// The flag received with `prev_addr`: the `is_comp` of the row before, and one from the
    /// public values.
    pub prev_valid: T,

    /// Whether the high limbs of `prev_addr` and `addr` differ. The high limbs decide the
    /// comparison when it is one; they are equal and the low limbs decide it when it is zero.
    pub hi_differs: T,

    /// The limb of `addr` less that of `prev_addr`, at the limbs that decide the comparison.
    /// A compared row range-checks `gap - 1` to 16 bits. Both limbs are integers below `2^16`
    /// (those of `prev_addr` by the argument in [`MemoryGlobalChip`]), so the check holds
    /// only where the limb of `addr` is the larger one, and `prev_addr < addr` follows: the
    /// high limb is larger, or the high limbs are equal and the low limb is larger.
    pub gap: T,

    /// The bytes of the value of the memory access, each range-checked.
    pub value: [T; 4],

    /// Whether the memory access is a real access.
    pub is_real: T,

    /// Whether this row asserts `prev_addr < addr`: every real row but the one with index
    /// zero and a zero `prev_addr`.
    pub is_comp: T,

    /// The inverse of `index + prev_addr[0] + prev_addr[1]` on a compared row, which shows
    /// that the three are not all zero.
    pub zero_inv: T,
}

pub(crate) const NUM_MEMORY_INIT_COLS: usize = size_of::<MemoryInitCols<u8>>();

impl<F: Field> MemoryInitCols<F> {
    /// Fills the row of `event`, which stands at `index` in its table with the address
    /// comparison `cmp`.
    fn populate(
        &mut self,
        event: &MemoryInitializeFinalizeEvent,
        cmp: &AddrComparison,
        index: usize,
    ) {
        let [lo, hi] = addr_limbs(event.addr);
        let [prev_lo, prev_hi] = addr_limbs(cmp.prev_addr);
        self.shard = F::from_u32(event.shard);
        self.timestamp = F::from_u32(event.timestamp);
        self.addr = [F::from_u32(lo), F::from_u32(hi)];
        self.top_inv = (F::from_u32(TOP_ADDR_HI) - self.addr[1]).try_inverse().unwrap_or(F::ZERO);
        self.index = F::from_usize(index);
        self.prev_addr = [F::from_u32(prev_lo), F::from_u32(prev_hi)];
        self.prev_valid = F::from_bool(cmp.prev_valid);
        self.hi_differs = F::from_bool(cmp.hi_differs);
        self.gap = if cmp.hi_differs {
            self.addr[1] - self.prev_addr[1]
        } else {
            self.addr[0] - self.prev_addr[0]
        };
        self.value = event.value.to_le_bytes().map(F::from_u8);
        self.is_real = F::ONE;
        self.is_comp = F::from_bool(cmp.is_comp);
        self.zero_inv = if cmp.is_comp {
            (self.index + self.prev_addr[0] + self.prev_addr[1]).try_inverse().unwrap_or(F::ZERO)
        } else {
            F::ZERO
        };
    }
}

impl<AB> Air<AB> for MemoryGlobalChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &MemoryInitCols<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_real);
        builder.assert_bool(local.is_comp);
        builder.assert_bool(local.hi_differs);

        let [addr_lo, addr_hi] = local.addr;
        let [prev_lo, prev_hi] = local.prev_addr;
        let top_distance = AB::Expr::from_u32(TOP_ADDR_HI) - addr_hi;
        let u16_range = AB::Expr::from_u8(ByteOpcode::U16Range as u8);

        builder.slice_range_check_u8(&local.value, local.is_real);
        builder.slice_range_check_u16(&local.addr, local.is_real);
        builder.send_byte(
            u16_range.clone(),
            top_distance.clone(),
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            local.is_real,
        );
        builder.assert_zero(addr_lo * (AB::Expr::ONE - local.top_inv * top_distance));

        let addr = addr_lo.into() + addr_hi.into() * AB::F::from_u32(1 << 16);
        let value: [AB::Expr; 4] = local.value.map(Into::into);
        if self.kind == MemoryChipType::Initialize {
            let mut values = vec![AB::Expr::ZERO, AB::Expr::ZERO, addr];
            values.extend(value);
            builder.send(
                AirLookup::new(values, local.is_real.into(), LookupKind::Memory),
                LookupScope::Global,
            );
        } else {
            let mut values = vec![local.shard.into(), local.timestamp.into(), addr];
            values.extend(value);
            builder.receive(
                AirLookup::new(values, local.is_real.into(), LookupKind::Memory),
                LookupScope::Global,
            );
        }

        builder.assert_eq(
            local.is_comp,
            local.is_real * local.zero_inv * (local.index + prev_lo + prev_hi),
        );
        let is_not_comp = local.is_real.into() - local.is_comp.into();
        for zero in [local.index, prev_lo, prev_hi, addr_lo, addr_hi].into_iter().chain(local.value)
        {
            builder.when(is_not_comp.clone()).assert_zero(zero);
        }

        builder.when_not(local.hi_differs).assert_eq(addr_hi, prev_hi);
        builder.assert_eq(
            local.gap,
            local.hi_differs * (addr_hi - prev_hi)
                + (AB::Expr::ONE - local.hi_differs) * (addr_lo - prev_lo),
        );
        builder.send_byte(
            u16_range,
            local.gap - AB::Expr::ONE,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            local.is_comp,
        );

        let control_kind = match self.kind {
            MemoryChipType::Initialize => LookupKind::MemoryGlobalInitControl,
            MemoryChipType::Finalize => LookupKind::MemoryGlobalFinalizeControl,
        };
        builder.receive(
            AirLookup::new(
                vec![local.index.into(), prev_lo.into(), prev_hi.into(), local.prev_valid.into()],
                local.is_real.into(),
                control_kind,
            ),
            LookupScope::Local,
        );
        builder.send(
            AirLookup::new(
                vec![
                    local.index.into() + AB::Expr::ONE,
                    addr_lo.into(),
                    addr_hi.into(),
                    local.is_comp.into(),
                ],
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

    type F = KoalaBear;
    type EF = p3_field::extension::QuinticTrinomialExtensionField<F>;

    /// The row at `index` of a table that holds `addrs`, each with value `value`, after the
    /// previous address `first_prev_addr`.
    fn chain_row(addrs: &[u32], first_prev_addr: u32, index: usize, value: u32) -> Vec<F> {
        let events = addrs
            .iter()
            .map(|&addr| MemoryInitializeFinalizeEvent { addr, value, shard: 3, timestamp: 1 })
            .collect::<Vec<_>>();
        let mut row = vec![F::ZERO; NUM_MEMORY_INIT_COLS];
        let cols: &mut MemoryInitCols<F> = row.as_mut_slice().borrow_mut();
        cols.populate(&events[index], &AddrComparison::new(&events, first_prev_addr, index), index);
        row
    }

    /// Whether the constraints of both kinds of the chip hold on `row` after `edit`. The
    /// lookups are not checked.
    fn holds_after(row: &[F], edit: impl Fn(&mut MemoryInitCols<F>)) -> bool {
        let mut row = row.to_vec();
        edit(row.as_mut_slice().borrow_mut());
        [MemoryChipType::Initialize, MemoryChipType::Finalize].into_iter().all(|kind| {
            zkm_pcs::constraints_hold_on_row::<F, EF, _>(
                &MemoryGlobalChip::new(kind),
                &row,
                &row,
                &[],
            )
        })
    }

    #[test]
    fn only_the_row_at_the_start_of_the_chain_skips_the_comparison() {
        let start = chain_row(&[0, 5], 0, 0, 0);
        assert!(holds_after(&start, |_| {}));
        assert!(!holds_after(&start, |cols| cols.value[2] = F::ONE));
        assert!(!holds_after(&start, |cols| cols.addr[0] = F::from_u32(4)));
        assert!(!holds_after(&start, |cols| cols.addr[1] = F::ONE));
        assert!(!holds_after(&start, |cols| cols.index = F::ONE));
        assert!(!holds_after(&start, |cols| cols.prev_addr[0] = F::ONE));
        assert!(!holds_after(&start, |cols| cols.prev_addr[1] = F::ONE));
        for zero_inv in [F::ZERO, F::ONE] {
            assert!(!holds_after(&start, |cols| {
                cols.is_comp = F::ONE;
                cols.zero_inv = zero_inv;
            }));
        }

        for (addrs, first_prev_addr, index) in
            [(&[0, 5][..], 0, 1), (&[0x1_0004, 0x1_0008], 0x1_0000, 0), (&[8, 12], 4, 0)]
        {
            let compared = chain_row(addrs, first_prev_addr, index, 0);
            assert!(holds_after(&compared, |_| {}));
            let honest: &MemoryInitCols<F> = compared.as_slice().borrow();
            for zero_inv in [F::ZERO, honest.zero_inv] {
                assert!(!holds_after(&compared, |cols: &mut MemoryInitCols<F>| {
                    cols.is_comp = F::ZERO;
                    cols.zero_inv = zero_inv;
                }));
            }
        }
    }

    #[test]
    fn the_top_high_limb_holds_only_the_last_address() {
        let top = TOP_ADDR_HI << 16;
        let last = chain_row(&[top - 4, top], 0, 1, 0x0403_0201);
        assert!(holds_after(&last, |_| {}));
        for top_inv in [F::ZERO, F::ONE, F::from_u32(TOP_ADDR_HI).inverse()] {
            assert!(!holds_after(&last, |cols| {
                cols.addr[0] = F::from_u32(4);
                cols.top_inv = top_inv;
            }));
        }
        let below = chain_row(&[top - 8, top - 4], 0, 1, 0);
        assert!(holds_after(&below, |_| {}));
        assert!(!holds_after(&below, |cols| cols.top_inv = F::ZERO));
    }

    #[test]
    fn the_gap_is_of_the_limbs_that_decide_the_comparison() {
        let low = chain_row(&[0x2_0010, 0x2_0030], 0, 1, 0);
        let high = chain_row(&[0x2_0010, 0x5_0004], 0, 1, 0);
        for row in [&low, &high] {
            assert!(holds_after(row, |_| {}));
            assert!(!holds_after(row, |cols| cols.gap += F::ONE));
        }
        assert!(!holds_after(&high, |cols| {
            cols.hi_differs = F::ZERO;
            cols.gap = cols.addr[0] - cols.prev_addr[0];
        }));
        assert!(!holds_after(&low, |cols| {
            cols.hi_differs = F::ONE;
            cols.gap = F::from_u32(0x20);
        }));
    }

    /// Two stores whose addresses differ in the high limb alone, with no address touched
    /// between them: the second row's comparison is decided by the high limbs, at equal low
    /// limbs.
    #[test]
    fn prove_neighbours_that_differ_in_the_high_limb_alone() {
        use zkm_core_executor::{Instruction, Opcode};

        let (first, second) = (0x2765_4320, 0x2766_4320);
        let program = Program::new(
            vec![
                Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
                Instruction::new(Opcode::SW, 29, 0, first, false, true),
                Instruction::new(Opcode::SW, 29, 0, second, false, true),
            ],
            0,
            0,
        );
        let mut runtime = Executor::new(program.clone(), ZKMCoreOpts::default());
        runtime.run().unwrap();
        let mut addrs = runtime
            .records
            .iter()
            .flat_map(|record| record.global_memory_initialize_events.iter())
            .map(|event| event.addr)
            .collect::<Vec<_>>();
        addrs.sort_unstable();
        assert!(addrs.windows(2).any(|pair| pair == [first, second]), "initialized: {addrs:x?}");

        crate::utils::run_test::<zkm_pcs::CpuProver<_, _>>(program).unwrap();
    }
}
