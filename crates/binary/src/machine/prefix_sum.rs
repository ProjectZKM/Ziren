//! The prefix-sum table: one row per bit of the jagged verifier's
//! prefix-sum checks, the field machine's `PrefixSumChecks` chip over bits.
//!
//! A row reads the bit `x1`, the point coordinate `x2`, the Lagrange product
//! `acc` and the Horner sum `fa` before the bit, and writes
//! `acc * eq(x1, x2)` and `2 fa + x1`.  With `x1` a bit the Lagrange factor
//! is `x2` when the bit is set and `1 - x2` otherwise, so the row subtracts
//! once, selects, and multiplies once in the extension.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, BaseAir, WindowAccess};
use p3_bus::{BusActivation, BusDirection};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_derive::AlignedBorrow;
use zkm_recursion_core::runtime::instruction::PrefixSumChecksInstr;
use zkm_recursion_core::{
    Address, ExecutionRecord, Instruction, PrefixSumChecksEvent, PrefixSumChecksIo,
    RecursionProgram,
};

use super::bits::{
    cell_tuple, dense, log_height_for, single_block, BitRows, Cell, ADDRESS_BITS, MEMORY, WRITE,
};
use super::memory::cell_of;
use crate::ext::{
    eval_ext_mul, ext_exprs, fill_ext_mul, ExtMulCols, ExtWord, EXT_DEGREE, EXT_MUL_REQUESTS,
};
use crate::machine_builder::MachineBuilder;
use crate::word::{
    bits_le, constant_bits, eval_sub, exprs, fill_sub, sub_borrows, sub_chain, SubCols, Word,
    KB_BITS, KB_PRIME,
};
use crate::BinaryBase;
use crate::F;

/// The program's part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct PrefixSumPrep<T> {
    /// Where the bit is read.
    pub addr_x1: [T; ADDRESS_BITS],
    /// Where the point coordinate is read.
    pub addr_x2: [T; ADDRESS_BITS],
    /// Where the Lagrange product before the bit is read.
    pub addr_acc: [T; ADDRESS_BITS],
    /// Where the Horner sum before the bit is read.
    pub addr_fa: [T; ADDRESS_BITS],
    /// Where the Lagrange product after the bit is written.
    pub addr_new_acc: [T; ADDRESS_BITS],
    /// Where the Horner sum after the bit is written.
    pub addr_new_fa: [T; ADDRESS_BITS],
    /// The row holds a bit, and reads its inputs.
    pub is_real: T,
    /// The new Lagrange product is read at least once.
    pub has_acc: T,
    /// The new Horner sum is read at least once.
    pub has_fa: T,
}

/// The witness part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct PrefixSumCols<T> {
    /// The bit, a word whose upper bits are zero.
    pub x1: Word<T>,
    /// The point coordinate.
    pub x2: ExtWord<T>,
    /// The Lagrange product before the bit.
    pub acc: ExtWord<T>,
    /// `1 - x2`, coefficient by coefficient.
    pub one_minus: [SubCols<T>; EXT_DEGREE],
    /// The Lagrange factor: `x2` when the bit is set, else `1 - x2`.
    pub factor: ExtWord<T>,
    /// `acc * factor`, the Lagrange product after the bit.
    pub mul: ExtMulCols<T>,
    /// The Horner sum before the bit.
    pub fa: Word<T>,
    /// Borrows of `2 fa + x1 - p` over 32 bits; the last is `1` when the
    /// doubled sum is below `p`.
    pub fa_borrows: [T; 32],
    /// `2 fa + x1 mod p`, the Horner sum after the bit.
    pub new_fa: Word<T>,
}

/// Columns of [`PrefixSumPrep`].
pub const NUM_PREFIX_SUM_PREP_COLS: usize = core::mem::size_of::<PrefixSumPrep<u8>>();

/// Columns of [`PrefixSumCols`].
pub const NUM_PREFIX_SUM_COLS: usize = core::mem::size_of::<PrefixSumCols<u8>>();

/// The prefix-sum table of one program.
pub struct PrefixSumAir {
    log_height: usize,
    pub(super) preprocessed: Vec<u8>,
    /// `(address, reads)` of each row's new Lagrange product and new Horner
    /// sum, in order.
    outputs: Vec<[(u32, u32); 2]>,
}

/// `2 fa + x1 mod p`.
fn horner(fa: u32, x1: u32) -> u32 {
    let doubled = 2 * u64::from(fa) + u64::from(x1);
    let p = u64::from(KB_PRIME);
    (if doubled < p { doubled } else { doubled - p }) as u32
}

/// The Lagrange factor of `x1` against `x2`, and `1 - x2`.
fn factor(x1: u32, x2: Cell, cols: &mut [SubCols<u8>; EXT_DEGREE]) -> Cell {
    let one_minus: Cell =
        core::array::from_fn(|k| fill_sub(u32::from(k == 0), x2[k], &mut cols[k]));
    if x1 == 1 {
        x2
    } else {
        one_minus
    }
}

/// Fill `row` with the witness of `event`'s inputs, the outputs computed
/// from them, adding the products the row asks the multiply table for to
/// `requests`.
fn fill_row(
    event: &PrefixSumChecksEvent<KoalaBear>,
    row: &mut [u8],
    requests: &mut Vec<(u32, u32)>,
) {
    let x1 = event.x1.as_canonical_u32();
    let x2 = cell_of(&event.x2);
    let acc = cell_of(&event.acc);
    let fa = event.field_acc.as_canonical_u32();
    let words = |cell: Cell| -> ExtWord<u8> { cell.map(|w| bits_le::<KB_BITS>(u64::from(w))) };
    let cols: &mut PrefixSumCols<u8> = row.borrow_mut();
    cols.x1 = bits_le::<KB_BITS>(u64::from(x1));
    cols.x2 = words(x2);
    cols.acc = words(acc);
    let lagrange = factor(x1, x2, &mut cols.one_minus);
    cols.factor = words(lagrange);
    fill_ext_mul(acc, lagrange, &mut cols.mul, requests);
    cols.fa = bits_le::<KB_BITS>(u64::from(fa));
    let doubled = 2 * u64::from(fa) + u64::from(x1);
    cols.fa_borrows = sub_borrows::<32>(doubled, u64::from(KB_PRIME));
    cols.new_fa = bits_le::<KB_BITS>(u64::from(horner(fa, x1)));
}

/// The event a padding row checks: a zero bit against a zero coordinate.
fn padding_event() -> PrefixSumChecksEvent<KoalaBear> {
    PrefixSumChecksEvent {
        x1: KoalaBear::ZERO,
        x2: [KoalaBear::ZERO; EXT_DEGREE].into(),
        acc: [KoalaBear::ZERO; EXT_DEGREE].into(),
        new_acc: [KoalaBear::ZERO; EXT_DEGREE].into(),
        field_acc: KoalaBear::ZERO,
        new_field_acc: KoalaBear::ZERO,
    }
}

impl PrefixSumAir {
    /// The prefix-sum table of `program`, one row per bit in program order,
    /// reading what the field machine's chip reads.
    #[must_use]
    pub fn new(program: &RecursionProgram<KoalaBear>) -> Self {
        let instrs: Vec<&PrefixSumChecksInstr<KoalaBear>> = program
            .iter_instructions()
            .filter_map(|instruction| match instruction {
                Instruction::PrefixSumChecks(instr) => Some(instr.as_ref()),
                _ => None,
            })
            .collect();
        let rows: usize = instrs.iter().map(|instr| instr.addrs.x1.len()).sum();
        let log_height = log_height_for(rows);
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_PREFIX_SUM_PREP_COLS];
        let mut outputs = Vec::with_capacity(rows);
        let addr =
            |a: Address<KoalaBear>| bits_le::<ADDRESS_BITS>(u64::from(a.0.as_canonical_u32()));
        let mut row = 0;
        for instr in instrs {
            let PrefixSumChecksInstr {
                addrs: PrefixSumChecksIo { zero, one, x1, x2, accs, field_accs },
                acc_mults,
                field_acc_mults,
            } = instr;
            for i in 0..x1.len() {
                let (acc, fa) =
                    if i == 0 { (*one, *zero) } else { (accs[i - 1], field_accs[i - 1]) };
                let (acc_reads, fa_reads) =
                    (acc_mults[i].as_canonical_u32(), field_acc_mults[i].as_canonical_u32());
                let prep: &mut PrefixSumPrep<u8> = preprocessed
                    [row * NUM_PREFIX_SUM_PREP_COLS..(row + 1) * NUM_PREFIX_SUM_PREP_COLS]
                    .borrow_mut();
                prep.addr_x1 = addr(x1[i]);
                prep.addr_x2 = addr(x2[i]);
                prep.addr_acc = addr(acc);
                prep.addr_fa = addr(fa);
                prep.addr_new_acc = addr(accs[i]);
                prep.addr_new_fa = addr(field_accs[i]);
                prep.is_real = 1;
                prep.has_acc = u8::from(acc_reads > 0);
                prep.has_fa = u8::from(fa_reads > 0);
                outputs.push([
                    (accs[i].0.as_canonical_u32(), acc_reads),
                    (field_accs[i].0.as_canonical_u32(), fa_reads),
                ]);
                row += 1;
            }
        }
        tracing::info!("binary stage PrefixSum: {rows} bits, {} rows", 1usize << log_height);
        Self { log_height, preprocessed, outputs }
    }

    /// The log height of the table.
    #[must_use]
    pub fn log_height(&self) -> usize {
        self.log_height
    }

    /// The writes `(address, reads)` of the table that are read, in order.
    #[must_use]
    pub fn writes(&self) -> Vec<(u32, u32)> {
        self.outputs.iter().flatten().copied().filter(|&(_, reads)| reads > 0).collect()
    }

    /// The values of [`Self::writes`], in order.
    #[must_use]
    pub fn written_values(&self, record: &ExecutionRecord<KoalaBear>) -> Vec<Cell> {
        let events = &record.prefix_sum_checks_events;
        assert_eq!(events.len(), self.outputs.len(), "one event per bit");
        events
            .iter()
            .zip(&self.outputs)
            .flat_map(|(event, outputs)| {
                let fa = [event.new_field_acc.as_canonical_u32(), 0, 0, 0];
                [(cell_of(&event.new_acc), outputs[0].1), (fa, outputs[1].1)]
                    .into_iter()
                    .filter(|&(_, reads)| reads > 0)
                    .map(|(value, _)| value)
            })
            .collect()
    }

    /// How many products the table asks for, fixed by the program: nine per
    /// bit.
    #[must_use]
    pub fn mul_request_count(&self) -> usize {
        EXT_MUL_REQUESTS * self.outputs.len()
    }

    /// The products the table asks for, nine per bit.
    #[must_use]
    pub fn mul_requests(&self, record: &ExecutionRecord<KoalaBear>) -> Vec<(u32, u32)> {
        let mut requests = Vec::with_capacity(self.mul_request_count());
        let mut row = vec![0u8; NUM_PREFIX_SUM_COLS];
        for event in &record.prefix_sum_checks_events {
            fill_row(event, &mut row, &mut requests);
        }
        requests
    }

    /// The witness: every bit's inputs, factor, products and sums; the rows
    /// past the program check a zero bit against a zero coordinate.
    #[must_use]
    pub fn main_table(&self, record: &ExecutionRecord<KoalaBear>) -> Table<F> {
        let events = &record.prefix_sum_checks_events;
        assert_eq!(events.len(), self.outputs.len(), "one event per bit");
        let mut rows = BitRows::new(NUM_PREFIX_SUM_COLS, self.log_height);
        let mut row = vec![0u8; NUM_PREFIX_SUM_COLS];
        let mut requests = Vec::new();
        let padding = padding_event();
        for r in 0..1usize << self.log_height {
            row.fill(0);
            requests.clear();
            fill_row(events.get(r).unwrap_or(&padding), &mut row, &mut requests);
            rows.set_row(r, &row);
        }
        rows.into_table()
    }
}

impl<X: Field> BaseAir<X> for PrefixSumAir {
    fn width(&self) -> usize {
        NUM_PREFIX_SUM_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PREFIX_SUM_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense(&self.preprocessed, NUM_PREFIX_SUM_PREP_COLS))
    }
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for PrefixSumAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &PrefixSumCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep_local: PrefixSumPrep<AB::Var> = *prep.current_slice().borrow();

        for bit in local
            .x1
            .iter()
            .chain(local.x2.iter().flatten())
            .chain(local.acc.iter().flatten())
            .chain(local.factor.iter().flatten())
            .chain(local.fa.iter())
            .chain(local.new_fa.iter())
        {
            builder.assert_bool(*bit);
        }
        for bit in &local.x1[1..] {
            builder.assert_zero(*bit);
        }

        let x2 = ext_exprs::<AB>(&local.x2);
        for (k, (coefficient, cols)) in x2.iter().zip(&local.one_minus).enumerate() {
            eval_sub(builder, &constant_bits::<AB, KB_BITS>(u64::from(k == 0)), coefficient, cols);
        }
        let set: AB::Expr = local.x1[0].into();
        let unset = AB::Expr::ONE + set.clone();
        for k in 0..EXT_DEGREE {
            for i in 0..KB_BITS {
                builder.assert_eq(
                    local.factor[k][i],
                    set.clone() * local.x2[k][i] + unset.clone() * local.one_minus[k].out[i],
                );
            }
        }
        let acc = ext_exprs::<AB>(&local.acc);
        let factor = ext_exprs::<AB>(&local.factor);
        eval_ext_mul(builder, &acc, &factor, &local.mul, prep_local.is_real.into());

        let doubled: [AB::Expr; 32] =
            core::array::from_fn(|i| if i == 0 { set.clone() } else { local.fa[i - 1].into() });
        let diff = sub_chain::<AB, 32>(
            builder,
            &doubled,
            &constant_bits::<AB, 32>(u64::from(KB_PRIME)),
            &local.fa_borrows,
        );
        let below_p: AB::Expr = local.fa_borrows[31].into();
        for i in 0..KB_BITS {
            let pick_doubled = below_p.clone() * (doubled[i].clone() + diff[i].clone());
            builder.assert_zero(diff[i].clone() + pick_doubled + local.new_fa[i].into());
        }
        builder.assert_zero((below_p + AB::Expr::ONE) * diff[31].clone());

        let block = |w: &ExtWord<AB::Var>| -> [AB::Expr; 4 * KB_BITS] {
            core::array::from_fn(|i| w[i / KB_BITS][i % KB_BITS].into())
        };
        let new_acc: [AB::Expr; 4 * KB_BITS] =
            core::array::from_fn(|i| local.mul.out(i / KB_BITS)[i % KB_BITS].into());
        let reads = [
            (&prep_local.addr_x1, single_block::<AB>(&exprs::<AB, KB_BITS>(&local.x1))),
            (&prep_local.addr_x2, block(&local.x2)),
            (&prep_local.addr_acc, block(&local.acc)),
            (&prep_local.addr_fa, single_block::<AB>(&exprs::<AB, KB_BITS>(&local.fa))),
        ];
        for (addr, value) in reads {
            builder.declare_bus(
                MEMORY,
                BusDirection::Pull,
                cell_tuple::<AB>(&exprs::<AB, ADDRESS_BITS>(addr), &value),
                BusActivation::Boolean(prep_local.is_real.into()),
            );
        }
        let writes = [
            (&prep_local.addr_new_acc, new_acc, prep_local.has_acc),
            (
                &prep_local.addr_new_fa,
                single_block::<AB>(&exprs::<AB, KB_BITS>(&local.new_fa)),
                prep_local.has_fa,
            ),
        ];
        for (addr, value, has) in writes {
            builder.declare_bus(
                WRITE,
                BusDirection::Push,
                cell_tuple::<AB>(&exprs::<AB, ADDRESS_BITS>(addr), &value),
                BusActivation::Boolean(has.into()),
            );
        }
    }
}
