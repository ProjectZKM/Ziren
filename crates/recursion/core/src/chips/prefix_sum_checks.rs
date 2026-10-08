use core::borrow::Borrow;
use instruction::PrefixSumChecksInstr;
use std::borrow::BorrowMut;

use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use zkm_core_machine::utils::{next_multiple_of_32_rows, pad_rows_exact};
use zkm_derive::AlignedBorrow;
use zkm_pcs::air::{BinomialExtension, MachineAir};

use crate::{builder::ZKMRecursionAirBuilder, *};

/// The jagged verifier's per-column prefix-sum check as a chip.
///
/// For every column the verifier takes the column's prefix-sum bits followed
/// by the next column's (`x1`, most significant bit first) and the sumcheck's
/// reduced point (`x2`, one coordinate per bit), and needs two values:
/// `eq(x1, x2) = prod_i ((1 - x1_i)(1 - x2_i) + x1_i x2_i)`, the Lagrange
/// factor of the jagged evaluation, and the Horner sum of the first half,
/// the column's prefix sum as a felt, which binds the hinted bits to the row
/// counts.  Emitted as generic field arithmetic that was some 580 recursion
/// instructions per column, three fifths of a leaf program; here it is one
/// row per bit: the row receives the bit and the coordinate, carries the two
/// running accumulators in from the previous row's addresses and sends the
/// next ones, and asserts the bit boolean, so no separate booleanity check
/// is needed for the bits it consumes.
///
/// The chip lives in the compress machine only, like `Ext2Felt`: the shrink
/// and wrap machines, and through them the wrap R1CS, are unchanged, and
/// their programs keep emitting the arithmetic.
#[derive(Default, Debug, Clone, Copy)]
pub struct PrefixSumChecksChip;

pub const NUM_PREFIX_SUM_CHECKS_COLS: usize = core::mem::size_of::<PrefixSumChecksCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct PrefixSumChecksCols<F: Copy> {
    /// The bit.
    pub x1: F,
    /// The point coordinate.
    pub x2: Block<F>,
    /// The Lagrange product before this bit.
    pub acc: Block<F>,
    /// The Lagrange product after this bit.
    pub new_acc: Block<F>,
    /// The Horner sum before this bit.
    pub felt_acc: F,
    /// The Horner sum after this bit.
    pub felt_new_acc: F,
}

pub const NUM_PREFIX_SUM_CHECKS_PREPROCESSED_COLS: usize =
    core::mem::size_of::<PrefixSumChecksPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct PrefixSumChecksPreprocessedCols<F: Copy> {
    pub x1_mem: Address<F>,
    pub x2_mem: Address<F>,
    pub acc_addr: Address<F>,
    pub next_acc_addr: Address<F>,
    pub next_acc_mult: F,
    pub felt_acc_addr: Address<F>,
    pub felt_next_acc_addr: Address<F>,
    pub felt_next_acc_mult: F,
    pub is_real: F,
}

impl<F: Send + Sync> BaseAir<F> for PrefixSumChecksChip {
    fn width(&self) -> usize {
        NUM_PREFIX_SUM_CHECKS_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for PrefixSumChecksChip {
    type Record = crate::ExecutionRecord<F>;

    type Program = crate::RecursionProgram<F>;

    type Error = crate::RecursionChipError;

    fn name(&self) -> String {
        "PrefixSumChecks".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PREFIX_SUM_CHECKS_PREPROCESSED_COLS
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        Some(next_multiple_of_32_rows(
            input.prefix_sum_checks_events.len(),
            input.fixed_rows(self),
            <PrefixSumChecksChip as MachineAir<F>>::name(self).as_str(),
        ))
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let instrs: Vec<&PrefixSumChecksInstr<F>> = program
            .iter_instructions()
            .filter_map(|instruction| match instruction {
                Instruction::PrefixSumChecks(instr) => Some(instr.as_ref()),
                _ => None,
            })
            .collect();

        let nb_rows: usize = instrs.iter().map(|instr| instr.addrs.x1.len()).sum();
        let padded_nb_rows = next_multiple_of_32_rows(
            nb_rows,
            program.fixed_rows(self),
            <PrefixSumChecksChip as MachineAir<F>>::name(self).as_str(),
        );
        let mut values = vec![F::ZERO; padded_nb_rows * NUM_PREFIX_SUM_CHECKS_PREPROCESSED_COLS];

        let mut row = 0usize;
        for instr in instrs {
            let PrefixSumChecksInstr { addrs, acc_mults, field_acc_mults } = instr;
            for i in 0..addrs.x1.len() {
                let start = row * NUM_PREFIX_SUM_CHECKS_PREPROCESSED_COLS;
                let cols: &mut PrefixSumChecksPreprocessedCols<F> =
                    values[start..start + NUM_PREFIX_SUM_CHECKS_PREPROCESSED_COLS].borrow_mut();
                // The first row of a chain reads the seeds; every later row reads
                // the previous row's outputs.
                if i == 0 {
                    cols.acc_addr = addrs.one;
                    cols.felt_acc_addr = addrs.zero;
                } else {
                    cols.acc_addr = addrs.accs[i - 1];
                    cols.felt_acc_addr = addrs.field_accs[i - 1];
                }
                cols.x1_mem = addrs.x1[i];
                cols.x2_mem = addrs.x2[i];
                cols.next_acc_addr = addrs.accs[i];
                cols.next_acc_mult = acc_mults[i];
                cols.felt_next_acc_addr = addrs.field_accs[i];
                cols.felt_next_acc_mult = field_acc_mults[i];
                cols.is_real = F::ONE;
                row += 1;
            }
        }

        Some(RowMajorMatrix::new(values, NUM_PREFIX_SUM_CHECKS_PREPROCESSED_COLS))
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
            .prefix_sum_checks_events
            .par_iter()
            .map(|event| {
                let mut row = [F::ZERO; NUM_PREFIX_SUM_CHECKS_COLS];
                let cols: &mut PrefixSumChecksCols<_> = row.as_mut_slice().borrow_mut();
                cols.x1 = event.x1;
                cols.x2 = event.x2;
                cols.acc = event.acc;
                cols.new_acc = event.new_acc;
                cols.felt_acc = event.field_acc;
                cols.felt_new_acc = event.new_field_acc;
                row
            })
            .collect::<Vec<_>>();

        pad_rows_exact(
            &mut rows,
            || [F::ZERO; NUM_PREFIX_SUM_CHECKS_COLS],
            input.fixed_rows(self),
            <PrefixSumChecksChip as MachineAir<F>>::name(self).as_str(),
        );

        Ok(RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_PREFIX_SUM_CHECKS_COLS,
        ))
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB> Air<AB> for PrefixSumChecksChip
where
    AB: ZKMRecursionAirBuilder,
    AB::Var: 'static,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &PrefixSumChecksCols<AB::Var> = (*local).borrow();
        let prep = builder.preprocessed().clone();
        let prep_local = prep.current_slice();
        let prep_local: &PrefixSumChecksPreprocessedCols<AB::Var> = (*prep_local).borrow();

        let x1: BinomialExtension<AB::Expr> = BinomialExtension::from_base(local.x1.into());
        let x2 = local.x2.as_extension::<AB>();
        let one: BinomialExtension<AB::Expr> = BinomialExtension::from_base(AB::Expr::ONE);
        let two = AB::Expr::TWO;
        let prod = x1.clone() * x2.clone();
        let sum = x1 + x2;

        builder.assert_bool(prep_local.is_real);
        // The bit is boolean: this is the booleanity check of every prefix-sum
        // bit the program hands the chip.
        builder.assert_bool(local.x1);

        builder.receive_single(prep_local.x1_mem, local.x1, prep_local.is_real);
        builder.receive_block(prep_local.x2_mem, local.x2, prep_local.is_real);
        builder.receive_block(prep_local.acc_addr, local.acc, prep_local.is_real);
        builder.receive_single(prep_local.felt_acc_addr, local.felt_acc, prep_local.is_real);

        // eq(x1, x2) = (1 - x1)(1 - x2) + x1 x2 = 1 - x1 - x2 + 2 x1 x2
        builder.assert_ext_eq(
            local.new_acc.as_extension::<AB>(),
            local.acc.as_extension::<AB>() * (one - sum + prod.clone() + prod),
        );
        builder.assert_eq(local.felt_new_acc, local.x1 + two * local.felt_acc);

        builder.send_block(prep_local.next_acc_addr, local.new_acc, prep_local.next_acc_mult);
        builder.send_single(
            prep_local.felt_next_acc_addr,
            local.felt_new_acc,
            prep_local.felt_next_acc_mult,
        );
    }
}

#[cfg(test)]
mod tests {
    use machine::tests::run_recursion_test_machines;
    use p3_field::{extension::BinomialExtensionField, BasedVectorSpace, PrimeCharacteristicRing};
    use p3_koala_bear::KoalaBear;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;
    use crate::runtime::instruction as instr;

    type F = KoalaBear;
    type EF = BinomialExtensionField<KoalaBear, D>;

    /// Random bit vectors against random points, each chain checked against
    /// the host's Lagrange product and Horner sum at the chain's end.
    #[test]
    fn prove_prefix_sum_checks() {
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut addr = 0u32;
        let instructions = (0..200)
            .flat_map(|_| {
                let len = 2 * rng.gen_range(1..=8usize);
                let bits: Vec<F> = (0..len).map(|_| F::from_bool(rng.gen_bool(0.5))).collect();
                let point: Vec<EF> = (0..len)
                    .map(|_| {
                        EF::from_basis_coefficients_fn(|_| F::from_u64(rng.gen::<u64>()))
                    })
                    .collect();
                let mut acc = EF::ONE;
                let mut felt_acc = F::ZERO;
                let mut mid_felt = F::ZERO;
                for (i, (&b, &p)) in bits.iter().zip(point.iter()).enumerate() {
                    let prod = p * b;
                    acc *= EF::ONE - b - p + prod + prod;
                    felt_acc = b + felt_acc * F::TWO;
                    if i + 1 == len / 2 {
                        mid_felt = felt_acc;
                    }
                }
                let base = addr;
                // layout: bits [0, len), point [len, 2len), zero, one, accs
                // [2len+2, 3len+2), field accs [3len+2, 4len+2)
                let l = len as u32;
                addr += 4 * l + 2;
                let mut v: Vec<Instruction<F>> = Vec::new();
                for (i, &b) in bits.iter().enumerate() {
                    v.push(instr::mem_single(MemAccessKind::Write, 1, base + i as u32, b));
                }
                for (i, &p) in point.iter().enumerate() {
                    v.push(instr::mem_ext(MemAccessKind::Write, 1, base + l + i as u32, p));
                }
                v.push(instr::mem_single(MemAccessKind::Write, 1, base + 2 * l, F::ZERO));
                v.push(instr::mem_ext(MemAccessKind::Write, 1, base + 2 * l + 1, EF::ONE));
                let accs: Vec<u32> = (0..l).map(|i| base + 2 * l + 2 + i).collect();
                let faccs: Vec<u32> = (0..l).map(|i| base + 3 * l + 2 + i).collect();
                // every chain value is read by the next row; the last Lagrange
                // product and the midpoint Horner sum also by the checks below,
                // and the last Horner sum by nobody
                let acc_mults = vec![1u32; len];
                let mut facc_mults = vec![1u32; len];
                facc_mults[len - 1] = 0;
                facc_mults[len / 2 - 1] += 1;
                v.push(instr::prefix_sum_checks(
                    acc_mults,
                    facc_mults,
                    (0..l).map(|i| base + i).collect(),
                    (0..l).map(|i| base + l + i).collect(),
                    base + 2 * l,
                    base + 2 * l + 1,
                    accs.clone(),
                    faccs.clone(),
                ));
                v.push(instr::mem_ext(MemAccessKind::Read, 1, accs[len - 1], acc));
                v.push(instr::mem_single(MemAccessKind::Read, 1, faccs[len / 2 - 1], mid_felt));
                v
            })
            .collect::<Vec<Instruction<F>>>();

        let program = RecursionProgram::new(
            crate::RawProgram::from_linear(instructions),
            0,
            Vec::new(),
            None,
        );
        run_recursion_test_machines(program);
    }
}
