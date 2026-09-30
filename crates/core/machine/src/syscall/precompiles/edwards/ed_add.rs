use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use std::{fmt::Debug, marker::PhantomData};
use zkm_derive::PicusAnnotations;
use zkm_pcs::PicusInfo;

use itertools::Itertools;
use num::BigUint;

use crate::{air::MemoryAirBuilder, CoreChipError};
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{IntoParallelRefIterator, ParallelIterator, ParallelSlice};
use zkm_core_executor::{
    events::{ByteRecord, EllipticCurveAddEvent, FieldOperation, PrecompileEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use zkm_curves::{
    edwards::{ed25519::Ed25519BaseField, EdwardsParameters, NUM_LIMBS, WORDS_CURVE_POINT},
    params::{limbs_from_vec, FieldParameters, Limbs, NumLimbs},
    AffinePoint, EllipticCurve,
};
use zkm_derive::AlignedBorrow;
use zkm_pcs::air::{BaseAirBuilder, LookupScope, MachineAir, ZKMAirBuilder};

use crate::{
    memory::{value_as_limbs, MemoryReadCols, MemoryWriteCols},
    operations::field::{
        field_den::FieldDenCols, field_inner_product::FieldInnerProductCols, field_op::FieldOpCols,
        range::FieldLtCols,
    },
    utils::{limbs_from_prev_access, pad_rows_fixed},
};

pub const NUM_ED_ADD_COLS: usize = size_of::<EdAddAssignCols<u8>>();

/// A set of columns to compute `EdAdd` where a, b are field elements.
/// Right now the number of limbs is assumed to be a constant, although this could be macro-ed
/// or made generic in the future.
#[derive(PicusAnnotations, Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct EdAddAssignCols<T> {
    pub is_real: T,
    pub shard: T,
    pub clk: T,
    pub p_ptr: T,
    pub q_ptr: T,
    pub p_access: [MemoryWriteCols<T>; WORDS_CURVE_POINT],
    pub q_access: [MemoryReadCols<T>; WORDS_CURVE_POINT],
    pub(crate) x3_numerator: FieldInnerProductCols<T, Ed25519BaseField>,
    pub(crate) y3_numerator: FieldInnerProductCols<T, Ed25519BaseField>,
    pub(crate) x1_mul_y1: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) x2_mul_y2: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) f: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) d_mul_f: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) x3_ins: FieldDenCols<T, Ed25519BaseField>,
    pub(crate) y3_ins: FieldDenCols<T, Ed25519BaseField>,
    pub(crate) x3_range: FieldLtCols<T, Ed25519BaseField>,
    pub(crate) y3_range: FieldLtCols<T, Ed25519BaseField>,
}

#[derive(Default)]
pub struct EdAddAssignChip<E> {
    _marker: PhantomData<E>,
}

impl<E: EllipticCurve + EdwardsParameters> EdAddAssignChip<E> {
    pub const fn new() -> Self {
        Self { _marker: PhantomData }
    }

    #[allow(clippy::too_many_arguments)]
    fn populate_field_ops<F: PrimeField32>(
        record: &mut impl ByteRecord,
        cols: &mut EdAddAssignCols<F>,
        p_x: BigUint,
        p_y: BigUint,
        q_x: BigUint,
        q_y: BigUint,
    ) {
        let x3_numerator = cols.x3_numerator.populate(
            record,
            &[p_x.clone(), q_x.clone()],
            &[q_y.clone(), p_y.clone()],
        );
        let y3_numerator = cols.y3_numerator.populate(
            record,
            &[p_y.clone(), p_x.clone()],
            &[q_y.clone(), q_x.clone()],
        );
        let x1_mul_y1 = cols.x1_mul_y1.populate(record, &p_x, &p_y, FieldOperation::Mul);
        let x2_mul_y2 = cols.x2_mul_y2.populate(record, &q_x, &q_y, FieldOperation::Mul);
        let f = cols.f.populate(record, &x1_mul_y1, &x2_mul_y2, FieldOperation::Mul);

        let d = E::d_biguint();
        let d_mul_f = cols.d_mul_f.populate(record, &f, &d, FieldOperation::Mul);

        let x3 = cols.x3_ins.populate(record, &x3_numerator, &d_mul_f, true);
        let y3 = cols.y3_ins.populate(record, &y3_numerator, &d_mul_f, false);
        cols.x3_range.populate(record, &x3, &Ed25519BaseField::modulus());
        cols.y3_range.populate(record, &y3, &Ed25519BaseField::modulus());
    }
}

impl<F: PrimeField32, E: EllipticCurve + EdwardsParameters> MachineAir<F> for EdAddAssignChip<E> {
    type Record = ExecutionRecord;

    type Program = Program;

    type Error = CoreChipError;

    fn name(&self) -> String {
        "EdAddAssign".to_string()
    }

    fn picus_info(&self) -> PicusInfo {
        EdAddAssignCols::<u8>::picus_info()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        let events = input.get_precompile_events(SyscallCode::ED_ADD);

        let mut rows = events
            .par_iter()
            .map(|(_, event)| {
                let event = if let PrecompileEvent::EdAdd(event) = event {
                    event
                } else {
                    unreachable!();
                };

                let mut row = [F::ZERO; NUM_ED_ADD_COLS];
                let cols: &mut EdAddAssignCols<F> = row.as_mut_slice().borrow_mut();
                let mut blu = Vec::new();
                self.event_to_row(event, cols, &mut blu);
                row
            })
            .collect::<Vec<_>>();

        pad_rows_fixed(
            &mut rows,
            || {
                let mut row = [F::ZERO; NUM_ED_ADD_COLS];
                let cols: &mut EdAddAssignCols<F> = row.as_mut_slice().borrow_mut();
                let zero = BigUint::ZERO;
                Self::populate_field_ops(
                    &mut vec![],
                    cols,
                    zero.clone(),
                    zero.clone(),
                    zero.clone(),
                    zero,
                );
                row
            },
            input.fixed_log2_rows::<F, _>(self),
            <EdAddAssignChip<E> as MachineAir<F>>::name(self).as_str(),
        );

        Ok(RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_ED_ADD_COLS))
    }

    fn generate_dependencies(
        &self,
        input: &Self::Record,
        output: &mut Self::Record,
    ) -> Result<(), Self::Error> {
        let events = input.get_precompile_events(SyscallCode::ED_ADD);
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_batches = events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: zkm_core_executor::events::ByteLookupMap = Default::default();
                events.iter().for_each(|(_, event)| {
                    let event = if let PrecompileEvent::EdAdd(event) = event {
                        event
                    } else {
                        unreachable!();
                    };

                    let mut row = [F::ZERO; NUM_ED_ADD_COLS];
                    let cols: &mut EdAddAssignCols<F> = row.as_mut_slice().borrow_mut();
                    self.event_to_row(event, cols, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
        Ok(())
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::ED_ADD).is_empty()
        }
    }
}

impl<E: EllipticCurve + EdwardsParameters> EdAddAssignChip<E> {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &EllipticCurveAddEvent,
        cols: &mut EdAddAssignCols<F>,
        blu: &mut impl ByteRecord,
    ) {
        let p = &event.p;
        let q = &event.q;
        let p = AffinePoint::<E>::from_words_le(p);
        let (p_x, p_y) = (p.x, p.y);
        let q = AffinePoint::<E>::from_words_le(q);
        let (q_x, q_y) = (q.x, q.y);

        cols.is_real = F::ONE;
        cols.shard = F::from_u32(event.shard);
        cols.clk = F::from_u32(event.clk);
        cols.p_ptr = F::from_u32(event.p_ptr);
        cols.q_ptr = F::from_u32(event.q_ptr);

        Self::populate_field_ops(blu, cols, p_x, p_y, q_x, q_y);

        for i in 0..WORDS_CURVE_POINT {
            cols.q_access[i].populate(event.q_memory_records[i], blu);
        }
        for i in 0..WORDS_CURVE_POINT {
            cols.p_access[i].populate(event.p_memory_records[i], blu);
        }
    }
}

impl<F, E: EllipticCurve + EdwardsParameters> BaseAir<F> for EdAddAssignChip<E> {
    fn width(&self) -> usize {
        NUM_ED_ADD_COLS
    }
}

impl<AB, E: EllipticCurve + EdwardsParameters> Air<AB> for EdAddAssignChip<E>
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &EdAddAssignCols<AB::Var> = (*local).borrow();

        let x1: Limbs<AB::Var, <Ed25519BaseField as NumLimbs>::Limbs> =
            limbs_from_prev_access(&local.p_access[0..8]);
        let x2: Limbs<AB::Var, <Ed25519BaseField as NumLimbs>::Limbs> =
            limbs_from_prev_access(&local.q_access[0..8]);
        let y1: Limbs<AB::Var, <Ed25519BaseField as NumLimbs>::Limbs> =
            limbs_from_prev_access(&local.p_access[8..16]);
        let y2: Limbs<AB::Var, <Ed25519BaseField as NumLimbs>::Limbs> =
            limbs_from_prev_access(&local.q_access[8..16]);

        local.x3_numerator.eval(builder, &[x1, x2], &[y2, y1], local.is_real);

        local.y3_numerator.eval(builder, &[y1, x1], &[y2, x2], local.is_real);

        local.x1_mul_y1.eval(builder, &x1, &y1, FieldOperation::Mul, local.is_real);
        local.x2_mul_y2.eval(builder, &x2, &y2, FieldOperation::Mul, local.is_real);

        let x1_mul_y1 = local.x1_mul_y1.result;
        let x2_mul_y2 = local.x2_mul_y2.result;
        local.f.eval(builder, &x1_mul_y1, &x2_mul_y2, FieldOperation::Mul, local.is_real);

        let f = local.f.result;
        let d_biguint = E::d_biguint();
        let d_const = E::BaseField::to_limbs_field::<AB::Expr, AB::F>(&d_biguint);
        local.d_mul_f.eval(builder, &f, &d_const, FieldOperation::Mul, local.is_real);

        let d_mul_f = local.d_mul_f.result;

        local.x3_ins.eval(builder, &local.x3_numerator.result, &d_mul_f, true, local.is_real);

        local.y3_ins.eval(builder, &local.y3_numerator.result, &d_mul_f, false, local.is_real);

        let modulus = limbs_from_vec::<AB::Expr, <Ed25519BaseField as NumLimbs>::Limbs, AB::F>(
            Ed25519BaseField::to_limbs_field_vec(&Ed25519BaseField::modulus()),
        );
        local.x3_range.eval(builder, &local.x3_ins.result, &modulus, local.is_real);
        local.y3_range.eval(builder, &local.y3_ins.result, &modulus, local.is_real);

        let p_access_vec = value_as_limbs(&local.p_access);
        builder
            .when(local.is_real)
            .assert_all_eq(local.x3_ins.result, p_access_vec[0..NUM_LIMBS].to_vec());
        builder
            .when(local.is_real)
            .assert_all_eq(local.y3_ins.result, p_access_vec[NUM_LIMBS..NUM_LIMBS * 2].to_vec());

        builder.eval_memory_access_slice(
            local.shard,
            local.clk.into(),
            local.q_ptr,
            &local.q_access,
            local.is_real,
        );

        builder.eval_memory_access_slice(
            local.shard,
            local.clk + AB::F::from_u32(1),
            local.p_ptr,
            &local.p_access,
            local.is_real,
        );

        builder.receive_syscall(
            local.shard,
            local.clk,
            AB::F::from_u32(SyscallCode::ED_ADD.syscall_id()),
            local.p_ptr,
            local.q_ptr,
            local.is_real,
            LookupScope::Local,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;
    use p3_field::extension::BinomialExtensionField;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::Matrix;
    use test_artifacts::{ED25519_ELF, ED_ADD_ELF};
    use zkm_core_executor::{ExecutionRecord, Executor, Program};
    use zkm_curves::edwards::{ed25519::Ed25519Parameters, EdwardsCurve};
    use zkm_pcs::{constraints_hold_on_row, CpuProver, ZKMCoreOpts};

    #[test]
    pub fn test_ed_add_program_execute() {
        utils::setup_logger();
        let program = Program::from(ED_ADD_ELF).unwrap();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
    }

    #[test]
    fn test_ed_add_simple() {
        utils::setup_logger();
        let program = Program::from(ED_ADD_ELF).unwrap();
        utils::run_test::<CpuProver<_, _>>(program).unwrap();
    }

    fn limbs_to_biguint<F: PrimeField32>(limbs: &[F]) -> BigUint {
        BigUint::from_bytes_le(&limbs.iter().map(|x| x.as_canonical_u32() as u8).collect_vec())
    }

    /// The division gadget and the binding to memory alone accept a coordinate `c + p`.
    struct DivisionAndBindingOnly;

    impl<F> BaseAir<F> for DivisionAndBindingOnly {
        fn width(&self) -> usize {
            NUM_ED_ADD_COLS
        }
    }

    impl<AB: ZKMAirBuilder> Air<AB> for DivisionAndBindingOnly {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.current_slice();
            let local: &EdAddAssignCols<AB::Var> = (*local).borrow();
            let d_mul_f = local.d_mul_f.result;
            local.x3_ins.eval(builder, &local.x3_numerator.result, &d_mul_f, true, local.is_real);
            local.y3_ins.eval(builder, &local.y3_numerator.result, &d_mul_f, false, local.is_real);
            let p_access_vec = value_as_limbs(&local.p_access);
            builder
                .when(local.is_real)
                .assert_all_eq(local.x3_ins.result, p_access_vec[0..NUM_LIMBS].to_vec());
            builder.when(local.is_real).assert_all_eq(
                local.y3_ins.result,
                p_access_vec[NUM_LIMBS..NUM_LIMBS * 2].to_vec(),
            );
        }
    }

    #[test]
    fn non_canonical_sum_is_rejected() {
        type F = KoalaBear;
        type EF = BinomialExtensionField<KoalaBear, 4>;
        utils::setup_logger();
        let program = Program::from(ED_ADD_ELF).unwrap();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        let record = runtime
            .records
            .iter()
            .find(|r| !r.get_precompile_events(SyscallCode::ED_ADD).is_empty())
            .expect("an ED_ADD event");
        let chip = EdAddAssignChip::<EdwardsCurve<Ed25519Parameters>>::new();
        let trace: RowMajorMatrix<F> =
            chip.generate_trace(record, &mut ExecutionRecord::default()).unwrap();
        let honest: Vec<F> = trace.row_slice(0).unwrap().to_vec();
        assert!(constraints_hold_on_row::<F, EF, _>(&chip, &honest, &honest, &[]));

        let p = Ed25519BaseField::modulus();
        for coordinate in 0..2 {
            let mut row = honest.clone();
            let cols: &mut EdAddAssignCols<F> = row.as_mut_slice().borrow_mut();
            let b = limbs_to_biguint(&cols.d_mul_f.result.0);
            let sign = coordinate == 0;
            let (a, ins) = if sign {
                (limbs_to_biguint(&cols.x3_numerator.result.0), &mut cols.x3_ins)
            } else {
                (limbs_to_biguint(&cols.y3_numerator.result.0), &mut cols.y3_ins)
            };
            let forged = limbs_to_biguint(&ins.result.0) + &p;
            assert!(forged.bits() <= 256);
            ins.populate_with_result(&mut Vec::new(), &a, &b, sign, &forged);
            let limbs = Ed25519BaseField::to_limbs_field::<F, _>(&forged);
            for (i, limb) in limbs.0.iter().enumerate() {
                cols.p_access[coordinate * 8 + i / 4].access.value.0[i % 4] = *limb;
            }
            assert!(
                constraints_hold_on_row::<F, EF, _>(&DivisionAndBindingOnly, &row, &row, &[]),
                "coordinate {coordinate}: the forged row must pass the division and binding"
            );
            assert!(
                !constraints_hold_on_row::<F, EF, _>(&chip, &row, &row, &[]),
                "coordinate {coordinate}: the chip must reject a coordinate of p or more"
            );
        }
    }

    #[test]
    fn test_ed25519_program() {
        utils::setup_logger();
        let program = Program::from(ED25519_ELF).unwrap();
        utils::run_test::<CpuProver<_, _>>(program).unwrap();
    }
}
