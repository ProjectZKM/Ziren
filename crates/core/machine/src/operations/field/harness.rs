use core::{borrow::Borrow, mem::size_of};
use std::fmt::Debug;

use p3_air::{Air, BaseAir};
use p3_field::{Field, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use zkm_core_executor::{events::FieldOperation, ExecutionRecord, Program};
use zkm_curves::{edwards::ed25519::Ed25519BaseField, params::Limbs};
use zkm_derive::{AlignedBorrow, PicusAnnotations};
use zkm_stark::{
    air::{MachineAir, ZKMAirBuilder},
    PicusInfo,
};

use crate::{
    operations::field::{
        field_den::FieldDenCols, field_inner_product::FieldInnerProductCols, field_op::FieldOpCols,
    },
    CoreChipError,
};

#[derive(AlignedBorrow, PicusAnnotations, Debug, Clone)]
#[repr(C)]
pub struct FieldOpHarnessCols<T> {
    pub is_real: T,
    #[picus(input)]
    pub a: Limbs<T, <Ed25519BaseField as zkm_curves::params::NumLimbs>::Limbs>,
    #[picus(input)]
    pub b: Limbs<T, <Ed25519BaseField as zkm_curves::params::NumLimbs>::Limbs>,
    #[picus(output)]
    pub op: FieldOpCols<T, Ed25519BaseField>,
}

#[derive(AlignedBorrow, PicusAnnotations, Debug, Clone)]
#[repr(C)]
pub struct FieldDenHarnessCols<T> {
    pub is_real: T,
    #[picus(input)]
    pub a: Limbs<T, <Ed25519BaseField as zkm_curves::params::NumLimbs>::Limbs>,
    #[picus(input)]
    pub b: Limbs<T, <Ed25519BaseField as zkm_curves::params::NumLimbs>::Limbs>,
    #[picus(output)]
    pub den: FieldDenCols<T, Ed25519BaseField>,
}

#[derive(AlignedBorrow, PicusAnnotations, Debug, Clone)]
#[repr(C)]
pub struct FieldInnerProductHarnessCols<T> {
    pub is_real: T,
    #[picus(input)]
    pub a: [Limbs<T, <Ed25519BaseField as zkm_curves::params::NumLimbs>::Limbs>; 2],
    #[picus(input)]
    pub b: [Limbs<T, <Ed25519BaseField as zkm_curves::params::NumLimbs>::Limbs>; 2],
    #[picus(output)]
    pub inner_product: FieldInnerProductCols<T, Ed25519BaseField>,
}

pub const NUM_FIELD_OP_HARNESS_COLS: usize = size_of::<FieldOpHarnessCols<u8>>();
pub const NUM_FIELD_DEN_HARNESS_COLS: usize = size_of::<FieldDenHarnessCols<u8>>();
pub const NUM_FIELD_INNER_PRODUCT_HARNESS_COLS: usize =
    size_of::<FieldInnerProductHarnessCols<u8>>();

pub struct FieldOpHarnessChip {
    pub operation: FieldOperation,
    pub name: &'static str,
}

impl FieldOpHarnessChip {
    pub const fn new(operation: FieldOperation, name: &'static str) -> Self {
        Self { operation, name }
    }
}

impl<F: PrimeField32> MachineAir<F> for FieldOpHarnessChip {
    type Record = ExecutionRecord;
    type Program = Program;
    type Error = CoreChipError;

    fn name(&self) -> String {
        self.name.to_string()
    }

    fn generate_trace(
        &self,
        _: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        Ok(RowMajorMatrix::new(vec![F::ZERO; NUM_FIELD_OP_HARNESS_COLS], NUM_FIELD_OP_HARNESS_COLS))
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }

    fn local_only(&self) -> bool {
        true
    }

    fn picus_info(&self) -> PicusInfo {
        FieldOpHarnessCols::<u8>::picus_info()
    }
}

impl<F: Field> BaseAir<F> for FieldOpHarnessChip {
    fn width(&self) -> usize {
        NUM_FIELD_OP_HARNESS_COLS
    }
}

impl<AB> Air<AB> for FieldOpHarnessChip
where
    AB: ZKMAirBuilder,
    Limbs<AB::Var, <Ed25519BaseField as zkm_curves::params::NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &FieldOpHarnessCols<AB::Var> = (*local).borrow();
        builder.assert_bool(local.is_real);
        local.op.eval(builder, &local.a, &local.b, self.operation, local.is_real);
    }
}

pub struct FieldDenHarnessChip {
    pub sign: bool,
    pub name: &'static str,
}

impl FieldDenHarnessChip {
    pub const fn new(sign: bool, name: &'static str) -> Self {
        Self { sign, name }
    }
}

impl<F: PrimeField32> MachineAir<F> for FieldDenHarnessChip {
    type Record = ExecutionRecord;
    type Program = Program;
    type Error = CoreChipError;

    fn name(&self) -> String {
        self.name.to_string()
    }

    fn generate_trace(
        &self,
        _: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        Ok(RowMajorMatrix::new(
            vec![F::ZERO; NUM_FIELD_DEN_HARNESS_COLS],
            NUM_FIELD_DEN_HARNESS_COLS,
        ))
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }

    fn local_only(&self) -> bool {
        true
    }

    fn picus_info(&self) -> PicusInfo {
        FieldDenHarnessCols::<u8>::picus_info()
    }
}

impl<F: Field> BaseAir<F> for FieldDenHarnessChip {
    fn width(&self) -> usize {
        NUM_FIELD_DEN_HARNESS_COLS
    }
}

impl<AB> Air<AB> for FieldDenHarnessChip
where
    AB: ZKMAirBuilder,
    Limbs<AB::Var, <Ed25519BaseField as zkm_curves::params::NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &FieldDenHarnessCols<AB::Var> = (*local).borrow();
        builder.assert_bool(local.is_real);
        local.den.eval(builder, &local.a, &local.b, self.sign, local.is_real);
    }
}

pub struct FieldInnerProductHarnessChip {
    pub name: &'static str,
}

impl FieldInnerProductHarnessChip {
    pub const fn new(name: &'static str) -> Self {
        Self { name }
    }
}

impl<F: PrimeField32> MachineAir<F> for FieldInnerProductHarnessChip {
    type Record = ExecutionRecord;
    type Program = Program;
    type Error = CoreChipError;

    fn name(&self) -> String {
        self.name.to_string()
    }

    fn generate_trace(
        &self,
        _: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        Ok(RowMajorMatrix::new(
            vec![F::ZERO; NUM_FIELD_INNER_PRODUCT_HARNESS_COLS],
            NUM_FIELD_INNER_PRODUCT_HARNESS_COLS,
        ))
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }

    fn local_only(&self) -> bool {
        true
    }

    fn picus_info(&self) -> PicusInfo {
        FieldInnerProductHarnessCols::<u8>::picus_info()
    }
}

impl<F: Field> BaseAir<F> for FieldInnerProductHarnessChip {
    fn width(&self) -> usize {
        NUM_FIELD_INNER_PRODUCT_HARNESS_COLS
    }
}

impl<AB> Air<AB> for FieldInnerProductHarnessChip
where
    AB: ZKMAirBuilder,
    Limbs<AB::Var, <Ed25519BaseField as zkm_curves::params::NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &FieldInnerProductHarnessCols<AB::Var> = (*local).borrow();
        builder.assert_bool(local.is_real);
        local.inner_product.eval(builder, &local.a, &local.b, local.is_real);
    }
}
