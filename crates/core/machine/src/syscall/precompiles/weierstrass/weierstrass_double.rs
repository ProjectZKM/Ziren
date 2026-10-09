use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use std::{fmt::Debug, marker::PhantomData};
use zkm_derive::PicusAnnotations;
use zkm_pcs::PicusInfo;

use crate::{
    air::MemoryAirBuilder,
    utils::{next_multiple_of_32, zeroed_f_vec},
    CoreChipError,
};
use generic_array::GenericArray;
use num::{BigUint, One};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator, ParallelSlice};
use zkm_core_executor::{
    events::{
        ByteLookupEvent, ByteRecord, EllipticCurveDoubleEvent, FieldOperation, MemoryWriteRecord,
        PrecompileEvent, SyscallEvent,
    },
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use zkm_curves::{
    params::{limbs_from_vec, FieldParameters, Limbs, NumLimbs, NumWords},
    weierstrass::WeierstrassParameters,
    AffinePoint, CurveType, EllipticCurve,
};
use zkm_derive::AlignedBorrow;
use zkm_pcs::air::{LookupScope, MachineAir, Polynomial, ZKMAirBuilder};

use crate::{
    memory::{MemoryCols, MemoryWriteCols},
    operations::field::{field_op::FieldOpCols, range::FieldLtCols},
    utils::limbs_from_prev_access,
};

pub const fn num_weierstrass_double_cols<P: FieldParameters + NumWords>() -> usize {
    size_of::<WeierstrassDoubleAssignCols<u8, P>>()
}

/// A set of columns to double a point on a Weierstrass curve.
///
/// Right now the number of limbs is assumed to be a constant, although this could be macro-ed or
/// made generic in the future.
#[derive(PicusAnnotations, Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct WeierstrassDoubleAssignCols<T, P: FieldParameters + NumWords> {
    pub is_real: T,
    pub shard: T,
    pub clk: T,
    pub p_ptr: T,
    pub p_access: GenericArray<MemoryWriteCols<T>, P::WordsCurvePoint>,
    pub(crate) slope_denominator: FieldOpCols<T, P>,
    pub(crate) slope_numerator: FieldOpCols<T, P>,
    pub(crate) slope: FieldOpCols<T, P>,
    pub(crate) p_x_squared: FieldOpCols<T, P>,
    pub(crate) p_x_squared_times_3: FieldOpCols<T, P>,
    pub(crate) slope_squared: FieldOpCols<T, P>,
    pub(crate) p_x_plus_p_x: FieldOpCols<T, P>,
    pub(crate) x3_ins: FieldOpCols<T, P>,
    pub(crate) p_x_minus_x: FieldOpCols<T, P>,
    pub(crate) y3_ins: FieldOpCols<T, P>,
    pub(crate) slope_times_p_x_minus_x: FieldOpCols<T, P>,
    pub(crate) x3_range: FieldLtCols<T, P>,
    pub(crate) y3_range: FieldLtCols<T, P>,
    pub(crate) inverse_check: FieldOpCols<T, P>,
}

#[derive(Default)]
pub struct WeierstrassDoubleAssignChip<E> {
    _marker: PhantomData<E>,
}

impl<E: EllipticCurve + WeierstrassParameters> WeierstrassDoubleAssignChip<E> {
    pub const fn new() -> Self {
        Self { _marker: PhantomData }
    }

    fn populate_field_ops<F: PrimeField32>(
        blu_events: &mut Vec<ByteLookupEvent>,
        cols: &mut WeierstrassDoubleAssignCols<F, E::BaseField>,
        p_x: BigUint,
        p_y: BigUint,
        is_real: bool,
    ) {
        let a = E::a_int();
        let slope = {
            let slope_numerator = {
                let p_x_squared =
                    cols.p_x_squared.populate(blu_events, &p_x, &p_x, FieldOperation::Mul);
                let p_x_squared_times_3 = cols.p_x_squared_times_3.populate(
                    blu_events,
                    &p_x_squared,
                    &BigUint::from(3u32),
                    FieldOperation::Mul,
                );
                cols.slope_numerator.populate(
                    blu_events,
                    &a,
                    &p_x_squared_times_3,
                    FieldOperation::Add,
                )
            };

            let slope_denominator = cols.slope_denominator.populate(
                blu_events,
                &BigUint::from(2u32),
                &p_y,
                FieldOperation::Mul,
            );
            let numerator = if is_real && slope_denominator != BigUint::ZERO {
                BigUint::one()
            } else {
                BigUint::ZERO
            };
            cols.inverse_check.populate(
                blu_events,
                &numerator,
                &slope_denominator,
                FieldOperation::Div,
            );

            cols.slope.populate(
                blu_events,
                &slope_numerator,
                &slope_denominator,
                FieldOperation::Div,
            )
        };

        let x = {
            let slope_squared =
                cols.slope_squared.populate(blu_events, &slope, &slope, FieldOperation::Mul);
            let p_x_plus_p_x =
                cols.p_x_plus_p_x.populate(blu_events, &p_x, &p_x, FieldOperation::Add);
            cols.x3_ins.populate(blu_events, &slope_squared, &p_x_plus_p_x, FieldOperation::Sub)
        };

        let y = {
            let p_x_minus_x = cols.p_x_minus_x.populate(blu_events, &p_x, &x, FieldOperation::Sub);
            let slope_times_p_x_minus_x = cols.slope_times_p_x_minus_x.populate(
                blu_events,
                &slope,
                &p_x_minus_x,
                FieldOperation::Mul,
            );
            cols.y3_ins.populate(blu_events, &slope_times_p_x_minus_x, &p_y, FieldOperation::Sub)
        };

        let modulus = E::BaseField::modulus();
        cols.x3_range.populate(blu_events, &x, &modulus);
        cols.y3_range.populate(blu_events, &y, &modulus);
    }
}

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters> MachineAir<F>
    for WeierstrassDoubleAssignChip<E>
{
    type Record = ExecutionRecord;
    type Program = Program;
    type Error = CoreChipError;

    fn name(&self) -> String {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => "Secp256k1DoubleAssign".to_string(),
            CurveType::Secp256r1 => "Secp256r1DoubleAssign".to_string(),
            CurveType::Bn254 => "Bn254DoubleAssign".to_string(),
            CurveType::Bls12381 => "Bls12381DoubleAssign".to_string(),
            _ => panic!("Unsupported curve"),
        }
    }

    fn picus_info(&self) -> PicusInfo {
        WeierstrassDoubleAssignCols::<u8, E::BaseField>::picus_info()
    }

    fn generate_dependencies(
        &self,
        input: &Self::Record,
        output: &mut Self::Record,
    ) -> Result<(), Self::Error> {
        let events = match E::CURVE_TYPE {
            CurveType::Secp256k1 => &input.get_precompile_events(SyscallCode::SECP256K1_DOUBLE),
            CurveType::Secp256r1 => &input.get_precompile_events(SyscallCode::SECP256R1_DOUBLE),
            CurveType::Bn254 => &input.get_precompile_events(SyscallCode::BN254_DOUBLE),
            CurveType::Bls12381 => &input.get_precompile_events(SyscallCode::BLS12381_DOUBLE),
            _ => panic!("Unsupported curve"),
        };

        let num_cols = num_weierstrass_double_cols::<E::BaseField>();
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_events: Vec<Vec<ByteLookupEvent>> = events
            .par_chunks(chunk_size)
            .map(|ops: &[(SyscallEvent, PrecompileEvent)]| {
                let mut blu = Vec::new();
                ops.iter().for_each(|(_, op)| match op {
                    PrecompileEvent::Secp256k1Double(event)
                    | PrecompileEvent::Secp256r1Double(event)
                    | PrecompileEvent::Bn254Double(event)
                    | PrecompileEvent::Bls12381Double(event) => {
                        let mut row = zeroed_f_vec(num_cols);
                        let cols: &mut WeierstrassDoubleAssignCols<F, E::BaseField> =
                            row.as_mut_slice().borrow_mut();
                        Self::populate_row(event, cols, &mut blu);
                    }
                    _ => unreachable!(),
                });
                blu
            })
            .collect();

        for blu in blu_events {
            output.add_byte_lookup_events(blu);
        }
        Ok(())
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        let events = match E::CURVE_TYPE {
            CurveType::Secp256k1 => input.get_precompile_events(SyscallCode::SECP256K1_DOUBLE),
            CurveType::Secp256r1 => input.get_precompile_events(SyscallCode::SECP256R1_DOUBLE),
            CurveType::Bn254 => input.get_precompile_events(SyscallCode::BN254_DOUBLE),
            CurveType::Bls12381 => input.get_precompile_events(SyscallCode::BLS12381_DOUBLE),
            _ => panic!("Unsupported curve"),
        };

        let num_cols = num_weierstrass_double_cols::<E::BaseField>();
        let num_rows = next_multiple_of_32(
            events.len(),
            input.fixed_log2_rows::<F, _>(self),
            <Self as MachineAir<F>>::name(self).as_str(),
        );
        let mut values = zeroed_f_vec(num_rows * num_cols);
        let chunk_size = 64;

        let num_words_field_element = E::BaseField::NB_LIMBS / 4;
        let mut dummy_row = zeroed_f_vec(num_cols);
        let cols: &mut WeierstrassDoubleAssignCols<F, E::BaseField> =
            dummy_row.as_mut_slice().borrow_mut();
        let dummy_memory_record = MemoryWriteRecord {
            value: 1,
            shard: 0,
            timestamp: 1,
            prev_value: 1,
            prev_shard: 0,
            prev_timestamp: 0,
        };
        let zero = BigUint::ZERO;
        let one = BigUint::one();
        cols.p_access[num_words_field_element].populate(dummy_memory_record, &mut vec![]);
        Self::populate_field_ops(&mut vec![], cols, zero, one, false);

        values.chunks_mut(chunk_size * num_cols).enumerate().par_bridge().for_each(|(i, rows)| {
            rows.chunks_mut(num_cols).enumerate().for_each(|(j, row)| {
                let idx = i * chunk_size + j;
                if idx < events.len() {
                    let mut new_byte_lookup_events = Vec::new();
                    let cols: &mut WeierstrassDoubleAssignCols<F, E::BaseField> = row.borrow_mut();
                    match &events[idx].1 {
                        PrecompileEvent::Secp256k1Double(event)
                        | PrecompileEvent::Secp256r1Double(event)
                        | PrecompileEvent::Bn254Double(event)
                        | PrecompileEvent::Bls12381Double(event) => {
                            Self::populate_row(event, cols, &mut new_byte_lookup_events);
                        }
                        _ => unreachable!(),
                    }
                } else {
                    row.copy_from_slice(&dummy_row);
                }
            });
        });

        Ok(RowMajorMatrix::new(values, num_weierstrass_double_cols::<E::BaseField>()))
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match E::CURVE_TYPE {
                CurveType::Secp256k1 => {
                    !shard.get_precompile_events(SyscallCode::SECP256K1_DOUBLE).is_empty()
                }
                CurveType::Secp256r1 => {
                    !shard.get_precompile_events(SyscallCode::SECP256R1_DOUBLE).is_empty()
                }
                CurveType::Bn254 => {
                    !shard.get_precompile_events(SyscallCode::BN254_DOUBLE).is_empty()
                }
                CurveType::Bls12381 => {
                    !shard.get_precompile_events(SyscallCode::BLS12381_DOUBLE).is_empty()
                }
                _ => panic!("Unsupported curve"),
            }
        }
    }
}

impl<E: EllipticCurve + WeierstrassParameters> WeierstrassDoubleAssignChip<E> {
    pub fn populate_row<F: PrimeField32>(
        event: &EllipticCurveDoubleEvent,
        cols: &mut WeierstrassDoubleAssignCols<F, E::BaseField>,
        new_byte_lookup_events: &mut Vec<ByteLookupEvent>,
    ) {
        let p = &event.p;
        let p = AffinePoint::<E>::from_words_le(p);
        let (p_x, p_y) = (p.x, p.y);

        cols.is_real = F::ONE;
        cols.shard = F::from_u32(event.shard);
        cols.clk = F::from_u32(event.clk);
        cols.p_ptr = F::from_u32(event.p_ptr);

        Self::populate_field_ops(new_byte_lookup_events, cols, p_x, p_y, true);

        for i in 0..cols.p_access.len() {
            cols.p_access[i].populate(event.p_memory_records[i], new_byte_lookup_events);
        }
    }
}

impl<F, E: EllipticCurve + WeierstrassParameters> BaseAir<F> for WeierstrassDoubleAssignChip<E> {
    fn width(&self) -> usize {
        num_weierstrass_double_cols::<E::BaseField>()
    }
}

impl<AB, E: EllipticCurve + WeierstrassParameters> Air<AB> for WeierstrassDoubleAssignChip<E>
where
    AB: ZKMAirBuilder,
    Limbs<AB::Var, <E::BaseField as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &WeierstrassDoubleAssignCols<AB::Var, E::BaseField> = (*local).borrow();

        let num_words_field_element = E::BaseField::NB_LIMBS / 4;
        let p_x = limbs_from_prev_access(&local.p_access[0..num_words_field_element]);
        let p_y = limbs_from_prev_access(&local.p_access[num_words_field_element..]);

        let a = E::BaseField::to_limbs_field::<AB::Expr, AB::F>(&E::a_int());

        let slope = {
            {
                local.p_x_squared.eval(builder, &p_x, &p_x, FieldOperation::Mul, local.is_real);

                local.p_x_squared_times_3.eval(
                    builder,
                    &local.p_x_squared.result,
                    &E::BaseField::to_limbs_field::<AB::Expr, AB::F>(&BigUint::from(3u32)),
                    FieldOperation::Mul,
                    local.is_real,
                );

                local.slope_numerator.eval(
                    builder,
                    &a,
                    &local.p_x_squared_times_3.result,
                    FieldOperation::Add,
                    local.is_real,
                );
            };

            local.slope_denominator.eval(
                builder,
                &E::BaseField::to_limbs_field::<AB::Expr, AB::F>(&BigUint::from(2u32)),
                &p_y,
                FieldOperation::Mul,
                local.is_real,
            );
            let mut one = vec![AB::Expr::ZERO; E::BaseField::NB_LIMBS];
            one[0] = local.is_real.into();
            local.inverse_check.eval(
                builder,
                &Polynomial::from_coefficients(&one),
                &local.slope_denominator.result,
                FieldOperation::Div,
                local.is_real,
            );

            local.slope.eval(
                builder,
                &local.slope_numerator.result,
                &local.slope_denominator.result,
                FieldOperation::Div,
                local.is_real,
            );

            &local.slope.result
        };

        let x = {
            local.slope_squared.eval(builder, slope, slope, FieldOperation::Mul, local.is_real);
            local.p_x_plus_p_x.eval(builder, &p_x, &p_x, FieldOperation::Add, local.is_real);
            local.x3_ins.eval(
                builder,
                &local.slope_squared.result,
                &local.p_x_plus_p_x.result,
                FieldOperation::Sub,
                local.is_real,
            );
            &local.x3_ins.result
        };

        {
            local.p_x_minus_x.eval(builder, &p_x, x, FieldOperation::Sub, local.is_real);
            local.slope_times_p_x_minus_x.eval(
                builder,
                slope,
                &local.p_x_minus_x.result,
                FieldOperation::Mul,
                local.is_real,
            );
            local.y3_ins.eval(
                builder,
                &local.slope_times_p_x_minus_x.result,
                &p_y,
                FieldOperation::Sub,
                local.is_real,
            );
        }

        let modulus = limbs_from_vec::<AB::Expr, <E::BaseField as NumLimbs>::Limbs, AB::F>(
            E::BaseField::to_limbs_field_vec(&E::BaseField::modulus()),
        );
        local.x3_range.eval(builder, &local.x3_ins.result, &modulus, local.is_real);
        local.y3_range.eval(builder, &local.y3_ins.result, &modulus, local.is_real);

        for i in 0..E::BaseField::NB_LIMBS {
            builder
                .when(local.is_real)
                .assert_eq(local.x3_ins.result[i], local.p_access[i / 4].value()[i % 4]);
            builder.when(local.is_real).assert_eq(
                local.y3_ins.result[i],
                local.p_access[num_words_field_element + i / 4].value()[i % 4],
            );
        }

        builder.eval_memory_access_slice(
            local.shard,
            local.clk.into(),
            local.p_ptr,
            &local.p_access,
            local.is_real,
        );

        let syscall_id_felt = match E::CURVE_TYPE {
            CurveType::Secp256k1 => AB::F::from_u32(SyscallCode::SECP256K1_DOUBLE.syscall_id()),
            CurveType::Secp256r1 => AB::F::from_u32(SyscallCode::SECP256R1_DOUBLE.syscall_id()),
            CurveType::Bn254 => AB::F::from_u32(SyscallCode::BN254_DOUBLE.syscall_id()),
            CurveType::Bls12381 => AB::F::from_u32(SyscallCode::BLS12381_DOUBLE.syscall_id()),
            _ => panic!("Unsupported curve"),
        };

        builder.receive_syscall(
            local.shard,
            local.clk,
            syscall_id_felt,
            local.p_ptr,
            AB::Expr::ZERO,
            local.is_real,
            LookupScope::Local,
        );
    }
}

#[cfg(test)]
pub mod tests {
    use test_artifacts::{
        BLS12381_DOUBLE_ELF, BN254_DOUBLE_ELF, SECP256K1_DOUBLE_ELF, SECP256R1_DOUBLE_ELF,
    };
    use zkm_core_executor::Program;
    use zkm_pcs::CpuProver;

    use crate::utils::{run_test, setup_logger};

    #[test]
    fn test_secp256k1_double_simple() {
        setup_logger();
        let program = Program::from(SECP256K1_DOUBLE_ELF).unwrap();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_secp256r1_double_simple() {
        setup_logger();
        let program = Program::from(SECP256R1_DOUBLE_ELF).unwrap();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_bn254_double_simple() {
        setup_logger();
        let program = Program::from(BN254_DOUBLE_ELF).unwrap();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_bls12381_double_simple() {
        setup_logger();
        let program = Program::from(BLS12381_DOUBLE_ELF).unwrap();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }
}

/// Doubling a point whose `y` vanishes (issue #534).
///
/// The slope gadget proves `slope · 2y ≡ 3x² + a (mod p)` and nothing about `2y`: for
/// `P = (0, 0)` on a curve with `a = 0` both sides vanish for every slope `s`, and without
/// `inverse_check` the row writing `(s², −s³)` satisfied every constraint of the chip.
/// `inverse_check` proves `is_real / 2y` exists, so every such row is rejected, honest or forged;
/// the executor refuses the input in `sw_double`.  The control forges the slope of the generator
/// `(1, 2)`, whose `2y` is invertible, and is rejected while its honest double is accepted.
#[cfg(test)]
mod zero_y {
    use core::borrow::BorrowMut;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use num::{BigUint, Zero};
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use zkm_core_executor::events::{EllipticCurveDoubleEvent, FieldOperation, MemoryWriteRecord};
    use zkm_curves::{
        params::FieldParameters,
        weierstrass::{bn254::Bn254Parameters, SwCurve},
        AffinePoint, EllipticCurveParameters,
    };
    use zkm_pcs::{koala_bear_poseidon2::KoalaBearPoseidon2, StarkGenericConfig};

    use super::{
        num_weierstrass_double_cols, WeierstrassDoubleAssignChip, WeierstrassDoubleAssignCols,
    };
    use crate::utils::{uni_stark_prove, uni_stark_verify};

    type E = SwCurve<Bn254Parameters>;
    type Base = <E as EllipticCurveParameters>::BaseField;
    type F = KoalaBear;

    const ROWS: usize = 16;

    /// The chip's trace with one real row doubling `p` and writing `out`; `slope`, when given,
    /// replaces the honest slope and every column computed from it.
    fn trace(
        p: &AffinePoint<E>,
        out: &AffinePoint<E>,
        slope: Option<&BigUint>,
    ) -> RowMajorMatrix<F> {
        let num_cols = num_weierstrass_double_cols::<Base>();
        let words_in = p.to_words_le();
        let words_out = out.to_words_le();
        let event = EllipticCurveDoubleEvent {
            shard: 1,
            clk: 8,
            p_ptr: 0x1000,
            p: words_in.clone(),
            p_memory_records: words_in
                .iter()
                .zip(&words_out)
                .map(|(&prev_value, &value)| MemoryWriteRecord {
                    value,
                    shard: 1,
                    timestamp: 8,
                    prev_value,
                    prev_shard: 1,
                    prev_timestamp: 4,
                })
                .collect(),
            local_mem_access: vec![],
        };
        let mut values = vec![F::default(); ROWS * num_cols];
        let mut blu = vec![];
        {
            let cols: &mut WeierstrassDoubleAssignCols<F, Base> = values[..num_cols].borrow_mut();
            WeierstrassDoubleAssignChip::<E>::populate_row(&event, cols, &mut blu);
            if let Some(s) = slope {
                let modulus = Base::modulus();
                let x1 = p.x.clone();
                let y1 = p.y.clone();
                cols.slope.populate_carry_and_witness(
                    s,
                    &((BigUint::from(2u32) * &y1) % &modulus),
                    FieldOperation::Mul,
                    &modulus,
                );
                cols.slope.result = Base::to_limbs_field::<F, _>(s);
                let s2 = cols.slope_squared.populate(&mut blu, s, s, FieldOperation::Mul);
                let two_x = cols.p_x_plus_p_x.populate(&mut blu, &x1, &x1, FieldOperation::Add);
                let x3 = cols.x3_ins.populate(&mut blu, &s2, &two_x, FieldOperation::Sub);
                let dx = cols.p_x_minus_x.populate(&mut blu, &x1, &x3, FieldOperation::Sub);
                let t =
                    cols.slope_times_p_x_minus_x.populate(&mut blu, s, &dx, FieldOperation::Mul);
                let y3 = cols.y3_ins.populate(&mut blu, &t, &y1, FieldOperation::Sub);
                cols.x3_range.populate(&mut blu, &x3, &modulus);
                cols.y3_range.populate(&mut blu, &y3, &modulus);
            }
        }
        let mut dummy = vec![F::default(); num_cols];
        {
            let cols: &mut WeierstrassDoubleAssignCols<F, Base> = dummy.as_mut_slice().borrow_mut();
            let record = MemoryWriteRecord {
                value: 1,
                shard: 0,
                timestamp: 1,
                prev_value: 1,
                prev_shard: 0,
                prev_timestamp: 0,
            };
            cols.p_access[Base::NB_LIMBS / 4].populate(record, &mut vec![]);
            WeierstrassDoubleAssignChip::<E>::populate_field_ops(
                &mut vec![],
                cols,
                BigUint::zero(),
                BigUint::from(1u32),
                false,
            );
        }
        for row in values[num_cols..].chunks_mut(num_cols) {
            row.copy_from_slice(&dummy);
        }
        RowMajorMatrix::new(values, num_cols)
    }

    /// Whether a proof over the chip's AIR alone accepts `trace`.
    fn accepted(trace: RowMajorMatrix<F>) -> bool {
        let config = KoalaBearPoseidon2::new();
        let chip = WeierstrassDoubleAssignChip::<E>::new();
        catch_unwind(AssertUnwindSafe(|| {
            let mut challenger = config.challenger();
            let proof =
                uni_stark_prove::<KoalaBearPoseidon2, _>(&config, &chip, &mut challenger, trace);
            let mut challenger = config.challenger();
            uni_stark_verify(&config, &chip, &mut challenger, &proof).is_ok()
        }))
        .unwrap_or(false)
    }

    /// The forged point `(s², −s³)` for the double of `(0, 0)` on a curve with `a = 0`.
    fn forged(s: &BigUint) -> AffinePoint<E> {
        let p = Base::modulus();
        let x3 = (s * s) % &p;
        let y3 = (&p - (s * s * s) % &p) % &p;
        AffinePoint::new(x3, y3)
    }

    #[test]
    fn honest_double_of_zero_point_is_rejected() {
        let zero = AffinePoint::<E>::new(BigUint::zero(), BigUint::zero());
        assert!(!accepted(trace(&zero, &zero, None)));
    }

    #[test]
    fn forged_double_of_zero_point_is_rejected() {
        let zero = AffinePoint::<E>::new(BigUint::zero(), BigUint::zero());
        for s in [5u32, 7, 0xdead_beef] {
            let s = BigUint::from(s);
            assert!(
                !accepted(trace(&zero, &forged(&s), Some(&s))),
                "forged slope {s} was accepted"
            );
        }
    }

    #[test]
    #[should_panic(expected = "y = 0")]
    fn executor_refuses_zero_y() {
        let zero = AffinePoint::<E>::new(BigUint::zero(), BigUint::zero());
        let _ = zero.sw_double();
    }

    #[test]
    fn forged_double_of_generator_is_rejected() {
        let (gx, gy) =
            <Bn254Parameters as zkm_curves::weierstrass::WeierstrassParameters>::generator();
        let g = AffinePoint::<E>::new(gx, gy);
        let honest = g.sw_double();
        assert!(accepted(trace(&g, &honest, None)));
        let s = BigUint::from(5u32);
        let p = Base::modulus();
        let x3 = (&s * &s + &p + &p - BigUint::from(2u32)) % &p;
        let y3 = (&s * ((&p + BigUint::from(1u32) - &x3) % &p) + &p - BigUint::from(2u32)) % &p;
        assert!(!accepted(trace(&g, &AffinePoint::new(x3, y3), Some(&s))));
    }
}
