#![allow(clippy::needless_range_loop)]

use std::{borrow::Borrow, ops::Deref};

//use p3_koala_bear::{MONTY_INVERSE, POSEIDON2_INTERNAL_MATRIX_DIAG_16_KOALABEAR_MONTY};
use p3_field::{FieldAlgebra, PrimeField32};
use p3_koala_bear::KoalaBear;

pub mod air;
pub mod columns;
pub mod trace;

use p3_poseidon2::matmul_internal;

use self::columns::{permutation::Poseidon2, Poseidon2Degree3, Poseidon2Degree9};

/// The width of the permutation.
pub const WIDTH: usize = 16;
pub const RATE: usize = WIDTH / 2;

pub const NUM_EXTERNAL_ROUNDS: usize = 8;
pub const NUM_INTERNAL_ROUNDS: usize = 13;
pub const NUM_ROUNDS: usize = NUM_EXTERNAL_ROUNDS + NUM_INTERNAL_ROUNDS;

/// A chip that implements addition for the opcode Poseidon2Wide.
#[derive(Default, Debug, Clone, Copy)]
pub struct Poseidon2WideChip<const DEGREE: usize>;

impl<'a, const DEGREE: usize> Poseidon2WideChip<DEGREE> {
    /// Transmute a row it to an immutable Poseidon2 instance.
    pub(crate) fn convert<T>(row: impl Deref<Target = [T]>) -> Box<dyn Poseidon2<T> + 'a>
    where
        T: Copy + 'a,
    {
        if DEGREE == 3 {
            let convert: &Poseidon2Degree3<T> = (*row).borrow();
            Box::new(*convert)
        } else if DEGREE == 9 || DEGREE == 17 {
            let convert: &Poseidon2Degree9<T> = (*row).borrow();
            Box::new(*convert)
        } else {
            panic!("Unsupported degree");
        }
    }
}

pub fn apply_m_4<AF>(x: &mut [AF])
where
    AF: FieldAlgebra,
{
    let t01 = x[0].clone() + x[1].clone();
    let t23 = x[2].clone() + x[3].clone();
    let t0123 = t01.clone() + t23.clone();
    let t01123 = t0123.clone() + x[1].clone();
    let t01233 = t0123.clone() + x[3].clone();
    // The order here is important. Need to overwrite x[0] and x[2] after x[1] and x[3].
    x[3] = t01233.clone() + x[0].double(); // 3*x[0] + x[1] + x[2] + 2*x[3]
    x[1] = t01123.clone() + x[2].double(); // x[0] + 2*x[1] + 3*x[2] + x[3]
    x[0] = t01123 + t01; // 2*x[0] + 3*x[1] + x[2] + x[3]
    x[2] = t01233 + t23; // x[0] + x[1] + 2*x[2] + 3*x[3]
}

// eq mds_light_permutation
pub(crate) fn external_linear_layer<AF: FieldAlgebra>(state: &mut [AF; WIDTH]) {
    for j in (0..WIDTH).step_by(4) {
        apply_m_4(&mut state[j..j + 4]);
    }
    let sums: [AF; 4] =
        core::array::from_fn(|k| (0..WIDTH).step_by(4).map(|j| state[j + k].clone()).sum::<AF>());

    for j in 0..WIDTH {
        state[j] = state[j].clone() + sums[j % 4].clone();
    }
}

pub(crate) fn external_linear_layer_immut<AF: FieldAlgebra + Copy>(
    state: &[AF; WIDTH],
) -> [AF; WIDTH] {
    let mut state = *state;
    external_linear_layer(&mut state);
    state
}

const POSEIDON2_INTERNAL_MATRIX_DIAG_16_KOALABEAR_MONTY: [KoalaBear; 16] = KoalaBear::new_array([
    KoalaBear::ORDER_U32 - 2,
    1,
    2,
    (KoalaBear::ORDER_U32 + 1) >> 1,
    3,
    4,
    (KoalaBear::ORDER_U32 - 1) >> 1,
    KoalaBear::ORDER_U32 - 3,
    KoalaBear::ORDER_U32 - 4,
    KoalaBear::ORDER_U32 - ((KoalaBear::ORDER_U32 - 1) >> 8),
    KoalaBear::ORDER_U32 - ((KoalaBear::ORDER_U32 - 1) >> 3),
    KoalaBear::ORDER_U32 - 127,
    (KoalaBear::ORDER_U32 - 1) >> 8,
    (KoalaBear::ORDER_U32 - 1) >> 3,
    (KoalaBear::ORDER_U32 - 1) >> 4,
    127,
]);

pub(crate) fn internal_linear_layer<F: FieldAlgebra>(state: &mut [F; WIDTH]) {
    let matmul_constants: [<F as FieldAlgebra>::F; WIDTH] =
        POSEIDON2_INTERNAL_MATRIX_DIAG_16_KOALABEAR_MONTY
            .iter()
            .map(|x| <F as FieldAlgebra>::F::from_wrapped_u32(x.as_canonical_u32()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
    matmul_internal(state, matmul_constants);
}

#[cfg(test)]
pub(crate) mod tests {

    use std::{iter::once, sync::Arc};

    use crate::{
        machine::RecursionAir, runtime::instruction as instr, stark::KoalaBearPoseidon2Outer,
        MemAccessKind, RecursionProgram, Runtime,
    };
    use p3_field::{FieldAlgebra, PrimeField32};
    use p3_koala_bear::{KoalaBear, Poseidon2InternalLayerKoalaBear};
    use p3_symmetric::Permutation;

    use zkhash::ark_ff::UniformRand;
    use zkm_core_machine::utils::{run_test_machine, setup_logger};
    use zkm_stark::{inner_perm, koala_bear_poseidon2::KoalaBearPoseidon2, StarkGenericConfig};

    use super::WIDTH;

    #[test]
    fn test_poseidon2() {
        setup_logger();
        type SC = KoalaBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;
        type A = RecursionAir<F, 3>;
        type B = RecursionAir<F, 9>;

        let input = [1; WIDTH];
        let output = inner_perm()
            .permute(input.map(KoalaBear::from_canonical_u32))
            .map(|x| KoalaBear::as_canonical_u32(&x));

        let rng = &mut rand::thread_rng();
        let input_1: [KoalaBear; WIDTH] = std::array::from_fn(|_| KoalaBear::rand(rng));
        let output_1 = inner_perm().permute(input_1).map(|x| KoalaBear::as_canonical_u32(&x));
        let input_1 = input_1.map(|x| KoalaBear::as_canonical_u32(&x));

        let instructions =
            (0..WIDTH)
                .map(|i| instr::mem(MemAccessKind::Write, 1, i as u32, input[i]))
                .chain(once(instr::poseidon2(
                    [1; WIDTH],
                    std::array::from_fn(|i| (i + WIDTH) as u32),
                    std::array::from_fn(|i| i as u32),
                )))
                .chain(
                    (0..WIDTH)
                        .map(|i| instr::mem(MemAccessKind::Read, 1, (i + WIDTH) as u32, output[i])),
                )
                .chain((0..WIDTH).map(|i| {
                    instr::mem(MemAccessKind::Write, 1, (2 * WIDTH + i) as u32, input_1[i])
                }))
                .chain(once(instr::poseidon2(
                    [1; WIDTH],
                    std::array::from_fn(|i| (i + 3 * WIDTH) as u32),
                    std::array::from_fn(|i| (i + 2 * WIDTH) as u32),
                )))
                .chain((0..WIDTH).map(|i| {
                    instr::mem(MemAccessKind::Read, 1, (i + 3 * WIDTH) as u32, output_1[i])
                }))
                .collect::<Vec<_>>();

        let program = Arc::new(RecursionProgram { instructions, ..Default::default() });
        let mut runtime = Runtime::<F, EF, Poseidon2InternalLayerKoalaBear<16>>::new(
            program.clone(),
            KoalaBearPoseidon2::new().perm,
        );
        runtime.run().unwrap();

        let config = SC::new();
        let machine_deg_3 = A::compress_machine(config);
        let (pk_3, vk_3) = machine_deg_3.setup(&program);
        let result_deg_3 =
            run_test_machine(vec![runtime.record.clone()], machine_deg_3, pk_3, vk_3);
        if let Err(e) = result_deg_3 {
            panic!("Verification failed: {e:?}");
        }

        let config = SC::new();
        let machine_deg_9 = B::compress_machine(config);
        let (pk_9, vk_9) = machine_deg_9.setup(&program);
        let result_deg_9 = run_test_machine(vec![runtime.record], machine_deg_9, pk_9, vk_9);
        if let Err(e) = result_deg_9 {
            panic!("Verification failed: {e:?}");
        }
    }
}
