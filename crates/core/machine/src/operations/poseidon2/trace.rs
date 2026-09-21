use std::borrow::Borrow;

use p3_field::PrimeField32;
use zkm_primitives::RC_16_30_U32;

use super::{
    air::{external_linear_layer, external_linear_layer_mut, internal_linear_layer_mut},
    permutation::permutation_mut,
    Poseidon2Operation, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, NUM_POSEIDON2_OPERATION_COLUMNS,
    WIDTH,
};

pub fn populate_perm_deg3<F: PrimeField32>(
    input: [F; WIDTH],
    expected_output: Option<[F; WIDTH]>,
) -> Poseidon2Operation<F> {
    let mut row: Vec<F> = vec![F::ZERO; NUM_POSEIDON2_OPERATION_COLUMNS];
    populate_perm::<F, 3>(input, expected_output, row.as_mut_slice());
    let op: &Poseidon2Operation<F> = row.as_slice().borrow();
    *op
}

pub fn populate_perm<F: PrimeField32, const DEGREE: usize>(
    input: [F; WIDTH],
    expected_output: Option<[F; WIDTH]>,
    input_row: &mut [F],
) {
    let permutation = permutation_mut::<F, DEGREE>(input_row);

    let (
        external_rounds_state,
        internal_rounds_state,
        internal_rounds_s0,
        mut external_sbox,
        mut internal_sbox,
        output_state,
    ) = permutation.get_cols_mut();

    external_rounds_state[0] = input;

    for r in 0..NUM_EXTERNAL_ROUNDS / 2 {
        let next_state =
            populate_external_round::<F, DEGREE>(external_rounds_state, &mut external_sbox, r);
        if r == NUM_EXTERNAL_ROUNDS / 2 - 1 {
            *internal_rounds_state = next_state;
        } else {
            external_rounds_state[r + 1] = next_state;
        }
    }

    external_rounds_state[NUM_EXTERNAL_ROUNDS / 2] =
        populate_internal_rounds(internal_rounds_state, internal_rounds_s0, &mut internal_sbox);

    for r in NUM_EXTERNAL_ROUNDS / 2..NUM_EXTERNAL_ROUNDS {
        let next_state =
            populate_external_round::<F, DEGREE>(external_rounds_state, &mut external_sbox, r);
        if r == NUM_EXTERNAL_ROUNDS - 1 {
            for i in 0..WIDTH {
                output_state[i] = next_state[i];
                if let Some(expected_output) = expected_output {
                    assert_eq!(expected_output[i], next_state[i]);
                }
            }
        } else {
            external_rounds_state[r + 1] = next_state;
        }
    }
}

pub fn populate_external_round<F: PrimeField32, const DEGREE: usize>(
    external_rounds_state: &[[F; WIDTH]],
    sbox: &mut Option<&mut [[F; WIDTH]; NUM_EXTERNAL_ROUNDS]>,
    r: usize,
) -> [F; WIDTH] {
    let mut state = {
        let round_state: &[F; WIDTH] = if r == 0 {
            &external_linear_layer(&external_rounds_state[r])
        } else {
            &external_rounds_state[r]
        };

        let round = if r < NUM_EXTERNAL_ROUNDS / 2 { r } else { r + NUM_INTERNAL_ROUNDS };
        let mut add_rc = *round_state;
        for i in 0..WIDTH {
            add_rc[i] += F::from_u32(RC_16_30_U32[round][i]);
        }

        let mut sbox_deg_3: [F; 16] = [F::ZERO; WIDTH];
        for i in 0..WIDTH {
            sbox_deg_3[i] = add_rc[i] * add_rc[i] * add_rc[i];
        }

        if let Some(sbox) = sbox.as_deref_mut() {
            sbox[r] = sbox_deg_3;
        }

        sbox_deg_3
    };

    external_linear_layer_mut(&mut state);
    state
}

pub fn populate_internal_rounds<F: PrimeField32>(
    internal_rounds_state: &[F; WIDTH],
    internal_rounds_s0: &mut [F; NUM_INTERNAL_ROUNDS - 1],
    sbox: &mut Option<&mut [F; NUM_INTERNAL_ROUNDS]>,
) -> [F; WIDTH] {
    let mut state: [F; WIDTH] = *internal_rounds_state;
    let mut sbox_deg_3: [F; NUM_INTERNAL_ROUNDS] = [F::ZERO; NUM_INTERNAL_ROUNDS];
    for r in 0..NUM_INTERNAL_ROUNDS {
        let round = r + NUM_EXTERNAL_ROUNDS / 2;
        let add_rc = state[0] + F::from_u32(RC_16_30_U32[round][0]);

        sbox_deg_3[r] = add_rc * add_rc * add_rc;

        state[0] = sbox_deg_3[r];
        internal_linear_layer_mut(&mut state);

        if r < NUM_INTERNAL_ROUNDS - 1 {
            internal_rounds_s0[r] = state[0];
        }
    }

    let ret_state = state;

    if let Some(sbox) = sbox.as_deref_mut() {
        *sbox = sbox_deg_3;
    }

    ret_state
}
