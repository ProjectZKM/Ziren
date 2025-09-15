//! Diffusion matrix for SECT
//!
//! Reference: https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage

use std::sync::OnceLock;

use p3_field::FieldAlgebra;
use p3_poseidon2::{ExternalLayerConstructor, ExternalLayer, matmul_internal, ExternalLayerConstants, external_initial_permute_state,
                   HLMDSMat4, external_terminal_permute_state, add_rc_and_sbox_generic, internal_permute_state, InternalLayer,
                    InternalLayerConstructor, Poseidon2};

use serde::{Deserialize, Serialize};

use crate::SectFr;

const SECT_WIDTH: usize = 3;
const SECT_S_BOX_DEGREE: u64 = 5;

pub type Poseidon2Sect<const WIDTH: usize> = Poseidon2<
    SectFr,
    Poseidon2ExternalLayerSect<WIDTH>,
    Poseidon2InternalLayerSect,
    WIDTH,
    SECT_S_BOX_DEGREE,
>;

#[inline]
fn get_diffusion_matrix_3() -> &'static [SectFr; 3] {
    static MAT_DIAG3_M_1: OnceLock<[SectFr; 3]> = OnceLock::new();
    MAT_DIAG3_M_1.get_or_init(|| [SectFr::ONE, SectFr::ONE, SectFr::TWO])
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Poseidon2InternalLayerSect {
    internal_constants: Vec<SectFr>,
}
impl InternalLayerConstructor<SectFr> for Poseidon2InternalLayerSect {
    fn new_from_constants(internal_constants: Vec<SectFr>) -> Self {
        Self { internal_constants }
    }
}
impl InternalLayer<SectFr, SECT_WIDTH, SECT_S_BOX_DEGREE> for Poseidon2InternalLayerSect {
    /// Perform the internal layers of the Poseidon2 permutation on the given state.
    fn permute_state(&self, state: &mut [SectFr; SECT_WIDTH]) {
        internal_permute_state::<SectFr, SECT_WIDTH, SECT_S_BOX_DEGREE>(
            state,
            |x| matmul_internal(x, *get_diffusion_matrix_3()),
            &self.internal_constants,
        )
    }
}

pub type Poseidon2ExternalLayerSect<const WIDTH: usize> = ExternalLayerConstants<SectFr, WIDTH>;

impl<const WIDTH: usize> ExternalLayerConstructor<SectFr, WIDTH>
for Poseidon2ExternalLayerSect<WIDTH>
{
    fn new_from_constants(external_constants: ExternalLayerConstants<SectFr, WIDTH>) -> Self {
        external_constants
    }
}

impl<const WIDTH: usize> ExternalLayer<SectFr, WIDTH, SECT_S_BOX_DEGREE>
for Poseidon2ExternalLayerSect<WIDTH>
{
    /// Perform the initial external layers of the Poseidon2 permutation on the given state.
    fn permute_state_initial(&self, state: &mut [SectFr; WIDTH]) {
        external_initial_permute_state(
            state,
            self.get_initial_constants(),
            add_rc_and_sbox_generic::<_, SECT_S_BOX_DEGREE>,
            &HLMDSMat4,
        );
    }

    /// Perform the terminal external layers of the Poseidon2 permutation on the given state.
    fn permute_state_terminal(&self, state: &mut [SectFr; WIDTH]) {
        external_terminal_permute_state(
            state,
            self.get_terminal_constants(),
            add_rc_and_sbox_generic::<_, SECT_S_BOX_DEGREE>,
            &HLMDSMat4,
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        params::{POSEIDON2_SECT_PARAMS, RC3},
        FpSECT as ark_FpBN256,
    };
    use ff::PrimeField;
    use p3_symmetric::Permutation;
    use p3_poseidon2::ExternalLayerConstants;
    use rand::Rng;
    use zkhash::{
        ark_ff::{BigInteger, PrimeField as ark_PrimeField},
        poseidon2::poseidon2::Poseidon2 as Poseidon2Ref,
    };

    use super::*;
    use crate::FFSectFr;

    fn sect_from_ark_ff(input: ark_FpBN256) -> SectFr {
        let bytes = input.into_bigint().to_bytes_le();

        let mut res = <FFSectFr as PrimeField>::Repr::default();

        for (i, digit) in res.0.as_mut().iter_mut().enumerate() {
            *digit = bytes[i];
        }

        let value = FFSectFr::from_repr(res);

        if value.is_some().into() {
            SectFr { value: value.unwrap() }
        } else {
            panic!("Invalid field element")
        }
    }

    #[test]
    fn test_poseidon2_sect() {
        const WIDTH: usize = 3;
        const D: u64 = 5;
        const ROUNDS_F: usize = 8;
        const ROUNDS_P: usize = 56;

        type F = SectFr;

        let mut rng = rand::thread_rng();

        // Poiseidon2 reference implementation from zkhash repo.
        let poseidon2_ref = Poseidon2Ref::new(&POSEIDON2_SECT_PARAMS);

        // Copy over round constants from zkhash.
        let mut round_constants: Vec<[F; WIDTH]> = RC3
            .iter()
            .map(|vec| {
                vec.iter().cloned().map(sect_from_ark_ff).collect::<Vec<_>>().try_into().unwrap()
            })
            .collect();

        let internal_start = ROUNDS_F / 2;
        let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
        let internal_round_constants = round_constants
            .drain(internal_start..internal_end)
            .map(|vec| vec[0])
            .collect::<Vec<_>>();
        let external_round_constants = ExternalLayerConstants::new(
            round_constants[..ROUNDS_F / 2].to_vec(),
            round_constants[ROUNDS_F / 2..ROUNDS_F].to_vec(),
        );
        // Our Poseidon2 implementation.
        //
        // Poseidon2<
        //     <F as Field>::Packing,
        // Poseidon2ExternalLayerKoalaBear<16>,
        // Diffusion,
        // PERMUTATION_WIDTH,
        // POSEIDON2_SBOX_DEGREE,
        // >,

        let poseidon2 = Poseidon2Sect::new(external_round_constants, internal_round_constants);



        // Generate random input and convert to both Goldilocks field formats.
        let input_ark_ff = rng.gen::<[ark_FpBN256; WIDTH]>();
        let input: [SectFr; 3] = input_ark_ff
            .iter()
            .cloned()
            .map(sect_from_ark_ff)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Run reference implementation.
        let output_ref = poseidon2_ref.permutation(&input_ark_ff);

        let expected: [F; WIDTH] = output_ref
            .iter()
            .cloned()
            .map(sect_from_ark_ff)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Run our implementation.
        let mut output = input;
        poseidon2.permute_mut(&mut output);

        assert_eq!(output, expected);
    }
}
