use permutation::Poseidon2Degree3Cols;
use zkm2_derive::AlignedBorrow;

pub mod air;
pub mod permutation;
pub mod trace;

/// The width of the permutation.
pub const WIDTH: usize = 16;

/// The rate of the permutation.
pub const RATE: usize = WIDTH / 2;

/// The number of external rounds.
pub const NUM_EXTERNAL_ROUNDS: usize = 8;

/// The number of internal rounds.
pub const NUM_INTERNAL_ROUNDS: usize = 13;

/// The total number of rounds.
pub const NUM_ROUNDS: usize = NUM_EXTERNAL_ROUNDS + NUM_INTERNAL_ROUNDS;

/// The number of columns in the Poseidon2 operation.
pub const NUM_POSEIDON2_OPERATION_COLUMNS: usize = std::mem::size_of::<Poseidon2Operation<u8>>();

/// A set of columns needed to compute the Poseidon2 operation.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2Operation<T: Copy> {
    /// The permutation.
    pub permutation: Poseidon2Degree3Cols<T>,
}

#[cfg(test)]
mod tests {
    use p3_koala_bear::KoalaBear;
    use p3_field::{FieldAlgebra, FieldExtensionAlgebra};
    use p3_symmetric::Permutation;
    use zkm2_stark::koala_bear_poseidon2::KoalaBearPoseidon2;
    use zkm2_stark::{
        septic_curve::SepticCurve,
        septic_extension::{SepticBlock, SepticExtension},
    };
    use crate::operations::poseidon2::{
        trace::populate_perm_deg3, permutation::Poseidon2Cols, 
    };

    #[test]
    fn test_poseidon2_operations() {
        type F = KoalaBear;
        let x = SepticExtension::<F>::from_base_fn(|_| F::from_canonical_u32(0));
        let (point, _offset, m_trial, m_hash) = SepticCurve::<F>::lift_x(x);
        let permutation = populate_perm_deg3(m_trial, Some(m_hash));
        let x_coordinate = SepticBlock::<F>::from(point.x.0);
        assert_eq!(x_coordinate.0[0], permutation.permutation.perm_output()[0]);
    }

    #[test]
    fn test_poseidon2_operations2() {
        type F = KoalaBear;
        let m_trial = [F::ZERO; 16];
        let m_hash = KoalaBearPoseidon2::new().perm.permute(m_trial);
        let x_trial = SepticExtension(m_hash[..7].try_into().unwrap());
        let permutation = populate_perm_deg3(m_trial, Some(m_hash));
        let x_coordinate = SepticBlock::<F>::from(x_trial.0);
        assert_eq!(x_coordinate.0[0], permutation.permutation.perm_output()[0]);
    }
}
