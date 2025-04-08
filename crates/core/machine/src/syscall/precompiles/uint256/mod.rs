mod air;

pub use air::*;

#[cfg(test)]
mod tests {

    use test_artifacts::UINT256_MUL_ELF;
    use zkm_core_executor::Program;
    use zkm_curves::{params::FieldParameters, uint256::U256Field, utils::biguint_from_limbs};
    use zkm_stark::CpuProver;

    use crate::{
        io::ZKMStdin,
        utils::{self, run_test_io},
    };

    #[test]
    fn test_uint256_mul() {
        utils::setup_logger();
        let program = Program::from(UINT256_MUL_ELF).unwrap();
        run_test_io::<CpuProver<_, _>>(program, ZKMStdin::new()).unwrap();
    }

    #[test]
    fn test_uint256_modulus() {
        assert_eq!(biguint_from_limbs(U256Field::MODULUS), U256Field::modulus());
    }
}
