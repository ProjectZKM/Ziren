use std::borrow::Borrow;
use log::__private_api::loc;
use p3_air::{Air, BaseAir};
use p3_field::FieldAlgebra;
use p3_matrix::Matrix;
use tempfile::Builder;
use zkm_stark::{MachineAir, ZKMAirBuilder};
use crate::KeccakSpongeChip;
use crate::syscall::precompiles::aes128_encrypt::AES128EncryptChip;
use crate::syscall::precompiles::aes128_encrypt::columns::{AES128EncryptionCols, NUM_AES128_ENCRYPTION_COLS};

impl<F> BaseAir<F> for AES128EncryptChip {
    fn width(&self) -> usize {
        NUM_AES128_ENCRYPTION_COLS
    }
}

impl<AB> Air<AB> for AES128EncryptChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &AES128EncryptionCols<AB::Var> = (*local).borrow();
        let next: &AES128EncryptionCols<AB::Var> = (*next).borrow();

        let first_round = local.round[0];
        let last_round = local.round[10];
        builder.assert_eq(first_round * local.is_real, local.receive_syscall);


    }
}

impl AES128EncryptChip {

}