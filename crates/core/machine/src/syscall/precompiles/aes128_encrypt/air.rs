use p3_air::{Air, BaseAir};
use tempfile::Builder;
use zkm_stark::ZKMAirBuilder;
use crate::syscall::precompiles::aes128_encrypt::AES128EncryptChip;
use crate::syscall::precompiles::aes128_encrypt::columns::NUM_AES128_ENCRYPTION_COLS;

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
        todo!()
    }
}