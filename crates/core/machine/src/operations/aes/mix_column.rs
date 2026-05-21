use crate::operations::aes::xor_byte_4::XorByte4;
use crate::operations::aes_mul2::MulBy2InAES;
use crate::operations::aes_mul3::MulBy3InAES;
use p3_field::Field;
use zkm_core_executor::events::ByteRecord;
use zkm_derive::AlignedBorrow;
use zkm_stark::ZKMAirBuilder;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MixColumn<T> {
    pub mul_by_2s: [MulBy2InAES<T>; 16],
    pub mul_by_3s: [MulBy3InAES<T>; 16],
    pub xor_byte4s: [XorByte4<T>; 16],
}

impl<F: Field> MixColumn<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, shifted_state: &[u8; 16]) -> [u8; 16] {
        let mut mixed = [0u8; 16];
        for col in 0..4 {
            let col_start = col * 4;
            let s0 = shifted_state[col_start];
            let s1 = shifted_state[col_start + 1];
            let s2 = shifted_state[col_start + 2];
            let s3 = shifted_state[col_start + 3];

            // mixed[col_start]     = mul_md5(s0, 2) ^ mul_md5(s1, 3) ^ mul_md5(s2, 1) ^ mul_md5(s3, 1);
            mixed[col_start] = {
                let s0x2 = self.mul_by_2s[col_start].populate(record, s0);
                let s1x3 = self.mul_by_3s[col_start].populate(record, s1);
                self.xor_byte4s[col_start].populate(record, s0x2, s1x3, s2, s3)
            };

            // mixed[col_start + 1] = mul_md5(s0, 1) ^ mul_md5(s1, 2) ^ mul_md5(s2, 3) ^ mul_md5(s3, 1);
            mixed[col_start + 1] = {
                let s1x2 = self.mul_by_2s[col_start + 1].populate(record, s1);
                let s2x3 = self.mul_by_3s[col_start + 1].populate(record, s2);
                self.xor_byte4s[col_start + 1].populate(record, s0, s1x2, s2x3, s3)
            };

            // mixed[col_start + 2] = mul_md5(s0, 1) ^ mul_md5(s1, 1) ^ mul_md5(s2, 2) ^ mul_md5(s3, 3);
            mixed[col_start + 2] = {
                let s2x2 = self.mul_by_2s[col_start + 2].populate(record, s2);
                let s3x3 = self.mul_by_3s[col_start + 2].populate(record, s3);
                self.xor_byte4s[col_start + 2].populate(record, s0, s1, s2x2, s3x3)
            };

            // mixed[col_start + 3] = mul_md5(s0, 3) ^ mul_md5(s1, 1) ^ mul_md5(s2, 1) ^ mul_md5(s3, 2);
            mixed[col_start + 3] = {
                let s0x3 = self.mul_by_3s[col_start + 3].populate(record, s0);
                let s3x2 = self.mul_by_2s[col_start + 3].populate(record, s3);
                self.xor_byte4s[col_start + 3].populate(record, s0x3, s1, s2, s3x2)
            }
        }
        mixed
    }

    pub fn eval<AB: ZKMAirBuilder>(
        builder: &mut AB,
        shifted_state: [AB::Var; 16],
        cols: MixColumn<AB::Var>,
        is_real: AB::Var,
    ) {
        for col in 0..4 {
            let col_start = col * 4;
            let s0 = shifted_state[col_start];
            let s1 = shifted_state[col_start + 1];
            let s2 = shifted_state[col_start + 2];
            let s3 = shifted_state[col_start + 3];

            // col_start
            {
                MulBy2InAES::<F>::eval(builder, s0, cols.mul_by_2s[col_start], is_real);
                MulBy3InAES::<F>::eval(builder, s1, cols.mul_by_3s[col_start], is_real);
                XorByte4::<F>::eval(
                    builder,
                    cols.mul_by_2s[col_start].xor_0x1b,
                    cols.mul_by_3s[col_start].xor_x,
                    s2,
                    s3,
                    cols.xor_byte4s[col_start],
                    is_real,
                );
            }

            // col_start + 1
            {
                MulBy2InAES::<F>::eval(builder, s1, cols.mul_by_2s[col_start + 1], is_real);
                MulBy3InAES::<F>::eval(builder, s2, cols.mul_by_3s[col_start + 1], is_real);
                XorByte4::<F>::eval(
                    builder,
                    s0,
                    cols.mul_by_2s[col_start + 1].xor_0x1b,
                    cols.mul_by_3s[col_start + 1].xor_x,
                    s3,
                    cols.xor_byte4s[col_start + 1],
                    is_real,
                )
            }

            // col_start + 2
            {
                MulBy2InAES::<F>::eval(builder, s2, cols.mul_by_2s[col_start + 2], is_real);
                MulBy3InAES::<F>::eval(builder, s3, cols.mul_by_3s[col_start + 2], is_real);
                XorByte4::<F>::eval(
                    builder,
                    s0,
                    s1,
                    cols.mul_by_2s[col_start + 2].xor_0x1b,
                    cols.mul_by_3s[col_start + 2].xor_x,
                    cols.xor_byte4s[col_start + 2],
                    is_real,
                )
            }

            // col_start + 3
            {
                MulBy3InAES::<F>::eval(builder, s0, cols.mul_by_3s[col_start + 3], is_real);
                MulBy2InAES::<F>::eval(builder, s3, cols.mul_by_2s[col_start + 3], is_real);
                XorByte4::<F>::eval(
                    builder,
                    cols.mul_by_3s[col_start + 3].xor_x,
                    s1,
                    s2,
                    cols.mul_by_2s[col_start + 3].xor_0x1b,
                    cols.xor_byte4s[col_start + 3],
                    is_real,
                )
            }
        }
    }
}
