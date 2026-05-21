use crate::operations::aes_mul2::MulBy2InAES;
use p3_field::{Field, FieldAlgebra};
use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode,
};
use zkm_derive::AlignedBorrow;
use zkm_stark::air::ZKMAirBuilder;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MulBy3InAES<T> {
    pub mul_by_2: MulBy2InAES<T>,
    pub xor_x: T, // also the result
}

impl<F: Field> MulBy3InAES<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, x: u8) -> u8 {
        let x2 = self.mul_by_2.populate(record, x);
        let xor_x = x2 ^ x;
        self.xor_x = F::from_canonical_u8(xor_x);

        // Byte lookup event for the final XOR
        let byte_event_xor =
            ByteLookupEvent { opcode: ByteOpcode::XOR, a1: xor_x as u16, a2: 0, b: x2, c: x };
        record.add_byte_lookup_event(byte_event_xor);
        xor_x
    }

    #[allow(unused_variables)]
    pub fn eval<AB: ZKMAirBuilder>(
        builder: &mut AB,
        x: AB::Var,
        cols: MulBy3InAES<AB::Var>,
        is_real: AB::Var,
    ) {
        MulBy2InAES::<F>::eval(builder, x, cols.mul_by_2, is_real);

        builder.send_byte(
            AB::F::from_canonical_u32(ByteOpcode::XOR as u32),
            cols.xor_x,
            cols.mul_by_2.xor_0x1b,
            x,
            is_real,
        );
    }
}
