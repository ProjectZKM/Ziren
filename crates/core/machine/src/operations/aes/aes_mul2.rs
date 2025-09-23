use p3_field::{Field, FieldAlgebra};
use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode,
};
use zkm_derive::AlignedBorrow;
use zkm_stark::air::ZKMAirBuilder;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MulBy2InAES<T> {
    pub and_0x80: T,
    pub left_shift_1: T,
    pub is_xor: T,   // 0 or 1
    pub xor_0x1b: T, // also the result
}

impl<F: Field> MulBy2InAES<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, x: u8) -> u8 {
        let and_0x80 = x & 0x80;
        let left_shift_1 = x << 1;
        let mut is_xor = 0_u8;
        let xor_0x1b = if and_0x80 != 0 {
            is_xor = 1;
            left_shift_1 ^ 0x1b
        } else {
            left_shift_1
        };

        self.and_0x80 = F::from_canonical_u8(and_0x80);
        self.left_shift_1 = F::from_canonical_u8(left_shift_1);
        self.xor_0x1b = F::from_canonical_u8(xor_0x1b);
        self.is_xor = F::from_canonical_u8(is_xor);

        // Byte lookup events
        let byte_event_and =
            ByteLookupEvent { opcode: ByteOpcode::AND, a1: and_0x80 as u16, a2: 0, b: x, c: 0x80 };
        record.add_byte_lookup_event(byte_event_and);

        let byte_event_ssl =
            ByteLookupEvent { opcode: ByteOpcode::SLL, a1: left_shift_1 as u16, a2: 0, b: x, c: 1 };
        record.add_byte_lookup_event(byte_event_ssl);

        if is_xor == 1 {
            let byte_event_xor = ByteLookupEvent {
                opcode: ByteOpcode::XOR,
                a1: xor_0x1b as u16,
                a2: 0,
                b: left_shift_1,
                c: 0x1b,
            };
            record.add_byte_lookup_event(byte_event_xor);
        }

        xor_0x1b
    }

    #[allow(unused_variables)]
    pub fn eval<AB: ZKMAirBuilder>(
        builder: &mut AB,
        x: AB::Var,
        cols: MulBy2InAES<AB::Var>,
        is_real: AB::Var,
    ) {
        builder.send_byte(
            AB::F::from_canonical_u32(ByteOpcode::AND as u32),
            cols.and_0x80,
            x,
            AB::F::from_canonical_u32(0x80),
            is_real,
        );

        builder.send_byte(
            AB::F::from_canonical_u32(ByteOpcode::SLL as u32),
            cols.left_shift_1,
            x,
            AB::F::from_canonical_u32(1),
            is_real,
        );

        builder.assert_bool(cols.is_xor);
        // if cols.is_xor == 1, then and_0x80 == 128, else and_0x80 = 0
        builder.assert_eq(cols.and_0x80, cols.is_xor * AB::Expr::from_canonical_u8(128u8));

        builder.assert_eq((AB::Expr::ONE - is_real.into()) * cols.is_xor, AB::Expr::ZERO);

        builder.send_byte(
            AB::F::from_canonical_u32(ByteOpcode::XOR as u32),
            cols.xor_0x1b,
            cols.left_shift_1,
            AB::F::from_canonical_u32(0x1b),
            cols.is_xor,
        );
    }
}
