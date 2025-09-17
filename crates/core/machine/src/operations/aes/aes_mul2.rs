use p3_field::{Field, FieldAlgebra};
use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode,
};
use zkm_derive::AlignedBorrow;
use zkm_stark::{air::ZKMAirBuilder, Word};

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MulBy2InAES<T> {
    pub and_0x80: T,
    pub left_shift_1: T,
    pub xor_0x1b: T  // also the result
}

impl<F: Field> MulBy2InAES<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, x: u8) -> u8 {
        let and_0x80 = x & 0x80;
        let left_shift_1 = x << 1;
        let xor_0x1b = if and_0x80 != 0 { left_shift_1 ^ 0x1b } else { left_shift_1 };

        self.and_0x80 = F::from_canonical_u8(and_0x80);
        self.left_shift_1 = F::from_canonical_u8(left_shift_1);
        self.xor_0x1b = F::from_canonical_u8(xor_0x1b);

        // Byte lookup events
        let byte_event_and = ByteLookupEvent {
            opcode: ByteOpcode::AND,
            a1: and_0x80 as u16,
            a2: 0,
            b: x,
            c: 0x80,
        };
        record.add_byte_lookup_event(byte_event_and);

        let byte_event_ssl = ByteLookupEvent {
            opcode: ByteOpcode::SLL,
            a1: left_shift_1 as u16,
            a2: 0,
            b: x,
            c: 1,
        };
        record.add_byte_lookup_event(byte_event_ssl);

        if and_0x80 != 0 {
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
    builder
        .when(cols.and_0x80).inner
        .send_byte(
            AB::F::from_canonical_u32(ByteOpcode::XOR as u32),
            cols.xor_0x1b,
            cols.left_shift_1,
            AB::F::from_canonical_u32(0x1b),
            is_real,
        );
    }
}
