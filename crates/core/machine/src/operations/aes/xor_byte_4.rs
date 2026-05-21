use p3_field::{Field, FieldAlgebra};
use zkm_core_executor::events::{ByteLookupEvent, ByteRecord};
use zkm_core_executor::ByteOpcode;
use zkm_derive::AlignedBorrow;
use zkm_stark::ZKMAirBuilder;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
// x ^ y ^ z ^ w
pub struct XorByte4<T> {
    pub interm1: T,
    pub interm2: T,
    pub value: T,
}

impl<F: Field> XorByte4<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, x: u8, y: u8, z: u8, w: u8) -> u8 {
        let xor_inter1 = x ^ y;
        self.interm1 = F::from_canonical_u8(xor_inter1);
        let byte_event =
            ByteLookupEvent { opcode: ByteOpcode::XOR, a1: xor_inter1 as u16, a2: 0, b: x, c: y };
        record.add_byte_lookup_event(byte_event);

        let xor_inter2 = xor_inter1 ^ z;
        self.interm2 = F::from_canonical_u8(xor_inter2);
        let byte_event = ByteLookupEvent {
            opcode: ByteOpcode::XOR,
            a1: xor_inter2 as u16,
            a2: 0,
            b: xor_inter1,
            c: z,
        };
        record.add_byte_lookup_event(byte_event);

        let result = xor_inter2 ^ w;
        self.value = F::from_canonical_u8(result);
        let byte_event = ByteLookupEvent {
            opcode: ByteOpcode::XOR,
            a1: result as u16,
            a2: 0,
            b: xor_inter2,
            c: w,
        };
        record.add_byte_lookup_event(byte_event);
        result
    }

    pub fn eval<AB: ZKMAirBuilder>(
        builder: &mut AB,
        x: AB::Var,
        y: AB::Var,
        z: AB::Var,
        w: AB::Var,
        cols: XorByte4<AB::Var>,
        is_real: AB::Var,
    ) {
        builder.send_byte(
            AB::F::from_canonical_u32(ByteOpcode::XOR as u32),
            cols.interm1,
            x,
            y,
            is_real,
        );
        builder.send_byte(
            AB::F::from_canonical_u32(ByteOpcode::XOR as u32),
            cols.interm2,
            cols.interm1,
            z,
            is_real,
        );
        builder.send_byte(
            AB::F::from_canonical_u32(ByteOpcode::XOR as u32),
            cols.value,
            cols.interm2,
            w,
            is_real,
        );
    }
}
