use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};
use zkm_core_executor::ByteOpcode;
use zkm_core_executor::events::{ByteLookupEvent, ByteRecord, MemoryReadRecord};
use zkm_derive::AlignedBorrow;
use zkm_stark::ZKMAirBuilder;
use crate::memory::{MemoryCols, MemoryReadCols};

pub const ROUND_CONST: [u8; 10] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
];

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct NextRoundKey<T> {
    pub round_const: T,
    pub add_round_const: T, // XOR
    // new round key
    pub w4: [T; 4],
    pub w5: [T; 4],
    pub w6: [T; 4],
    pub w7: [T; 4],
}

impl <F: Field> NextRoundKey<F> {
    pub fn populate(
        &mut self,
        records: &mut impl ByteRecord,
        prev_round_key: &[u8; 16],
        byte_subs_records: &[MemoryReadRecord; 4],
        round: u8,
    ) -> [u8; 16] {
        // check sbox values
        let sbox_values: [u32; 4] = byte_subs_records.map(|m| m.value);
        let all_in_u8 = sbox_values.iter().all(|&v| v <= u8::MAX as u32);
        if !all_in_u8 {
            panic!("Not all sbox_values fit in u8");
        }

        // previous round key
        let w0 = &prev_round_key[0..4];
        let w1 = &prev_round_key[4..8];
        let w2 = &prev_round_key[8..12];
        let w3 = &prev_round_key[12..16];

        let mut sub_rot_w3 = sbox_values.map(|u| u as u8);
        let rcon = ROUND_CONST[round as usize];
        self.round_const = F::from_canonical_u8(rcon);
        let first_byte = sub_rot_w3[0] ^ rcon;
        self.add_round_const = F::from_canonical_u8(first_byte);
        let first_byte_xor_event = ByteLookupEvent {
            opcode: ByteOpcode::XOR,
            a1: first_byte as u16,
            a2: 0,
            b: sub_rot_w3[0],
            c: rcon,
        };
        records.add_byte_lookup_event(first_byte_xor_event);
        // add constant
        sub_rot_w3[0] = first_byte;

        // Compute new words
        let mut new_key = [0u8; 16];
        // w4 = w0 ^ SubWord(RotWord(w3))
        for i in 0..4 {
            new_key[i] = w0[i] ^ sub_rot_w3[i];
            self.w4[i] = F::from_canonical_u8(new_key[i]);
            let xor_event = ByteLookupEvent {
                opcode: ByteOpcode::XOR,
                a1: new_key[i] as u16,
                a2: 0,
                b: w0[i],
                c: sub_rot_w3[i],
            };
            records.add_byte_lookup_event(xor_event);
        }

        // w5 = w4 ^ w1
        for i in 0..4 {
            new_key[4 + i] = new_key[i] ^ w1[i];
            self.w5[i] = F::from_canonical_u8(new_key[4 + i]);
            let xor_event = ByteLookupEvent {
                opcode: ByteOpcode::XOR,
                a1: new_key[4 + i] as u16,
                a2: 0,
                b: new_key[i],
                c: w1[i],
            };
            records.add_byte_lookup_event(xor_event);
        }

        // w6 = w5 ^ w2
        for i in 0..4 {
            new_key[8 + i] = new_key[4 + i] ^ w2[i];
            self.w6[i] = F::from_canonical_u8(new_key[8 + i]);
            let xor_event = ByteLookupEvent {
                opcode: ByteOpcode::XOR,
                a1: new_key[8 + i] as u16,
                a2: 0,
                b: new_key[4 + i],
                c: w2[i],
            };
            records.add_byte_lookup_event(xor_event);
        }

        // w7 = w6 ^ w3
        for i in 0..4 {
            new_key[12 + i] = new_key[8 + i] ^ w3[i];
            self.w7[i] = F::from_canonical_u8(new_key[12 + i]);
            let xor_event = ByteLookupEvent {
                opcode: ByteOpcode::XOR,
                a1: new_key[12 + i] as u16,
                a2: 0,
                b: new_key[8 + i],
                c: w3[i],
            };
            records.add_byte_lookup_event(xor_event);
        }

        new_key
    }

    pub fn eval<AB: ZKMAirBuilder>(
        builder: &mut AB,
        cols: NextRoundKey<AB::Var>,
        prev_round_key: [AB::Var; 16],
        sbox_read: &[MemoryReadCols<AB::Var>; 4],
        round: usize,
        is_real: AB::Var,
    ) {
        let w0 = &prev_round_key[0..4];
        let w1 = &prev_round_key[4..8];
        let w2 = &prev_round_key[8..12];
        let w3 = &prev_round_key[12..16];

        // round const
        let rcon = AB::F::from_canonical_u32(ROUND_CONST[round] as u32);
        builder.when(is_real).assert_eq(cols.round_const, rcon);

        let sbox_values: [AB::Var; 4] = sbox_read.map(|m| m.value().0[0]);

        builder.send_byte(
            AB::F::from_canonical_u32(ByteOpcode::XOR as u32),
            cols.add_round_const,
            sbox_values[0],
            cols.round_const,
            is_real,
        );

        builder.send_byte(
            AB::F::from_canonical_u32(ByteOpcode::XOR as u32),
            cols.w4[0],
            w0[0],
            cols.add_round_const,
            is_real,
        );

        for i in 1..4 {
            builder.send_byte(
                AB::F::from_canonical_u32(ByteOpcode::XOR as u32),
                cols.w4[i],
                w0[i],
                sbox_values[i],
                is_real,
            )
        }

        for i in 0..4 {
            builder.send_byte(
                AB::F::from_canonical_u32(ByteOpcode::XOR as u32),
                cols.w5[i],
                cols.w4[i],
                w1[i],
                is_real,
            )
        }

        for i in 0..4 {
            builder.send_byte(
                AB::F::from_canonical_u32(ByteOpcode::XOR as u32),
                cols.w6[i],
                cols.w5[i],
                w2[i],
                is_real,
            )
        }

        for i in 0..4 {
            builder.send_byte(
                AB::F::from_canonical_u32(ByteOpcode::XOR as u32),
                cols.w7[i],
                cols.w6[i],
                w3[i],
                is_real,
            )
        }
    }
}
