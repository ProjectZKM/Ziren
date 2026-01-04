use crate::memory::{MemoryReadCols, MemoryWriteCols};
use crate::operations::{IsEqualWordOperation, XorOperation};
use zkm_derive::AlignedBorrow;
use zkm_stark::Word;

/// BooleanCircuitGarbleCols is the column layout for the Boolean Circuit Garble.
/// The number of rows equal to the number of gates
#[derive(AlignedBorrow)]
#[repr(C)]
pub struct BooleanCircuitGarbleCols<T> {
    pub shard: T,
    pub clk: T,
    pub is_real: T,
    pub input_address: T,
    pub output_address: T,
    pub is_first_row: T, // The first row contains gates_num and delta
    pub is_gate: T,
    pub is_first_gate: T,
    pub is_last_gate: T,
    pub not_last_gate: T, // from first gate -> (last - 1)-th gate
    pub gate_type: [T; 2],
    pub gate_id: T,
    pub gates_num: T,
    pub delta: [Word<T>; 4],                      // [u8; 16]
    pub gates_input_mem: [MemoryReadCols<T>; 17], // gate_type, h0, h1, label_b, expected_ciphertext
    pub result_mem: MemoryWriteCols<T>,
    pub aux1: [XorOperation<T>; 4],                   // h1 ^ h0
    pub aux2: [XorOperation<T>; 4],                   // h1 ^ h0 ^ label_b
    pub aux3: [XorOperation<T>; 4],                   // h1 ^ h0 ^ label_b ^ delta
    pub is_equal_words: [IsEqualWordOperation<T>; 4], // computed ciphertext == expected_ciphertext
    pub checks: [T; 4], // check result for each pair of is_equal_words
}

pub const NUM_BOOLEAN_CIRCUIT_GARBLE_COLS: usize = size_of::<BooleanCircuitGarbleCols<u8>>();
