use crate::memory::{MemoryReadCols, MemoryWriteCols};
use crate::operations::{IsEqualWordOperation, XorOperation};
use zkm_derive::AlignedBorrow;
#[cfg(feature = "picus")]
use zkm_derive::PicusAnnotations;
use zkm_stark::Word;

#[cfg(feature = "picus")]
use zkm_stark::PicusInfo;
/// BooleanCircuitGarbleCols is the column layout for the Boolean Circuit Garble.
/// The number of rows equal to the number of gates
#[derive(AlignedBorrow)]
#[cfg_attr(feature = "picus", derive(PicusAnnotations))]
#[repr(C)]
pub struct BooleanCircuitGarbleCols<T> {
    #[cfg_attr(feature = "picus", picus(transition_input))]
    pub shard: T,
    #[cfg_attr(feature = "picus", picus(transition_input))]
    pub clk: T,
    pub is_real: T,
    #[cfg_attr(feature = "picus", picus(transition_input))]
    pub input_address: T,
    #[cfg_attr(feature = "picus", picus(transition_input))]
    pub output_address: T,
    pub is_first_row: T, // The first row contains gates_num and delt
    #[cfg_attr(feature = "picus", picus(transition_input))]
    pub is_gate: T,
    #[cfg_attr(feature = "picus", picus(transition_input))]
    pub is_first_gate: T,
    #[cfg_attr(feature = "picus", picus(transition_input))]
    pub is_last_gate: T,
    #[cfg_attr(feature = "picus", picus(transition_input))]
    pub not_last_gate: T, // from first gate -> (last - 1)-th gate
    pub gate_type: [T; 2],
    #[cfg_attr(feature = "picus", picus(transition_input))]
    pub gate_id: T,
    #[cfg_attr(feature = "picus", picus(transition_input))]
    pub gates_num: T,
    #[cfg_attr(feature = "picus", picus(transition_input))]
    pub delta: [Word<T>; 4], // [u8; 16]
    pub gates_input_mem: [MemoryReadCols<T>; 17], // gate_type, h0, h1, label_b, expected_ciphertext
    pub result_mem: MemoryWriteCols<T>,
    pub aux1: [XorOperation<T>; 4],                   // h1 ^ h0
    pub aux2: [XorOperation<T>; 4],                   // h1 ^ h0 ^ label_b
    pub aux3: [XorOperation<T>; 4],                   // h1 ^ h0 ^ label_b ^ delta
    pub is_equal_words: [IsEqualWordOperation<T>; 4], // computed ciphertext == expected_ciphertext
    pub checks: [T; 3],                               // row-local chaining result
    #[cfg_attr(feature = "picus", picus(input, transition_input))]
    pub checks_acc: T, // cross-row accumulated check state
}

pub const NUM_BOOLEAN_CIRCUIT_GARBLE_COLS: usize = size_of::<BooleanCircuitGarbleCols<u8>>();
