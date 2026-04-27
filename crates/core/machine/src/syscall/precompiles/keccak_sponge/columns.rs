use core::mem::{size_of, transmute};

use crate::memory::{MemoryReadCols, MemoryWriteCols};
use crate::operations::XorOperation;
use crate::syscall::precompiles::keccak_sponge::{
    KECCAK_GENERAL_OUTPUT_U32S, KECCAK_GENERAL_RATE_U32S, KECCAK_STATE_U32S,
};
use crate::utils::indices_arr;

use p3_keccak_air::{KeccakCols, NUM_KECCAK_COLS, U64_LIMBS};
use zkm_derive::{AlignedBorrow, PicusAnnotations, PicusProjection};
use zkm_stark::{PicusInfo, Word};

/// KeccakSpongeCols is the column layout for the keccak sponge.
/// The number of rows equal to the number of block.
#[derive(AlignedBorrow, PicusAnnotations)]
#[repr(C)]
pub(crate) struct KeccakSpongeCols<T> {
    pub keccak: KeccakCols<T>,
    pub block_mem: [MemoryReadCols<T>; KECCAK_GENERAL_RATE_U32S],
    pub shard: T,
    pub clk: T,
    pub is_real: T,
    pub read_block: T,
    pub input_address: T,
    pub output_address: T,
    pub input_len: T,
    pub already_absorbed_u32s: T,
    pub is_absorbed: T,
    pub receive_syscall: T,
    pub write_output: T,
    pub is_first_input_block: T,
    pub is_final_input_block: T,
    pub original_state: [Word<T>; KECCAK_STATE_U32S],
    pub xored_general_rate: [XorOperation<T>; KECCAK_GENERAL_RATE_U32S],
    pub input_length_mem: MemoryReadCols<T>,
    pub output_mem: [MemoryWriteCols<T>; KECCAK_GENERAL_OUTPUT_U32S],
}

pub const NUM_KECCAK_SPONGE_COLS: usize = size_of::<KeccakSpongeCols<u8>>();

#[allow(dead_code)]
/// The full Keccak-f state is 25 lanes, each stored as 4 u16 limbs.
pub const KECCAK_STATE_LIMBS: usize = 25 * U64_LIMBS;
#[allow(dead_code)]
/// The witness stores the final `(0, 0)` lane after iota in a dedicated field.
/// The remaining 24 lanes stay in `a_prime_prime`, so the semantic output
/// boundary needs a tail slice for those lanes.
pub const KECCAK_STATE_TAIL_LIMBS: usize = KECCAK_STATE_LIMBS - U64_LIMBS;

#[allow(dead_code)]
pub const KECCAK_PICUS_COL_MAP: KeccakCols<usize> = make_keccak_picus_col_map();

#[allow(dead_code)]
const fn make_keccak_picus_col_map() -> KeccakCols<usize> {
    let indices_arr = indices_arr::<NUM_KECCAK_COLS>();
    unsafe { transmute::<[usize; NUM_KECCAK_COLS], KeccakCols<usize>>(indices_arr) }
}

/// Semantic Picus projection for the observable input/output contract of the
/// embedded Keccak-f permutation witness.
///
/// The full witness stores many intermediate round columns that should remain
/// internal to any future Keccak operation submodule. The semantic boundary is:
/// - `state_in`: the full 25-lane permutation input state
/// - `first_step` / `final_step`: the caller-visible round-position flags
/// - `state_out_0_0`: the `(0, 0)` output lane after iota
/// - `state_out_rest`: the remaining 24 output lanes
///
/// The output is split because the witness layout stores the `(0, 0)` lane in
/// `a_prime_prime_prime_0_0_limbs`, while the other 24 lanes remain in
/// `a_prime_prime`.
#[allow(dead_code)]
#[derive(PicusProjection)]
#[picus_projection(source = KeccakCols<u8>, col_map = KECCAK_PICUS_COL_MAP)]
pub struct KeccakPermutationProjection {
    #[picus(input, path = a)]
    pub state_in: [[[u8; U64_LIMBS]; 5]; 5],
    #[picus(output, path = step_flags[0])]
    pub first_step: u8,
    #[picus(output, path = step_flags[23])]
    pub final_step: u8,
    #[picus(output, path = a_prime_prime_prime_0_0_limbs)]
    pub state_out_0_0: [u8; U64_LIMBS],
    #[picus(output, path = a_prime_prime[0][1])]
    pub state_out_rest: [u8; KECCAK_STATE_TAIL_LIMBS],
}
