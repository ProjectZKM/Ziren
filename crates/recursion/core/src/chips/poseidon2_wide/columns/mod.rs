use std::mem::{size_of, transmute};

use permutation::PermutationNoSbox;
use zkm_core_machine::utils::indices_arr;

pub mod permutation;
pub mod preprocessed;

pub const POSEIDON2_DEGREE3_COL_MAP: Poseidon2Degree3<usize> = make_col_map_degree3();
pub const NUM_POSEIDON2_DEGREE3_COLS: usize = size_of::<Poseidon2Degree3<u8>>();

const fn make_col_map_degree3() -> Poseidon2Degree3<usize> {
    let indices_arr = indices_arr::<NUM_POSEIDON2_DEGREE3_COLS>();
    unsafe {
        transmute::<[usize; NUM_POSEIDON2_DEGREE3_COLS], Poseidon2Degree3<usize>>(indices_arr)
    }
}

/// The columns of the compress machine's Poseidon2 chip. The S-box is a cube,
/// so a round's constraint on the next state has degree 3 with the cube
/// written out, and the cubes have no columns.
pub type Poseidon2Degree3<T> = PermutationNoSbox<T>;

pub const NUM_POSEIDON2_DEGREE9_COLS: usize = size_of::<Poseidon2Degree9<u8>>();
const fn make_col_map_degree9() -> Poseidon2Degree9<usize> {
    let indices_arr = indices_arr::<NUM_POSEIDON2_DEGREE9_COLS>();
    unsafe {
        transmute::<[usize; NUM_POSEIDON2_DEGREE9_COLS], Poseidon2Degree9<usize>>(indices_arr)
    }
}
pub const POSEIDON2_DEGREE9_COL_MAP: Poseidon2Degree9<usize> = make_col_map_degree9();

pub type Poseidon2Degree9<T> = PermutationNoSbox<T>;
