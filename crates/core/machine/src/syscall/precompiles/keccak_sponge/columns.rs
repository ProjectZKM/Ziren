use core::mem::size_of;
use zkm_derive::PicusAnnotations;
use zkm_pcs::PicusInfo;

use p3_keccak_air::{KeccakCols, NUM_ROUNDS, U64_LIMBS};
use zkm_derive::AlignedBorrow;

/// Keccak-f rho rotation offsets `r[x][y]` (Keccak spec), as in `p3_keccak_air`.
const R: [[u8; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

/// The per-round keccak-f columns of [`p3_keccak_air::KeccakCols`] that the worker's AIR
/// constrains.  `KeccakCols` also carries `preimage` (the permutation input, 100 limbs) and
/// `export`; the worker never reads them, since the absorbed state reaches it on the control
/// chip's bus as round 0's `a` and the permuted state leaves on it from round 23.
#[derive(PicusAnnotations, AlignedBorrow)]
#[repr(C)]
pub(crate) struct KeccakRoundCols<T> {
    /// `step_flags[i]` is one exactly on round `i`.
    pub step_flags: [T; NUM_ROUNDS],
    /// The round's input state, as `U64_LIMBS` 16-bit limbs per lane, `[y][x]`.
    pub a: [[[T; U64_LIMBS]; 5]; 5],
    /// `C[x, z]`, the column parities of `a`.
    pub c: [[T; 64]; 5],
    /// `C'[x, z] = C[x, z] ^ C[x - 1, z] ^ ROT(C[x + 1], 1)[z]`.
    pub c_prime: [[T; 64]; 5],
    /// `A'[x, y, z] = A[x, y, z] ^ C[x, z] ^ C'[x, z]`, as bits, `[y][x][z]`.
    pub a_prime: [[[T; 64]; 5]; 5],
    /// `A''[x, y] = B[x, y] ^ (~B[x + 1, y] & B[x + 2, y])`, as limbs, `[y][x]`.
    pub a_prime_prime: [[[T; U64_LIMBS]; 5]; 5],
    /// `A''[0, 0]` as bits, for the iota step.
    pub a_prime_prime_0_0_bits: [T; 64],
    /// `A'''[0, 0, z] = A''[0, 0, z] ^ RC[k, z]`, as limbs.
    pub a_prime_prime_prime_0_0_limbs: [T; U64_LIMBS],
}

impl<T: Copy> KeccakRoundCols<T> {
    /// `B[x, y, z]`, the rho/pi image of `A'`: `B[y, 2x + 3y] = ROT(A'[x, y], r[x, y])`.
    pub fn b(&self, x: usize, y: usize, z: usize) -> T {
        debug_assert!(x < 5 && y < 5 && z < 64);
        let a = (x + 3 * y) % 5;
        let rot = R[a][x] as usize;
        self.a_prime[x][a][(z + 64 - rot) % 64]
    }

    /// The round's output state `A'''`, limb `limb` of lane `[y][x]`.
    pub fn a_prime_prime_prime(&self, y: usize, x: usize, limb: usize) -> T {
        debug_assert!(y < 5 && x < 5 && limb < U64_LIMBS);
        if y == 0 && x == 0 {
            self.a_prime_prime_prime_0_0_limbs[limb]
        } else {
            self.a_prime_prime[y][x][limb]
        }
    }

    /// Copies the constrained columns out of a `p3_keccak_air` round row.
    pub fn copy_from(&mut self, p3: &KeccakCols<T>) {
        self.step_flags = p3.step_flags;
        self.a = p3.a;
        self.c = p3.c;
        self.c_prime = p3.c_prime;
        self.a_prime = p3.a_prime;
        self.a_prime_prime = p3.a_prime_prime;
        self.a_prime_prime_0_0_bits = p3.a_prime_prime_0_0_bits;
        self.a_prime_prime_prime_0_0_limbs = p3.a_prime_prime_prime_0_0_limbs;
    }
}

/// Worker column layout for the keccak permutation.  Each row is **one** of the
/// 24 keccak-f rounds.  The round-to-round state hand-off and the multi-block
/// sponge are carried on the `PrecompileChain` buses (see `air` + the
/// `control` chip), so no multi-row window or row selector is needed (the
/// single-row zerocheck folder has neither).
#[derive(PicusAnnotations, AlignedBorrow)]
#[repr(C)]
pub(crate) struct KeccakSpongeCols<T> {
    pub keccak: KeccakRoundCols<T>,
    /// The syscall clock (identifies which syscall this permutation belongs to).
    pub clk: T,
    /// Which sponge block (0..num_blocks) this permutation is for.
    pub block: T,
    /// This row's round index `0..24`, constrained to `Σ i·step_flags[i]`.
    pub index: T,
    pub is_real: T,
}

pub const NUM_KECCAK_SPONGE_COLS: usize = size_of::<KeccakSpongeCols<u8>>();
