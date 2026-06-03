//! Keccak-f[1600] round constants, for the inlined single-row round AIR in
//! [`super::air`].  Mirrors SP1's `keccak256/constants.rs` (and the upstream
//! `p3_keccak_air` round constants), but derives the per-bit value directly from
//! `RC` instead of hard-coding the unpacked `RC_BITS` table.

/// The 24 Keccak-f round constants.
pub const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// The `bit_index`-th bit (LSB-first) of round constant `round`.
#[inline]
pub const fn rc_value_bit(round: usize, bit_index: usize) -> u8 {
    ((RC[round] >> bit_index) & 1) as u8
}
