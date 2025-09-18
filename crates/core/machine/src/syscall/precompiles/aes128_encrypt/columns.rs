use zkm_derive::AlignedBorrow;
use crate::memory::{MemoryReadCols, MemoryReadWriteCols};
use crate::operations::mix_column::MixColumn;
use crate::operations::round_key::NextRoundKey;

/// AES128EncryptCols is the column layout for the AES128 encryption.
/// The number of rows equal to the number of block.
#[derive(AlignedBorrow)]
#[repr(C)]
pub struct AES128EncryptionCols<T> {
    pub shard: T,
    pub clk: T,
    pub is_real: T,
    pub key_address: T,
    pub block_address: T,
    pub sbox_address: T,
    pub receive_syscall: T,
    pub sbox_addr_read: MemoryReadCols<T>,
    pub key: [MemoryReadCols<T>; 4],
    pub block: [MemoryReadWriteCols<T>; 4],
    pub sbox: [MemoryReadCols<T>; 24], //24 * 11 = 264 > 256 Sbox elements.
    pub round: [T; 11], // [0,..10]
    pub round_1to9: T, // 1 to 9
    pub state_matrix: [T; 16],
    pub round_key_matrix: [T; 16],
    pub next_round_key: NextRoundKey<T>,
    pub roundkey_subs_bytes: [MemoryReadCols<T>; 4], // byte subs for round key
    pub state_subs_bytes: [MemoryReadCols<T>; 16], // byte subs for state
    pub mix_column: MixColumn<T>,
    pub add_round_key: [T; 16], // result of this round
}

pub const NUM_AES128_ENCRYPTION_COLS: usize = core::mem::size_of::<AES128EncryptionCols<u8>>();
