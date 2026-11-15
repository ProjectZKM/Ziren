//! The Blake3 compression function, as the recursion VM runs it.
//!
//! One compression takes a chaining value of eight words, a block of
//! sixteen, the chunk counter, the block length and the domain flags, and
//! returns sixteen words, of which the first eight are the chaining value
//! the next block starts from, or the digest when the block is the root.
//! A hash of at most one chunk, which is every hash the verifier of the
//! Blake3 ring computes, is a run of compressions over the input's blocks
//! starting from the IV.

/// Bytes in a block.
pub const BLOCK_LEN: usize = 64;

/// Bytes in a chunk, the most a run of compressions hashes.
pub const CHUNK_LEN: usize = 1024;

/// Words of the output a compression yields.
pub const OUT_WORDS: usize = 16;

/// Words of a chaining value.
pub const CV_WORDS: usize = 8;

/// Words of a block.
pub const BLOCK_WORDS: usize = 16;

pub const CHUNK_START: u32 = 1 << 0;
pub const CHUNK_END: u32 = 1 << 1;
pub const PARENT: u32 = 1 << 2;
pub const ROOT: u32 = 1 << 3;

/// The initialisation vector, the chaining value every hash starts from.
pub const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

/// The message schedule: word `i` of the next round is word `MSG_PERMUTATION[i]`.
pub const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

#[inline]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

/// One compression: `(cv, block, counter, block_len, flags)` to its sixteen
/// output words.
#[must_use]
pub fn compress(
    chaining_value: &[u32; CV_WORDS],
    block: &[u32; BLOCK_WORDS],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; OUT_WORDS] {
    let mut state = [
        chaining_value[0],
        chaining_value[1],
        chaining_value[2],
        chaining_value[3],
        chaining_value[4],
        chaining_value[5],
        chaining_value[6],
        chaining_value[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    let mut m = *block;
    for r in 0..7 {
        round(&mut state, &m);
        if r < 6 {
            m = core::array::from_fn(|i| m[MSG_PERMUTATION[i]]);
        }
    }
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= chaining_value[i];
    }
    state
}

/// The words of a block of at most sixty-four bytes, zero padded.
#[must_use]
pub fn block_words(bytes: &[u8]) -> [u32; BLOCK_WORDS] {
    assert!(bytes.len() <= BLOCK_LEN, "a block holds sixty-four bytes");
    let mut padded = [0u8; BLOCK_LEN];
    padded[..bytes.len()].copy_from_slice(bytes);
    core::array::from_fn(|i| {
        u32::from_le_bytes([padded[4 * i], padded[4 * i + 1], padded[4 * i + 2], padded[4 * i + 3]])
    })
}

/// One compression's inputs: `(cv, block, counter, block_len, flags)`.
pub type Compression = ([u32; CV_WORDS], [u32; BLOCK_WORDS], u64, u32, u32);

/// The compressions a hash of at most one chunk runs, in order, the digest
/// being the first eight output words of the last.  The empty input is one
/// compression of an empty block.
#[must_use]
pub fn chunk_schedule(bytes: &[u8]) -> Vec<Compression> {
    assert!(bytes.len() <= CHUNK_LEN, "a run of compressions hashes at most one chunk");
    let blocks: Vec<&[u8]> =
        if bytes.is_empty() { vec![&[][..]] } else { bytes.chunks(BLOCK_LEN).collect() };
    let last = blocks.len() - 1;
    let mut cv = IV;
    let mut schedule = Vec::with_capacity(blocks.len());
    for (i, block) in blocks.iter().enumerate() {
        let mut flags = 0;
        if i == 0 {
            flags |= CHUNK_START;
        }
        if i == last {
            flags |= CHUNK_END | ROOT;
        }
        let words = block_words(block);
        schedule.push((cv, words, 0u64, block.len() as u32, flags));
        let out = compress(&cv, &words, 0, block.len() as u32, flags);
        cv = core::array::from_fn(|j| out[j]);
    }
    schedule
}

/// The Blake3 digest of at most one chunk of bytes, as eight words.
#[must_use]
pub fn hash_chunk(bytes: &[u8]) -> [u32; CV_WORDS] {
    let (cv, block, counter, len, flags) =
        *chunk_schedule(bytes).last().expect("a schedule has a compression");
    let out = compress(&cv, &block, counter, len, flags);
    core::array::from_fn(|j| out[j])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words_to_bytes(words: &[u32; 8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, w) in words.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    /// The run of compressions matches the reference hash at every length
    /// up to a chunk, including the empty input and exact block multiples.
    #[test]
    fn chunk_hash_matches_the_reference() {
        let data: Vec<u8> =
            (0..CHUNK_LEN as u32).map(|i| (i.wrapping_mul(31) ^ (i >> 3)) as u8).collect();
        for len in [0usize, 1, 3, 4, 31, 32, 63, 64, 65, 100, 127, 128, 129, 500, 1023, 1024] {
            let expected = *blake3::hash(&data[..len]).as_bytes();
            assert_eq!(
                words_to_bytes(&hash_chunk(&data[..len])),
                expected,
                "digest differs at {len} bytes"
            );
        }
    }
}
