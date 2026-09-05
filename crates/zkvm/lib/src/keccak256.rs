use crate::syscall_keccak_sponge;

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    if data.is_empty() {
        return [
            0xC5, 0xD2, 0x46, 0x01, 0x86, 0xF7, 0x23, 0x3C, 0x92, 0x7E, 0x7D, 0xB2, 0xDC, 0xC7,
            0x03, 0xC0, 0xE5, 0, 0xB6, 0x53, 0xCA, 0x82, 0x27, 0x3B, 0x7B, 0xFA, 0xD8, 0x04, 0x5D,
            0x85, 0xA4, 0x70,
        ];
    }

    let u32_array = keccak_sponge_words(data);

    let mut general_result = [0u32; 17];
    let mut keccak256_result = [0u8; 32];
    // Write the number which indicate the rate length (bytes) in the first cell of result.
    general_result[16] = u32_array.len() as u32;
    // Call precompile
    unsafe {
        syscall_keccak_sponge(u32_array.as_ptr(), &mut general_result);
    }

    let tmp: &mut [u8; 64] = unsafe { core::mem::transmute(&mut general_result) };
    keccak256_result.copy_from_slice(&tmp[..32]);
    keccak256_result
}

/// The sponge precompile's input for `data`: per 136-byte block, 34
/// little-endian words followed by two zero words (the precompile's state
/// stride), with keccak's `10*1` padding applied in the last block.
///
/// Built straight from the input slice: the previous version copied the data
/// into a padded `Vec<u8>`, zero-filled it, then pushed the words one at a
/// time — ~30 M cycles of copies and pushes on a reth block that hashes
/// ~5 MB.  Kept as a pure function so the layout is testable natively.
pub fn keccak_sponge_words(data: &[u8]) -> Vec<u32> {
    const RATE: usize = 136;
    const RATE_WORDS: usize = RATE / 4;
    const STRIDE: usize = RATE_WORDS + 2;

    let blocks = data.len() / RATE + 1;
    let mut words = vec![0u32; blocks * STRIDE];

    let mut full = data.chunks_exact(RATE);
    let mut base = 0;
    for block in &mut full {
        let out = &mut words[base..base + RATE_WORDS];
        for (w, chunk) in block.chunks_exact(4).enumerate() {
            out[w] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        base += STRIDE;
    }

    // The last block: the leftover bytes, then 0x01 right after them and
    // 0x80 in the block's final byte (the same byte when 135 bytes are left).
    let rem = full.remainder();
    let out = &mut words[base..base + RATE_WORDS];
    let mut tail = rem.chunks_exact(4);
    let mut w = 0;
    for chunk in &mut tail {
        out[w] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        w += 1;
    }
    let mut last = 0u32;
    for (k, &byte) in tail.remainder().iter().enumerate() {
        last |= (byte as u32) << (8 * k);
    }
    out[w] = last | (1u32 << (8 * (rem.len() % 4)));
    out[RATE_WORDS - 1] |= 0x80u32 << 24;
    words
}

#[cfg(test)]
mod tests {
    use super::keccak_sponge_words;

    /// The layout the precompile has always been fed (the previous builder).
    fn reference(data: &[u8]) -> Vec<u32> {
        let len = data.len();
        let final_block_len = len % 136;
        let padded_len = len - final_block_len + 136;
        let mut padded_data = Vec::with_capacity(padded_len);
        padded_data.extend_from_slice(data);
        padded_data.resize(padded_len, 0);
        if len % 136 == 135 {
            padded_data[padded_len - 1] = 0b10000001;
        } else {
            padded_data[len] = 1;
            padded_data[padded_len - 1] = 0b10000000;
        }
        let mut u32_array = Vec::new();
        let mut count = 0;
        for chunk in padded_data.chunks_exact(4) {
            u32_array.push(u32::from_be_bytes([chunk[3], chunk[2], chunk[1], chunk[0]]));
            count += 1;
            if count == 34 {
                u32_array.extend_from_slice(&[0, 0]);
                count = 0;
            }
        }
        u32_array
    }

    #[test]
    fn sponge_words_match_the_reference_layout() {
        let mut state = 0x9e3779b9u32;
        let data: Vec<u8> = (0..1000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        for len in 0..=600 {
            assert_eq!(keccak_sponge_words(&data[..len]), reference(&data[..len]), "len {len}");
        }
        assert_eq!(keccak_sponge_words(&data), reference(&data));
    }
}
