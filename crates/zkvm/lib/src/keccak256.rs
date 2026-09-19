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

    // The digest is the first 8 words of the precompile's output. This used to
    // `transmute` `&mut [u32; 17]` into `&mut [u8; 64]` and slice it; the byte
    // order that produced is the target's, and every target this runs on -- the
    // mipsel guest and the host the tests use -- is little-endian, so
    // `to_le_bytes` is the same bytes without the unsafe.
    for (out, word) in keccak256_result.chunks_exact_mut(4).zip(&general_result[..8]) {
        out.copy_from_slice(&word.to_le_bytes());
    }
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
    let total = blocks * STRIDE;
    // Not zero-filled first: on a reth block that memset was ~5.5 M cycles. The
    // buffer is therefore `MaybeUninit<u32>` and stays that way until every slot
    // is written -- `set_len` on a `Vec<u32>` whose elements are uninitialized is
    // instant UB, because uninitialized is not a valid `u32`, and it is what
    // `clippy::uninit_vec` (deny-level, correctness) fires on. The same pattern is
    // already used in `zkm-pcs`'s row-GKR round buffers.
    let mut out_vec: Vec<u32> = Vec::with_capacity(total);
    let words = &mut out_vec.spare_capacity_mut()[..total];

    let mut full = data.chunks_exact(RATE);
    let mut base = 0;
    for block in &mut full {
        let out = &mut words[base..base + STRIDE];
        for (w, chunk) in block.chunks_exact(4).enumerate() {
            out[w].write(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
        out[RATE_WORDS].write(0);
        out[RATE_WORDS + 1].write(0);
        base += STRIDE;
    }

    // The last block: the leftover bytes, then 0x01 right after them, zeros,
    // and 0x80 in the block's final byte (the same byte when 135 bytes are
    // left).
    let rem = full.remainder();
    let out = &mut words[base..base + STRIDE];
    let mut tail = rem.chunks_exact(4);
    let mut w = 0;
    for chunk in &mut tail {
        out[w].write(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        w += 1;
    }
    let mut last = 0u32;
    for (k, &byte) in tail.remainder().iter().enumerate() {
        last |= (byte as u32) << (8 * k);
    }
    last |= 1u32 << (8 * (rem.len() % 4));
    // `w <= RATE_WORDS - 1` always, since `rem.len() < RATE`. When the two
    // coincide the 0x80 lands in the same word as the 0x01, which is the
    // 135-byte case the reference layout also folds together.
    if w == RATE_WORDS - 1 {
        last |= 0x80u32 << 24;
    }
    out[w].write(last);
    for slot in out[w + 1..].iter_mut() {
        slot.write(0);
    }
    if w < RATE_WORDS - 1 {
        out[RATE_WORDS - 1].write(0x80u32 << 24);
    }

    // SAFETY: every one of the `total` slots is written above -- the data words,
    // the two stride words of each block, and the tail, padding and zero fill of
    // the last one -- so the buffer is fully initialized.
    unsafe { out_vec.set_len(total) };
    out_vec
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
