//! The Blake3 compression on words: each 32-bit state word sits in the low
//! lane of a word, a 32-bit addition is one lane carry chain, and XOR and
//! the rotations are free.  A compression is 7 rounds of 8 G functions of
//! 6 additions: 336 AND relations.

use p3_word::ShiftKind;
use zkm_recursion_core::runtime::blake3::{IV, MSG_PERMUTATION};

use crate::builder::{Builder, Val};

impl Builder {
    fn add32(&mut self, x: Val, y: Val) -> Val {
        if x.constant && y.constant {
            return self.constant(u64::from((x.value as u32).wrapping_add(y.value as u32)));
        }
        self.add_word(x, y, true)
    }

    fn xor_rotate(&mut self, x: Val, y: Val, amount: usize) -> Val {
        let mixed = self.xor(x, y);
        let rotated = self.shifted(mixed, ShiftKind::Lane32RotateRight, amount);
        self.materialize(rotated)
    }

    #[allow(clippy::too_many_arguments)]
    fn g(
        &mut self,
        state: &mut [Val; 16],
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        mx: Val,
        my: Val,
    ) {
        let sum = self.add32(state[a], state[b]);
        state[a] = self.add32(sum, mx);
        state[d] = self.xor_rotate(state[d], state[a], 16);
        state[c] = self.add32(state[c], state[d]);
        state[b] = self.xor_rotate(state[b], state[c], 12);
        let sum = self.add32(state[a], state[b]);
        state[a] = self.add32(sum, my);
        state[d] = self.xor_rotate(state[d], state[a], 8);
        state[c] = self.add32(state[c], state[d]);
        state[b] = self.xor_rotate(state[b], state[c], 7);
    }

    /// The first eight output words of one compression, each a single word
    /// in the low lane.
    pub fn blake3_compress(
        &mut self,
        chaining_value: [Val; 8],
        block: [Val; 16],
        counter: u32,
        block_len: u32,
        flags: u32,
    ) -> [Val; 8] {
        let mut state: [Val; 16] = std::array::from_fn(|i| match i {
            0..8 => chaining_value[i],
            8..12 => self.constant(u64::from(IV[i - 8])),
            12 => self.constant(u64::from(counter)),
            13 => Val::ZERO,
            14 => self.constant(u64::from(block_len)),
            _ => self.constant(u64::from(flags)),
        });
        let mut message = block;
        for round in 0..7 {
            let m = message;
            self.g(&mut state, 0, 4, 8, 12, m[0], m[1]);
            self.g(&mut state, 1, 5, 9, 13, m[2], m[3]);
            self.g(&mut state, 2, 6, 10, 14, m[4], m[5]);
            self.g(&mut state, 3, 7, 11, 15, m[6], m[7]);
            self.g(&mut state, 0, 5, 10, 15, m[8], m[9]);
            self.g(&mut state, 1, 6, 11, 12, m[10], m[11]);
            self.g(&mut state, 2, 7, 8, 13, m[12], m[13]);
            self.g(&mut state, 3, 4, 9, 14, m[14], m[15]);
            if round < 6 {
                message = std::array::from_fn(|i| m[MSG_PERMUTATION[i]]);
            }
        }
        std::array::from_fn(|i| {
            let mixed = self.xor(state[i], state[i + 8]);
            self.materialize(mixed)
        })
    }

    /// The 32-bit word of two 16-bit limbs, low limb first; a limb not
    /// known to be narrow is checked to be.
    pub fn limbs_to_word(&mut self, low: Val, high: Val) -> Val {
        let low = self.narrow(low);
        let high = self.narrow(high);
        let moved = self.shifted(high, ShiftKind::LogicalLeft, 16);
        self.xor(low, moved)
    }

    fn narrow(&mut self, limb: Val) -> Val {
        if limb.narrow || limb.is_zero() {
            return limb;
        }
        let limb = self.materialize(limb);
        let excess = self.shifted(limb, ShiftKind::LogicalRight, 16);
        self.assert_zero(excess.terms());
        limb.narrowed()
    }

    /// The two 16-bit limbs of a value below `2^32`, low limb first.
    pub fn word_to_limbs(&mut self, word: Val) -> [Val; 2] {
        let low_bits = self.shifted(word, ShiftKind::LogicalLeft, 48);
        let low = self.shifted(low_bits, ShiftKind::LogicalRight, 48);
        let high = self.shifted(word, ShiftKind::LogicalRight, 16);
        [low.narrowed(), high.narrowed()]
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use zkm_recursion_core::runtime::blake3::{compress, CHUNK_END, CHUNK_START, ROOT};

    use super::*;

    #[test]
    fn compression_matches_the_runtime() {
        let mut rng = StdRng::seed_from_u64(3);
        let mut builder = Builder::new(0);
        for flags in [CHUNK_START, CHUNK_START | CHUNK_END | ROOT] {
            let cv: [u32; 8] = std::array::from_fn(|_| rng.gen());
            let block: [u32; 16] = std::array::from_fn(|_| rng.gen());
            let limbs = |builder: &mut Builder, word: u32| {
                let low = builder.word(u64::from(word & 0xFFFF));
                let high = builder.word(u64::from(word >> 16));
                builder.limbs_to_word(low, high)
            };
            let cv_vals = cv.map(|w| limbs(&mut builder, w));
            let block_vals = block.map(|w| limbs(&mut builder, w));
            let before = builder.cost();
            let out = builder.blake3_compress(cv_vals, block_vals, 0, 64, flags);
            assert_eq!((builder.cost() - before).and, 336);
            let expected = compress(&cv, &block, 0, 64, flags);
            for (word, limb_pair) in out.iter().zip(expected) {
                assert_eq!(word.value, u64::from(limb_pair));
                let [low, high] = builder.word_to_limbs(*word);
                assert_eq!(low.value | (high.value << 16), u64::from(limb_pair));
            }
        }
        let built = builder.build().unwrap();
        built.system.verify(&built.public, &built.witness).unwrap();
    }
}
