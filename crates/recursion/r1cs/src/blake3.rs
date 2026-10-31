//! The Blake3 compression on words: each 32-bit state word sits in a lane
//! of a word, a 32-bit addition is one lane carry chain, and XOR and the
//! rotations are free.  A compression is 7 rounds of 8 G functions of 6
//! additions: 336 AND relations, which two compressions share by running
//! in the two lanes.
//!
//! A compression's output words are committed when it is met, from their
//! native values, so its relations can be emitted later, together with
//! any other compression, whatever the dependencies between them.
//!
//! Every input of a compression is one committed word, constants read from
//! their pool words, and a compression left without a partner runs beside a
//! constant one: every pair of compressions is then the same relations over
//! different words.

use p3_word::ShiftKind;
use zkm_recursion_core::runtime::blake3::{compress, IV, MSG_PERMUTATION};

use crate::builder::{lane_add, Builder, Val};

/// A compression whose relations are not emitted yet: its inputs, the counter, block length
/// and flags last, and its outputs, each one committed word.
pub(crate) struct Compression {
    chaining_value: [Val; 8],
    block: [Val; 16],
    parameters: [Val; 3],
    out: [Val; 8],
}

impl Builder {
    fn add32(&mut self, x: Val, y: Val) -> Val {
        if x.constant && y.constant {
            return self.constant(lane_add(x.value, y.value));
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

    /// The first eight output words of one compression, each a committed
    /// word below `2^32`; the relations follow when a second compression
    /// can share them, or at [`Builder::flush_compressions`].
    pub fn blake3_compress(
        &mut self,
        chaining_value: [Val; 8],
        block: [Val; 16],
        counter: u32,
        block_len: u32,
        flags: u32,
    ) -> [Val; 8] {
        let native = compress(
            &chaining_value.map(|v| v.value as u32),
            &block.map(|v| v.value as u32),
            u64::from(counter),
            block_len,
            flags,
        );
        let out = std::array::from_fn(|i| {
            let word = self.word(u64::from(native[i]));
            let term = word.plain().expect("a fresh word is plain");
            self.below_bits(term, 32);
            word
        });
        let chaining_value = chaining_value.map(|value| self.port(value));
        let block = block.map(|value| self.port(value));
        let parameters = [counter, block_len, flags].map(|value| self.pool_word(u64::from(value)));
        self.push_compression(Compression { chaining_value, block, parameters, out });
        out
    }

    fn push_compression(&mut self, compression: Compression) {
        self.compressions.push(compression);
        if self.compressions.len() == 2 {
            let second = self.compressions.pop().expect("two compressions");
            let first = self.compressions.pop().expect("two compressions");
            self.emit_compressions(&first, &second);
        }
    }

    /// Emits the relations of a compression still waiting for a partner, beside the
    /// compression of zeros, whose outputs are constants.
    pub fn flush_compressions(&mut self) {
        if self.compressions.is_empty() {
            return;
        }
        self.begin_gadget("Blake3Pad");
        let native = compress(&[0; 8], &[0; 16], 0, 0, 0);
        let zero = self.pool_word(0);
        let parameters = [zero; 3];
        let out = std::array::from_fn(|i| self.pool_word(u64::from(native[i])));
        self.end_gadget();
        self.push_compression(Compression {
            chaining_value: [zero; 8],
            block: [zero; 16],
            parameters,
            out,
        });
    }

    /// `low` in the low lane and `high` in the high lane, both below `2^32`.
    pub(crate) fn lanes(&mut self, low: Val, high: Option<Val>) -> Val {
        let low = self.materialize(low);
        match high {
            None => low,
            Some(high) => {
                let high = self.materialize(high);
                let moved = self.shifted(high, ShiftKind::LogicalLeft, 32);
                self.xor(low, moved)
            }
        }
    }

    fn lane_constant(&mut self, low: u32, high: Option<u32>) -> Val {
        self.constant(u64::from(low) | (u64::from(high.unwrap_or(0)) << 32))
    }

    fn emit_compressions(&mut self, first: &Compression, second: &Compression) {
        self.begin_gadget("Blake3Compress");
        let [first, second] = [first, second].map(|compression| Compression {
            chaining_value: compression.chaining_value.map(|value| self.port_copy(value)),
            block: compression.block.map(|value| self.port_copy(value)),
            parameters: compression.parameters.map(|value| self.port_copy(value)),
            out: compression.out.map(|value| self.port_copy(value)),
        });
        let chaining_value: [Val; 8] = std::array::from_fn(|i| {
            self.lanes(first.chaining_value[i], Some(second.chaining_value[i]))
        });
        let mut message: [Val; 16] =
            std::array::from_fn(|i| self.lanes(first.block[i], Some(second.block[i])));
        let mut state: [Val; 16] = std::array::from_fn(|i| match i {
            0..=7 => chaining_value[i],
            8..=11 => self.lane_constant(IV[i - 8], Some(IV[i - 8])),
            12 => self.lanes(first.parameters[0], Some(second.parameters[0])),
            13 => Val::ZERO,
            14 => self.lanes(first.parameters[1], Some(second.parameters[1])),
            _ => self.lanes(first.parameters[2], Some(second.parameters[2])),
        });
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
        for i in 0..8 {
            let mixed = self.xor(state[i], state[i + 8]);
            let out = self.lanes(first.out[i], Some(second.out[i]));
            debug_assert_eq!(mixed.value, out.value, "the lanes compute the committed outputs");
            self.assert_zero(mixed.terms().chain(out.terms()));
        }
        self.end_gadget();
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
            let out = builder.blake3_compress(cv_vals, block_vals, 0, 64, flags);
            let expected = compress(&cv, &block, 0, 64, flags);
            for (word, limb_pair) in out.iter().zip(expected) {
                assert_eq!(word.value, u64::from(limb_pair));
                let [low, high] = builder.word_to_limbs(*word);
                assert_eq!(low.value | (high.value << 16), u64::from(limb_pair));
            }
        }
        let before = builder.cost();
        builder.flush_compressions();
        assert_eq!((builder.cost() - before).and, 0, "the two compressions shared their lanes");
        let (built, tape) = builder.build_with_tape().unwrap();
        assert_eq!(built.system.and_constraints().len(), 336);
        built.system.verify(&built.public, &built.witness).unwrap();
        crate::tape::tests::computes(&built, &tape);
    }

    #[test]
    fn a_lone_compression_runs_beside_the_compression_of_zeros() {
        let mut builder = Builder::new(0);
        let words: [Val; 24] = std::array::from_fn(|i| builder.word(0x9E37_79B9 ^ i as u64));
        let cv: [Val; 8] = std::array::from_fn(|i| words[i]);
        let block: [Val; 16] = std::array::from_fn(|i| words[8 + i]);
        let out = builder.blake3_compress(cv, block, 7, 32, CHUNK_START);
        builder.flush_compressions();
        let expected = compress(
            &cv.map(|v| v.value as u32),
            &block.map(|v| v.value as u32),
            7,
            32,
            CHUNK_START,
        );
        assert_eq!(out.map(|v| v.value as u32), expected[..8]);
        let built = builder.build().unwrap();
        built.system.verify(&built.public, &built.witness).unwrap();
    }
}
