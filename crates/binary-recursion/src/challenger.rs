//! The binary stage's transcript over traced bytes.
//!
//! This is `BinaryChallenger<F, HashChallenger<u8, Blake3, 32>>` step for
//! step: observed elements append their sixteen little-endian bytes to the
//! input, a flush hashes the whole input with Blake3 and the digest becomes
//! both the next input and the bytes to sample, and samples pop bytes from
//! the end of the digest.  The input is kept as the elements and bytes that
//! were observed, so a hash reads whole elements wherever they fall on a
//! sixteen-byte boundary, and every hash is recorded.
//!
//! A sampled index is the one value the verifier uses as an integer: a
//! query position.  Its bits come from sampled bytes, so they are recorded
//! too, and the index is logged with them in [`crate::queries`] for the
//! commitment and the domain to take in the order they were drawn.

use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, CanSampleUniformBits, FieldChallenger,
    GrindingChallenger, ResamplingError,
};
use p3_field::PrimeCharacteristicRing;

use crate::bytes::{blake3, byte_bits, byte_value, constant_byte, digest_bytes, from_bytes, Piece};
use crate::queries;
use crate::traced::Traced;

/// Bytes a sampled index is drawn from.
const INDEX_BYTES: usize = 8;

/// The transcript, over traced values.
#[derive(Clone, Debug)]
pub struct TracedChallenger {
    input: Vec<Piece>,
    output: Vec<Traced>,
}

impl TracedChallenger {
    /// A transcript whose input starts with these bytes, as the binary
    /// stage's starts with its domain separator.
    #[must_use]
    pub fn new(initial: &[u8]) -> Self {
        Self {
            input: initial.iter().map(|&b| Piece::Byte(constant_byte(b))).collect(),
            output: Vec::new(),
        }
    }

    fn flush(&mut self) {
        let digest = blake3(&self.input);
        self.input = digest.map(Piece::Element).to_vec();
        self.output = digest_bytes(digest).to_vec();
    }

    /// Append bytes to the input, discarding the unread output.
    pub fn observe_bytes(&mut self, bytes: &[Traced]) {
        if !bytes.is_empty() {
            self.output.clear();
            self.input.extend(bytes.iter().map(|&b| Piece::Byte(b)));
        }
    }

    /// Append elements' sixteen bytes each to the input, discarding the
    /// unread output.
    pub fn observe_elements(&mut self, elements: &[Traced]) {
        if !elements.is_empty() {
            self.output.clear();
            self.input.extend(elements.iter().map(|&x| Piece::Element(x)));
        }
    }

    /// The next sampled byte.
    pub fn sample_byte(&mut self) -> Traced {
        if self.output.is_empty() {
            self.flush();
        }
        self.output.pop().expect("a flush fills the output")
    }

    /// `bits` bits drawn as an index, with the index's bits, lowest first.
    fn sample_index(&mut self, bits: usize) -> (usize, Vec<Traced>) {
        assert!(bits < usize::BITS as usize, "an index fits a usize");
        let bytes: [Traced; INDEX_BYTES] = core::array::from_fn(|_| self.sample_byte());
        let value = u64::from_le_bytes(bytes.each_ref().map(byte_value));
        let index = usize::try_from(value & ((1u64 << bits) - 1)).expect("fits a usize");
        let index_bits: Vec<Traced> = bytes.into_iter().flat_map(byte_bits).take(bits).collect();
        (index, index_bits)
    }
}

impl CanObserve<Traced> for TracedChallenger {
    fn observe(&mut self, value: Traced) {
        self.observe_elements(&[value]);
    }
}

impl CanObserve<u8> for TracedChallenger {
    fn observe(&mut self, value: u8) {
        self.observe_bytes(&[constant_byte(value)]);
    }
}

impl CanSample<Traced> for TracedChallenger {
    fn sample(&mut self) -> Traced {
        let bytes: [Traced; 16] = core::array::from_fn(|_| self.sample_byte());
        from_bytes(&bytes)
    }
}

impl CanSampleBits<usize> for TracedChallenger {
    /// Draw an index and log it with its bits: the verifier uses an index
    /// only as a query position.
    fn sample_bits(&mut self, bits: usize) -> usize {
        let (index, index_bits) = self.sample_index(bits);
        queries::log(index, index_bits);
        index
    }
}

impl CanSampleUniformBits<Traced> for TracedChallenger {
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        bits: usize,
    ) -> Result<usize, ResamplingError> {
        Ok(self.sample_bits(bits))
    }
}

impl GrindingChallenger for TracedChallenger {
    type Witness = Traced;

    /// Only a prover grinds.
    fn grind(&mut self, _bits: usize) -> Traced {
        panic!("the recorded verifier does not grind")
    }

    /// Observe the witness and require the `bits` bits drawn after it to be
    /// zero, recording each.
    fn check_witness(&mut self, bits: usize, witness: Traced) -> bool {
        if bits == 0 {
            return true;
        }
        self.observe(witness);
        let (index, index_bits) = self.sample_index(bits);
        for bit in &index_bits {
            bit.assert_eq(&Traced::ZERO);
        }
        index == 0
    }
}

impl FieldChallenger<Traced> for TracedChallenger {}

#[cfg(test)]
mod tests {
    use p3_binary_field::{BinaryChallenger, BinaryField128, TowerLevel};
    use p3_blake3::Blake3;
    use p3_challenger::HashChallenger;

    use super::*;
    use crate::tape;

    type Native = BinaryChallenger<BinaryField128, HashChallenger<u8, Blake3, 32>>;

    /// The traced transcript draws what the native one draws through
    /// observations, element and index samples, and a grind.
    #[test]
    fn matches_the_native_transcript() {
        let mut native = Native::from_hasher(b"seed".to_vec(), Blake3);
        let ((), tape) = tape::record(|| {
            let mut traced = TracedChallenger::new(b"seed");
            for i in 0..40u128 {
                let value = BinaryField128::from_repr(i.wrapping_mul(0x9e37_79b9_7f4a_7c15_f39c));
                native.observe(value);
                traced.observe(Traced::input(value));
                if i % 7 == 3 {
                    let x: BinaryField128 = native.sample();
                    assert_eq!(CanSample::<Traced>::sample(&mut traced).value(), x);
                    assert_eq!(traced.sample_bits(19), native.sample_bits(19));
                }
            }
            let witness = native.grind(6);
            assert!(traced.check_witness(6, Traced::input(witness)));
            let x: BinaryField128 = native.sample();
            assert_eq!(CanSample::<Traced>::sample(&mut traced).value(), x);
        });
        assert!(tape.census()[9] > 0, "the transcript's hashes are recorded");
        queries::take();
    }
}
