//! The field traits of the binary stage, over traced values.
//!
//! The binary stage's configuration names `GF(2^128)` as its base field,
//! its challenge field and the representation its sumchecks run in.  The
//! recorded verifier names [`Traced`] in all three places, which is the same
//! field, so every trait here is the native implementation's, with the
//! steps that read a representation going through constants or refusing.

use p3_binary_dft::EncodableLevel;
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_binary_pcs::whir::BinaryWhirAlphabet;
use p3_binary_pcs::{ChallengeField, Coordinates};
use p3_challenger::fs::{TranscriptError, TranscriptField, TypeTag};
use p3_challenger::CanObserve;
use zkm_binary_stark::BinaryBase;

use crate::domain::TracedDomain;
use crate::tape::F;
use crate::traced::Traced;

impl BinaryBase for Traced {
    fn from_native(value: F) -> Self {
        Self::constant(value)
    }
}

impl TranscriptField for Traced {
    fn algebra_tag(degree: usize, basis: [u8; 32]) -> TypeTag {
        F::algebra_tag(degree, basis)
    }

    /// The native seeding, whose elements are constants: a seed is a
    /// label, never a proof value.
    fn observe_seed<C: CanObserve<Self>>(challenger: &mut C, bytes: &[u8]) {
        const WIDTH: usize = 16;
        let element = |chunk: &[u8]| {
            let mut padded = [0u8; WIDTH];
            padded[..chunk.len()].copy_from_slice(chunk);
            Self::from_repr(u128::from_le_bytes(padded))
        };
        for chunk in (bytes.len() as u64).to_le_bytes().chunks(WIDTH) {
            challenger.observe(element(chunk));
        }
        for chunk in bytes.chunks(WIDTH) {
            challenger.observe(element(chunk));
        }
    }

    fn wire_len() -> usize {
        F::wire_len()
    }

    /// Encoding reads the representation, so only a constant encodes.
    fn encode(value: &Self, out: &mut Vec<u8>) {
        F::encode(&value.expect_constant("encoding for the transcript"), out);
    }

    fn decode(_bytes: &[u8]) -> Result<Self, TranscriptError> {
        panic!("the recorded verifier reads its proof through serde, not the typed transcript")
    }
}

// SAFETY: the count states the field's dimension, which is not the size of
// a `Traced` (a value and a variable).  Plonky3 pins `COORDINATES == 8 *
// size_of` in a constant evaluated wherever values are packed or unpacked
// by their bytes, so any such use of `Traced` fails to compile rather than
// reading its bytes; the verifier performs none.
unsafe impl Coordinates for Traced {
    const COORDINATES: usize = 128;
}

impl EncodableLevel for Traced {
    type Encoder = TracedDomain;
}

impl BinaryWhirAlphabet for Traced {
    const DOMAIN_ID: &'static [u8] = <BinaryField128 as BinaryWhirAlphabet>::DOMAIN_ID;
}

/// The residual sumchecks run in `GF(2^128)` itself: the native
/// representation is an isomorphic copy, so the transcript is the same.
impl ChallengeField<Traced> for Traced {
    type SumcheckRepr = Self;
}
