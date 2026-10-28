//! Proving lowered relations with the word backend, the committed bits
//! under the binary stage's Boolean WHIR and Blake3 transcript.

use p3_binary_pcs::BooleanBackend;
use p3_word::Word64;
use p3_word_backend::{PackedWitness, WordProof, WordProofKey};
use zkm_binary_stark::{
    challenger,
    config::{bit_commitment, BitPcs},
    BinarySchedule, F,
};

use crate::builder::Built;

/// The commitment of a word proof.
pub type Commitment = <BitPcs as BooleanBackend<F>>::Commitment;

/// A word proof.
pub type Proof = WordProof<F, F, <BitPcs as BooleanBackend<F>>::Proof>;

/// A key, the commitment it is proven under, and its relations.
pub struct WordKey {
    /// The compiled relations.
    pub key: WordProofKey<Word64>,
    /// The commitment of the key's trace.
    pub pcs: BitPcs,
}

impl WordKey {
    /// The key of `built`'s relations under `schedule`.
    pub fn new(built: &Built, schedule: &BinarySchedule) -> Result<Self, String> {
        let key = WordProofKey::new(built.system.clone()).map_err(|e| format!("key: {e:?}"))?;
        let pcs = bit_commitment(key.trace_variables(), schedule).map_err(|e| e.to_string())?;
        Ok(Self { key, pcs })
    }

    /// Proves `built`'s words satisfy the key's relations.
    pub fn prove(&self, built: &Built) -> Result<(Commitment, Proof), String> {
        let values = PackedWitness::new(self.key.statement(), &built.public, &built.witness)
            .map_err(|e| format!("witness: {e:?}"))?;
        self.key
            .prove::<F, F, _, _>(&self.pcs, &values, &mut challenger())
            .map_err(|e| format!("prove: {e:?}"))
    }

    /// Verifies a proof against the public words.
    pub fn verify(
        &self,
        commitment: &Commitment,
        public: &[Word64],
        proof: &Proof,
    ) -> Result<(), String> {
        self.key
            .verify::<F, F, _, _>(&self.pcs, commitment, public, proof, &mut challenger())
            .map_err(|e| format!("verify: {e:?}"))
    }
}

/// The serialized size of a proof, in bytes.
pub fn proof_size(proof: &Proof) -> usize {
    postcard::to_allocvec(proof).map_or(0, |bytes| bytes.len())
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;
    use crate::{builder::Builder, kb::P};

    #[test]
    fn small_relations_prove_and_verify() {
        let mut rng = StdRng::seed_from_u64(4);
        let mut builder = Builder::new(1);
        let mut acc = builder.hint(1);
        for _ in 0..64 {
            let x = builder.hint(rng.gen_range(0..P));
            let y = builder.hint(rng.gen_range(0..P));
            let sum = builder.add(acc, x);
            acc = builder.mul(sum, y);
        }
        let output = builder.output(0, acc.value);
        builder.assert_zero(acc.terms().chain([output]));
        let built = builder.build().unwrap();
        let key = WordKey::new(&built, &BinarySchedule::default()).unwrap();
        let (commitment, proof) = key.prove(&built).unwrap();
        key.verify(&commitment, &built.public, &proof).unwrap();
        let mut wrong = built.public.clone();
        wrong[0] = Word64::new(wrong[0].get() ^ 1);
        assert!(key.verify(&commitment, &wrong, &proof).is_err());
    }
}
