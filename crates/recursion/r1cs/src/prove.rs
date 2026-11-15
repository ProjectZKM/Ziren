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

/// The deferred values as the prover knows them.
pub type Hints = p3_word_backend::ShiftHints<F>;

/// The schedule a word proof commits under.
///
/// Decoding to the proven Johnson radius halves the queries of unique
/// decoding, which keeps a leaf's opening under the proof-size ceiling.
pub fn schedule() -> BinarySchedule {
    BinarySchedule {
        regime: zkm_binary_stark::WhirRegime::Johnson,
        log_inv_rate: 2,
        folding: 3,
        ..BinarySchedule::default()
    }
}

/// A key, the commitment it is proven under, and its relations.
pub struct WordKey {
    /// The compiled relations.
    pub key: WordProofKey<Word64>,
    /// The commitment of the key's trace.
    pub pcs: BitPcs,
    /// The key's constants: its public words past the outputs.
    pub constants: Vec<Word64>,
    /// The number of outputs, the public words before the constants.
    pub outputs: usize,
    /// The Blake3 digest naming the key: of a tag, the commitment's
    /// variables, the outputs, the constants and the relations.
    pub digest: [u8; 32],
}

impl WordKey {
    /// The key of `built`'s relations under `schedule`, whose first
    /// `outputs` public words are outputs.
    pub fn new(built: &Built, schedule: &BinarySchedule) -> Result<Self, String> {
        Self::with_outputs(built, schedule, zkm_recursion_core::DIGEST_SIZE)
    }

    /// [`Self::new`] for `outputs` public words before the constants.
    pub fn with_outputs(
        built: &Built,
        schedule: &BinarySchedule,
        outputs: usize,
    ) -> Result<Self, String> {
        let key = WordProofKey::new(built.system.clone()).map_err(|e| format!("key: {e:?}"))?;
        let pcs = bit_commitment(key.trace_variables(), schedule).map_err(|e| e.to_string())?;
        let outputs = outputs.min(built.public.len());
        let constants = built.public[outputs..].to_vec();
        let digest = relations_digest(built, outputs);
        Ok(Self { key, pcs, constants, outputs, digest })
    }

    /// The statement's public words for the outputs `outputs`.
    pub fn public(&self, outputs: &[Word64]) -> Vec<Word64> {
        outputs.iter().chain(&self.constants).copied().collect()
    }

    /// Proves `built`'s words satisfy the key's relations.
    pub fn prove(&self, built: &Built) -> Result<(Commitment, Proof, Hints), String> {
        let values = PackedWitness::new(self.key.statement(), &built.public, &built.witness)
            .map_err(|e| format!("witness: {e:?}"))?;
        self.key
            .prove_with_hints::<F, F, _, _>(&self.pcs, &values, &mut challenger())
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

/// The digest naming the key of `built`'s relations with `outputs` outputs:
/// the dimensions, the constants and the relations as [`Built::write`]
/// writes them.  The key's commitment is a function of them.
#[must_use]
pub fn relations_digest(built: &Built, outputs: usize) -> [u8; 32] {
    let system = &built.system;
    let outputs = outputs.min(built.public.len());
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ziren word key");
    for count in [
        outputs,
        built.public.len(),
        built.witness.len(),
        system.zero_constraints().len(),
        system.and_constraints().len(),
        system.integer_mul_constraints().len(),
    ] {
        hasher.update(&(count as u64).to_le_bytes());
    }
    for word in &built.public[outputs..] {
        hasher.update(&word.get().to_le_bytes());
    }
    let mut out = std::io::BufWriter::with_capacity(1 << 20, &mut hasher);
    built.write_relations(&mut out).expect("hashing does not fail");
    drop(out);
    *hasher.finalize().as_bytes()
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
        let key = WordKey::new(&built, &schedule()).unwrap();
        let (commitment, proof, _) = key.prove(&built).unwrap();
        key.verify(&commitment, &built.public, &proof).unwrap();
        let mut wrong = built.public.clone();
        wrong[0] = Word64::new(wrong[0].get() ^ 1);
        assert!(key.verify(&commitment, &wrong, &proof).is_err());
    }

    /// The opening's queries, grinding and byte bound at the leaf's arity, per schedule.
    #[test]
    #[ignore]
    fn leaf_schedule_sizes() {
        let arity = std::env::var("ZIREN_WORD_ARITY").map_or(31, |a| a.parse().unwrap());
        for regime in
            [zkm_binary_stark::WhirRegime::UniqueDecoding, zkm_binary_stark::WhirRegime::Johnson]
        {
            for log_inv_rate in 1..=6 {
                for folding in 2..=8 {
                    let schedule =
                        BinarySchedule { regime, log_inv_rate, folding, ..Default::default() };
                    match bit_commitment(arity, &schedule) {
                        Ok(pcs) => {
                            let shape = pcs
                                .proof_shape(1, false)
                                .expect("a built schedule has a shape");
                            println!(
                                "{regime:?} rate 2^-{log_inv_rate} fold {folding}: {} queries, {} grind bits, {} bytes",
                                shape.stir_queries,
                                shape.grinding_bits,
                                shape.max_bytes(19, 19, 32).expect("the shape fits a usize")
                            );
                        }
                        Err(e) => println!("{regime:?} rate 2^-{log_inv_rate} fold {folding}: {e}"),
                    }
                }
            }
        }
    }
}
