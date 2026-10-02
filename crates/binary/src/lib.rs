//! The binary stage: a multi-STARK over `GF(2^128)` whose traces are committed
//! with Boolean WHIR under Blake3, so that its verifier is cheap as a boolean
//! circuit: Blake3 Merkle paths and `GF(2^128)` sumcheck arithmetic, no prime
//! field and no algebraic hash.
//!
//! The stage sits after `compress`: it proves, over bits, the recursion
//! program that verifies the compressed proof, and its proof is what a garbled
//! verifier consumes.  This crate holds the proof system the stage proves
//! under; the AIRs of the recursion machine over bits are built on it.

pub mod arith;
pub mod config;
pub mod machine_builder;
pub mod word;

use p3_binary_field::{BinaryChallenger, BinaryField128, BinaryField2, Ghash128};
use p3_blake3::Blake3;
use p3_challenger::HashChallenger;
use p3_examples::binary::{
    boolean_whir_config, BinaryAir, BinaryProofError, BinaryProofOptions, BinaryWhirBudget,
    BooleanPcsChoice, BooleanWhirStarkConfig, HashFamily, WhirOptions, WhirRegime,
};
use p3_multi_stark::config::{PcsError, PcsProverError};
use p3_multi_stark::{
    prove_with_backend, security_report, setup, verify, MultiStarkProof, ProverInstance,
    ProverInstances, ProvingError, ProvingKey, ReprBackend, SecurityError, SubfieldBackend,
    VerificationError, VerifierInstance, VerifierInstances, VerifyingKey,
};
use p3_sumcheck::layout::Table;
use p3_sumcheck::TableShape;

/// The field every trace cell and every challenge lives in.
pub type F = BinaryField128;

/// The transcript: Blake3 over bytes, sampling `GF(2^128)` challenges.
pub type Challenger = BinaryChallenger<F, HashChallenger<u8, Blake3, 32>>;

/// The configuration the stage proves under: Boolean WHIR with a Blake3
/// Merkle tree of arity 2.
pub type Config = BooleanWhirStarkConfig<Blake3>;

/// A proof of the stage.
pub type Proof = MultiStarkProof<Config>;

/// The proving and verifying keys of an AIR under a [`Config`].
pub type Keys = (ProvingKey<Config>, VerifyingKey<Config>);

/// What proving can fail with.
pub type ProveError = ProvingError<PcsProverError<Config>>;

/// What verification can fail with.
pub type VerifyError = VerificationError<PcsError<Config>>;

/// The domain separator of the stage's transcript.
pub const TRANSCRIPT_DOMAIN: &[u8] = b"zkm-binary-stage-v1";

/// The Boolean WHIR schedule of the stage, with the levers that trade proof
/// size against prover time at a fixed security level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BinarySchedule {
    /// `-log2` of the first oracle's rate.
    pub log_inv_rate: usize,
    /// Variables folded per WHIR round.
    pub folding: usize,
    /// The per-term target the schedule is derived for, under the Johnson
    /// bound.
    pub term_security_bits: usize,
    /// The composed security the whole proof must reach.
    pub security_bits: usize,
    /// Ceilings on queries, proof bytes and grinding.
    pub budget: BinaryWhirBudget,
}

impl Default for BinarySchedule {
    fn default() -> Self {
        Self {
            log_inv_rate: 5,
            folding: 4,
            term_security_bits: 108,
            security_bits: 100,
            budget: BinaryWhirBudget { max_grinding_bits: 27, ..BinaryWhirBudget::PRODUCTION },
        }
    }
}

impl BinarySchedule {
    /// The WHIR options of the schedule.
    #[must_use]
    pub const fn whir(&self) -> WhirOptions {
        WhirOptions {
            regime: WhirRegime::Johnson,
            term_security_bits: self.term_security_bits,
            budget: self.budget,
        }
    }

    /// The proof options of the schedule: Blake3, Merkle arity 2, no
    /// sumcheck grinding.
    #[must_use]
    pub const fn options(&self) -> BinaryProofOptions {
        BinaryProofOptions {
            pcs: BooleanPcsChoice::Whir(self.whir()),
            log_inv_rate: self.log_inv_rate,
            pcs_pow_bits: 0,
            security_bits: self.security_bits,
            folding: self.folding,
            sumcheck_pow_bits: 0,
            merkle_arity: 2,
            hash: HashFamily::Blake3,
            leaf_elements: None,
        }
    }

    /// The configuration of `air` at `shape` under the schedule.
    pub fn config<A: BinaryAir>(
        &self,
        air: &A,
        shape: TableShape,
    ) -> Result<Config, BinaryProofError> {
        boolean_whir_config::<A, Blake3>(air, shape, self.options(), self.whir())
    }
}

/// A fresh transcript of the stage.
#[must_use]
pub fn challenger() -> Challenger {
    Challenger::from_hasher(TRANSCRIPT_DOMAIN.to_vec(), Blake3)
}

/// The proving and verifying keys of `air` under `config`.
pub fn keys<A: BinaryAir>(config: &Config, air: &A) -> Result<Keys, ProveError> {
    setup(config, &[air], &mut challenger())
}

/// The composed security of proving `air` at `2^log_height` rows under
/// `config`, which must reach `security_bits`.
pub fn security<A: BinaryAir>(
    config: &Config,
    air: &A,
    vk: &VerifyingKey<Config>,
    log_height: usize,
    security_bits: usize,
) -> Result<f64, SecurityError> {
    let public_values: [F; 0] = [];
    let instances =
        VerifierInstances::new(vec![VerifierInstance::new(air, vk, log_height, &public_values)]);
    let report = security_report(config, &instances)?;
    report.require_security(security_bits)?;
    Ok(report.security_bits().unwrap_or(0.0))
}

/// Prove `table`, one row per step of `air`, under `config`.
///
/// The polynomial-basis backend runs where the host multiplies in
/// `GF(2^128)` with a carry-less multiply; the subfield backend elsewhere.
pub fn prove<A: BinaryAir>(
    config: &Config,
    air: &A,
    pk: &ProvingKey<Config>,
    table: Table<F>,
) -> Result<Proof, ProveError> {
    let public_values: [F; 0] = [];
    let instances = ProverInstances::new(vec![ProverInstance::new(air, table, pk, &public_values)]);
    if p3_binary_field::poly_basis::HAS_HARDWARE_CLMUL {
        prove_with_backend::<_, _, ReprBackend<BinaryField2, Ghash128, true>>(
            config,
            instances,
            0,
            &mut challenger(),
        )
    } else {
        prove_with_backend::<_, _, SubfieldBackend<BinaryField2>>(
            config,
            instances,
            0,
            &mut challenger(),
        )
    }
}

/// Verify `proof` as a proof of `air` at `2^log_height` rows under `config`.
pub fn verify_proof<A: BinaryAir>(
    config: &Config,
    air: &A,
    vk: &VerifyingKey<Config>,
    log_height: usize,
    proof: &Proof,
) -> Result<(), VerifyError> {
    let public_values: [F; 0] = [];
    let instances =
        VerifierInstances::new(vec![VerifierInstance::new(air, vk, log_height, &public_values)]);
    verify(config, instances, proof, 0, &mut challenger())
}

/// The bytes of `proof`, as the stage ships them.
pub fn encode(proof: &Proof) -> Vec<u8> {
    postcard::to_allocvec(proof).expect("a proof serializes")
}

/// A proof from the bytes [`encode`] produced.
pub fn decode(bytes: &[u8]) -> Result<Proof, postcard::Error> {
    postcard::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use p3_binary_field::Gf2;
    use p3_blake3_air::{Blake3BinaryAir, NUM_BLAKE3_BINARY_COLS};
    use p3_matrix::dense::RowMajorMatrix;

    use super::*;

    /// Upstream's Blake3 compression AIR over bits, proved and verified under
    /// the stage's schedule, with the proof going through its byte encoding.
    #[test]
    fn blake3_air_round_trip() {
        let log_height = 10;
        let air = Blake3BinaryAir::default();
        let shape = TableShape::new(log_height, NUM_BLAKE3_BINARY_COLS);
        let schedule = BinarySchedule::default();
        let config = schedule.config(&air, shape).expect("schedule fits the AIR");
        let (pk, vk) = keys(&config, &air).expect("keys");
        let bits = security(&config, &air, &vk, log_height, schedule.security_bits)
            .expect("the schedule reaches the target");
        let words: RowMajorMatrix<u64> = air.generate_random_trace_packed::<Gf2>(1 << log_height);
        let started = std::time::Instant::now();
        let proof = prove(&config, &air, &pk, Table::<F>::from_packed_bits(words, log_height))
            .expect("proof");
        let prove_secs = started.elapsed().as_secs_f64();
        let bytes = encode(&proof);
        let proof = decode(&bytes).expect("round trip");
        let started = std::time::Instant::now();
        verify_proof(&config, &air, &vk, log_height, &proof).expect("verifies");
        println!(
            "blake3 2^{log_height} rows: {bits:.2} bits, {} proof bytes, prove {prove_secs:.1} s, verify {:.3} s",
            bytes.len(),
            started.elapsed().as_secs_f64()
        );
        assert!(bits >= schedule.security_bits as f64);
    }
}
