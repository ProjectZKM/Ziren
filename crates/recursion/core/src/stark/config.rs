use p3_bn254_fr::{Bn254, Poseidon2Bn254};
use p3_challenger::MultiField32Challenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{extension::{BinomialExtensionField, QuinticTrinomialExtensionField}, PrimeCharacteristicRing};
use p3_commit::BatchOpening;
use p3_fri::{CommitPhaseProofStep, FriParameters, FriProof, QueryProof, TwoAdicFriPcs};
use p3_koala_bear::KoalaBear;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2::ExternalLayerConstants;
use p3_symmetric::{Hash, MultiField32PaddingFreeSponge, TruncatedPermutation};
use serde::{Deserialize, Serialize};
use zkm_stark::{Com, StarkGenericConfig, ZeroCommitment};

use super::{poseidon2::bn254_poseidon2_rc3, zkm_dev_mode};

pub const DIGEST_SIZE: usize = 1;

pub const OUTER_MULTI_FIELD_CHALLENGER_WIDTH: usize = 3;
pub const OUTER_MULTI_FIELD_CHALLENGER_RATE: usize = 2;
pub const OUTER_MULTI_FIELD_CHALLENGER_DIGEST_SIZE: usize = 1;

/// A configuration for outer recursion.
pub type OuterVal = KoalaBear;
pub type OuterChallenge = BinomialExtensionField<OuterVal, 4>;
pub type OuterPerm = Poseidon2Bn254<3>;
pub type OuterHash =
    MultiField32PaddingFreeSponge<OuterVal, Bn254, OuterPerm, 3, 16, DIGEST_SIZE>;
pub type OuterDigestHash = Hash<OuterVal, Bn254, DIGEST_SIZE>;
pub type OuterDigest = [Bn254; DIGEST_SIZE];
pub type OuterCompress = TruncatedPermutation<OuterPerm, 2, 1, 3>;
pub type OuterValMmcs = MerkleTreeMmcs<KoalaBear, Bn254, OuterHash, OuterCompress, 2, DIGEST_SIZE>;
pub type OuterChallengeMmcs = ExtensionMmcs<OuterVal, OuterChallenge, OuterValMmcs>;
pub type OuterDft = Radix2DitParallel<OuterVal>;
pub type OuterChallenger = MultiField32Challenger<
    OuterVal,
    Bn254,
    OuterPerm,
    OUTER_MULTI_FIELD_CHALLENGER_WIDTH,
    OUTER_MULTI_FIELD_CHALLENGER_RATE,
>;
pub type OuterPcs = TwoAdicFriPcs<OuterVal, OuterDft, OuterValMmcs, OuterChallengeMmcs>;

pub type OuterInputProof = Vec<BatchOpening<OuterVal, OuterValMmcs>>;

pub type OuterQueryProof = QueryProof<OuterChallenge, OuterChallengeMmcs, OuterInputProof>;
pub type OuterCommitPhaseStep = CommitPhaseProofStep<OuterChallenge, OuterChallengeMmcs>;
pub type OuterFriProof = FriProof<OuterChallenge, OuterChallengeMmcs, OuterVal, OuterInputProof>;
pub type OuterBatchOpening = BatchOpening<OuterVal, OuterValMmcs>;
pub type OuterPcsProof = <OuterPcs as p3_commit::Pcs<OuterChallenge, OuterChallenger>>::Proof;

// ── Quintic extension outer types (D=5, 128-bit security) ─────────────────
pub type Outer128Challenge = QuinticTrinomialExtensionField<OuterVal>;
pub type Outer128ChallengeMmcs = ExtensionMmcs<OuterVal, Outer128Challenge, OuterValMmcs>;
pub type Outer128Pcs = TwoAdicFriPcs<OuterVal, OuterDft, OuterValMmcs, Outer128ChallengeMmcs>;

pub type Outer128InputProof = Vec<BatchOpening<OuterVal, OuterValMmcs>>;
pub type Outer128QueryProof = QueryProof<Outer128Challenge, Outer128ChallengeMmcs, Outer128InputProof>;
pub type Outer128CommitPhaseStep = CommitPhaseProofStep<Outer128Challenge, Outer128ChallengeMmcs>;
pub type Outer128FriProof = FriProof<Outer128Challenge, Outer128ChallengeMmcs, OuterVal, Outer128InputProof>;
pub type Outer128BatchOpening = BatchOpening<OuterVal, OuterValMmcs>;
pub type Outer128PcsProof = <Outer128Pcs as p3_commit::Pcs<Outer128Challenge, OuterChallenger>>::Proof;

/// The permutation for outer recursion.
pub fn outer_perm() -> OuterPerm {
    const ROUNDS_F: usize = 8;
    const ROUNDS_P: usize = 56;
    let mut round_constants = bn254_poseidon2_rc3();
    let internal_start = ROUNDS_F / 2;
    let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
    let internal_round_constants =
        round_constants.drain(internal_start..internal_end).map(|vec| vec[0]).collect::<Vec<_>>();
    let external_round_constants = ExternalLayerConstants::new(
        round_constants[..(ROUNDS_F / 2)].to_vec(),
        round_constants[(ROUNDS_F / 2)..].to_vec(),
    );

    OuterPerm::new(external_round_constants, internal_round_constants)
}

/// The FRI config for outer recursion.
/// This targets by default 100 bits of security.
pub fn outer_fri_config() -> FriParameters<OuterChallengeMmcs> {
    let perm = outer_perm();
    let hash = OuterHash::new(perm.clone()).unwrap();
    let compress = OuterCompress::new(perm.clone());
    let challenge_mmcs = OuterChallengeMmcs::new(OuterValMmcs::new(hash, compress, 0));
    let num_queries = if zkm_dev_mode() {
        1
    } else {
        match std::env::var("FRI_QUERIES") {
            Ok(value) => value.parse().unwrap(),
            Err(_) => 21,
        }
    };
    FriParameters { log_blowup: 4, log_final_poly_len: 0, max_log_arity: 1, num_queries, commit_proof_of_work_bits: 16, query_proof_of_work_bits: 16, mmcs: challenge_mmcs }
}

/// The FRI config for outer recursion.
/// This targets by default 100 bits of security.
pub fn outer_fri_config_with_blowup(log_blowup: usize) -> FriParameters<OuterChallengeMmcs> {
    let perm = outer_perm();
    let hash = OuterHash::new(perm.clone()).unwrap();
    let compress = OuterCompress::new(perm.clone());
    let challenge_mmcs = OuterChallengeMmcs::new(OuterValMmcs::new(hash, compress, 0));
    let num_queries = if zkm_dev_mode() {
        1
    } else {
        match std::env::var("FRI_QUERIES") {
            Ok(value) => value.parse().unwrap(),
            Err(_) => 84 / log_blowup,
        }
    };
    FriParameters { log_blowup, log_final_poly_len: 0, max_log_arity: 1, num_queries, commit_proof_of_work_bits: 16, query_proof_of_work_bits: 16, mmcs: challenge_mmcs }
}

#[derive(Deserialize)]
#[serde(from = "std::marker::PhantomData<KoalaBearPoseidon2Outer>")]
pub struct KoalaBearPoseidon2Outer {
    pub perm: OuterPerm,
    pub pcs: OuterPcs,
    fri_config: FriParameters<OuterChallengeMmcs>,
}

impl Clone for KoalaBearPoseidon2Outer {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl Serialize for KoalaBearPoseidon2Outer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        std::marker::PhantomData::<KoalaBearPoseidon2Outer>.serialize(serializer)
    }
}

impl From<std::marker::PhantomData<KoalaBearPoseidon2Outer>> for KoalaBearPoseidon2Outer {
    fn from(_: std::marker::PhantomData<KoalaBearPoseidon2Outer>) -> Self {
        Self::new()
    }
}

impl KoalaBearPoseidon2Outer {
    pub fn new() -> Self {
        let perm = outer_perm();
        let hash = OuterHash::new(perm.clone()).unwrap();
        let compress = OuterCompress::new(perm.clone());
        let val_mmcs = OuterValMmcs::new(hash, compress, 0);
        let dft = OuterDft::default();
        let fri_config = outer_fri_config();
        let pcs = OuterPcs::new(dft, val_mmcs, fri_config.clone());
        Self { pcs, perm, fri_config }
    }

    /// Get a reference to the FRI configuration.
    pub fn get_fri_config(&self) -> &FriParameters<OuterChallengeMmcs> {
        &self.fri_config
    }
    pub fn new_with_log_blowup(log_blowup: usize) -> Self {
        let perm = outer_perm();
        let hash = OuterHash::new(perm.clone()).unwrap();
        let compress = OuterCompress::new(perm.clone());
        let val_mmcs = OuterValMmcs::new(hash, compress, 0);
        let dft = OuterDft::default();
        let fri_config = outer_fri_config_with_blowup(log_blowup);
        let pcs = OuterPcs::new(dft, val_mmcs, fri_config.clone());
        Self { pcs, perm, fri_config }
    }
}

impl Default for KoalaBearPoseidon2Outer {
    fn default() -> Self {
        Self::new()
    }
}

impl StarkGenericConfig for KoalaBearPoseidon2Outer {
    type Val = OuterVal;
    type Domain = <OuterPcs as p3_commit::Pcs<OuterChallenge, OuterChallenger>>::Domain;
    type Pcs = OuterPcs;
    type Challenge = OuterChallenge;
    type Challenger = OuterChallenger;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn challenger(&self) -> Self::Challenger {
        OuterChallenger::new(self.perm.clone()).unwrap()
    }
}

impl ZeroCommitment<KoalaBearPoseidon2Outer> for OuterPcs {
    fn zero_commitment(&self) -> Com<KoalaBearPoseidon2Outer> {
        Com::<KoalaBearPoseidon2Outer>::default()
    }
}

/// The FRI config for testing recursion.
pub fn test_fri_config() -> FriParameters<OuterChallengeMmcs> {
    let perm = outer_perm();
    let hash = OuterHash::new(perm.clone()).unwrap();
    let compress = OuterCompress::new(perm.clone());
    let challenge_mmcs = OuterChallengeMmcs::new(OuterValMmcs::new(hash, compress, 0));
    FriParameters { log_blowup: 1, log_final_poly_len: 0, max_log_arity: 1, num_queries: 1, commit_proof_of_work_bits: 1, query_proof_of_work_bits: 1, mmcs: challenge_mmcs }
}

// ── D=5 outer config (128-bit security) ───────────────────────────────────

/// FRI config for outer recursion with D=5 quintic extension.
///
/// `security_bits`: target security level (e.g. 100, 128).
pub fn outer_fri_config_d5(security_bits: usize) -> FriParameters<Outer128ChallengeMmcs> {
    let perm = outer_perm();
    let hash = OuterHash::new(perm.clone()).unwrap();
    let compress = OuterCompress::new(perm.clone());
    let challenge_mmcs = Outer128ChallengeMmcs::new(OuterValMmcs::new(hash, compress, 0));

    let pow_bits: usize = 16;
    let log_blowup: usize = 1;

    let protocol_bits = security_bits.saturating_sub(pow_bits);
    let num_queries = if zkm_dev_mode() {
        1
    } else {
        match std::env::var("FRI_QUERIES") {
            Ok(value) => value.parse().unwrap(),
            Err(_) => {
                let rate = 1.0 / (1u64 << log_blowup) as f64;
                let delta = 0.5 * (1.0 - rate);
                let log_1_delta = (1.0 - delta).log2();
                (-(protocol_bits as f64) / log_1_delta).ceil() as usize
            }
        }
    };

    FriParameters {
        log_blowup,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: pow_bits,
        mmcs: challenge_mmcs,
    }
}

#[derive(Deserialize)]
#[serde(from = "std::marker::PhantomData<KoalaBearPoseidon2OuterD5>")]
pub struct KoalaBearPoseidon2OuterD5 {
    pub perm: OuterPerm,
    pub pcs: Outer128Pcs,
    fri_config: FriParameters<Outer128ChallengeMmcs>,
}

impl Clone for KoalaBearPoseidon2OuterD5 {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl Serialize for KoalaBearPoseidon2OuterD5 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        std::marker::PhantomData::<KoalaBearPoseidon2OuterD5>.serialize(serializer)
    }
}

impl From<std::marker::PhantomData<KoalaBearPoseidon2OuterD5>> for KoalaBearPoseidon2OuterD5 {
    fn from(_: std::marker::PhantomData<KoalaBearPoseidon2OuterD5>) -> Self {
        Self::new()
    }
}

impl KoalaBearPoseidon2OuterD5 {
    pub fn new() -> Self {
        let perm = outer_perm();
        let hash = OuterHash::new(perm.clone()).unwrap();
        let compress = OuterCompress::new(perm.clone());
        let val_mmcs = OuterValMmcs::new(hash, compress, 0);
        let dft = OuterDft::default();
        let fri_config = outer_fri_config_d5(128);
        let pcs = Outer128Pcs::new(dft, val_mmcs, fri_config.clone());
        Self { pcs, perm, fri_config }
    }

    pub fn get_fri_config(&self) -> &FriParameters<Outer128ChallengeMmcs> {
        &self.fri_config
    }
}

impl Default for KoalaBearPoseidon2OuterD5 {
    fn default() -> Self {
        Self::new()
    }
}

impl StarkGenericConfig for KoalaBearPoseidon2OuterD5 {
    type Val = OuterVal;
    type Domain = <Outer128Pcs as p3_commit::Pcs<Outer128Challenge, OuterChallenger>>::Domain;
    type Pcs = Outer128Pcs;
    type Challenge = Outer128Challenge;
    type Challenger = OuterChallenger;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn challenger(&self) -> Self::Challenger {
        OuterChallenger::new(self.perm.clone()).unwrap()
    }
}

impl ZeroCommitment<KoalaBearPoseidon2OuterD5> for Outer128Pcs {
    fn zero_commitment(&self) -> Com<KoalaBearPoseidon2OuterD5> {
        Com::<KoalaBearPoseidon2OuterD5>::default()
    }
}
