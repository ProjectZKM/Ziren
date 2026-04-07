#![allow(missing_docs)]

use crate::{Com, StarkGenericConfig, ZeroCommitment};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{extension::{BinomialExtensionField, QuinticTrinomialExtensionField}, Field, PrimeCharacteristicRing};
use p3_commit::BatchOpening;
use p3_fri::{CommitPhaseProofStep, FriParameters, FriProof, QueryProof, TwoAdicFriPcs};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{Hash, PaddingFreeSponge, TruncatedPermutation};
use serde::{Deserialize, Serialize};
use zkm_primitives::poseidon2_init;

pub const DIGEST_SIZE: usize = 8;

/// A configuration for inner recursion.
pub type InnerVal = KoalaBear;
pub type InnerChallenge = BinomialExtensionField<InnerVal, 4>;
pub type InnerPerm = Poseidon2KoalaBear<16>;
pub type InnerHash = PaddingFreeSponge<InnerPerm, 16, 8, DIGEST_SIZE>;
pub type InnerDigestHash = Hash<InnerVal, InnerVal, DIGEST_SIZE>;
pub type InnerDigest = [InnerVal; DIGEST_SIZE];
pub type InnerCompress = TruncatedPermutation<InnerPerm, 2, 8, 16>;
pub type InnerValMmcs = MerkleTreeMmcs<
    <InnerVal as Field>::Packing,
    <InnerVal as Field>::Packing,
    InnerHash,
    InnerCompress,
    2,
    8,
>;
pub type InnerChallengeMmcs = ExtensionMmcs<InnerVal, InnerChallenge, InnerValMmcs>;
pub type InnerChallenger = DuplexChallenger<InnerVal, InnerPerm, 16, 8>;
pub type InnerDft = Radix2DitParallel<InnerVal>;
pub type InnerPcs = TwoAdicFriPcs<InnerVal, InnerDft, InnerValMmcs, InnerChallengeMmcs>;

pub type InnerInputProof = Vec<BatchOpening<InnerVal, InnerValMmcs>>;

pub type InnerQueryProof = QueryProof<InnerChallenge, InnerChallengeMmcs, InnerInputProof>;
pub type InnerCommitPhaseStep = CommitPhaseProofStep<InnerChallenge, InnerChallengeMmcs>;
pub type InnerFriProof = FriProof<InnerChallenge, InnerChallengeMmcs, InnerVal, InnerInputProof>;
pub type InnerBatchOpening = BatchOpening<InnerVal, InnerValMmcs>;

pub type InnerPcsProof = <InnerPcs as p3_commit::Pcs<InnerChallenge, InnerChallenger>>::Proof;

// ── Quintic extension types (D=5, ~155 bits) ─────────────────────────────
//
// Reference: Plonky3-recursion uses D=5 for KoalaBear to achieve provable
// 128-bit security under Johnson Bound [BCSS25].

/// Quintic extension challenge field (~155 bits).
pub type Inner128Challenge = QuinticTrinomialExtensionField<InnerVal>;
pub type Inner128ChallengeMmcs = ExtensionMmcs<InnerVal, Inner128Challenge, InnerValMmcs>;
pub type Inner128Pcs = TwoAdicFriPcs<InnerVal, InnerDft, InnerValMmcs, Inner128ChallengeMmcs>;

/// FRI config targeting a given security level with quintic extension (D=5).
///
/// With D=5 extension (~155-bit field), the Johnson Bound [BCSS25] analysis
/// provides provable security up to ~128 bits without conjectures.
///
/// Reference: Plonky3-recursion uses log_blowup=3, max_log_arity=4,
/// log_final_poly_len=5, query_pow_bits=16 as defaults for recursive layers.
///
/// `security_bits`: target security level (e.g. 100, 128).
/// Queries are derived as: ceil((security_bits - pow_bits) / log2(1/(1-delta)))
#[must_use]
pub fn fri_config_d5(security_bits: usize) -> FriParameters<Inner128ChallengeMmcs> {
    let perm = inner_perm();
    let hash = InnerHash::new(perm.clone());
    let compress = InnerCompress::new(perm.clone());
    let challenge_mmcs = Inner128ChallengeMmcs::new(InnerValMmcs::new(hash, compress, 0));

    let pow_bits: usize = 16;
    let log_blowup: usize = 1;

    // delta for UniqueDecoding at rate 1/2: delta = 0.25, log2(1-delta) = -0.415
    // queries = ceil(protocol_bits / 0.415)
    let protocol_bits = security_bits.saturating_sub(pow_bits);
    let num_queries = match std::env::var("FRI_QUERIES") {
        Ok(value) => value.parse().unwrap(),
        Err(_) => {
            // UniqueDecoding: delta = 0.5 * (1 - rate), rate = 1/2^log_blowup
            let rate = 1.0 / (1u64 << log_blowup) as f64;
            let delta = 0.5 * (1.0 - rate);
            let log_1_delta = (1.0 - delta).log2();
            (-(protocol_bits as f64) / log_1_delta).ceil() as usize
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

/// The permutation for inner recursion.
#[must_use]
pub fn inner_perm() -> InnerPerm {
    poseidon2_init()
}

/// The FRI config for Ziren proofs.
#[must_use]
pub fn zkm_fri_config() -> FriParameters<InnerChallengeMmcs> {
    let perm = inner_perm();
    let hash = InnerHash::new(perm.clone());
    let compress = InnerCompress::new(perm.clone());
    let challenge_mmcs = InnerChallengeMmcs::new(InnerValMmcs::new(hash, compress, 0));
    let num_queries = match std::env::var("FRI_QUERIES") {
        Ok(value) => value.parse().unwrap(),
        Err(_) => 84,
    };
    FriParameters { log_blowup: 1, log_final_poly_len: 0, max_log_arity: 1, num_queries, commit_proof_of_work_bits: 0, query_proof_of_work_bits: 16, mmcs: challenge_mmcs }
}

/// The FRI config for inner recursion.
/// This targets by default 100 bits of security.
#[must_use]
pub fn inner_fri_config() -> FriParameters<InnerChallengeMmcs> {
    let perm = inner_perm();
    let hash = InnerHash::new(perm.clone());
    let compress = InnerCompress::new(perm.clone());
    let challenge_mmcs = InnerChallengeMmcs::new(InnerValMmcs::new(hash, compress, 0));
    let num_queries = match std::env::var("FRI_QUERIES") {
        Ok(value) => value.parse().unwrap(),
        Err(_) => 84,
    };
    FriParameters { log_blowup: 1, log_final_poly_len: 0, max_log_arity: 1, num_queries, commit_proof_of_work_bits: 0, query_proof_of_work_bits: 16, mmcs: challenge_mmcs }
}

/// The recursion config used for recursive reduce circuit.
#[derive(Deserialize)]
#[serde(from = "std::marker::PhantomData<KoalaBearPoseidon2Inner>")]
pub struct KoalaBearPoseidon2Inner {
    pub perm: InnerPerm,
    pub pcs: InnerPcs,
}

impl Clone for KoalaBearPoseidon2Inner {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl Serialize for KoalaBearPoseidon2Inner {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        std::marker::PhantomData::<KoalaBearPoseidon2Inner>.serialize(serializer)
    }
}

impl From<std::marker::PhantomData<KoalaBearPoseidon2Inner>> for KoalaBearPoseidon2Inner {
    fn from(_: std::marker::PhantomData<KoalaBearPoseidon2Inner>) -> Self {
        Self::new()
    }
}

impl KoalaBearPoseidon2Inner {
    #[must_use]
    pub fn new() -> Self {
        let perm = inner_perm();
        let hash = InnerHash::new(perm.clone());
        let compress = InnerCompress::new(perm.clone());
        let val_mmcs = InnerValMmcs::new(hash, compress, 0);
        let dft = InnerDft::default();

        let fri_config = inner_fri_config();
        let pcs = InnerPcs::new(dft, val_mmcs, fri_config);
        Self { perm, pcs }
    }
}

impl Default for KoalaBearPoseidon2Inner {
    fn default() -> Self {
        Self::new()
    }
}

impl StarkGenericConfig for KoalaBearPoseidon2Inner {
    type Val = InnerVal;
    type Domain = <InnerPcs as p3_commit::Pcs<InnerChallenge, InnerChallenger>>::Domain;
    type Pcs = InnerPcs;
    type Challenge = InnerChallenge;
    type Challenger = InnerChallenger;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn challenger(&self) -> Self::Challenger {
        InnerChallenger::new(self.perm.clone())
    }
}

impl ZeroCommitment<KoalaBearPoseidon2Inner> for InnerPcs {
    fn zero_commitment(&self) -> Com<KoalaBearPoseidon2Inner> {
        InnerDigestHash::from([InnerVal::ZERO; DIGEST_SIZE]).into()
    }
}

// ── 128-bit StarkGenericConfig ────────────────────────────────────────────

/// STARK configuration with quintic extension (D=5) for higher security levels.
///
/// Uses quintic extension (~155 bits) over KoalaBear with Poseidon2.
/// The Johnson Bound analysis from [BCSS25] provides provable security
/// up to ~128 bits without relying on the Capacity Bound conjecture.
///
/// Reference: Plonky3-recursion uses D=5 for KoalaBear with configurable
/// security levels via FRI parameter tuning.
///
/// The security level is configurable — use `KoalaBearPoseidon2D5::with_security(128)`
/// for 128-bit, or any other target up to ~155 bits.
#[derive(Deserialize)]
#[serde(from = "std::marker::PhantomData<KoalaBearPoseidon2D5>")]
pub struct KoalaBearPoseidon2D5 {
    pub perm: InnerPerm,
    pub pcs: Inner128Pcs,
    security_bits: usize,
}

impl Clone for KoalaBearPoseidon2D5 {
    fn clone(&self) -> Self {
        Self::with_security(self.security_bits)
    }
}

impl Serialize for KoalaBearPoseidon2D5 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        std::marker::PhantomData::<KoalaBearPoseidon2D5>.serialize(serializer)
    }
}

impl From<std::marker::PhantomData<KoalaBearPoseidon2D5>> for KoalaBearPoseidon2D5 {
    fn from(_: std::marker::PhantomData<KoalaBearPoseidon2D5>) -> Self {
        Self::with_security(128)
    }
}

impl KoalaBearPoseidon2D5 {
    /// Create a D=5 config with a specific security level.
    #[must_use]
    pub fn with_security(security_bits: usize) -> Self {
        let perm = inner_perm();
        let hash = InnerHash::new(perm.clone());
        let compress = InnerCompress::new(perm.clone());
        let val_mmcs = InnerValMmcs::new(hash, compress, 0);
        let dft = InnerDft::default();
        let fri_config = fri_config_d5(security_bits);
        let pcs = Inner128Pcs::new(dft, val_mmcs, fri_config);
        Self { perm, pcs, security_bits }
    }

    /// Create a D=5 config with default 128-bit security.
    #[must_use]
    pub fn new() -> Self {
        Self::with_security(128)
    }
}

impl Default for KoalaBearPoseidon2D5 {
    fn default() -> Self {
        Self::new()
    }
}

impl StarkGenericConfig for KoalaBearPoseidon2D5 {
    type Val = InnerVal;
    type Domain = <Inner128Pcs as p3_commit::Pcs<Inner128Challenge, InnerChallenger>>::Domain;
    type Pcs = Inner128Pcs;
    type Challenge = Inner128Challenge;
    type Challenger = InnerChallenger;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn challenger(&self) -> Self::Challenger {
        InnerChallenger::new(self.perm.clone())
    }
}

impl ZeroCommitment<KoalaBearPoseidon2D5> for Inner128Pcs {
    fn zero_commitment(&self) -> Com<KoalaBearPoseidon2D5> {
        InnerDigestHash::from([InnerVal::ZERO; DIGEST_SIZE]).into()
    }
}

/// Alias for backward compatibility.
pub type KoalaBearPoseidon2_128 = KoalaBearPoseidon2D5;

pub mod koala_bear_poseidon2 {

    use p3_challenger::DuplexChallenger;
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::{extension::BinomialExtensionField, Field, PrimeCharacteristicRing};
    use p3_fri::{FriParameters, TwoAdicFriPcs};
    use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_poseidon2::ExternalLayerConstants;
    use p3_symmetric::{Hash, PaddingFreeSponge, TruncatedPermutation};
    use serde::{Deserialize, Serialize};
    use zkm_primitives::RC_16_30;

    use crate::{Com, StarkGenericConfig, ZeroCommitment, DIGEST_SIZE};

    pub type Val = KoalaBear;
    pub type Challenge = BinomialExtensionField<Val, 4>;

    pub type Perm = Poseidon2KoalaBear<16>;
    pub type MyHash = PaddingFreeSponge<Perm, 16, 8, DIGEST_SIZE>;
    pub type DigestHash = Hash<Val, Val, DIGEST_SIZE>;
    pub type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    pub type ValMmcs =
        MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 2, 8>;
    pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    pub type Dft = Radix2DitParallel<Val>;
    pub type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

    #[must_use]
    pub fn my_perm() -> Perm {
        const ROUNDS_F: usize = 8;
        const ROUNDS_P: usize = 13;
        let mut round_constants = RC_16_30.to_vec();
        let internal_start = ROUNDS_F / 2;
        let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
        let internal_round_constants = round_constants
            .drain(internal_start..internal_end)
            .map(|vec| vec[0])
            .collect::<Vec<_>>();
        let external_round_constants = ExternalLayerConstants::new(
            round_constants[..ROUNDS_F / 2].to_vec(),
            round_constants[ROUNDS_F / 2..ROUNDS_F].to_vec(),
        );
        Perm::new(external_round_constants, internal_round_constants)
    }

    #[must_use]
    /// This targets by default 100 bits of security.
    pub fn default_fri_config() -> FriParameters<ChallengeMmcs> {
        let perm = my_perm();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let challenge_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress, 0));
        let num_queries = match std::env::var("FRI_QUERIES") {
            Ok(value) => value.parse().unwrap(),
            Err(_) => 84,
        };
        FriParameters { log_blowup: 1, log_final_poly_len: 0, max_log_arity: 1, num_queries, commit_proof_of_work_bits: 0, query_proof_of_work_bits: 16, mmcs: challenge_mmcs }
    }

    #[must_use]
    /// This targets by default 100 bits of security.
    pub fn compressed_fri_config() -> FriParameters<ChallengeMmcs> {
        let perm = my_perm();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let challenge_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress, 0));
        let num_queries = match std::env::var("FRI_QUERIES") {
            Ok(value) => value.parse().unwrap(),
            Err(_) => 42,
        };
        FriParameters { log_blowup: 2, log_final_poly_len: 0, max_log_arity: 1, num_queries, commit_proof_of_work_bits: 0, query_proof_of_work_bits: 16, mmcs: challenge_mmcs }
    }

    #[must_use]
    /// This targets by default 100 bits of security.
    pub fn ultra_compressed_fri_config() -> FriParameters<ChallengeMmcs> {
        let perm = my_perm();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let challenge_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress, 0));
        let num_queries = match std::env::var("FRI_QUERIES") {
            Ok(value) => value.parse().unwrap(),
            Err(_) => 28,
        };
        FriParameters { log_blowup: 3, log_final_poly_len: 0, max_log_arity: 1, num_queries, commit_proof_of_work_bits: 0, query_proof_of_work_bits: 16, mmcs: challenge_mmcs }
    }

    enum KoalaBearPoseidon2Type {
        Default,
        Compressed,
    }

    #[derive(Deserialize)]
    #[serde(from = "std::marker::PhantomData<KoalaBearPoseidon2>")]
    pub struct KoalaBearPoseidon2 {
        pub perm: Perm,
        pcs: Pcs,
        fri_config: FriParameters<ChallengeMmcs>,
        config_type: KoalaBearPoseidon2Type,
    }

    impl KoalaBearPoseidon2 {
        #[must_use]
        pub fn new() -> Self {
            let perm = my_perm();
            let hash = MyHash::new(perm.clone());
            let compress = MyCompress::new(perm.clone());
            let val_mmcs = ValMmcs::new(hash, compress, 0);
            let dft = Dft::default();
            let fri_config = default_fri_config();
            let pcs = Pcs::new(dft, val_mmcs, fri_config.clone());
            Self { pcs, perm, fri_config, config_type: KoalaBearPoseidon2Type::Default }
        }

        #[must_use]
        pub fn compressed() -> Self {
            let perm = my_perm();
            let hash = MyHash::new(perm.clone());
            let compress = MyCompress::new(perm.clone());
            let val_mmcs = ValMmcs::new(hash, compress, 0);
            let dft = Dft::default();
            let fri_config = compressed_fri_config();
            let pcs = Pcs::new(dft, val_mmcs, fri_config.clone());
            Self { pcs, perm, fri_config, config_type: KoalaBearPoseidon2Type::Compressed }
        }

        #[must_use]
        pub fn ultra_compressed() -> Self {
            let perm = my_perm();
            let hash = MyHash::new(perm.clone());
            let compress = MyCompress::new(perm.clone());
            let val_mmcs = ValMmcs::new(hash, compress, 0);
            let dft = Dft::default();
            let fri_config = ultra_compressed_fri_config();
            let pcs = Pcs::new(dft, val_mmcs, fri_config.clone());
            Self { pcs, perm, fri_config, config_type: KoalaBearPoseidon2Type::Compressed }
        }

        /// Get a reference to the FRI configuration.
        pub fn get_fri_config(&self) -> &FriParameters<ChallengeMmcs> {
            &self.fri_config
        }
    }

    impl Clone for KoalaBearPoseidon2 {
        fn clone(&self) -> Self {
            match self.config_type {
                KoalaBearPoseidon2Type::Default => Self::new(),
                KoalaBearPoseidon2Type::Compressed => Self::compressed(),
            }
        }
    }

    impl Default for KoalaBearPoseidon2 {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Implement serialization manually instead of using serde to avoid cloning the config.
    impl Serialize for KoalaBearPoseidon2 {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            std::marker::PhantomData::<KoalaBearPoseidon2>.serialize(serializer)
        }
    }

    impl From<std::marker::PhantomData<KoalaBearPoseidon2>> for KoalaBearPoseidon2 {
        fn from(_: std::marker::PhantomData<KoalaBearPoseidon2>) -> Self {
            Self::new()
        }
    }

    impl StarkGenericConfig for KoalaBearPoseidon2 {
        type Val = KoalaBear;
        type Domain = <Pcs as p3_commit::Pcs<Challenge, Challenger>>::Domain;
        type Pcs = Pcs;
        type Challenge = Challenge;
        type Challenger = Challenger;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }

        fn challenger(&self) -> Self::Challenger {
            Challenger::new(self.perm.clone())
        }
    }

    impl ZeroCommitment<KoalaBearPoseidon2> for Pcs {
        fn zero_commitment(&self) -> Com<KoalaBearPoseidon2> {
            DigestHash::from([Val::ZERO; DIGEST_SIZE]).into()
        }
    }
}
