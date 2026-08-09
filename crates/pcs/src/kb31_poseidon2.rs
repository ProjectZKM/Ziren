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

        fn prep_commit(
            named_preprocessed_traces: &[(
                String,
                p3_matrix::dense::RowMajorMatrix<crate::jagged_pcs::JaggedVal>,
            )],
        ) -> Com<Self> {
            inner_prep_commit(named_preprocessed_traces)
        }

    }

    /// SP1-style PREPROCESSED-trace setup commit for the inner
    /// (`KoalaBearPoseidon2`) core/compress/shrink config: stacked BaseFold
    /// over the Poseidon2-KoalaBear `JaggedMmcs` (no two-adic coset LDE, so no
    /// `2^(TWO_ADICITY - log_blowup)` ceiling).  Mirrors `outer_prep_commit`
    /// (recursion-core, BN254 ring).  Returns bincode of the
    /// `JaggedMmcs::Commitment` — equal to `Com<KoalaBearPoseidon2>` since the
    /// inner `Pcs` is `TwoAdicFriPcs<_, _, InnerValMmcs, _>` and
    /// `JaggedMmcs == InnerValMmcs` (same Poseidon2-KoalaBear Merkle root).
    /// Preprocessed-trace commit for the inner config: the jagged BaseFold
    /// path (no two-adic coset LDE), returning `Com<KoalaBearPoseidon2>`.
    pub fn inner_prep_commit(
        chip_traces: &[(
            String,
            p3_matrix::dense::RowMajorMatrix<crate::jagged_pcs::JaggedVal>,
        )],
    ) -> Com<KoalaBearPoseidon2> {
        use crate::jagged_pcs::jagged::precompute_jagged_basefold_commit_generic;
        let mmcs = <KoalaBearPoseidon2 as crate::config::BasefoldRing>::bf_mmcs();
        let fri = <KoalaBearPoseidon2 as crate::config::BasefoldRing>::fri_config();
        // SITE-1 trace-unification: the commit consumes BORROWED views over the
        // owned `chip_traces` (JaggedVal == InnerVal), kept alive across the call.
        let chip_trace_views = crate::jagged_pcs::jagged::views_over_owned(chip_traces);
        let pre = precompute_jagged_basefold_commit_generic::<crate::jagged_pcs::JaggedMmcs>(
            &chip_trace_views,
            mmcs,
            fri,
            // Preprocessed-trace commit helper (setup / vk path): LEGACY bitrev
            // orientation (`use_rev = false`), byte-identical.
            false,
            // Preprocessed / setup commit is never a recursion prove commit
            // → no AREA PIN (`None`), byte-identical.
            None,
        );
        pre.commit.original_commitment
    }

    impl ZeroCommitment<KoalaBearPoseidon2> for Pcs {
        fn zero_commitment(&self) -> Com<KoalaBearPoseidon2> {
            DigestHash::from([Val::ZERO; DIGEST_SIZE]).into()
        }
    }

    // BaseFold-over-BN254 wrap port: the inner (default core / compress /
    // shrink) config proves via the BaseFold jagged-PCS over the
    // Poseidon2-KoalaBear Merkle MMCS (`JaggedMmcs`).  `bf_mmcs()` reproduces
    // the construction in `crate::jagged_pcs::commit_jagged_pcs_host`
    // (InnerHash/InnerCompress over the shared `poseidon2_init` perm) so the
    // generic BaseFold cores can be driven through this trait.  `use_basefold`
    // returns `true`, matching the legacy TypeId gate's inner-config result.
    impl crate::config::BasefoldRing for KoalaBearPoseidon2 {
        type BfMmcs = crate::jagged_pcs::JaggedMmcs;

        fn bf_mmcs() -> Self::BfMmcs {
            let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
            let hash = crate::kb31_poseidon2::InnerHash::new(perm.clone());
            let compress = crate::kb31_poseidon2::InnerCompress::new(perm);
            crate::jagged_pcs::JaggedMmcs::new(hash, compress, 0)
        }

        fn use_basefold() -> bool {
            true
        }

        fn digest_felts(
            commit: &<Self::BfMmcs as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Commitment,
        ) -> [crate::jagged_pcs::JaggedVal; 8] {
            crate::jagged_pcs::basefold_commit_digest_felts(commit)
        }

        fn precompute_jagged_inline(
            named_inner: &[crate::jagged_pcs::jagged::ChipTraceView],
            use_rev: bool,
            recursion_area_pin: Option<usize>,
        ) -> crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<Self::BfMmcs> {
            crate::jagged_pcs::jagged::precompute_jagged_basefold_commit_generic::<Self::BfMmcs>(
                named_inner,
                Self::bf_mmcs(),
                Self::fri_config(),
                use_rev,
                recursion_area_pin,
            )
        }

        /// Ring-native jagged BaseFold open.  `Self::BfMmcs == JaggedMmcs` and
        /// `Self::Challenger == JaggedChallenger` CONCRETELY here, so the shared
        /// inner body takes both directly — no `Box<dyn Any>` / `downcast_mut`.
        fn prove_jagged_open(
            chip_traces: &[crate::jagged_pcs::jagged::ChipTraceView],
            r_row_per_chip: &[alloc::vec::Vec<crate::InnerChallenge>],
            z_row: &[crate::InnerChallenge],
            pre_y_per_chip: Option<alloc::vec::Vec<alloc::vec::Vec<crate::InnerChallenge>>>,
            precomputed: Option<
                crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<Self::BfMmcs>,
            >,
            challenger: &mut Self::Challenger,
        ) -> crate::shard_level::shard_proof::EvaluationProof {
            crate::shard_level::prover::prove_jagged_open_inner(
                chip_traces,
                r_row_per_chip,
                z_row,
                pre_y_per_chip,
                precomputed,
                challenger,
            )
        }
    }

}

