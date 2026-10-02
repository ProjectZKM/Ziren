#![allow(missing_docs)]

use p3_challenger::DuplexChallenger;
use p3_field::{extension::BinomialExtensionField, Field};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use zkm_primitives::poseidon2_init;

pub const DIGEST_SIZE: usize = 8;

/// A configuration for inner recursion.
pub type InnerVal = KoalaBear;
pub type InnerChallenge = BinomialExtensionField<InnerVal, 4>;
pub type InnerPerm = Poseidon2KoalaBear<16>;
pub type InnerHash = PaddingFreeSponge<InnerPerm, 16, 8, DIGEST_SIZE>;
pub type InnerCompress = TruncatedPermutation<InnerPerm, 2, 8, 16>;
pub type InnerValMmcs = MerkleTreeMmcs<
    <InnerVal as Field>::Packing,
    <InnerVal as Field>::Packing,
    InnerHash,
    InnerCompress,
    2,
    8,
>;
pub type InnerChallenger = DuplexChallenger<InnerVal, InnerPerm, 16, 8>;

/// The permutation for inner recursion.
#[must_use]
pub fn inner_perm() -> InnerPerm {
    poseidon2_init()
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
        const ROUNDS_P: usize = 20;
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
        FriParameters {
            log_blowup: 1,
            log_final_poly_len: 0,
            max_log_arity: 1,
            num_queries,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: 16,
            mmcs: challenge_mmcs,
        }
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
        FriParameters {
            log_blowup: 2,
            log_final_poly_len: 0,
            max_log_arity: 1,
            num_queries,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: 16,
            mmcs: challenge_mmcs,
        }
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
        FriParameters {
            log_blowup: 3,
            log_final_poly_len: 0,
            max_log_arity: 1,
            num_queries,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: 16,
            mmcs: challenge_mmcs,
        }
    }

    enum KoalaBearPoseidon2Type {
        Default,
        Compressed,
    }

    /// The `P` of the ring that proves under the core WHIR schedule
    /// ([`crate::whir::jagged::WhirProfile::Core`]): the core shards.
    pub const WHIR_PROFILE_CORE: u8 = 0;

    /// The `P` of the ring that proves under the compress WHIR schedule
    /// ([`crate::whir::jagged::WhirProfile::Compress`]): every recursion
    /// stage below wrap.
    pub const WHIR_PROFILE_COMPRESS: u8 = 1;

    /// The inner ring: KoalaBear, its quartic extension, the Poseidon2
    /// sponge, and the jagged-WHIR PCS.  `P` selects the WHIR schedule the
    /// ring commits, opens and verifies under; the hash, the field and the
    /// transcript are the same for every `P`, so a proof of one ring is a
    /// proof over the other's field and hash but under a different schedule,
    /// which the other ring's verifier rejects.
    #[derive(Deserialize)]
    #[serde(from = "std::marker::PhantomData<KoalaBearPoseidon2Ring<P>>")]
    pub struct KoalaBearPoseidon2Ring<const P: u8> {
        pub perm: Perm,
        pcs: Pcs,
        fri_config: FriParameters<ChallengeMmcs>,
        config_type: KoalaBearPoseidon2Type,
    }

    /// The inner ring under the core schedule: the core machine.
    pub type KoalaBearPoseidon2 = KoalaBearPoseidon2Ring<WHIR_PROFILE_CORE>;

    /// The inner ring under the compress schedule: the recursion machines
    /// (normalize, compose, shrink).
    pub type KoalaBearPoseidon2Compress = KoalaBearPoseidon2Ring<WHIR_PROFILE_COMPRESS>;

    /// A shard proof of ring `P` as a shard proof of ring `Q`.  The two rings
    /// share the field, the hash and the commitment type, so the proof's data
    /// is the same; only the WHIR schedule a verifier must check it under
    /// differs, and that is the caller's to keep straight.
    pub fn retype_shard_proof<const P: u8, const Q: u8>(
        proof: crate::ShardProof<KoalaBearPoseidon2Ring<P>>,
    ) -> crate::ShardProof<KoalaBearPoseidon2Ring<Q>> {
        crate::ShardProof {
            public_values: proof.public_values,
            jagged_shard_proof: proof.jagged_shard_proof,
        }
    }

    /// A verifying key of ring `P` as one of ring `Q`; see
    /// [`retype_shard_proof`].
    pub fn retype_vk<const P: u8, const Q: u8>(
        vk: crate::StarkVerifyingKey<KoalaBearPoseidon2Ring<P>>,
    ) -> crate::StarkVerifyingKey<KoalaBearPoseidon2Ring<Q>> {
        crate::StarkVerifyingKey {
            commit: vk.commit,
            pc_start: vk.pc_start,
            initial_global_cumulative_sum: vk.initial_global_cumulative_sum,
            chip_information: vk.chip_information,
            chip_ordering: vk.chip_ordering,
        }
    }

    impl<const P: u8> KoalaBearPoseidon2Ring<P> {
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

    impl<const P: u8> Clone for KoalaBearPoseidon2Ring<P> {
        fn clone(&self) -> Self {
            match self.config_type {
                KoalaBearPoseidon2Type::Default => Self::new(),
                KoalaBearPoseidon2Type::Compressed => Self::compressed(),
            }
        }
    }

    impl<const P: u8> Default for KoalaBearPoseidon2Ring<P> {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Implement serialization manually instead of using serde to avoid cloning the config.
    impl<const P: u8> Serialize for KoalaBearPoseidon2Ring<P> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            std::marker::PhantomData::<KoalaBearPoseidon2Ring<P>>.serialize(serializer)
        }
    }

    impl<const P: u8> From<std::marker::PhantomData<KoalaBearPoseidon2Ring<P>>>
        for KoalaBearPoseidon2Ring<P>
    {
        fn from(_: std::marker::PhantomData<KoalaBearPoseidon2Ring<P>>) -> Self {
            Self::new()
        }
    }

    impl<const P: u8> StarkGenericConfig for KoalaBearPoseidon2Ring<P> {
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
            pin: Option<crate::jagged::AreaPin>,
        ) -> Com<Self> {
            <Self::PrepPrecomputed as crate::config::PrepCommitRoot<Self>>::commit_root(
                &Self::prep_precompute(named_preprocessed_traces, pin),
            )
        }

        type PrepPrecomputed = crate::jagged_pcs::jagged::PrecomputedJaggedCommit;

        fn prep_precompute(
            named_preprocessed_traces: &[(
                String,
                p3_matrix::dense::RowMajorMatrix<crate::jagged_pcs::JaggedVal>,
            )],
            pin: Option<crate::jagged::AreaPin>,
        ) -> Self::PrepPrecomputed {
            let views =
                crate::jagged_pcs::jagged::views_over_traces(named_preprocessed_traces.to_vec());
            <Self as crate::config::BasefoldRing>::commit_multilinears(&views, pin)
        }
    }

    /// PREPROCESSED-trace setup commit for the inner
    /// (`KoalaBearPoseidon2`) core/compress/shrink config: stacked BaseFold
    /// over the Poseidon2-KoalaBear `JaggedMmcs` (no two-adic coset LDE, so no
    /// `2^(TWO_ADICITY - log_blowup)` ceiling).  Mirrors `outer_prep_commit`
    /// (recursion-core, BN254 ring).  Returns the
    /// `JaggedMmcs::Commitment` — equal to `Com<KoalaBearPoseidon2>` since the
    /// inner `Pcs` is `TwoAdicFriPcs<_, _, InnerValMmcs, _>` and
    /// `JaggedMmcs == InnerValMmcs` (same Poseidon2-KoalaBear Merkle root).
    impl<const P: u8> crate::config::PrepCommitRoot<KoalaBearPoseidon2Ring<P>>
        for crate::jagged_pcs::jagged::PrecomputedJaggedCommit
    {
        /// The HASH-BOUND commitment: the raw BaseFold root with the committed
        /// GEOMETRY folded in,
        /// `compress([root, hash(row_counts ++ column_counts)])` — the same
        /// binding the MAIN round uses.
        ///
        /// The geometry binding is what makes a verifying key say anything
        /// about the shape of what it committed: a verifier that cannot see
        /// the traces (the recursion circuit) pins the preprocessed row
        /// counts against this digest.  The raw root travels in the PROOF,
        /// and the verifier re-derives the digest from it.
        fn commit_root(&self) -> Com<KoalaBearPoseidon2Ring<P>> {
            let raw = crate::jagged_pcs::basefold_commit_digest(&self.commit);
            let modified =
                crate::jagged_pcs::jagged_hash_bind_from_jagged_packing(raw, &self.packing);
            Com::<KoalaBearPoseidon2Ring<P>>::new(alloc::vec![modified])
        }
    }

    pub fn inner_prep_commit(
        chip_traces: &[(String, p3_matrix::dense::RowMajorMatrix<crate::jagged_pcs::JaggedVal>)],
        pin: Option<crate::jagged::AreaPin>,
    ) -> Com<KoalaBearPoseidon2> {
        <crate::jagged_pcs::jagged::PrecomputedJaggedCommit as crate::config::PrepCommitRoot<
            KoalaBearPoseidon2,
        >>::commit_root(&inner_prep_precompute(chip_traces, pin))
    }

    /// Same commit as [`inner_prep_commit`], keeping the BaseFold prover data
    /// and jagged packing so the preprocessed round can be OPENED, not just
    /// observed.  See `StarkGenericConfig::PrepPrecomputed`.
    pub fn inner_prep_precompute(
        chip_traces: &[(String, p3_matrix::dense::RowMajorMatrix<crate::jagged_pcs::JaggedVal>)],
        pin: Option<crate::jagged::AreaPin>,
    ) -> crate::jagged_pcs::jagged::PrecomputedJaggedCommit {
        inner_prep_precompute_owned(chip_traces.to_vec(), pin)
    }

    /// [`inner_prep_precompute`] consuming the traces, for a caller done with
    /// them: the cells move into the commit's views with no copy.
    pub fn inner_prep_precompute_owned(
        chip_traces: Vec<(String, p3_matrix::dense::RowMajorMatrix<crate::jagged_pcs::JaggedVal>)>,
        pin: Option<crate::jagged::AreaPin>,
    ) -> crate::jagged_pcs::jagged::PrecomputedJaggedCommit {
        let chip_trace_views = crate::jagged_pcs::jagged::views_over_traces(chip_traces);
        <KoalaBearPoseidon2 as crate::config::BasefoldRing>::commit_multilinears(
            &chip_trace_views,
            pin,
        )
    }

    impl<const P: u8> ZeroCommitment<KoalaBearPoseidon2Ring<P>> for Pcs {
        fn zero_commitment(&self) -> Com<KoalaBearPoseidon2Ring<P>> {
            DigestHash::from([Val::ZERO; DIGEST_SIZE]).into()
        }
    }

    // BaseFold-over-BN254 wrap port: the inner (default core / compress /
    // shrink) config proves via the BaseFold jagged-PCS over the
    // Poseidon2-KoalaBear Merkle MMCS (`JaggedMmcs`).  `bf_mmcs()` reproduces
    // the construction in `crate::jagged_pcs::commit_jagged_pcs_host`
    // (InnerHash/InnerCompress over the shared `poseidon2_init` perm) so the
    // generic BaseFold cores can be driven through this trait.
    impl<const P: u8> crate::config::BasefoldRing for KoalaBearPoseidon2Ring<P> {
        const WHIR_INNER_PCS: bool = true;

        const WHIR_PROFILE: crate::whir::jagged::WhirProfile = if P == WHIR_PROFILE_COMPRESS {
            crate::whir::jagged::WhirProfile::Compress
        } else {
            crate::whir::jagged::WhirProfile::Core
        };

        fn prep_open_data(
            prep: &Self::PrepPrecomputed,
        ) -> &crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<Self::BfMmcs> {
            prep
        }

        type BfMmcs = crate::jagged_pcs::JaggedMmcs;

        fn bf_mmcs() -> Self::BfMmcs {
            let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
            let hash = crate::kb31_poseidon2::InnerHash::new(perm.clone());
            let compress = crate::kb31_poseidon2::InnerCompress::new(perm);
            crate::jagged_pcs::JaggedMmcs::new(hash, compress, 0)
        }

        fn digest_felts(
            commit: &<Self::BfMmcs as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Commitment,
        ) -> [crate::jagged_pcs::JaggedVal; 8] {
            crate::jagged_pcs::basefold_commit_digest_felts(commit)
        }

        fn whir_committed_bf_prover_data(
            commit: &<Self::BfMmcs as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Commitment,
        ) -> Option<
            <Self::BfMmcs as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::ProverData<
                p3_matrix::dense::RowMajorMatrix<crate::jagged_pcs::JaggedVal>,
            >,
        > {
            let root = crate::jagged_pcs::basefold_commit_digest_felts(commit);
            Some(p3_merkle_tree::MerkleTree::from_parts(Vec::new(), vec![vec![root]], Vec::new()))
        }

        // `commit_multilinears` — the ring commit — is the trait DEFAULT
        // (this ring's `bf_mmcs()` / `fri_config()` are what it reads).

        /// Ring-native jagged BaseFold open.  `Self::BfMmcs == JaggedMmcs` and
        /// `Self::Challenger == JaggedChallenger` CONCRETELY here, so the shared
        /// inner body takes both directly — no `Box<dyn Any>` / `downcast_mut`.
        fn prove_jagged_open(
            z_row: &[crate::InnerChallenge],
            rounds: alloc::vec::Vec<crate::jagged_pcs::jagged::JaggedOpenRound<'_, Self::BfMmcs>>,
            challenger: &mut Self::Challenger,
        ) -> crate::shard_level::shard_proof::EvaluationProof {
            let bundle = crate::jagged_pcs::jagged::prove_jagged_rounds_with_profile(
                &rounds,
                z_row,
                challenger,
                Self::WHIR_PROFILE,
            );
            crate::shard_level::shard_proof::EvaluationProof::Bundle(bundle)
        }
    }
}
