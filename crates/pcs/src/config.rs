use p3_challenger::{CanObserve, CanSample, FieldChallenger};
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{ExtensionField, Field, PrimeField};
use serde::{de::DeserializeOwned, Serialize};

pub type PcsError<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Error;

pub type Domain<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Domain;

pub type Val<SC> = <Domain<SC> as PolynomialSpace>::Val;

pub type PackedVal<SC> = <Val<SC> as Field>::Packing;

pub type Com<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Commitment;

pub type OpeningProof<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Proof;

pub type OpeningError<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Error;

pub type Dom<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Domain;

pub type PcsProverData<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::ProverData;

pub type Challenge<SC> = <SC as StarkGenericConfig>::Challenge;
pub type Challenger<SC> = <SC as StarkGenericConfig>::Challenger;

pub type PackedChallenge<SC> =
    <<SC as StarkGenericConfig>::Challenge as ExtensionField<Val<SC>>>::ExtensionPacking;

pub trait StarkGenericConfig: 'static + Send + Sync + Serialize + DeserializeOwned + Clone {
    type Val: PrimeField + p3_field::TwoAdicField;
    type Domain: PolynomialSpace<Val = Self::Val> + Sync;

    /// The PCS used to commit to trace polynomials.
    type Pcs: Pcs<Self::Challenge, Self::Challenger, Domain = Self::Domain>
        + Sync
        + ZeroCommitment<Self>;

    /// The field from which most random challenges are drawn.
    type Challenge: ExtensionField<Self::Val>;

    /// The challenger (Fiat-Shamir) implementation used.
    type Challenger: FieldChallenger<Val<Self>>
        + CanObserve<<Self::Pcs as Pcs<Self::Challenge, Self::Challenger>>::Commitment>
        + CanSample<Self::Challenge>;

    /// Get the PCS used by this configuration.
    fn pcs(&self) -> &Self::Pcs;

    /// Initialize a new challenger.
    fn challenger(&self) -> Self::Challenger;

    /// The BaseFold preprocessed-commit for this config, if it has one.  Commits
    /// the preprocessed traces via the jagged BaseFold path (no two-adic coset
    /// LDE) and returns the commitment directly.  `StarkMachine::setup` uses it
    /// whenever it is defined -- there is no height threshold and no opt-in
    /// flag.
    ///
    /// The default is `None`, which keeps the two-adic `pcs.commit`.  That is
    /// what the test-only `KoalaBearPoseidon2Inner` / `KoalaBearPoseidon2D5`
    /// configs use; the two production configs (`KoalaBearPoseidon2` and the
    /// wrap `KoalaBearPoseidon2Outer`) both override it, so the production
    /// setup path never takes the `None` branch.
    fn prep_commit(
        named_preprocessed_traces: &[(String, p3_matrix::dense::RowMajorMatrix<Val<Self>>)],
        use_rev: bool,
    ) -> Com<Self>;

    /// The PRECOMPUTED preprocessed commit: the commitment together with the
    /// BaseFold prover data (codeword + Merkle tree) and the jagged packing.
    ///
    /// [`prep_commit`](Self::prep_commit) throws all of that away and keeps only
    /// the root, which is enough to OBSERVE the preprocessed commitment but not
    /// to OPEN it.  `setup` retains both: the commit goes into the verifying
    /// key and the data into the proving key
    /// (`StarkProvingKey::preprocessed_data`), and the preprocessed traces are
    /// opened as their OWN ROUND of every shard proof
    /// (`[preprocessed_commit, main_commitment]`).
    ///
    /// Committed once per program, NOT once per shard.
    type PrepPrecomputed: PrepCommitRoot<Self> + Send + Sync + 'static;

    /// Build the precomputed preprocessed commit.  Deterministic in its input,
    /// so a key that was deserialized without it can rebuild it on demand.
    /// `use_rev` is the MACHINE's row orientation (`StarkMachine::core_rev`).
    /// The preprocessed round is opened at the same shard point as main, so it
    /// must be committed under the SAME orientation — a preprocessed commit
    /// built LEGACY-bitrev while the shard reduces natural-row makes the two
    /// rounds disagree on row order, and the preprocessed reduction fails.
    fn prep_precompute(
        named_preprocessed_traces: &[(String, p3_matrix::dense::RowMajorMatrix<Val<Self>>)],
        use_rev: bool,
    ) -> Self::PrepPrecomputed;
}

/// Read the commitment root out of a config's
/// [`PrepPrecomputed`](StarkGenericConfig::PrepPrecomputed).
///
/// The precomputed value is opaque to generic code, but `setup` must publish its
/// root as the verifying key's preprocessed commitment — this is the one thing
/// generic code needs from it.
pub trait PrepCommitRoot<SC: StarkGenericConfig> {
    /// The commitment this precompute produced — byte-identical to what
    /// [`StarkGenericConfig::prep_commit`] would return for the same traces.
    fn commit_root(&self) -> Com<SC>;
}

pub trait ZeroCommitment<SC: StarkGenericConfig> {
    fn zero_commitment(&self) -> Com<SC>;
}

/// **#H (BaseFold-over-BN254 wrap port)** — selects the BaseFold jagged-PCS
/// MMCS (and hence the commitment-hash family) for a given STARK config, and
/// whether that config proves via the BaseFold path at all.
///
/// `Val<Self>`/`Challenge<Self>` stay KoalaBear / KoalaBear⁴ for *both* the
/// inner (Poseidon2-KoalaBear) and the wrap (OuterSC, Poseidon2-BN254) paths
/// — only the challenger + Merkle-commitment hash vary by context.  This
/// trait is the single source of truth for the dispatch (no runtime
/// `TypeId` gates in `prover.rs` / `shard_level/*`).
///
/// * Inner (`KoalaBearPoseidon2`, the default core/compress/shrink config):
///   `BfMmcs = JaggedMmcs` (Poseidon2-KoalaBear Merkle).
/// * Wrap (`KoalaBearPoseidon2Outer`): `BfMmcs = OuterValMmcs`
///   (Poseidon2-BN254 Merkle, `Commitment = Hash<KoalaBear, Bn254, 1>`).
///   `bf_mmcs()` builds that MMCS so the generic BaseFold cores
///   (`commit/open/verify_jagged_pcs_generic`) can run over it.  See the impl
///   in `crates/recursion/core/src/stark/config.rs` (zkm-pcs cannot import
///   OuterSC — the recursion-core crate depends on stark, not vice versa).
///
/// Both rings run BaseFold.  The higher-level jagged bundle / 8-felt digest
/// stack (`JaggedBasefoldBundle`, `prove_shard_with_data`'s
/// `main_commitment: [Val; 8]`) is still concrete rather than generic over
/// `BfMmcs::Commitment`; genericizing it is what would let `bf_mmcs()` be
/// consumed directly.
pub trait BasefoldRing: StarkGenericConfig {
    /// Borrow this config's [`PrepPrecomputed`](StarkGenericConfig::PrepPrecomputed)
    /// as the concrete jagged commit the BaseFold prove path opens.
    ///
    /// `PrepPrecomputed` has to stay opaque on `StarkGenericConfig`, because
    /// `setup` is generic over configs that know nothing about BaseFold — but
    /// every implementor IS a `PrecomputedJaggedCommitGeneric<Self::BfMmcs>`,
    /// and the shard prover (which is `BasefoldRing`-bounded) needs it as
    /// exactly that to open the preprocessed round against the vk's commitment.
    fn prep_open_data(
        prep: &Self::PrepPrecomputed,
    ) -> &crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<Self::BfMmcs>;

    /// The MMCS (Merkle commitment scheme over `Val<Self>` = KoalaBear) used by
    /// the BaseFold jagged-PCS for this config.  Inner = Poseidon2-KoalaBear;
    /// wrap = Poseidon2-BN254 (`Commitment = Hash<KoalaBear, Bn254, 1>`).
    ///
    /// `Commitment`/`Proof` carry `Serialize + Deserialize` so the
    /// generic bundle's `to_bytes()` is callable directly from the shard prover
    /// (the wrap `EvaluationProof::Bytes` path).  These are associated-type
    /// bounds (implied at every `SC: BasefoldRing` site).  The `SC::Challenger`
    /// capability bounds the generic BaseFold prover needs are NOT expressible
    /// as implied bounds, so they live on the shard-prover call chain instead
    /// (see `prove_trusted_evaluations`).
    type BfMmcs: p3_commit::Mmcs<Val<Self>, Commitment: Clone>
        + p3_commit::Mmcs<
            crate::jagged_pcs::JaggedVal,
            Commitment: Clone
                + Send
                + Sync
                + 'static
                + serde::Serialize
                + for<'d> serde::Deserialize<'d>,
            Proof: serde::Serialize + for<'d> serde::Deserialize<'d>,
            ProverData<p3_matrix::dense::RowMajorMatrix<crate::jagged_pcs::JaggedVal>>:
                Send + Sync + 'static,
        >
        + Clone;

    /// Construct the BaseFold MMCS for this config (perm + hash + compress).
    fn bf_mmcs() -> Self::BfMmcs;

    /// Per-stage BaseFold FRI config (rate / query count / grinding).
    ///
    /// The default returns the
    /// inner / env-overridable config (`FriConfig::from_env_or_default()` =
    /// `(log_blowup=1, num_queries=94, pow_bits=16)`), which is used by
    /// core/compress/shrink.  The **wrap** ring (`KoalaBearPoseidon2Outer`)
    /// overrides this to `FriConfig::wrap_fri_config()` = `(3, 94, 22)` so the
    /// on-chain wrap proof hits the full 100-bit query-phase soundness target
    /// (the inner default at the wrap is only ~55-bit — see
    /// `FriConfig::wrap_fri_config`).  Carried as a single source of truth from
    /// commit through open/verify so the prover and verifier always agree on
    /// the codeword rate.
    fn fri_config() -> crate::basefold::config::FriConfig<crate::jagged_pcs::JaggedVal> {
        crate::basefold::config::FriConfig::<crate::jagged_pcs::JaggedVal>::from_env_or_default()
    }


    /// #H: per-ring projection of the BaseFold commitment to 8 KoalaBear felts
    /// for the `[F;8] main_commitment` FS observe (host path). Inner = MerkleCap
    /// root[0]; outer = deterministic projection of the BN254 commit.
    fn digest_felts(
        commit: &<Self::BfMmcs as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Commitment,
    ) -> [crate::jagged_pcs::JaggedVal; 8];

    /// Ring-native jagged BaseFold precompute for the inline commit path.
    ///
    /// Used by `commit_traces` on the OUTER/wrap ring (whose
    /// `BfMmcs = OuterValMmcs` cannot flow through the inner-only
    /// `commit_multilinears` device seam).  This is a required method — NOT a
    /// default — so the `Self::BfMmcs: Clone + 'static` bounds that
    /// [`crate::jagged_pcs::jagged::precompute_jagged_basefold_commit_generic`]
    /// needs are discharged INSIDE each concrete impl (where `Self::BfMmcs` is a
    /// concrete `'static` MMCS), rather than propagating up the whole
    /// shard-prover call chain.  Builds with the ring's own MMCS / FRI config
    /// and the caller's `use_rev` / `recursion_area_pin`.
    fn precompute_jagged_inline(
        named_inner: &[crate::jagged_pcs::jagged::ChipTraceView],
        use_rev: bool,
        recursion_area_pin: Option<usize>,
    ) -> crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<Self::BfMmcs>;

    /// Ring-native jagged BaseFold OPEN — the prove-side counterpart of
    /// [`Self::precompute_jagged_inline`], and the reason
    /// [`crate::shard_level::prover::prove_trusted_evaluations`] needs no
    /// runtime type test to pick a jagged open.
    ///
    /// The open must run over the ring's OWN `Self::BfMmcs` and
    /// `Self::Challenger`, and it must produce the matching
    /// [`crate::shard_level::shard_proof::EvaluationProof`] shape: the inner
    /// (KoalaBear/Poseidon2) rings emit a concrete `Bundle`, the wrap ring
    /// emits `Bytes` (an rmp-serialized `JaggedBasefoldBundleGeneric<
    /// OuterValMmcs>`, which has no concrete slot in the enum).  Dispatching
    /// that on `Self` puts the choice where the concrete types are known.
    ///
    /// Like `precompute_jagged_inline` this is a required method, NOT a
    /// default, so the `Self::Challenger` capability bounds the generic
    /// BaseFold prover needs (`FieldChallenger` / `GrindingChallenger` /
    /// `CanObserve<BfCommitment<Self>>`) are discharged INSIDE each concrete
    /// impl instead of propagating up the whole shard-prover call chain.
    ///
    /// Every round's `precomputed` commit is built by `commit_traces` before
    /// the open and handed over — the open itself must NOT observe the
    /// BaseFold commit in-band: the verifier uses
    /// `verify_jagged_basefold_no_observe`, so an in-band observe here is a
    /// transcript desync no green test suite can see.
    ///
    /// Opens the jagged PCS over one or more commitment ROUNDS at the shared
    /// `z_row`, each round's commit, traces and claims kept together.  One
    /// round is a main-only proof; two are `[preprocessed, main]`.
    fn prove_jagged_open(
        z_row: &[crate::InnerChallenge],
        rounds: alloc::vec::Vec<
            crate::jagged_pcs::jagged::JaggedOpenRound<'_, Self::BfMmcs>,
        >,
        challenger: &mut Self::Challenger,
    ) -> crate::shard_level::shard_proof::EvaluationProof;
}

/// The BaseFold jagged-PCS commitment type for a `BasefoldRing`
/// config — `<SC::BfMmcs as Mmcs<JaggedVal>>::Commitment`.  Exposed so
/// downstream crates (e.g. `zkm-core-machine`, which does not depend on
/// `p3-commit`) can name the `CanObserve<..>` bound the static outer BaseFold
/// open threads through the shard-prover call chain.
pub type BfCommitment<SC> = <<SC as BasefoldRing>::BfMmcs as p3_commit::Mmcs<
    crate::jagged_pcs::JaggedVal,
>>::Commitment;

#[derive(Clone)]
pub struct UniConfig<SC>(pub SC);

impl<SC: StarkGenericConfig> p3_uni_stark::StarkGenericConfig for UniConfig<SC> {
    type Pcs = SC::Pcs;

    type Challenge = SC::Challenge;

    type Challenger = SC::Challenger;

    fn pcs(&self) -> &Self::Pcs {
        self.0.pcs()
    }

    fn initialise_challenger(&self) -> Self::Challenger {
        self.0.challenger()
    }
}
