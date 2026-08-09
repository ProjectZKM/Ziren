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
    ) -> Com<Self>;

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
/// — mirrors SP1's `BNGC<KoalaBear, KoalaBear⁴>`, where only the
/// challenger + Merkle-commitment hash vary by context.  This trait is the
/// single source of truth for the dispatch, replacing an open-coded
/// `TypeId::of::<SC::Challenger>() == TypeId::of::<JaggedChallenger>()` gate in
/// `prover.rs` / `shard_level/*`.
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
/// stack (`JaggedBasefoldBundle`, `prove_shard_to_basefold`'s
/// `main_commitment: [Val; 8]`) is still concrete rather than generic over
/// `BfMmcs::Commitment`; genericizing it is what would let `bf_mmcs()` be
/// consumed directly.
pub trait BasefoldRing: StarkGenericConfig {
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
    /// SP1 keeps SEPARATE per-stage configs (core/recursion vs shrink/wrap;
    /// `crates/primitives/src/fri_params.rs`).  The Ziren default returns the
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

    /// Ring-native jagged BaseFold precompute for the INLINE lazy-commit path.
    ///
    /// Used by `maybe_auto_precompute_basefold` on the OUTER/wrap ring (whose
    /// `BfMmcs = OuterValMmcs` cannot flow through the inner-only
    /// `commit_multilinears` device seam).  This is a required method — NOT a
    /// default — so the `Self::BfMmcs: Clone + 'static` bounds that
    /// [`crate::jagged_pcs::jagged::precompute_jagged_basefold_commit_generic`]
    /// needs are discharged INSIDE each concrete impl (where `Self::BfMmcs` is a
    /// concrete `'static` MMCS), rather than propagating up the whole
    /// shard-prover call chain.  It is EXACTLY the commit body the retired
    /// eager wrap-ring commit produced (same MMCS / FRI config / `use_rev` /
    /// `recursion_area_pin`), just built during the prove pass.
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
    /// This replaces a `TypeId::of::<SC::Challenger>()` test that stood in for
    /// two facts the type system was not carrying: that the CHALLENGER is
    /// `JaggedChallenger`, and — separately, and not implied by it — that
    /// `Self::BfMmcs` is `JaggedMmcs`, so that
    /// `PrecomputedJaggedCommitGeneric<Self::BfMmcs>` could be `.expect()`-ed
    /// out of a `Box<dyn Any>`.  Both downcasts are gone: inside each impl the
    /// two types ARE the concrete ones, by construction.
    ///
    /// Like `precompute_jagged_inline` this is a required method, NOT a
    /// default, so the `Self::Challenger` capability bounds the generic
    /// BaseFold prover needs (`FieldChallenger` / `GrindingChallenger` /
    /// `CanObserve<BfCommitment<Self>>`) are discharged INSIDE each concrete
    /// impl instead of propagating up the whole shard-prover call chain.
    ///
    /// `precomputed` is NOT optional: the commit is built inline during the
    /// prove pass and handed over.  It used to be an `Option` for a legacy
    /// in-band-commit flow that no longer exists — and a `None` reaching here
    /// would have made the prover observe the BaseFold commit in-band while the
    /// verifier uses `verify_jagged_basefold_no_observe`, a transcript desync no
    /// green test suite can see.
    fn prove_jagged_open(
        chip_traces: &[crate::jagged_pcs::jagged::ChipTraceView],
        r_row_per_chip: &[alloc::vec::Vec<crate::InnerChallenge>],
        z_row: &[crate::InnerChallenge],
        pre_y_per_chip: Option<alloc::vec::Vec<alloc::vec::Vec<crate::InnerChallenge>>>,
        precomputed: crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<Self::BfMmcs>,
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
