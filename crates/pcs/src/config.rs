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
    /// Whether `StarkMachine::setup` commits PREPROCESSED traces via the
    /// registered `OuterPrepCommitFn` hook (SP1-style stacked BaseFold, no
    /// two-adic coset LDE) instead of `pcs.commit`.  The legacy LDE caps
    /// prep heights at `2^(TWO_ADICITY - log_blowup)`; the BaseFold path
    /// never consumes the LDE `ProverData`.  Default false; the OuterSC
    /// wrap config overrides to true.
    fn prep_commit_via_hook() -> bool {
        false
    }

    /// The BaseFold preprocessed-commit hook for this config, if any.  Commits
    /// KoalaBear-valued preprocessed traces via stacked BaseFold (no two-adic
    /// coset LDE) and returns the bincode of `Com<Self>`.  `StarkMachine::setup`
    /// invokes it when `prep_commit_via_hook()` is set OR a prep trace exceeds
    /// `prep_two_adic_ceiling_log()`.  Default None (only `pcs.commit` is used).
    /// The inner (`KoalaBearPoseidon2`) config returns `inner_prep_commit`; the
    /// wrap (`KoalaBearPoseidon2Outer`) config returns `outer_prep_commit`
    /// (statically, replacing the retired runtime hook registry).
    fn prep_commit_hook() -> Option<crate::shard_level::sumcheck_poly::OuterPrepCommitFn> {
        None
    }

    /// Max preprocessed LOG height committable via the two-adic `pcs.commit`
    /// (= `TWO_ADICITY - log_blowup`).  Above this, the coset LDE
    /// (`height << log_blowup`) would exceed `TWO_ADICITY` and panic in
    /// `two_adic_generator`, so setup routes prep through `prep_commit_hook`
    /// instead (height-agnostic recursion: FIX-off recursion prep reaches
    /// 2^24 > the inner 2^23 ceiling).  Default `usize::MAX` (never
    /// height-trigger — preserves byte-identical two-adic prep for every
    /// config that fits, incl. core and FIX-on recursion).
    fn prep_two_adic_ceiling_log() -> usize {
        usize::MAX
    }
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
///   `BfMmcs = JaggedMmcs` (Poseidon2-KoalaBear Merkle), `use_basefold = true`.
/// * Wrap (`KoalaBearPoseidon2Outer`): `BfMmcs = OuterValMmcs`
///   (Poseidon2-BN254 Merkle, `Commitment = Hash<KoalaBear, Bn254, 1>`).
///   `bf_mmcs()` builds that MMCS so the generic BaseFold cores
///   (`commit/open/verify_jagged_pcs_generic`) can run over it.  See the impl
///   in `crates/recursion/core/src/stark/config.rs` (zkm-pcs cannot import
///   OuterSC — the recursion-core crate depends on stark, not vice versa).
///
/// `use_basefold()` returns the *same boolean* the legacy TypeId gate computed
/// (inner = true, wrap = false) so swapping the gates is non-breaking.  The
/// wrap can be flipped to `true` once the higher-level jagged bundle / 8-felt
/// digest stack (`JaggedBasefoldBundle`, `prove_shard_to_basefold`'s
/// `main_commitment: [Val; 8]`) is genericized over `BfMmcs::Commitment` — at
/// which point the `bf_mmcs()` infrastructure provided here is consumed
/// directly.
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

    /// Whether this config proves/verifies via the BaseFold jagged-PCS path
    /// (vs. the legacy two-adic FRI path).  Replaces the open-coded
    /// `use_basefold_path` TypeId gate.
    fn use_basefold() -> bool;

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
    /// shard-prover call chain.  It is EXACTLY the commit body the deleted
    /// `commit_basefold_path` produced for the wrap ring (same MMCS / FRI config
    /// / `use_rev` / `recursion_area_pin`), just built during the prove pass.
    fn precompute_jagged_inline(
        named_inner: &[crate::jagged_pcs::jagged::ChipTraceView<'_>],
        use_rev: bool,
        recursion_area_pin: Option<usize>,
    ) -> crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<Self::BfMmcs>;
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
