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
    type Val: PrimeField + p3_field::PrimeField32 + p3_field::TwoAdicField + 'static;
    type Domain: PolynomialSpace<Val = Self::Val> + Sync;

    /// The PCS that commits to trace polynomials.
    type Pcs: Pcs<Self::Challenge, Self::Challenger, Domain = Self::Domain>
        + Sync
        + ZeroCommitment<Self>;

    /// The field from which most random challenges are drawn.
    type Challenge: ExtensionField<Self::Val> + p3_field::BasedVectorSpace<Self::Val> + 'static;

    /// The challenger (Fiat-Shamir) implementation used.
    ///
    /// The declaration-position bounds elaborate at every `SC:
    /// StarkGenericConfig` site (the reference keeps its capability floor on
    /// the config trait's associated types the same way), so shard-prover
    /// signatures don't repeat them.  Every config is KoalaBear-based, so the
    /// jagged-field capabilities hold for all of them.
    type Challenger: FieldChallenger<Val<Self>>
        + CanObserve<<Self::Pcs as Pcs<Self::Challenge, Self::Challenger>>::Commitment>
        + CanSample<Self::Challenge>
        + FieldChallenger<crate::jagged_pcs::JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
        + 'static;

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
        pin: Option<crate::jagged::AreaPin>,
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
    /// The preprocessed round is opened at the same shard point as main, so it
    /// must be committed in the same (natural) row order as main; a
    /// bit-reversed preprocessed commit fails the preprocessed reduction.
    fn prep_precompute(
        named_preprocessed_traces: &[(String, p3_matrix::dense::RowMajorMatrix<Val<Self>>)],
        pin: Option<crate::jagged::AreaPin>,
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
/// stack (`JaggedPcsProof`, `prove_shard_with_data`'s
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
    /// Whether this ring's machines commit under the jagged-WHIR inner
    /// PCS.  The INNER ring (the core machine and every recursion stage
    /// below wrap: normalize/compose/shrink) is WHIR — ONE PCS family down
    /// the whole proof tree; the OUTER/wrap ring stays BaseFold, because its
    /// proof is consumed by the gnark circuit, which has no WHIR verifier.
    /// The verifier needs no flag: it dispatches per proof on
    /// `bundle.whir_proof`.
    const WHIR_INNER_PCS: bool;

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
            ProverData<p3_matrix::dense::RowMajorMatrix<crate::jagged_pcs::JaggedVal>>: Send
                                                                                            + Sync
                                                                                            + 'static,
        > + Clone
        // `'static` so the DEFAULT `commit_multilinears` body (which hands the
        // MMCS to the generic BaseFold commit) typechecks at the trait level;
        // both rings are concrete `'static` types, so this is a no-op.
        + 'static;

    /// Construct the BaseFold MMCS for this config (perm + hash + compress).
    fn bf_mmcs() -> Self::BfMmcs;

    /// The BaseFold prover data standing in for a round committed under WHIR:
    /// a leafless tree carrying the WHIR root alone.  Of that data only the
    /// interleaved MLEs beside it are ever read (the jagged reduction rebuilds
    /// the dense polynomial from them); no BaseFold opening walks the tree,
    /// exactly as for a device-committed round.  `None` for a ring that never
    /// commits under WHIR.
    fn whir_committed_bf_prover_data(
        commit: &<Self::BfMmcs as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Commitment,
    ) -> Option<
        <Self::BfMmcs as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::ProverData<
            p3_matrix::dense::RowMajorMatrix<crate::jagged_pcs::JaggedVal>,
        >,
    > {
        let _ = commit;
        None
    }

    /// Per-stage BaseFold FRI config (rate / query count / grinding).
    ///
    /// The default returns the
    /// inner / env-overridable config (`FriConfig::from_env_or_default()` =
    /// `(log_blowup=1, num_queries=94, pow_bits=16)`), which is used by
    /// core/compress/shrink.  The **wrap** ring (`KoalaBearPoseidon2Outer`)
    /// overrides this to `FriConfig::wrap_fri_config()` = `(3, 94,
    /// wrap_query_grinding_bits())` so the
    /// on-chain wrap proof hits the full 100-bit query-phase soundness target
    /// (the inner default at the wrap is only ~55-bit — see
    /// `FriConfig::wrap_fri_config`).  Carried as a single source of truth from
    /// commit through open/verify so the prover and verifier always agree on
    /// the codeword rate.
    fn fri_config() -> crate::basefold::config::FriConfig<crate::jagged_pcs::JaggedVal> {
        crate::basefold::config::FriConfig::<crate::jagged_pcs::JaggedVal>::from_env_or_default()
    }

    /// Does the verifying key's commitment EQUAL the raw root the BaseFold open
    /// authenticates a preceding round against?
    ///
    /// The two rings store different things under `vk.commit`, so the question
    /// only has a direct answer on one of them:
    ///
    /// * OUTER — `commit_root` returns `commit.original_commitment` unmixed
    ///   (`recursion/core/src/stark/config.rs`), so key and root are the same
    ///   value of the same type and the comparison is a plain equality:
    ///   `Some(vk_commit == raw)`.
    /// * INNER — the key holds `compress([raw, hash(counts)])`
    ///   (`kb31_poseidon2.rs`), so no equality against `raw` can hold; `None`,
    ///   and the caller re-derives the bound form instead (which pins the
    ///   round's geometry as well as its root).
    ///
    /// Answered per ring rather than by relabelling `Com<Self>` at the call
    /// site: the two types coincide only on the outer ring, and that is a fact
    /// each implementor knows concretely and no caller can establish.
    fn vk_commit_is_preceding_root(
        _vk_commit: &crate::Com<Self>,
        _raw: &<Self::BfMmcs as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Commitment,
    ) -> Option<bool> {
        None
    }

    /// #H: per-ring projection of the BaseFold commitment to 8 KoalaBear felts
    /// for the `[F;8] main_commitment` FS observe (host path). Inner = MerkleCap
    /// root[0]; outer = deterministic projection of the BN254 commit.
    fn digest_felts(
        commit: &<Self::BfMmcs as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Commitment,
    ) -> [crate::jagged_pcs::JaggedVal; 8];

    /// Ring-native jagged BaseFold commit: build the BaseFold commit over
    /// this ring's [`Self::BfMmcs`] — no free-fn indirection.
    /// Inner (`KoalaBearPoseidon2`) commits over the Poseidon2-KoalaBear
    /// `JaggedMmcs`; the wrap ring over the Poseidon2-BN254 `OuterValMmcs`
    /// so the commitment is the BN254 root.  The DFT is over KoalaBear for
    /// BOTH rings (Val == KoalaBear everywhere).  No challenger observe
    /// (the caller surfaces the commitment).
    ///
    /// DEFAULT body, and the ONLY body: no ring overrides this method (checked
    /// across both repos), so the per-ring variation is entirely in the associated
    /// `BfMmcs` / `bf_mmcs()` / `fri_config()` / `WHIR_INNER_PCS`. In particular
    /// there is no `StarkGpuProver` override of it -- the device path commits
    /// through its own separate hook.
    ///
    /// INVARIANT the caller inherits: when `WHIR_INNER_PCS`, the returned `commit`
    /// is the WHIR root while `prover_data` remains the BaseFold one (whose Merkle
    /// tree is then dead, kept only for the interleaved MLEs the step-4 reduction
    /// reads), and `whir_data` is `Some`. Those three move together here, but
    /// `PrecomputedJaggedCommitGeneric` can represent them disagreeing.  The
    /// AREA PIN (`Some(target_log)` on a compress commit pins
    /// `log_dense_size` to `max(natural, target_log)`; `None` = NATURAL
    /// own-area packing).
    fn commit_multilinears(
        chip_traces: &[crate::jagged_pcs::jagged::ChipTraceView],
        pin: Option<crate::jagged::AreaPin>,
    ) -> crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<Self::BfMmcs> {
        use p3_matrix::dense::RowMajorMatrix;

        let mut packing =
            crate::jagged::compute_jagged_metadata_pinned::<crate::InnerVal>(chip_traces, pin);
        if packing.dense_len == 0 {
            packing.dense_len = 1;
        }
        let dense_q = crate::jagged::materialize_dense_jagged::<crate::InnerVal>(
            chip_traces,
            packing.dense_len,
        );
        assert_eq!(
            dense_q.len(),
            packing.dense_len,
            "materialize_dense_jagged produced {} cells for a dense_len of {}",
            dense_q.len(),
            packing.dense_len,
        );
        let dense_traces = alloc::vec![(
            alloc::string::String::from("<jagged-dense>"),
            RowMajorMatrix::new(dense_q, 1),
        )];
        let dft = std::sync::Arc::new(crate::jagged_pcs::JaggedDft::default());

        let (commit, prover_data, whir_data) = if Self::WHIR_INNER_PCS {
            let (mles, chip_dims) = crate::jagged_pcs::chips_to_mles_owned(dense_traces);
            let total_entries: usize = mles.iter().map(|m| m.guts().total_len()).sum();
            let log_stacking_height = crate::jagged_pcs::pick_log_stacking_height(total_entries);
            let area = total_entries.next_multiple_of(1usize << log_stacking_height);
            let interleaved_mles =
                crate::basefold::stacked::interleave_multilinears_with_fixed_rate(
                    crate::jagged_pcs::DEFAULT_BATCH_SIZE,
                    mles,
                    log_stacking_height,
                );
            let cfg = crate::whir::jagged::core_whir_config(log_stacking_height as usize);
            let (wcommit, wdata) = crate::whir::jagged::commit_jagged_whir_from_stripes::<
                Self::BfMmcs,
                crate::jagged_pcs::JaggedDft,
            >(
                &interleaved_mles,
                chip_dims.clone(),
                area,
                log_stacking_height,
                Self::bf_mmcs(),
                dft,
                cfg,
            );
            let tree = Self::whir_committed_bf_prover_data(&wcommit.original_commitment)
                .expect("a ring committing under WHIR supplies its leafless BaseFold prover data");
            let pcs_batch_data = crate::basefold::BasefoldProverData {
                prover_data: tree,
                encoded_codewords: Vec::new(),
                digest_layers: Vec::new(),
            };
            let prover_data = crate::jagged_pcs::JaggedProverDataGeneric::<Self::BfMmcs> {
                stacked_data: crate::basefold::stacked::StackedBasefoldProverData {
                    pcs_batch_data,
                    interleaved_mles,
                },
                chip_dims,
                area,
                log_stacking_height,
            };
            (wcommit, prover_data, Some(wdata))
        } else {
            let (commit, prover_data) =
                crate::jagged_pcs::commit_jagged_pcs_generic::<
                    Self::BfMmcs,
                    crate::jagged_pcs::JaggedDft,
                >(dense_traces, Self::bf_mmcs(), dft, Self::fri_config());
            (commit, prover_data, None)
        };
        crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric {
            packing,
            commit,
            prover_data,
            whir_data,
            fixed_pad_columns: pin.map(|p| p.pad_columns),
        }
    }

    /// Ring-native jagged BaseFold OPEN — the prove-side counterpart of
    /// [`Self::commit_multilinears`], and the reason
    /// [`crate::shard_level::prover::prove_trusted_evaluations`] needs no
    /// runtime type test to pick a jagged open.
    ///
    /// The open must run over the ring's OWN `Self::BfMmcs` and
    /// `Self::Challenger`, and it must produce the matching
    /// [`crate::shard_level::shard_proof::EvaluationProof`] shape: the inner
    /// (KoalaBear/Poseidon2) rings emit a concrete `Bundle`, the wrap ring
    /// emits `Bytes` (an rmp-serialized `JaggedPcsProofGeneric<
    /// OuterValMmcs>`, which has no concrete slot in the enum).  Dispatching
    /// that on `Self` puts the choice where the concrete types are known.
    ///
    /// Unlike `commit_multilinears` this is a required method, NOT a
    /// default, so the `Self::Challenger` capability bounds the generic
    /// BaseFold prover needs (`FieldChallenger` / `GrindingChallenger` /
    /// `CanObserve<BfCommitment<Self>>`) are discharged INSIDE each concrete
    /// impl instead of propagating up the whole shard-prover call chain.
    ///
    /// Every round's `precomputed` commit is built by `commit_traces` before
    /// the open and handed over — the open itself must NOT observe the
    /// BaseFold commit in-band: the verifier uses
    /// `verify_jagged_no_observe`, so an in-band observe here is a
    /// transcript desync no green test suite can see.
    ///
    /// Opens the jagged PCS over one or more commitment ROUNDS at the shared
    /// `z_row`, each round's commit, traces and claims kept together.  One
    /// round is a main-only proof; two are `[preprocessed, main]`.
    fn prove_jagged_open(
        z_row: &[crate::InnerChallenge],
        rounds: alloc::vec::Vec<crate::jagged_pcs::jagged::JaggedOpenRound<'_, Self::BfMmcs>>,
        challenger: &mut Self::Challenger,
    ) -> crate::shard_level::shard_proof::EvaluationProof;
}

/// The BaseFold jagged-PCS commitment type for a `BasefoldRing`
/// config — `<SC::BfMmcs as Mmcs<JaggedVal>>::Commitment`.  Exposed so
/// downstream crates (e.g. `zkm-core-machine`, which does not depend on
/// `p3-commit`) can name the `CanObserve<..>` bound the static outer BaseFold
/// open threads through the shard-prover call chain.
pub type BfCommitment<SC> =
    <<SC as BasefoldRing>::BfMmcs as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Commitment;

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
