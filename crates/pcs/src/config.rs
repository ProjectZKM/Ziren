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

    /// The PCS used to commit to trace polynomials.
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

    /// Ring-native jagged BaseFold commit: build the BaseFold commit over
    /// this ring's [`Self::BfMmcs`] — no free-fn indirection.
    /// Inner (`KoalaBearPoseidon2`) commits over the Poseidon2-KoalaBear
    /// `JaggedMmcs`; the wrap ring over the Poseidon2-BN254 `OuterValMmcs`
    /// so the commitment is the BN254 root.  The DFT is over KoalaBear for
    /// BOTH rings (Val == KoalaBear everywhere).  No challenger observe
    /// (the caller surfaces the commitment).
    ///
    /// DEFAULT body — every ring commits the same way with its own
    /// `bf_mmcs()` / `fri_config()`.  `use_rev` is the per-shard rev(zeta)
    /// orientation, threaded to `materialize_dense_jagged` and recorded on
    /// the returned commit; the
    /// AREA PIN (`Some(target_log)` on a compress commit pins
    /// `log_dense_size` to `max(natural, target_log)`; `None` = NATURAL
    /// own-area packing).
    fn commit_multilinears(
        chip_traces: &[crate::jagged_pcs::jagged::ChipTraceView],
        use_rev: bool,
    ) -> crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<Self::BfMmcs> {
        use p3_matrix::dense::RowMajorMatrix;

        let mut packing = crate::jagged::compute_jagged_metadata::<crate::InnerVal>(chip_traces);
        // A round with NO CELLS still has to produce a well-formed commitment.
        // `setup` drops every chip that generates no preprocessed trace, so a
        // machine whose chips all have `preprocessed_width() == 0` reaches here
        // with an empty trace list and a zero-length dense — and the Merkle
        // commit cannot commit zero matrices ("all matrices have height 0").
        // The shard prover already handles the empty round downstream: it reads
        // the round's chips off `packing.chip_infos`, which stays EMPTY here, so
        // no preprocessed round is opened and the proof is single-round.  All
        // that is needed is one cell to hang a commitment on; nothing is ever
        // opened against it.
        if packing.dense_len == 0 {
            packing.dense_len = 1;
        }
        let (commit, prover_data) =
            {
                let dense_q = crate::jagged::materialize_dense_jagged::<crate::InnerVal>(
                    chip_traces,
                    packing.dense_len,
                    use_rev,
                );
                debug_assert_eq!(dense_q.len(), packing.dense_len);
                let dense_traces = alloc::vec![(
                    alloc::string::String::from("<jagged-dense>"),
                    RowMajorMatrix::new(dense_q, 1),
                )];

                let dft = std::sync::Arc::new(crate::jagged_pcs::JaggedDft::default());
                crate::jagged_pcs::commit_jagged_pcs_generic::<
                    Self::BfMmcs,
                    crate::jagged_pcs::JaggedDft,
                >(dense_traces, Self::bf_mmcs(), dft, Self::fri_config())
            };
        // The experimental jagged-WHIR gate: ALSO commit the same dense
        // polynomial under WHIR and let ITS root be the observed commitment.
        // The BaseFold commit above is kept purely for `prover_data`'s
        // interleaved MLEs (the step-4 jagged reduction reads them); its
        // Merkle tree goes unused in WHIR mode.  Cost: a second commit —
        // acceptable for the gated experimental path.
        //
        // CORE MACHINE ONLY: recursion shards must stay BaseFold — the
        // compose/shrink/wrap circuits verify BaseFold recursion proofs, and
        // a WHIR recursion bundle panics the compose program build (measured:
        // the keccak multi-shard e2e trips `unreachable!` in
        // compress_basefold without this gate; single-leaf runs mask it
        // because compress short-circuits compose and the host verifier
        // accepts either PCS).  `use_rev` does NOT discriminate — the
        // NORMALIZE machine also proves in the rev orientation.  The chip
        // NAMES do: "Byte" is a MIPS-machine chip present in EVERY core
        // round (setup commits its preprocessed table, every shard commits
        // its multiplicities) and in NO recursion machine (BaseAlu/ExtAlu/
        // Poseidon2/... namespace).  Commit and open stay consistent
        // per-proof because the open dispatches on the whir_data this
        // decision populates; a proof this gate routes to BaseFold verifies
        // as BaseFold end-to-end (per-proof dispatch), so correctness never
        // rests on the marker.
        let is_core_machine = chip_traces.iter().any(|(name, _)| name == "Byte");
        let whir_data = if is_core_machine && crate::whir::core_pcs_is_whir() {
            let dense_traces = alloc::vec![(
                alloc::string::String::from("<jagged-dense>"),
                RowMajorMatrix::new(
                    crate::basefold::stacked::dense_from_interleaved_mles::<crate::InnerVal>(
                        &prover_data.stacked_data.interleaved_mles,
                        prover_data.area,
                    ),
                    1,
                ),
            )];
            let dft = std::sync::Arc::new(crate::jagged_pcs::JaggedDft::default());
            let cfg =
                crate::whir::jagged::core_whir_config(prover_data.log_stacking_height as usize);
            let (wcommit, wdata) = crate::whir::jagged::commit_jagged_whir_generic::<
                Self::BfMmcs,
                crate::jagged_pcs::JaggedDft,
            >(dense_traces, Self::bf_mmcs(), dft, cfg);
            debug_assert_eq!(wcommit.area, prover_data.area);
            Some((wcommit, wdata))
        } else {
            None
        };
        let (commit, whir_data) = match whir_data {
            Some((wcommit, wdata)) => (wcommit, Some(wdata)),
            None => (commit, None),
        };
        crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric {
            packing,
            commit,
            prover_data,
            whir_data,
            rev: use_rev,
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
    /// emits `Bytes` (an rmp-serialized `JaggedBasefoldBundleGeneric<
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
    /// `verify_jagged_basefold_no_observe`, so an in-band observe here is a
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
