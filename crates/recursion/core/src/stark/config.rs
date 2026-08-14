use p3_bn254_fr::{Bn254, Poseidon2Bn254};
use p3_challenger::MultiField32Challenger;
use p3_commit::BatchOpening;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{CommitPhaseProofStep, FriParameters, FriProof, QueryProof, TwoAdicFriPcs};
use p3_koala_bear::KoalaBear;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2::ExternalLayerConstants;
use p3_symmetric::{Hash, MultiField32PaddingFreeSponge, TruncatedPermutation};
use serde::{Deserialize, Serialize};
use zkm_pcs::{BasefoldRing, Com, StarkGenericConfig, ZeroCommitment};

use super::{poseidon2::bn254_poseidon2_rc3, zkm_dev_mode};

pub const DIGEST_SIZE: usize = 1;

pub const OUTER_MULTI_FIELD_CHALLENGER_WIDTH: usize = 3;
pub const OUTER_MULTI_FIELD_CHALLENGER_RATE: usize = 2;
pub const OUTER_MULTI_FIELD_CHALLENGER_DIGEST_SIZE: usize = 1;

/// A configuration for outer recursion.
pub type OuterVal = KoalaBear;
pub type OuterChallenge = BinomialExtensionField<OuterVal, 4>;
pub type OuterPerm = Poseidon2Bn254<3>;
pub type OuterHash = MultiField32PaddingFreeSponge<OuterVal, Bn254, OuterPerm, 3, 16, DIGEST_SIZE>;
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
    FriParameters {
        log_blowup: 4,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries,
        commit_proof_of_work_bits: 16,
        query_proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    }
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
    FriParameters {
        log_blowup,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries,
        commit_proof_of_work_bits: 16,
        query_proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    }
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
    fn prep_commit(
        named_preprocessed_traces: &[(
            String,
            p3_matrix::dense::RowMajorMatrix<zkm_pcs::jagged_pcs::JaggedVal>,
        )],
        use_rev: bool,
    ) -> zkm_pcs::Com<Self> {
        // The OuterSC wrap-machine PREPROCESSED commit goes through the jagged
        // BaseFold path over the Poseidon2-BN254 `OuterValMmcs` (no two-adic
        // coset LDE).
        outer_jagged_hooks::outer_prep_commit(named_preprocessed_traces, use_rev)
    }

    type PrepPrecomputed =
        zkm_pcs::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<OuterValMmcs>;

    fn prep_precompute(
        named_preprocessed_traces: &[(
            String,
            p3_matrix::dense::RowMajorMatrix<zkm_pcs::jagged_pcs::JaggedVal>,
        )],
        use_rev: bool,
    ) -> Self::PrepPrecomputed {
        outer_jagged_hooks::outer_prep_precompute(named_preprocessed_traces, use_rev)
    }

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

// The OUTER (wrap) impl of `BasefoldRing`.
// Lives here — not in zkm-pcs — because zkm-pcs cannot import OuterSC
// (recursion-core depends on stark, not vice versa). `Val<OuterSC> = KoalaBear`
// and `Challenge<OuterSC> = KoalaBear⁴` (same as
// inner), so the BaseFold jagged-PCS over the
// Poseidon2-BN254 Merkle MMCS (`OuterValMmcs`, whose
// `Commitment = Hash<KoalaBear, Bn254, 1>`) applies directly. `bf_mmcs()`
// builds that MMCS so the generic BaseFold cores
// (`commit/open/verify_jagged_pcs_generic`) can run over it once the
// higher-level jagged bundle + 8-felt-digest stack is genericized over
// `BfMmcs::Commitment`.
//
// The digest tunnel + the outer jagged open/verify dispatch are wired, so the
// wrap STARK proves and host-verifies over the BN254 BaseFold jagged-PCS
// (OuterValMmcs + OuterChallenger): the outer commit builds the BN254 commit
// via `precompute_jagged_basefold_commit_generic::<OuterValMmcs>`, and
// `prove_trusted_evaluations` / `verify_jagged_pcs_host` dispatch statically
// through this impl.
impl BasefoldRing for KoalaBearPoseidon2Outer {
    fn prep_open_data(
        prep: &Self::PrepPrecomputed,
    ) -> &zkm_pcs::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<Self::BfMmcs> {
        prep
    }

    type BfMmcs = OuterValMmcs;

    fn bf_mmcs() -> Self::BfMmcs {
        let perm = outer_perm();
        let hash = OuterHash::new(perm.clone()).unwrap();
        let compress = OuterCompress::new(perm);
        OuterValMmcs::new(hash, compress, 0)
    }

    fn fri_config() -> zkm_pcs::basefold::config::FriConfig<zkm_pcs::jagged_pcs::JaggedVal> {
        // WRAP-stage params: (log_blowup=3, num_queries=94,
        // pow_bits=22) for full 100-bit query-phase soundness on the on-chain
        // wrap proof.  The inner env-default (1,94,16) here would be only
        // ~55-bit.  Two-adicity: codeword = log_stacking(≤21) + 3 ≤ 24 = OK.
        // See `FriConfig::wrap_fri_config`.
        zkm_pcs::basefold::config::FriConfig::<zkm_pcs::jagged_pcs::JaggedVal>::wrap_fri_config()
    }

    fn digest_felts(
        commit: &<Self::BfMmcs as p3_commit::Mmcs<zkm_pcs::jagged_pcs::JaggedVal>>::Commitment,
    ) -> [zkm_pcs::jagged_pcs::JaggedVal; 8] {
        // `commit: Hash<KoalaBear, Bn254, 1>`
        // is the BN254 wrap commitment. Project it to 8 KoalaBear felts via
        // `split_32` (the same BN254->base primitive the MultiField32 challenger
        // uses) for the host `[F;8]` FS observe. The gnark step observes the BN254
        // commit natively; this host projection only needs prover/verifier
        // agreement, which split_32 gives deterministically.
        let roots = commit.roots();
        assert!(!roots.is_empty(), "BN254 wrap commitment MerkleCap must have at least one root",);
        let felts = p3_field::split_32::<Bn254, KoalaBear>(roots[0][0], 8);
        let mut out = [KoalaBear::default(); 8];
        for i in 0..8 {
            out[i] = felts.get(i).copied().unwrap_or_default();
        }
        out
    }

    fn precompute_jagged_inline(
        named_inner: &[zkm_pcs::jagged_pcs::jagged::ChipTraceView],
        use_rev: bool,
        recursion_area_pin: Option<usize>,
    ) -> zkm_pcs::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<Self::BfMmcs> {
        // The wrap ring's BN254 jagged BaseFold precompute — EXACTLY the commit
        // the retired outer BaseFold commit path produced for OuterSC (same
        // OuterValMmcs / wrap FRI config / `use_rev` / `recursion_area_pin`),
        // now built INLINE during the prove pass.
        zkm_pcs::jagged_pcs::jagged::precompute_jagged_basefold_commit_generic::<Self::BfMmcs>(
            named_inner,
            Self::bf_mmcs(),
            Self::fri_config(),
            use_rev,
            recursion_area_pin,
        )
    }

    fn prove_jagged_open(
        z_row: &[zkm_pcs::InnerChallenge],
        rounds: Vec<zkm_pcs::jagged_pcs::jagged::JaggedOpenRound<'_, Self::BfMmcs>>,
        challenger: &mut Self::Challenger,
    ) -> zkm_pcs::shard_level::shard_proof::EvaluationProof {
        // ONE jagged proof spanning every round, exactly as the inner ring
        // does — the wrap machine has preprocessed chips, so its terminal proof
        // opens `[preprocessed, main]` and binds the preprocessed round to the
        // key like every stage before it.
        //
        // The round's `claims` reach the generic body, which weighs them into
        // the reduction; the ring only names its own commitment family here.
        let bundle = zkm_pcs::jagged_pcs::jagged::prove_jagged_basefold_rounds_generic::<
            Self::Challenger,
            Self::BfMmcs,
            zkm_pcs::jagged_pcs::JaggedDft,
        >(
            &rounds,
            z_row,
            challenger,
            Self::bf_mmcs(),
            std::sync::Arc::new(zkm_pcs::jagged_pcs::JaggedDft::default()),
            Self::fri_config(),
        );
        zkm_pcs::shard_level::shard_proof::EvaluationProof::Bytes(bundle.to_bytes())
    }
}

/// The FRI config for testing recursion.
pub fn test_fri_config() -> FriParameters<OuterChallengeMmcs> {
    let perm = outer_perm();
    let hash = OuterHash::new(perm.clone()).unwrap();
    let compress = OuterCompress::new(perm.clone());
    let challenge_mmcs = OuterChallengeMmcs::new(OuterValMmcs::new(hash, compress, 0));
    FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 1,
        commit_proof_of_work_bits: 1,
        query_proof_of_work_bits: 1,
        mmcs: challenge_mmcs,
    }
}

// ── D=5 outer config (128-bit security) ───────────────────────────────────

// Compile-time proof that the genericized
// BaseFold jagged-PCS digest path (`zkm_pcs::jagged_pcs::*_generic`) is
// instantiable over the OUTER ring's BN254 commitment family, i.e. that the
// BN254 commitment (`OuterValMmcs::Commitment = Hash<KoalaBear, Bn254, 1>`)
// "flows" through commit/open/verify exactly where the inner ring uses the
// 8-felt Poseidon2-KoalaBear digest. `Val`/`Challenge` stay KoalaBear /
// KoalaBear⁴ for both; only the
// Merkle-commitment hash + challenger vary.
//
// No runtime body: these functions are never *called* here (the OuterSC wrap
// orchestration that drives them lives in `zkm-pcs`'s `prover.rs`
// `commit()/open()` + gnark `build_outer_circuit`, which are the remaining
// wrap-port work). The point is purely to monomorphize the generic cores at
// `MT = OuterValMmcs` + `Challenger = OuterChallenger` so the trait bounds
// (`OuterChallenger: CanObserve<OuterValMmcs::Commitment>`,
// `OuterDft: TwoAdicSubgroupDft<KoalaBear>`) are checked by the compiler. If
// the BN254 commit family ever drifts out of the generic-core bounds, this
// stops compiling — a guardrail for the wrap port.
#[cfg(test)]
#[allow(dead_code, clippy::type_complexity)]
mod basefold_over_bn254_generic_typecheck {
    use super::{KoalaBearPoseidon2Outer, OuterChallenger, OuterDft, OuterValMmcs};
    // The commit no longer observes internally, so the caller needs `CanObserve`.
    use p3_challenger::CanObserve;
    use p3_matrix::dense::RowMajorMatrix;
    use std::sync::Arc;
    use zkm_pcs::basefold::{StackedBasefoldProof, StackedVerifierError};
    use zkm_pcs::jagged_pcs::{
        commit_jagged_pcs_generic, open_jagged_pcs_generic, verify_jagged_pcs_generic,
        JaggedChallenge, JaggedCommitGeneric, JaggedMmcs, JaggedProverDataGeneric, JaggedVal,
    };

    // Sanity: `JaggedVal == OuterVal == KoalaBear`, so the OUTER MMCS is an
    // `Mmcs<JaggedVal>` exactly as the generic cores require. (Inner alias is
    // a `MerkleTreeMmcs` over the same `JaggedVal`.)
    type _AssertOuterIsJaggedValMmcs = OuterValMmcs;
    type _AssertInner = JaggedMmcs;

    // commit (no observe) over the BN254 MMCS.
    fn _commit_no_observe(
        traces: std::vec::Vec<(std::string::String, RowMajorMatrix<JaggedVal>)>,
        mmcs: OuterValMmcs,
        dft: Arc<OuterDft>,
    ) -> (JaggedCommitGeneric<OuterValMmcs>, JaggedProverDataGeneric<OuterValMmcs>) {
        let fri = <KoalaBearPoseidon2Outer as zkm_pcs::BasefoldRing>::fri_config();
        commit_jagged_pcs_generic::<OuterValMmcs, OuterDft>(traces, mmcs, dft, fri)
    }

    // commit (with observe) — exercises `OuterChallenger:
    // CanObserve<OuterValMmcs::Commitment>` (the BN254 commit observe the
    // prologue would perform on the outer path).
    fn _commit_observe(
        traces: std::vec::Vec<(std::string::String, RowMajorMatrix<JaggedVal>)>,
        ch: &mut OuterChallenger,
        mmcs: OuterValMmcs,
        dft: Arc<OuterDft>,
    ) -> (JaggedCommitGeneric<OuterValMmcs>, JaggedProverDataGeneric<OuterValMmcs>) {
        let fri = <KoalaBearPoseidon2Outer as zkm_pcs::BasefoldRing>::fri_config();
        let (commit, prover_data) =
            commit_jagged_pcs_generic::<OuterValMmcs, OuterDft>(traces, mmcs, dft, fri);
        // The transcript write lives HERE, at the caller, not inside the PCS helper.
        ch.observe(commit.original_commitment.clone());
        (commit, prover_data)
    }

    // open over the BN254 MMCS.
    fn _open(
        pd: JaggedProverDataGeneric<OuterValMmcs>,
        eval_point: std::vec::Vec<JaggedChallenge>,
        ch: &mut OuterChallenger,
        mmcs: OuterValMmcs,
        dft: Arc<OuterDft>,
    ) -> StackedBasefoldProof<JaggedVal, JaggedChallenge, OuterValMmcs> {
        let fri = <KoalaBearPoseidon2Outer as zkm_pcs::BasefoldRing>::fri_config();
        open_jagged_pcs_generic::<OuterChallenger, OuterValMmcs, OuterDft>(
            &pd, eval_point, ch, mmcs, dft, fri,
        )
    }

    // verify over the BN254 MMCS — exercises the verifier-side
    // `CanObserve<OuterValMmcs::Commitment>` (the BN254 commit observe the
    // outer-path verifier prologue would perform).
    #[allow(clippy::too_many_arguments)]
    fn _verify(
        commitment: &<OuterValMmcs as p3_commit::Mmcs<JaggedVal>>::Commitment,
        area: usize,
        log_stacking_height: u32,
        eval_point: &[JaggedChallenge],
        evaluation_claim: JaggedChallenge,
        proof: &StackedBasefoldProof<JaggedVal, JaggedChallenge, OuterValMmcs>,
        ch: &mut OuterChallenger,
        mmcs: OuterValMmcs,
        dft: Arc<OuterDft>,
    ) -> Result<(), StackedVerifierError> {
        let fri = <KoalaBearPoseidon2Outer as zkm_pcs::BasefoldRing>::fri_config();
        verify_jagged_pcs_generic::<OuterChallenger, OuterValMmcs>(
            commitment,
            area,
            log_stacking_height,
            eval_point,
            evaluation_claim,
            proof,
            ch,
            mmcs,
            fri,
        )
    }
}

// OUTER-ring jagged BaseFold setup commit.
//
// `outer_prep_commit` is the wrap ring's `StarkGenericConfig::prep_commit` body.
// It exists because `StarkMachine::setup` is generic over `SC` and so cannot name
// `OuterValMmcs`, while `precompute_jagged_basefold_commit_generic` must be told
// which MMCS to use; the config impl supplies it.  `Val`/`Challenge` are
// KoalaBear / KoalaBear^4 for both rings, so only the MMCS differs.
pub mod outer_jagged_hooks {
    use super::{KoalaBearPoseidon2Outer, OuterValMmcs};
    use p3_matrix::dense::RowMajorMatrix;
    use zkm_pcs::jagged_pcs::JaggedVal;

    // The shard prover (`prove_trusted_evaluations`) and host verifier
    // (`verify_jagged_pcs_host`) name `OuterChallenger`/`OuterValMmcs` via the
    // `BasefoldRing` associated type and call the generic BaseFold open/verify
    // statically, so only the setup/VK-side commit lives here.

    /// PREPROCESSED-trace setup commit for the OuterSC wrap
    /// machine: stacked BaseFold over the Poseidon2-BN254 `OuterValMmcs`
    /// (no two-adic coset LDE).  Returns the `OuterValMmcs::Commitment`, which
    /// is `Com<KoalaBearPoseidon2Outer>` since
    /// `OuterPcs = TwoAdicFriPcs<_, _, OuterValMmcs, _>` -- the equality the
    /// generic `setup` cannot see, which is why this impl exists.
    impl zkm_pcs::PrepCommitRoot<KoalaBearPoseidon2Outer>
        for zkm_pcs::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<OuterValMmcs>
    {
        /// The RAW root, NOT the hash-bound digest the inner ring now returns.
        /// The bind is `compress([root, hash(counts)])` over the Poseidon2-
        /// KOALABEAR compressor, and this ring's digest is a BN254 element; the
        /// wrap machine also opens a single round, so there is no preceding
        /// round whose geometry would need pinning here.  If the wrap ever
        /// grows a preprocessed opening round, it needs its own BN254 bind.
        fn commit_root(&self) -> zkm_pcs::Com<KoalaBearPoseidon2Outer> {
            self.commit.original_commitment.clone()
        }
    }

    pub(crate) fn outer_prep_commit(
        chip_traces: &[(String, RowMajorMatrix<JaggedVal>)],
        use_rev: bool,
    ) -> zkm_pcs::Com<KoalaBearPoseidon2Outer> {
        outer_prep_precompute(chip_traces, use_rev).commit.original_commitment
    }

    /// Same commit as [`outer_prep_commit`], keeping the BaseFold prover data
    /// so the preprocessed round can be OPENED.  See
    /// `StarkGenericConfig::PrepPrecomputed`.
    pub(crate) fn outer_prep_precompute(
        chip_traces: &[(String, RowMajorMatrix<JaggedVal>)],
        use_rev: bool,
    ) -> zkm_pcs::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<OuterValMmcs> {
        use zkm_pcs::jagged_pcs::jagged::precompute_jagged_basefold_commit_generic;

        let mmcs = <KoalaBearPoseidon2Outer as zkm_pcs::BasefoldRing>::bf_mmcs();
        let fri = <KoalaBearPoseidon2Outer as zkm_pcs::BasefoldRing>::fri_config();
        // The commit consumes BORROWED views over the
        // owned `chip_traces` (JaggedVal == InnerVal), kept alive across the call.
        let chip_trace_views = zkm_pcs::jagged_pcs::jagged::views_over_owned(chip_traces);
        let pre = precompute_jagged_basefold_commit_generic::<OuterValMmcs>(
            &chip_trace_views,
            mmcs,
            fri,
            // The machine's orientation (the wrap machine is LEGACY bitrev).
            use_rev,
            // setup/preprocessed commit is never
            // a recursion prove commit → no AREA PIN (`None`), byte-identical.
            None,
        );
        pre
    }
}

// Runtime validation that the stacked
// BaseFold jagged-PCS actually commits / opens / verifies over the OUTER ring
// (Poseidon2-BN254 `OuterValMmcs` + `MultiField32Challenger`). This is the
// cryptographic heart the wrap shard reuses; an honest proof must verify.
#[cfg(test)]
mod basefold_over_bn254_roundtrip_test {
    use super::{outer_perm, KoalaBearPoseidon2Outer, OuterChallenger, OuterDft, OuterValMmcs};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    use std::sync::Arc;
    use zkm_pcs::jagged_pcs::JaggedVal;
    use zkm_pcs::BasefoldRing;

    fn make_challenger() -> OuterChallenger {
        OuterChallenger::new(outer_perm()).unwrap()
    }

    #[test]
    fn test_basefold_jagged_pcs_roundtrip_bn254() {
        let mk = |w: usize, h: usize, seed: u64| -> RowMajorMatrix<JaggedVal> {
            let v: Vec<JaggedVal> = (0..(w * h))
                .map(|i| {
                    JaggedVal::from_u32(((i as u64 * 2_654_435_761 + seed) % 1_000_003) as u32)
                })
                .collect();
            RowMajorMatrix::new(v, w)
        };
        let traces = vec![("Cpu".to_string(), mk(20, 100, 1)), ("Add".to_string(), mk(8, 50, 7))];

        let mmcs = <KoalaBearPoseidon2Outer as BasefoldRing>::bf_mmcs();
        let dft = Arc::new(OuterDft::default());

        // The commit/open/verify roundtrip body is inlined in this test.
        //
        // It lives HERE rather than next to the PCS purely because of crate layering: the outer-ring
        // types (`OuterValMmcs` / `OuterChallenger` / `OuterDft`) are defined in this crate while the
        // PCS is in `zkm-pcs`, so the test cannot sit beside the code it exercises.
        // Do NOT "tidy" this back into a shared `pub fn` in the prover library — that ships a test
        // fixture as public API.
        use p3_challenger::{CanObserve, FieldChallenger};
        use zkm_pcs::basefold::FriConfig;
        use zkm_pcs::jagged_pcs::{
            commit_jagged_pcs_generic, open_jagged_pcs_generic, verify_jagged_pcs_generic,
            JaggedChallenge,
        };

        // Committed the way PRODUCTION commits: as ONE width-1 jagged dense
        // (`materialize_dense_jagged` over `committed_dense_len` cells — the
        // precompute call shape).  Committing the raw per-chip matrices
        // instead would round EACH chip's height up to whole 2^21 stacking
        // blocks (28 stripes for this toy, vs the dense's single stripe).
        let trace_views: Vec<zkm_pcs::jagged_pcs::jagged::ChipTraceView> = traces
            .iter()
            .map(|(name, m)| {
                (name.clone(), {
                    let h = if m.width == 0 { 0 } else { m.values.len() / m.width };
                    let log_h = if h <= 1 { 0 } else { h.next_power_of_two().ilog2() };
                    zkm_pcs::multilinear::PaddedMle::padded_with_zeros(
                        std::sync::Arc::new(zkm_pcs::basefold::Mle::from_row_major(
                            p3_matrix::dense::RowMajorMatrix::new(m.values.clone(), m.width),
                        )),
                        log_h,
                    )
                })
            })
            .collect();
        let packing = zkm_pcs::jagged::compute_jagged_metadata::<JaggedVal>(&trace_views);
        let dense = zkm_pcs::jagged::materialize_dense_jagged::<JaggedVal>(
            &trace_views,
            packing.dense_len,
            false,
        );
        let dense_traces = vec![("<jagged-dense>".to_string(), RowMajorMatrix::new(dense, 1))];

        // Self-consistency roundtrip: commit/open/verify must agree on ONE config;
        // env-default rate keeps prover == verifier (any rate works here).
        let rt_fri = FriConfig::<JaggedVal>::from_env_or_default();
        let mut p_chal = make_challenger();
        let (commit, prover_data) = commit_jagged_pcs_generic::<OuterValMmcs, OuterDft>(
            dense_traces,
            mmcs.clone(),
            dft.clone(),
            rt_fri.clone(),
        );
        // Caller owns the transcript write, matching the prove path.
        p_chal.observe(commit.original_commitment.clone());

        let stack_dim = commit.log_stacking_height as usize;
        let num_stripes = commit.area >> stack_dim;
        let num_batch_vars = num_stripes.next_power_of_two().trailing_zeros() as usize;
        let total_vars = num_batch_vars + stack_dim;

        // Deterministic eval point from a fresh (unobserved) challenger, so prover and
        // verifier agree without an RNG dependency.
        let mut pt_chal = make_challenger();
        let eval_point: Vec<JaggedChallenge> =
            (0..total_vars).map(|_| pt_chal.sample_algebra_element()).collect();

        // The honest evaluation claim, folded from the committed interleaved MLEs.
        let stack_point: Vec<JaggedChallenge> = eval_point[..stack_dim].to_vec();
        let batch_evals_flat: Vec<JaggedChallenge> = prover_data
            .stacked_data
            .interleaved_mles
            .iter()
            .flat_map(|m| m.eval_at::<JaggedChallenge>(&stack_point))
            .collect();
        // The verifier's `eval_multilinear_padded` (zkm-pcs basefold/stacked.rs)
        // walks the point coords FORWARD (LSB-first, `point[0]` binds var 0), so
        // this hand-rolled fold must too.
        let batch_point = &eval_point[stack_dim..];
        let evaluation_claim = {
            let target = 1usize << batch_point.len();
            let mut current: Vec<JaggedChallenge> = batch_evals_flat.clone();
            current.resize(target, JaggedChallenge::ZERO);
            for &r in batch_point.iter() {
                let half = current.len() / 2;
                for i in 0..half {
                    let lo = current[2 * i];
                    let hi = current[2 * i + 1];
                    current[i] = lo + r * (hi - lo);
                }
                current.truncate(half);
            }
            current[0]
        };

        let proof = open_jagged_pcs_generic::<OuterChallenger, OuterValMmcs, OuterDft>(
            &prover_data,
            eval_point.clone(),
            &mut p_chal,
            mmcs.clone(),
            dft.clone(),
            rt_fri.clone(),
        );

        let mut v_chal = make_challenger();
        v_chal.observe(commit.original_commitment.clone());
        verify_jagged_pcs_generic::<OuterChallenger, OuterValMmcs>(
            &commit.original_commitment,
            commit.area,
            commit.log_stacking_height,
            &eval_point,
            evaluation_claim,
            &proof,
            &mut v_chal,
            mmcs,
            rt_fri,
        )
        .expect("BaseFold jagged-PCS commit/open/verify roundtrip over the BN254 outer ring");
    }

    // Full jagged-basefold BUNDLE pipeline (jagged sumcheck reduction +
    // jagged-eval + BaseFold open/verify) over the BN254 outer ring — one layer
    // above the PCS roundtrip; this is what the wrap shard's open/verify hooks
    // drive: `prove_jagged_basefold_rounds_generic` with the single MAIN round
    // and the `build_jagged_verify_inputs` +
    // `verify_jagged_basefold_inner_generic` mirror.
    #[test]
    fn test_jagged_basefold_bundle_roundtrip_bn254() {
        use p3_challenger::{CanObserve, FieldChallenger};
        use zkm_pcs::jagged_pcs::jagged::{
            build_jagged_verify_inputs, precompute_jagged_basefold_commit_generic,
            prove_jagged_basefold_rounds_generic, verify_jagged_basefold_inner_generic,
            JaggedOpenRound,
        };
        use zkm_pcs::jagged_pcs::JaggedChallenge;

        let mk = |w: usize, h: usize, seed: u64| -> RowMajorMatrix<JaggedVal> {
            let v: Vec<JaggedVal> = (0..(w * h))
                .map(|i| {
                    JaggedVal::from_u32(
                        (((i as u64).wrapping_mul(2_654_435_761).wrapping_add(seed)) % 1_000_003)
                            as u32,
                    )
                })
                .collect();
            RowMajorMatrix::new(v, w)
        };
        let traces = vec![("Cpu".to_string(), mk(4, 16, 1)), ("Add".to_string(), mk(2, 8, 7))];

        let mmcs = <KoalaBearPoseidon2Outer as BasefoldRing>::bf_mmcs();
        let dft = Arc::new(OuterDft::default());

        // z_row sampled deterministically from a fresh challenger, shared by
        // prover and verifier — the production shape: ONE shared eval point of
        // `DEFAULT_LOG_STACKING_HEIGHT` coords (the zerocheck z*), from which
        // each chip's `r_row` is the trailing `log2(height)` slice
        // (shard_level/prover.rs).
        let mut pt = make_challenger();
        let z_row: Vec<JaggedChallenge> = (0..zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT
            as usize)
            .map(|_| pt.sample_algebra_element())
            .collect();
        let r_row_per_chip: Vec<Vec<JaggedChallenge>> = traces
            .iter()
            .map(|(_, t)| {
                let h = t.values.len() / t.width.max(1);
                let log_h = h.next_power_of_two().trailing_zeros() as usize;
                z_row[z_row.len() - log_h..].to_vec()
            })
            .collect();

        // The jagged entry points take `(name, PaddedMle)` pairs, not owned
        // matrices; build them once and reuse.
        let trace_views: Vec<zkm_pcs::jagged_pcs::jagged::ChipTraceView> = traces
            .iter()
            .map(|(name, m)| {
                (name.clone(), {
                    let h = if m.width == 0 { 0 } else { m.values.len() / m.width };
                    let log_h = if h <= 1 { 0 } else { h.next_power_of_two().ilog2() };
                    zkm_pcs::multilinear::PaddedMle::padded_with_zeros(
                        std::sync::Arc::new(zkm_pcs::basefold::Mle::from_row_major(
                            p3_matrix::dense::RowMajorMatrix::new(m.values.clone(), m.width),
                        )),
                        log_h,
                    )
                })
            })
            .collect();

        let fri = <KoalaBearPoseidon2Outer as BasefoldRing>::fri_config();
        let precompute = precompute_jagged_basefold_commit_generic::<OuterValMmcs>(
            &trace_views,
            mmcs.clone(),
            fri.clone(),
            // use_rev: false on the wrap/BN254 path.
            false,
            // recursion_area_pin: None => NATURAL own-area packing (this is a wrap-ring test).
            None,
        );
        let commitment = precompute.commit.original_commitment.clone();

        // Honest step-3 column claims — the values the production prover reads
        // off the zerocheck residual: the full row_eq over z_row indexed by the
        // BIT-REVERSED trace row (legacy orientation, in lockstep with the
        // `use_rev = false` commit above).
        let claims: Vec<Vec<JaggedChallenge>> = {
            let z_row_rev: Vec<JaggedChallenge> = z_row.iter().rev().copied().collect();
            let eq_c = zkm_pcs::zerocheck_prover::eq_mle_table::<JaggedChallenge>(&z_row_rev);
            traces
                .iter()
                .map(|(_, t)| {
                    let w = t.width;
                    let h = t.values.len() / w;
                    let log_h = (h as u32).trailing_zeros();
                    (0..w)
                        .map(|col| {
                            (0..h).fold(JaggedChallenge::ZERO, |acc, row| {
                                let src =
                                    ((row as u32).reverse_bits() >> (32 - log_h)) as usize;
                                acc + eq_c[row] * JaggedChallenge::from(t.values[src * w + col])
                            })
                        })
                        .collect()
                })
                .collect()
        };

        let mut p_chal = make_challenger();
        p_chal.observe(commitment.clone());
        let rounds = [JaggedOpenRound {
            chip_traces: &trace_views,
            r_row_per_chip: &r_row_per_chip,
            claims,
            precomputed: &precompute,
        }];
        let bundle =
            prove_jagged_basefold_rounds_generic::<OuterChallenger, OuterValMmcs, OuterDft>(
                &rounds,
                &z_row,
                &mut p_chal,
                mmcs.clone(),
                dft,
                fri.clone(),
            );

        // Verifier inputs rebuilt from the bundle's packing — chip_infos
        // carrying the EXPLICIT stacking-padding columns, exactly as the outer
        // shard verifier rebuilds them (shard_level/verifier.rs).
        let chip_widths: Vec<usize> = traces.iter().map(|(_, t)| t.width).collect();
        let (chip_infos, r_row_v, z_row_v) =
            build_jagged_verify_inputs(&bundle.packing, &chip_widths, &z_row);
        let mut v_chal = make_challenger();
        v_chal.observe(commitment);
        let ok = verify_jagged_basefold_inner_generic::<OuterChallenger, OuterValMmcs>(
            &chip_infos,
            &r_row_v,
            &z_row_v,
            &bundle,
            &mut v_chal,
            mmcs,
            /* skip_commit_observe = */ true,
            fri,
            // Single-round fixture: no preceding rounds.
            &[],
        );
        assert!(
            ok,
            "jagged-basefold full bundle pipeline should accept the honest proof over BN254"
        );
    }
}
