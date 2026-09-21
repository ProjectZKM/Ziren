use p3_bn254_fr::{Bn254, Poseidon2Bn254};
use p3_challenger::MultiField32Challenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
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
        pin: Option<zkm_pcs::jagged::AreaPin>,
    ) -> zkm_pcs::Com<Self> {
        outer_jagged_hooks::outer_prep_commit(named_preprocessed_traces, pin)
    }

    type PrepPrecomputed =
        zkm_pcs::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<OuterValMmcs>;

    fn prep_precompute(
        named_preprocessed_traces: &[(
            String,
            p3_matrix::dense::RowMajorMatrix<zkm_pcs::jagged_pcs::JaggedVal>,
        )],
        pin: Option<zkm_pcs::jagged::AreaPin>,
    ) -> Self::PrepPrecomputed {
        outer_jagged_hooks::outer_prep_precompute(named_preprocessed_traces, pin)
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
// via the `BasefoldRing::commit_multilinears` default (over `OuterValMmcs`), and
// `prove_trusted_evaluations` / `verify_jagged_pcs_host` dispatch statically
// through this impl.
impl BasefoldRing for KoalaBearPoseidon2Outer {
    const WHIR_INNER_PCS: bool = false;

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
        zkm_pcs::basefold::config::FriConfig::<zkm_pcs::jagged_pcs::JaggedVal>::wrap_fri_config()
    }

    /// `Com<KoalaBearPoseidon2Outer>` is `OuterPcs::Commitment` =
    /// `OuterValMmcs::Commitment` = `Hash<KoalaBear, Bn254, 1>`, the SAME type
    /// the BaseFold open Merkle-verifies against, and this ring's `commit_root`
    /// stores it unmixed — so the bind is the equality itself.
    fn vk_commit_is_preceding_root(
        vk_commit: &zkm_pcs::Com<Self>,
        raw: &<Self::BfMmcs as p3_commit::Mmcs<zkm_pcs::jagged_pcs::JaggedVal>>::Commitment,
    ) -> Option<bool> {
        Some(vk_commit == raw)
    }

    fn digest_felts(
        commit: &<Self::BfMmcs as p3_commit::Mmcs<zkm_pcs::jagged_pcs::JaggedVal>>::Commitment,
    ) -> [zkm_pcs::jagged_pcs::JaggedVal; 8] {
        let roots = commit.roots();
        assert!(!roots.is_empty(), "BN254 wrap commitment MerkleCap must have at least one root",);
        let felts = p3_field::split_32::<Bn254, KoalaBear>(roots[0][0], 8);
        let mut out = [KoalaBear::default(); 8];
        for (i, o) in out.iter_mut().enumerate() {
            *o = felts.get(i).copied().unwrap_or_default();
        }
        out
    }

    // `commit_multilinears` — the wrap ring's BN254 jagged BaseFold
    // precompute — is the trait DEFAULT (this ring's `bf_mmcs()` /
    // `fri_config()` are what it reads): EXACTLY the commit the retired
    // outer BaseFold commit path produced for OuterSC.

    fn prove_jagged_open(
        z_row: &[zkm_pcs::InnerChallenge],
        rounds: Vec<zkm_pcs::jagged_pcs::jagged::JaggedOpenRound<'_, Self::BfMmcs>>,
        challenger: &mut Self::Challenger,
    ) -> zkm_pcs::shard_level::shard_proof::EvaluationProof {
        let bundle = zkm_pcs::jagged_pcs::jagged::prove_jagged_rounds_generic::<
            Self::Challenger,
            Self::BfMmcs,
            zkm_pcs::jagged_pcs::JaggedDft,
            zkm_pcs::jagged_pcs::jagged::BasefoldDenseOpen,
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
    // The commit does not observe internally; the caller needs `CanObserve`.
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
        _dft: Arc<OuterDft>,
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
// `OuterValMmcs`, while the ring commit (`BasefoldRing::commit_multilinears`)
// must be dispatched on a concrete ring; the config impl supplies it.  `Val`/`Challenge` are
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
        pin: Option<zkm_pcs::jagged::AreaPin>,
    ) -> zkm_pcs::Com<KoalaBearPoseidon2Outer> {
        outer_prep_precompute(chip_traces, pin).commit.original_commitment
    }

    /// Same commit as [`outer_prep_commit`], keeping the BaseFold prover data
    /// so the preprocessed round can be OPENED.  See
    /// `StarkGenericConfig::PrepPrecomputed`.
    pub(crate) fn outer_prep_precompute(
        chip_traces: &[(String, RowMajorMatrix<JaggedVal>)],
        pin: Option<zkm_pcs::jagged::AreaPin>,
    ) -> zkm_pcs::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<OuterValMmcs> {
        let chip_trace_views = zkm_pcs::jagged_pcs::jagged::views_over_owned(chip_traces);
        <KoalaBearPoseidon2Outer as zkm_pcs::BasefoldRing>::commit_multilinears(
            &chip_trace_views,
            pin,
        )
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
        let traces = [("Cpu".to_string(), mk(20, 100, 1)), ("Add".to_string(), mk(8, 50, 7))];

        let mmcs = <KoalaBearPoseidon2Outer as BasefoldRing>::bf_mmcs();
        let dft = Arc::new(OuterDft::default());

        use p3_challenger::{CanObserve, FieldChallenger};
        use zkm_pcs::basefold::FriConfig;
        use zkm_pcs::jagged_pcs::{
            commit_jagged_pcs_generic, open_jagged_pcs_generic, verify_jagged_pcs_generic,
            JaggedChallenge,
        };

        let trace_views: Vec<zkm_pcs::jagged_pcs::jagged::ChipTraceView> = traces
            .iter()
            .map(|(name, m)| {
                (name.clone(), {
                    let h = m.values.len().checked_div(m.width).unwrap_or(0);
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
        let dense =
            zkm_pcs::jagged::materialize_dense_jagged::<JaggedVal>(&trace_views, packing.dense_len);
        let dense_traces = vec![("<jagged-dense>".to_string(), RowMajorMatrix::new(dense, 1))];

        let rt_fri = FriConfig::<JaggedVal>::from_env_or_default();
        let mut p_chal = make_challenger();
        let (commit, prover_data) = commit_jagged_pcs_generic::<OuterValMmcs, OuterDft>(
            dense_traces,
            mmcs.clone(),
            dft.clone(),
            rt_fri.clone(),
        );
        p_chal.observe(commit.original_commitment.clone());

        let stack_dim = commit.log_stacking_height as usize;
        let num_stripes = commit.area >> stack_dim;
        let num_batch_vars = num_stripes.next_power_of_two().trailing_zeros() as usize;
        let total_vars = num_batch_vars + stack_dim;

        let mut pt_chal = make_challenger();
        let eval_point: Vec<JaggedChallenge> =
            (0..total_vars).map(|_| pt_chal.sample_algebra_element()).collect();

        let stack_point: Vec<JaggedChallenge> = eval_point[..stack_dim].to_vec();
        let batch_evals_flat: Vec<JaggedChallenge> = prover_data
            .stacked_data
            .interleaved_mles
            .iter()
            .flat_map(|m| m.eval_at::<JaggedChallenge>(&stack_point))
            .collect();
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

    #[test]
    fn test_jagged_basefold_bundle_roundtrip_bn254() {
        use p3_challenger::{CanObserve, FieldChallenger};
        use zkm_pcs::jagged_pcs::jagged::{
            build_jagged_verify_inputs, prove_jagged_rounds_generic, verify_jagged_inner_generic,
            BasefoldDenseOpen, JaggedOpenRound,
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
        let traces = [("Cpu".to_string(), mk(4, 16, 1)), ("Add".to_string(), mk(2, 8, 7))];

        let mmcs = <KoalaBearPoseidon2Outer as BasefoldRing>::bf_mmcs();
        let dft = Arc::new(OuterDft::default());

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

        let trace_views: Vec<zkm_pcs::jagged_pcs::jagged::ChipTraceView> = traces
            .iter()
            .map(|(name, m)| {
                (name.clone(), {
                    let h = m.values.len().checked_div(m.width).unwrap_or(0);
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
        let precompute =
            <KoalaBearPoseidon2Outer as BasefoldRing>::commit_multilinears(&trace_views, None);
        let commitment = precompute.commit.original_commitment.clone();

        let claims: Vec<Vec<JaggedChallenge>> = {
            let z_row_rev: Vec<JaggedChallenge> = z_row.iter().rev().copied().collect();
            let eq_c = zkm_pcs::zerocheck_prover::eq_mle_table::<JaggedChallenge>(&z_row_rev);
            traces
                .iter()
                .map(|(_, t)| {
                    let w = t.width;
                    let h = t.values.len() / w;
                    (0..w)
                        .map(|col| {
                            (0..h).fold(JaggedChallenge::ZERO, |acc, row| {
                                acc + eq_c[row] * JaggedChallenge::from(t.values[row * w + col])
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
        let bundle = prove_jagged_rounds_generic::<
            OuterChallenger,
            OuterValMmcs,
            OuterDft,
            BasefoldDenseOpen,
        >(&rounds, &z_row, &mut p_chal, mmcs.clone(), dft, fri.clone());

        let chip_widths: Vec<usize> = traces.iter().map(|(_, t)| t.width).collect();
        let (chip_infos, r_row_v, z_row_v) =
            build_jagged_verify_inputs(&bundle.packing, &chip_widths, &z_row);
        let mut v_chal = make_challenger();
        v_chal.observe(commitment.clone());
        let ok = verify_jagged_inner_generic::<OuterChallenger, OuterValMmcs>(
            &chip_infos,
            &r_row_v,
            &z_row_v,
            &bundle,
            &mut v_chal,
            mmcs,
            true,
            fri,
            &[],
            &bundle.y_per_chip.clone(),
        );
        assert!(
            ok,
            "jagged-basefold full bundle pipeline should accept the honest proof over BN254"
        );

        let honest: Vec<Vec<JaggedChallenge>> = bundle.y_per_chip.clone();
        let mut v_chal = make_challenger();
        v_chal.observe(commitment.clone());
        assert!(
            verify_jagged_inner_generic::<OuterChallenger, OuterValMmcs>(
                &chip_infos,
                &r_row_v,
                &z_row_v,
                &bundle,
                &mut v_chal,
                <KoalaBearPoseidon2Outer as BasefoldRing>::bf_mmcs(),
                true,
                <KoalaBearPoseidon2Outer as BasefoldRing>::fri_config(),
                &[],
                &honest,
            ),
            "the cross-bind must accept openings that agree with the bundle's column claims"
        );

        let mut tampered = honest.clone();
        tampered[0][0] += JaggedChallenge::ONE;
        let mut v_chal = make_challenger();
        v_chal.observe(commitment.clone());
        assert!(
            !verify_jagged_inner_generic::<OuterChallenger, OuterValMmcs>(
                &chip_infos,
                &r_row_v,
                &z_row_v,
                &bundle,
                &mut v_chal,
                <KoalaBearPoseidon2Outer as BasefoldRing>::bf_mmcs(),
                true,
                <KoalaBearPoseidon2Outer as BasefoldRing>::fri_config(),
                &[],
                &tampered,
            ),
            "the cross-bind must REJECT openings that disagree with the bundle's column \
             claims — without it the zerocheck and the jagged phase can describe two \
             different traces"
        );
    }

    /// **Commitment order on the ring that feeds gnark.**
    ///
    /// The outer BaseFold bundle is the artifact the Groth16 circuit verifies,
    /// and its roots must be witnessed in opening order `[preceding.., main]`.
    /// The single-round fixture above cannot reach that: with no preceding
    /// round the root vector has one entry, so every ordering of it is correct.
    ///
    /// Covers the substitutions the audit's cross-binding gate names, on this
    /// ring: the raw MAIN root, the raw PRECEDING (preprocessed) root, and the
    /// packing counts.  Each must be REJECTED — and the honest two-round bundle
    /// must verify first, or the rejections below prove nothing.
    #[test]
    fn outer_two_round_rejects_substituted_roots() {
        use p3_challenger::{CanObserve, FieldChallenger};
        use zkm_pcs::jagged_pcs::jagged::{
            build_jagged_verify_inputs, prove_jagged_rounds_generic, verify_jagged_inner_generic,
            BasefoldDenseOpen, JaggedOpenRound,
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
        let prep_traces =
            [("PrepA".to_string(), mk(4, 16, 11)), ("PrepB".to_string(), mk(2, 8, 13))];
        let main_traces = [("MainA".to_string(), mk(3, 32, 17))];

        let views = |ts: &[(String, RowMajorMatrix<JaggedVal>)]| -> Vec<
            zkm_pcs::jagged_pcs::jagged::ChipTraceView,
        > {
            ts.iter()
                .map(|(name, m)| {
                    (name.clone(), {
                        let h = m.values.len().checked_div(m.width).unwrap_or(0);
                        let log_h = if h <= 1 { 0 } else { h.next_power_of_two().ilog2() };
                        zkm_pcs::multilinear::PaddedMle::padded_with_zeros(
                            std::sync::Arc::new(zkm_pcs::basefold::Mle::from_row_major(
                                p3_matrix::dense::RowMajorMatrix::new(m.values.clone(), m.width),
                            )),
                            log_h,
                        )
                    })
                })
                .collect()
        };
        let prep_views = views(&prep_traces);
        let main_views = views(&main_traces);

        let mmcs = <KoalaBearPoseidon2Outer as BasefoldRing>::bf_mmcs();
        let dft = Arc::new(OuterDft::default());
        let fri = <KoalaBearPoseidon2Outer as BasefoldRing>::fri_config();
        let prep =
            <KoalaBearPoseidon2Outer as BasefoldRing>::commit_multilinears(&prep_views, None);
        let main =
            <KoalaBearPoseidon2Outer as BasefoldRing>::commit_multilinears(&main_views, None);
        let prep_root = prep.commit.original_commitment.clone();
        let main_root = main.commit.original_commitment.clone();
        assert_ne!(
            format!("{prep_root:?}"),
            format!("{main_root:?}"),
            "the two rounds must commit to different roots or the substitutions below are no-ops"
        );

        let mut pt = make_challenger();
        let z_row: Vec<JaggedChallenge> = (0..zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT
            as usize)
            .map(|_| pt.sample_algebra_element())
            .collect();
        let r_row = |ts: &[(String, RowMajorMatrix<JaggedVal>)]| -> Vec<Vec<JaggedChallenge>> {
            ts.iter()
                .map(|(_, t)| {
                    let h = t.values.len() / t.width.max(1);
                    let log_h = h.next_power_of_two().trailing_zeros() as usize;
                    z_row[z_row.len() - log_h..].to_vec()
                })
                .collect()
        };
        let claims = |ts: &[(String, RowMajorMatrix<JaggedVal>)]| -> Vec<Vec<JaggedChallenge>> {
            let z_row_rev: Vec<JaggedChallenge> = z_row.iter().rev().copied().collect();
            let eq_c = zkm_pcs::zerocheck_prover::eq_mle_table::<JaggedChallenge>(&z_row_rev);
            ts.iter()
                .map(|(_, t)| {
                    let w = t.width;
                    let h = t.values.len() / w;
                    (0..w)
                        .map(|col| {
                            (0..h).fold(JaggedChallenge::ZERO, |acc, row| {
                                acc + eq_c[row] * JaggedChallenge::from(t.values[row * w + col])
                            })
                        })
                        .collect()
                })
                .collect()
        };
        let prep_r_row = r_row(&prep_traces);
        let main_r_row = r_row(&main_traces);

        let mut p_chal = make_challenger();
        p_chal.observe(prep_root.clone());
        p_chal.observe(main_root.clone());
        let rounds = [
            JaggedOpenRound {
                chip_traces: &prep_views,
                r_row_per_chip: &prep_r_row,
                claims: claims(&prep_traces),
                precomputed: &prep,
            },
            JaggedOpenRound {
                chip_traces: &main_views,
                r_row_per_chip: &main_r_row,
                claims: claims(&main_traces),
                precomputed: &main,
            },
        ];
        let bundle = prove_jagged_rounds_generic::<
            OuterChallenger,
            OuterValMmcs,
            OuterDft,
            BasefoldDenseOpen,
        >(&rounds, &z_row, &mut p_chal, mmcs.clone(), dft, fri.clone());

        assert_eq!(bundle.preceding_commits.len(), 1);
        assert_eq!(format!("{:?}", bundle.preceding_commits[0]), format!("{prep_root:?}"));
        assert_eq!(format!("{:?}", bundle.commit.original_commitment), format!("{main_root:?}"));

        let chip_widths: Vec<usize> =
            prep_traces.iter().chain(main_traces.iter()).map(|(_, t)| t.width).collect();
        let (chip_infos, r_row_v, z_row_v) =
            build_jagged_verify_inputs(&bundle.packing, &chip_widths, &z_row);

        let verify = |b: &zkm_pcs::jagged_pcs::jagged::JaggedPcsProofGeneric<OuterValMmcs>,
                      preceding_root: &<OuterValMmcs as p3_commit::Mmcs<JaggedVal>>::Commitment|
         -> bool {
            let mut v_chal = make_challenger();
            v_chal.observe(prep_root.clone());
            v_chal.observe(main_root.clone());
            verify_jagged_inner_generic::<OuterChallenger, OuterValMmcs>(
                &chip_infos,
                &r_row_v,
                &z_row_v,
                b,
                &mut v_chal,
                mmcs.clone(),
                true,
                fri.clone(),
                &[(preceding_root.clone(), prep.prover_data.area)],
                &b.y_per_chip.clone(),
            )
        };

        assert!(verify(&bundle, &prep_root), "the honest two-round outer bundle must verify");

        assert!(
            !verify(&bundle, &main_root),
            "a substituted preceding (preprocessed) root must be rejected"
        );

        let mut tampered = bundle.clone();
        tampered.commit.original_commitment = prep_root.clone();
        assert!(!verify(&tampered, &prep_root), "a substituted main root must be rejected");
    }

    /// The preceding-root bind (the preprocessed round's root is the key's) is
    /// dispatched through a trait method whose default is `None` = "this ring
    /// cannot answer, re-derive instead". A `None` here would make the host
    /// bind a silent no-op, so the answer being `Some`, and discriminating, is
    /// the thing to test.
    #[test]
    fn outer_vk_commit_bind_is_not_vacuous() {
        type R = KoalaBearPoseidon2Outer;
        let traces = vec![("Cpu".to_string(), {
            let v: Vec<JaggedVal> = (0..64)
                .map(|i| JaggedVal::from_u32((i * 2_654_435_761u64 % 1_000_003) as u32))
                .collect();
            RowMajorMatrix::new(v, 4)
        })];
        let real = crate::stark::config::outer_jagged_hooks::outer_prep_commit(&traces, None);
        let other = zkm_pcs::Com::<R>::default();
        assert_ne!(real, other, "fixture precondition: a real commit differs from the default");
        assert_eq!(
            <R as BasefoldRing>::vk_commit_is_preceding_root(&real, &real),
            Some(true),
            "the outer ring stores the raw root, so a key equal to the proof's root is a match"
        );
        assert_eq!(
            <R as BasefoldRing>::vk_commit_is_preceding_root(&other, &real),
            Some(false),
            "a different root must be reported as a mismatch, not as unanswerable"
        );
    }
}

/// The wrap ring performs the LogUp-GKR grind its soundness report counts.
///
/// `docs/soundness/ziren.soundcalc.toml` credits `grinding_bits_lookup = 16` on
/// every circuit, wrap included. That was once false here: `gkr_grind` returned
/// zero without observing for a non-inner challenger, the host's
/// `gkr_check_witness` accepted unconditionally, and the circuit's
/// `MultiField32ChallengerVariable` override was an explicit no-op — so the wrap
/// figure credited 16 bits nothing earned, and the stated 100 was closer to 96.
///
/// The premise for that split was that the outer challenger could not grind. It
/// can: the wrap BaseFold open grinds `pow_bits = 22` through the very same
/// `GrindingChallenger`. These tests pin all three halves of the property on
/// THIS ring — the grind advances the transcript, an honest witness is accepted
/// and leaves prover and verifier in the same state, and a tampered one is not —
/// so the no-op cannot come back and still pass.
///
/// The inner ring's copies live in `zkm_pcs::logup_gkr`; zkm-pcs cannot import
/// `OuterSC`, which is why this ring's are here.
#[cfg(test)]
mod wrap_gkr_grind {
    use super::{outer_perm, OuterChallenger};
    use p3_challenger::{CanObserve, CanSample};
    use p3_field::PrimeCharacteristicRing;
    use zkm_pcs::jagged_pcs::JaggedVal;
    use zkm_pcs::logup_gkr::{gkr_check_witness, gkr_grind, GKR_GRINDING_BITS};

    /// Seeded so the grind starts from a non-trivial state, and reproducible so
    /// prover and verifier can be handed the SAME state.
    fn seeded() -> OuterChallenger {
        let mut ch = OuterChallenger::new(outer_perm()).unwrap();
        ch.observe(JaggedVal::from_u32(0xA11CE));
        ch.observe(JaggedVal::from_u32(0xB0B));
        ch
    }

    /// The assertion a no-op cannot pass.
    ///
    /// Accept/reject alone does not distinguish a grind from a stub: a stub that
    /// returns zero and observes nothing still "round-trips" against a stub
    /// checker. What separates them is whether the challenger MOVED, because
    /// every subsequent alpha and beta is drawn from that state.
    #[test]
    fn wrap_gkr_grind_advances_the_transcript() {
        let mut ungrinded = seeded();
        let before: JaggedVal = ungrinded.sample();

        let mut prover = seeded();
        let _witness: JaggedVal = gkr_grind(&mut prover, GKR_GRINDING_BITS);
        let after: JaggedVal = prover.sample();

        assert_ne!(
            before, after,
            "the wrap LogUp-GKR grind must advance the transcript; a grind that leaves the \
             challenger untouched costs nothing to produce, while the soundness report \
             counts 16 bits for it",
        );
    }

    /// The honest witness is accepted, and the two sides end in the same state —
    /// which is what "the verifier consumes the challenger exactly as the prover
    /// did" means in practice.
    #[test]
    fn wrap_gkr_grinding_witness_roundtrips() {
        let mut prover = seeded();
        let witness: JaggedVal = gkr_grind(&mut prover, GKR_GRINDING_BITS);

        let mut verifier = seeded();
        assert!(
            gkr_check_witness(&mut verifier, GKR_GRINDING_BITS, witness),
            "the honest wrap grinding witness must be accepted, or the negative case proves \
             nothing",
        );

        let p: JaggedVal = prover.sample();
        let v: JaggedVal = verifier.sample();
        assert_eq!(p, v, "prover and verifier must leave the wrap transcript in the same state");
    }

    /// NEGATIVE: one off-by-one witness. The check observes the witness and
    /// requires the squeezed challenge's low `GKR_GRINDING_BITS` to be zero, so a
    /// different witness re-seeds the sponge and fails except with probability
    /// `2^-16`.
    #[test]
    fn wrap_gkr_grinding_rejects_a_tampered_witness() {
        let mut prover = seeded();
        let witness: JaggedVal = gkr_grind(&mut prover, GKR_GRINDING_BITS);

        let mut verifier = seeded();
        assert!(
            !gkr_check_witness(&mut verifier, GKR_GRINDING_BITS, witness + JaggedVal::ONE),
            "a tampered wrap grinding witness must be rejected",
        );
    }
}
