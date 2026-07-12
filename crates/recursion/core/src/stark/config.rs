use p3_bn254_fr::{Bn254, Poseidon2Bn254};
use p3_challenger::MultiField32Challenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_commit::BatchOpening;
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
pub type OuterHash =
    MultiField32PaddingFreeSponge<OuterVal, Bn254, OuterPerm, 3, 16, DIGEST_SIZE>;
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
    FriParameters { log_blowup: 4, log_final_poly_len: 0, max_log_arity: 1, num_queries, commit_proof_of_work_bits: 16, query_proof_of_work_bits: 16, mmcs: challenge_mmcs }
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
    FriParameters { log_blowup, log_final_poly_len: 0, max_log_arity: 1, num_queries, commit_proof_of_work_bits: 16, query_proof_of_work_bits: 16, mmcs: challenge_mmcs }
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
    fn prep_commit_via_hook() -> bool {
        // SP1-style: the wrap machine's PREPROCESSED commit goes through the
        // stacked BaseFold (outer_prep_commit hook) — no two-adic coset LDE.
        // The `pcs.commit` LDE path caps prep heights at
        // 2^(TWO_ADICITY - log_blowup) = 2^20 (blowup 4) and panics once
        // the wrap program's tallest prep trace crosses it; its ProverData
        // has no consumers on the basefold path.
        true
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
// and `Challenge<OuterSC> = KoalaBear⁴` (same as inner; mirrors SP1's
// `BNGC<KoalaBear, KoalaBear⁴>`), so the BaseFold jagged-PCS over the
// Poseidon2-BN254 Merkle MMCS (`OuterValMmcs`, whose
// `Commitment = Hash<KoalaBear, Bn254, 1>`) applies directly. `bf_mmcs()`
// builds that MMCS so the generic BaseFold cores
// (`commit/open/verify_jagged_pcs_generic`) can run over it once the
// higher-level jagged bundle + 8-felt-digest stack is genericized over
// `BfMmcs::Commitment`.
//
// `use_basefold()` returns `false` for now — exactly mirroring the legacy
// `TypeId::of::<SC::Challenger>() == TypeId::of::<JaggedChallenger>()` gate,
// which was false for OuterSC (`Challenger = MultiField32Challenger`). This
// keeps the swap to `BasefoldRing` dispatch non-breaking: the wrap stays on
// the two-adic FRI path. Flip to `true` once `JaggedBasefoldBundle` /
// `prove_shard_to_basefold`'s `main_commitment: [Val; 8]` are genericized over
// `Self::BfMmcs::Commitment` (the remaining wrap-port work + vk regen); the
// `bf_mmcs()` infrastructure here is then consumed directly.
impl BasefoldRing for KoalaBearPoseidon2Outer {
    type BfMmcs = OuterValMmcs;

    fn bf_mmcs() -> Self::BfMmcs {
        let perm = outer_perm();
        let hash = OuterHash::new(perm.clone()).unwrap();
        let compress = OuterCompress::new(perm);
        OuterValMmcs::new(hash, compress, 0)
    }

    fn use_basefold() -> bool {
        // The digest tunnel + the outer
        // jagged open/verify dispatch (hooks) are wired, so the wrap STARK
        // proves + host-verifies over the BN254 BaseFold jagged-PCS
        // (OuterValMmcs + OuterChallenger). commit_basefold_path builds the BN254
        // commit via precompute_jagged_basefold_commit_generic::<OuterValMmcs>;
        // prove_trusted_evaluations / verify_jagged_pcs_host route to the
        // recursion-core hooks. (gnark verify_wrap_basefold + wrap vk regen +
        // FRI deletion remain.)
        true
    }

    fn fri_config(
    ) -> zkm_pcs::basefold::config::FriConfig<zkm_pcs::jagged_pcs::JaggedVal> {
        // WRAP-stage params: SP1-faithful (log_blowup=3, num_queries=94,
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
        assert!(
            !roots.is_empty(),
            "BN254 wrap commitment MerkleCap must have at least one root",
        );
        let felts = p3_field::split_32::<Bn254, KoalaBear>(roots[0][0], 8);
        let mut out = [KoalaBear::default(); 8];
        for i in 0..8 {
            out[i] = felts.get(i).copied().unwrap_or_default();
        }
        out
    }
}

/// The FRI config for testing recursion.
pub fn test_fri_config() -> FriParameters<OuterChallengeMmcs> {
    let perm = outer_perm();
    let hash = OuterHash::new(perm.clone()).unwrap();
    let compress = OuterCompress::new(perm.clone());
    let challenge_mmcs = OuterChallengeMmcs::new(OuterValMmcs::new(hash, compress, 0));
    FriParameters { log_blowup: 1, log_final_poly_len: 0, max_log_arity: 1, num_queries: 1, commit_proof_of_work_bits: 1, query_proof_of_work_bits: 1, mmcs: challenge_mmcs }
}

// ── D=5 outer config (128-bit security) ───────────────────────────────────


// Compile-time proof that the genericized
// BaseFold jagged-PCS digest path (`zkm_pcs::jagged_pcs::*_generic`) is
// instantiable over the OUTER ring's BN254 commitment family, i.e. that the
// BN254 commitment (`OuterValMmcs::Commitment = Hash<KoalaBear, Bn254, 1>`)
// "flows" through commit/open/verify exactly where the inner ring uses the
// 8-felt Poseidon2-KoalaBear digest. `Val`/`Challenge` stay KoalaBear /
// KoalaBear⁴ for both (mirrors SP1's `BNGC<KoalaBear, KoalaBear⁴>`); only the
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
    use std::sync::Arc;
    use zkm_pcs::jagged_pcs::{
        commit_jagged_pcs_host_generic, commit_jagged_pcs_no_observe_generic,
        open_jagged_pcs_host_generic, verify_jagged_pcs_generic,
        JaggedCommitGeneric, JaggedProverDataGeneric,
        JaggedChallenge, JaggedMmcs, JaggedVal,
    };
    use p3_matrix::dense::RowMajorMatrix;
    use zkm_pcs::basefold::{StackedBasefoldProof, StackedVerifierError};

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
    ) -> (
        JaggedCommitGeneric<OuterValMmcs>,
        JaggedProverDataGeneric<OuterValMmcs>,
    ) {
        let fri = <KoalaBearPoseidon2Outer as zkm_pcs::BasefoldRing>::fri_config();
        commit_jagged_pcs_no_observe_generic::<OuterValMmcs, OuterDft>(traces, mmcs, dft, fri)
    }

    // commit (with observe) — exercises `OuterChallenger:
    // CanObserve<OuterValMmcs::Commitment>` (the BN254 commit observe the
    // prologue would perform on the outer path).
    fn _commit_observe(
        traces: std::vec::Vec<(std::string::String, RowMajorMatrix<JaggedVal>)>,
        ch: &mut OuterChallenger,
        mmcs: OuterValMmcs,
        dft: Arc<OuterDft>,
    ) -> (
        JaggedCommitGeneric<OuterValMmcs>,
        JaggedProverDataGeneric<OuterValMmcs>,
    ) {
        let fri = <KoalaBearPoseidon2Outer as zkm_pcs::BasefoldRing>::fri_config();
        commit_jagged_pcs_host_generic::<OuterChallenger, OuterValMmcs, OuterDft>(
            traces, ch, mmcs, dft, fri,
        )
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
        open_jagged_pcs_host_generic::<OuterChallenger, OuterValMmcs, OuterDft>(
            pd, eval_point, ch, mmcs, dft, fri,
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
        verify_jagged_pcs_generic::<OuterChallenger, OuterValMmcs, OuterDft>(
            commitment,
            area,
            log_stacking_height,
            eval_point,
            evaluation_claim,
            proof,
            ch,
            mmcs,
            dft,
            fri,
        )
    }
}


// OUTER-ring jagged BaseFold setup hook.
// The open + verify hook bodies are static generic calls
// in `prove_trusted_evaluations` / `verify_jagged_pcs_host` over the `BasefoldRing`
// associated type). Only `outer_prep_commit` remains — registered into zkm-pcs's
// process-global hook slot so `StarkMachine::setup` (which cannot name
// `OuterValMmcs`) routes the wrap-ring preprocessed commit here. `Val`/`Challenge`
// are KoalaBear / KoalaBear^4 for both rings, so only the MMCS differs.
pub mod outer_jagged_hooks {
    use super::{KoalaBearPoseidon2Outer, OuterValMmcs};
    use p3_matrix::dense::RowMajorMatrix;
    use zkm_pcs::jagged_pcs::JaggedVal;

    // The shard prover (`prove_trusted_evaluations`) and host verifier
    // (`verify_jagged_pcs_host`) name `OuterChallenger`/`OuterValMmcs` via the
    // `BasefoldRing` associated type and call the generic BaseFold open/verify
    // statically, so the dyn-Any open/verify hooks are absent. Only
    // `outer_prep_commit` remains (setup/VK-side; a plain crate-dep fn pointer).

    /// Register the outer-ring jagged BaseFold prep-commit hook into zkm-pcs.
    /// Idempotent (OnceLock-backed); safe to call repeatedly. Must run before the
    /// wrap STARK proves/verifies on the BaseFold-over-BN254 path (i.e. once
    /// `KoalaBearPoseidon2Outer::use_basefold()` returns `true`).
    pub fn register_outer_jagged_hooks() {
        // The open + verify paths are static generic calls in the shard
        // prover / host verifier, so no open/verify hooks are registered.
        // Only the PREP-COMMIT hook remains (setup/VK-side crate-dep fn pointer).
        let _ = zkm_pcs::shard_level::sumcheck_poly::register_outer_prep_commit_hook(
            outer_prep_commit,
        );
    }

    /// SP1-style PREPROCESSED-trace setup commit for the OuterSC wrap
    /// machine: stacked BaseFold over the Poseidon2-BN254 `OuterValMmcs`
    /// (no two-adic coset LDE).  Returns bincode of the
    /// `OuterValMmcs::Commitment` (== `Com<KoalaBearPoseidon2Outer>` since
    /// `OuterPcs = TwoAdicFriPcs<_, _, OuterValMmcs, _>`).
    fn outer_prep_commit(
        chip_traces: Vec<(String, RowMajorMatrix<JaggedVal>)>,
    ) -> Vec<u8> {
        use zkm_pcs::jagged_pcs::jagged::precompute_jagged_basefold_commit_generic;
        
        let mmcs = <KoalaBearPoseidon2Outer as zkm_pcs::BasefoldRing>::bf_mmcs();
        let fri = <KoalaBearPoseidon2Outer as zkm_pcs::BasefoldRing>::fri_config();
        // SITE-1 trace-unification: the commit consumes BORROWED views over the
        // owned `chip_traces` (JaggedVal == InnerVal), kept alive across the call.
        let chip_trace_views = zkm_pcs::jagged_pcs::jagged::views_over_owned(&chip_traces);
        let pre = precompute_jagged_basefold_commit_generic::<OuterValMmcs>(
            &chip_trace_views,
            mmcs,
            fri,
            // #118: setup-time preprocessed commit → host (device BN254
            // wrap commit is opt-in via the wrap prover under ZIREN_GPU_WRAP_DEVICE).
            None,
            // band-cap carrier removal Phase B: outer/wrap prep commit is LEGACY
            // bitrev (`use_rev = false`), byte-identical to the pre-carrier path.
            false,
            // band-cap carrier removal Phase C: setup/preprocessed commit is never
            // a recursion prove commit → no AREA PIN (`None`), byte-identical.
            None,
        );
        bincode::serialize(&pre.commit.original_commitment)
            .expect("outer_prep_commit: serialize commitment")
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
    use zkm_pcs::jagged_pcs::{roundtrip_jagged_pcs_generic, JaggedVal};
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
        let traces = vec![
            ("Cpu".to_string(), mk(20, 100, 1)),
            ("Add".to_string(), mk(8, 50, 7)),
        ];

        let mmcs = <KoalaBearPoseidon2Outer as BasefoldRing>::bf_mmcs();
        let dft = Arc::new(OuterDft::default());

        roundtrip_jagged_pcs_generic::<OuterChallenger, OuterValMmcs, OuterDft>(
            traces,
            make_challenger,
            mmcs,
            dft,
        )
        .expect("BaseFold jagged-PCS commit/open/verify roundtrip over the BN254 outer ring");
    }

    // Full jagged-basefold BUNDLE pipeline (jagged sumcheck reduction +
    // jagged-eval + BaseFold open/verify) over the BN254 outer ring — one layer
    // above the PCS roundtrip; this is what the wrap shard's open/verify hooks
    // drive.
    #[test]
    fn test_jagged_basefold_bundle_roundtrip_bn254() {
        use p3_challenger::{CanObserve, FieldChallenger};
        use zkm_pcs::jagged_pcs::jagged::{
            precompute_jagged_basefold_commit_generic, prove_jagged_basefold_inner_generic,
            verify_jagged_basefold_inner_generic,
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
        let traces = vec![
            ("Cpu".to_string(), mk(4, 16, 1)),
            ("Add".to_string(), mk(2, 8, 7)),
        ];

        let mmcs = <KoalaBearPoseidon2Outer as BasefoldRing>::bf_mmcs();
        let dft = Arc::new(OuterDft::default());

        // r_row / z_row sampled deterministically from a fresh challenger;
        // shared by prover and verifier.
        let mut pt = make_challenger();
        let r_row_per_chip: Vec<Vec<JaggedChallenge>> = traces
            .iter()
            .map(|(_, t)| {
                let h = t.values.len() / t.width.max(1);
                let log_h = h.next_power_of_two().trailing_zeros() as usize;
                (0..log_h).map(|_| pt.sample_algebra_element()).collect()
            })
            .collect();
        let z_row: Vec<JaggedChallenge> = r_row_per_chip
            .iter()
            .max_by_key(|v| v.len())
            .cloned()
            .unwrap_or_default();

        let fri = <KoalaBearPoseidon2Outer as BasefoldRing>::fri_config();
        let precompute = precompute_jagged_basefold_commit_generic::<OuterValMmcs>(
            &traces,
            mmcs.clone(),
            fri.clone(),
            None,
        );
        let commitment = precompute.commit.original_commitment.clone();

        let mut p_chal = make_challenger();
        p_chal.observe(commitment.clone());
        let bundle = prove_jagged_basefold_inner_generic::<OuterChallenger, OuterValMmcs>(
            &traces,
            &r_row_per_chip,
            &z_row,
            None,
            precompute,
            &mut p_chal,
            mmcs.clone(),
            fri.clone(),
        );

        let chip_infos =
            zkm_pcs::jagged::compute_jagged_metadata::<JaggedVal>(&traces).chip_infos;
        let mut v_chal = make_challenger();
        v_chal.observe(commitment);
        let ok = verify_jagged_basefold_inner_generic::<OuterChallenger, OuterValMmcs, OuterDft>(
            &chip_infos,
            &r_row_per_chip,
            &z_row,
            &bundle,
            &mut v_chal,
            mmcs,
            dft,
            /* skip_commit_observe = */ true,
            fri,
        );
        assert!(
            ok,
            "jagged-basefold full bundle pipeline should accept the honest proof over BN254"
        );
    }
}
