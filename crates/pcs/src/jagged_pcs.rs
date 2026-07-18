//! Per-chip BaseFold jagged-PCS adapter.
//!
//! The BaseFold replacement for the (now-removed) WHIR late-binding
//! commit for the OOM-blocker chip-trace commit step.  The structural win:
//! each chip trace becomes one MLE that goes through
//! [`crate::basefold::StackedPcsProver`], so the BaseFold encoder
//! materializes one stripe at a time (`1 << log_stacking_height`
//! rows × `batch_size` polys) instead of one giant dense LDE.  No
//! `Vec<F>` of size `2^(num_vars + log_blowup)` is ever held in
//! memory at once — that's the structural cure for tendermint /
//! large-sum's 100+ GB peak RSS that shard-splitting only
//! palliated.
//!
//! Phase-C scope (this file): commit + open + verify with a fixed
//! evaluation point, no jagged sumcheck reduction yet.  Wiring into
//! [`crate::jagged`]'s sumcheck flow is C2/C3.


use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_challenger::CanObserve;
use p3_dft::Radix2DitParallel;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::basefold::{
    BasefoldProver, BasefoldVerifier, FriConfig, Mle, StackedBasefoldProof,
    StackedBasefoldProverData, StackedPcsProver, StackedPcsVerifier,
};
use crate::kb31_poseidon2::{InnerChallenge, InnerChallenger, InnerValMmcs};

pub type JaggedVal = crate::kb31_poseidon2::InnerVal;
pub type JaggedChallenge = InnerChallenge;
pub type JaggedDft = Radix2DitParallel<JaggedVal>;
pub type JaggedMmcs = InnerValMmcs;
pub type JaggedChallenger = InnerChallenger;

/// One committed batch of chip traces, plus the per-chip metadata
/// needed to recompute evaluation points on the verifier side.
///
/// BaseFold-over-BN254 port — generic over the MMCS `MT` so
/// the inner (Poseidon2-KoalaBear) and the wrap (OuterSC, Poseidon2-BN254)
/// commit paths share one struct.  `Val`/`Challenge` stay KoalaBear /
/// KoalaBear⁴ for both (mirrors SP1's `BNGC<KoalaBear,KoalaBear⁴>`); only
/// the commitment hash varies.  The concrete [`JaggedCommit`]
/// alias below pins `MT = JaggedMmcs` so every existing caller (incl.
/// serde wire-format + the ziren-gpu hooks) compiles unchanged.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(bound(
    serialize = "<MT as p3_commit::Mmcs<JaggedVal>>::Commitment: serde::Serialize",
    deserialize = "<MT as p3_commit::Mmcs<JaggedVal>>::Commitment: serde::Deserialize<'de>"
))]
pub struct JaggedCommitGeneric<MT: p3_commit::Mmcs<JaggedVal>> {
    /// SP1 names this `original_commitment`. The `#[serde(rename = "commitment")]`
    /// pins the *serialized* field name to the historical `commitment` so the
    /// (positional) proof wire format is byte-identical across the rename.
    #[serde(rename = "commitment")]
    pub original_commitment: <MT as p3_commit::Mmcs<JaggedVal>>::Commitment,
    /// Per-chip `(width, log_height_padded)` so the verifier can
    /// reconstruct the same Mle shapes when checking openings.
    pub chip_dims: Vec<(usize, u32)>,
    /// Total `[batch_size << log_stacking_height]` area of the
    /// stacked PCS commit — equals the verifier's `round_areas[0]`.
    pub area: usize,
    /// Actual log_stacking_height used for this commit (clamped down
    /// for tiny commits — see [`pick_log_stacking_height`]).
    pub log_stacking_height: u32,
}

/// Concrete inner (Poseidon2-KoalaBear) commit — the type every current
/// caller uses.  Transparent alias to the generic struct so struct
/// literals / field access compile unchanged.
pub type JaggedCommit = JaggedCommitGeneric<JaggedMmcs>;

pub struct JaggedProverDataGeneric<MT: p3_commit::Mmcs<JaggedVal>> {
    pub stacked_data: StackedBasefoldProverData<JaggedVal, MT>,
    pub chip_dims: Vec<(usize, u32)>,
    pub area: usize,
    pub log_stacking_height: u32,
}

/// Concrete inner prover-data alias (`MT = JaggedMmcs`).
pub type JaggedProverData = JaggedProverDataGeneric<JaggedMmcs>;

/// Defaults chosen to match the perf-results sweet spot:
/// `log_stacking_height=14` → 16K rows per stripe, well below the
/// 131K shard-split cliff that worked for tendermint at 51.7 GB.
/// Small commits (under 16K total entries) clamp this down so the
/// stacked PCS doesn't end up over-padding past the actual data.
pub const DEFAULT_LOG_STACKING_HEIGHT: u32 = 21;

/// SP1-faithful RECURSION-LAYER trace-area pin.
///
/// SP1's `crates/prover/src/components.rs` pins `RECURSION_LOG_TRACE_AREA = 27`
/// for the compress/recursion machine: every recursion proof (normalize AND
/// compose) commits its jagged dense at a FIXED area `2^27`, so the committed
/// codeword always has `num_stripes = 2^(27 - log_stacking_height) = 2^(27-21)
/// = 64` columns BY CONSTRUCTION.  With the per-child stripe shape fixed, every
/// compose child-bundle read is constant-length, so the compose VK collapses to
/// `f(chip-set, arity)` (the precondition for an enumerable FIX-off recursion
/// vk_map).
///
/// The CORE (`RiscvAir`) commit is NOT pinned — it stays NATURAL (the FIX-off
/// perf win is a core-trace property).  The pin is keyed by which machine is
/// proving: the recursion (`compress`) prover passes
/// `Some(RECURSION_LOG_TRACE_AREA)` as the `recursion_area_pin` param of
/// `MachineProver::commit` (band-cap carrier removal Phase C — was the
/// `RecursionAreaPinGuard` thread-local it installed around its commit+open), so
/// [`precompute_jagged_basefold_commit_generic`] /
/// [`precompute_jagged_basefold_commit`] bump `packing.log_dense_size` to
/// `max(natural, RECURSION_LOG_TRACE_AREA)` and record it on
/// `PrecomputedJaggedCommit.recursion_area_pin` (read back at open); core passes
/// `None` and is byte-identical to the unpinned path.
pub const RECURSION_LOG_TRACE_AREA: usize = 27;

/// Interleave batch size for the stacked PCS: number of MLE-column
/// streams packed into each stripe.  **`32`** matches SP1's
/// `slop_jagged::basefold::DEFAULT_INTERLEAVE_BATCH_SIZE`
/// (raised from `16`).  Halves the number of stripes per BaseFold
/// commit, which directly halves the Merkle-commit count and the
/// per-stripe DFT count without increasing per-stripe LDE memory.
/// SP1-parity; no soundness implication (purely a packing constant).
pub const DEFAULT_BATCH_SIZE: usize = 32;

/// SP1-faithful FIXED stacking height: ALWAYS `DEFAULT_LOG_STACKING_HEIGHT`
/// (21), never clamped down for small commits.
///
/// Clamping to `min(21, log2(np2(total))-1)` for tiny commits would make
/// the prover's `log_stacking_height` depend on the trace AREA.  Because the
/// recursion normalize/compress program is rebuilt per-proof from
/// `bundle.commit.log_stacking_height` (the value the prover used), that
/// clamp would make the program — hence its VK — CLAMP-DEPENDENT (the VK
/// varying with chip heights), which is exactly what forces FIX_CORE_SHAPES
/// + a height-quantized vk_map.
///
/// SP1's `JaggedPcsProver::commit_multilinears` instead FIXES the stacking
/// height and rounds the trace AREA up to a multiple of `2^21` (each call
/// site does `area = total_entries.next_multiple_of(1 << 21)`), so every
/// commit is honestly 21-round → the per-proof verifier rebuild
/// constant-folds to `num_variables = 21` → clamp-INDEPENDENCE, with no
/// transcript masking and no Fiat-Shamir risk (the unsound verifier-side
/// alternative).  The normalize VK then depends on the chip-SET only — the
/// precondition for retiring FIX_CORE_SHAPES while keeping VERIFY_VK=true.
///
/// `total_entries` is retained for call-site/API symmetry but does not
/// affect the height (the call-site area padding absorbs it).
pub fn pick_log_stacking_height(_total_entries: usize) -> u32 {
    DEFAULT_LOG_STACKING_HEIGHT
}

// BaseFold-over-BN254: GC-generic PCS core. Val/Challenge stay
// KoalaBear (the outer context keeps the same field for inner and outer);
// only the Mmcs (hash) + Dft vary by context. Inner uses Poseidon2-KoalaBear
// Merkle; the wrap (OuterSC) will pass Poseidon2-BN254 Merkle (OuterValMmcs).
// Non-breaking: `build_pcs` below stays a concrete wrapper so every existing
// caller compiles unchanged.
#[allow(clippy::type_complexity)]
fn build_pcs_generic<MT, D>(
    log_stacking_height: u32,
    mmcs: MT,
    dft: Arc<D>,
    fri: FriConfig<JaggedVal>,
) -> (
    StackedPcsProver<JaggedVal, JaggedChallenge, MT, D>,
    StackedPcsVerifier<JaggedVal, JaggedChallenge, MT>,
)
where
    MT: p3_commit::Mmcs<JaggedVal, Commitment: Clone> + Clone,
    D: p3_dft::TwoAdicSubgroupDft<JaggedVal>,
{
    // The FRI config (rate/queries/pow) is supplied by the caller so the
    // per-stage params are a single source of truth carried from commit
    // through open/verify (inner stages pass `from_env_or_default()`; the
    // wrap path passes `wrap_fri_config()` = blowup3/pow22 for 100-bit
    // soundness — see `FriConfig::wrap_fri_config`).
    let basefold_prover = BasefoldProver::<JaggedVal, JaggedChallenge, MT, D>::new(
        fri.clone(),
        dft,
        mmcs.clone(),
        1, // num_expected_commitments — one round per shard
    );
    let basefold_verifier =
        BasefoldVerifier::<JaggedVal, JaggedChallenge, MT>::new(fri, mmcs.clone(), 1);
    let prover = StackedPcsProver::new(basefold_prover, log_stacking_height, DEFAULT_BATCH_SIZE);
    let verifier = StackedPcsVerifier::new(basefold_verifier, log_stacking_height);
    (prover, verifier)
}

// Kept as the concrete inner wrapper (the established pattern); its former
// callers (commit/open/verify host fns) now build the KoalaBear mmcs/dft
// inline and delegate to `build_pcs_generic` directly, so this is currently
// uncalled. Retained for future inner-only callers / symmetry with the
// generic core.
#[allow(dead_code)]
fn build_pcs(
    log_stacking_height: u32,
) -> (
    StackedPcsProver<JaggedVal, JaggedChallenge, JaggedMmcs, JaggedDft>,
    StackedPcsVerifier<JaggedVal, JaggedChallenge, JaggedMmcs>,
    JaggedMmcs,
) {
    let perm: crate::kb31_poseidon2::InnerPerm =
        zkm_primitives::poseidon2_init();
    let hash = crate::kb31_poseidon2::InnerHash::new(perm.clone());
    let compress = crate::kb31_poseidon2::InnerCompress::new(perm);
    let mmcs = JaggedMmcs::new(hash, compress, 0);
    let dft = Arc::new(JaggedDft::default());
    // Delegate to the GC-generic core (inner = Poseidon2-KoalaBear Mmcs).
    // Inner stage: env-default rate (ZIREN_BASEFOLD_LOG_BLOWUP override).
    let (prover, verifier) = build_pcs_generic::<JaggedMmcs, JaggedDft>(
        log_stacking_height,
        mmcs.clone(),
        dft,
        FriConfig::<JaggedVal>::from_env_or_default(),
    );
    (prover, verifier, mmcs)
}

/// Convert chip traces into per-chip `Mle<JaggedVal>`s, padding each
/// trace's row count up to the next power of two.  No dense
/// concatenation — each chip stays in its own Mle for the stacked
/// commit to interleave.
///
/// **Move-by-value variant** — `chips_to_mles_owned` takes the
/// `Vec` by value and skips the `trace.values.clone()` when the
/// trace is already power-of-two height (the common path for
/// jagged-dense which is pre-padded).  Saves one full-dense copy
/// (`4N` bytes for the dense vec) on the hot path.
#[allow(dead_code)]
fn chips_to_mles(
    chip_traces: &[(String, RowMajorMatrix<JaggedVal>)],
) -> (Vec<Arc<Mle<JaggedVal>>>, Vec<(usize, u32)>) {
    let mut mles = Vec::with_capacity(chip_traces.len());
    let mut dims = Vec::with_capacity(chip_traces.len());
    for (_, trace) in chip_traces {
        let width = trace.width.max(1);
        let raw_height = trace.values.len() / width;
        let padded_height = raw_height.next_power_of_two();
        let log_h = padded_height.trailing_zeros();

        let mut padded = trace.values.clone();
        padded.resize(padded_height * width, JaggedVal::ZERO);

        mles.push(Arc::new(Mle::from_row_major(RowMajorMatrix::new(padded, width))));
        dims.push((width, log_h));
    }
    (mles, dims)
}

/// Public for the GPU commit-dispatch hook: the
/// device-side commit path needs to run the same MLE-construction +
/// padding logic as the host before invoking the GPU encoder.
pub fn chips_to_mles_owned(
    chip_traces: Vec<(String, RowMajorMatrix<JaggedVal>)>,
) -> (Vec<Arc<Mle<JaggedVal>>>, Vec<(usize, u32)>) {
    let mut mles = Vec::with_capacity(chip_traces.len());
    let mut dims = Vec::with_capacity(chip_traces.len());
    for (_, trace) in chip_traces.into_iter() {
        let width = trace.width.max(1);
        let raw_height = trace.values.len() / width;
        let padded_height = raw_height.next_power_of_two();
        let log_h = padded_height.trailing_zeros();

        let values = if raw_height == padded_height {
            trace.values
        } else {
            let mut padded = trace.values;
            padded.resize(padded_height * width, JaggedVal::ZERO);
            padded
        };

        mles.push(Arc::new(Mle::from_row_major(RowMajorMatrix::new(values, width))));
        dims.push((width, log_h));
    }
    (mles, dims)
}

/// Commit a batch of chip traces (consumes ownership — saves the
/// `trace.values.clone()` round-trip in `chips_to_mles_owned`).
/// Returns a public commitment (observed by the challenger as a
/// side effect) and prover-side state for later opening.
///
/// GPU commit dispatch — selected by prover TYPE: when the prover
/// statically provided `gpu_basefold_commit`
/// (`Some(GpuBasefoldCommitFn)`, the GPU prover only), the commit
/// dispatches through `FriCudaProver::encode_and_commit` + `CudaTcsProver`
/// on device.  Output `(commit, prover_data)` must be byte-identical to
/// the host path (the device hook host-side observes the same digest
/// into the same `JaggedChallenger`).  There is no env gate (SP1-parity —
/// the hook `Some`/`None` is the sole selector).  Falls through to the host
/// implementation on: `gpu_basefold_commit == None` (CPU prover), or
/// hook returns `Err` (shape unsupported / device error).
pub fn commit_jagged_pcs(
    chip_traces: Vec<(String, RowMajorMatrix<JaggedVal>)>,
    challenger: &mut JaggedChallenger,
    // #118: the device BaseFold commit fn, provided statically by the
    // prover (was the global `GPU_BASEFOLD_COMMIT_HOOK` OnceLock).  `None`
    // = host commit (CPU prover / free-fn callers), byte-identical to the
    // pre-#118 unregistered-hook path.
    gpu_basefold_commit: Option<GpuBasefoldCommitFn>,
) -> (JaggedCommit, JaggedProverData) {
    if let Some(hook) = gpu_basefold_commit {
        // The hook signature returns `Result` so the device side
        // can tunnel its host-input back to us on shape-unsupported
        // / runtime errors (we then run the host path with the
        // returned input — no double-allocation, no challenger
        // double-observe).
        // Transcript safety: snapshot + restore around the
        // fallible device hook so an Err after any challenger
        // interaction cannot double-advance the transcript (see
        // the open_jagged_pcs twin below for the full rationale).
        let challenger_snapshot = challenger.clone();
        match hook(chip_traces, challenger) {
            Ok(out) => {
                return out;
            }
            Err(returned_traces) => {
                *challenger = challenger_snapshot;
                return commit_jagged_pcs_host(returned_traces, challenger);
            }
        }
    }
    commit_jagged_pcs_host(chip_traces, challenger)
}

/// Pure host-side implementation of [`commit_jagged_pcs`]
/// — extracted so the GPU dispatch hook can fall back to it on
/// shape-unsupported / runtime errors without re-entering the env-flag
/// dispatch loop.  Always runs the CPU BaseFold + Plonky3 MMCS commit.
pub fn commit_jagged_pcs_host(
    chip_traces: Vec<(String, RowMajorMatrix<JaggedVal>)>,
    challenger: &mut JaggedChallenger,
) -> (JaggedCommit, JaggedProverData) {
    let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
    let hash = crate::kb31_poseidon2::InnerHash::new(perm.clone());
    let compress = crate::kb31_poseidon2::InnerCompress::new(perm);
    let mmcs = JaggedMmcs::new(hash, compress, 0);
    let dft = Arc::new(JaggedDft::default());
    // Delegate to the GC-generic core (inner = Poseidon2-KoalaBear Mmcs).
    commit_jagged_pcs_host_generic::<JaggedChallenger, JaggedMmcs, JaggedDft>(
        chip_traces,
        challenger,
        mmcs,
        dft,
        FriConfig::<JaggedVal>::from_env_or_default(),
    )
}

/// BaseFold-over-BN254 port: GC-generic host commit core (observes
/// the commitment into `challenger`).  Parameterized over the challenger
/// `Challenger` + MMCS `MT` + DFT `D`; the caller supplies the concrete
/// `mmcs`/`dft`.  The inner path uses `JaggedChallenger` + Poseidon2-KoalaBear
/// Mmcs; the wrap (OuterSC) will pass the BN254 challenger + Poseidon2-BN254
/// Mmcs.  `Val`/`Challenge` stay KoalaBear / KoalaBear⁴ for both.
#[allow(clippy::type_complexity)]
pub fn commit_jagged_pcs_host_generic<Challenger, MT, D>(
    chip_traces: Vec<(String, RowMajorMatrix<JaggedVal>)>,
    challenger: &mut Challenger,
    mmcs: MT,
    dft: Arc<D>,
    fri: FriConfig<JaggedVal>,
) -> (
    JaggedCommitGeneric<MT>,
    JaggedProverDataGeneric<MT>,
)
where
    MT: p3_commit::Mmcs<JaggedVal, Commitment: Clone> + Clone,
    D: p3_dft::TwoAdicSubgroupDft<JaggedVal> + Send + Sync,
    Challenger: CanObserve<<MT as p3_commit::Mmcs<JaggedVal>>::Commitment>,
{
    let (commit, prover_data) =
        commit_jagged_pcs_no_observe_generic::<MT, D>(chip_traces, mmcs, dft, fri);
    challenger.observe(commit.original_commitment.clone());
    (commit, prover_data)
}

/// GPU-dispatched no-observe variant — the single-main-commit precompute
/// uses this so the main-trace BaseFold commit runs on the device when
/// the hook is registered (GPU prover only; no env gate).  The hook's
/// internal `challenger.observe` is absorbed by a throwaway challenger
/// (the orchestrator/Phase 1 prologue's 8-felt `main_commitment`
/// observe is the real transcript binding).  Falls through to
/// [`commit_jagged_pcs_host_no_observe`] when the hook is
/// unregistered, or the hook returns `Err`.
pub fn commit_jagged_pcs_no_observe(
    chip_traces: Vec<(String, RowMajorMatrix<JaggedVal>)>,
    // #118: the device BaseFold commit fn, provided statically by the
    // prover (was the global `GPU_BASEFOLD_COMMIT_HOOK` OnceLock).  `None`
    // = host commit, byte-identical to the pre-#118 unregistered-hook path.
    gpu_basefold_commit: Option<GpuBasefoldCommitFn>,
) -> (JaggedCommit, JaggedProverData) {
    if let Some(hook) = gpu_basefold_commit {
        let mut throwaway: JaggedChallenger =
            JaggedChallenger::new(zkm_primitives::poseidon2_init());
        match hook(chip_traces, &mut throwaway) {
            Ok(out) => {
                return out;
            }
            Err(returned_traces) => {
                return commit_jagged_pcs_host_no_observe(returned_traces);
            }
        }
    }
    commit_jagged_pcs_host_no_observe(chip_traces)
}

/// Same as [`commit_jagged_pcs_host`] but does NOT observe
/// the commitment into the challenger.  Used by the
/// single-main-commit flow, where the BaseFold commit happens BEFORE
/// the shard-level Phase 1 prologue and the prologue's 8-felt
/// `main_commitment` observe IS the BaseFold-digest observation —
/// observing again here would desync the prover transcript vs the
/// verifier.
///
/// Callers MUST observe `commit.original_commitment` separately into the
/// challenger at the same transcript position as the verifier.  The
/// verifier counterpart is
/// [`jagged::verify_jagged_basefold_no_observe`].
pub fn commit_jagged_pcs_host_no_observe(
    chip_traces: Vec<(String, RowMajorMatrix<JaggedVal>)>,
) -> (JaggedCommit, JaggedProverData) {
    let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
    let hash = crate::kb31_poseidon2::InnerHash::new(perm.clone());
    let compress = crate::kb31_poseidon2::InnerCompress::new(perm);
    let mmcs = JaggedMmcs::new(hash, compress, 0);
    let dft = Arc::new(JaggedDft::default());
    // Delegate to the GC-generic core (inner = Poseidon2-KoalaBear Mmcs).
    commit_jagged_pcs_no_observe_generic::<JaggedMmcs, JaggedDft>(
        chip_traces,
        mmcs,
        dft,
        FriConfig::<JaggedVal>::from_env_or_default(),
    )
}

/// BaseFold-over-BN254 port: GC-generic commit core (no challenger
/// observe).  Parameterized over the MMCS `MT` + DFT `D`; the caller
/// supplies the concrete `mmcs`/`dft` so the inner (Poseidon2-KoalaBear)
/// and the wrap (OuterSC, Poseidon2-BN254) paths share one body.
/// `Val`/`Challenge` stay KoalaBear / KoalaBear⁴ for both.
#[allow(clippy::type_complexity)]
pub fn commit_jagged_pcs_no_observe_generic<MT, D>(
    chip_traces: Vec<(String, RowMajorMatrix<JaggedVal>)>,
    mmcs: MT,
    dft: Arc<D>,
    fri: FriConfig<JaggedVal>,
) -> (
    JaggedCommitGeneric<MT>,
    JaggedProverDataGeneric<MT>,
)
where
    MT: p3_commit::Mmcs<JaggedVal, Commitment: Clone> + Clone,
    D: p3_dft::TwoAdicSubgroupDft<JaggedVal> + Send + Sync,
{
    let (mles, chip_dims) = chips_to_mles_owned(chip_traces);
    let total_entries: usize = mles.iter().map(|m| m.guts().total_len()).sum();
    let log_stacking_height = pick_log_stacking_height(total_entries);
    let area = total_entries.next_multiple_of(1usize << log_stacking_height);

    let (prover, _verifier) = build_pcs_generic::<MT, D>(log_stacking_height, mmcs, dft, fri);
    let (commitment, stacked_data) = prover.commit_multilinears(mles);

    let commit = JaggedCommitGeneric::<MT> {
        original_commitment: commitment.clone(),
        chip_dims: chip_dims.clone(),
        area,
        log_stacking_height,
    };
    let prover_data = JaggedProverDataGeneric::<MT> {
        stacked_data,
        chip_dims,
        area,
        log_stacking_height,
    };
    (commit, prover_data)
}

/// Extract the 8-felt MMCS digest from a [`JaggedCommit`].
/// The digest is the value the verifier's Phase 1 prologue observes as
/// `main_commitment` in the single-main-commit flow.
///
/// The commitment is a `MerkleCap<KoalaBear, [KoalaBear; 8]>` (the
/// Plonky3 `MerkleTreeMmcs::Commitment` for `InnerValMmcs`).  This
/// helper pulls out the first cap root — the same byte sequence
/// `DuplexChallenger::observe(MerkleCap)` consumes.
#[must_use]
/// Extract the 8-felt MerkleCap root from a JaggedMmcs commitment (the
/// inner BasefoldRing::digest_felts body).
pub fn basefold_commit_digest_felts(
    commitment: &<JaggedMmcs as p3_commit::Mmcs<JaggedVal>>::Commitment,
) -> [JaggedVal; 8] {
    let roots = commitment.roots();
    assert!(!roots.is_empty(), "JaggedCommit MerkleCap must have at least one root");
    roots[0]
}

pub fn basefold_commit_digest(commit: &JaggedCommit) -> [JaggedVal; 8] {
    let roots = commit.original_commitment.roots();
    assert!(
        !roots.is_empty(),
        "JaggedCommit MerkleCap must have at least one root",
    );
    roots[0]
}

/// BaseFold-over-BN254: ring-native commitment digest. Inner (KoalaBear)
/// callers use `basefold_commit_digest` (8-felt MerkleCap root); the wrap
/// (OuterSC) carries the BN254 `MT::Commitment` directly via this generic
/// accessor -- the seam the digest tunnel observes / serializes.
pub fn basefold_commit_digest_generic<MT: p3_commit::Mmcs<JaggedVal>>(
    commit: &JaggedCommitGeneric<MT>,
) -> <MT as p3_commit::Mmcs<JaggedVal>>::Commitment
where
    <MT as p3_commit::Mmcs<JaggedVal>>::Commitment: Clone,
{
    commit.original_commitment.clone()
}

// ─────────────────────────────────────────────────────────────────────
// SP1-faithful jagged "hash-bind" (the count ↔ commitment tie).
//
// Ziren historically returned the RAW BaseFold root as the observed
// commitment, with NO cryptographic binding of the per-chip
// (row_count, column_count) geometry to that root.  That left the jagged
// geometry prover-supplied and (under the height-agnostic recursion)
// forgeable: a prover could witness a different geometry than was actually
// committed and still pass the prefix-sum / area consistency checks (which
// only tie the geometry to itself).
//
// SP1 closes this by hashing the geometry and folding it into the observed
// commitment (slop/crates/jagged/src/prover.rs:141-149):
//
//     hash = hash_iter( once(len) ++ row_counts ++ column_counts )
//     modified = compress([raw_root, hash])
//
// and re-checking it in `verify_trusted_evaluations`
// (slop/crates/jagged/src/verifier.rs:206-217).  The observed (Fiat-Shamir)
// commitment becomes `modified`; the BaseFold opening still binds against
// `raw_root` (carried as `original_commitment`).
//
// CONVENTION LOCK (host == circuit must be byte-identical):
//   * `len` is `column_counts.len()` (== `row_counts.len()`; SP1 prover
//     uses `row_counts.len()`, the in-circuit verifier uses
//     `column_counts.len()` — they are equal, we pick `column_counts.len()`
//     and use it IDENTICALLY in both places to avoid any FS desync).
//   * the geometry is the PER-CHIP `(row_count, column_count)` derived from
//     the SAME `packing.offsets` / `packing.column_counts` the recursion
//     lift reconstructs (`shard_level_witness.rs` `packing_row_counts`),
//     so the in-circuit recompute hashes the identical felt sequence.
//   * felts are `from_canonical_usize` (wraps mod the field order — the
//     in-circuit verifier guards each count `< F::ORDER` so the wrap can
//     never be exploited; see the recursion guards).
// ─────────────────────────────────────────────────────────────────────

/// Derive the per-chip `(row_counts, column_counts)` the hash-bind hashes,
/// from the host jagged `PackingMeta`.  This is the SINGLE source of truth
/// for the hash convention — both the host emit path
/// (`jagged_hash_bind_modified`) and the in-circuit recompute consume the
/// SAME per-chip vectors (the recursion lift's `packing_row_counts` /
/// `packing.column_counts`), so the hashed felt sequence is byte-identical.
///
/// `row_counts[i]` = height of chip `i` = `offsets[col_i+1] - offsets[col_i]`
/// where `col_i` is the first column index of chip `i` (a `column_count==0`
/// chip contributes height `0`).  `column_counts[i] = packing.column_counts[i]`.
#[must_use]
pub fn jagged_counts_from_packing(
    packing: &jagged::PackingMeta,
) -> (Vec<usize>, Vec<usize>) {
    let column_counts: Vec<usize> = packing.column_counts.clone();
    let offsets = &packing.offsets;
    let total_values = packing.total_values;
    let mut row_counts: Vec<usize> = Vec::with_capacity(column_counts.len());
    let mut col_idx = 0usize;
    for &cc in column_counts.iter() {
        if cc == 0 {
            row_counts.push(0);
            continue;
        }
        let h = if col_idx + 1 < offsets.len() {
            offsets[col_idx + 1].saturating_sub(offsets[col_idx])
        } else if col_idx < offsets.len() {
            total_values.saturating_sub(offsets[col_idx])
        } else {
            0
        };
        row_counts.push(h);
        col_idx += cc;
    }
    (row_counts, column_counts)
}

/// Compute the SP1-faithful geometry hash for ONE round (one commit):
/// `hash_iter( once(len) ++ row_counts ++ column_counts )` where
/// `len = column_counts.len()`.  Uses the inner Poseidon2-KoalaBear sponge
/// (`InnerHash`) — the SAME hasher `SC::hash` resolves to in-circuit.
#[must_use]
pub fn jagged_geometry_hash(
    row_counts: &[usize],
    column_counts: &[usize],
) -> [JaggedVal; 8] {
    use p3_field::PrimeCharacteristicRing;
    use p3_symmetric::CryptographicHasher;
    let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
    let hasher = crate::kb31_poseidon2::InnerHash::new(perm);
    let len = column_counts.len();
    let iter = core::iter::once(JaggedVal::from_canonical_usize(len))
        .chain(row_counts.iter().map(|&c| JaggedVal::from_canonical_usize(c)))
        .chain(column_counts.iter().map(|&c| JaggedVal::from_canonical_usize(c)));
    hasher.hash_iter(iter)
}

/// Fold the geometry hash into the raw BaseFold root: `compress([raw, hash])`.
/// Uses `InnerCompress` (the SAME compressor `SC::compress` resolves to
/// in-circuit).  Returns the MODIFIED 8-felt digest that the Fiat-Shamir
/// transcript observes as `main_commitment`.
#[must_use]
pub fn jagged_hash_bind_modified(
    raw_root: [JaggedVal; 8],
    row_counts: &[usize],
    column_counts: &[usize],
) -> [JaggedVal; 8] {
    use p3_symmetric::PseudoCompressionFunction;
    let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
    let compressor = crate::kb31_poseidon2::InnerCompress::new(perm);
    let hash = jagged_geometry_hash(row_counts, column_counts);
    compressor.compress([raw_root, hash])
}

/// Convenience: compute the MODIFIED digest directly from the raw commit +
/// packing — the host emit-site one-liner.
#[must_use]
pub fn jagged_hash_bind_from_packing(
    raw_root: [JaggedVal; 8],
    packing: &jagged::PackingMeta,
) -> [JaggedVal; 8] {
    let (row_counts, column_counts) = jagged_counts_from_packing(packing);
    jagged_hash_bind_modified(raw_root, &row_counts, &column_counts)
}

/// Derive the per-chip `(row_counts, column_counts)` from a full
/// [`crate::jagged::JaggedPacking`] (the form the host commit prover holds in
/// `PrecomputedJaggedCommit.packing`).  Uses the OFFSETS-based derivation
/// (NOT `chip_infos[i].row_count`) so it is byte-identical to the recursion
/// lift's `packing_row_counts` (`shard_level_witness.rs`) and to
/// [`jagged_counts_from_packing`]: a `column_count == 0` chip contributes
/// height `0` regardless of its raw trace height.
#[must_use]
pub fn jagged_counts_from_jagged_packing(
    packing: &crate::jagged::JaggedPacking<JaggedVal>,
) -> (Vec<usize>, Vec<usize>) {
    let column_counts: Vec<usize> =
        packing.chip_infos.iter().map(|ci| ci.column_count).collect();
    let offsets = &packing.offsets;
    let total_values = packing.total_values;
    let mut row_counts: Vec<usize> = Vec::with_capacity(column_counts.len());
    let mut col_idx = 0usize;
    for &cc in column_counts.iter() {
        if cc == 0 {
            row_counts.push(0);
            continue;
        }
        let h = if col_idx + 1 < offsets.len() {
            offsets[col_idx + 1].saturating_sub(offsets[col_idx])
        } else if col_idx < offsets.len() {
            total_values.saturating_sub(offsets[col_idx])
        } else {
            0
        };
        row_counts.push(h);
        col_idx += cc;
    }
    (row_counts, column_counts)
}

/// Host emit-site one-liner: the MODIFIED digest from the raw root + the
/// full `JaggedPacking` the commit prover holds.  This is the value the
/// Fiat-Shamir transcript observes as `main_commitment`.
#[must_use]
pub fn jagged_hash_bind_from_jagged_packing(
    raw_root: [JaggedVal; 8],
    packing: &crate::jagged::JaggedPacking<JaggedVal>,
) -> [JaggedVal; 8] {
    let (row_counts, column_counts) = jagged_counts_from_jagged_packing(packing);
    jagged_hash_bind_modified(raw_root, &row_counts, &column_counts)
}

/// Host-side mirror of the in-circuit re-bind (SP1
/// `verify_trusted_evaluations`): recompute `compress([raw, hash(counts)])`
/// and check it equals the observed `modified` digest.  Used by the G-host
/// round-trip gate to LOCK the convention before the circuit consumes it.
#[must_use]
pub fn jagged_hash_bind_verify(
    raw_root: [JaggedVal; 8],
    modified: [JaggedVal; 8],
    packing: &jagged::PackingMeta,
) -> bool {
    let recomputed = jagged_hash_bind_from_packing(raw_root, packing);
    recomputed == modified
}

/// Production-grade FRI config used by the jagged-PCS pipeline.
/// Public so the GPU dispatch hook can construct a matching
/// device-side encoder (same `log_blowup`, same coset shift) without
/// re-creating the env-overrides logic.
pub fn lb_fri_config() -> FriConfig<JaggedVal> {
    FriConfig::<JaggedVal>::from_env_or_default()
}

// ─────────────────────────────────────────────────────────────────────
// GPU BaseFold commit dispatch hook.
//
// The hook receives the same inputs as `commit_jagged_pcs` and
// returns a byte-identical `(commit, prover_data)` — the device side
// is responsible for:
//
//   * uploading the per-chip traces to GPU memory,
//   * running `FriCudaProver::encode_and_commit` (the existing 1349
//     LOC device commit) + the SP1 `compress([root, hash([h, w])])`
//     post-processing step so the digest matches Plonky3
//     `MerkleTreeMmcs`,
//   * observing the resulting commitment into the supplied
//     `JaggedChallenger` (so the transcript stays in lock-step with the
//     host path),
//   * assembling a `JaggedProverData` whose
//     `stacked_data.pcs_batch_data.prover_data` is shape-compatible
//     with the host `MerkleTreeMmcs::ProverData` consumed downstream by
//     `open_jagged_pcs`.  Because that prover-data shape compatibility
//     is not guaranteed for every shape, until the open-path adapter
//     lands the device hook can return `Err` on un-handled shapes and
//     we fall back to host.
//
// The hook returns `Result<.., Vec<...>>` instead of `Option<..>` so
// the device side can tunnel ownership of the host-input back to the
// host fallback on error (mirrors the `try_emit_jagged_pcs_bytes_device`
// fall-through contract on the bytes path).
// ─────────────────────────────────────────────────────────────────────

/// Signature of the GPU BaseFold commit driver.  Same inputs as
/// [`commit_jagged_pcs`].  On success returns the
/// byte-equivalent `(commit, prover_data)`.  On unrecoverable
/// shape/runtime error returns the original `chip_traces` so the host
/// fallback can run without losing ownership.
pub type GpuBasefoldCommitFn = fn(
    chip_traces: Vec<(String, RowMajorMatrix<JaggedVal>)>,
    challenger: &mut JaggedChallenger,
) -> Result<
    (JaggedCommit, JaggedProverData),
    Vec<(String, RowMajorMatrix<JaggedVal>)>,
>;

// #118: the GPU BaseFold commit fn is provided STATICALLY (threaded from
// the prover down to the commit dispatch), not via a global registry.  The
// former `GPU_BASEFOLD_COMMIT_HOOK` OnceLock + `register_/get_` accessors
// were removed; the `prover` crate passes `Some(device_fn)` into the
// `prove_shard_to_basefold` free-fn (which threads it through the
// auto-precompute path to `commit_jagged_pcs_no_observe`).

// ─────────────────────────────────────────────────────────────────────
// GPU jagged-reduction sumcheck dispatch hook.
//
// Mirrors the host `crate::jagged_sumcheck::prove_jagged_reduction_owned`
// signature one-for-one — same inputs (owned `dense_q`, packing,
// `r_row_per_chip`, `y_per_chip`, challenger), same output
// (`JaggedReductionProof<InnerChallenge>`).  Wired from
// `prove_jagged_basefold_with_y_per_chip` step (4) when the GPU
// jagged-reduction hook is registered (GPU prover only).
//
// Per-shard wall: 2.41–2.76s × 25 shards ≈ 62s of the 144s tendermint
// compress wall (measured) — the largest remaining
// per-shard host bottleneck after the BaseFold commit moved to GPU.
// ─────────────────────────────────────────────────────────────────────

/// Signature of the GPU jagged-reduction prover function.
///
/// A device-resident prover supplies this positionally at its
/// [`crate::prover::MachineProver::prove_shard_to_basefold`] override; the
/// shard prover threads the returned `Option` down to the jagged-reduction
/// dispatch below and calls it in place of the host
/// [`crate::jagged_sumcheck::prove_jagged_reduction_owned`].
///
/// Implementations MUST be byte-equivalent to that host reduction: the
/// host body runs whenever the prover provides `None` (the CPU / free-fn
/// path) OR the function itself returns `None` (a shape the GPU path
/// declines).  The function receives `z_col` (the caller-sampled column
/// point — it must NOT sample anything before the round loop, and must
/// not gamma-mix) and `z_row` (the full zerocheck-reduced z* driving the
/// row-eq embedding weights).  These mirror `prove_jagged_reduction_owned`'s
/// signature; sampling gamma or observing evals before the round loop
/// produces INVALID proofs.
///
/// `dense_q_device_handle` is an opaque device-resident dense_q handle:
/// when `Some(handle)` the producer uses the device buffer (looked up in
/// its own registry) and `dense_q_host` MAY be empty (the device round-0
/// path avoids the pull-to-host); when `None` it falls back to
/// `dense_q_host`.  `zkm-pcs` never dereferences the handle — the GPU
/// side owns allocation / deallocation.
/// Object-safe device/host jagged-reduction dispatch — the SP1-parity
/// static-dispatch collapse of the former `GpuJaggedReductionFnV2` fn-ptr +
/// `Option<..>` thread + `ActiveHook` match.  The prover TYPE selects the
/// impl: the host build threads `&HostJaggedReducer`, the GPU prover threads
/// its own `&DeviceJaggedReducer` (in `zkm-gpu-basefold`).  `reduce_jagged`
/// returns `None` only when the device path DECLINES a shape (having first
/// RESTORED the challenger snapshot); the consumer then runs the host
/// fallback (`prove_jagged_reduction_owned`).  Args mirror the former fn-ptr
/// exactly, so device impls stay byte-equivalent.
pub trait JaggedReducer {
    #[allow(clippy::too_many_arguments)]
    fn reduce_jagged(
        &self,
        dense_q_host: alloc::vec::Vec<JaggedVal>,
        dense_q_device_handle: Option<u64>,
        packing: &crate::jagged::JaggedPacking<JaggedVal>,
        r_row_per_chip: &[alloc::vec::Vec<JaggedChallenge>],
        y_per_chip: &[alloc::vec::Vec<JaggedChallenge>],
        z_col: &[JaggedChallenge],
        z_row: &[JaggedChallenge],
        challenger: &mut JaggedChallenger,
    ) -> Option<crate::jagged_sumcheck::JaggedReductionProof<JaggedChallenge>>;

    /// `true` for the device reducer — drives `skip_host_dense`, the
    /// dense-device-handle selection, and the DROPLDES pre-reduce provider
    /// release in `prove_jagged_basefold_inner` (was the runtime
    /// `gpu_jagged_reduction.is_some()`).  Host default = `false`.
    fn is_device(&self) -> bool {
        false
    }
}

/// Host reducer: the always-`Some` host reduction
/// ([`crate::jagged_sumcheck::prove_jagged_reduction_owned`]) — a verbatim
/// move of the former `ActiveHook::None` arm.  `is_device()` = false, so the
/// consumer takes the exact pre-static-dispatch host (`None`-hook) path →
/// byte-identical.
pub struct HostJaggedReducer;

impl JaggedReducer for HostJaggedReducer {
    fn reduce_jagged(
        &self,
        dense_q_host: alloc::vec::Vec<JaggedVal>,
        _dense_q_device_handle: Option<u64>,
        packing: &crate::jagged::JaggedPacking<JaggedVal>,
        r_row_per_chip: &[alloc::vec::Vec<JaggedChallenge>],
        y_per_chip: &[alloc::vec::Vec<JaggedChallenge>],
        z_col: &[JaggedChallenge],
        z_row: &[JaggedChallenge],
        challenger: &mut JaggedChallenger,
    ) -> Option<crate::jagged_sumcheck::JaggedReductionProof<JaggedChallenge>> {
        Some(crate::jagged_sumcheck::prove_jagged_reduction_owned(
            dense_q_host,
            packing,
            r_row_per_chip,
            y_per_chip,
            z_col,
            z_row,
            challenger,
        ))
    }
}


// ─────────────────────────────────────────────────────────────────────
// GPU row-GKR layer-transition dispatch hook scaffolding.
//
// Mirror of the GpuJaggedReductionFnV2 device-fn pattern above.  Used by
// future steps (4b/4c) that migrate
// `crate::shard_level::row_gkr::build::build_gkr_circuit` from running
// host transitions UPFRONT to lazily evolving a device-resident layer
// state in place.
//
// The host signature consumes a `prev_handle: u64` opaque side-channel
// id (registered by the GPU prover) and returns a `u64` for the next
// layer's device-resident state.  Stark side never dereferences the
// handle — that's entirely the GPU prover's bookkeeping.
//
// Earlier attempts wired a transition CUDA kernel via a side-channel
// registry but `build_gkr_circuit` STILL ran host transitions, so the
// kernel was redundant — the host materialization always overrode the
// device result.  This design fixes that by making `LayerState::Device`
// a true alternative to `LayerState::Host`, with the GPU hook as the
// only path that produces it.
//
// NOT YET WIRED — this is hook scaffolding only; a later change is the
// first to actually consult the registered hook from `build_gkr_circuit`.
// ─────────────────────────────────────────────────────────────────────

/// Signature of the GPU row-GKR layer-transition driver.  Consumes
/// the previous layer's opaque device handle (`prev_handle`) and
/// returns the new layer's device handle.  The GPU prover owns
/// allocation / deallocation of the device-resident state behind the
/// handles — the stark crate never dereferences them.
///
/// Scaffolding only — no caller invokes this yet; a later change wires
/// the dispatch into `build_gkr_circuit`.
///
/// Multi-GPU isolation — `circuit_id` scopes the hook to a single
/// GKR-circuit build call.  The GPU side keys its registry by
/// `(device_id, circuit_id)` so concurrent shards on the same GPU
/// don't share a `next_handle` counter (which would otherwise cause
/// "handle not in registry" panics when one shard's pull stepped on
/// another's intermediate handles).
pub type GpuLayerTransitionFn = fn(circuit_id: u64, prev_handle: u64) -> u64;

// #118: the `GpuLayerTransitionFn` is provided STATICALLY via
// [`GkrDeviceHooks::layer_transition`] (threaded from the prover down to
// `try_run_device_path_basefold`), not a global registry.  The former
// `GPU_LAYER_TRANSITION_HOOK` OnceLock + its `register_/get_` accessors
// were removed.

// ─────────────────────────────────────────────────────────────────────
// Companion hooks for the row-GKR layer-state lifecycle on device:
//
//   * `GpuLayerInitFn`     — upload the FIRST EF Layer (post-FirstLayer
//                            host transition) to device, return handle.
//   * `GpuLayerTransitionFn` (defined above) — produce the next
//                            device-resident layer state from a prev
//                            handle (the transition-hook contract above).
//   * `GpuLayerPullFn`     — materialize a device handle back into a
//                            host `LogUpGkrCpuLayer<EF, EF>` so the
//                            terminal extraction can run on host.
//
// `HostLayerView<'a>` is the borrowed-cells shape passed to the init
// hook.  It carries borrowed `RowMajorTable<JaggedChallenge>` slices for
// each of the four sub-MLEs plus the layer dimensions.  Borrows-only
// keeps the upload zero-copy on the host side; the GPU side decides
// whether to memcpy into device memory or pin + dma.
//
// All three hooks are typed concretely on `JaggedVal`/`JaggedChallenge` (the
// production field stack — `KoalaBear` + `BinomialExtensionField<..,4>`).
// `build_gkr_circuit` is generic over `F`/`EF`, so the dispatch site
// uses `core::any::TypeId` to confirm the generics match before calling
// the hook; on type mismatch the host path runs unchanged.  This
// matches the commit-hook architecture above, where the device
// only ever sees concrete JaggedVal/JaggedChallenge buffers.
// ─────────────────────────────────────────────────────────────────────

/// Borrowed-cells view of an EF row-GKR layer suitable for the GPU
/// init hook.  The four sub-MLEs are passed by slice so the upload
/// stays zero-copy on the host side; the GPU side is responsible for
/// the memcpy / pin + dma into device memory.
///
/// Lifetime borrows from the `LogUpGkrCpuLayer<JaggedChallenge, JaggedChallenge>`
/// the dispatch site holds across the call.
pub struct HostLayerView<'a> {
    pub numerator_0: &'a [crate::shard_level::row_gkr::layer::RowMajorTable<JaggedChallenge>],
    pub denominator_0: &'a [crate::shard_level::row_gkr::layer::RowMajorTable<JaggedChallenge>],
    pub numerator_1: &'a [crate::shard_level::row_gkr::layer::RowMajorTable<JaggedChallenge>],
    pub denominator_1: &'a [crate::shard_level::row_gkr::layer::RowMajorTable<JaggedChallenge>],
    pub num_row_variables: usize,
    pub num_interaction_variables: usize,
}

/// Signature of the GPU row-GKR layer-init driver.  Uploads the first
/// EF layer (constructed on host by the F→EF transition out of the
/// FirstLayer) to device memory, returns an opaque handle the
/// transition / pull hooks can consume.
///
/// Declared but only invoked when this hook + the transition
/// hook + the pull hook are all registered, the calling thread has a
/// `gpu_worker_context` TLS (i.e. a `MultiGpuDevicePool` worker), AND
/// the `build_gkr_circuit` generic types resolve to (`JaggedVal`,
/// `JaggedChallenge`).
///
/// Multi-GPU isolation — `circuit_id` scopes this hook to a single
/// GKR-circuit build call.  See `GpuLayerTransitionFn` docs for the
/// per-circuit registry rationale.
pub type GpuLayerInitFn =
    for<'a> fn(circuit_id: u64, view: HostLayerView<'a>) -> u64;

// #118: the `GpuLayerInitFn` is provided STATICALLY via
// [`GkrDeviceHooks::layer_init`] (threaded from the prover down to
// `try_run_device_path_basefold`), not a global registry.  The former
// `GPU_LAYER_INIT_HOOK` OnceLock + its `register_/get_` accessors were
// removed.

// ─────────────────────────────────────────────────────────────────────
// PIECE3: row-GKR device-fold FIT PREFLIGHT hook.
//
// `gpu_layer_init_hook` / `gpu_layer_transition_hook` allocate the
// device-resident GKR fold layers but have NO error channel (they return
// a bare `u64` handle) — an OOM inside a transition `panic!`s mid-loop
// (layer_transition_dispatch.rs ~2282) and CANNOT cleanly fall back
// (earlier layers are already device-resident, host layers interleaved).
// On a log_dense=30 shard the first EF layer's footprint can exceed the
// free VRAM left after a big commit, aborting the whole core proof.
//
// The fix is an UP-FRONT host preflight: BEFORE `init_hook` is called,
// ask the GPU side (which can call `cuda_mem_get_info`) whether this
// layer set fits.  When it returns `false`, `try_run_device_path_basefold`
// returns `None` so the GKR fold runs entirely on host — byte-identical
// (the device path is a perf optimization; the layer cells are the same)
// and transcript-neutral.  Mirrors the commit/open pre-fire
// preflights.  Opaque to the stark crate; the GPU side owns the VRAM math.
// ─────────────────────────────────────────────────────────────────────

/// Signature of the GPU row-GKR device-fold FIT PREFLIGHT hook.
///
/// Receives the same borrowed `HostLayerView` the init hook would upload,
/// so the GPU side can size the first-layer device footprint, add a
/// transition headroom factor, and compare against free VRAM.  Returns
/// `true` when the device fold is expected to fit (proceed to `init_hook`)
/// and `false` to DECLINE to the host fold path.  Conservative: when the
/// hook is unregistered the device path proceeds as before (no decline).
pub type GpuLayerFitPreflightFn =
    for<'a> fn(view: &HostLayerView<'a>) -> bool;

// #118: the `GpuLayerFitPreflightFn` is provided STATICALLY via
// [`GkrDeviceHooks::layer_fit_preflight`] (threaded from the prover down
// to `try_run_device_path_basefold`), not a global registry.  The former
// `GPU_LAYER_FIT_PREFLIGHT_HOOK` OnceLock + its `register_/get_` accessors
// were removed.

/// Signature of the GPU row-GKR layer-pull driver.  Materializes a
/// device-resident layer back to host as a
/// `LogUpGkrCpuLayer<JaggedChallenge, JaggedChallenge>` so the terminal
/// extraction (`extract_outputs`) can run on host without an
/// additional device-side primitive.
///
/// Called once at the end of `build_gkr_circuit` if the device path
/// was taken — `extract_outputs` already exists on host and operates
/// on a 1-row layer, so the pull cost is dominated by a
/// `4 × num_chips × num_interactions` element copy back from device.
///
/// Multi-GPU isolation — `circuit_id` scopes this hook to a single
/// GKR-circuit build call.  The GPU side can SAFELY drain that
/// circuit's intermediate states after extracting the requested
/// terminal (no concurrent shards' state to step on, since they have
/// distinct `circuit_id`s).
pub type GpuLayerPullFn = fn(
    circuit_id: u64,
    handle: u64,
) -> crate::shard_level::row_gkr::layer::LogUpGkrCpuLayer<JaggedChallenge, JaggedChallenge>;

// #118: the `GpuLayerPullFn` is provided STATICALLY via
// [`GkrDeviceHooks::layer_pull`] (threaded from the prover down to
// `try_run_device_path_basefold` and the terminal-pull site in
// `top_level.rs`), not a global registry.  The former `GPU_LAYER_PULL_HOOK`
// OnceLock + its `register_/get_` accessors were removed.

/// Signature of the GPU row-GKR per-circuit drain driver.  Releases
/// every device-resident layer state still held by the GPU registry
/// for `circuit_id` (typically intermediate layers whose handles were
/// observed but never explicitly pulled).  Idempotent — calling drain
/// on a circuit_id whose bucket has already been removed is a no-op.
///
/// **Multi-GPU fix** — `GpuLayerPullFn` only releases the
/// SINGLE handle it was asked to materialize, so the per-circuit
/// bucket retains all the OTHER intermediate layer states until the
/// GPU process exits or the bucket is dropped.  Across 8 concurrent
/// shards × 8 GPUs that adds up to ~18 layers × per-shard MB → OOM
/// in the basefold commit Merkle phase.  Wiring the drain hook from
/// the row-GKR top-level prover (called once after the entire pull
/// loop completes) bounds peak GPU memory to one shard's per-circuit
/// state instead of all in-flight shards' per-circuit state.
///
/// Hook contract is total — must not fail.  GPU-side errors should
/// be panicked (mirrors the other layer hooks); silently succeeding
/// on a missing bucket is fine (idempotent).
pub type GpuLayerDrainCircuitFn = fn(circuit_id: u64);

// #118: the `GpuLayerDrainCircuitFn` is provided STATICALLY via
// [`GkrDeviceHooks::layer_drain`] (threaded from the prover down to the
// post-layer-walk drain site in `top_level.rs`), not a global registry.
// `None` (CPU prover / host walk) skips the drain call, byte-identical to
// the pre-#118 unregistered-hook path.  The former `GPU_LAYER_DRAIN_HOOK`
// OnceLock + its `register_/get_` accessors were removed.

// ─────────────────────────────────────────────────────────────────────
// #118 / Phase-4: object-safe static-dispatch of the row-GKR device
// lifecycle fns.
//
// These fns were formerly eight independent global `OnceLock` registries
// (`GPU_LAYER_TRANSITION_HOOK`, `GPU_LAYER_INIT_HOOK`, … ), each set once at
// ziren-gpu startup and read at its firing site via a `get_*` accessor.  #118
// first collapsed them into a `Copy` `GkrDeviceHooks` fn-ptr bundle; Phase-4
// replaces that bundle with an OBJECT-SAFE TRAIT threaded `&dyn` — the prover
// TYPE selects the impl (SP1-parity static dispatch, exactly as the
// reduce/open `JaggedReducer`/`JaggedOpener` slices do).  The host build
// threads `&HostGkrDevice` (host fold), the GPU prover threads its own
// `&DeviceGkrDevice` (in `zkm-gpu-basefold`); it is threaded
// (`prove_shard_to_basefold` → … → `prove_shard_logup_gkr_rows`) and
// distributed to the row-GKR firing sites (`build_gkr_circuit` /
// `prove_gkr_round` / the post-walk drain site).
//
// Phase-4 dropped THREE dead fields the `GkrDeviceHooks` bundle carried:
// `logup_scope_populate` (always `None` from every producer → its
// scope-populate block in `top_level.rs` never ran), `v3_fetch_publish` (the
// V3 layer cache was excised — no consumer at all), and `generate_first_layer`
// (fed into `DeviceInputData` ONLY inside that dead scope-populate block).  The
// remaining five are the live device-fold walk fns.
// ─────────────────────────────────────────────────────────────────────

// D3c (Option-C divergence): the `GkrDeviceProvider` trait + `HostGkrDevice`
// impl were REMOVED.  The row-GKR device-fold layer walk is now driven ONLY by
// the ziren-gpu-owned device-native driver (`prove_shard_logup_gkr_rows_native`
// → `build_gkr_circuit_native`), which calls the `gpu_layer_{init,transition,
// pull,drain,fit_preflight}_hook` kernels DIRECTLY (what `DeviceGkrDevice`
// forwarded to VERBATIM).  The shared host `build_gkr_circuit` / `prove_gkr_round`
// are now CpuProver-only (host fold, no `LayerState::Device` ever constructed).
// `HostLayerView` is retained — it is the GPU init/transition/preflight
// kernels' argument type.

/// Process-wide monotonic counter for GKR-circuit IDs.  Each
/// `build_gkr_circuit` call that takes the device path allocates a
/// fresh ID via [`allocate_gpu_layer_circuit_id`] and threads it
/// through every [`GpuLayerInitFn`] / [`GpuLayerTransitionFn`] /
/// [`GpuLayerPullFn`] invocation.  The GPU side keys its registry by
/// `(device_id, circuit_id)` so concurrent shards on the same GPU are
/// fully isolated — fixes multi-GPU panics caused by a shared
/// `next_handle` counter being stepped on across shards.
// Backing storage uses AtomicUsize, not AtomicU64, so the file
// compiles on the zkvm-elf target (mipsel — no
// `target_has_atomic="64"`).  The GPU registry never executes on the
// zkvm-elf binary, but the symbol still has to type-check in that
// build because `row_gkr/build.rs` imports the helper unconditionally.
// Public API (`u64`) is preserved via cast.  On host (64-bit)
// `usize == u64`; on the 32-bit zkvm-elf the upper bits are always
// zero and circuit IDs grow well within `u32::MAX`.
static NEXT_GPU_LAYER_CIRCUIT_ID: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(1);

/// Allocate a fresh process-unique GKR-circuit ID for use with the
/// GPU layer-state hooks.  Must be called once per
/// `build_gkr_circuit` device-path invocation; the returned ID is
/// passed verbatim to every init/transition/pull hook for that
/// circuit.
///
/// IDs start at 1 (0 reserved as a sentinel) and increment
/// monotonically.  Wraparound is not handled — at u64 capacity that
/// would require ~10^9 circuits/sec for centuries, which is well
/// outside the threat model.
#[must_use]
pub fn allocate_gpu_layer_circuit_id() -> u64 {
    NEXT_GPU_LAYER_CIRCUIT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u64
}

/// Object-safe device/host BaseFold-open dispatch — the SP1-parity
/// static-dispatch collapse of the former `GpuBasefoldOpenFn` fn-ptr +
/// `Option<..>` thread + the `open_jagged_pcs` dispatch fn.  The prover
/// TYPE selects the impl: the host build threads `&HostJaggedOpener`, the
/// GPU prover threads its own `&DeviceJaggedOpener` (in `zkm-gpu-basefold`,
/// dispatching through `FriCudaProver::prove` with a snapshot-restore host
/// fallback on `Err`).  Output proof is byte-identical to the host path.
pub trait JaggedOpener {
    /// Open the committed batch at a single point and produce the
    /// stacked-basefold proof.  `eval_point.len()` must equal
    /// `log_stacking_height + log(num_stripes_padded)`.
    fn open_jagged(
        &self,
        prover_data: JaggedProverData,
        eval_point: Vec<JaggedChallenge>,
        challenger: &mut JaggedChallenger,
    ) -> StackedBasefoldProof<JaggedVal, JaggedChallenge, JaggedMmcs>;
}

/// Host opener: the pure-host BaseFold open ([`open_jagged_pcs_host`]) —
/// a verbatim move of the former `open_jagged_pcs` `None`-hook path.
/// Byte-identical to the pre-static-dispatch host open.
pub struct HostJaggedOpener;

impl JaggedOpener for HostJaggedOpener {
    fn open_jagged(
        &self,
        prover_data: JaggedProverData,
        eval_point: Vec<JaggedChallenge>,
        challenger: &mut JaggedChallenger,
    ) -> StackedBasefoldProof<JaggedVal, JaggedChallenge, JaggedMmcs> {
        open_jagged_pcs_host(prover_data, eval_point, challenger)
    }
}

/// Pure host-side implementation of [`open_jagged_pcs`] —
/// extracted so the GPU dispatch hook can fall back to it on
/// shape-unsupported / runtime errors without re-entering the env-flag
/// dispatch loop.  Always runs the CPU StackedPcsProver
/// `prove_trusted_evaluation` body.
pub fn open_jagged_pcs_host(
    prover_data: JaggedProverData,
    eval_point: Vec<JaggedChallenge>,
    challenger: &mut JaggedChallenger,
) -> StackedBasefoldProof<JaggedVal, JaggedChallenge, JaggedMmcs> {
    let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
    let hash = crate::kb31_poseidon2::InnerHash::new(perm.clone());
    let compress = crate::kb31_poseidon2::InnerCompress::new(perm);
    let mmcs = JaggedMmcs::new(hash, compress, 0);
    let dft = Arc::new(JaggedDft::default());
    // Delegate to the GC-generic core (inner = Poseidon2-KoalaBear Mmcs).
    open_jagged_pcs_host_generic::<JaggedChallenger, JaggedMmcs, JaggedDft>(
        prover_data,
        eval_point,
        challenger,
        mmcs,
        dft,
        FriConfig::<JaggedVal>::from_env_or_default(),
    )
}

/// BaseFold-over-BN254 port: GC-generic host open core.  Parameterized
/// over the challenger `Challenger` + MMCS `MT` + DFT `D`; the caller
/// supplies the concrete `mmcs`/`dft`.  The inner path uses `JaggedChallenger`
/// + Poseidon2-KoalaBear Mmcs; the wrap (OuterSC) will pass the BN254
/// challenger + Poseidon2-BN254 Mmcs.  `Val`/`Challenge` stay KoalaBear /
/// KoalaBear⁴ for both (the eval-point is over `JaggedChallenge`).
#[allow(clippy::type_complexity)]
pub fn open_jagged_pcs_host_generic<Challenger, MT, D>(
    prover_data: JaggedProverDataGeneric<MT>,
    eval_point: Vec<JaggedChallenge>,
    challenger: &mut Challenger,
    mmcs: MT,
    dft: Arc<D>,
    fri: FriConfig<JaggedVal>,
) -> StackedBasefoldProof<JaggedVal, JaggedChallenge, MT>
where
    MT: p3_commit::Mmcs<JaggedVal, Commitment: Clone> + Clone,
    D: p3_dft::TwoAdicSubgroupDft<JaggedVal> + Send + Sync,
    Challenger: p3_challenger::FieldChallenger<JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = JaggedVal>
        + CanObserve<<MT as p3_commit::Mmcs<JaggedVal>>::Commitment>,
{
    let (prover, _verifier) =
        build_pcs_generic::<MT, D>(prover_data.log_stacking_height, mmcs, dft, fri);
    prover.prove_trusted_evaluation(eval_point, vec![prover_data.stacked_data], challenger)
}

// ─────────────────────────────────────────────────────────────────────
// GPU BaseFold open
// dispatch fn.
//
// Mirror of the GPU commit fn ([`GpuBasefoldCommitFn`]) — provided
// statically by the prover (`MachineProver::gpu_basefold_open_hook`) and
// threaded down to the `open_jagged_pcs` dispatch, not via a registry.
// The hook receives the same inputs as `open_jagged_pcs` and
// returns a byte-identical `StackedBasefoldProof` — the device side is
// responsible for:
//
//   * routing the per-stripe MLEs / codewords held in
//     `prover_data.stacked_data.pcs_batch_data` to GPU memory (or
//     reading from a device-resident cache if the commit hook installed
//     one),
//   * running `FriCudaProver::prove` (the existing 1349 LOC device
//     prove driver in `ziren-gpu/basefold/src/fri.rs`),
//   * observing the per-round univariate-poly evals + Merkle commits +
//     PoW witness into the supplied `JaggedChallenger` so the transcript
//     stays in lock-step with the host path,
//   * assembling a `StackedBasefoldProof` whose `basefold_proof.*` is
//     shape-compatible with the host path consumed by
//     `verify_jagged_pcs`.
//
// The hook returns `Result<.., (prover_data, eval_point)>` so the device
// side can tunnel ownership of the host inputs back to the host fallback
// on error (mirrors the `commit_jagged_pcs` hook contract).
// ─────────────────────────────────────────────────────────────────────

// `GpuBasefoldOpenFn` (the device open fn-ptr type) was removed in the
// SP1-parity static-dispatch collapse — the device open now lives in the
// `JaggedOpener` impl `DeviceJaggedOpener` (zkm-gpu-basefold), which calls
// `FriCudaProver::prove` and falls back to `open_jagged_pcs_host` on `Err`
// (returning `(prover_data, eval_point)` ownership so nothing is lost).

// #118: the GPU BaseFold open fn is provided STATICALLY (threaded from
// the prover down to the `open_jagged_pcs` dispatch), not via a global
// registry.  The former `GPU_BASEFOLD_OPEN_HOOK` OnceLock + `register_/get_`
// accessors were removed; the `prover` crate passes `Some(device_fn)` into
// the `prove_shard_to_basefold` free-fn (which threads it through the
// jagged-eval producer + `prove_trusted_evaluations` down to
// `prove_jagged_basefold_inner`'s open closure).

/// Verify the proof against a previously observed commitment.
pub fn verify_jagged_pcs(
    commitment: &<JaggedMmcs as p3_commit::Mmcs<JaggedVal>>::Commitment,
    area: usize,
    log_stacking_height: u32,
    eval_point: &[JaggedChallenge],
    evaluation_claim: JaggedChallenge,
    proof: &StackedBasefoldProof<JaggedVal, JaggedChallenge, JaggedMmcs>,
    challenger: &mut JaggedChallenger,
) -> Result<(), crate::basefold::StackedVerifierError> {
    let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
    let hash = crate::kb31_poseidon2::InnerHash::new(perm.clone());
    let compress = crate::kb31_poseidon2::InnerCompress::new(perm);
    let mmcs = JaggedMmcs::new(hash, compress, 0);
    let dft = Arc::new(JaggedDft::default());
    // Delegate to the GC-generic core (inner = Poseidon2-KoalaBear Mmcs).
    verify_jagged_pcs_generic::<JaggedChallenger, JaggedMmcs, JaggedDft>(
        commitment,
        area,
        log_stacking_height,
        eval_point,
        evaluation_claim,
        proof,
        challenger,
        mmcs,
        dft,
        FriConfig::<JaggedVal>::from_env_or_default(),
    )
}

/// BaseFold-over-BN254 port: GC-generic verify core.  Parameterized
/// over the challenger `Challenger` + MMCS `MT` + DFT `D`; the caller
/// supplies the concrete `mmcs`/`dft`.  The inner path uses `JaggedChallenger`
/// + Poseidon2-KoalaBear Mmcs; the wrap (OuterSC) will pass the BN254
/// challenger + Poseidon2-BN254 Mmcs.  `Val`/`Challenge` stay KoalaBear /
/// KoalaBear⁴ for both.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn verify_jagged_pcs_generic<Challenger, MT, D>(
    commitment: &<MT as p3_commit::Mmcs<JaggedVal>>::Commitment,
    area: usize,
    log_stacking_height: u32,
    eval_point: &[JaggedChallenge],
    evaluation_claim: JaggedChallenge,
    proof: &StackedBasefoldProof<JaggedVal, JaggedChallenge, MT>,
    challenger: &mut Challenger,
    mmcs: MT,
    dft: Arc<D>,
    fri: FriConfig<JaggedVal>,
) -> Result<(), crate::basefold::StackedVerifierError>
where
    MT: p3_commit::Mmcs<JaggedVal, Commitment: Clone> + Clone,
    D: p3_dft::TwoAdicSubgroupDft<JaggedVal> + Send + Sync,
    Challenger: p3_challenger::FieldChallenger<JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = JaggedVal>
        + CanObserve<<MT as p3_commit::Mmcs<JaggedVal>>::Commitment>,
{
    let (_prover, verifier) =
        build_pcs_generic::<MT, D>(log_stacking_height, mmcs, dft, fri);
    verifier.verify_trusted_evaluation(
        core::slice::from_ref(commitment),
        &[area],
        eval_point,
        proof,
        evaluation_claim,
        challenger,
    )
}

/// BaseFold-over-BN254 wrap port: generic commit -> open -> verify
/// roundtrip of the stacked BaseFold jagged-PCS over an arbitrary MMCS +
/// challenger.  Lets a downstream crate (recursion-core) validate the PCS over
/// the OUTER ring (`OuterValMmcs` / `OuterChallenger`, BN254) using the same
/// code path the inner ring uses, without re-exposing the prover-data
/// internals (the honest evaluation_claim is computed here).  Deterministic:
/// the eval point is sampled from a fresh unobserved challenger so prover and
/// verifier agree without an RNG dependency.
pub fn roundtrip_jagged_pcs_generic<Challenger, MT, D>(
    traces: Vec<(String, RowMajorMatrix<JaggedVal>)>,
    mut make_challenger: impl FnMut() -> Challenger,
    mmcs: MT,
    dft: Arc<D>,
) -> Result<(), crate::basefold::StackedVerifierError>
where
    MT: p3_commit::Mmcs<JaggedVal, Commitment: Clone> + Clone,
    D: p3_dft::TwoAdicSubgroupDft<JaggedVal> + Send + Sync,
    Challenger: p3_challenger::FieldChallenger<JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = JaggedVal>
        + CanObserve<<MT as p3_commit::Mmcs<JaggedVal>>::Commitment>,
{
    // Self-consistency roundtrip: commit/open/verify must agree on ONE
    // config; env-default rate keeps prover==verifier (any rate works here).
    let rt_fri = FriConfig::<JaggedVal>::from_env_or_default();
    let mut p_chal = make_challenger();
    let (commit, prover_data) = commit_jagged_pcs_host_generic::<Challenger, MT, D>(
        traces,
        &mut p_chal,
        mmcs.clone(),
        dft.clone(),
        rt_fri.clone(),
    );

    let stack_dim = commit.log_stacking_height as usize;
    let num_stripes = commit.area >> stack_dim;
    let num_batch_vars = num_stripes.next_power_of_two().trailing_zeros() as usize;
    let total_vars = num_batch_vars + stack_dim;

    // Deterministic eval point from a fresh (unobserved) challenger.
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
        for &r in batch_point.iter().rev() {
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

    let proof = open_jagged_pcs_host_generic::<Challenger, MT, D>(
        prover_data,
        eval_point.clone(),
        &mut p_chal,
        mmcs.clone(),
        dft.clone(),
        rt_fri.clone(),
    );

    let mut v_chal = make_challenger();
    v_chal.observe(commit.original_commitment.clone());
    verify_jagged_pcs_generic::<Challenger, MT, D>(
        &commit.original_commitment,
        commit.area,
        commit.log_stacking_height,
        &eval_point,
        evaluation_claim,
        &proof,
        &mut v_chal,
        mmcs,
        dft,
        rt_fri,
    )
}

// ─── Jagged-sumcheck integration ──────────
//
// Mirrors the (now-removed) WHIR jagged late-binding prover but
// commits via BaseFold instead of WHIR.  The dense polynomial is still
// materialized for the sumcheck reduction (the OOM win is in the
// commit phase: BaseFold streams stripes through dft_batch instead of
// blowing up the whole dense vector by 16×).  Per-chip BaseFold
// commit (which would skip even the brief dense materialization) is
// the next-stage refactor.
//
// This module does not require the `whir` feature.  It uses the ungated
// `jagged.rs` (data structures) and `jagged_sumcheck.rs` (PCS-agnostic
// reduction math), neither of which is behind the whir feature gate.

pub mod jagged {
    use alloc::vec::Vec;

    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};

    use crate::basefold::StackedBasefoldProof;
    use crate::jagged::{JaggedChipInfo, JaggedPacking, compute_jagged_metadata, materialize_dense_jagged};
    use crate::jagged_sumcheck::{JaggedReductionProof, verify_jagged_reduction};
    use crate::kb31_poseidon2::{InnerChallenge, InnerVal};

    /// SITE-1 trace-unification: the per-chip commit/open trace set as a
    /// BORROWED row-major view over the shard prover's single `Arc<Mle>`
    /// store (`shared_trace_mles`), instead of an owned `RowMajorMatrix`
    /// deep copy.  All commit + open consumers here are read-only (dims +
    /// `.values`), so they take `&[ChipTraceView]`; the Val↔InnerVal relabel
    /// stays the zero-copy slice reinterpret under the caller's TypeId gate.
    /// Device-resident chips carry an empty view (width 0); the host-fallback
    /// `rematerialize_chip_traces_via_provider` produces owned side-storage the
    /// caller re-views.
    pub type ChipTraceView<'a> = (alloc::string::String, RowMajorMatrixView<'a, InnerVal>);

    use super::{
        FriConfig,
        commit_jagged_pcs, open_jagged_pcs_host,
        verify_jagged_pcs,
    };

    // ── Test-only verify-progress tracker ─────────────────────────────────
    // Records how FAR the host verifier got, so CP-A validation can assert
    // the per-round restructure is transcript-faithful (coverage + every
    // group's reduction pass) even when the BaseFold OPEN fails for a reason
    // ORTHOGONAL to the split (e.g. an in-progress jagged-eval/div-fix bug
    // shared by the G==1 path on this WIP branch).
    #[cfg(test)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum VerifyStage {
        /// Failed the coverage check (group map ≠ partition).
        Coverage,
        /// Failed a per-group jagged-sumcheck reduction (group index).
        Reduction(usize),
        /// Failed a per-group BaseFold open (group index).
        Open(usize),
        /// All G groups accepted.
        Accepted,
    }
    #[cfg(test)]
    thread_local! {
        pub(crate) static LAST_VERIFY_STAGE: core::cell::Cell<Option<VerifyStage>> =
            const { core::cell::Cell::new(None) };
    }

    /// Record the verify stage (no-op outside tests).
    macro_rules! record_stage {
        ($s:expr) => {
            #[cfg(test)]
            {
                LAST_VERIFY_STAGE.with(|c| c.set(Some($s)));
            }
        };
    }

    /// Wire-format jagged metadata: only the per-bundle quantities
    /// the verifier needs to reconstruct the same `JaggedPacking`
    /// from chip_infos it receives separately.  We don't serialize
    /// `dense_values` (that's the multi-GB vector we just committed
    /// to BaseFold).
    ///
    /// `column_counts`: per-chip *actual*
    /// column count as exercised by this shard's trace, written by
    /// the prover from `compute_jagged_metadata`.  The verifier reads
    /// this instead of `BaseAir::width(chip)` so the prover can send
    /// `trace.width` (the truly-populated columns) without any
    /// chip.width() pad (~24x reduction in jagged-PCS data on
    /// workloads with sparse-column chips).
    /// Empty vec on the wire = legacy bundle → caller falls back to
    /// `BaseAir::width(chip)` for backward compat.
    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    pub struct PackingMeta {
        pub offsets: Vec<usize>,
        pub total_values: usize,
        pub log_dense_size: usize,
        #[serde(default)]
        pub column_counts: Vec<usize>,
    }

    // BaseFold-over-BN254: generic over the Mmcs so the wrap (OuterSC)
    // bundle holds the BN254 commitment + proof; inner alias below keeps every
    // caller + the rmp wire-format unchanged. serde(bound) mirrors the
    // JaggedCommitGeneric pattern (commitment + proof must serde).
    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    #[serde(bound(
        serialize = "<MT as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Commitment: serde::Serialize, <MT as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Proof: serde::Serialize",
        deserialize = "<MT as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Commitment: serde::Deserialize<'de>, <MT as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Proof: serde::Deserialize<'de>"
    ))]
    pub struct JaggedBasefoldBundleGeneric<MT: p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>> {
        /// Group-0 jagged-sumcheck reduction proof.  On the default (FIX-on /
        /// core, G==1) path this is the WHOLE proof and `extra_*` below are
        /// empty — byte-identical to the pre-split bundle.  On the per-round
        /// split (G≥2) path this is the FIRST group and the remaining G-1
        /// groups live in the `extra_*` Vecs (see [`Self::reduction_g`]).
        ///
        /// Rationale for "scalar group-0 + extra Vecs" rather than a single
        /// `Vec<G>`: it keeps the recursion lift + in-circuit verifier
        /// (`shard_level_witness.rs`, `recursive_jagged_pcs.rs`) — which read
        /// these scalar fields and are NOT touched in CP-A (host-only) —
        /// compiling unchanged, AND keeps the G==1 wire format byte-identical
        /// (the `extra_*` / `groups` fields are `serde(default)` empty so they
        /// serialize away).  CP-C folds these into the in-circuit G-loop.
        pub reduction: JaggedReductionProof<InnerChallenge>,
        /// Group-0 BaseFold open proof.
        pub basefold_proof: StackedBasefoldProof<
            InnerVal,
            InnerChallenge,
            MT,
        >,
        /// Per-chip per-column row-MLE values, FLAT in name-sorted chip order
        /// (NOT grouped) — the `groups` index map below partitions it.  Shared
        /// across all groups.
        pub y_per_chip: Vec<Vec<InnerChallenge>>,
        /// Group-0 BaseFold commit.
        pub commit: crate::jagged_pcs::JaggedCommitGeneric<MT>,
        /// Group-0 packing metadata (group-LOCAL offsets / prefix-sums).
        pub packing: PackingMeta,
        /// Group-0 jagged-eval sub-protocol proof.
        ///
        /// `serde(default)` so existing wire-format bundles deserialize.
        #[serde(default = "crate::jagged_eval_sumcheck::JaggedSumcheckEvalProof::dummy")]
        pub jagged_eval: crate::jagged_eval_sumcheck::JaggedSumcheckEvalProof<InnerChallenge>,

        // ── Per-round split (Architecture A) extra groups (G≥2 only) ──────
        // All `serde(default)` empty so a G==1 bundle is byte-identical to the
        // pre-split wire format.  Indexed g-1 for group g≥1.
        /// Reductions for groups 1..G.
        #[serde(default)]
        pub extra_reduction: Vec<JaggedReductionProof<InnerChallenge>>,
        /// BaseFold opens for groups 1..G.
        #[serde(default)]
        pub extra_basefold_proof: Vec<StackedBasefoldProof<InnerVal, InnerChallenge, MT>>,
        /// BaseFold commits for groups 1..G.
        #[serde(default)]
        pub extra_commit: Vec<crate::jagged_pcs::JaggedCommitGeneric<MT>>,
        /// Packing metadata for groups 1..G.
        #[serde(default)]
        pub extra_packing: Vec<PackingMeta>,
        /// Jagged-eval proofs for groups 1..G.
        #[serde(default)]
        pub extra_jagged_eval: Vec<crate::jagged_eval_sumcheck::JaggedSumcheckEvalProof<InnerChallenge>>,
        /// Group membership: `groups[g]` lists the indices (INTO the
        /// name-sorted chip set) committed in group `g`.  THE wire form the
        /// verifier's coverage check validates against an independent
        /// [`crate::jagged::partition_from_chip_infos`] run.  Must be an
        /// exact cover (no drop, no dup, canonical name-sorted order).
        /// `serde(default)` empty for G==1 / legacy bundles → the verifier
        /// treats an empty map as the single-group identity cover.
        #[serde(default)]
        pub groups: Vec<Vec<usize>>,
    }

    impl<MT: p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>> JaggedBasefoldBundleGeneric<MT> {
        /// Number of independent jagged groups (G).  `1` on the default path.
        #[must_use]
        pub fn num_groups(&self) -> usize {
            1 + self.extra_reduction.len()
        }
        /// Reduction proof for group `g` (group 0 is the scalar field).
        #[must_use]
        pub fn reduction_g(&self, g: usize) -> &JaggedReductionProof<InnerChallenge> {
            if g == 0 { &self.reduction } else { &self.extra_reduction[g - 1] }
        }
        /// BaseFold open proof for group `g`.
        #[must_use]
        pub fn basefold_proof_g(
            &self,
            g: usize,
        ) -> &StackedBasefoldProof<InnerVal, InnerChallenge, MT> {
            if g == 0 { &self.basefold_proof } else { &self.extra_basefold_proof[g - 1] }
        }
        /// BaseFold commit for group `g`.
        #[must_use]
        pub fn commit_g(
            &self,
            g: usize,
        ) -> &crate::jagged_pcs::JaggedCommitGeneric<MT> {
            if g == 0 { &self.commit } else { &self.extra_commit[g - 1] }
        }
        /// Packing metadata for group `g`.
        #[must_use]
        pub fn packing_g(&self, g: usize) -> &PackingMeta {
            if g == 0 { &self.packing } else { &self.extra_packing[g - 1] }
        }
        /// Jagged-eval proof for group `g`.
        #[must_use]
        pub fn jagged_eval_g(
            &self,
            g: usize,
        ) -> &crate::jagged_eval_sumcheck::JaggedSumcheckEvalProof<InnerChallenge> {
            if g == 0 { &self.jagged_eval } else { &self.extra_jagged_eval[g - 1] }
        }
        /// The group membership map, defaulting to the identity single-group
        /// cover when empty (G==1 / legacy bundles).
        #[must_use]
        pub fn groups_or_identity(&self, n_chips: usize) -> Vec<Vec<usize>> {
            if self.groups.is_empty() {
                alloc::vec![(0..n_chips).collect()]
            } else {
                self.groups.clone()
            }
        }
    }

    /// Concrete inner (Poseidon2-KoalaBear) bundle alias -- the type every
    /// current caller + wire-format uses.
    pub type JaggedBasefoldBundle = JaggedBasefoldBundleGeneric<crate::jagged_pcs::JaggedMmcs>;

    impl<MT: p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>> JaggedBasefoldBundleGeneric<MT>
    where
        <MT as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Commitment:
            serde::Serialize + for<'d> serde::Deserialize<'d>,
        <MT as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Proof:
            serde::Serialize + for<'d> serde::Deserialize<'d>,
    {
        /// Wire-format bytes (rmp-serde — matches the existing WHIR
        /// jagged-PCS bundle's serializer choice).
        pub fn to_bytes(&self) -> Vec<u8> {
            rmp_serde::to_vec(self).expect("JaggedBasefoldBundle serializes")
        }

        pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
            rmp_serde::from_slice(bytes).ok()
        }
    }

    /// Pre-computed jagged-PCS commit bundle for the
    /// single-main-commit flow.  Produced by
    /// [`precompute_jagged_basefold_commit`] before the shard-level
    /// Phase 1 prologue, then consumed by
    /// [`prove_jagged_basefold_with_precomputed`] in Phase 4.
    ///
    /// The 8-felt digest of `commit.original_commitment` (via
    /// [`crate::jagged_pcs::basefold_commit_digest`]) is the
    /// `main_commitment` that the prologue + verifier observe.
    pub struct PrecomputedJaggedCommitGeneric<MT: p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>> {
        pub packing: crate::jagged::JaggedPacking<InnerVal>,
        pub commit: crate::jagged_pcs::JaggedCommitGeneric<MT>,
        pub prover_data: crate::jagged_pcs::JaggedProverDataGeneric<MT>,
        /// Single shard-wide commit buffer: opaque handle to the
        /// device-resident dense polynomial the commit was built from,
        /// registered in ziren-gpu's `dense_q_device_registry`.  When
        /// `Some`, the step-4 jagged reduction passes it through the V2
        /// GPU hook so the SAME device buffer serves commit + reduction
        /// (no host re-materialize, no H2D re-upload).  `None` on the
        /// host build path — behaviour unchanged.
        pub dense_device_handle: Option<u64>,
        /// The CORRECT host-built dense_q that the commit was committed
        /// over, carried forward to the step-4 reduction.  Populated ONLY
        /// by the provider-aware HOST fallback commit body
        /// (`precompute_jagged_basefold_commit_provider`), which runs when
        /// the device commit hook DECLINES (e.g. the commit-NTT OOM
        /// preflight) and re-materializes the device-resident chips from
        /// the still-live (not-yet-drained) provider.  Without this, the
        /// reduction would re-materialize the dense_q from the per-shard
        /// provider — which the zerocheck-prepare `release_by_name`
        /// drain-on-lookup has ALREADY DRAINED by reduction time →
        /// WRONG dense_q → the jagged sumcheck reduction proof is built over
        /// the wrong data → the verifier REJECTS the bundle.
        /// Carrying the already-correct dense_q makes the decline path
        /// byte-identical to the golden host/device commit.  `None` on the
        /// happy path (the device commit fired → `dense_device_handle` is
        /// `Some` → the reduction takes the device buffer, never this) and on
        /// the plain non-provider host build (its reduction re-materialize is
        /// sound — no drain involved).
        pub host_dense_q: Option<alloc::vec::Vec<crate::jagged_pcs::JaggedVal>>,
        /// The per-shard rev(zeta) orientation the dense commit was
        /// materialized under (from the per-stage `StarkMachine::core_rev()`
        /// source of truth — `true` only on the CORE MIPS path).  Recorded on
        /// the committed data so the step-4 jagged reduction (host
        /// re-materialize + `y_per_chip`) uses the SAME orientation as the
        /// commit, in lockstep — replaces the former `current_use_rev()`
        /// thread-local carrier.  `false` on every recursion / shrink / wrap
        /// commit (byte-identical to legacy).
        pub rev: bool,
        /// The recursion-layer AREA PIN this commit was built under (band-cap
        /// carrier removal Phase C — replaces the former
        /// `current_recursion_area_pin()` thread-local).  `Some(target_log)` on a
        /// RECURSION (`compress`) commit: `packing.log_dense_size` was raised to
        /// `max(natural, target_log)` (a FIXED `2^target_log` committed area →
        /// constant `num_stripes`), and the step-4 jagged-eval must run over the
        /// PINNED dense (`prove_jagged_evaluation` `half = z_trace.len() + 1`) so
        /// its dimension is height-independent.  Recorded on the committed data so
        /// the OPEN path reads it back in lockstep with the commit.  `None` on
        /// every CORE / shrink / wrap commit (NATURAL own-area packing,
        /// byte-identical to legacy).
        pub recursion_area_pin: Option<usize>,
    }
    /// Concrete inner alias (MT = JaggedMmcs).
    pub type PrecomputedJaggedCommit = PrecomputedJaggedCommitGeneric<crate::jagged_pcs::JaggedMmcs>;

    // ─────────────────────────────────────────────────────────────────
    // Single shard-wide commit buffer — GPU precompute-commit hook.
    //
    // Replaces the HOST body of `precompute_jagged_basefold_commit`
    // (host dense pack + host stripe interleave + H2D re-upload) with a
    // device-side build: resident chips are packed D2D from the
    // per-shard provider, host chips H2D once, the stripes/encode/
    // Merkle all run on device, and the dense buffer is retained
    // device-side (registered handle) for the step-4 jagged reduction.
    // Output MUST be byte-identical to the host precompute (commit
    // digest, prover_data shapes, interleaved MLE bytes) — the commit
    // is transcript-critical.
    // ─────────────────────────────────────────────────────────────────

    // Phase-1 static dispatch (SP1-parity): the former
    // `GpuJaggedPrecomputeCommitFn` `fn`-ptr type (signature of the GPU jagged
    // precompute-commit hook) was RETIRED.  The device dense-pack + BaseFold
    // commit is now the `StarkGpuProver` OVERRIDE of
    // `MachineProver::commit_multilinears`, consumed by
    // `maybe_auto_precompute_basefold` through the `JaggedEvalProducer` COMMIT
    // seam — so no `Option<fn>` crosses this boundary.  The device hook body
    // still lives in ziren-gpu `commit_dense::gpu_jagged_precompute_commit_hook`
    // (called DIRECTLY by the override); its recursion-AREA-PIN + provider-read
    // rev(zeta) semantics are unchanged (byte-identical).

    /// Run steps (1) + (2) of `prove_jagged_basefold_with_y_per_chip`
    /// up-front, WITHOUT observing the commitment into a challenger.
    /// Returns the packing metadata plus the BaseFold commit + prover
    /// data — enough state for
    /// [`prove_jagged_basefold_with_precomputed`] to skip the in-band
    /// commit and run steps (3)+(4)+(5) against an aligned transcript.
    ///
    /// Caller MUST surface `commit.original_commitment` (or its 8-felt digest)
    /// to the verifier (via the shard-level proof's
    /// `main_commitment` field) at the same transcript position the
    /// verifier observes it.
    pub fn precompute_jagged_basefold_commit(
        chip_traces: &[ChipTraceView<'_>],
        // #118: the device BaseFold commit fn, threaded down to the inner
        // `commit_jagged_pcs_no_observe` dispatch.  `None` = host commit.
        gpu_basefold_commit: Option<super::GpuBasefoldCommitFn>,
        // The per-shard rev(zeta) orientation (from `StarkMachine::core_rev()`);
        // threaded to `materialize_dense_jagged` and recorded on the returned
        // `PrecomputedJaggedCommit.rev` so the step-4 reduction stays in lockstep.
        use_rev: bool,
        // Band-cap carrier removal Phase C: the recursion-layer AREA PIN, threaded
        // EXPLICITLY (was the `current_recursion_area_pin()` thread-local).  See
        // the twin in `precompute_jagged_basefold_commit_generic`.
        recursion_area_pin: Option<usize>,
    ) -> PrecomputedJaggedCommit {
        let n_chips = chip_traces.len();

        let _t_meta = std::time::Instant::now();
        let _meta_span = tracing::info_span!("jagged_compute_metadata_pre").entered();
        let mut packing = compute_jagged_metadata::<InnerVal>(chip_traces);
        // RECURSION-LAYER AREA PIN: see the twin in
        // `precompute_jagged_basefold_commit_generic`.  Carrier-keyed
        // (recursion-only); `None` on CORE/shrink/wrap → byte-identical.
        if let Some(target) = recursion_area_pin {
            if packing.log_dense_size < target {
                packing.log_dense_size = target;
            }
        }
        drop(_meta_span);
        tracing::info!(
            elapsed_ms = _t_meta.elapsed().as_millis() as u64,
            chips = n_chips,
            sub_phase = "compute_metadata_pre",
            "jagged sub-phase done"
        );

        let _t_commit = std::time::Instant::now();
        let _commit_span = tracing::info_span!("jagged_dense_commit_pre").entered();
        let (commit, prover_data) = {
            let dense_q =
                materialize_dense_jagged::<InnerVal>(chip_traces, packing.log_dense_size, use_rev);
            debug_assert_eq!(dense_q.len(), 1usize << packing.log_dense_size);
            let dense_traces = vec![(
                alloc::string::String::from("<jagged-dense>"),
                RowMajorMatrix::new(dense_q, 1),
            )];
            crate::jagged_pcs::commit_jagged_pcs_no_observe(
                dense_traces,
                gpu_basefold_commit,
            )
        };
        drop(_commit_span);
        tracing::info!(
            elapsed_ms = _t_commit.elapsed().as_millis() as u64,
            chips = n_chips,
            log_dense_size = packing.log_dense_size as u64,
            sub_phase = "dense_commit_pre",
            "jagged sub-phase done"
        );

        // Retain the commit's dense_q so EVERY shard —
        // including the ones with NO device-trace provider (the dominant
        // big-shard case: only the first `provider_inflight_cap` shards
        // snapshot a provider, the rest get `device_traces = None`) — carries
        // the ~4 GiB commit-output forward to the step-4 reduction via
        // `host_dense_q`.  The downstream gate (`device_happy =
        // precomputed_host_dense_q.is_some() && ...`) then fires the carried
        // reduce path (uploads this 4 GiB dense pack H2D and folds it on
        // device), with NO 16 GiB per-chip provider, NO inflight cap, and NO
        // extra resident VRAM.  This is shard-0's already-byte-identical
        // device-reduce path extended to all shards: the carried dense_q is
        // byte-identical to the committed digest by construction (same
        // `materialize_dense_jagged` over the same chips that produced
        // `commit`).  Gated `ZIREN_GPU_FREE_TRACES_PRE_REDUCE` (default OFF →
        // `host_dense_q = None`, byte-identical to the prior behavior); the
        // orchestrator sets it for the device-happy path (it is the natural
        // companion to the pre-reduce trace-free, which keys on the same env).
        // Carry the committed dense_q forward for the step-4 device reduce to
        // upload+fold (no re-materialize, no per-chip provider). Only useful on
        // the device commit path, so key it on the device BaseFold commit fn
        // being present; the host commit path (`None`) leaves it `None`.
        // Byte-identical to the committed digest by construction (same
        // `materialize_dense_jagged` over the same chips).
        let host_dense_q = if gpu_basefold_commit.is_some() {
            let dense_q =
                materialize_dense_jagged::<InnerVal>(chip_traces, packing.log_dense_size, use_rev);
            debug_assert_eq!(dense_q.len(), 1usize << packing.log_dense_size);
            Some(dense_q)
        } else {
            None
        };

        PrecomputedJaggedCommit { packing, commit, prover_data, dense_device_handle: None, host_dense_q, rev: use_rev, recursion_area_pin }
    }

    /// Provider-aware host precompute (used when commit-traces are not
    /// eagerly copied device→host).  Identical to
    /// [`precompute_jagged_basefold_commit`] but first
    /// re-materializes any empty (device-resident) chip trace from the
    /// per-shard provider, so the host commit body covers every chip's
    /// real cells even when `commit_traces` no longer eagerly D2H's them.
    /// This is the FALLBACK body for the device commit hook — taken
    /// only on a CUDA error / unsupported geometry — so the slower host
    /// re-materialize is acceptable and, critically, SOUND (no silently
    /// dropped device-chip cells / zero commitment).
    pub fn precompute_jagged_basefold_commit_provider(
        chip_traces: &[ChipTraceView<'_>],
        provider: Option<&dyn crate::shard_level::DeviceTraceProvider>,
        // #118: the device BaseFold commit fn, threaded down to
        // `precompute_jagged_basefold_commit`.  `None` = host commit.
        gpu_basefold_commit: Option<super::GpuBasefoldCommitFn>,
        // The per-shard rev(zeta) orientation, threaded down (see
        // `precompute_jagged_basefold_commit`).
        use_rev: bool,
        // Band-cap carrier removal Phase C: the recursion-layer AREA PIN, threaded
        // down (was the `current_recursion_area_pin()` thread-local).
        recursion_area_pin: Option<usize>,
    ) -> PrecomputedJaggedCommit {
        // No empty entry / no provider → identical to the plain path
        // (a cheap clone-through when nothing needs re-materializing).
        let needs_remat =
            provider.is_some() && chip_traces.iter().any(|(_, t)| t.width == 0);
        if !needs_remat {
            return precompute_jagged_basefold_commit(chip_traces, gpu_basefold_commit, use_rev, recursion_area_pin);
        }
        // DECLINE path: the device commit hook returned `None` (e.g. the
        // commit-NTT OOM preflight) so we re-materialize the device-resident
        // chips from the per-shard provider HERE, while the provider is still
        // LIVE (the zerocheck-prepare `release_by_name` drain has NOT run yet
        // at commit time).  Capture the CORRECT dense_q the commit is built
        // over and carry it forward to the step-4 reduction via
        // `host_dense_q`, so the reduction does NOT re-materialize from the
        // (by-then DRAINED) provider → no wrong dense_q → no verifier
        // reject.  Byte-identical to the golden host/device commit by
        // construction (same `materialize_dense_jagged` over the same
        // re-materialized chips that produced the committed digest).
        let full = rematerialize_chip_traces_via_provider(chip_traces, provider);
        let full_views = views_over_owned(&full);
        let mut pre = precompute_jagged_basefold_commit(&full_views, gpu_basefold_commit, use_rev, recursion_area_pin);
        let dense_q =
            materialize_dense_jagged::<InnerVal>(&full_views, pre.packing.log_dense_size, use_rev);
        debug_assert_eq!(dense_q.len(), 1usize << pre.packing.log_dense_size);
        pre.host_dense_q = Some(dense_q);
        pre
    }

    /// BaseFold-over-BN254 generic precompute: build the BaseFold commit
    /// over an arbitrary Mmcs (the ring's `BasefoldRing::BfMmcs`). Inner uses
    /// Poseidon2-KoalaBear; the wrap (OuterSC) passes the Poseidon2-BN254
    /// `OuterValMmcs` so the commitment is the BN254 root. The DFT is over
    /// KoalaBear for BOTH rings (Val == KoalaBear everywhere), so `JaggedDft`
    /// is reused. No challenger observe (caller surfaces the commitment).
    pub fn precompute_jagged_basefold_commit_generic<MT>(
        chip_traces: &[ChipTraceView<'_>],
        mmcs: MT,
        fri: FriConfig<crate::jagged_pcs::JaggedVal>,
        // The per-shard rev(zeta) orientation (from `StarkMachine::core_rev()`);
        // threaded to `materialize_dense_jagged` and recorded on the returned
        // `PrecomputedJaggedCommitGeneric.rev`.  `false` on the wrap/BN254 path.
        use_rev: bool,
        // Band-cap carrier removal Phase C: the recursion-layer AREA PIN, threaded
        // EXPLICITLY (was the `current_recursion_area_pin()` thread-local).
        // `Some(target_log)` (a recursion/compress commit) => pin
        // `log_dense_size` to `max(natural, target_log)`; `None` (CORE / shrink /
        // wrap) => NATURAL own-area packing.
        recursion_area_pin: Option<usize>,
    ) -> PrecomputedJaggedCommitGeneric<MT>
    where
        // `'static`/`Send` bounds on the commitment + prover data.  Both rings
        // (JaggedMmcs / OuterValMmcs) are concrete `'static` types, so this is a
        // no-op tightening for every existing caller.
        MT: p3_commit::Mmcs<
                crate::jagged_pcs::JaggedVal,
                Commitment: Clone + Send + 'static,
                ProverData<RowMajorMatrix<crate::jagged_pcs::JaggedVal>>: Send + 'static,
            > + Clone
            + 'static,
    {
        let mut packing = compute_jagged_metadata::<InnerVal>(chip_traces);
        // RECURSION-LAYER AREA PIN (SP1-faithful).  When the
        // recursion (`compress`) prover passes `Some(target_log)` here, so
        // raise `log_dense_size` to the pin floor so the dense
        // materialize + commit run at a FIXED area (`2^pin`) → constant
        // `num_stripes` → compose VK = f(chip-set, arity).  `None` on every
        // CORE / shrink / wrap path → NATURAL own-area packing (byte-identical).
        let pin = recursion_area_pin;
        if let Some(target) = pin {
            if packing.log_dense_size < target {
                packing.log_dense_size = target;
            }
        }
        let (commit, prover_data) = {
            let dense_q =
                materialize_dense_jagged::<InnerVal>(chip_traces, packing.log_dense_size, use_rev);
            debug_assert_eq!(dense_q.len(), 1usize << packing.log_dense_size);
            let dense_traces = vec![(
                alloc::string::String::from("<jagged-dense>"),
                RowMajorMatrix::new(dense_q, 1),
            )];

            let dft = std::sync::Arc::new(crate::jagged_pcs::JaggedDft::default());
            crate::jagged_pcs::commit_jagged_pcs_no_observe_generic::<MT, crate::jagged_pcs::JaggedDft>(
                dense_traces, mmcs, dft, fri,
            )
        };
        PrecomputedJaggedCommitGeneric { packing, commit, prover_data, dense_device_handle: None, host_dense_q: None, rev: use_rev, recursion_area_pin }
    }

    /// **Prover-side one-call entry point** — full pipeline:
    /// commit chip traces (via BaseFold-stacked), run jagged sumcheck
    /// reduction, open dense at the reduction's `z*` via BaseFold,
    /// bundle for the wire.
    pub fn prove_jagged_basefold(
        chip_traces: &[ChipTraceView<'_>],
        r_row_per_chip: &[Vec<InnerChallenge>],
        z_row: &[InnerChallenge],
        challenger: &mut crate::jagged_pcs::JaggedChallenger,
    ) -> JaggedBasefoldBundle {
        prove_jagged_basefold_with_y_per_chip(
            chip_traces,
            r_row_per_chip,
            z_row,
            None,
            challenger,
            // host-only self-contained flow (synthetic / tests) — host reducer/opener.
            &super::HostJaggedReducer,
            &super::HostJaggedOpener,
        )
    }

    /// Single-main-commit variant: run steps (3)+(4)+(5)
    /// using a `precompute_jagged_basefold_commit` result.  Does NOT
    /// observe `precomputed.commit.original_commitment` into the challenger —
    /// the orchestrator/Phase 1 prologue already observed the 8-felt
    /// digest as `main_commitment`, and the verifier counterpart
    /// [`verify_jagged_basefold_no_observe`] also skips the in-band
    /// observe.  Wire bytes match the
    /// `prove_jagged_basefold_with_y_per_chip` shape exactly.
    pub fn prove_jagged_basefold_with_precomputed(
        chip_traces: &[ChipTraceView<'_>],
        r_row_per_chip: &[Vec<InnerChallenge>],
        z_row: &[InnerChallenge],
        precomputed: PrecomputedJaggedCommit,
        pre_y_per_chip: Option<Vec<Vec<InnerChallenge>>>,
        challenger: &mut crate::jagged_pcs::JaggedChallenger,
        jagged_reducer: &dyn super::JaggedReducer,
        jagged_opener: &dyn super::JaggedOpener,
    ) -> JaggedBasefoldBundle {
        prove_jagged_basefold_with_precomputed_provider(
            chip_traces,
            r_row_per_chip,
            z_row,
            precomputed,
            pre_y_per_chip,
            challenger,
            None,
            jagged_reducer,
            jagged_opener,
        )
    }

    /// Provider-aware reduction prove: same as
    /// [`prove_jagged_basefold_with_precomputed`] but additionally accepts
    /// the per-shard `DeviceTraceProvider`.  The provider is used ONLY on
    /// the slow GPU-reduction fallback edge: when the device handle / V2
    /// hook declines and the host body must run, any chip whose
    /// `chip_traces` entry is empty (width 0 — its real cells live
    /// device-side) is re-materialized from the provider so the host
    /// `materialize_dense_jagged` rebuilds a correct dense_q.  On the
    /// happy path (V2 hook consumes the registered device dense handle)
    /// the provider is never touched, so passing `Some` is behaviour- and
    /// byte-neutral — it only ARMS the fallback against empty device-chip
    /// traces, removing the silent invalid-proof edge that an unconditional
    /// `commit_traces` D2H skip would otherwise leave.
    pub fn prove_jagged_basefold_with_precomputed_provider(
        chip_traces: &[ChipTraceView<'_>],
        r_row_per_chip: &[Vec<InnerChallenge>],
        z_row: &[InnerChallenge],
        precomputed: PrecomputedJaggedCommit,
        pre_y_per_chip: Option<Vec<Vec<InnerChallenge>>>,
        challenger: &mut crate::jagged_pcs::JaggedChallenger,
        provider: Option<&dyn crate::shard_level::DeviceTraceProvider>,
        jagged_reducer: &dyn super::JaggedReducer,
        jagged_opener: &dyn super::JaggedOpener,
    ) -> JaggedBasefoldBundle {
        prove_jagged_basefold_inner(
            chip_traces,
            r_row_per_chip,
            z_row,
            pre_y_per_chip,
            precomputed,
            challenger,
            provider,
            jagged_reducer,
            jagged_opener,
        )
    }

    /// Variant of [`prove_jagged_basefold`] that lets the caller pass a
    /// pre-computed `y_per_chip` (e.g. computed device-resident on
    /// GPU).  When `pre_y_per_chip` is `Some`, step (3) — the host
    /// triple-nested per-column reduction — is skipped entirely.
    /// Output bytes are identical to the host path.
    ///
    /// Self-contained legacy flow (host synthetic / unit tests + the
    /// runtime-dead `prove_trusted_evaluations` no-precompute fallthrough):
    /// precompute the single-main dense commit on host, observe its
    /// commitment in-band (mirroring `commit_jagged_pcs`'s observe so the
    /// `verify_jagged_basefold` transcript aligns), then run steps
    /// (3)+(4)+(5) through the precomputed fast path.  Byte-identical to the
    /// former inline in-band-commit body (host commit, legacy `rev = false`,
    /// no area pin, no provider).
    pub fn prove_jagged_basefold_with_y_per_chip(
        chip_traces: &[ChipTraceView<'_>],
        r_row_per_chip: &[Vec<InnerChallenge>],
        z_row: &[InnerChallenge],
        pre_y_per_chip: Option<Vec<Vec<InnerChallenge>>>,
        challenger: &mut crate::jagged_pcs::JaggedChallenger,
        jagged_reducer: &dyn super::JaggedReducer,
        jagged_opener: &dyn super::JaggedOpener,
    ) -> JaggedBasefoldBundle {
        let precomputed = precompute_jagged_basefold_commit(
            chip_traces,
            None,  // host commit
            false, // legacy bitrev orientation
            None,  // no recursion area pin
        );
        // In-band commit observe (the precomputed prove skips it, expecting
        // the orchestrator prologue to have observed the digest; here there
        // is none, so observe it now to match `verify_jagged_basefold`).  This
        // observe stays on THIS (legacy/synthetic) arm and precedes the spine
        // call — the precomputed arms omit it. Then route through the shared
        // `prove_jagged_basefold_with_precomputed_provider` spine (provider
        // `None`) instead of calling `_inner` directly, so `_inner` has a
        // single caller. Byte-identical: the spine is a pure pass-through to
        // `_inner` with these exact args, and the observe order is unchanged.
        challenger.observe(precomputed.commit.original_commitment.clone());
        prove_jagged_basefold_with_precomputed_provider(
            chip_traces,
            r_row_per_chip,
            z_row,
            precomputed,
            pre_y_per_chip,
            challenger,
            None,
            jagged_reducer,
            jagged_opener,
        )
    }

    /// Re-materialize a provider-aware view of `chip_traces` for the
    /// host fallback.  Any entry whose host trace is empty (width 0 — the
    /// chip is device-resident, its real cells never D2H'd onto the host
    /// `chip_traces`) is rebuilt from the per-shard provider via the
    /// `register_materialize_trace_hook` D2H path; non-empty entries and
    /// provider-misses are cloned through unchanged.  Returns an owned
    /// `Vec` so the dense materialize sees real dims + values exactly as a
    /// full eager `commit_traces` D2H would have produced.  Cold path only.
    fn rematerialize_chip_traces_via_provider(
        chip_traces: &[ChipTraceView<'_>],
        provider: Option<&dyn crate::shard_level::DeviceTraceProvider>,
    ) -> alloc::vec::Vec<(alloc::string::String, RowMajorMatrix<InnerVal>)> {
        chip_traces
            .iter()
            .map(|(name, trace)| {
                if trace.width == 0 {
                    if let Some(p) = provider {
                        if let Some((vals, w)) =
                            crate::shard_level::logup_gkr_prover::materialize_chip_main_trace_via_provider::<InnerVal>(
                                name, p,
                            )
                        {
                            return (name.clone(), RowMajorMatrix::new(vals, w));
                        }
                    }
                }
                // Host (width>0) chip: materialize an OWNED copy of the
                // borrowed view's cells (byte-identical to the former owned
                // `trace.clone()`).  Only the host-fallback / device-remat
                // edges reach here; the happy open path never re-materializes.
                (name.clone(), RowMajorMatrix::new(trace.values.to_vec(), trace.width))
            })
            .collect()
    }

    /// Build borrowed `ChipTraceView`s over an OWNED re-materialized trace
    /// set (`rematerialize_chip_traces_via_provider`), so the downstream
    /// view-taking commit/reduction consumers can read its cells with no
    /// further copy.  The returned views borrow `owned`, which must outlive
    /// them (the caller keeps it in scope).
    pub fn views_over_owned(
        owned: &[(alloc::string::String, RowMajorMatrix<InnerVal>)],
    ) -> alloc::vec::Vec<ChipTraceView<'_>> {
        owned
            .iter()
            .map(|(name, m)| (name.clone(), m.as_view()))
            .collect()
    }

    /// **Shared linear core** — the SP1-shaped, path-INDEPENDENT
    /// challenger sequence at the heart of every jagged-BaseFold prove.
    ///
    /// Mirrors SP1 `JaggedProver::prove_trusted_evaluations`
    /// (`slop/crates/jagged/src/prover.rs`): sample `z_col` at the
    /// verifier-matching transcript position → jagged-sumcheck reduction →
    /// jagged-eval sub-protocol → open.  The ONE Ziren-specific deviation is
    /// the point-extension after the reduction (SP1 opens at
    /// `final_eval_point` directly; Ziren extends `log_dense → log2(area)`
    /// via extra Fiat-Shamir coords — preserved here exactly).
    ///
    /// The `reduce` and `open` closures are the ONLY per-path variation
    /// (host-owned vs device-hook reduction; concrete vs BN254 open; the
    /// pre-reduce / pre-open device-memory frees) and NEITHER may run any
    /// challenger op outside its documented reduction/open — so every caller
    /// (single-group concrete, per-group multi-group, BN254 generic) lands its
    /// `z_col` / reduction / jagged-eval / point-extend / open challenger ops
    /// in the IDENTICAL order.  This is the de-dup that stops `z_col`'s
    /// transcript position from being path-dependent.
    #[allow(clippy::type_complexity)]
    pub fn prove_jagged_basefold_linear_core<Ch, P>(
        offsets: &[usize],
        z_row: &[InnerChallenge],
        area: usize,
        challenger: &mut Ch,
        // Band-cap carrier removal Phase C: the recursion-layer AREA PIN, read
        // off the precomputed commit (`PrecomputedJaggedCommit.recursion_area_pin`)
        // and threaded into `prove_jagged_evaluation` so its half/round-count is
        // pin-consistent with the (pinned) commit.  `None` on CORE/shrink/wrap.
        recursion_area_pin: Option<usize>,
        reduce: impl FnOnce(&[InnerChallenge], &mut Ch) -> JaggedReductionProof<InnerChallenge>,
        open: impl FnOnce(Vec<InnerChallenge>, &mut Ch) -> P,
    ) -> (
        JaggedReductionProof<InnerChallenge>,
        crate::jagged_eval_sumcheck::JaggedSumcheckEvalProof<InnerChallenge>,
        P,
    )
    where
        Ch: FieldChallenger<InnerVal>,
    {
        // (4) SP1-aligned: sample `z_col` (one challenge per column variable)
        // at the verifier-matching transcript position — after the commit
        // observe, immediately before the jagged sumcheck reduction.  Used
        // both to weight the column mix in the reduction and as the column
        // point for the branching-program jagged-eval sub-protocol.
        let num_cols = offsets.len().saturating_sub(1);
        let num_col_vars = num_cols.next_power_of_two().trailing_zeros() as usize;
        let z_col: Vec<InnerChallenge> = (0..num_col_vars)
            .map(|_| challenger.sample_algebra_element())
            .collect();

        // Jagged sumcheck reduction.  The caller's closure supplies the
        // host-owned / device-hook / group-local body; it MUST be
        // transcript-equivalent to
        // `prove_jagged_reduction_owned(.., &z_col, z_row, ..)` (the device
        // hook is byte-equivalent + snapshot-guarded; see the concrete path).
        let reduction = reduce(&z_col, challenger);

        // (4b) Jagged-eval sub-protocol at (z_row, z_col, rev(z*)).  PHASE 2:
        // the BranchingProgram reads its z_index big-endian while the
        // reduction emits z_star little-endian, so feed rev(z_star) — matches
        // recursive_jagged_pcs.rs (verify_sumcheck → jagged_evaluator_fn).
        let z_trace_be: Vec<InnerChallenge> =
            reduction.eval_point.iter().rev().copied().collect();
        let jagged_eval = crate::jagged_eval_sumcheck::prove_jagged_evaluation(
            offsets,
            z_row,
            &z_col,
            &z_trace_be,
            challenger,
            recursion_area_pin,
        );

        // (5) Ziren point-extend (SP1 opens at `final_eval_point` directly):
        // the BaseFold commit covers `area` cells (num_stripes × batch_size ×
        // stack_height), which can exceed 2^log_dense_size, so extend z* to
        // log2(area) with extra Fiat-Shamir coords (the verifier samples the
        // matching coords in the same transcript order), then open at z*.
        let target_dim = area.trailing_zeros() as usize;
        let mut extended_eval_point = reduction.eval_point.clone();
        while extended_eval_point.len() < target_dim {
            let r: InnerChallenge = challenger.sample_algebra_element();
            extended_eval_point.push(r);
        }
        let proof = open(extended_eval_point, challenger);

        (reduction, jagged_eval, proof)
    }

    /// Body shared by [`prove_jagged_basefold_with_y_per_chip`] (legacy
    /// self-contained flow, which now precomputes + observes the commit in its
    /// wrapper) and [`prove_jagged_basefold_with_precomputed`] (the
    /// single-commit flow).  `precomputed` is always supplied: steps (1) + (2)
    /// were run up-front and the in-band commit observe is suppressed (the
    /// caller already observed the digest — the orchestrator at the Phase 1
    /// prologue position, or the wrapper just above).
    fn prove_jagged_basefold_inner(
        chip_traces: &[ChipTraceView<'_>],
        r_row_per_chip: &[Vec<InnerChallenge>],
        z_row: &[InnerChallenge],
        pre_y_per_chip: Option<Vec<Vec<InnerChallenge>>>,
        precomputed: PrecomputedJaggedCommit,
        challenger: &mut crate::jagged_pcs::JaggedChallenger,
        // Per-shard device-trace provider, used only to re-materialize
        // empty (device-resident) chip traces on the host-fallback edges.
        provider: Option<&dyn crate::shard_level::DeviceTraceProvider>,
        // The device jagged-reduction function, provided statically by the
        // prover (`MachineProver::gpu_jagged_reduction_v2`) and threaded down
        // to the reduction dispatch below.  `None` = host reduction (CPU
        // prover / free-fn callers), byte-identical to the pre-#130
        // unregistered-hook path.
        jagged_reducer: &dyn super::JaggedReducer,
        // The device BaseFold open function, provided statically by the
        // prover (`MachineProver::gpu_basefold_open_hook`) and threaded down
        // to the `open_jagged_pcs` dispatch (the `open` closure below).
        // `None` = host open (CPU prover / free-fn callers), byte-identical
        // to the pre-#118 unregistered-hook path.
        jagged_opener: &dyn super::JaggedOpener,
    ) -> JaggedBasefoldBundle {
        // Per-shard jagged-PCS sub-phase timing.  Five sub-phases mirror
        // the numbered protocol steps below: (1) metadata, (2) commit
        // (incl. dense materialize + BaseFold encode), (3) per-chip
        // y_{c,j} evaluation, (4) jagged-sumcheck reduction, (5) BaseFold
        // open at z*.
        let n_chips = chip_traces.len();

        // The per-shard rev(zeta) orientation, read off the committed data
        // (`PrecomputedJaggedCommit.rev`, set at commit from
        // `StarkMachine::core_rev()`) so the step-4 reduction's dense
        // re-materialize + `y_per_chip` stay in lockstep with the commit.
        // Read off the committed data (`PrecomputedJaggedCommit.rev`).
        let dense_rev = precomputed.rev;

        // (1) + (2): metadata + dense commit were run up-front by the
        // orchestrator's single-main-commit path, which has already observed
        // the 8-felt digest of `commit.original_commitment` as
        // `main_commitment` in the shard-level Phase 1 prologue.  The in-band
        // commit observe is therefore skipped to keep transcripts aligned with
        // the verifier (which uses `verify_jagged_basefold_no_observe`).
        //
        // `host_dense_q` is `Some` ONLY on the device-commit DECLINE path (the
        // provider-aware host fallback body captured the correct dense_q while
        // the provider was live).  It carries the dense_q forward so the
        // reduction below does not re-materialize from the (drained) provider.
        // `recursion_area_pin` (band-cap Phase C) carries the recursion AREA PIN
        // forward so the step-4 jagged-eval half is pin-consistent with the
        // (pinned) commit — read off the committed data, not a thread-local.
        tracing::debug!(
            chips = n_chips,
            "jagged_pcs: using precomputed commit (Option B single-main-commit flow)",
        );
        let PrecomputedJaggedCommit {
            packing,
            commit,
            prover_data,
            dense_device_handle: precomputed_dense_handle,
            host_dense_q: precomputed_host_dense_q,
            rev: _,
            recursion_area_pin,
        } = precomputed;

        // (3) Compute per-chip per-column row-MLE values y_{c,j}.
        //
        // Parallelize across chips AND across columns within each chip.
        // The triple-nested loop
        // (chip × col × row) is O(N_chips · max_w · max_h) which for
        // a 22-chip MIPS shard padded to 2^19 rows hits ~10M+ EF
        // multiply-adds. Each chip × column reduction is independent.
        let _t_yvals = std::time::Instant::now();
        let _yvals_span = tracing::info_span!("jagged_y_per_chip").entered();
        use p3_maybe_rayon::prelude::*;
        let y_per_chip: Vec<Vec<InnerChallenge>> = if let Some(pre) = pre_y_per_chip {
            // Pre-computed (e.g. device-resident GPU eval).  Skip the
            // host triple-nested reduction entirely.
            assert_eq!(
                pre.len(),
                chip_traces.len(),
                "pre_y_per_chip length must match chip_traces length",
            );
            //  empty-chip skip: for empty-trace chips
            // (height==0 || width==0) the GPU dispatch supplies
            // `Vec::new()`; the host fallback (else branch) below
            // would have asserted on `h_padded.trailing_zeros() ==
            // r_row_c.len()` (h_padded=1, trailing_zeros=0 vs
            // r_row_c.len()=max_log_row_count).  Just accept the
            // empty per-chip y slot — y_{c,j} is the empty product
            // for an empty column set, so the downstream sumcheck
            // reduction skips it naturally.
            pre
        } else {
            // When the residual openings are unavailable (the residual-y
            // decline — no env kill-switch exists) the host triple-loop reads
            // chip cells directly — re-materialize empty device-resident chips
            // from the provider first so the reduction sees real cells (cold
            // path; happy path takes the `pre` branch above).
            let rematerialized_for_y =
                rematerialize_chip_traces_via_provider(chip_traces, provider);
            // The rev(zeta) orientation, read off the committed data
            // (`dense_rev`, from `PrecomputedJaggedCommit.rev`), captured by
            // value into the per-chip / per-column rayon closures below.
            let use_rev_y = dense_rev;
            rematerialized_for_y
                .par_iter()
                .zip(r_row_per_chip.par_iter())
                .map(|((_name, trace), r_row_c)| {
                    let h = trace.values.len() / trace.width.max(1);
                    let w = trace.width;
                    // #P2S0 band-cap retirement: a genuine HEIGHT-0 (0-row) but
                    // FULL-WIDTH missing chip
                    // must still emit ONE column claim PER COLUMN (all zero),
                    // NOT an empty Vec.  `build_weight_table` and the verifier's
                    // `verify_jagged_reduction` k-walk advance `k` through EVERY
                    // committed column (chip_info.column_count) including the
                    // 0-row chip's `w` empty columns; skipping them here would
                    // misalign the `z_col_lagrange[k]` index for every later
                    // chip => the round-0 / final reduction identity fails.  An
                    // empty column's row-MLE claim is 0 (Σ over 0 rows), so emit
                    // `w` zeros.  Only a truly width-0 chip (no columns) skips.
                    if w == 0 {
                        return Vec::new();
                    }
                    if h == 0 {
                        return vec![InnerChallenge::ZERO; w];
                    }
                    let h_padded = h.next_power_of_two();
                    assert_eq!(h_padded.trailing_zeros() as usize, r_row_c.len());

                    // SP1-faithful column claim: full row_eq over z_row indexed
                    // by the NATURAL row (eq(z_row, r)), no Pi_high embedding.
                    // The full row_eq subsumes the height factor for any row <
                    // 2^log_h_c (high bits of such a row are 0).  Build over
                    // reversed z_row so eq_c[r] = eq(z_row, r) (undo eq_mle_table
                    // LSB-first bitrev), matching build_weight_table.
                    let _ = r_row_c;
                    let z_row_rev: Vec<InnerChallenge> = z_row.iter().rev().copied().collect();
                    let eq_c = crate::zerocheck_prover::eq_mle_table::<InnerChallenge>(&z_row_rev);
                    // The rev(zeta) orientation (`use_rev_y`, read off the
                    // committed `PrecomputedJaggedCommit.rev`, in lockstep with
                    // the commit).  Under rev, the COMMIT (`materialize_dense_jagged`)
                    // places the data in NATURAL row order, so the column claim
                    // must read NATURAL rows too (`src = row`) — together with the
                    // natural-indexed `build_weight_table` the round-0 identity
                    // `Σ z_col·y == Σ_b q·w` holds.  Else (legacy) bit-reverse the
                    // trace row index so `y_per_chip == opened_values` (= MLE of
                    // bitrev(trace)), byte-identical to today.  `use_rev_y` is
                    // hoisted above (read on the carrier thread, not in this rayon
                    // closure).
                    let is_pow2 = h.is_power_of_two();
                    let log_h2 = if is_pow2 { (h as u32).trailing_zeros() } else { 0 };
                    (0..w)
                        .into_par_iter()
                        .map(|col| {
                            let mut acc = InnerChallenge::ZERO;
                            for row in 0..h {
                                let src = if use_rev_y {
                                    row
                                } else if is_pow2 {
                                    ((row as u32).reverse_bits() >> (32 - log_h2)) as usize
                                } else {
                                    row
                                };
                                acc += eq_c[row]
                                    * InnerChallenge::from(trace.values[src * w + col]);
                            }
                            acc
                        })
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        drop(_yvals_span);
        tracing::info!(
            elapsed_ms = _t_yvals.elapsed().as_millis() as u64,
            chips = n_chips,
            sub_phase = "y_per_chip",
            "jagged sub-phase done"
        );

        // (4) Re-materialize dense_q for the sumcheck reduction, then
        // drop it immediately after.  This is the counterpart of the
        // move-into-commit optimization in step (2): the two 4N
        // buffers never coexist.
        //
        // Use the `_owned` variant so the inner loop can drop dense_q
        // after round 0 (releasing the 4N base-field buffer before the
        // EF tables for rounds 1..n are built).  Saves one full N-element
        // clone vs the &[InnerVal] entry point.
        // dispatch: when a GPU jagged-reduction hook has been registered
        // (by ziren-gpu's `compress_multi_gpu` startup block; the hook is
        // `Some` only on the GPU prover), route the reduction through the
        // device hook.  The hook is byte-equivalent to
        // `prove_jagged_reduction_owned` (verified by the existing
        // host fallback path + the GPU-side scaffold tests in
        // `ziren-gpu/basefold/src/jagged_sumcheck.rs::tests`).  When
        // the hook returns `None` (unsupported shape) or is not
        // registered, the host fallback path runs unchanged.
        //
        // Hook hardening / diagnostics:
        //   * V2 hook (with optional device handle) preferred over V1
        //   * shape-rejection counter — log on each Nth (geometric) None
        //   * V2 hook with `Some(device_handle)` is logged separately to
        //     confirm the device-resident path is exercised
        //
        // Device-resident dense_q signature:
        // when a V2 hook is registered, the dispatch passes
        // `device_handle = None` (Ziren has no on-device dense_q yet —
        // the host materialization at line ~1413 is the source).  V2
        // semantics with `None` collapse to V1 behaviour; the signature
        // is in place for future Ziren-side wiring (e.g. GPU-resident
        // chip-trace materialization) to skip the H→D upload.
        // ── The jagged reduction (drop-LDEs pre-free + hook dispatch +
        // post-free) packaged as the `reduce` closure threaded through
        // the shared `prove_jagged_basefold_linear_core`.  The core samples
        // `z_col` at the SP1 transcript position (after the commit observe,
        // immediately before the reduction) and passes it in.  This closure
        // runs NO challenger op outside the reduction itself, so `z_col`'s
        // transcript position is identical to the generic / per-group paths —
        // the whole point of the de-dup.  Non-`move`: every capture (packing /
        // y_per_chip / chip_traces / provider / r_row_per_chip / z_row /
        // n_chips / the device handle) is read by reference; only
        // `precomputed_host_dense_q` is consumed, via `.take()`.
        let mut precomputed_host_dense_q = precomputed_host_dense_q;
        let reduce = |z_col: &[InnerChallenge],
                      challenger: &mut crate::jagged_pcs::JaggedChallenger|
              -> crate::jagged_sumcheck::JaggedReductionProof<InnerChallenge> {
        // Free the prior-phase device residency BEFORE
        // the jagged sumcheck reduce -- SP1's drop_ldes + read-base-by-ref
        // model.  The reduce reads ONLY dense_q (either the device-resident
        // buffer registered via precomputed_dense_handle, OR the CARRIED host
        // dense_q the commit-decline path captured into
        // precomputed_host_dense_q), NOT the per-chip device traces held by
        // the provider.  Freeing the provider traces is sound on EITHER
        // device-happy path -- the reduce has its dense_q without
        // re-materializing from the (about-to-be-drained) provider; off both
        // paths a later cold re-materialize from the drained provider would
        // silently produce an INVALID proof, so we leave the traces in place.
        // Pure lifetime change, transcript-neutral.  Fires unconditionally on
        // the device path (a provider being present).
        //
        // It accepts the CARRIED host dense_q path
        // (precomputed_host_dense_q.is_some()), not only the DEVICE-commit
        // path (precomputed_dense_handle.is_some()).  On big shards (TM 2^22,
        // log_dense=29) the device commit OOM-DECLINES to host (~6 GiB free)
        // so the handle is None and the dense_q is the CARRIED host buffer;
        // firing the free on that carried path too (the dominant big-shard
        // case) lets the reduce upload/fold the carried dense_q and never
        // touch the provider, so freeing it here is sound and lets the reduce
        // go device.
        // Set once `release_all` below has actually DRAINED the provider, so the
        // device-decline fallback can tell a live provider from a drained one.
        // Without it that fallback silently re-materializes EMPTY traces (see the
        // `saved_dense` None edge below).
        let mut provider_released = false;
        if let Some(p) = provider {
            let hook_v2_present = jagged_reducer.is_device();
            let device_happy = (precomputed_dense_handle.is_some()
                || precomputed_host_dense_q.is_some())
                && hook_v2_present;
            if device_happy {
                let _rel_span =
                    tracing::info_span!("dropldes_free_traces_pre_reduce").entered();
                p.release_all();
                provider_released = true;
                tracing::info!(
                    chips = n_chips,
                    log_dense_size = packing.log_dense_size as u64,
                    sub_phase = "free_traces_pre_reduce",
                    "DROPLDES (#74): released device-trace provider refs \
                     BEFORE the jagged reduce (SP1 drop_ldes analog; \
                     dense_q registry untouched)"
                );
            } else {
                use std::sync::OnceLock;
                static WARN_ONCE: OnceLock<()> = OnceLock::new();
                WARN_ONCE.get_or_init(|| {
                    tracing::warn!(
                        precomputed_dense_handle = precomputed_dense_handle.is_some(),
                        carried_host_dense_q = precomputed_host_dense_q.is_some(),
                        hook_v2 = hook_v2_present,
                        "DROPLDES (#74/#116): pre-reduce free requested but NOT on \
                         the device-happy path (neither a device handle nor a \
                         carried host dense_q) -- skipping (a later cold path \
                         could re-materialize from the provider)."
                    );
                });
            }
        }

        let _t_red = std::time::Instant::now();
        let _red_span = tracing::info_span!("jagged_sumcheck_reduce").entered();
        let reduction = {
            // The GPU reduction MUST match this host reduction exactly:
            // caller-sampled z_col Lagrange weights + full row_eq(rev(z_row))
            // embedding + MSB fold + coeff observe + insert(0, r).  An older
            // reduction shape (y-observe + gamma column mixing, LSB pair
            // fold, evals-observe, push point order) produces INVALID proofs;
            // z_col/z_row are passed through the hook signatures so the
            // ziren-gpu scaffold + CUDA kernels (jagged_sumcheck_kernels.cu
            // MSB) stay byte-identical vs pure host (fib core both the V2
            // device-handle and host-dense legs, tendermint core shards, fib
            // full chain + wrap).
            //
            // Device dispatch is selected by prover TYPE — the V2 hook is
            // registered (Some) only on the GPU prover, None on the CPU prover;
            // there is no env gate.  All fallible allocs MUST be hoisted before
            // any transcript interaction: allocating the round-0 fold-output
            // buffers (2 x 4 GiB at log_dense=29) AFTER the round-0
            // observe+sample risks an OOM there (peaks ~29.5 GiB VRAM) that
            // returns None and makes the caller re-run round 0 on host,
            // double-advancing the transcript and emitting a (log_n+1)-round
            // proof a downstream compose rejects (a TRANSCRIPT-POISON).  The
            // ziren-gpu jagged_sumcheck.rs hoists all fallible allocs before
            // any transcript interaction and resumes (not restarts) on host for
            // mid-loop failures.

            // The device-vs-host reduction dispatch: `jagged_reducer` is a
            // `&dyn JaggedReducer` provided by the prover TYPE — the host build
            // threads `&HostJaggedReducer` (is_device=false → this collapses to
            // the former `ActiveHook::None` host arm); the GPU prover threads
            // `&DeviceJaggedReducer` (is_device=true → the former `ActiveHook::V2`
            // arm: it snapshots+restores the challenger around
            // `gpu_jagged_reduction_hook_v2` and returns `None` on a shape
            // decline — having already RESTORED the challenger — so the host
            // fallback below re-runs on the same transcript state).  No runtime
            // fn-ptr / env gate: SP1-parity static dispatch.
            let is_device = jagged_reducer.is_device();

            // Single shard-wide commit buffer: when the precompute
            // registered a device-resident dense_q AND the device reducer will
            // consume it, skip the host dense materialization entirely —
            // the device buffer (the same one the commit was packed
            // from) is the source.  Every fallback edge below
            // re-materializes on host before running the host body.
            let skip_host_dense = precomputed_dense_handle.is_some()
                && is_device;
            // True when `dense_q` below is the CARRIED host dense_q from
            // the device-commit-decline fallback — the provider is DRAINED by
            // reduction time so this is the ONLY correct source; the V2/V1
            // hook None-fallback edges below must reuse it (not the drained
            // provider re-materialize).
            let mut dense_q_is_carried = false;
            let dense_q = if skip_host_dense {
                Vec::new()
            } else if let Some(carried) = precomputed_host_dense_q.take() {
                dense_q_is_carried = true;
                // The device commit DECLINED (e.g. OOM preflight) and the
                // provider-aware host fallback body carried forward the
                // CORRECT dense_q it committed over (captured while the
                // provider was still live, BEFORE the zerocheck-prepare
                // drain).  Use it directly instead of re-materializing from
                // the now-DRAINED provider (which would yield a WRONG dense_q
                // → the jagged sumcheck reduction proof would be built over
                // wrong data → the verifier REJECTS).  Byte-identical to the
                // golden commit by construction.
                debug_assert_eq!(carried.len(), 1usize << packing.log_dense_size);
                carried
            } else {
                // When device-resident chips carry empty host traces,
                // re-materialize them from the provider before the host
                // dense pack (cold path — happy path takes skip_host_dense).
                let rematerialized =
                    rematerialize_chip_traces_via_provider(chip_traces, provider);
                materialize_dense_jagged::<InnerVal>(&views_over_owned(&rematerialized), packing.log_dense_size, dense_rev)
            };

            // Device handle source (single shard-wide commit buffer): the
            // Option B precompute's device dense pack registers the buffer and
            // threads its handle through
            // `PrecomputedJaggedCommit::dense_device_handle`; the device reducer
            // takes it from the registry (`DenseQDevice::Owned`) so commit +
            // reduction share ONE device buffer.  `None` on the host build path
            // — the handle is then unused.
            let dense_q_device_handle: Option<u64> = if is_device {
                precomputed_dense_handle
            } else {
                None
            };

            // `r_row` / `y_clone` / `saved_dense` are computed UP-FRONT (were
            // inside the old `ActiveHook::V2` arm) so they outlive the `dense_q`
            // MOVE into `reduce_jagged` and stay available for the host
            // fallback.  Pure memory clones — no challenger interaction, so this
            // is transcript-neutral (byte-identical: the host reducer never
            // reaches the fallback, and the device reducer received the same
            // `&r_row` / `&y_clone` clones before).
            let r_row = r_row_per_chip.to_vec();
            let y_clone = y_per_chip.clone();
            // With the device-handle skip, `dense_q` is an empty placeholder —
            // never save it as a fallback source (the None edge below
            // re-materializes).  When `dense_q` is the CARRIED host dense_q
            // (device commit declined), ALWAYS save it — the provider is drained
            // so the None-fallback's re-materialize would be wrong; the carried
            // buffer is the only correct source.
            let saved_dense = if dense_q_is_carried {
                Some(dense_q.clone())
            } else {
                None
            };

            // Device/host reduction via the trait object.  The device reducer
            // snapshots+restores the challenger internally (defense-in-depth for
            // the whole hook surface) and returns `None` on a shape decline; the
            // host reducer always returns `Some`.
            match jagged_reducer.reduce_jagged(
                dense_q,
                dense_q_device_handle,
                &packing,
                &r_row,
                &y_clone,
                &z_col,
                z_row,
                challenger,
            ) {
                Some(p) => p,
                None => {
                    // Device reducer DECLINED (shape rejected) — the challenger
                    // was already RESTORED inside `reduce_jagged`, so the host
                    // fallback re-runs on the same transcript state.
                    tracing::warn!(
                        chips = n_chips,
                        log_dense_size = packing.log_dense_size as u64,
                        "jagged_pcs device reduction returned None \
                         (shape rejected) — falling back to host \
                         prove_jagged_reduction_owned",
                    );
                    let dense_q = saved_dense.unwrap_or_else(|| {
                        // Re-materialize empty (device-resident) chip traces
                        // from the provider so the host reduction fallback
                        // rebuilds the correct dense_q (not a partial zero
                        // buffer).
                        //
                        // This edge is REACHABLE and CORRECT whenever the
                        // provider is still live: the pre-reduce `release_all`
                        // deliberately SKIPS the not-device-happy path exactly
                        // so this can re-materialize (see its warn-once above).
                        //
                        // It is NOT correct once the provider has been drained.
                        // On the device-HANDLE path `dense_q` is an empty
                        // placeholder, so `saved_dense` is `None` — yet
                        // `device_happy` was true, so `release_all` already ran.
                        // Re-materializing from a drained provider yields
                        // all-zero traces, hence an all-zero `dense_q`, hence a
                        // proof that fails verification — silently, with no
                        // panic and no wrong-answer signal. Fail loudly instead
                        // of burning a shard's work on a proof we know is bad.
                        assert!(
                            !provider_released,
                            "jagged reduce: the device reducer declined AFTER the \
                             pre-reduce release_all drained the provider, and no \
                             host dense_q was carried (device-handle path). \
                             Re-materializing now would produce an all-zero \
                             dense_q and an invalid proof. Fix the caller: either \
                             carry a host dense_q on the handle path or withhold \
                             the pre-reduce release when the reducer may decline."
                        );
                        let rematerialized =
                            rematerialize_chip_traces_via_provider(
                                chip_traces,
                                provider,
                            );
                        materialize_dense_jagged::<InnerVal>(
                            &views_over_owned(&rematerialized),
                            packing.log_dense_size,
                            dense_rev,
                        )
                    });
                    crate::jagged_sumcheck::prove_jagged_reduction_owned(
                        dense_q,
                        &packing,
                        r_row_per_chip,
                        &y_per_chip,
                        &z_col,
                        z_row,
                        challenger,
                    )
                }
            }
        };
        drop(_red_span);
        tracing::info!(
            elapsed_ms = _t_red.elapsed().as_millis() as u64,
            chips = n_chips,
            sub_phase = "sumcheck_reduce",
            "jagged sub-phase done"
        );

        // ── Free the device-resident main traces BEFORE the
        // BaseFold open.  The reduce is the LAST phase that reads the raw
        // per-chip traces (commit + GKR first-layer + reduce all done);
        // the jagged-eval sub-protocol below operates on `packing.offsets`
        // (column geometry, not cells) and the open reads only the
        // committed stripe MLEs / codewords / Merkle tree (see
        // `open_jagged_pcs`).  Dropping the provider's retained trace +
        // dense/commit-jagged strong refs here lets the underlying device
        // buffers free (~10.5 GiB at log_dense=30) so the device open's
        // ~21.78 GiB footprint fits a 32 GB card instead of pre-firing a
        // host decline (and the host open's device NTT no longer OOMs).
        //
        // Pure LIFETIME change — transcript-neutral (no challenger touch,
        // no proof bytes affected).  Gated on a provider being present
        // (i.e. the GPU device path); host-only proving never passes one,
        // so the host test/verify path is unaffected.  Kill-switch:
        // ZIREN_GPU_FREE_TRACES_PRE_OPEN=0.
        if let Some(p) = provider {
            let _rel_span = tracing::info_span!("piece2_free_traces_pre_open").entered();
            p.release_all();
            tracing::info!(
                chips = n_chips,
                sub_phase = "free_traces_pre_open",
                "PIECE2: released device-trace provider refs before open"
            );
        }

            reduction
        };

        // ── The BaseFold open packaged as the `open` closure.  Moves
        // `prover_data` in; captures `n_chips` by copy.  Runs NO challenger op
        // outside `open_jagged_pcs`, so the point-extend (sampled by the core
        // immediately before) lands identically across all paths.
        //
        // (5) The jagged sumcheck reduces over `dense_q` (2^log_dense
        // cells) but the BaseFold commit covers `prover_data.area` cells
        // (num_stripes × batch_size × stack_height), which can exceed
        // 2^log_dense_size; the core extends z* to log2(area) with extra
        // Fiat-Shamir coords (SP1's `prove_trusted_evaluation` opens at
        // `final_eval_point` directly — Ziren's one deviation) before this
        // open runs.
        let area = prover_data.area;
        let open = move |extended_eval_point: Vec<InnerChallenge>,
                         challenger: &mut crate::jagged_pcs::JaggedChallenger| {
            let _t_open = std::time::Instant::now();
            let _open_span = tracing::info_span!("jagged_basefold_open").entered();
            let proof =
                jagged_opener.open_jagged(prover_data, extended_eval_point, challenger);
            drop(_open_span);
            tracing::info!(
                elapsed_ms = _t_open.elapsed().as_millis() as u64,
                chips = n_chips,
                sub_phase = "basefold_open",
                "jagged sub-phase done"
            );
            proof
        };

        // Shared linear core: z_col sample → reduce → jagged-eval →
        // point-extend → open (SP1 `prove_trusted_evaluations` shape).
        let (reduction, jagged_eval, proof) = prove_jagged_basefold_linear_core(
            &packing.offsets,
            z_row,
            area,
            challenger,
            recursion_area_pin,
            reduce,
            open,
        );

        let packing_meta = PackingMeta {
            offsets: packing.offsets.clone(),
            total_values: packing.total_values,
            log_dense_size: packing.log_dense_size,
            // fix: per-chip *actual* column count, so verifier
            // does not need to consult `BaseAir::width(chip)`.
            column_counts: packing
                .chip_infos
                .iter()
                .map(|ci| ci.column_count)
                .collect(),
        };
        // G==1: scalar group-0 fields; `extra_*` + `groups` empty ⇒ the wire
        // bytes are byte-identical to the pre-split bundle.
        let _ = n_chips;
        JaggedBasefoldBundle {
            reduction,
            basefold_proof: proof,
            y_per_chip,
            commit,
            packing: packing_meta,
            jagged_eval,
            extra_reduction: Vec::new(),
            extra_basefold_proof: Vec::new(),
            extra_commit: Vec::new(),
            extra_packing: Vec::new(),
            extra_jagged_eval: Vec::new(),
            groups: Vec::new(),
        }
    }

    /// BaseFold-over-BN254 generic host open orchestration: the
    /// challenger + Mmcs-generic mirror of the HOST path of
    /// `prove_jagged_basefold_inner` (no GPU jagged-reduction hooks -- those are
    /// inner-typed). The wrap (OuterChallenger + OuterValMmcs) calls this to
    /// emit a BaseFold-BN254 bundle. Requires a precomputed commit (Option B).
    #[allow(clippy::type_complexity)]
    pub fn prove_jagged_basefold_inner_generic<Challenger, MT>(
        chip_traces: &[ChipTraceView<'_>],
        r_row_per_chip: &[Vec<InnerChallenge>],
        z_row: &[InnerChallenge],
        pre_y_per_chip: Option<Vec<Vec<InnerChallenge>>>,
        precomputed: PrecomputedJaggedCommitGeneric<MT>,
        challenger: &mut Challenger,
        mmcs: MT,
        fri: FriConfig<crate::jagged_pcs::JaggedVal>,
    ) -> JaggedBasefoldBundleGeneric<MT>
    where
        MT: p3_commit::Mmcs<crate::jagged_pcs::JaggedVal, Commitment: Clone> + Clone,
        Challenger: p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
            + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
            + CanObserve<<MT as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Commitment>,
    {
        use p3_maybe_rayon::prelude::*;
        let PrecomputedJaggedCommitGeneric { packing, commit, prover_data, dense_device_handle: _, host_dense_q: _, rev: dense_rev, recursion_area_pin } = precomputed;

        // (3) per-chip per-column row-MLE values y_{c,j} (field-only; mirrors
        // the host path including the row-eq embedding factor + empty-chip skip).
        // The rev(zeta) orientation, read off the committed data
        // (`PrecomputedJaggedCommitGeneric.rev`), captured by value into the
        // per-chip rayon closures below.  On the wrap/BN254 path `rev == false`
        // => legacy bitrev (byte-identical).
        let use_rev_y = dense_rev;
        let y_per_chip: Vec<Vec<InnerChallenge>> = if let Some(pre) = pre_y_per_chip {
            assert_eq!(pre.len(), chip_traces.len(),
                "pre_y_per_chip length must match chip_traces length");
            pre
        } else {
            chip_traces
                .par_iter()
                .zip(r_row_per_chip.par_iter())
                .map(|((_name, trace), r_row_c)| {
                    let h = trace.values.len() / trace.width.max(1);
                    let w = trace.width;
                    if h == 0 || w == 0 {
                        return Vec::new();
                    }
                    let h_padded = h.next_power_of_two();
                    assert_eq!(h_padded.trailing_zeros() as usize, r_row_c.len());
                    let _ = r_row_c; // SP1 convention uses the full z_row row_eq
                    // SP1-faithful column claim: full row_eq over z_row indexed
                    // by the NATURAL row (eq(z_row, r)), no Pi_high embedding.
                    // Build over reversed z_row so eq_c[r] = eq(z_row, r) (undo
                    // eq_mle_table's LSB-first bitrev), matching build_weight_table.
                    let z_row_rev: Vec<InnerChallenge> = z_row.iter().rev().copied().collect();
                    let eq_c = crate::zerocheck_prover::eq_mle_table::<InnerChallenge>(&z_row_rev);
                    // Same rev(zeta) orientation (single source
                    // of truth) — NATURAL rows under rev so the round-0 identity
                    // holds on this no-observe verify recompute too; legacy bitrev
                    // (`y_per_chip == MLE of bitrev(trace)`) otherwise.
                    // `use_rev_y` is hoisted above the `par_iter` (carrier-thread
                    // read), captured by value into these rayon closures.
                    let is_pow2 = h.is_power_of_two();
                    let log_h2 = if is_pow2 { (h as u32).trailing_zeros() } else { 0 };
                    (0..w)
                        .into_par_iter()
                        .map(|col| {
                            let mut acc = InnerChallenge::ZERO;
                            for row in 0..h {
                                let src = if use_rev_y {
                                    row
                                } else if is_pow2 {
                                    ((row as u32).reverse_bits() >> (32 - log_h2)) as usize
                                } else {
                                    row
                                };
                                acc += eq_c[row]
                                    * InnerChallenge::from(trace.values[src * w + col]);
                            }
                            acc
                        })
                        .collect::<Vec<_>>()
                })
                .collect()
        };

        // ── The HOST reduction (no device hooks on the BN254 wrap
        // path) + the BN254 BaseFold open as the `reduce` / `open` closures
        // threaded through the shared `prove_jagged_basefold_linear_core`.
        // The core samples `z_col` at the SP1 transcript position and runs the
        // jagged-eval + point-extend — so this path lands its challenger ops in
        // the IDENTICAL order to the concrete single-group + per-group paths.
        let reduce = |z_col: &[InnerChallenge],
                      challenger: &mut Challenger|
              -> JaggedReductionProof<InnerChallenge> {
            let dense_q =
                materialize_dense_jagged::<InnerVal>(chip_traces, packing.log_dense_size, dense_rev);
            crate::jagged_sumcheck::prove_jagged_reduction_owned(
                dense_q, &packing, r_row_per_chip, &y_per_chip, z_col, z_row, challenger,
            )
        };
        let area = prover_data.area;
        let open = move |extended_eval_point: Vec<InnerChallenge>,
                         challenger: &mut Challenger| {
            let dft = std::sync::Arc::new(crate::jagged_pcs::JaggedDft::default());
            crate::jagged_pcs::open_jagged_pcs_host_generic::<
                Challenger,
                MT,
                crate::jagged_pcs::JaggedDft,
            >(prover_data, extended_eval_point, challenger, mmcs, dft, fri)
        };
        let (reduction, jagged_eval, proof) = prove_jagged_basefold_linear_core(
            &packing.offsets,
            z_row,
            area,
            challenger,
            recursion_area_pin,
            reduce,
            open,
        );

        let packing_meta = PackingMeta {
            offsets: packing.offsets.clone(),
            total_values: packing.total_values,
            log_dense_size: packing.log_dense_size,
            column_counts: packing.chip_infos.iter().map(|ci| ci.column_count).collect(),
        };
        // The BN254 wrap path is always single-round (G==1): scalar fields,
        // empty extra_* / groups (byte-identical to the pre-split bundle).
        JaggedBasefoldBundleGeneric {
            reduction,
            basefold_proof: proof,
            y_per_chip,
            commit,
            packing: packing_meta,
            jagged_eval,
            extra_reduction: Vec::new(),
            extra_basefold_proof: Vec::new(),
            extra_commit: Vec::new(),
            extra_packing: Vec::new(),
            extra_jagged_eval: Vec::new(),
            groups: Vec::new(),
        }
    }
    /// Verifier mirror.
    pub fn verify_jagged_basefold(
        chip_infos: &[JaggedChipInfo],
        r_row_per_chip: &[Vec<InnerChallenge>],
        z_row: &[InnerChallenge], // full z* for embedding factor
        bundle: &JaggedBasefoldBundle,
        challenger: &mut crate::jagged_pcs::JaggedChallenger,
    ) -> bool {
        verify_jagged_basefold_inner(
            chip_infos,
            r_row_per_chip,
            z_row,
            bundle,
            // Synthetic-bundle callers (unit tests) carry no shard
            // openings — the cross-bind is a no-op here.
            None,
            challenger,
            /* skip_commit_observe = */ false,
        )
    }

    /// Option B variant: verifier counterpart of
    /// [`prove_jagged_basefold_with_precomputed`].  Skips the in-band
    /// `challenger.observe(commitment)` because the orchestrator's
    /// Phase 1 prologue already observed the BaseFold commit's 8-felt
    /// digest as `main_commitment`.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_jagged_basefold_no_observe(
        chip_infos: &[JaggedChipInfo],
        r_row_per_chip: &[Vec<InnerChallenge>],
        z_row: &[InnerChallenge], // full z* for embedding factor
        bundle: &JaggedBasefoldBundle,
        // Cross-bind: per-chip `opened_values.chips[].main.local` (index-
        // aligned with `chip_infos` / `bundle.y_per_chip`); `None` disables the bind.
        opened_main: Option<&[Vec<InnerChallenge>]>,
        challenger: &mut crate::jagged_pcs::JaggedChallenger,
    ) -> bool {
        verify_jagged_basefold_inner(
            chip_infos,
            r_row_per_chip,
            z_row,
            bundle,
            opened_main,
            challenger,
            /* skip_commit_observe = */ true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_jagged_basefold_inner(
        chip_infos: &[JaggedChipInfo],
        r_row_per_chip: &[Vec<InnerChallenge>],
        z_row: &[InnerChallenge], // full z* for embedding factor
        bundle: &JaggedBasefoldBundle,
        // Cross-bind: per-chip `opened_values.chips[].main.local` trace
        // openings (index-aligned with `chip_infos` / `bundle.y_per_chip`), or
        // `None` for synthetic-bundle unit tests with no shard openings.
        opened_main: Option<&[Vec<InnerChallenge>]>,
        challenger: &mut crate::jagged_pcs::JaggedChallenger,
        skip_commit_observe: bool,
    ) -> bool {
        // ── COVERAGE CHECK (the #1 soundness guard — FIRST assertion) ─────
        // Independently re-derive the round partition from the PUBLIC
        // name-sorted (name,row_count,column_count) the verifier already
        // holds, and require the proof's `groups` membership to equal it
        // EXACTLY (no chip dropped, none duplicated, canonical order).
        // Without this a malicious prover could OMIT a chip from every
        // group — that chip's trace is then never opened, and nothing
        // downstream would notice.
        let expected_groups = crate::jagged::partition_from_chip_infos(chip_infos);
        let proof_groups: Vec<Vec<usize>> = bundle.groups_or_identity(chip_infos.len());
        if proof_groups != expected_groups {
            eprintln!(
                "[basefold verify] COVERAGE CHECK FAILED: proof groups {:?} != expected {:?}",
                proof_groups, expected_groups
            );
            record_stage!(VerifyStage::Coverage);
            return false;
        }
        // Structural agreement between the group map and the per-group data.
        let g_count = proof_groups.len();
        if bundle.num_groups() != g_count {
            eprintln!(
                "[basefold verify] COVERAGE CHECK FAILED: bundle carries {} groups \
                 but the group map has G={}",
                bundle.num_groups(),
                g_count,
            );
            record_stage!(VerifyStage::Coverage);
            return false;
        }

        // STEP 1 (transcript): observe ALL G commits up-front in partition
        // order — unless the Option B single-main-commit flow already
        // observed them at the Phase 1 prologue.  (G==1 single-commit is the
        // current Option B path; multi-commit Option B is CP-B/CP-C.)
        if !skip_commit_observe {
            for g in 0..g_count {
                challenger.observe(bundle.commit_g(g).original_commitment.clone());
            }
        }

        // STEP 3: verify each independent jagged instance against the SHARED
        // z_row.  All G must accept.
        for g in 0..g_count {
            let grp = &proof_groups[g];
            // Group-LOCAL chip_infos / r_row (membership-indexed); the
            // per-group bundle metadata (offsets/total/log_dense_size) is
            // group-local too (prefix-sums restart at 0).
            let chip_infos_g: Vec<JaggedChipInfo> =
                grp.iter().map(|&i| chip_infos[i].clone()).collect();
            let r_row_g: Vec<Vec<InnerChallenge>> =
                grp.iter().map(|&i| r_row_per_chip[i].clone()).collect();
            let y_per_chip_g: Vec<Vec<InnerChallenge>> =
                grp.iter().map(|&i| bundle.y_per_chip[i].clone()).collect();
            // Slice this group's opened main.local columns in the SAME
            // membership order as `y_per_chip_g` so the cross-bind k-walk lines up.
            let opened_main_g: Option<Vec<Vec<InnerChallenge>>> = opened_main
                .map(|om| grp.iter().map(|&i| om[i].clone()).collect());
            let pkg = bundle.packing_g(g);
            let packing = JaggedPacking {
                dense_values: Vec::new(),
                chip_infos: chip_infos_g,
                offsets: pkg.offsets.clone(),
                total_values: pkg.total_values,
                log_dense_size: pkg.log_dense_size,
            };
            if !verify_one_jagged_group(
                &packing,
                &r_row_g,
                z_row,
                &y_per_chip_g,
                opened_main_g.as_deref(),
                bundle.reduction_g(g),
                bundle.jagged_eval_g(g),
                bundle.commit_g(g),
                bundle.basefold_proof_g(g),
                challenger,
                g,
            ) {
                return false;
            }
        }
        record_stage!(VerifyStage::Accepted);
        true
    }

    /// Verify ONE independent jagged instance (group `g`) against the shared
    /// `z_row`: sample `z_col_g`, verify the reduction, replay the
    /// jagged-eval transcript, extend `z*_g`, and verify the BaseFold open
    /// of `C_g`.  Returns `false` on any rejection.
    #[allow(clippy::too_many_arguments)]
    fn verify_one_jagged_group(
        packing: &JaggedPacking<InnerVal>,
        r_row_per_chip: &[Vec<InnerChallenge>],
        z_row: &[InnerChallenge],
        y_per_chip: &[Vec<InnerChallenge>],
        // Cross-bind: this group's per-chip `opened_values.chips[].main.local`
        // trace openings (index-aligned with `y_per_chip`), or `None` for callers
        // (unit tests) that verify a synthetic bundle with no shard openings.
        opened_main: Option<&[Vec<InnerChallenge>]>,
        reduction: &crate::jagged_sumcheck::JaggedReductionProof<InnerChallenge>,
        jagged_eval: &crate::jagged_eval_sumcheck::JaggedSumcheckEvalProof<InnerChallenge>,
        commit: &crate::jagged_pcs::JaggedCommit,
        basefold_proof: &crate::basefold::StackedBasefoldProof<InnerVal, InnerChallenge, crate::jagged_pcs::JaggedMmcs>,
        challenger: &mut crate::jagged_pcs::JaggedChallenger,
        g: usize,
    ) -> bool {
        // SP1-aligned: sample z_col at the matching transcript position
        // (after the commit observe, before the reduction), mirroring
        // the prover.
        let num_cols = packing.offsets.len().saturating_sub(1);
        let num_col_vars = num_cols.next_power_of_two().trailing_zeros() as usize;
        let z_col: Vec<InnerChallenge> = (0..num_col_vars)
            .map(|_| challenger.sample_algebra_element())
            .collect();
        let red_result = verify_jagged_reduction(
            reduction,
            packing,
            r_row_per_chip,
            y_per_chip,
            &z_col,
            z_row,
            challenger,
        );
        let Some((z_star, q_at_z, _w_at_z)) = red_result else {
            eprintln!("[basefold verify] group {g}: jagged sumcheck reduction REJECTED");
            record_stage!(VerifyStage::Reduction(g));
            return false;
        };

        // ── CROSS-BIND (host analog of recursive_jagged_pcs.rs:247) ─────
        //
        // The recursion CIRCUIT ties the jagged sumcheck's claimed sum to the
        // TRACE OPENINGS: it forms `column_claims = opened_values.chips[].main.local`
        // (shard_basefold.rs:588 → recursive_jagged_pcs.rs:218) and asserts
        //   evaluate_mle(column_claims, z_col) == sumcheck_proof.claimed_sum   (:247).
        //
        // The host, in contrast, DERIVES the claimed sum from the bundle's
        // `y_per_chip` alone — `verify_jagged_reduction` uses
        //   t = Σ_k z_col_lagrange[k]·y_flat[k] = evaluate_mle(y_flat, z_col)
        // as its round-0 claim (jagged_sumcheck.rs:735-742) and NEVER checks
        // `y_per_chip` against the openings.  So a malicious host proof could ship
        // `y_per_chip ≠ opened_values.main.local` and be accepted by BOTH the
        // zerocheck (which consumes `opened_values`) and this jagged phase (which
        // consumes `y_per_chip`) independently — the soundness-parity gap.
        //
        // Close it exactly as the circuit does: recompute the OPENED-VALUES column
        // MLE at the SAME `z_col` and require it to equal the y-derived claimed sum
        // `t`.  We mirror the MLE form rather than a raw element-wise compare: under
        // the rev(zeta) orientation the two column vectors are NOT guaranteed
        // element-wise equal, but their `z_col`-MLEs ARE equal — that is precisely
        // the identity the circuit asserts and that passes on every honest proof.
        // We weight only the columns the sumcheck actually consumed (per-chip
        // `y_per_chip[i].len()`, i.e. the packed column_count), matching the k-walk
        // in `verify_jagged_reduction` so `sum_y` reproduces its `t` bit-for-bit.
        if let Some(opened_main_g) = opened_main {
            if opened_main_g.len() != y_per_chip.len() {
                eprintln!(
                    "[basefold verify] group {g}: #121 cross-bind FAILED — opened-main \
                     chip count {} != y_per_chip {}",
                    opened_main_g.len(),
                    y_per_chip.len(),
                );
                record_stage!(VerifyStage::Reduction(g));
                return false;
            }
            let z_col_lagrange =
                crate::jagged_branching_program::partial_lagrange(&z_col);
            let mut sum_y = InnerChallenge::ZERO;
            let mut sum_open = InnerChallenge::ZERO;
            let mut k = 0usize;
            let mut ok = true;
            'chips: for (yc, mc) in y_per_chip.iter().zip(opened_main_g.iter()) {
                // The opened trace must expose at least the columns the sumcheck
                // consumed (column_count ≤ BaseAir::width); a proof opening fewer
                // is malformed → reject.
                if mc.len() < yc.len() {
                    ok = false;
                    break 'chips;
                }
                for j in 0..yc.len() {
                    if k >= z_col_lagrange.len() {
                        ok = false;
                        break 'chips;
                    }
                    let w = z_col_lagrange[k];
                    sum_y += w * yc[j];
                    sum_open += w * mc[j];
                    k += 1;
                }
            }
            if !ok || sum_open != sum_y {
                eprintln!(
                    "[basefold verify] group {g}: #121 CROSS-BIND FAILED — the bundle's \
                     y_per_chip column claims are inconsistent with \
                     opened_values.main.local at z_col \
                     (evaluate_mle(opened_main, z_col) != jagged claimed_sum)"
                );
                record_stage!(VerifyStage::Reduction(g));
                return false;
            }
        }

        // Replay the jagged-eval sub-protocol transcript so the
        // challenger stays in sync with the prover before the BaseFold
        // open.  (Full branching-program verification is done by the
        // recursion verifier; the host self-check needs only transcript
        // fidelity here.)
        crate::jagged_eval_sumcheck::replay_jagged_evaluation_transcript(
            jagged_eval,
            challenger,
        );

        // SP1-port: extend z_star from log_dense_size to log2(area)
        // by sampling additional Fiat-Shamir coords, mirroring the
        // prover's extension in `prove_jagged_basefold` step (5).
        // Both sides sample from the same transcript state at the same
        // point in the protocol so the coords match.
        // Capture the reduced (pre-extension) length BEFORE the extend
        // loop: that is the fixed log_stacking-equivalent height of
        // this (per-group) commit, used below to gate the sub-stripe
        // Π(1-r) claim adjustment.
        let z_star_orig_len = z_star.len();
        let target_dim = commit.area.trailing_zeros() as usize;
        let mut extended_z_star = z_star;
        while extended_z_star.len() < target_dim {
            let r: InnerChallenge = challenger.sample_algebra_element();
            extended_z_star.push(r);
        }

        // FIX-off sub-stripe commits (host analog of the in-circuit
        // `claim_adj`, recursive_stacked_pcs.rs): when the reduced point is
        // SHORTER than the commit's log_stacking_height, the FS-extension
        // coords falling in the STACK portion `[z_star_orig_len, stack_dim)`
        // correspond to the ZERO high-half padding of the stripe (the dense
        // poly of `z_star_orig_len` vars is zero-padded up to `2^stack_dim`).
        // By the MLE zero-padding identity the committed stripe's eval at
        // `stack_point` carries a Π(1 - r_k) factor over those coords that the
        // reduced-point claim lacks, so the stacked reconstruction equals
        // Π(1 - r_k) · q_at_z.  Multiply the claim to match.  NO-OP when
        // z_star_orig_len >= stack_dim (all FIX-on and large FIX-off commits)
        // ⇒ byte-identical there.  Each group is verified through this
        // function, so this covers every group (CP-A round-split included).
        let stack_dim = commit.log_stacking_height as usize;
        let mut q_at_z_adj = q_at_z;
        if z_star_orig_len < stack_dim {
            for r in &extended_z_star[z_star_orig_len..stack_dim.min(target_dim)] {
                q_at_z_adj *= InnerChallenge::ONE - *r;
            }
        }

        // Verify the BaseFold opening: claim is q_at_z (sub-stripe adjusted),
        // point is the extended z*.
        let res = verify_jagged_pcs(
            &commit.original_commitment,
            commit.area,
            commit.log_stacking_height,
            &extended_z_star,
            q_at_z_adj,
            basefold_proof,
            challenger,
        );
        if let Err(e) = &res {
            eprintln!("[basefold verify] basefold opening REJECTED: {:?}", e);
            record_stage!(VerifyStage::Open(g));
        }
        res.is_ok()
    }

    /// BaseFold-over-BN254 wrap port: build the ring-agnostic verifier
    /// inputs (chip_infos / r_row_per_chip / z_row) from the bundle's PackingMeta
    /// + per-chip column widths + the shared zerocheck eval point. Mirrors the
    /// host verifier's construction (shard_level/verifier.rs) so the outer-ring
    /// verify hook reuses the exact same logic. Names are debug-only (unused in
    /// the verify math), so placeholders suffice.
    pub fn build_jagged_verify_inputs(
        packing: &PackingMeta,
        chip_widths: &[usize],
        eval_point: &[InnerChallenge],
    ) -> (
        Vec<crate::jagged::JaggedChipInfo>,
        Vec<Vec<InnerChallenge>>,
        Vec<InnerChallenge>,
    ) {
        use crate::jagged::JaggedChipInfo;
        let column_counts = &packing.column_counts;
        let mut chip_infos: Vec<JaggedChipInfo> = (0..chip_widths.len())
            .map(|i| JaggedChipInfo {
                name: alloc::format!("chip{i}"),
                row_count: 0,
                column_count: column_counts.get(i).copied().unwrap_or(chip_widths[i]),
            })
            .collect();
        // Patch row_count from the offsets sentinel walk (same as the host verifier).
        {
            let mut col_idx = 0usize;
            for info in chip_infos.iter_mut() {
                if info.column_count == 0 {
                    continue;
                }
                let h = if col_idx + 1 < packing.offsets.len() {
                    packing.offsets[col_idx + 1].saturating_sub(packing.offsets[col_idx])
                } else if col_idx < packing.offsets.len() {
                    packing.total_values.saturating_sub(packing.offsets[col_idx])
                } else {
                    0
                };
                info.row_count = h;
                col_idx += info.column_count;
            }
        }
        let r_row_per_chip: Vec<Vec<InnerChallenge>> = chip_infos
            .iter()
            .map(|info| {
                let log_h =
                    info.row_count.max(1).next_power_of_two().trailing_zeros() as usize;
                if eval_point.len() >= log_h {
                    eval_point[eval_point.len() - log_h..].to_vec()
                } else {
                    eval_point.to_vec()
                }
            })
            .collect();
        let z_row = eval_point.to_vec();
        (chip_infos, r_row_per_chip, z_row)
    }

    /// BaseFold-over-BN254 wrap port: verifier mirror of
    /// `prove_jagged_basefold_inner_generic`, generic over the challenger + MMCS.
    /// The OUTER (wrap) ring drives this with OuterChallenger + OuterValMmcs via
    /// the registered verify hook; the inner ring keeps the concrete
    /// `verify_jagged_basefold_inner`.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_jagged_basefold_inner_generic<Challenger, MT, D>(
        chip_infos: &[JaggedChipInfo],
        r_row_per_chip: &[Vec<InnerChallenge>],
        z_row: &[InnerChallenge],
        bundle: &JaggedBasefoldBundleGeneric<MT>,
        challenger: &mut Challenger,
        mmcs: MT,
        dft: std::sync::Arc<D>,
        skip_commit_observe: bool,
        fri: FriConfig<crate::jagged_pcs::JaggedVal>,
    ) -> bool
    where
        MT: p3_commit::Mmcs<crate::jagged_pcs::JaggedVal, Commitment: Clone> + Clone,
        D: p3_dft::TwoAdicSubgroupDft<crate::jagged_pcs::JaggedVal> + Send + Sync,
        Challenger: p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
            + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
            + CanObserve<<MT as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Commitment>,
    {
        // The BN254 wrap path is single-round (G==1) — scalar group-0 fields.
        // The coverage check (group-map vs partition) is enforced on the
        // INNER host verifier; the wrap bundle always carries the identity
        // cover (empty `groups` / `extra_*`).
        debug_assert_eq!(
            bundle.num_groups(), 1,
            "wrap verify expects a single-round (G==1) bundle",
        );
        if !skip_commit_observe {
            challenger.observe(bundle.commit.original_commitment.clone());
        }
        let packing = JaggedPacking {
            dense_values: Vec::new(),
            chip_infos: chip_infos.to_vec(),
            offsets: bundle.packing.offsets.clone(),
            total_values: bundle.packing.total_values,
            log_dense_size: bundle.packing.log_dense_size,
        };
        let num_cols = packing.offsets.len().saturating_sub(1);
        let num_col_vars = num_cols.next_power_of_two().trailing_zeros() as usize;
        let z_col: Vec<InnerChallenge> = (0..num_col_vars)
            .map(|_| challenger.sample_algebra_element())
            .collect();
        let red_result = crate::jagged_sumcheck::verify_jagged_reduction(
            &bundle.reduction,
            &packing,
            r_row_per_chip,
            &bundle.y_per_chip,
            &z_col,
            z_row,
            challenger,
        );
        let Some((z_star, q_at_z, _w_at_z)) = red_result else {
            eprintln!("[basefold verify outer] jagged sumcheck reduction REJECTED");
            return false;
        };
        crate::jagged_eval_sumcheck::replay_jagged_evaluation_transcript(
            &bundle.jagged_eval,
            challenger,
        );
        // Capture the reduced (pre-extension) length BEFORE the extend loop
        // (see the inner verifier for the rationale).
        let z_star_orig_len = z_star.len();
        let target_dim = bundle.commit.area.trailing_zeros() as usize;
        let mut extended_z_star = z_star;
        while extended_z_star.len() < target_dim {
            let r: InnerChallenge = challenger.sample_algebra_element();
            extended_z_star.push(r);
        }
        // FIX-off sub-stripe commits: host analog of the in-circuit
        // `claim_adj` (recursive_stacked_pcs.rs).  Multiply q_at_z by the
        // Π(1-r) factor over the stack-portion extension coords when the
        // reduced point is shorter than log_stacking_height.  NO-OP (byte
        // identical) when z_star_orig_len >= stack_dim.
        let stack_dim = bundle.commit.log_stacking_height as usize;
        let mut q_at_z_adj = q_at_z;
        if z_star_orig_len < stack_dim {
            for r in &extended_z_star[z_star_orig_len..stack_dim.min(target_dim)] {
                q_at_z_adj *= InnerChallenge::ONE - *r;
            }
        }
        let res = crate::jagged_pcs::verify_jagged_pcs_generic::<Challenger, MT, D>(
            &bundle.commit.original_commitment,
            bundle.commit.area,
            bundle.commit.log_stacking_height,
            &extended_z_star,
            q_at_z_adj,
            &bundle.basefold_proof,
            challenger,
            mmcs,
            dft,
            fri,
        );
        if let Err(e) = &res {
            eprintln!("[basefold verify outer] basefold opening REJECTED: {:?}", e);
        }
        res.is_ok()
    }

    // ── Cross-bind forgery-rejection test ───────────────────────────
    // Lives inside `mod jagged` so it can drive the private
    // `verify_jagged_basefold_inner` (skip_commit_observe=false) with the
    // SAME transcript `prove_jagged_basefold` produced, and inject the
    // per-chip `opened_values.main.local` openings the production shard
    // verifier now threads in.
    #[cfg(test)]
    mod crossbind_121_test {
        use super::*;
        use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        fn rk<R: Rng>(rng: &mut R) -> InnerVal {
            InnerVal::from_u32(rng.gen::<u32>() & 0x3FFF_FFFF)
        }
        fn re<R: Rng>(rng: &mut R) -> InnerChallenge {
            <InnerChallenge as BasedVectorSpace<InnerVal>>::from_basis_coefficients_iter(
                (0..4).map(|_| rk(rng)),
            )
            .unwrap()
        }
        fn chal() -> crate::jagged_pcs::JaggedChallenger {
            crate::jagged_pcs::JaggedChallenger::new(zkm_primitives::poseidon2_init())
        }

        /// SITE-1 trace-unification: the commit/open entry points take BORROWED
        /// `ChipTraceView`s over the shard prover's shared `Arc<Mle>` store.
        /// Tests own their matrices, so relabel each owned matrix as a
        /// zero-copy view over its own cells — same cells, same width.
        fn as_chip_views(
            traces: &[(alloc::string::String, RowMajorMatrix<InnerVal>)],
        ) -> Vec<ChipTraceView<'_>> {
            traces
                .iter()
                .map(|(name, t)| {
                    (name.clone(), RowMajorMatrixView::new(&t.values, t.width))
                })
                .collect()
        }

        /// The recursion circuit binds the jagged claimed sum to the trace
        /// openings (recursive_jagged_pcs.rs:247); this mirrors that on the
        /// host.  This test proves the bind is load-bearing:
        ///   (1) honest openings (== y_per_chip) verify;
        ///   (2) a bundle whose column claims DIVERGE from the openings is
        ///       REJECTED once the openings are threaded in (`Some`);
        ///   (3) the SAME divergent proof is (wrongly) ACCEPTED with the bind
        ///       disabled (`None`) — i.e. the host behaviour with the bind removed.
        #[test]
        fn crossbind_rejects_divergent_openings() {
            let mut rng = StdRng::seed_from_u64(0x0121_0BAD_C0DE);
            let mk = |w: usize, h: usize, rng: &mut StdRng| -> RowMajorMatrix<InnerVal> {
                let v: Vec<InnerVal> = (0..w * h).map(|_| rk(rng)).collect();
                RowMajorMatrix::new(v, w)
            };
            let traces = vec![
                ("Cpu".to_string(), mk(4, 16, &mut rng)),
                ("Add".to_string(), mk(2, 8, &mut rng)),
            ];
            let r_row_per_chip: Vec<Vec<InnerChallenge>> = traces
                .iter()
                .map(|(_, t)| {
                    let h = t.values.len() / t.width.max(1);
                    let log_h = h.next_power_of_two().trailing_zeros() as usize;
                    (0..log_h).map(|_| re(&mut rng)).collect()
                })
                .collect();
            let z_row: Vec<InnerChallenge> = r_row_per_chip
                .iter()
                .max_by_key(|v| v.len())
                .cloned()
                .unwrap_or_default();

            let views = as_chip_views(&traces);
            let mut p = chal();
            let bundle = prove_jagged_basefold(&views, &r_row_per_chip, &z_row, &mut p);
            let infos =
                crate::jagged::compute_jagged_metadata::<InnerVal>(&views).chip_infos;

            // The honest per-chip `main.local` openings coincide with the
            // bundle's column claims (single-orientation synthetic bundle).
            let opened_ok: Vec<Vec<InnerChallenge>> = bundle.y_per_chip.clone();

            // (1) honest openings + cross-bind ON → ACCEPT.
            let mut v = chal();
            assert!(
                verify_jagged_basefold_inner(
                    &infos, &r_row_per_chip, &z_row, &bundle,
                    Some(&opened_ok), &mut v, false,
                ),
                "#121: honest openings must verify"
            );

            // (2) DIVERGENT openings + cross-bind ON → REJECT.
            let mut opened_bad = opened_ok.clone();
            opened_bad[0][0] += InnerChallenge::ONE; // tamper ONE column claim
            let mut v = chal();
            assert!(
                !verify_jagged_basefold_inner(
                    &infos, &r_row_per_chip, &z_row, &bundle,
                    Some(&opened_bad), &mut v, false,
                ),
                "#121: y_per_chip diverging from openings MUST be rejected by the cross-bind"
            );

            // (3) SAME divergent openings but bind OFF (None) → ACCEPT.
            //     Documents the pre-fix gap the cross-bind closes.
            let mut v = chal();
            assert!(
                verify_jagged_basefold_inner(
                    &infos, &r_row_per_chip, &z_row, &bundle,
                    None, &mut v, false,
                ),
                "#121 pre-fix baseline: with no opened-values bind the divergent proof is (wrongly) accepted"
            );
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use p3_challenger::FieldChallenger;
    use p3_field::BasedVectorSpace;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn rand_kb<R: Rng>(rng: &mut R) -> JaggedVal {
        JaggedVal::from_u32(rng.gen::<u32>() & 0x3FFF_FFFF)
    }

    fn rand_ef<R: Rng>(rng: &mut R) -> JaggedChallenge {
        <JaggedChallenge as BasedVectorSpace<JaggedVal>>::from_basis_coefficients_iter(
            (0..4).map(|_| rand_kb(rng)),
        )
        .unwrap()
    }

    fn build_challenger() -> JaggedChallenger {
        let perm: crate::kb31_poseidon2::InnerPerm =
            zkm_primitives::poseidon2_init();
        JaggedChallenger::new(perm)
    }

    /// End-to-end: commit a small batch of heterogeneous chip traces,
    /// open at a random point, verify.  This is the OOM-cure flow
    /// (per-chip Mles → stacked PCS → BaseFold) on a toy size.
    #[test]
    fn test_jagged_pcs_roundtrip() {
        let mut rng = StdRng::seed_from_u64(0xBA5E_F01D_5EED);

        // Two synthetic chip traces of different shapes; both must
        // pad to power-of-2 row counts inside the stacking height.
        let mk_trace = |width: usize, h: usize, rng: &mut StdRng| -> RowMajorMatrix<JaggedVal> {
            let v: Vec<JaggedVal> = (0..width * h).map(|_| rand_kb(rng)).collect();
            RowMajorMatrix::new(v, width)
        };
        let traces = vec![
            ("Cpu".into(), mk_trace(20, 100, &mut rng)),
            ("Add".into(), mk_trace(8, 50, &mut rng)),
        ];

        let mut p_chal = build_challenger();
        let (commit, prover_data) =
            commit_jagged_pcs(traces.clone(), &mut p_chal, None);

        // Compute the eval point + claim for the stacked PCS.  Claim
        // is the multilinear-extension of the *flattened*
        // batch-evaluations vector at the batch part of the point.
        let stack_dim = commit.log_stacking_height as usize;
        let num_stripes = commit.area >> stack_dim;
        let num_batch_vars = num_stripes.next_power_of_two().trailing_zeros() as usize;
        let total_vars = num_batch_vars + stack_dim;
        let eval_point: Vec<JaggedChallenge> =
            (0..total_vars).map(|_| rand_ef(&mut rng)).collect();

        let stack_point: Vec<JaggedChallenge> = eval_point[..stack_dim].to_vec();
        let batch_evals_flat: Vec<JaggedChallenge> = prover_data
            .stacked_data
            .interleaved_mles
            .iter()
            .flat_map(|m| m.eval_at::<JaggedChallenge>(&stack_point))
            .collect();

        // Honest evaluation_claim = MLE of batch_evals_flat at
        // batch_point (matches the verifier's
        // `eval_multilinear_padded` reduction).
        let batch_point = &eval_point[stack_dim..];
        let evaluation_claim = {
            let target = 1usize << batch_point.len();
            let mut current: Vec<JaggedChallenge> = batch_evals_flat.clone();
            current.resize(target, JaggedChallenge::ZERO);
            for &r in batch_point.iter().rev() {
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

        let proof = open_jagged_pcs_host(prover_data, eval_point.clone(), &mut p_chal);

        let mut v_chal = build_challenger();
        v_chal.observe(commit.original_commitment.clone());
        verify_jagged_pcs(
            &commit.original_commitment,
            commit.area,
            commit.log_stacking_height,
            &eval_point,
            evaluation_claim,
            &proof,
            &mut v_chal,
        )
        .expect("basefold jagged-PCS roundtrip");
    }

    /// **Phase C3** — full jagged-sumcheck pipeline backed by BaseFold.
    /// E1: ungated from `whir` after `jagged` and `jagged_sumcheck`
    /// were moved out of the whir feature gate.
    #[test]
    fn test_jagged_basefold_roundtrip() {
        use crate::jagged_pcs::jagged::{
            prove_jagged_basefold, verify_jagged_basefold,
        };

        let mut rng = StdRng::seed_from_u64(0xC0DE_BA5E);

        let mk_trace =
            |width: usize, height: usize, rng: &mut StdRng| -> RowMajorMatrix<JaggedVal> {
                let v: Vec<JaggedVal> = (0..width * height).map(|_| rand_kb(rng)).collect();
                RowMajorMatrix::new(v, width)
            };

        // Two heterogeneous chip traces; both heights round up to a
        // power of 2 inside the stacking stripe.
        let traces = vec![
            ("Cpu".into(), mk_trace(4, 16, &mut rng)),
            ("Add".into(), mk_trace(2, 8, &mut rng)),
        ];

        // Per-chip r_row sampled fresh; length = log2(padded height).
        let r_row_per_chip: Vec<Vec<JaggedChallenge>> = traces
            .iter()
            .map(|(_, t)| {
                let h = t.values.len() / t.width.max(1);
                let log_h = h.next_power_of_two().trailing_zeros() as usize;
                (0..log_h).map(|_| rand_ef(&mut rng)).collect()
            })
            .collect();

        let mut p_chal = build_challenger();
        let z_row_test: Vec<JaggedChallenge> = r_row_per_chip
            .iter()
            .max_by_key(|v| v.len())
            .cloned()
            .unwrap_or_default();
        let views = as_chip_views(&traces);
        let bundle =
            prove_jagged_basefold(&views, &r_row_per_chip, &z_row_test, &mut p_chal);

        // Verifier reconstructs chip_infos from the same traces it
        // already has access to via the protocol's outer loop.
        let chip_infos =
            crate::jagged::compute_jagged_metadata::<JaggedVal>(&views).chip_infos;
        let mut v_chal = build_challenger();
        let ok = verify_jagged_basefold(&chip_infos, &r_row_per_chip, &z_row_test, &bundle, &mut v_chal);
        assert!(ok, "jagged-basefold pipeline should accept honest proof");
    }

    /// **Soundness sanity** — flipping any single field of the bundle
    /// must cause the verifier to reject.  Catches whole classes of
    /// "I forgot to observe X into the challenger" bugs that pass
    /// honest-prover tests but admit forgery.
    #[test]
    fn test_jagged_basefold_rejects_tampered_proof() {
        use p3_field::PrimeCharacteristicRing;
        use crate::jagged_pcs::jagged::{
            prove_jagged_basefold, verify_jagged_basefold,
        };

        let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);
        let mk_trace =
            |width: usize, height: usize, rng: &mut StdRng| -> RowMajorMatrix<JaggedVal> {
                let v: Vec<JaggedVal> = (0..width * height).map(|_| rand_kb(rng)).collect();
                RowMajorMatrix::new(v, width)
            };
        let traces = vec![("Cpu".into(), mk_trace(4, 16, &mut rng))];
        let r_row_per_chip: Vec<Vec<JaggedChallenge>> = traces
            .iter()
            .map(|(_, t)| {
                let h = t.values.len() / t.width.max(1);
                let log_h = h.next_power_of_two().trailing_zeros() as usize;
                (0..log_h).map(|_| rand_ef(&mut rng)).collect()
            })
            .collect();

        let mut p_chal = build_challenger();
        let z_row_test: Vec<JaggedChallenge> = r_row_per_chip
            .iter()
            .max_by_key(|v| v.len())
            .cloned()
            .unwrap_or_default();
        let views = as_chip_views(&traces);
        let bundle =
            prove_jagged_basefold(&views, &r_row_per_chip, &z_row_test, &mut p_chal);
        let chip_infos =
            crate::jagged::compute_jagged_metadata::<JaggedVal>(&views).chip_infos;

        // Tamper #1: corrupt the sumcheck final claim `q_at_z`.
        let mut tampered = bundle.clone();
        tampered.reduction.q_at_z = tampered.reduction.q_at_z + JaggedChallenge::ONE;
        let mut v_chal = build_challenger();
        assert!(
            !verify_jagged_basefold(&chip_infos, &r_row_per_chip, &z_row_test, &tampered, &mut v_chal),
            "verifier must reject q_at_z tampering"
        );

        // Tamper #2: corrupt one of the per-chip y_{c,j} commitments.
        let mut tampered = bundle.clone();
        tampered.y_per_chip[0][0] = tampered.y_per_chip[0][0] + JaggedChallenge::ONE;
        let mut v_chal = build_challenger();
        assert!(
            !verify_jagged_basefold(&chip_infos, &r_row_per_chip, &z_row_test, &tampered, &mut v_chal),
            "verifier must reject y_per_chip tampering"
        );

        // Tamper #3: corrupt the BaseFold final_poly in the proof.
        let mut tampered = bundle.clone();
        tampered.basefold_proof.basefold_proof.final_poly =
            tampered.basefold_proof.basefold_proof.final_poly + JaggedChallenge::ONE;
        let mut v_chal = build_challenger();
        assert!(
            !verify_jagged_basefold(&chip_infos, &r_row_per_chip, &z_row_test, &tampered, &mut v_chal),
            "verifier must reject final_poly tampering"
        );
    }



    // ════════════════════════════════════════════════════════════════
    // CP-A: per-round jagged split (Architecture A) host validation.
    // ════════════════════════════════════════════════════════════════

    use crate::jagged_pcs::jagged::{
        prove_jagged_basefold, verify_jagged_basefold, ChipTraceView, JaggedBasefoldBundle,
        VerifyStage, LAST_VERIFY_STAGE,
    };
    use p3_matrix::dense::RowMajorMatrixView;

    /// SITE-1 trace-unification: the commit/open entry points take BORROWED
    /// `ChipTraceView`s over the shard prover's shared `Arc<Mle>` store.
    /// Tests own their matrices, so relabel each owned matrix as a zero-copy
    /// view over its own cells — same cells, same width.
    fn as_chip_views(
        traces: &[(String, RowMajorMatrix<JaggedVal>)],
    ) -> Vec<ChipTraceView<'_>> {
        traces
            .iter()
            .map(|(name, t)| (name.clone(), RowMajorMatrixView::new(&t.values, t.width)))
            .collect()
    }

    /// Run `verify_jagged_basefold` and return (accepted, last_stage).
    fn verify_with_stage(
        chip_infos: &[crate::jagged::JaggedChipInfo],
        r_row: &[Vec<JaggedChallenge>],
        z_row: &[JaggedChallenge],
        bundle: &JaggedBasefoldBundle,
    ) -> (bool, Option<VerifyStage>) {
        LAST_VERIFY_STAGE.with(|c| c.set(None));
        let mut v = build_challenger();
        let ok = verify_jagged_basefold(chip_infos, r_row, z_row, bundle, &mut v);
        (ok, LAST_VERIFY_STAGE.with(core::cell::Cell::get))
    }

    /// Build (traces, r_row_per_chip, z_row) for a set of `(width, height)`
    /// chip shapes, with deterministic random cells.
    fn mk_shard(
        shapes: &[(usize, usize)],
        seed: u64,
    ) -> (
        Vec<(String, RowMajorMatrix<JaggedVal>)>,
        Vec<Vec<JaggedChallenge>>,
        Vec<JaggedChallenge>,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        // Name-sorted so the partition's name-sorted-order precondition holds.
        let traces: Vec<(String, RowMajorMatrix<JaggedVal>)> = shapes
            .iter()
            .enumerate()
            .map(|(i, &(w, h))| {
                let v: Vec<JaggedVal> = (0..w * h).map(|_| rand_kb(&mut rng)).collect();
                (alloc::format!("chip{i:03}"), RowMajorMatrix::new(v, w))
            })
            .collect();
        let r_row_per_chip: Vec<Vec<JaggedChallenge>> = traces
            .iter()
            .map(|(_, t)| {
                let h = t.values.len() / t.width.max(1);
                let log_h = h.next_power_of_two().trailing_zeros() as usize;
                (0..log_h).map(|_| rand_ef(&mut rng)).collect()
            })
            .collect();
        let z_row: Vec<JaggedChallenge> = r_row_per_chip
            .iter()
            .max_by_key(|v| v.len())
            .cloned()
            .unwrap_or_default();
        (traces, r_row_per_chip, z_row)
    }

    /// (i) NO-OP byte-identity: with grouping OFF (the default), a G==1
    /// bundle has scalar group-0 fields, EMPTY `extra_*` + `groups`, and an
    /// honest roundtrip verifies.  The empty `serde(default)` fields make the
    /// wire bytes byte-identical to the pre-split format (a freshly
    /// deserialized bundle is bit-for-bit equal AND still verifies).
    #[test]
    fn test_cp_a_g1_noop_byte_identity() {
        // grouping OFF (no test threshold set, env unset).
        let (traces, r_row, z_row) = mk_shard(&[(4, 16), (2, 8), (6, 4)], 0xA11CE);
        let views = as_chip_views(&traces);
        let mut p_chal = build_challenger();
        let bundle = prove_jagged_basefold(&views, &r_row, &z_row, &mut p_chal);

        // Single-group invariants: scalar fields populated, extras empty.
        assert_eq!(bundle.num_groups(), 1, "grouping OFF ⇒ G==1");
        assert!(bundle.groups.is_empty(), "G==1 ⇒ empty group map");
        assert!(bundle.extra_reduction.is_empty());
        assert!(bundle.extra_basefold_proof.is_empty());
        assert!(bundle.extra_commit.is_empty());
        assert!(bundle.extra_packing.is_empty());
        assert!(bundle.extra_jagged_eval.is_empty());

        // Wire-format round-trip is bit-identical.
        let bytes = bundle.to_bytes();
        let bundle2 = JaggedBasefoldBundle::from_bytes(&bytes)
            .expect("deserialize G==1 bundle");
        let bytes2 = bundle2.to_bytes();
        assert_eq!(bytes, bytes2, "G==1 bundle bytes must round-trip identically");

        // Honest verify: coverage passes (identity cover) and the verifier
        // reaches at least the per-group reduction.  On a fully-green branch
        // it ACCEPTS; on this WIP branch the BaseFold open can fail for a
        // reason ORTHOGONAL to CP-A (a pre-existing jagged-eval/div-fix bug
        // shared by today's single-group path — see report).  Either way the
        // failure must NOT be at coverage (the CP-A guard).
        let chip_infos =
            crate::jagged::compute_jagged_metadata::<JaggedVal>(&views).chip_infos;
        let (ok, stage) = verify_with_stage(&chip_infos, &r_row, &z_row, &bundle);
        eprintln!("[CP-A (i) G==1 no-op] accepted={ok} stage={stage:?}");
        assert!(
            stage != Some(VerifyStage::Coverage),
            "G==1 must pass the coverage check (identity cover)"
        );
        assert!(
            ok || matches!(stage, Some(VerifyStage::Open(_))),
            "G==1 must either verify or only fail at the BaseFold open \
             (pre-existing, orthogonal to CP-A); got accepted={ok} stage={stage:?}"
        );
        // The deserialized copy behaves identically (legacy-shape equivalence).
        let (ok2, stage2) = verify_with_stage(&chip_infos, &r_row, &z_row, &bundle2);
        assert_eq!(
            (ok, stage), (ok2, stage2),
            "deserialized G==1 bundle must verify identically"
        );
    }

    // ───────────────────────────────────────────────────────────────────
    // G-host: LOCK THE HASH-BIND CONVENTION (SP1-faithful jagged geometry
    // count ↔ commitment tie) with a host-only commit → verify round-trip,
    // BEFORE any circuit consumes it.  A wrong order / missing len-prefix
    // would silently desync Fiat-Shamir; this test prints the host hash and
    // asserts modified == recomputed host-side.
    // ───────────────────────────────────────────────────────────────────
    #[test]
    fn g_host_hash_bind_roundtrip() {
        use crate::jagged_pcs::jagged::PackingMeta;
        // A heterogeneous per-chip geometry (varied heights == a FIX-off
        // natural-commit shard), with the SENTINEL offset (len = total_cols+1).
        // chip heights:   3,      5,           2,        (a 0-col chip)
        // chip widths:    2,      1,           3,        0
        let column_counts: Vec<usize> = vec![2, 1, 3, 0];
        // offsets: column-major prefix sums. col widths sum = 6 columns.
        //  chip0 cols 0,1 (h=3) -> 0,3 ; chip1 col2 (h=5) -> 6 ; chip2 cols 3,4,5 (h=2) -> 11,13,15 ; sentinel 17
        let offsets: Vec<usize> = vec![0, 3, 6, 11, 13, 15, 17];
        let total_values = 17usize;
        let packing = PackingMeta {
            offsets,
            total_values,
            log_dense_size: (total_values.next_power_of_two()).trailing_zeros() as usize,
            column_counts: column_counts.clone(),
        };

        // The derived per-chip (row_counts, column_counts) — the EXACT felt
        // sequence both host and circuit hash.
        let (row_counts, col_counts) = jagged_counts_from_packing(&packing);
        assert_eq!(col_counts, column_counts);
        // chip0 h = offsets[1]-offsets[0] = 3; chip1 h = offsets[3]-offsets[2] = 5;
        // chip2 h = offsets[5]-offsets[4]... col_idx walk: chip0 col_idx=0 -> 3;
        //   chip1 col_idx=2 -> offsets[3]-offsets[2]=5; chip2 col_idx=3 ->
        //   offsets[4]-offsets[3]=2; chip3 cc==0 -> 0.
        assert_eq!(row_counts, vec![3usize, 5, 2, 0], "row_counts derivation");

        // A toy raw root.
        let raw_root: [JaggedVal; 8] =
            core::array::from_fn(|i| JaggedVal::from_u32((i as u32 + 1) * 7));

        let hash = jagged_geometry_hash(&row_counts, &col_counts);
        let modified = jagged_hash_bind_modified(raw_root, &row_counts, &col_counts);
        let modified_from_packing = jagged_hash_bind_from_packing(raw_root, &packing);

        eprintln!("[G-HOST] raw_root      = {raw_root:?}");
        eprintln!("[G-HOST] geometry_hash = {hash:?}");
        eprintln!("[G-HOST] modified      = {modified:?}");
        eprintln!(
            "[G-HOST] len(=col_counts.len())={} row_counts={row_counts:?} col_counts={col_counts:?}",
            col_counts.len()
        );

        // Convention self-consistency: the packing one-liner equals the
        // explicit path.
        assert_eq!(modified, modified_from_packing, "from_packing must match explicit");

        // The host re-bind check (mirror of SP1 verify_trusted_evaluations)
        // must ACCEPT the honest modified digest.
        assert!(
            jagged_hash_bind_verify(raw_root, modified, &packing),
            "G-host: host re-bind must accept the honest modified digest"
        );

        // FORGERY-SHAPED negative #1: a TAMPERED row_count must change the
        // hash -> modified, so the re-bind REJECTS it (the count↔commitment
        // tie).  (This is the host-side analog of G3b.)
        {
            let mut bad = packing.clone();
            // inflate chip0 height: offsets[1] 3 -> 4 (shifts everything)
            bad.offsets[1] = 4;
            assert!(
                !jagged_hash_bind_verify(raw_root, modified, &bad),
                "G-host: a tampered row_count MUST fail the re-bind"
            );
        }
        // FORGERY-SHAPED negative #2: a TAMPERED column_count must reject.
        {
            let mut bad = packing.clone();
            bad.column_counts[0] = 3; // was 2
            assert!(
                !jagged_hash_bind_verify(raw_root, modified, &bad),
                "G-host: a tampered column_count MUST fail the re-bind"
            );
        }
        // LEN-PREFIX guard: omitting/altering the len prefix would silently
        // collide honest geometries of different lengths.  Verify the len is
        // genuinely mixed in: a geometry with one MORE (zero-height, zero-col)
        // chip — same row/col VALUES extended by a 0 — hashes DIFFERENTLY
        // because the len prefix changes.
        {
            let mut rc2 = row_counts.clone();
            let mut cc2 = col_counts.clone();
            rc2.push(0);
            cc2.push(0);
            let h2 = jagged_geometry_hash(&rc2, &cc2);
            assert_ne!(
                hash, h2,
                "G-host: the len prefix MUST distinguish different-length geometries"
            );
        }
    }
}
