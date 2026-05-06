//! Per-chip BaseFold late-binding adapter.
//!
//! Replaces [`crate::whir_late_binding`] / [`crate::jagged_late_binding`]
//! for the OOM-blocker chip-trace commit step.  The structural win:
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

#![cfg(feature = "basefold")]

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

pub type LbVal = crate::kb31_poseidon2::InnerVal;
pub type LbChallenge = InnerChallenge;
pub type LbDft = Radix2DitParallel<LbVal>;
pub type LbMmcs = InnerValMmcs;
pub type LbChallenger = InnerChallenger;

/// One committed batch of chip traces, plus the per-chip metadata
/// needed to recompute evaluation points on the verifier side.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct BasefoldLateBindingCommit {
    pub commitment: <LbMmcs as p3_commit::Mmcs<LbVal>>::Commitment,
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

pub struct BasefoldLateBindingProverData {
    pub stacked_data: StackedBasefoldProverData<LbVal, LbMmcs>,
    pub chip_dims: Vec<(usize, u32)>,
    pub area: usize,
    pub log_stacking_height: u32,
}

/// Defaults chosen to match the perf-results sweet spot:
/// `log_stacking_height=14` → 16K rows per stripe, well below the
/// 131K shard-split cliff that worked for tendermint at 51.7 GB.
/// Small commits (under 16K total entries) clamp this down so the
/// stacked PCS doesn't end up over-padding past the actual data.
pub const DEFAULT_LOG_STACKING_HEIGHT: u32 = 14;

/// Interleave batch size for the stacked PCS: number of MLE-column
/// streams packed into each stripe.  **`32`** matches SP1's
/// `slop_jagged::basefold::DEFAULT_INTERLEAVE_BATCH_SIZE`
/// (raised from `16`).  Halves the number of stripes per BaseFold
/// commit, which directly halves the Merkle-commit count and the
/// per-stripe DFT count without increasing per-stripe LDE memory.
/// SP1-parity; no soundness implication (purely a packing constant).
pub const DEFAULT_BATCH_SIZE: usize = 32;

/// Choose the largest `log_stacking_height ≤ DEFAULT` that still
/// leaves at least one batch_point variable.  Required for tiny
/// commits where total entries < `1 << DEFAULT_LOG_STACKING_HEIGHT`.
pub fn pick_log_stacking_height(total_entries: usize) -> u32 {
    let log_total = total_entries.next_power_of_two().trailing_zeros();
    // Reserve at least 1 var for the batching point (= 2 stripes
    // minimum).  If the data is so small that even one stripe covers
    // everything, we still need that extra var so the stacked PCS
    // verifier's `point.len() ≥ log_stacking_height` invariant holds.
    let max_for_data = log_total.saturating_sub(1).max(1);
    DEFAULT_LOG_STACKING_HEIGHT.min(max_for_data)
}

fn build_pcs(
    log_stacking_height: u32,
) -> (
    StackedPcsProver<LbVal, LbChallenge, LbMmcs, LbDft>,
    StackedPcsVerifier<LbVal, LbChallenge, LbMmcs>,
    LbMmcs,
) {
    let perm: crate::kb31_poseidon2::InnerPerm =
        zkm_primitives::poseidon2_init();
    let hash = crate::kb31_poseidon2::InnerHash::new(perm.clone());
    let compress = crate::kb31_poseidon2::InnerCompress::new(perm);
    let mmcs = LbMmcs::new(hash, compress, 0);

    // Route through `from_env_or_default` so `ZIREN_BASEFOLD_LOG_BLOWUP`
    // can override the rate for memory-measurement runs (see
    // `FriConfig::from_env_or_default`).
    let fri = FriConfig::<LbVal>::from_env_or_default();
    let dft = Arc::new(LbDft::default());

    let basefold_prover = BasefoldProver::<LbVal, LbChallenge, _, _>::new(
        fri.clone(),
        dft,
        mmcs.clone(),
        1, // num_expected_commitments — one round per shard
    );
    let basefold_verifier =
        BasefoldVerifier::<LbVal, LbChallenge, _>::new(fri, mmcs.clone(), 1);

    let prover = StackedPcsProver::new(
        basefold_prover,
        log_stacking_height,
        DEFAULT_BATCH_SIZE,
    );
    let verifier = StackedPcsVerifier::new(basefold_verifier, log_stacking_height);

    (prover, verifier, mmcs)
}

/// Convert chip traces into per-chip `Mle<LbVal>`s, padding each
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
    chip_traces: &[(String, RowMajorMatrix<LbVal>)],
) -> (Vec<Arc<Mle<LbVal>>>, Vec<(usize, u32)>) {
    let mut mles = Vec::with_capacity(chip_traces.len());
    let mut dims = Vec::with_capacity(chip_traces.len());
    for (_, trace) in chip_traces {
        let width = trace.width.max(1);
        let raw_height = trace.values.len() / width;
        let padded_height = raw_height.next_power_of_two();
        let log_h = padded_height.trailing_zeros();

        let mut padded = trace.values.clone();
        padded.resize(padded_height * width, LbVal::ZERO);

        mles.push(Arc::new(Mle::new(RowMajorMatrix::new(padded, width))));
        dims.push((width, log_h));
    }
    (mles, dims)
}

/// Public for the GPU dispatch hook (#76 / D2 — C-full E2): the
/// device-side commit path needs to run the same MLE-construction +
/// padding logic as the host before invoking the GPU encoder.
pub fn chips_to_mles_owned(
    chip_traces: Vec<(String, RowMajorMatrix<LbVal>)>,
) -> (Vec<Arc<Mle<LbVal>>>, Vec<(usize, u32)>) {
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
            padded.resize(padded_height * width, LbVal::ZERO);
            padded
        };

        mles.push(Arc::new(Mle::new(RowMajorMatrix::new(values, width))));
        dims.push((width, log_h));
    }
    (mles, dims)
}

/// Commit a batch of chip traces (consumes ownership — saves the
/// `trace.values.clone()` round-trip in `chips_to_mles_owned`).
/// Returns a public commitment (observed by the challenger as a
/// side effect) and prover-side state for later opening.
///
/// **#76 / D2 (C-full C4 plan §5)** — when `ZIREN_GPU_BASEFOLD=1` is
/// set AND ziren-gpu has registered the device commit hook (via
/// [`register_gpu_basefold_commit_hook`]), the commit dispatches
/// through `FriCudaProver::encode_and_commit` + `CudaTcsProver` on
/// device.  Output `(commit, prover_data)` must be byte-identical to
/// the host path (the device hook host-side observes the same digest
/// into the same `LbChallenger`).  Falls through to the host
/// implementation on any of: env unset, hook unregistered, hook
/// returns `Err` (shape unsupported / device error).
pub fn commit_basefold_late_binding(
    chip_traces: Vec<(String, RowMajorMatrix<LbVal>)>,
    challenger: &mut LbChallenger,
) -> (BasefoldLateBindingCommit, BasefoldLateBindingProverData) {
    if std::env::var("ZIREN_GPU_BASEFOLD").map(|v| v == "1").unwrap_or(false) {
        if let Some(hook) = get_gpu_basefold_commit_hook() {
            // The hook signature returns `Result` so the device side
            // can tunnel its host-input back to us on shape-unsupported
            // / runtime errors (we then run the host path with the
            // returned input — no double-allocation, no challenger
            // double-observe).
            use std::sync::OnceLock;
            static FIRED_ONCE: OnceLock<()> = OnceLock::new();
            static FELLBACK_ONCE: OnceLock<()> = OnceLock::new();
            match hook(chip_traces, challenger) {
                Ok(out) => {
                    FIRED_ONCE.get_or_init(|| {
                        tracing::warn!(
                            "GPU BaseFold commit FIRED \
                             (#76/D2 ZIREN_GPU_BASEFOLD=1, gpu_hook dispatched, \
                             area={}, log_stacking_height={})",
                            out.0.area, out.0.log_stacking_height,
                        );
                    });
                    return out;
                }
                Err(returned_traces) => {
                    FELLBACK_ONCE.get_or_init(|| {
                        tracing::warn!(
                            "GPU BaseFold commit hook returned Err — falling \
                             back to host commit_basefold_late_binding. The \
                             device side could not handle this shape; the \
                             host commit is the source of truth."
                        );
                    });
                    return commit_basefold_late_binding_host(returned_traces, challenger);
                }
            }
        } else {
            use std::sync::OnceLock;
            static WARN_ONCE: OnceLock<()> = OnceLock::new();
            WARN_ONCE.get_or_init(|| {
                tracing::warn!(
                    "ZIREN_GPU_BASEFOLD=1 set but no GPU commit hook \
                     registered; ziren-gpu's compress_multi_gpu must call \
                     register_gpu_basefold_commit_hook at startup. \
                     Falling back to host BaseFold commit. See #76/D2."
                );
            });
        }
    }
    commit_basefold_late_binding_host(chip_traces, challenger)
}

/// Pure host-side implementation of [`commit_basefold_late_binding`]
/// — extracted so the GPU dispatch hook can fall back to it on
/// shape-unsupported / runtime errors without re-entering the env-flag
/// dispatch loop.  Always runs the CPU BaseFold + Plonky3 MMCS commit.
pub fn commit_basefold_late_binding_host(
    chip_traces: Vec<(String, RowMajorMatrix<LbVal>)>,
    challenger: &mut LbChallenger,
) -> (BasefoldLateBindingCommit, BasefoldLateBindingProverData) {
    let (mles, chip_dims) = chips_to_mles_owned(chip_traces);
    let total_entries: usize = mles.iter().map(|m| m.guts.values.len()).sum();
    let log_stacking_height = pick_log_stacking_height(total_entries);
    let area = total_entries.next_multiple_of(1usize << log_stacking_height);

    let (prover, _verifier, _mmcs) = build_pcs(log_stacking_height);
    let (commitment, stacked_data) = prover.commit_multilinears(mles);
    challenger.observe(commitment.clone());

    let commit = BasefoldLateBindingCommit {
        commitment: commitment.clone(),
        chip_dims: chip_dims.clone(),
        area,
        log_stacking_height,
    };
    let prover_data = BasefoldLateBindingProverData {
        stacked_data,
        chip_dims,
        area,
        log_stacking_height,
    };
    (commit, prover_data)
}

/// Driver shared by host + GPU dispatch: takes per-chip traces and a
/// codeword-encoder closure (host: `DftEncoder::encode_batch`; GPU:
/// `FriCudaProver::encode_and_commit` per-mle), and produces the
/// late-binding commit + prover_data.
///
/// The codeword shape supplied by the closure MUST be byte-equivalent
/// to what the host encoder produces (validated by
/// `ziren-gpu/basefold/tests/cpu_vs_gpu_commit.rs` for the GPU path).
/// The MMCS commit step itself stays on host so the returned
/// `prover_data.stacked_data.pcs_batch_data.prover_data` is shape-
/// compatible with the open path (`open_basefold_late_binding`)
/// without further changes.
///
/// Used by the GPU dispatch hook (#76 / D2 — C-full E2) to shortcut
/// the encode step onto device while keeping the MMCS-commit + open
/// path on host (option A in `/tmp/c_full_d2_followup.md`).
pub fn commit_basefold_late_binding_with_encoder<E>(
    chip_traces: Vec<(String, RowMajorMatrix<LbVal>)>,
    challenger: &mut LbChallenger,
    encoder: E,
) -> (BasefoldLateBindingCommit, BasefoldLateBindingProverData)
where
    E: FnOnce(
        &[Arc<Mle<LbVal>>],
    ) -> Vec<Arc<crate::basefold::code::RsCodeWord<LbVal>>>,
{
    let (mles, chip_dims) = chips_to_mles_owned(chip_traces);
    let total_entries: usize = mles.iter().map(|m| m.guts.values.len()).sum();
    let log_stacking_height = pick_log_stacking_height(total_entries);
    let area = total_entries.next_multiple_of(1usize << log_stacking_height);

    let (prover, _verifier, _mmcs) = build_pcs(log_stacking_height);

    // Shape-equivalent to `prover.commit_multilinears(mles)` but with
    // the encode step bypassed: the supplied closure produces the
    // per-stripe codewords (typically on device).  The MMCS commit
    // runs on host so the returned `BasefoldProverData::prover_data`
    // is the Plonky3 `MerkleTreeMmcs::ProverData` shape that the open
    // path (`open_basefold_late_binding` →
    // `prove_trusted_evaluation`) consumes — no enum variant or
    // open-path adapter required.
    let interleaved_mles = crate::basefold::stacked::interleave_multilinears_with_fixed_rate(
        DEFAULT_BATCH_SIZE,
        mles,
        log_stacking_height,
    );
    let codewords = encoder(&interleaved_mles);
    debug_assert_eq!(
        interleaved_mles.len(),
        codewords.len(),
        "encoder must return one codeword per interleaved stripe",
    );
    let (commitment, stacked_data) =
        prover.commit_multilinears_with_codewords(interleaved_mles, codewords);

    challenger.observe(commitment.clone());

    let commit = BasefoldLateBindingCommit {
        commitment: commitment.clone(),
        chip_dims: chip_dims.clone(),
        area,
        log_stacking_height,
    };
    let prover_data = BasefoldLateBindingProverData {
        stacked_data,
        chip_dims,
        area,
        log_stacking_height,
    };
    (commit, prover_data)
}

/// Production-grade FRI config used by the late-binding pipeline.
/// Public so the GPU dispatch hook can construct a matching
/// device-side encoder (same `log_blowup`, same coset shift) without
/// re-creating the env-overrides logic.
pub fn lb_fri_config() -> FriConfig<LbVal> {
    FriConfig::<LbVal>::from_env_or_default()
}

// ─────────────────────────────────────────────────────────────────────
// #76 / D2 (C-full C4 plan §5) — GPU BaseFold commit dispatch hook.
//
// Mirror of the #174 (C-full B1) jagged-PCS device-trace hook pattern
// in `crate::shard_level::sumcheck_poly::jagged_pcs_device_hook`.  The
// hook receives the same inputs as `commit_basefold_late_binding` and
// returns a byte-identical `(commit, prover_data)` — the device side
// is responsible for:
//
//   * uploading the per-chip traces to GPU memory,
//   * running `FriCudaProver::encode_and_commit` (the existing 1349
//     LOC device commit) + the SP1 `compress([root, hash([h, w])])`
//     post-processing step (C4 risk #3) so the digest matches Plonky3
//     `MerkleTreeMmcs`,
//   * observing the resulting commitment into the supplied
//     `LbChallenger` (so the transcript stays in lock-step with the
//     host path),
//   * assembling a `BasefoldLateBindingProverData` whose
//     `stacked_data.pcs_batch_data.prover_data` is shape-compatible
//     with the host `MerkleTreeMmcs::ProverData` consumed downstream by
//     `open_basefold_late_binding`.  The shape compatibility risk is
//     C4 risk #1 — until the open-path adapter lands the device hook
//     can return `Err` on un-handled shapes and we fall back to host.
//
// The hook returns `Result<.., Vec<...>>` instead of `Option<..>` so
// the device side can tunnel ownership of the host-input back to the
// host fallback on error (mirrors the `try_emit_jagged_pcs_bytes_device`
// fall-through contract in B1).
// ─────────────────────────────────────────────────────────────────────

/// Signature of the GPU BaseFold commit driver.  Same inputs as
/// [`commit_basefold_late_binding`].  On success returns the
/// byte-equivalent `(commit, prover_data)`.  On unrecoverable
/// shape/runtime error returns the original `chip_traces` so the host
/// fallback can run without losing ownership.
pub type GpuBasefoldCommitFn = fn(
    chip_traces: Vec<(String, RowMajorMatrix<LbVal>)>,
    challenger: &mut LbChallenger,
) -> Result<
    (BasefoldLateBindingCommit, BasefoldLateBindingProverData),
    Vec<(String, RowMajorMatrix<LbVal>)>,
>;

static GPU_BASEFOLD_COMMIT_HOOK: std::sync::OnceLock<GpuBasefoldCommitFn> =
    std::sync::OnceLock::new();

/// Register the GPU BaseFold commit driver.  Idempotent; returns
/// `Err(existing_hook)` when a hook was already registered.  Called
/// once by `ziren-gpu`'s `compress_multi_gpu` at startup.
pub fn register_gpu_basefold_commit_hook(
    f: GpuBasefoldCommitFn,
) -> Result<(), GpuBasefoldCommitFn> {
    GPU_BASEFOLD_COMMIT_HOOK.set(f)
}

/// Read the registered GPU BaseFold commit hook, if any.
#[must_use]
pub fn get_gpu_basefold_commit_hook() -> Option<GpuBasefoldCommitFn> {
    GPU_BASEFOLD_COMMIT_HOOK.get().copied()
}

// ─────────────────────────────────────────────────────────────────────
// #107 / G1 — GPU jagged-reduction sumcheck dispatch hook.
//
// Mirrors the host `crate::jagged_sumcheck::prove_jagged_reduction_owned`
// signature one-for-one — same inputs (owned `dense_q`, packing,
// `r_row_per_chip`, `y_per_chip`, challenger), same output
// (`JaggedReductionProof<InnerChallenge>`).  Wired from
// `prove_jagged_basefold_with_y_per_chip` step (4) when
// `ZIREN_GPU_JAGGED_PCS=1` is set.
//
// Per-shard wall: 2.41–2.76s × 25 shards ≈ 62s of the 144s tendermint
// compress wall (per E2's per-shard logs) — the largest remaining
// per-shard host bottleneck after the BaseFold commit moved to GPU.
// ─────────────────────────────────────────────────────────────────────

/// Signature of the GPU jagged-reduction prover hook.  Same inputs
/// as [`crate::jagged_sumcheck::prove_jagged_reduction_owned`], same
/// output.  Implementations MUST be byte-equivalent to the host
/// reduction (verified by the existing host fallback when the hook is
/// not registered).  Implementations MAY return `None` to signal a
/// hard fall-through to the host body (e.g. when shape constraints
/// the GPU path doesn't support are detected).
pub type GpuJaggedReductionFn = fn(
    dense_q: alloc::vec::Vec<LbVal>,
    packing: &crate::jagged::JaggedPacking<LbVal>,
    r_row_per_chip: &[alloc::vec::Vec<LbChallenge>],
    y_per_chip: &[alloc::vec::Vec<LbChallenge>],
    challenger: &mut LbChallenger,
) -> Option<crate::jagged_sumcheck::JaggedReductionProof<LbChallenge>>;

static GPU_JAGGED_REDUCTION_HOOK: std::sync::OnceLock<GpuJaggedReductionFn> =
    std::sync::OnceLock::new();

/// Register the GPU jagged-reduction hook.  Idempotent; returns
/// `Err(existing_hook)` when a hook was already registered.  Called
/// once by `ziren-gpu`'s `compress_multi_gpu` at startup.
pub fn register_gpu_jagged_reduction_hook(
    f: GpuJaggedReductionFn,
) -> Result<(), GpuJaggedReductionFn> {
    GPU_JAGGED_REDUCTION_HOOK.set(f)
}

/// Read the registered GPU jagged-reduction hook, if any.
#[must_use]
pub fn get_gpu_jagged_reduction_hook() -> Option<GpuJaggedReductionFn> {
    GPU_JAGGED_REDUCTION_HOOK.get().copied()
}

// ─────────────────────────────────────────────────────────────────────
// Step 4a (`/tmp/step4_backend_parametrize_plan.md`) — GPU row-GKR
// layer-transition dispatch hook scaffolding.
//
// Mirror of the existing GpuJaggedReductionFn pattern above.  Used by
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
// Three previous attempts (#218 Q1, #219 Q2, #220 R1) wired a
// transition CUDA kernel via a side-channel registry but
// `build_gkr_circuit` STILL ran host transitions, so the kernel was
// redundant — the host materialization always overrode the device
// result.  Step 4 fixes this by making `LayerState::Device` a true
// alternative to `LayerState::Host`, with the GPU hook as the only
// path that produces it.
//
// **NOT YET WIRED** — Step 4a is scaffolding only.  Step 4c will be
// the first commit that actually consults the registered hook.
// ─────────────────────────────────────────────────────────────────────

/// Signature of the GPU row-GKR layer-transition driver.  Consumes
/// the previous layer's opaque device handle (`prev_handle`) and
/// returns the new layer's device handle.  The GPU prover owns
/// allocation / deallocation of the device-resident state behind the
/// handles — the stark crate never dereferences them.
///
/// Step 4a scaffolding only — no caller invokes this yet.  Step 4c
/// will wire the dispatch into `build_gkr_circuit`.
pub type GpuLayerTransitionFn = fn(prev_handle: u64) -> u64;

static GPU_LAYER_TRANSITION_HOOK: std::sync::OnceLock<GpuLayerTransitionFn> =
    std::sync::OnceLock::new();

/// Register the GPU row-GKR layer-transition driver.  Idempotent;
/// returns `Err(existing_hook)` when a hook was already registered.
/// Will be called once by `ziren-gpu`'s `compress_multi_gpu` at
/// startup once Step 4c lands.
pub fn register_gpu_layer_transition_hook(
    f: GpuLayerTransitionFn,
) -> Result<(), GpuLayerTransitionFn> {
    GPU_LAYER_TRANSITION_HOOK.set(f)
}

/// Read the registered GPU row-GKR layer-transition hook, if any.
#[must_use]
pub fn get_gpu_layer_transition_hook() -> Option<GpuLayerTransitionFn> {
    GPU_LAYER_TRANSITION_HOOK.get().copied()
}

/// Open the committed batch at a single point and produce the
/// stacked-basefold proof.  `eval_point.len()` must equal
/// `log_stacking_height + log(num_stripes_padded)`.
///
/// **#191 / H3 (C-full C4 plan §5 sister to E2)** — when
/// `ZIREN_GPU_BASEFOLD=1` is set AND ziren-gpu has registered the GPU
/// open hook (via [`register_gpu_basefold_open_hook`]), the open
/// dispatches through `FriCudaProver::prove` on device.  Output proof
/// must be byte-identical to the host path (the device hook host-side
/// observes the same digests + univariate messages into the supplied
/// `LbChallenger`).  Falls through to the host implementation on any
/// of: env unset, hook unregistered, hook returns `Err` (shape
/// unsupported / device error — `Err` returns ownership of the
/// `prover_data` so the host fallback can run without losing it).
pub fn open_basefold_late_binding(
    prover_data: BasefoldLateBindingProverData,
    eval_point: Vec<LbChallenge>,
    challenger: &mut LbChallenger,
) -> StackedBasefoldProof<LbVal, LbChallenge, LbMmcs> {
    if std::env::var("ZIREN_GPU_BASEFOLD").map(|v| v == "1").unwrap_or(false) {
        if let Some(hook) = get_gpu_basefold_open_hook() {
            use std::sync::OnceLock;
            static FIRED_ONCE: OnceLock<()> = OnceLock::new();
            static FELLBACK_ONCE: OnceLock<()> = OnceLock::new();
            match hook(prover_data, eval_point, challenger) {
                Ok(proof) => {
                    FIRED_ONCE.get_or_init(|| {
                        tracing::warn!(
                            "GPU BaseFold open FIRED \
                             (#191/H3 ZIREN_GPU_BASEFOLD=1, gpu_hook dispatched)"
                        );
                    });
                    return proof;
                }
                Err((returned_prover_data, returned_eval_point)) => {
                    FELLBACK_ONCE.get_or_init(|| {
                        tracing::warn!(
                            "GPU BaseFold open hook returned Err — falling \
                             back to host open_basefold_late_binding. The \
                             device side could not handle this shape; the \
                             host open is the source of truth."
                        );
                    });
                    return open_basefold_late_binding_host(
                        returned_prover_data,
                        returned_eval_point,
                        challenger,
                    );
                }
            }
        }
        // No hook registered: silently fall through (the COMMIT site
        // already emits its own one-shot WARN_ONCE for the same
        // env-set + no-hook condition; we don't need to double up).
    }
    open_basefold_late_binding_host(prover_data, eval_point, challenger)
}

/// Pure host-side implementation of [`open_basefold_late_binding`] —
/// extracted so the GPU dispatch hook can fall back to it on
/// shape-unsupported / runtime errors without re-entering the env-flag
/// dispatch loop.  Always runs the CPU StackedPcsProver
/// `prove_trusted_evaluation` body.
pub fn open_basefold_late_binding_host(
    prover_data: BasefoldLateBindingProverData,
    eval_point: Vec<LbChallenge>,
    challenger: &mut LbChallenger,
) -> StackedBasefoldProof<LbVal, LbChallenge, LbMmcs> {
    let (prover, _verifier, _mmcs) = build_pcs(prover_data.log_stacking_height);
    prover.prove_trusted_evaluation(eval_point, vec![prover_data.stacked_data], challenger)
}

// ─────────────────────────────────────────────────────────────────────
// #191 / H3 (C-full C4 plan §5 sister to E2) — GPU BaseFold open
// dispatch hook.
//
// Mirror of the E2 commit hook ([`register_gpu_basefold_commit_hook`]).
// The hook receives the same inputs as `open_basefold_late_binding` and
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
//     PoW witness into the supplied `LbChallenger` so the transcript
//     stays in lock-step with the host path,
//   * assembling a `StackedBasefoldProof` whose `basefold_proof.*` is
//     shape-compatible with the host path consumed by
//     `verify_basefold_late_binding`.
//
// The hook returns `Result<.., (prover_data, eval_point)>` so the device
// side can tunnel ownership of the host inputs back to the host fallback
// on error (mirrors the `commit_basefold_late_binding` hook contract).
// ─────────────────────────────────────────────────────────────────────

/// Signature of the GPU BaseFold open driver.  Same inputs as
/// [`open_basefold_late_binding`].  On success returns the byte-
/// equivalent `StackedBasefoldProof`.  On unrecoverable shape/runtime
/// error returns the original `(prover_data, eval_point)` so the host
/// fallback can run without losing ownership.
pub type GpuBasefoldOpenFn = fn(
    prover_data: BasefoldLateBindingProverData,
    eval_point: Vec<LbChallenge>,
    challenger: &mut LbChallenger,
) -> Result<
    StackedBasefoldProof<LbVal, LbChallenge, LbMmcs>,
    (BasefoldLateBindingProverData, Vec<LbChallenge>),
>;

static GPU_BASEFOLD_OPEN_HOOK: std::sync::OnceLock<GpuBasefoldOpenFn> =
    std::sync::OnceLock::new();

/// Register the GPU BaseFold open driver.  Idempotent; returns
/// `Err(existing_hook)` when a hook was already registered.  Called
/// once by `ziren-gpu`'s `compress_multi_gpu` at startup.
pub fn register_gpu_basefold_open_hook(
    f: GpuBasefoldOpenFn,
) -> Result<(), GpuBasefoldOpenFn> {
    GPU_BASEFOLD_OPEN_HOOK.set(f)
}

/// Read the registered GPU BaseFold open hook, if any.
#[must_use]
pub fn get_gpu_basefold_open_hook() -> Option<GpuBasefoldOpenFn> {
    GPU_BASEFOLD_OPEN_HOOK.get().copied()
}

/// Verify the proof against a previously observed commitment.
pub fn verify_basefold_late_binding(
    commitment: &<LbMmcs as p3_commit::Mmcs<LbVal>>::Commitment,
    area: usize,
    log_stacking_height: u32,
    eval_point: &[LbChallenge],
    evaluation_claim: LbChallenge,
    proof: &StackedBasefoldProof<LbVal, LbChallenge, LbMmcs>,
    challenger: &mut LbChallenger,
) -> Result<(), crate::basefold::StackedVerifierError> {
    let (_prover, verifier, _mmcs) = build_pcs(log_stacking_height);
    verifier.verify_trusted_evaluation(
        core::slice::from_ref(commitment),
        &[area],
        eval_point,
        proof,
        evaluation_claim,
        challenger,
    )
}

// ─── Jagged-sumcheck integration ──────────
//
// Mirrors [`crate::jagged_late_binding::prove_jagged_late_binding`] but
// commits via BaseFold instead of WHIR.  The dense polynomial is still
// materialized for the sumcheck reduction (the OOM win is in the
// commit phase: BaseFold streams stripes through dft_batch instead of
// blowing up the whole dense vector by 16×).  Per-chip BaseFold
// commit (which would skip even the brief dense materialization) is
// the next-stage refactor.
//
// E1 step 2: this module no longer requires the `whir` feature.  It
// uses the ungated `jagged.rs` (data structures) and the new
// `jagged_sumcheck.rs` (PCS-agnostic reduction math) — both moved
// out of the whir feature gate as part of E1.

#[cfg(feature = "basefold")]
pub mod jagged {
    use alloc::vec::Vec;

    use p3_challenger::CanObserve;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;

    use crate::basefold::StackedBasefoldProof;
    use crate::jagged::{JaggedChipInfo, JaggedPacking, compute_jagged_metadata, materialize_dense_jagged};
    use crate::jagged_sumcheck::{
        JaggedReductionProof, prove_jagged_reduction_streaming,
        verify_jagged_reduction,
    };
    use crate::kb31_poseidon2::{InnerChallenge, InnerVal};

    use super::{
        BasefoldLateBindingCommit,
        commit_basefold_late_binding, open_basefold_late_binding,
        verify_basefold_late_binding,
    };

    /// Wire-format jagged metadata: only the per-bundle quantities
    /// the verifier needs to reconstruct the same `JaggedPacking`
    /// from chip_infos it receives separately.  We don't serialize
    /// `dense_values` (that's the multi-GB vector we just committed
    /// to BaseFold).
    ///
    /// `column_counts` (#95-fix, May 2 2026): per-chip *actual*
    /// column count as exercised by this shard's trace, written by
    /// the prover from `compute_jagged_metadata`.  The verifier reads
    /// this instead of `BaseAir::width(chip)` so the prover can send
    /// `trace.width` (the truly-populated columns) without any
    /// chip.width() pad.  Restores Apr 30's perf (~24x reduction in
    /// jagged-PCS data on workloads with sparse-column chips).
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

    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    pub struct JaggedBasefoldBundle {
        pub reduction: JaggedReductionProof<InnerChallenge>,
        pub basefold_proof: StackedBasefoldProof<
            InnerVal,
            InnerChallenge,
            crate::basefold_late_binding::LbMmcs,
        >,
        pub y_per_chip: Vec<Vec<InnerChallenge>>,
        pub commit: BasefoldLateBindingCommit,
        pub packing: PackingMeta,
    }

    impl JaggedBasefoldBundle {
        /// Wire-format bytes (rmp-serde — matches the existing WHIR
        /// late-binding bundle's serializer choice).
        pub fn to_bytes(&self) -> Vec<u8> {
            rmp_serde::to_vec(self).expect("JaggedBasefoldBundle serializes")
        }

        pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
            rmp_serde::from_slice(bytes).ok()
        }
    }

    /// **Prover-side one-call entry point** — full pipeline:
    /// commit chip traces (via BaseFold-stacked), run jagged sumcheck
    /// reduction, open dense at the reduction's `z*` via BaseFold,
    /// bundle for the wire.
    pub fn prove_jagged_basefold(
        chip_traces: &[(alloc::string::String, RowMajorMatrix<InnerVal>)],
        r_row_per_chip: &[Vec<InnerChallenge>],
        challenger: &mut crate::basefold_late_binding::LbChallenger,
    ) -> JaggedBasefoldBundle {
        prove_jagged_basefold_with_y_per_chip(
            chip_traces,
            r_row_per_chip,
            None,
            challenger,
        )
    }

    /// Variant of [`prove_jagged_basefold`] that lets the caller pass a
    /// pre-computed `y_per_chip` (e.g. computed device-resident on
    /// GPU).  When `pre_y_per_chip` is `Some`, step (3) — the host
    /// triple-nested per-column reduction — is skipped entirely.
    /// Output bytes are identical to the host path.
    pub fn prove_jagged_basefold_with_y_per_chip(
        chip_traces: &[(alloc::string::String, RowMajorMatrix<InnerVal>)],
        r_row_per_chip: &[Vec<InnerChallenge>],
        pre_y_per_chip: Option<Vec<Vec<InnerChallenge>>>,
        challenger: &mut crate::basefold_late_binding::LbChallenger,
    ) -> JaggedBasefoldBundle {
        // Per-shard jagged-PCS sub-phase timing.  Five sub-phases mirror
        // the numbered protocol steps below: (1) metadata, (2) commit
        // (incl. dense materialize + BaseFold encode), (3) per-chip
        // y_{c,j} evaluation, (4) jagged-sumcheck reduction, (5) BaseFold
        // open at z*.
        let n_chips = chip_traces.len();

        // (1) Pack metadata.
        let _t_meta = std::time::Instant::now();
        let _meta_span = tracing::info_span!("jagged_compute_metadata").entered();
        let packing = compute_jagged_metadata::<InnerVal>(chip_traces);
        drop(_meta_span);
        tracing::info!(
            elapsed_ms = _t_meta.elapsed().as_millis() as u64,
            chips = n_chips,
            sub_phase = "compute_metadata",
            "jagged sub-phase done"
        );

        // (2) Commit dense as a single Mle via BaseFold-stacked.  The
        // stacked PCS interleaves into stripes of bounded size — the
        // 16× LDE never materializes for the whole 2^N vector.
        //
        // Memory-critical ordering (E3 partial): materialize `dense_q`
        // ONLY long enough to hand it to the commit — move, don't
        // clone — then drop it and re-materialize for the reduction.
        // Previous flow kept a duplicate live across (commit + reduction)
        // which doubled peak RSS on wide workloads (tendermint OOM'd at
        // 112 GB RSS).  Re-materialization is a cheap linear pass over
        // `chip_traces` compared to the LDE / stripe work already done
        // in the commit.
        let _t_commit = std::time::Instant::now();
        let _commit_span = tracing::info_span!("jagged_dense_commit").entered();
        let (commit, prover_data) = {
            let dense_q =
                materialize_dense_jagged::<InnerVal>(chip_traces, packing.log_dense_size);
            debug_assert_eq!(dense_q.len(), 1usize << packing.log_dense_size);
            let dense_traces = vec![(
                alloc::string::String::from("<jagged-dense>"),
                RowMajorMatrix::new(dense_q, 1),
            )];
            commit_basefold_late_binding(dense_traces, challenger)
        };
        drop(_commit_span);
        tracing::info!(
            elapsed_ms = _t_commit.elapsed().as_millis() as u64,
            chips = n_chips,
            log_dense_size = packing.log_dense_size as u64,
            sub_phase = "dense_commit",
            "jagged sub-phase done"
        );

        // (3) Compute per-chip per-column row-MLE values y_{c,j}.
        //
        // Phase 4 perf fix (Apr 25 2026): parallelize across chips
        // AND across columns within each chip. The triple-nested loop
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
            // C-full D1 empty-chip skip: for empty-trace chips
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
            chip_traces
                .par_iter()
                .zip(r_row_per_chip.par_iter())
                .map(|((_name, trace), r_row_c)| {
                    let h = trace.values.len() / trace.width.max(1);
                    let w = trace.width;
                    // C-full D1 empty-chip skip: for an empty-trace
                    // chip (h == 0 || w == 0) there are no columns to
                    // reduce; return an empty Vec.  The original
                    // assertion `h_padded.trailing_zeros() ==
                    // r_row_c.len()` fires for h=0 (h_padded=1,
                    // trailing_zeros=0) but r_row_c is sized to
                    // max_log_row_count (e.g. 4), so the chip would
                    // panic before reaching the inner reduction.
                    // This matches the device-fusion path's behavior
                    // (Vec::new() per empty chip) above and the
                    // downstream consumers tolerate empty per-chip
                    // y slots.
                    if h == 0 || w == 0 {
                        return Vec::new();
                    }
                    let h_padded = h.next_power_of_two();
                    assert_eq!(h_padded.trailing_zeros() as usize, r_row_c.len());

                    let eq_c = crate::zerocheck_prover::eq_mle_table::<InnerChallenge>(r_row_c);
                    (0..w)
                        .into_par_iter()
                        .map(|col| {
                            let mut acc = InnerChallenge::ZERO;
                            for row in 0..h {
                                acc += eq_c[row] * InnerChallenge::from(trace.values[row * w + col]);
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
        // #107 / G1 dispatch: when ZIREN_GPU_JAGGED_PCS=1 is set AND a
        // GPU jagged-reduction hook has been registered (by ziren-gpu's
        // `compress_multi_gpu` startup block), route the reduction
        // through the device hook.  The hook is byte-equivalent to
        // `prove_jagged_reduction_owned` (verified by the existing
        // host fallback path + the GPU-side scaffold tests in
        // `ziren-gpu/basefold/src/jagged_sumcheck.rs::tests`).  When
        // the hook returns `None` (unsupported shape) or is not
        // registered, the host fallback path runs unchanged.
        let _t_red = std::time::Instant::now();
        let _red_span = tracing::info_span!("jagged_sumcheck_reduce").entered();
        let reduction = {
            let dense_q =
                materialize_dense_jagged::<InnerVal>(chip_traces, packing.log_dense_size);

            let try_gpu = std::env::var("ZIREN_GPU_JAGGED_PCS")
                .map(|v| v == "1")
                .unwrap_or(false);
            let hook = if try_gpu {
                super::get_gpu_jagged_reduction_hook()
            } else {
                None
            };

            match hook {
                Some(f) => {
                    use std::sync::OnceLock;
                    static FIRED_ONCE: OnceLock<()> = OnceLock::new();
                    FIRED_ONCE.get_or_init(|| {
                        tracing::warn!(
                            chips = n_chips,
                            log_dense_size = packing.log_dense_size as u64,
                            "#107 jagged_pcs FIRED — GPU jagged-reduction hook \
                             driving sumcheck reduce ({} chips)",
                            n_chips,
                        );
                    });
                    // Move dense_q into the hook.  Move-not-clone:
                    // avoids holding a 4N base-field duplicate live
                    // across the call.  On a hard fall-through (None
                    // returned by the hook) we lose ownership — the
                    // host fallback below re-materializes dense_q in
                    // that case, mirroring the pre-G1 behaviour.
                    let r_row = r_row_per_chip.to_vec();
                    let y_clone = y_per_chip.clone();
                    let saved_dense = if std::env::var("ZIREN_GPU_JAGGED_PCS_HOST_GUARD")
                        .map(|v| v == "1").unwrap_or(false)
                    {
                        Some(dense_q.clone())
                    } else {
                        None
                    };
                    match f(dense_q, &packing, &r_row, &y_clone, challenger) {
                        Some(p) => p,
                        None => {
                            tracing::warn!(
                                chips = n_chips,
                                log_dense_size = packing.log_dense_size as u64,
                                "#107 jagged_pcs hook returned None — falling back \
                                 to host prove_jagged_reduction_owned",
                            );
                            let dense_q = saved_dense.unwrap_or_else(|| {
                                materialize_dense_jagged::<InnerVal>(
                                    chip_traces,
                                    packing.log_dense_size,
                                )
                            });
                            crate::jagged_sumcheck::prove_jagged_reduction_owned(
                                dense_q,
                                &packing,
                                r_row_per_chip,
                                &y_per_chip,
                                challenger,
                            )
                        }
                    }
                }
                None => crate::jagged_sumcheck::prove_jagged_reduction_owned(
                    dense_q,
                    &packing,
                    r_row_per_chip,
                    &y_per_chip,
                    challenger,
                ),
            }
        };
        drop(_red_span);
        tracing::info!(
            elapsed_ms = _t_red.elapsed().as_millis() as u64,
            chips = n_chips,
            sub_phase = "sumcheck_reduce",
            "jagged sub-phase done"
        );

        // (5) Open the BaseFold commit at z*.
        // The reduction's eval_point matches the BaseFold eval point
        // dimension (= log_dense_size) by construction.
        let _t_open = std::time::Instant::now();
        let _open_span = tracing::info_span!("jagged_basefold_open").entered();
        let proof = open_basefold_late_binding(
            prover_data,
            reduction.eval_point.clone(),
            challenger,
        );
        drop(_open_span);
        tracing::info!(
            elapsed_ms = _t_open.elapsed().as_millis() as u64,
            chips = n_chips,
            sub_phase = "basefold_open",
            "jagged sub-phase done"
        );

        let packing_meta = PackingMeta {
            offsets: packing.offsets.clone(),
            total_values: packing.total_values,
            log_dense_size: packing.log_dense_size,
            // #95-fix: per-chip *actual* column count, so verifier
            // does not need to consult `BaseAir::width(chip)`.
            column_counts: packing
                .chip_infos
                .iter()
                .map(|ci| ci.column_count)
                .collect(),
        };
        JaggedBasefoldBundle {
            reduction,
            basefold_proof: proof,
            y_per_chip,
            commit,
            packing: packing_meta,
        }
    }
    /// Verifier mirror.
    pub fn verify_jagged_basefold(
        chip_infos: &[JaggedChipInfo],
        r_row_per_chip: &[Vec<InnerChallenge>],
        bundle: &JaggedBasefoldBundle,
        challenger: &mut crate::basefold_late_binding::LbChallenger,
    ) -> bool {
        // Replay the commit observation.
        challenger.observe(bundle.commit.commitment.clone());

        // Verify jagged sumcheck reduction (verifier-side).  We
        // recompose the full `JaggedPacking` from the `chip_infos`
        // the verifier already has + the per-bundle metadata
        // (offsets, total_values, log_dense_size).  `dense_values`
        // stays empty — `verify_jagged_reduction` only needs the
        // metadata fields.
        let packing = JaggedPacking {
            dense_values: Vec::new(),
            chip_infos: chip_infos.to_vec(),
            offsets: bundle.packing.offsets.clone(),
            total_values: bundle.packing.total_values,
            log_dense_size: bundle.packing.log_dense_size,
        };
        let red_result = verify_jagged_reduction(
            &bundle.reduction,
            &packing,
            r_row_per_chip,
            &bundle.y_per_chip,
            challenger,
        );
        let Some((z_star, q_at_z, _w_at_z)) = red_result else {
            eprintln!("[basefold verify] jagged sumcheck reduction REJECTED");
            return false;
        };

        // Verify the BaseFold opening: claim is q_at_z, point is z*.
        let res = verify_basefold_late_binding(
            &bundle.commit.commitment,
            bundle.commit.area,
            bundle.commit.log_stacking_height,
            &z_star,
            q_at_z,
            &bundle.basefold_proof,
            challenger,
        );
        if let Err(e) = &res {
            eprintln!("[basefold verify] basefold opening REJECTED: {:?}", e);
        }
        res.is_ok()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use p3_field::BasedVectorSpace;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn rand_kb<R: Rng>(rng: &mut R) -> LbVal {
        LbVal::from_u32(rng.gen::<u32>() & 0x3FFF_FFFF)
    }

    fn rand_ef<R: Rng>(rng: &mut R) -> LbChallenge {
        <LbChallenge as BasedVectorSpace<LbVal>>::from_basis_coefficients_iter(
            (0..4).map(|_| rand_kb(rng)),
        )
        .unwrap()
    }

    fn build_challenger() -> LbChallenger {
        let perm: crate::kb31_poseidon2::InnerPerm =
            zkm_primitives::poseidon2_init();
        LbChallenger::new(perm)
    }

    /// End-to-end: commit a small batch of heterogeneous chip traces,
    /// open at a random point, verify.  This is the OOM-cure flow
    /// (per-chip Mles → stacked PCS → BaseFold) on a toy size.
    #[test]
    fn test_basefold_late_binding_roundtrip() {
        let mut rng = StdRng::seed_from_u64(0xBA5E_F01D_5EED);

        // Two synthetic chip traces of different shapes; both must
        // pad to power-of-2 row counts inside the stacking height.
        let mk_trace = |width: usize, h: usize, rng: &mut StdRng| -> RowMajorMatrix<LbVal> {
            let v: Vec<LbVal> = (0..width * h).map(|_| rand_kb(rng)).collect();
            RowMajorMatrix::new(v, width)
        };
        let traces = vec![
            ("Cpu".into(), mk_trace(20, 100, &mut rng)),
            ("Add".into(), mk_trace(8, 50, &mut rng)),
        ];

        let mut p_chal = build_challenger();
        let (commit, prover_data) =
            commit_basefold_late_binding(traces.clone(), &mut p_chal);

        // Compute the eval point + claim for the stacked PCS.  Claim
        // is the multilinear-extension of the *flattened*
        // batch-evaluations vector at the batch part of the point.
        let stack_dim = commit.log_stacking_height as usize;
        let num_stripes = commit.area >> stack_dim;
        let num_batch_vars = num_stripes.next_power_of_two().trailing_zeros() as usize;
        let total_vars = num_batch_vars + stack_dim;
        let eval_point: Vec<LbChallenge> =
            (0..total_vars).map(|_| rand_ef(&mut rng)).collect();

        let stack_point: Vec<LbChallenge> = eval_point[..stack_dim].to_vec();
        let batch_evals_flat: Vec<LbChallenge> = prover_data
            .stacked_data
            .interleaved_mles
            .iter()
            .flat_map(|m| m.eval_at::<LbChallenge>(&stack_point))
            .collect();

        // Honest evaluation_claim = MLE of batch_evals_flat at
        // batch_point (matches the verifier's
        // `eval_multilinear_padded` reduction).
        let batch_point = &eval_point[stack_dim..];
        let evaluation_claim = {
            let target = 1usize << batch_point.len();
            let mut current: Vec<LbChallenge> = batch_evals_flat.clone();
            current.resize(target, LbChallenge::ZERO);
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

        let proof = open_basefold_late_binding(prover_data, eval_point.clone(), &mut p_chal);

        let mut v_chal = build_challenger();
        v_chal.observe(commit.commitment.clone());
        verify_basefold_late_binding(
            &commit.commitment,
            commit.area,
            commit.log_stacking_height,
            &eval_point,
            evaluation_claim,
            &proof,
            &mut v_chal,
        )
        .expect("basefold late-binding roundtrip");
    }

    /// **Phase C3** — full jagged-sumcheck pipeline backed by BaseFold.
    /// E1: ungated from `whir` after `jagged` and `jagged_sumcheck`
    /// were moved out of the whir feature gate.
    #[test]
    fn test_jagged_basefold_roundtrip() {
        use crate::basefold_late_binding::jagged::{
            prove_jagged_basefold, verify_jagged_basefold,
        };

        let mut rng = StdRng::seed_from_u64(0xC0DE_BA5E);

        let mk_trace =
            |width: usize, height: usize, rng: &mut StdRng| -> RowMajorMatrix<LbVal> {
                let v: Vec<LbVal> = (0..width * height).map(|_| rand_kb(rng)).collect();
                RowMajorMatrix::new(v, width)
            };

        // Two heterogeneous chip traces; both heights round up to a
        // power of 2 inside the stacking stripe.
        let traces = vec![
            ("Cpu".into(), mk_trace(4, 16, &mut rng)),
            ("Add".into(), mk_trace(2, 8, &mut rng)),
        ];

        // Per-chip r_row sampled fresh; length = log2(padded height).
        let r_row_per_chip: Vec<Vec<LbChallenge>> = traces
            .iter()
            .map(|(_, t)| {
                let h = t.values.len() / t.width.max(1);
                let log_h = h.next_power_of_two().trailing_zeros() as usize;
                (0..log_h).map(|_| rand_ef(&mut rng)).collect()
            })
            .collect();

        let mut p_chal = build_challenger();
        let bundle = prove_jagged_basefold(&traces, &r_row_per_chip, &mut p_chal);

        // Verifier reconstructs chip_infos from the same traces it
        // already has access to via the protocol's outer loop.
        let chip_infos =
            crate::jagged::compute_jagged_metadata::<LbVal>(&traces).chip_infos;
        let mut v_chal = build_challenger();
        let ok = verify_jagged_basefold(&chip_infos, &r_row_per_chip, &bundle, &mut v_chal);
        assert!(ok, "jagged-basefold pipeline should accept honest proof");
    }


    /// **Soundness sanity** — flipping any single field of the bundle
    /// must cause the verifier to reject.  Catches whole classes of
    /// "I forgot to observe X into the challenger" bugs that pass
    /// honest-prover tests but admit forgery.
    #[test]
    fn test_jagged_basefold_rejects_tampered_proof() {
        use p3_field::PrimeCharacteristicRing;
        use crate::basefold_late_binding::jagged::{
            prove_jagged_basefold, verify_jagged_basefold,
        };

        let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);
        let mk_trace =
            |width: usize, height: usize, rng: &mut StdRng| -> RowMajorMatrix<LbVal> {
                let v: Vec<LbVal> = (0..width * height).map(|_| rand_kb(rng)).collect();
                RowMajorMatrix::new(v, width)
            };
        let traces = vec![("Cpu".into(), mk_trace(4, 16, &mut rng))];
        let r_row_per_chip: Vec<Vec<LbChallenge>> = traces
            .iter()
            .map(|(_, t)| {
                let h = t.values.len() / t.width.max(1);
                let log_h = h.next_power_of_two().trailing_zeros() as usize;
                (0..log_h).map(|_| rand_ef(&mut rng)).collect()
            })
            .collect();

        let mut p_chal = build_challenger();
        let bundle = prove_jagged_basefold(&traces, &r_row_per_chip, &mut p_chal);
        let chip_infos =
            crate::jagged::compute_jagged_metadata::<LbVal>(&traces).chip_infos;

        // Tamper #1: corrupt the sumcheck final claim `q_at_z`.
        let mut tampered = bundle.clone();
        tampered.reduction.q_at_z = tampered.reduction.q_at_z + LbChallenge::ONE;
        let mut v_chal = build_challenger();
        assert!(
            !verify_jagged_basefold(&chip_infos, &r_row_per_chip, &tampered, &mut v_chal),
            "verifier must reject q_at_z tampering"
        );

        // Tamper #2: corrupt one of the per-chip y_{c,j} commitments.
        let mut tampered = bundle.clone();
        tampered.y_per_chip[0][0] = tampered.y_per_chip[0][0] + LbChallenge::ONE;
        let mut v_chal = build_challenger();
        assert!(
            !verify_jagged_basefold(&chip_infos, &r_row_per_chip, &tampered, &mut v_chal),
            "verifier must reject y_per_chip tampering"
        );

        // Tamper #3: corrupt the BaseFold final_poly in the proof.
        let mut tampered = bundle.clone();
        tampered.basefold_proof.basefold_proof.final_poly =
            tampered.basefold_proof.basefold_proof.final_poly + LbChallenge::ONE;
        let mut v_chal = build_challenger();
        assert!(
            !verify_jagged_basefold(&chip_infos, &r_row_per_chip, &tampered, &mut v_chal),
            "verifier must reject final_poly tampering"
        );
    }
}
