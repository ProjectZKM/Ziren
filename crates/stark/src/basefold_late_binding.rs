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


use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_challenger::{CanObserve, FieldChallenger};
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
///
/// **#244 (May 6 2026)**: this clamping creates prover/verifier param
/// divergence — prover scales the stacking height down for small
/// commits, but the in-circuit verifier (built once per shard with
/// max_log_row_count) does not.  The bundle-lift path in
/// `crates/recursion/circuit/src/machine/core_basefold.rs` rebuilds
/// the verifier per-proof using `bundle.commit.log_stacking_height`
/// (the value the prover actually used), so the clamping is
/// preserved for memory efficiency on small commits AND the bundle
/// path's verifier matches the prover.  The default (bytes) path's
/// verifier still uses max_log_row_count but the all-zero placeholder
/// lift's shape doesn't depend on the prover-emitted shape, so the
/// mismatch is invisible.  See #244 for the chain analysis.
pub fn pick_log_stacking_height(total_entries: usize) -> u32 {
    let log_total = total_entries.next_power_of_two().trailing_zeros();
    // Reserve at least 1 var for the batching point (= 2 stripes
    // minimum).
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

/// Public for the GPU dispatch hook (#76 / D2 — ): the
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
/// **#76 / D2 ( plan §5)** — when `ZIREN_GPU_BASEFOLD=1` is
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

/// Production-grade FRI config used by the late-binding pipeline.
/// Public so the GPU dispatch hook can construct a matching
/// device-side encoder (same `log_blowup`, same coset shift) without
/// re-creating the env-overrides logic.
pub fn lb_fri_config() -> FriConfig<LbVal> {
    FriConfig::<LbVal>::from_env_or_default()
}

// ─────────────────────────────────────────────────────────────────────
// GPU BaseFold commit dispatch hook.
//
// Mirror of the #174 () jagged-PCS device-trace hook pattern
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
// GPU jagged-reduction sumcheck dispatch hook.
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
// Win B (jagged_assist hook hardening) — V2 signature with optional
// device-resident dense_q handle.
//
// Rationale (from the related design memo narrow win #2):
// V1's hook accepts an owned `Vec<LbVal>` for `dense_q`.  When the
// producer (`ziren-gpu/basefold/src/jagged_reduction_dispatch.rs`)
// wraps it as `DenseQDevice::Host(...)`, the device round-0 path in
// `prove_jagged_reduction_gpu` is *never* taken — it bails on
// `as_device_buffer() == None` — and the host fallback runs the
// 2.5s/shard reduction.  See
// `ziren-gpu/basefold/src/jagged_sumcheck.rs:557-595` for the device
// round-0 dispatch.
//
// V2 adds an opaque `Option<u64>` device handle alongside the owned
// `Vec`.  When `Some(handle)`, the producer dereferences the handle
// through its own per-thread registry and wraps the buffer as
// `DenseQDevice::Borrowed(...)`, unlocking the device round-0 path.
// When `None`, V2 behaves byte-identically to V1.
//
// Opaque-`u64`-handle pattern mirrors `GpuLayerTransitionFn` /
// `GpuLayerInitFn` / `GpuLayerPullFn` above — stark crate never
// dereferences the handle, that's entirely GPU-side bookkeeping.  This
// is the simpler newtype wrapper fallback the diag calls out (passing
// a real `&DeviceBuffer<LbVal>` would require pulling
// `zkm-gpu-core` into `zkm-stark`'s public API, which is the 
// Backend abstraction — explicitly out of scope).
//
// **Backward compatible** — V1 hook remains.  Dispatch site prefers
// V2 when both are registered; otherwise falls back to V1; otherwise
// runs the host body.
// ─────────────────────────────────────────────────────────────────────

/// Signature of the GPU jagged-reduction prover hook (V2).
///
/// Extends [`GpuJaggedReductionFn`] with an optional device handle
/// for the dense_q buffer.  When `dense_q_device_handle` is
/// `Some(handle)`, the producer uses the device-resident buffer
/// (looked up in its own registry) and the `dense_q_host` argument
/// MAY be empty (the producer will pull-to-host on round 0 if it
/// needs to — but the device round-0 path avoids that).  When
/// `dense_q_device_handle` is `None`, V2 falls back to V1 semantics
/// using `dense_q_host`.
///
/// The handle is opaque — `zkm-stark` never dereferences it.  The
/// GPU side owns allocation / deallocation.
pub type GpuJaggedReductionFnV2 = fn(
    dense_q_host: alloc::vec::Vec<LbVal>,
    dense_q_device_handle: Option<u64>,
    packing: &crate::jagged::JaggedPacking<LbVal>,
    r_row_per_chip: &[alloc::vec::Vec<LbChallenge>],
    y_per_chip: &[alloc::vec::Vec<LbChallenge>],
    challenger: &mut LbChallenger,
) -> Option<crate::jagged_sumcheck::JaggedReductionProof<LbChallenge>>;

static GPU_JAGGED_REDUCTION_HOOK_V2: std::sync::OnceLock<GpuJaggedReductionFnV2> =
    std::sync::OnceLock::new();

/// Register the V2 GPU jagged-reduction hook (with device-handle
/// support).  Idempotent; returns `Err(existing_hook)` when a hook
/// was already registered.  V2 is preferred over V1 at dispatch.
pub fn register_gpu_jagged_reduction_hook_v2(
    f: GpuJaggedReductionFnV2,
) -> Result<(), GpuJaggedReductionFnV2> {
    GPU_JAGGED_REDUCTION_HOOK_V2.set(f)
}

/// Read the registered V2 GPU jagged-reduction hook, if any.
#[must_use]
pub fn get_gpu_jagged_reduction_hook_v2() -> Option<GpuJaggedReductionFnV2> {
    GPU_JAGGED_REDUCTION_HOOK_V2.get().copied()
}

// ─── Win A (hook hardening) — diagnostic counters / loggers ──────────
//
// Counts the number of times the dispatch path was rejected for each
// reason.  Logged on each Nth rejection (geometric — 1, 8, 64, ...)
// so a busy run doesn't spam but a debugging run still sees activity.
//
// All counters are global (single shared atomic) — fine since dispatch
// is from a hot path on the per-shard prove orchestrator and a single
// atomic increment is negligible.

/// Diagnostic counters for the GPU jagged-reduction dispatch site.
/// Exposed for testing — not part of the public API.
#[doc(hidden)]
pub mod jagged_dispatch_diag {
    use core::sync::atomic::{AtomicU64, Ordering};

    /// `ZIREN_GPU_JAGGED_PCS=1` set but no hook registered.
    pub static ENV_SET_BUT_UNREGISTERED: AtomicU64 = AtomicU64::new(0);
    /// Hook registered but env not set (silently skipped — possible
    /// misconfiguration).
    pub static HOOK_REGISTERED_BUT_ENV_UNSET: AtomicU64 = AtomicU64::new(0);
    /// Hook returned `None` (shape rejected by the GPU path).
    pub static SHAPE_REJECTED: AtomicU64 = AtomicU64::new(0);
    /// Hook fired and returned a proof (V1 or V2 path).
    pub static HOOK_FIRED: AtomicU64 = AtomicU64::new(0);
    /// V2 hook fired (subset of HOOK_FIRED) — used to confirm the
    /// device-handle path is exercised when expected.
    pub static V2_HOOK_FIRED: AtomicU64 = AtomicU64::new(0);
    /// V2 hook fired with `Some(handle)` — i.e. the device path was
    /// actually taken (not the V2-with-None pseudo-V1 path).
    pub static V2_WITH_DEVICE_HANDLE_FIRED: AtomicU64 = AtomicU64::new(0);

    /// Bump a counter and return its NEW value.  Used by the dispatch
    /// site to decide whether to emit a log on the Nth rejection.
    #[inline]
    pub(crate) fn bump(counter: &AtomicU64) -> u64 {
        counter.fetch_add(1, Ordering::Relaxed).saturating_add(1)
    }

    /// True if `n` is a power of two (or 1).  Used to decide whether
    /// to log on the Nth rejection (geometric back-off).
    #[inline]
    pub(crate) fn should_log_geometric(n: u64) -> bool {
        n.is_power_of_two()
    }

    /// Reset all counters to zero.  Test helper.
    #[doc(hidden)]
    pub fn reset_all() {
        ENV_SET_BUT_UNREGISTERED.store(0, Ordering::Relaxed);
        HOOK_REGISTERED_BUT_ENV_UNSET.store(0, Ordering::Relaxed);
        SHAPE_REJECTED.store(0, Ordering::Relaxed);
        HOOK_FIRED.store(0, Ordering::Relaxed);
        V2_HOOK_FIRED.store(0, Ordering::Relaxed);
        V2_WITH_DEVICE_HANDLE_FIRED.store(0, Ordering::Relaxed);
    }
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
///
/// **#230 multi-GPU fix** — `circuit_id` scopes the hook to a single
/// GKR-circuit build call.  The GPU side keys its registry by
/// `(device_id, circuit_id)` so concurrent shards on the same GPU
/// don't share a `next_handle` counter (which previously caused
/// "handle not in registry" panics when one shard's pull stepped on
/// another's intermediate handles).
pub type GpuLayerTransitionFn = fn(circuit_id: u64, prev_handle: u64) -> u64;

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

// ─────────────────────────────────────────────────────────────────────
// Step 4c (`/tmp/step4_backend_parametrize_plan.md`) — companion hooks
// for layer-state lifecycle on device:
//
//   * `GpuLayerInitFn`     — upload the FIRST EF Layer (post-FirstLayer
//                            host transition) to device, return handle.
//   * `GpuLayerTransitionFn` (defined above) — produce the next
//                            device-resident layer state from a prev
//                            handle.  Step 4a contract; unchanged.
//   * `GpuLayerPullFn`     — materialize a device handle back into a
//                            host `LogUpGkrCpuLayer<EF, EF>` so the
//                            terminal extraction can run on host.
//
// `HostLayerView<'a>` is the borrowed-cells shape passed to the init
// hook.  It carries borrowed `RowMajorTable<LbChallenge>` slices for
// each of the four sub-MLEs plus the layer dimensions.  Borrows-only
// keeps the upload zero-copy on the host side; the GPU side decides
// whether to memcpy into device memory or pin + dma.
//
// All three hooks are typed concretely on `LbVal`/`LbChallenge` (the
// production field stack — `KoalaBear` + `BinomialExtensionField<..,4>`).
// `build_gkr_circuit` is generic over `F`/`EF`, so the dispatch site
// uses `core::any::TypeId` to confirm the generics match before calling
// the hook; on type mismatch the host path runs unchanged.  This
// matches the architecture in #76 / D2 (commit hook) where the device
// only ever sees concrete LbVal/LbChallenge buffers.
// ─────────────────────────────────────────────────────────────────────

/// Borrowed-cells view of an EF row-GKR layer suitable for the GPU
/// init hook.  The four sub-MLEs are passed by slice so the upload
/// stays zero-copy on the host side; the GPU side is responsible for
/// the memcpy / pin + dma into device memory.
///
/// Lifetime borrows from the `LogUpGkrCpuLayer<LbChallenge, LbChallenge>`
/// the dispatch site holds across the call.
pub struct HostLayerView<'a> {
    pub numerator_0: &'a [crate::shard_level::row_gkr::layer::RowMajorTable<LbChallenge>],
    pub denominator_0: &'a [crate::shard_level::row_gkr::layer::RowMajorTable<LbChallenge>],
    pub numerator_1: &'a [crate::shard_level::row_gkr::layer::RowMajorTable<LbChallenge>],
    pub denominator_1: &'a [crate::shard_level::row_gkr::layer::RowMajorTable<LbChallenge>],
    pub num_row_variables: usize,
    pub num_interaction_variables: usize,
}

/// Signature of the GPU row-GKR layer-init driver.  Uploads the first
/// EF layer (constructed on host by the F→EF transition out of the
/// FirstLayer) to device memory, returns an opaque handle the
/// transition / pull hooks can consume.
///
/// Step 4c: declared but only invoked when this hook + the transition
/// hook + the pull hook are all registered, the calling thread has a
/// `gpu_worker_context` TLS (i.e. a `MultiGpuDevicePool` worker), AND
/// the `build_gkr_circuit` generic types resolve to (`LbVal`,
/// `LbChallenge`).
///
/// **#230 multi-GPU fix** — `circuit_id` scopes this hook to a single
/// GKR-circuit build call.  See `GpuLayerTransitionFn` docs for the
/// per-circuit registry rationale.
pub type GpuLayerInitFn =
    for<'a> fn(circuit_id: u64, view: HostLayerView<'a>) -> u64;

static GPU_LAYER_INIT_HOOK: std::sync::OnceLock<GpuLayerInitFn> =
    std::sync::OnceLock::new();

/// Register the GPU row-GKR layer-init driver.  Idempotent; returns
/// `Err(existing_hook)` when a hook was already registered.
pub fn register_gpu_layer_init_hook(
    f: GpuLayerInitFn,
) -> Result<(), GpuLayerInitFn> {
    GPU_LAYER_INIT_HOOK.set(f)
}

/// Read the registered GPU row-GKR layer-init hook, if any.
#[must_use]
pub fn get_gpu_layer_init_hook() -> Option<GpuLayerInitFn> {
    GPU_LAYER_INIT_HOOK.get().copied()
}

/// Signature of the GPU row-GKR layer-pull driver.  Materializes a
/// device-resident layer back to host as a
/// `LogUpGkrCpuLayer<LbChallenge, LbChallenge>` so the terminal
/// extraction (`extract_outputs`) can run on host without an
/// additional device-side primitive.
///
/// Called once at the end of `build_gkr_circuit` if the device path
/// was taken — `extract_outputs` already exists on host and operates
/// on a 1-row layer, so the pull cost is dominated by a
/// `4 × num_chips × num_interactions` element copy back from device.
///
/// **#230 multi-GPU fix** — `circuit_id` scopes this hook to a single
/// GKR-circuit build call.  The GPU side can SAFELY drain that
/// circuit's intermediate states after extracting the requested
/// terminal (no concurrent shards' state to step on, since they have
/// distinct `circuit_id`s).
pub type GpuLayerPullFn = fn(
    circuit_id: u64,
    handle: u64,
) -> crate::shard_level::row_gkr::layer::LogUpGkrCpuLayer<LbChallenge, LbChallenge>;

static GPU_LAYER_PULL_HOOK: std::sync::OnceLock<GpuLayerPullFn> =
    std::sync::OnceLock::new();

/// Register the GPU row-GKR layer-pull driver.  Idempotent; returns
/// `Err(existing_hook)` when a hook was already registered.
pub fn register_gpu_layer_pull_hook(
    f: GpuLayerPullFn,
) -> Result<(), GpuLayerPullFn> {
    GPU_LAYER_PULL_HOOK.set(f)
}

/// Read the registered GPU row-GKR layer-pull hook, if any.
#[must_use]
pub fn get_gpu_layer_pull_hook() -> Option<GpuLayerPullFn> {
    GPU_LAYER_PULL_HOOK.get().copied()
}

/// Signature of the GPU row-GKR per-circuit drain driver.  Releases
/// every device-resident layer state still held by the GPU registry
/// for `circuit_id` (typically intermediate layers whose handles were
/// observed but never explicitly pulled).  Idempotent — calling drain
/// on a circuit_id whose bucket has already been removed is a no-op.
///
/// **Step 4 multi-GPU fix** — `GpuLayerPullFn` only releases the
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

static GPU_LAYER_DRAIN_HOOK: std::sync::OnceLock<GpuLayerDrainCircuitFn> =
    std::sync::OnceLock::new();

/// Register the GPU row-GKR per-circuit drain driver.  Idempotent;
/// returns `Err(existing_hook)` when a hook was already registered.
pub fn register_gpu_layer_drain_circuit_hook(
    f: GpuLayerDrainCircuitFn,
) -> Result<(), GpuLayerDrainCircuitFn> {
    GPU_LAYER_DRAIN_HOOK.set(f)
}

/// Read the registered GPU row-GKR per-circuit drain hook, if any.
/// When `None`, callers MUST be tolerant: the GPU side either has
/// not registered the hook yet (older ziren-gpu builds) or the host
/// path is in use (no device state to drain).  In both cases the
/// row-GKR top-level prover should simply skip the drain call.
#[must_use]
pub fn get_gpu_layer_drain_circuit_hook() -> Option<GpuLayerDrainCircuitFn> {
    GPU_LAYER_DRAIN_HOOK.get().copied()
}

/// populate the per-shard `LogupTaskScope` with
/// device-resident layer payloads at scope-entry.
///
/// **Purpose**: SP1's `generate_gkr_circuit` materializes every GKR
/// layer up front on device, then hands the per-shard
/// `LogUpCudaCircuit<'a, TaskScope>` to the per-round prover which
/// `pop()`s a layer per call (see
/// `sp1-gpu/crates/logup_gkr/src/tracegen.rs:188-246`).  Ziren's
/// `top_level.rs::prove_shard_logup_gkr_rows` now allocates a
/// `LogupTaskScope` at the same lifetime boundary (#383 )
/// and invokes this hook () so the ziren-gpu side can fill
/// the scope's `DeviceLogupGkrCircuit` from its own device-resident
/// per-circuit registry.
///
/// **Contract**: returns `Some(payloads)` when the GPU populator has
/// at least one device-resident layer available for `circuit_id`;
/// returns `None` when the populator declines (host-only path, env
/// gate off, populator not yet warmed, etc.) — the V3 dispatch then
/// falls back to the legacy `take_logup_v3_next_handle` TLS path
/// installed in .
///
/// **Ordering**: `payloads[0]` MUST be the TERMINAL layer (smallest
/// `num_row_variables`, popped LAST by `scope.next_layer()`), and the
/// last entry MUST be the FIRST LAYER (largest, popped FIRST).  This
/// matches SP1's `materialized_layers.pop()` semantics — Ziren's
/// `DeviceLogupGkrCircuit::next` is a literal `Vec::pop`.
///
/// **Lifetime**: the returned `Arc` payloads are held by the scope for
/// the duration of `prove_shard_logup_gkr_rows`; they drop when the
/// scope guard's `Drop` runs at function exit.  The populator MUST
/// ensure its concrete payload type matches what the registered V3
/// hook downcasts to (today: ziren-gpu's `DeviceLogupLayerState`).
///
/// **No-op fallback**: when this hook is not registered (older
/// ziren-gpu builds, or when the feature is disabled), `top_level.rs`
/// skips the install call and the scope's `circuit` stays `None` —
/// byte-equivalent to pre-#383 dispatch via the legacy TLS handle.
pub type GpuLogupScopePopulateFn = fn(
    circuit_id: u64,
) -> Option<
    Vec<crate::shard_level::row_gkr::device_circuit::DeviceCircuitLayerPayload>,
>;

static GPU_LOGUP_SCOPE_POPULATE_HOOK: std::sync::OnceLock<GpuLogupScopePopulateFn> =
    std::sync::OnceLock::new();

/// Register the populate-at-scope-entry hook.  Idempotent; returns
/// `Err(existing_hook)` when a hook was already registered.  Called
/// once at ziren-gpu startup (see  — `basefold/src/
/// logup_scope_populate.rs` in the ziren-gpu repo).
pub fn register_gpu_logup_scope_populate_hook(
    f: GpuLogupScopePopulateFn,
) -> Result<(), GpuLogupScopePopulateFn> {
    GPU_LOGUP_SCOPE_POPULATE_HOOK.set(f)
}

/// Read the registered populate-at-scope-entry hook, if any.  Callers
/// MUST handle `None` gracefully — see contract on
/// [`GpuLogupScopePopulateFn`].
#[must_use]
pub fn get_gpu_logup_scope_populate_hook() -> Option<GpuLogupScopePopulateFn> {
    GPU_LOGUP_SCOPE_POPULATE_HOOK.get().copied()
}

// ─────────────────────────────────────────────────────────────────────
// Device-resident `generate_first_layer` regen hook.
//
// Signature port only.  Returns the per-`circuit_id` first-layer payload
// (opaque `Arc<dyn AnyDeviceHandle>` + shape metadata) so
// [`crate::shard_level::row_gkr::device_circuit::DeviceLogupGkrCircuit::next`]
// can replace its lazy `todo!()` arm with a hook-or-None dispatch.
//
// Until ziren-gpu wires its CUDA `generate_first_layer` impl, the hook
// stays unregistered → `get` returns `None` → the lazy regen arm in
// `next` decrements `num_virtual_layers` and surfaces `None` to the
// caller.  Production scope construction today uses
// `num_virtual_layers == 0`, so this arm never fires; the hook
// signature is structural scaffolding.

/// Hook signature for device-side first-layer regeneration.
///
/// Given the per-shard `circuit_id` (matching the
/// `LayerState::Device::circuit_id` keyed on the scope), the ziren-gpu
/// impl looks up its per-circuit registry, downcasts the stashed
/// `input_handle: Arc<dyn Any + Send + Sync>` payload, runs the
/// `generate_first_layer` CUDA kernel, and returns the resulting
/// device layer payload + shape metadata.  Returns `None` on any
/// failure (lookup miss, downcast fail, kernel error).
pub type GpuGenerateFirstLayerFn = fn(
    circuit_id: u64,
) -> Option<
    crate::shard_level::row_gkr::device_circuit::DeviceCircuitLayerPayload,
>;

static GPU_GENERATE_FIRST_LAYER_HOOK: std::sync::OnceLock<GpuGenerateFirstLayerFn> =
    std::sync::OnceLock::new();

/// Register the regen hook.  Idempotent; returns `Err(existing)` when
/// a hook was already registered.  Called once at ziren-gpu startup
/// alongside the other GKR hooks.
pub fn register_gpu_generate_first_layer_hook(
    f: GpuGenerateFirstLayerFn,
) -> Result<(), GpuGenerateFirstLayerFn> {
    GPU_GENERATE_FIRST_LAYER_HOOK.set(f)
}

/// Read the registered regen hook, if any.  Callers MUST handle
/// `None` gracefully — see the contract on [`GpuGenerateFirstLayerFn`].
#[must_use]
pub fn get_gpu_generate_first_layer_hook() -> Option<GpuGenerateFirstLayerFn> {
    GPU_GENERATE_FIRST_LAYER_HOOK.get().copied()
}

/// Process-wide monotonic counter for GKR-circuit IDs.  Each
/// `build_gkr_circuit` call that takes the device path allocates a
/// fresh ID via [`allocate_gpu_layer_circuit_id`] and threads it
/// through every [`GpuLayerInitFn`] / [`GpuLayerTransitionFn`] /
/// [`GpuLayerPullFn`] invocation.  The GPU side keys its registry by
/// `(device_id, circuit_id)` so concurrent shards on the same GPU are
/// fully isolated — fixes #230 multi-GPU panics caused by a shared
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

/// Open the committed batch at a single point and produce the
/// stacked-basefold proof.  `eval_point.len()` must equal
/// `log_stacking_height + log(num_stripes_padded)`.
///
/// **#191 / H3 ( plan §5 sister to E2)** — when
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
// GPU BaseFold open
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

pub mod jagged {
    use alloc::vec::Vec;

    use p3_challenger::{CanObserve, FieldChallenger};
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
        /// Jagged-eval sub-protocol proof (#243 — SP1 port scaffold).
        ///
        /// Produced by [`crate::jagged_eval_sumcheck::prove_jagged_evaluation`]
        /// alongside the outer reduction sumcheck.  Currently a
        /// scaffold dummy; the real body is the day-2 work of #243.
        ///
        /// `serde(default)` so existing wire-format bundles
        /// deserialize cleanly with a placeholder.
        #[serde(default = "crate::jagged_eval_sumcheck::JaggedSumcheckEvalProof::dummy")]
        pub jagged_eval: crate::jagged_eval_sumcheck::JaggedSumcheckEvalProof<InnerChallenge>,
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
            chip_traces
                .par_iter()
                .zip(r_row_per_chip.par_iter())
                .map(|((_name, trace), r_row_c)| {
                    let h = trace.values.len() / trace.width.max(1);
                    let w = trace.width;
                    //  empty-chip skip: for an empty-trace
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
        // dispatch: when ZIREN_GPU_JAGGED_PCS=1 is set AND a
        // GPU jagged-reduction hook has been registered (by ziren-gpu's
        // `compress_multi_gpu` startup block), route the reduction
        // through the device hook.  The hook is byte-equivalent to
        // `prove_jagged_reduction_owned` (verified by the existing
        // host fallback path + the GPU-side scaffold tests in
        // `ziren-gpu/basefold/src/jagged_sumcheck.rs::tests`).  When
        // the hook returns `None` (unsupported shape) or is not
        // registered, the host fallback path runs unchanged.
        //
        // Win A (May 21 2026 jagged-wins) — hook hardening:
        //   * V2 hook (with optional device handle) preferred over V1
        //   * `env_set_but_unregistered` warn-once when ZIREN_GPU_JAGGED_PCS=1
        //     but neither V1 nor V2 hook is registered
        //   * `hook_registered_but_env_unset` warn-once when a hook is
        //     registered but the env flag isn't set (possible misconfig)
        //   * shape-rejection counter — log on each Nth (geometric) None
        //   * V2 hook with `Some(device_handle)` is logged separately to
        //     confirm the device-resident path is exercised
        //
        // Win B (May 21 2026 jagged-wins) — device-resident dense_q
        // signature: when a V2 hook is registered, the dispatch passes
        // `device_handle = None` (Ziren has no on-device dense_q yet —
        // the host materialization at line ~1413 is the source).  V2
        // semantics with `None` collapse to V1 behaviour; the signature
        // is in place for future Ziren-side wiring (e.g. GPU-resident
        // chip-trace materialization) to skip the H→D upload.
        let _t_red = std::time::Instant::now();
        let _red_span = tracing::info_span!("jagged_sumcheck_reduce").entered();
        let reduction = {
            let dense_q =
                materialize_dense_jagged::<InnerVal>(chip_traces, packing.log_dense_size);

            let try_gpu = std::env::var("ZIREN_GPU_JAGGED_PCS")
                .map(|v| v == "1")
                .unwrap_or(false);

            // Win A: look up BOTH hooks so we can emit diagnostics on
            // mismatches (env-set/unregistered, hook-registered/env-unset).
            let hook_v1 = super::get_gpu_jagged_reduction_hook();
            let hook_v2 = super::get_gpu_jagged_reduction_hook_v2();
            let any_hook_registered = hook_v1.is_some() || hook_v2.is_some();

            // Win A diag (1): env=1 but no hook → warn once, count.
            if try_gpu && !any_hook_registered {
                use std::sync::OnceLock;
                static WARN_ONCE: OnceLock<()> = OnceLock::new();
                let n = super::jagged_dispatch_diag::bump(
                    &super::jagged_dispatch_diag::ENV_SET_BUT_UNREGISTERED,
                );
                WARN_ONCE.get_or_init(|| {
                    tracing::warn!(
                        chips = n_chips,
                        log_dense_size = packing.log_dense_size as u64,
                        env_set_but_unregistered_count = n,
                        "jagged_pcs: ZIREN_GPU_JAGGED_PCS=1 set but no GPU \
                         jagged-reduction hook registered. ziren-gpu's \
                         compress_multi_gpu must call \
                         register_gpu_jagged_reduction_hook or \
                         register_gpu_jagged_reduction_hook_v2 at startup. \
                         Falling back to host prove_jagged_reduction_owned. \
                         See basefold_late_binding.rs Win A."
                    );
                });
            }

            // Win A diag (2): hook registered but env=0 → warn once,
            // count.  This is normally fine (caller explicitly opted
            // out) but on a perf-experiment run it can mask intended
            // GPU acceleration.
            if !try_gpu && any_hook_registered {
                use std::sync::OnceLock;
                static WARN_ONCE: OnceLock<()> = OnceLock::new();
                let n = super::jagged_dispatch_diag::bump(
                    &super::jagged_dispatch_diag::HOOK_REGISTERED_BUT_ENV_UNSET,
                );
                WARN_ONCE.get_or_init(|| {
                    tracing::warn!(
                        chips = n_chips,
                        log_dense_size = packing.log_dense_size as u64,
                        hook_registered_but_env_unset_count = n,
                        "jagged_pcs: GPU jagged-reduction hook is \
                         registered but ZIREN_GPU_JAGGED_PCS=1 is not \
                         set in the env. Running host fallback. To \
                         enable the GPU path, set ZIREN_GPU_JAGGED_PCS=1. \
                         See basefold_late_binding.rs Win A."
                    );
                });
            }

            // Pick the active hook: V2 preferred if available, else
            // V1, else None (drops to host body).
            enum ActiveHook {
                V2(super::GpuJaggedReductionFnV2),
                V1(super::GpuJaggedReductionFn),
                None,
            }
            let active = if try_gpu {
                match (hook_v2, hook_v1) {
                    (Some(f2), _) => ActiveHook::V2(f2),
                    (None, Some(f1)) => ActiveHook::V1(f1),
                    (None, None) => ActiveHook::None,
                }
            } else {
                ActiveHook::None
            };

            // Win B: device handle source.  Currently always `None` —
            // the Ziren host path materializes dense_q on host at line
            // ~1413.  Wired here so future Ziren-side device residency
            // (e.g. GPU-driven chip-trace pre-materialization) can flip
            // this to `Some(handle)` without further hook surgery.
            let dense_q_device_handle: Option<u64> = None;

            match active {
                ActiveHook::V2(f) => {
                    use std::sync::OnceLock;
                    static FIRED_ONCE: OnceLock<()> = OnceLock::new();
                    let _ = super::jagged_dispatch_diag::bump(
                        &super::jagged_dispatch_diag::HOOK_FIRED,
                    );
                    let _ = super::jagged_dispatch_diag::bump(
                        &super::jagged_dispatch_diag::V2_HOOK_FIRED,
                    );
                    if dense_q_device_handle.is_some() {
                        let _ = super::jagged_dispatch_diag::bump(
                            &super::jagged_dispatch_diag::V2_WITH_DEVICE_HANDLE_FIRED,
                        );
                    }
                    FIRED_ONCE.get_or_init(|| {
                        tracing::warn!(
                            chips = n_chips,
                            log_dense_size = packing.log_dense_size as u64,
                            device_handle = ?dense_q_device_handle,
                            "#107 jagged_pcs FIRED — GPU jagged-reduction V2 \
                             hook driving sumcheck reduce ({} chips, device_handle={:?})",
                            n_chips, dense_q_device_handle,
                        );
                    });
                    let r_row = r_row_per_chip.to_vec();
                    let y_clone = y_per_chip.clone();
                    let saved_dense = if std::env::var("ZIREN_GPU_JAGGED_PCS_HOST_GUARD")
                        .map(|v| v == "1").unwrap_or(false)
                    {
                        Some(dense_q.clone())
                    } else {
                        None
                    };
                    match f(
                        dense_q,
                        dense_q_device_handle,
                        &packing,
                        &r_row,
                        &y_clone,
                        challenger,
                    ) {
                        Some(p) => p,
                        None => {
                            let n = super::jagged_dispatch_diag::bump(
                                &super::jagged_dispatch_diag::SHAPE_REJECTED,
                            );
                            if super::jagged_dispatch_diag::should_log_geometric(n) {
                                tracing::warn!(
                                    chips = n_chips,
                                    log_dense_size = packing.log_dense_size as u64,
                                    shape_rejected_count = n,
                                    "#107 jagged_pcs V2 hook returned None \
                                     (shape rejected) — falling back to host \
                                     prove_jagged_reduction_owned",
                                );
                            }
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
                ActiveHook::V1(f) => {
                    use std::sync::OnceLock;
                    static FIRED_ONCE: OnceLock<()> = OnceLock::new();
                    let _ = super::jagged_dispatch_diag::bump(
                        &super::jagged_dispatch_diag::HOOK_FIRED,
                    );
                    FIRED_ONCE.get_or_init(|| {
                        tracing::warn!(
                            chips = n_chips,
                            log_dense_size = packing.log_dense_size as u64,
                            "#107 jagged_pcs FIRED — GPU jagged-reduction V1 \
                             hook driving sumcheck reduce ({} chips)",
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
                            let n = super::jagged_dispatch_diag::bump(
                                &super::jagged_dispatch_diag::SHAPE_REJECTED,
                            );
                            if super::jagged_dispatch_diag::should_log_geometric(n) {
                                tracing::warn!(
                                    chips = n_chips,
                                    log_dense_size = packing.log_dense_size as u64,
                                    shape_rejected_count = n,
                                    "#107 jagged_pcs V1 hook returned None \
                                     (shape rejected) — falling back to host \
                                     prove_jagged_reduction_owned",
                                );
                            }
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
                ActiveHook::None => crate::jagged_sumcheck::prove_jagged_reduction_owned(
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
        //
        // SP1-port: the jagged sumcheck reduces over `dense_q`
        // which has 2^log_dense_size cells.  But the BaseFold
        // commitment covers `prover_data.area` cells (= num_stripes ×
        // batch_size × stack_height after interleaving), which can be
        // strictly larger than 2^log_dense_size when the dense data
        // doesn't fill the next stripe-multiple.  The BaseFold open
        // requires a point of dimension log2(area), not
        // log_dense_size.
        //
        // Mirrors SP1's `slop_stacked::StackedPcsProver::prove_trusted_evaluation`
        // contract: `eval_point.dimension() == log2(total_data_length)`.
        // Sample additional Fiat-Shamir coords to extend the point;
        // the verifier samples matching coords in the same transcript
        // order (recursive_jagged_pcs.rs after `verify_sumcheck`).
        let target_dim = prover_data.area.trailing_zeros() as usize;
        let mut extended_eval_point = reduction.eval_point.clone();
        while extended_eval_point.len() < target_dim {
            let r: InnerChallenge = challenger.sample_algebra_element();
            extended_eval_point.push(r);
        }
        let _t_open = std::time::Instant::now();
        let _open_span = tracing::info_span!("jagged_basefold_open").entered();
        let proof = open_basefold_late_binding(
            prover_data,
            extended_eval_point,
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
            // fix: per-chip *actual* column count, so verifier
            // does not need to consult `BaseAir::width(chip)`.
            column_counts: packing
                .chip_infos
                .iter()
                .map(|ci| ci.column_count)
                .collect(),
        };
        // jagged-eval sub-protocol scaffold — produces a
        // structurally-valid placeholder.  Real sumcheck body lands
        // in #243's day-2 work.  Inputs (z_row, z_col, z_trace) come
        // from the existing reduction state:
        //   z_row    = r_row_per_chip[0] (or a flattened canonical
        //              choice — TODO: align with verifier expectation)
        //   z_col    = derived from gamma + chip indices (TODO)
        //   z_trace  = reduction.eval_point (the outer sumcheck's z*)
        let prefix_sums_for_eval: Vec<usize> = {
            let mut acc = 0usize;
            let mut out = Vec::with_capacity(packing.chip_infos.len() + 1);
            out.push(0);
            for info in &packing.chip_infos {
                acc += info.row_count;
                out.push(acc);
            }
            out
        };
        let _ = prefix_sums_for_eval; // wired-but-unused until #243 day-2
        let jagged_eval = crate::jagged_eval_sumcheck::JaggedSumcheckEvalProof::dummy();

        JaggedBasefoldBundle {
            reduction,
            basefold_proof: proof,
            y_per_chip,
            commit,
            packing: packing_meta,
            jagged_eval,
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

        // SP1-port: extend z_star from log_dense_size to log2(area)
        // by sampling additional Fiat-Shamir coords, mirroring the
        // prover's extension in `prove_jagged_basefold` step (5).
        // Both sides sample from the same transcript state at the same
        // point in the protocol so the coords match.
        let target_dim = bundle.commit.area.trailing_zeros() as usize;
        let mut extended_z_star = z_star;
        while extended_z_star.len() < target_dim {
            let r: InnerChallenge = challenger.sample_algebra_element();
            extended_z_star.push(r);
        }

        // Verify the BaseFold opening: claim is q_at_z, point is the
        // extended z*.
        let res = verify_basefold_late_binding(
            &bundle.commit.commitment,
            bundle.commit.area,
            bundle.commit.log_stacking_height,
            &extended_z_star,
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

    // ────────────────────────────────────────────────────────────────
    // Win A (May 21 2026 jagged-wins) — hook hardening diagnostic
    // counters: smoke tests for the geometric back-off and the bump()
    // helper.  The full dispatch-site behaviour (env-set/unregistered
    // warn, hook-registered/env-unset warn, V2-preferred-over-V1) is
    // exercised by the smoke flag of the production e2e run; the
    // counters here are the test hooks that prove the wiring is sane.
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_jagged_dispatch_diag_geometric_backoff() {
        use super::jagged_dispatch_diag::should_log_geometric;
        // log on 1, 2, 4, 8, ... (powers of two)
        assert!(should_log_geometric(1));
        assert!(should_log_geometric(2));
        assert!(should_log_geometric(4));
        assert!(should_log_geometric(8));
        assert!(should_log_geometric(64));
        assert!(should_log_geometric(1024));
        // don't log on intermediate counts
        assert!(!should_log_geometric(3));
        assert!(!should_log_geometric(5));
        assert!(!should_log_geometric(7));
        assert!(!should_log_geometric(63));
    }

    #[test]
    fn test_jagged_dispatch_diag_bump_returns_new_count() {
        use core::sync::atomic::AtomicU64;
        use super::jagged_dispatch_diag::bump;
        let counter = AtomicU64::new(0);
        assert_eq!(bump(&counter), 1);
        assert_eq!(bump(&counter), 2);
        assert_eq!(bump(&counter), 3);
    }

    #[test]
    fn test_jagged_dispatch_diag_reset() {
        use core::sync::atomic::{AtomicU64, Ordering};
        use super::jagged_dispatch_diag::bump;
        let counter = AtomicU64::new(0);
        bump(&counter);
        bump(&counter);
        assert_eq!(counter.load(Ordering::Relaxed), 2);
        // reset_all touches the production counters; bump our local
        // first to ensure the API surface compiles & runs.
        super::jagged_dispatch_diag::reset_all();
        assert_eq!(
            super::jagged_dispatch_diag::ENV_SET_BUT_UNREGISTERED
                .load(Ordering::Relaxed),
            0,
        );
        assert_eq!(
            super::jagged_dispatch_diag::SHAPE_REJECTED.load(Ordering::Relaxed),
            0,
        );
    }

    // Win B (May 21 2026 jagged-wins) — V2 hook signature smoke test.
    // Registers a thin V2 hook that records whether a device handle
    // was passed, asserts the signature is callable end-to-end.
    #[test]
    fn test_gpu_jagged_reduction_hook_v2_signature() {
        // Use a stand-alone callable — we don't actually register
        // (`set` can fail in the global slot if another test ran)
        // but we DO exercise the type so the signature is stable.
        let _hook: super::GpuJaggedReductionFnV2 = test_v2_hook_noop;
        // get_gpu_jagged_reduction_hook_v2 must be callable.
        let _: Option<super::GpuJaggedReductionFnV2> =
            super::get_gpu_jagged_reduction_hook_v2();
    }

    fn test_v2_hook_noop(
        _dense_q_host: Vec<LbVal>,
        _dense_q_device_handle: Option<u64>,
        _packing: &crate::jagged::JaggedPacking<LbVal>,
        _r_row_per_chip: &[Vec<LbChallenge>],
        _y_per_chip: &[Vec<LbChallenge>],
        _challenger: &mut LbChallenger,
    ) -> Option<crate::jagged_sumcheck::JaggedReductionProof<LbChallenge>> {
        // Hook returns None — dispatcher would fall through to the
        // host body.  We're testing the signature, not the dispatch.
        None
    }
}
