//! The unified object-safe device seam for the shard-level prover.
//!
//! `ShardDeviceOps` is the SP1-parity static-dispatch collapse of the
//! former process-global `OnceLock` GPU-hook registries (the
//! `gpu_hook_accessors!` slots in [`crate::shard_level::sumcheck_poly`]).
//! Instead of a device build REGISTERING a fn-ptr into a global that the
//! host prover consults per call, the prover TYPE selects the impl and it
//! is threaded `&dyn` positionally, exactly as the reduce/open
//! `JaggedReducer`/`JaggedOpener` and the Phase-4
//! `FirstRoundProvider`/`DrainProvider`/`GkrDeviceProvider` slices do:
//!
//!   * the host build threads [`NoDeviceOps`] (`is_device()` = `false`,
//!     the device methods are `unreachable!()` because they are gated by
//!     `is_device()`), so the shard prover walks byte-identically to the
//!     pre-hook host path;
//!   * the GPU core prover overrides `prove_shard_to_basefold` and threads
//!     its own `CudaShardDeviceOps` (in `zkm-gpu-core`) whose methods
//!     forward VERBATIM to the same device fns the `register_*` hooks used
//!     to install — same kernels, same marshaling, same `TypeId`/transmute
//!     guards — so the device walk is byte-equivalent too.
//!
//! This is the reusable seam later phases EXTEND with the remaining
//! Category-B device ops; the five original slots collapsed here are the
//! "provider-carried" ones read where a `&dyn DeviceTraceProvider` is
//! already threaded.  The full-trace materialize op is NOT here: it is a
//! pure device-trace-provider query (it downcasts the provider and pulls
//! the chip's trace), it is consumed on the deep cross-crate jagged
//! reduce/open edges where only the provider is threaded, so it lives on
//! [`crate::shard_level::DeviceTraceProvider::materialize_main_trace`]
//! (strictly lower threading-churn, semantically the provider's job).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use crate::shard_level::DeviceTraceProvider;

/// `Ef4` — the KoalaBear degree-4 binomial extension, the concrete
/// challenge field of the KoalaBear jagged-PCS config; the device ops
/// carry it explicitly (the former hook fn-ptrs did, so the device impls
/// stay byte-equivalent).
type Ef4 = p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>;
/// `Kb` — KoalaBear, the base field of the same config.
type Kb = p3_koala_bear::KoalaBear;

/// Object-safe device/host dispatch for the shard-level prover's
/// "provider-carried" device ops (the SP1-parity static-dispatch collapse
/// of the former `GPU_EVAL_AT_PROVIDER` / `GPU_EVAL_AT_BATCH_PROVIDER` /
/// `GPU_INTERACTION_EVAL` / `GPU_ZEROCHECK_PREPARE_CELLS` `OnceLock`
/// registries) plus (P6) the zerocheck y-tuple family
/// (`GPU_ZEROCHECK_YTUPLE` / `_YTUPLE_DEVICE` / `_FOLD_DEVICE` /
/// `_BATCHED_YTUPLE` / `_EXTRACT_FINAL`), the latter carried by
/// `ZeroCheckPoly`, plus (P7) the logup-round sumcheck family
/// (`GPU_SUMCHECK` / `GPU_CHIP_STRUCTURED_SUMCHECK` /
/// `GPU_CHIP_STRUCTURED_SUMCHECK_DEVICE`), carried by
/// `LogupRoundPolynomial` — both carried rather than threaded positionally
/// (their read sites sit inside trait impls with no prover in scope), plus
/// (P8) the two per-layer logup-round device drivers (`GPU_LOGUP_ROUND_HOOK` /
/// `GPU_LOGUP_ROUND_HOOK_DEVICE_FOLD`), threaded POSITIONALLY into
/// `prove_gkr_round` (where the per-shard `dev` is already in scope).  All
/// methods take `&self`
/// and concrete arg types (no generics) so the trait is object-safe and
/// threads as `&dyn`.
///
/// `is_device()` gates every device op (it replaces the former
/// `get_gpu_*_hook().is_some()` presence check); on the host it is `false`
/// and the device methods are never reached.  The GPU impl overrides
/// `is_device()` to `true` and provides real bodies.
pub trait ShardDeviceOps: Send + Sync {
    /// `true` for the device ops provider — gates every device op below
    /// (was the `get_gpu_*_hook().is_some()` presence check).  Host
    /// default = `false`, so the shard prover takes the pre-hook host path.
    fn is_device(&self) -> bool {
        false
    }

    /// Per-chip `eval_at` via the per-shard device-trace provider, for a
    /// device-only chip with NO host main trace (was
    /// `GPU_EVAL_AT_PROVIDER`).  Returns one `Ef4` per column, or `None`
    /// (caller emits the legacy zero vector).  Only called under
    /// `is_device()`.
    fn eval_at_provider(
        &self,
        _chip_name: &str,
        _eval_point: &[Ef4],
        _device_traces: &dyn DeviceTraceProvider,
    ) -> Option<Vec<Ef4>> {
        unreachable!("host ShardDeviceOps::eval_at_provider — gated by is_device()")
    }

    /// BATCHED per-chip `eval_at` via the provider: one call resolves every
    /// device-only chip at its eval-point, building one eq-table per
    /// distinct point (was `GPU_EVAL_AT_BATCH_PROVIDER`).  `results[i]` is
    /// `Some(per-column Ef4)` for resolved chips, `None` otherwise.  Only
    /// called under `is_device()`.
    fn eval_at_batch_provider(
        &self,
        _requests: &[String],
        _eval_points: &[Vec<Ef4>],
        _device_traces: &dyn DeviceTraceProvider,
    ) -> Vec<Option<Vec<Ef4>>> {
        unreachable!("host ShardDeviceOps::eval_at_batch_provider — gated by is_device()")
    }

    /// Per-chip LogUp-GKR phase-2 interaction-table builder (was
    /// `GPU_INTERACTION_EVAL`).  Returns `(numer, denom)` row-major, or
    /// `None` to fall back to host.  Only called under `is_device()`.
    #[allow(clippy::too_many_arguments)]
    fn interaction_eval(
        &self,
        _chip_name: &str,
        _main_row_major: &[Kb],
        _main_width: usize,
        _preprocessed_row_major: &[Kb],
        _preprocessed_width: usize,
        _alpha: Ef4,
        _betas: &[Ef4],
        _device_traces: Option<&dyn DeviceTraceProvider>,
    ) -> Option<(Vec<Kb>, Vec<Ef4>)> {
        unreachable!("host ShardDeviceOps::interaction_eval — gated by is_device()")
    }

    /// Device-fold: bit-reverse + prepare the provider trace once into the
    /// device-cell handle the ZeroCheckPoly carries (was
    /// `GPU_ZEROCHECK_PREPARE_CELLS`).  Args: the erased round-0 device
    /// cells, the chip's preprocessed cells (column-major, provider
    /// height) + prep width, and the per-shard `dense_rev` orientation.
    /// Returns the erased prepared handle, or `None` to fall back.  Only
    /// called under `is_device()`.
    fn zerocheck_prepare_cells(
        &self,
        _cells: &(dyn Any + Send + Sync),
        _prep_cells: &[Kb],
        _num_prep_cols: usize,
        _dense_rev: bool,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        unreachable!("host ShardDeviceOps::zerocheck_prepare_cells — gated by is_device()")
    }

    // ── P6: the zerocheck y-tuple family (carried by `ZeroCheckPoly`) ──────
    //
    // The five methods below are the SP1-parity static-dispatch collapse of
    // the former `GPU_ZEROCHECK_YTUPLE` / `GPU_ZEROCHECK_YTUPLE_DEVICE` /
    // `GPU_ZEROCHECK_FOLD_DEVICE` / `GPU_ZEROCHECK_BATCHED_YTUPLE` /
    // `GPU_ZEROCHECK_EXTRACT_FINAL` `OnceLock` hooks.  They are read INSIDE
    // `ZeroCheckPoly`'s `SumcheckPoly`/`ComponentPoly`/first-round impls,
    // whose signatures are fixed by the generic `reduce_sumcheck_to_evaluation`
    // driver (no `&self`-prover in scope), so the `&dyn ShardDeviceOps` is
    // carried by the poly (a `dev` field, threaded through every ctor + fold).
    // `is_device()` gates each (was the `get_*_hook().is_some()` presence
    // check); the round polynomials the y-tuple feeds are observed into the
    // Fiat-Shamir transcript via `finalize_round_poly`, which stays host, so
    // the transcript is byte-identical to the former global-registry dispatch.

    /// Per-chip per-round zerocheck y-tuple from HOST cells (was
    /// `GPU_ZEROCHECK_YTUPLE`).  Returns `(y_0, y_2, y_3, y_4)` — the per-pair
    /// eq-weighted accumulators mirroring `accumulate_y_tuple_host`, BEFORE
    /// the `finalize_round_poly` scaling (which stays host).  `main_cells` /
    /// `prep_cells` are the current folded `Ef4` rows (row-major
    /// `num_real × width`, bit-reversed on round 0); `gkr_powers` is the
    /// main-then-prep batch-power vector; `eq = partial_lagrange(zeta[..dim-1])`.
    /// `None` on chip-reject → host fallback.  Only called under `is_device()`.
    #[allow(clippy::too_many_arguments)]
    fn zerocheck_ytuple(
        &self,
        _chip_name: &str,
        _main_cells: &[Ef4],
        _num_main_cols: usize,
        _prep_cells: &[Ef4],
        _num_prep_cols: usize,
        _gkr_powers: &[Ef4],
        _alpha: Ef4,
        _eq: &[Ef4],
        _public_values: &[Kb],
        _num_real: usize,
        _is_first_round: bool,
    ) -> Option<[Ef4; 4]> {
        unreachable!("host ShardDeviceOps::zerocheck_ytuple — gated by is_device()")
    }

    /// Per-chip per-round y-tuple from DEVICE-resident cells (no host upload;
    /// was `GPU_ZEROCHECK_YTUPLE_DEVICE`).  `dev_cells` is the erased device
    /// handle the `ZeroCheckPoly` carries (`ColMajorMatrixDevice<Felt>` round 0,
    /// `DeviceBuffer<Ef4>` later); the impl downcasts it.  Returns
    /// `(y_0, y_2, y_3, y_4)` or `None` to fall back.  Only called under
    /// `is_device()`.
    #[allow(clippy::too_many_arguments)]
    fn zerocheck_ytuple_device(
        &self,
        _chip_name: &str,
        _dev_cells: &(dyn Any + Send + Sync),
        _num_main_cols: usize,
        _dev_prep: Option<&(dyn Any + Send + Sync)>,
        _num_prep_cols: usize,
        _gkr_powers: &[Ef4],
        _alpha: Ef4,
        _eq: &[Ef4],
        _public_values: &[Kb],
        _num_real: usize,
        _is_first_round: bool,
    ) -> Option<[Ef4; 4]> {
        unreachable!("host ShardDeviceOps::zerocheck_ytuple_device — gated by is_device()")
    }

    /// Fold the device-resident cells on the last variable to `alpha`, on
    /// device (was `GPU_ZEROCHECK_FOLD_DEVICE`).  Returns the new erased
    /// device handle (`DeviceBuffer<Ef4>`); `is_first_round` => current cells
    /// are Felt (round 0) and the fold lifts Felt→Ef4.  `None` to fall back.
    /// Only called under `is_device()`.
    fn zerocheck_fold_device(
        &self,
        _dev_cells: &(dyn Any + Send + Sync),
        _num_cols: usize,
        _num_real: usize,
        _alpha: Ef4,
        _is_first_round: bool,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        unreachable!("host ShardDeviceOps::zerocheck_fold_device — gated by is_device()")
    }

    /// BATCHED per-round y-tuple over ALL real chips in one fused device
    /// launch (chip fusion; was `GPU_ZEROCHECK_BATCHED_YTUPLE`).  One tuple per
    /// input chip in the SAME order; `None` => whole-round host fallback.  Only
    /// called under `is_device()`.
    fn zerocheck_batched_ytuple(
        &self,
        _chips: &[crate::shard_level::sumcheck_poly::ZerocheckChipYTupleInput<'_>],
        _public_values: &[Kb],
        _is_first_round: bool,
    ) -> Option<Vec<[Ef4; 4]>> {
        unreachable!("host ShardDeviceOps::zerocheck_batched_ytuple — gated by is_device()")
    }

    /// Extract the fully-folded per-chip openings (1 row) from the device
    /// cells so the host `get_component_poly_evals` (the trace_at_z openings)
    /// reads the device result (was `GPU_ZEROCHECK_EXTRACT_FINAL`).  A single-
    /// row D2H — cheap.  `None` to fall back.  Only called under `is_device()`.
    fn zerocheck_extract_final(
        &self,
        _dev_cells: &(dyn Any + Send + Sync),
        _num_main_cols: usize,
    ) -> Option<Vec<Ef4>> {
        unreachable!("host ShardDeviceOps::zerocheck_extract_final — gated by is_device()")
    }

    // ── P8: the logup-round device drivers (threaded POSITIONALLY into
    //    `prove_gkr_round`) ─────────────────────────────────────────────
    //
    // The two methods below are the SP1-parity static-dispatch collapse of the
    // former `GPU_LOGUP_ROUND_HOOK` / `GPU_LOGUP_ROUND_HOOK_DEVICE_FOLD`
    // `OnceLock` hooks.  Unlike the P6/P7 poly-carried ops, these fire in
    // `prove_gkr_round` itself (a free fn where the per-shard `dev` is already
    // in scope), so the `&dyn ShardDeviceOps` is threaded POSITIONALLY (deref'd
    // `&**dev` from the P7 `Arc`) into the `try_logup_round_gpu{,_device_fold}`
    // helpers that host the dispatch — no poly field needed.  `is_device()`
    // gates each (was the `get_*_hook().is_some()` presence check); the round
    // polynomials the driver emits are observed/sampled into the caller's live
    // `&mut InnerChallenger` in the SAME transcript order as before (the helpers
    // snapshot for a sound host fallback on a `None` decline), so the
    // Fiat-Shamir transcript is byte-identical to the former global-registry
    // dispatch.  Both retain the SAME concrete arg types the retired fn-ptr
    // aliases used (`Vec<Ef4>`, `DeviceLayerHandle`, `&mut InnerChallenger`,
    // the `&dyn Fn(Ef4)` transcript closures) and the GPU impl forwards VERBATIM
    // to the same fns — same nv28 device-pack logic + cross-round
    // `DeviceLayerHandle` / eq-row-point / chip-meta TLS chain inside the body.

    /// Device-pack per-layer LogUp-GKR round driver (was `GPU_LOGUP_ROUND_HOOK`).
    /// `input` is `None` for the outermost layer's round 0; the `*_flat` vectors
    /// are the host-fallback shape and may be ignored when `input.is_some()`.
    /// Observes/samples into the caller's live challenger.  `None` => GPU
    /// declined; the caller falls back to the host trait driver (transcript
    /// restored).  Only called under `is_device()`.
    #[allow(clippy::too_many_arguments)]
    fn logup_round(
        &self,
        _input: Option<crate::shard_level::sumcheck_poly::DeviceLayerHandle>,
        _n0_flat: Vec<Ef4>,
        _d0_flat: Vec<Ef4>,
        _n1_flat: Vec<Ef4>,
        _d1_flat: Vec<Ef4>,
        _eq_int: Vec<Ef4>,
        _eq_row: Vec<Ef4>,
        _lambda: Ef4,
        _initial_claim: Ef4,
        _num_variables: usize,
        _challenger: &mut crate::InnerChallenger,
    ) -> Option<crate::shard_level::sumcheck_poly::GpuLogupRoundResult> {
        unreachable!("host ShardDeviceOps::logup_round — gated by is_device()")
    }

    /// Device-fold per-layer LogUp-GKR round driver (was
    /// `GPU_LOGUP_ROUND_HOOK_DEVICE_FOLD`).  Drives the transcript via the
    /// `observe_ef` / `sample_ef` closures instead of a concrete challenger
    /// (fn-ptr dispatch could not carry a generic `Challenger`).  `None` => GPU
    /// declined; the caller falls back.  Only called under `is_device()`.
    #[allow(clippy::too_many_arguments)]
    fn logup_round_device_fold(
        &self,
        _n0_flat: Vec<Ef4>,
        _d0_flat: Vec<Ef4>,
        _n1_flat: Vec<Ef4>,
        _d1_flat: Vec<Ef4>,
        _eq_int: Vec<Ef4>,
        _eq_row: Vec<Ef4>,
        _lambda: Ef4,
        _initial_claim: Ef4,
        _num_variables: usize,
        _observe_ef: &dyn Fn(Ef4),
        _sample_ef: &dyn Fn() -> Ef4,
    ) -> Option<crate::shard_level::sumcheck_poly::GpuLogupRoundResult> {
        unreachable!("host ShardDeviceOps::logup_round_device_fold — gated by is_device()")
    }
}

/// Host device-ops provider: `is_device()` = false, so no device op is
/// ever dispatched and the shard prover walks entirely on host —
/// byte-identical to the pre-hook unregistered-`OnceLock` path.
pub struct NoDeviceOps;

impl ShardDeviceOps for NoDeviceOps {}
