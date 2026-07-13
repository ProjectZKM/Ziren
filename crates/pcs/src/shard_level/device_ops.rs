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
/// registries).  All methods take `&self` and concrete arg types (no
/// generics) so the trait is object-safe and threads as `&dyn`.
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
}

/// Host device-ops provider: `is_device()` = false, so no device op is
/// ever dispatched and the shard prover walks entirely on host —
/// byte-identical to the pre-hook unregistered-`OnceLock` path.
pub struct NoDeviceOps;

impl ShardDeviceOps for NoDeviceOps {}
