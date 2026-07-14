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
//! Option-C divergence has since retired the "provider-carried" eval-at ops
//! (the former `GPU_EVAL_AT_PROVIDER` / `GPU_EVAL_AT_BATCH_PROVIDER` slots) and
//! the two per-layer logup-round drivers (the former `GPU_LOGUP_ROUND_HOOK` /
//! `GPU_LOGUP_ROUND_HOOK_DEVICE_FOLD` slots): the GPU prover diverged to
//! device-native drivers (`device_logup_gkr` / `device_gkr_circuit`) that call
//! the underlying `zkm-gpu-core` kernels DIRECTLY, so the shared host
//! `prove_shard_logup_gkr_rows` / `prove_gkr_round` those seams dispatched from
//! are now CpuProver-only (`is_device()` == `false`) and the device arms were
//! dead.  What remains is the P6 zerocheck host-cell y-tuple family, still fired
//! by the MULTI-GPU route, which delegates to the shared host
//! `prove_shard_zerocheck` threaded with `CudaShardDeviceOps`.
//!
//! The full-trace materialize op is NOT here: it is a pure device-trace-provider
//! query (it downcasts the provider and pulls the chip's trace), consumed on the
//! deep cross-crate jagged reduce/open edges where only the provider is threaded,
//! so it lives on
//! [`crate::shard_level::DeviceTraceProvider::materialize_main_trace`].

use alloc::vec::Vec;

/// `Ef4` — the KoalaBear degree-4 binomial extension, the concrete
/// challenge field of the KoalaBear jagged-PCS config; the device ops
/// carry it explicitly (the former hook fn-ptrs did, so the device impls
/// stay byte-equivalent).
type Ef4 = p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>;
/// `Kb` — KoalaBear, the base field of the same config.
type Kb = p3_koala_bear::KoalaBear;

/// Object-safe device/host dispatch for the shard-level prover's zerocheck
/// y-tuple family (P6) — the SP1-parity static-dispatch collapse of the former
/// `GPU_ZEROCHECK_YTUPLE` / `GPU_ZEROCHECK_BATCHED_YTUPLE` `OnceLock`
/// registries, carried by `ZeroCheckPoly` (their read sites sit inside trait
/// impls with no prover in scope, so the `&dyn ShardDeviceOps` is carried by the
/// poly rather than threaded positionally).  All methods take `&self` and
/// concrete arg types (no generics) so the trait is object-safe and threads as
/// `&dyn`.
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

    // ── P6: the zerocheck y-tuple family (carried by `ZeroCheckPoly`) ──────
    //
    // The two methods below are the SP1-parity static-dispatch collapse of
    // the former `GPU_ZEROCHECK_YTUPLE` / `GPU_ZEROCHECK_BATCHED_YTUPLE`
    // `OnceLock` hooks.  They are read INSIDE `ZeroCheckPoly`'s
    // `SumcheckPoly`/`ComponentPoly`/first-round impls, whose signatures are
    // fixed by the generic `reduce_sumcheck_to_evaluation` driver (no
    // `&self`-prover in scope), so the `&dyn ShardDeviceOps` is carried by the
    // poly (a `dev` field, threaded through every ctor + fold).  `is_device()`
    // gates each (was the `get_*_hook().is_some()` presence check); the round
    // polynomials the y-tuple feeds are observed into the Fiat-Shamir transcript
    // via `finalize_round_poly`, which stays host, so the transcript is
    // byte-identical to the former global-registry dispatch.

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
}

/// Host device-ops provider: `is_device()` = false, so no device op is
/// ever dispatched and the shard prover walks entirely on host —
/// byte-identical to the pre-hook unregistered-`OnceLock` path.
pub struct NoDeviceOps;

impl ShardDeviceOps for NoDeviceOps {}
