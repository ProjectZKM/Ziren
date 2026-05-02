//! GPU device-tracegen dispatch hooks for recursion-core chips
//! (integration #3 in the path-(a) sequence to SP1-class perf).
//!
//! ## Design (mirrors #102 / #103 / #106 / #111)
//!
//! Function-pointer + `OnceLock` pattern: the `ziren-gpu` prover crate
//! registers a concrete-typed device-tracegen implementation at startup;
//! the host `*Chip::generate_trace` checks the hook and, when
//! `ZIREN_GPU_TRACEGEN_DEVICE=1` is set AND `F = KoalaBear`, dispatches
//! through it instead of running the rayon-parallel host fill.
//!
//! This avoids a cyclic Cargo dep between `zkm-recursion-core` and
//! `zkm-gpu-core` — the GPU crate has the kernel + FFI; this crate
//! only stores a function pointer that the GPU crate registers.
//!
//! ## Why integration #3 starts here
//!
//! ziren-gpu already has the CUDA kernel + `DeviceAir` impls for
//! `SelectChip` (and 6 other recursion chips); see
//! `cuda/tracegen/recursion.cuh::recursion_select_generate_trace_kernel`
//! and `core/src/tracegen/recursion.rs`.  But none of those are wired
//! into the host prover, so they're dead code.  This hook completes
//! the integration: now the host `MachineChip::generate_trace` actually
//! lands on device-resident bytes when the env flag is set.
//!
//! ## Status (v1)
//!
//! - [x] [`SelectChipDeviceTraceFn`] hook + dispatch wiring in
//!       [`crate::chips::select::SelectChip::generate_trace`].
//! - [x] [`register_select_device_trace_hook`] entry point for
//!       `ziren-gpu` to call from `compress_multi_gpu` startup.
//! - [ ] Remaining recursion chips (BaseAlu / ExtAlu / FriFold /
//!       BatchFRI / Poseidon2{Skinny,Wide}) — same pattern, deferred to
//!       integration #4+ (the `DeviceAir` impls already exist in
//!       `ziren-gpu/core/src/tracegen/recursion.rs`).

use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;

use crate::SelectEvent;

// ────────────────────────────────────────────────────────────────────
// SelectChip device-tracegen hook
// ────────────────────────────────────────────────────────────────────

/// Signature of the GPU `SelectChip` trace generator.  Receives the
/// host-side `select_events` slice plus the padded row count;
/// returns a row-major matrix that is byte-identical to the host
/// `SelectChip::generate_trace` output (i.e. column-0 = `bit`,
/// column-1 = `out1`, column-2 = `out2`, column-3 = `in1`,
/// column-4 = `in2`, padded with zeros to `padded_nb_rows`).
///
/// Returning `None` lets the caller fall back to the host
/// implementation (e.g. when the GPU is unhealthy or the chip's
/// width/event-count is below the device-launch threshold).
pub type SelectChipDeviceTraceFn = fn(
    events: &[SelectEvent<KoalaBear>],
    padded_nb_rows: usize,
) -> Option<RowMajorMatrix<KoalaBear>>;

static SELECT_DEVICE_TRACE_HOOK: std::sync::OnceLock<SelectChipDeviceTraceFn> =
    std::sync::OnceLock::new();

/// Register the GPU `SelectChip` tracegen.  Idempotent — returns
/// `Err(_)` if a hook is already installed.  Called once by the
/// `ziren-gpu` prover crate at startup (alongside the existing
/// `register_with_zkm_stark` calls for sumcheck / eval_at /
/// zerocheck / constraint_eval hooks).
pub fn register_select_device_trace_hook(
    f: SelectChipDeviceTraceFn,
) -> Result<(), SelectChipDeviceTraceFn> {
    SELECT_DEVICE_TRACE_HOOK.set(f)
}

/// Read the registered hook, if any.  Used by
/// [`crate::chips::select::SelectChip::generate_trace`] under
/// `ZIREN_GPU_TRACEGEN_DEVICE=1`.
#[must_use]
pub fn get_select_device_trace_hook() -> Option<SelectChipDeviceTraceFn> {
    SELECT_DEVICE_TRACE_HOOK.get().copied()
}
