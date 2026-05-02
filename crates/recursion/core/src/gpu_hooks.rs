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
//! ## Status (v3)
//!
//! - [x] [`SelectChipDeviceTraceFn`] hook + dispatch wiring in
//!       [`crate::chips::select::SelectChip::generate_trace`].
//! - [x] [`register_select_device_trace_hook`] entry point for
//!       `ziren-gpu` to call from `compress_multi_gpu` startup.
//! - [x] [`Poseidon2WideChipDeviceTraceFn`] hook (integration #4
//!       follow-on; populate-heavy ~150-col chip).
//! - [x] [`BaseAluChipDeviceTraceFn`] +
//!       [`ExtAluChipDeviceTraceFn`] hooks (integration #4) — the two
//!       simplest device-only chips after Select.  Both share the
//!       `ZIREN_GPU_TRACEGEN_DEVICE=1` env flag.
//! - [ ] Remaining recursion chips (FriFold / BatchFRI /
//!       Poseidon2Skinny) — same pattern, deferred to integration
//!       #5+ (the `DeviceAir` impls already exist in
//!       `ziren-gpu/core/src/tracegen/recursion.rs`).

use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;

use crate::{BaseAluEvent, ExtAluEvent, Poseidon2Event, SelectEvent};

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

// ────────────────────────────────────────────────────────────────────
// Poseidon2WideChip device-tracegen hook (integration #4 — same
// pattern as #3 SelectChip; see `ziren-gpu/core/src/basefold/
// tracegen/poseidon2_wide.rs`).
// ────────────────────────────────────────────────────────────────────

/// Signature of the GPU `Poseidon2WideChip<DEGREE>` trace generator.
///
/// Receives the host-side `poseidon2_events` slice (the chip uses
/// only the `input` field of each `Poseidon2Io`; the `output` is
/// recomputed inside the kernel and is asserted-equal only on the
/// `cfg(not(feature = "sys"))` host path), the padded row count, and
/// the chip width — which depends on `DEGREE`:
///
/// * `DEGREE == 3`  → `NUM_POSEIDON2_DEGREE3_COLS` (sbox columns omitted)
/// * `DEGREE == 9`  → `NUM_POSEIDON2_DEGREE9_COLS` (sbox columns present)
/// * `DEGREE == 17` → same width as `DEGREE == 9`
///
/// Returns a row-major matrix that is byte-identical to the host
/// `Poseidon2WideChip::generate_trace` output.  Crucially, the
/// padding rows beyond `events.len()` are **not** zero-filled — they
/// are filled by running `populate_perm` on the all-zero input (see
/// the `dummy_row` branch in `chips/poseidon2_wide/trace.rs`).  The
/// CUDA kernel handles this by calling `event_to_row` with a zero
/// input on the trailing rows.
///
/// The width is passed in (rather than recomputed) because the host
/// already knows it from `BaseAir::width()` and we want to keep the
/// wrapper's degree-vs-width branching on the host side.
///
/// Returning `None` lets the caller fall back to the host
/// implementation (e.g. when the GPU is unhealthy or a CUDA op fails).
pub type Poseidon2WideChipDeviceTraceFn = fn(
    events: &[Poseidon2Event<KoalaBear>],
    padded_nb_rows: usize,
    width: usize,
) -> Option<RowMajorMatrix<KoalaBear>>;

static POSEIDON2_WIDE_DEVICE_TRACE_HOOK: std::sync::OnceLock<Poseidon2WideChipDeviceTraceFn> =
    std::sync::OnceLock::new();

/// Register the GPU `Poseidon2WideChip` tracegen.  Idempotent — returns
/// `Err(_)` if a hook is already installed.  Called once by the
/// `ziren-gpu` prover crate at startup.
pub fn register_poseidon2_wide_device_trace_hook(
    f: Poseidon2WideChipDeviceTraceFn,
) -> Result<(), Poseidon2WideChipDeviceTraceFn> {
    POSEIDON2_WIDE_DEVICE_TRACE_HOOK.set(f)
}

/// Read the registered hook, if any.  Used by
/// [`crate::chips::poseidon2_wide::Poseidon2WideChip::generate_trace`]
/// under `ZIREN_GPU_TRACEGEN_DEVICE=1`.
#[must_use]
pub fn get_poseidon2_wide_device_trace_hook() -> Option<Poseidon2WideChipDeviceTraceFn> {
    POSEIDON2_WIDE_DEVICE_TRACE_HOOK.get().copied()
}

// ────────────────────────────────────────────────────────────────────
// BaseAluChip device-tracegen hook (integration #4 — sister of Select)
// ────────────────────────────────────────────────────────────────────

/// Signature of the GPU `BaseAluChip` trace generator.  Receives the
/// host-side `base_alu_events` slice plus the padded row count;
/// returns a row-major matrix that is byte-identical to the host
/// `BaseAluChip::generate_trace` output (4 entries per row, each
/// holding `BaseAluValueCols<F>` = `(out, in1, in2)`; padded with
/// zeros to `padded_nb_rows`).
///
/// Returning `None` lets the caller fall back to the host
/// implementation (e.g. when the GPU is unhealthy or the hook is
/// not registered).
pub type BaseAluChipDeviceTraceFn = fn(
    events: &[BaseAluEvent<KoalaBear>],
    padded_nb_rows: usize,
) -> Option<RowMajorMatrix<KoalaBear>>;

static BASE_ALU_DEVICE_TRACE_HOOK: std::sync::OnceLock<BaseAluChipDeviceTraceFn> =
    std::sync::OnceLock::new();

/// Register the GPU `BaseAluChip` tracegen.  Idempotent — returns
/// `Err(_)` if a hook is already installed.  Called once by the
/// `ziren-gpu` prover crate at startup (alongside the existing
/// `register_*_device_trace_hook` calls for Select / Poseidon2Wide).
pub fn register_base_alu_device_trace_hook(
    f: BaseAluChipDeviceTraceFn,
) -> Result<(), BaseAluChipDeviceTraceFn> {
    BASE_ALU_DEVICE_TRACE_HOOK.set(f)
}

/// Read the registered hook, if any.  Used by
/// [`crate::chips::alu_base::BaseAluChip::generate_trace`] under
/// `ZIREN_GPU_TRACEGEN_DEVICE=1`.
#[must_use]
pub fn get_base_alu_device_trace_hook() -> Option<BaseAluChipDeviceTraceFn> {
    BASE_ALU_DEVICE_TRACE_HOOK.get().copied()
}

// ────────────────────────────────────────────────────────────────────
// ExtAluChip device-tracegen hook (integration #4 — sister of Select)
// ────────────────────────────────────────────────────────────────────

/// Signature of the GPU `ExtAluChip` trace generator.  Receives the
/// host-side `ext_alu_events` slice (each element is an EF4
/// `ExtAluIo<Block<KoalaBear>>` triple) plus the padded row count;
/// returns a row-major matrix that is byte-identical to the host
/// `ExtAluChip::generate_trace` output (4 entries per row, each
/// holding `ExtAluValueCols<F>` = `(out, in1, in2)` of `Block<F>`;
/// padded with zeros to `padded_nb_rows`).
///
/// Returning `None` falls back to the host implementation.
pub type ExtAluChipDeviceTraceFn = fn(
    events: &[ExtAluEvent<KoalaBear>],
    padded_nb_rows: usize,
) -> Option<RowMajorMatrix<KoalaBear>>;

static EXT_ALU_DEVICE_TRACE_HOOK: std::sync::OnceLock<ExtAluChipDeviceTraceFn> =
    std::sync::OnceLock::new();

/// Register the GPU `ExtAluChip` tracegen.  Idempotent.
pub fn register_ext_alu_device_trace_hook(
    f: ExtAluChipDeviceTraceFn,
) -> Result<(), ExtAluChipDeviceTraceFn> {
    EXT_ALU_DEVICE_TRACE_HOOK.set(f)
}

/// Read the registered hook, if any.  Used by
/// [`crate::chips::alu_ext::ExtAluChip::generate_trace`] under
/// `ZIREN_GPU_TRACEGEN_DEVICE=1`.
#[must_use]
pub fn get_ext_alu_device_trace_hook() -> Option<ExtAluChipDeviceTraceFn> {
    EXT_ALU_DEVICE_TRACE_HOOK.get().copied()
}
