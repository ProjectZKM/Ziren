//! GKR circuit builder — ties together first-layer + transitions +
//! output extraction (task #24, A.2 step 4.5).
//!
//! Mirrors the data-side flow of
//! [`generate_gkr_circuit`](file:///tmp/sp1/crates/hypercube/src/logup_gkr/cpu.rs#L75-L133)
//! but stops short of the per-round sumcheck (step 5).  The output
//! is the full layer stack plus the unified [`LogUpGkrOutput`] — the
//! sumcheck round proofs are layered on top in step 5.

use alloc::vec::Vec;

use p3_field::{ExtensionField, PrimeField};
use p3_matrix::dense::RowMajorMatrix;

use super::extract::{extract_outputs, LogUpGkrOutput};
use super::first_layer::generate_first_layer;
use super::layer::{GkrCircuitLayer, LayerState, LogupGkrCpuCircuit};
use super::transition::layer_transition;
use crate::air::MachineAir;
use crate::Chip;

/// Build the full GKR circuit (data side) and return the unified
/// output.
///
/// **Inputs:**
/// - `chips`: per-chip lookup specs
/// - `preprocessed_traces`, `main_traces`: per-chip raw traces
/// - `alpha`, `betas`: post-commit challenges (`betas[0]` covers the
///   `argument_index` slot, `betas[1..]` cover per-column values)
/// - `num_row_variables`: log₂ of padded row count
///   (must be `>= 1` for the row-reduction to terminate at
///   `num_row_variables == 1`)
///
/// **Output:**
/// `(LogUpGkrOutput<EF>, LogupGkrCpuCircuit<F, EF>)` — same shape as
/// the `generate_gkr_circuit` return type, lets the caller (step 5)
/// walk the layer stack bottom-up to drive per-round sumchecks.
///
/// **Panics** when `num_row_variables == 0` (degenerate empty shard
/// — handled by the caller, not by this builder).
#[allow(clippy::too_many_arguments)]
pub fn build_gkr_circuit<F, EF, A>(
    chips: &[&Chip<F, A>],
    preprocessed_traces: &[RowMajorMatrix<F>],
    main_traces: &[RowMajorMatrix<F>],
    alpha: EF,
    betas: &[EF],
    num_row_variables: usize,
    // #263: per-shard device-trace provider, threaded into the GPU
    // first-layer hook through `generate_first_layer`.
    device_traces: Option<&dyn crate::shard_level::DeviceTraceProvider>,
) -> (LogUpGkrOutput<EF>, LogupGkrCpuCircuit<F, EF>)
where
    F: PrimeField,
    EF: ExtensionField<F>,
    A: MachineAir<F>,
{
    assert!(num_row_variables >= 1, "build_gkr_circuit requires num_row_variables >= 1");

    let first = generate_first_layer::<F, EF, A>(
        chips,
        preprocessed_traces,
        main_traces,
        alpha,
        betas,
        num_row_variables,
        device_traces,
    );

    // generate_first_layer reduces num_row_variables by 1 (per its
    // docstring: "set to original - 1"). So:
    //
    //   input num_row_variables=N → first.num_row_variables=N-1
    //
    // Two distinct degenerate cases to handle:
    //
    //   N=1 input → first.num=0 → no transitions possible. Terminal
    //               extraction needs num=1; we don't have it. Reject
    //               at entry (#80 fix below — but realistically
    //               num_row_variables=1 doesn't appear in production
    //               shapes since shard padding hits ≥ 2).
    //
    //   N=2 input → first.num=1 → the FirstLayer IS the terminal.
    //               Previously the code only checked layers[len-2]
    //               for an EF Layer and panicked when it found a
    //               FirstLayer there. Fix: F→EF-promote the FirstLayer
    //               into a regular Layer at the same row count, then
    //               treat it as the terminal.
    //
    //   N≥3 input → first.num≥2 → ≥1 transitions, terminal Layer
    //               with num=1 ends up at layers[len-2]. Original
    //               flow.
    assert!(num_row_variables >= 2,
        "build_gkr_circuit requires num_row_variables >= 2 (got {num_row_variables}); \
         num_row_variables=1 produces no terminal EF layer for output extraction");

    // Step 4b (`/tmp/step4_backend_parametrize_plan.md`) — `layers` now
    // stores `LayerState<F, EF>` so a future GPU prover (Step 4c) can
    // install `LayerState::Device { handle, .. }` entries on the way
    // down.  Today every entry is `LayerState::Host(GkrCircuitLayer)`,
    // so behavior is byte-identical to the pre-4b path.
    //
    // ─────────────────────────────────────────────────────────────────
    // Step 4c (`/tmp/step4_backend_parametrize_plan.md`) — opt-in GPU
    // dispatch path:
    //
    //   * Env var:  ZIREN_GPU_LAYER_TRANSITION=1
    //   * Hooks:    register_gpu_layer_init_hook
    //               register_gpu_layer_transition_hook
    //               register_gpu_layer_pull_hook
    //               (all three must be installed by ziren-gpu at startup;
    //                if any are missing we fall through to the host path)
    //   * Type req: F == LbVal && EF == LbChallenge (TypeId-checked at
    //               runtime; recursion-circuit / wrap-circuit
    //               instantiations don't satisfy this and stay host-only)
    //
    // When all conditions hold, the FIRST EF layer (produced by the
    // F→EF host transition out of the FirstLayer) is uploaded to device
    // via `GpuLayerInitFn`; subsequent transitions evolve the
    // device-resident layer state in place via `GpuLayerTransitionFn`;
    // the terminal device handle is materialized back to host via
    // `GpuLayerPullFn` so `extract_outputs` can run on host unchanged.
    //
    // The first EF layer is computed on host (one round, the F→EF
    // promotion happens here) so the device hook sees uniform-EF
    // input; this avoids an init contract that branches on the
    // base-vs-extension state of the input layer.
    //
    // Default behavior (env var unset OR any hook missing OR TypeId
    // mismatch) is byte-identical to the pre-4c path.
    // ─────────────────────────────────────────────────────────────────
    let mut layers: Vec<LayerState<F, EF>> = Vec::with_capacity(first.num_row_variables + 1);

    // Special case: num_row_variables=2 input → first.num=1 → use
    // first as the terminal directly via F→EF promotion.
    let terminal_owned: Option<super::layer::LogUpGkrCpuLayer<EF, EF>> =
        if first.num_row_variables == 1 {
            // FirstLayer at num_row_variables=1 IS the terminal.
            // Promote numerator F → EF; denominator already EF.
            Some(promote_first_layer_numerator_to_ef::<F, EF>(&first))
        } else {
            None
        };

    let mut last_ef_layer: Option<super::layer::LogUpGkrCpuLayer<EF, EF>> = None;

    // First transition: NumF = F → EF (numerator type promotion).
    // Only run when first.num_row_variables >= 1; the transition
    // reduces by 1, so for first.num=1 the result has num=0 (the
    // null terminal), and for first.num >= 2 the result has the
    // intermediate num >= 1 (used for the next transition).
    if first.num_row_variables >= 1 {
        let next = layer_transition::<F, EF>(&first);
        last_ef_layer = Some(next);
    }
    layers.push(LayerState::Host(GkrCircuitLayer::FirstLayer(first)));

    // Step 4c device-path probe: only enter the device branch if env
    // var is set, all three hooks registered, types match, AND there is
    // at least one EF layer in hand (i.e. at least one host transition
    // happened, so `last_ef_layer` is `Some`).
    let device_terminal: Option<super::layer::LogUpGkrCpuLayer<EF, EF>> =
        try_run_device_path::<F, EF>(&mut last_ef_layer, &mut layers);

    // Subsequent transitions stay in EF.  When the device path took
    // over, `last_ef_layer` is `None` here and the loop is a no-op
    // (all intermediate `LayerState::Device` entries were already
    // pushed by `try_run_device_path`).
    while let Some(curr) = last_ef_layer.take() {
        if curr.num_row_variables >= 1 {
            let next = layer_transition::<EF, EF>(&curr);
            last_ef_layer = Some(next);
            layers.push(LayerState::Host(GkrCircuitLayer::Layer(curr)));
        } else {
            // curr is the null terminal layer (num_row_variables == 0).
            // Add to layer stack but stop transitioning.
            layers.push(LayerState::Host(GkrCircuitLayer::Layer(curr)));
        }
    }

    // Pick the terminal layer (num_row_variables == 1) for output
    // extraction. Three paths:
    //
    //   * num_row_variables=2 input → terminal_owned is Some
    //     (F→EF-promoted FirstLayer)
    //   * device path took over → device_terminal is Some
    //     (pulled from device via GpuLayerPullFn)
    //   * num_row_variables>=3 input, host path → layers[len-2] is the
    //     EF Layer with num_row_variables==1
    let output = if let Some(t) = terminal_owned.as_ref() {
        extract_outputs(t)
    } else if let Some(t) = device_terminal.as_ref() {
        extract_outputs(t)
    } else {
        match &layers[layers.len() - 2] {
            LayerState::Host(GkrCircuitLayer::Layer(l)) => extract_outputs(l),
            LayerState::Host(GkrCircuitLayer::FirstLayer(_)) => unreachable!(
                "for num_row_variables >= 3 the second-to-last layer is always an EF Layer"
            ),
            LayerState::Device { .. } => unreachable!(
                "Step 4c: when the device path was taken, `device_terminal` \
                 carries the pulled host EF layer; the layers[len-2] arm is \
                 only entered on the host-only path where every entry is Host."
            ),
        }
    };
    (output, LogupGkrCpuCircuit::new(layers))
}

/// Step 4c device-path entry point.  Returns `Some(terminal)` when
/// the device path was taken (terminal layer pulled back to host for
/// `extract_outputs`), `None` otherwise (host path runs unchanged).
///
/// Side effects when `Some` is returned:
///   * `last_ef_layer` is consumed (set to `None`) — the device branch
///     drives all remaining transitions, no further host work needed.
///   * `layers` gains one `LayerState::Device { .. }` entry per
///     intermediate device-resident layer (matching the count the host
///     path would have pushed).
///
/// Returns `None` when ANY of the following:
///   * `ZIREN_GPU_LAYER_TRANSITION` env var is unset / not "1"
///   * any of the three GPU hooks (init, transition, pull) is unregistered
///   * `F != LbVal` or `EF != LbChallenge` (TypeId check)
///   * `last_ef_layer` is `None` on entry (no host transition happened —
///     can only occur when `first.num_row_variables == 0`, which the
///     `>= 2` assertion above already rules out, but this guard keeps
///     the device branch robust)
/// #263/#266 perf fix — process-cached env lookup for the
/// layer-transition GPU dispatch.  Returns true when EITHER the
/// master switch `ZIREN_GPU_DEVICE_HOOKS=1` OR the legacy
/// `ZIREN_GPU_LAYER_TRANSITION=1` is set.
///
/// Safe under the master switch now (#266) because the call site
/// gates on `gpu_worker_context::current_gpu_pool_worker_device()`
/// being `Some(_)` — off-pool basefold workers without a
/// `cudaSetDevice` context have TLS=None and skip GPU dispatch.
fn layer_transition_env_cached() -> bool {
    use std::sync::OnceLock;
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| {
        let master = std::env::var("ZIREN_GPU_DEVICE_HOOKS")
            .map(|v| v == "1")
            .unwrap_or(false);
        master
            || std::env::var("ZIREN_GPU_LAYER_TRANSITION")
                .map(|v| v == "1")
                .unwrap_or(false)
    })
}

fn try_run_device_path<F, EF>(
    last_ef_layer: &mut Option<super::layer::LogUpGkrCpuLayer<EF, EF>>,
    layers: &mut Vec<LayerState<F, EF>>,
) -> Option<super::layer::LogUpGkrCpuLayer<EF, EF>>
where
    F: PrimeField,
    EF: ExtensionField<F>,
{
    // Gate 1: env var.  Either the legacy `ZIREN_GPU_LAYER_TRANSITION=1`
    // OR the master switch `ZIREN_GPU_DEVICE_HOOKS=1` (#263) engages
    // the device transition path.  Cached per-process to avoid
    // libc-environ Mutex acquisition cost (per-shard call site).
    //
    // Gate 1b (#266 fix): also require a GPU pool worker TLS context.
    // Without this, dispatching from an off-pool basefold rayon worker
    // hits the wrong cudaSetDevice context — kernel either fails or
    // runs on GPU 0, paying full PCIe + launch overhead.  Reth A/B
    // showed +16% core regression from this exact failure mode.
    if !layer_transition_env_cached() {
        return None;
    }
    if crate::gpu_worker_context::current_gpu_pool_worker_device().is_none() {
        return None;
    }

    // Gate 2: feature + concrete-type + hooks all available.  The
    // device path is only meaningful when the basefold feature is
    // compiled in (the hooks live there) and when the generic types
    // resolve to the production stack.
    #[cfg(feature = "basefold")]
    {
        try_run_device_path_basefold::<F, EF>(last_ef_layer, layers)
    }
    #[cfg(not(feature = "basefold"))]
    {
        // Without the basefold feature there are no GPU hooks; the env
        // var is silently ignored.  Suppress unused-variable warnings.
        let _ = (last_ef_layer, layers);
        None
    }
}

#[cfg(feature = "basefold")]
fn try_run_device_path_basefold<F, EF>(
    last_ef_layer: &mut Option<super::layer::LogUpGkrCpuLayer<EF, EF>>,
    layers: &mut Vec<LayerState<F, EF>>,
) -> Option<super::layer::LogUpGkrCpuLayer<EF, EF>>
where
    F: PrimeField,
    EF: ExtensionField<F>,
{
    use core::any::TypeId;

    use crate::basefold_late_binding::{
        allocate_gpu_layer_circuit_id, get_gpu_layer_init_hook, get_gpu_layer_pull_hook,
        get_gpu_layer_transition_hook, HostLayerView, LbChallenge, LbVal,
    };

    // Need 'static bound on F/EF to use TypeId; the build_gkr_circuit
    // generics already satisfy this (PrimeField : 'static is implied
    // by the standard p3 field bounds), but we re-check via the
    // TypeId comparisons below — `TypeId::of::<F>()` requires F : 'static.

    // Gate 3: hooks registered.
    let init_hook = get_gpu_layer_init_hook()?;
    let transition_hook = get_gpu_layer_transition_hook()?;
    let pull_hook = get_gpu_layer_pull_hook()?;

    // Gate 4: TypeId match (recursion-circuit instantiates over a
    // different field stack — those calls fall through to host).
    if TypeId::of::<F>() != TypeId::of::<LbVal>()
        || TypeId::of::<EF>() != TypeId::of::<LbChallenge>()
    {
        return None;
    }

    // Gate 5: at least one EF layer present (i.e. the F→EF host
    // transition above produced something).  When this is `None` the
    // FirstLayer was already the terminal and the host path's
    // `terminal_owned` short-circuit takes over; no device dispatch.
    let first_ef_layer = last_ef_layer.take()?;

    // SAFETY: TypeId gates 4 confirm `EF == LbChallenge` and
    // `F == LbVal` at runtime; the layer type
    // `LogUpGkrCpuLayer<EF, EF>` therefore has identical layout to
    // `LogUpGkrCpuLayer<LbChallenge, LbChallenge>` and `RowMajorTable<EF>`
    // to `RowMajorTable<LbChallenge>`.  We reinterpret-borrow via a
    // pointer cast so the upload stays zero-copy on the host side.
    //
    // The borrow in `view` cannot outlive `first_ef_layer`; we pass
    // `view` by value to the init hook which returns immediately with
    // a `u64` handle.
    let layer_as_lb: &super::layer::LogUpGkrCpuLayer<LbChallenge, LbChallenge> = unsafe {
        &*(&first_ef_layer
            as *const super::layer::LogUpGkrCpuLayer<EF, EF>
            as *const super::layer::LogUpGkrCpuLayer<LbChallenge, LbChallenge>)
    };

    let view = HostLayerView {
        numerator_0: &layer_as_lb.numerator_0,
        denominator_0: &layer_as_lb.denominator_0,
        numerator_1: &layer_as_lb.numerator_1,
        denominator_1: &layer_as_lb.denominator_1,
        num_row_variables: layer_as_lb.num_row_variables,
        num_interaction_variables: layer_as_lb.num_interaction_variables,
    };

    // #230 multi-GPU fix: allocate a fresh circuit_id for this
    // build_gkr_circuit call.  The GPU side keys its registry by
    // (device_id, circuit_id) so concurrent shards on the same GPU
    // don't share a `next_handle` counter.  Threaded through every
    // init/transition/pull invocation for this circuit.
    let circuit_id: u64 = allocate_gpu_layer_circuit_id();

    let mut handle: u64 = init_hook(circuit_id, view);
    let mut cur_num_row_variables = first_ef_layer.num_row_variables;
    let cur_num_interaction_variables = first_ef_layer.num_interaction_variables;

    // Push the first EF layer as a Host entry — the host transition
    // out of the FirstLayer already happened, and the sumcheck round
    // dispatcher (Step 4d, future) needs the per-layer cells anyway.
    // Storing it host-side here matches the host path's behavior for
    // this one layer; only SUBSEQUENT layers go through Device.
    layers.push(LayerState::Host(GkrCircuitLayer::Layer(first_ef_layer)));

    // Drive the remaining transitions on device.  `cur_num_row_variables`
    // was the ROW count of the layer we just uploaded; each transition
    // halves it, mirroring the host loop's `curr.num_row_variables >= 1`
    // termination.
    //
    // The host loop pushes EVERY layer (including the final null
    // terminal at num=0).  We do the same to keep `layers.len()`
    // identical to the host path so `layers[layers.len() - 2]`
    // indexing in downstream code (Step 4d round.rs migration, future)
    // still resolves to the terminal at num=1.
    //
    // We capture the handle at num=1 (the TERMINAL layer
    // `extract_outputs` needs) before the final transition that takes
    // it to num=0; pulling the terminal handle (not the post-final
    // null one) mirrors the host path's `layers[len - 2]` indexing.
    let mut terminal_handle: Option<u64> = None;
    while cur_num_row_variables >= 1 {
        // BEFORE invoking the next transition, record this handle if
        // the layer at the CURRENT step has num_row_variables == 1
        // (i.e. transitioning out of the terminal candidate).
        if cur_num_row_variables == 1 {
            terminal_handle = Some(handle);
        }
        let next_handle = transition_hook(circuit_id, handle);
        cur_num_row_variables = cur_num_row_variables.saturating_sub(1);
        layers.push(LayerState::Device {
            circuit_id,
            handle: next_handle,
            num_row_variables: cur_num_row_variables,
            num_interaction_variables: cur_num_interaction_variables,
        });
        handle = next_handle;
    }

    // Special case: when first_ef_layer.num_row_variables == 1 the
    // first uploaded layer IS the terminal — the loop above never
    // ran (entry condition `cur >= 1` would fire for one iteration,
    // setting terminal_handle = first_handle, then transition + push
    // null terminal).  Both branches have terminal_handle = Some(_).
    //
    // Edge case: when first_ef_layer.num_row_variables == 0 the loop
    // body never executes and terminal_handle stays None.  In that
    // case extract_outputs cannot run on this device-pulled terminal,
    // so we fall back to pulling the initial handle.  This degenerate
    // shape never appears in production (build_gkr_circuit asserts
    // num_row_variables >= 2 at entry, which guarantees the first EF
    // layer has num >= 1) but the `unwrap_or(handle)` keeps the
    // device-path code total.
    let terminal_handle = terminal_handle.unwrap_or(handle);

    // Pull the terminal device-resident layer back to host so
    // `extract_outputs` (host primitive) can run unchanged.  Pulling
    // the captured terminal_handle (NOT the post-loop `handle` which
    // points at the null terminal at num=0) mirrors the host path's
    // `layers[layers.len() - 2]` indexing.
    let terminal_lb: super::layer::LogUpGkrCpuLayer<LbChallenge, LbChallenge> =
        pull_hook(circuit_id, terminal_handle);

    // SAFETY: TypeId gate 4 confirms `LbChallenge == EF` at runtime;
    // the `LogUpGkrCpuLayer<LbChallenge, LbChallenge>` struct has
    // identical layout to `LogUpGkrCpuLayer<EF, EF>`.  Reinterpret via
    // `transmute_copy` and `forget` to move ownership safely.
    let terminal_ef: super::layer::LogUpGkrCpuLayer<EF, EF> = unsafe {
        let out: super::layer::LogUpGkrCpuLayer<EF, EF> =
            core::mem::transmute_copy(&terminal_lb);
        core::mem::forget(terminal_lb);
        out
    };

    Some(terminal_ef)
}

/// F→EF promotion of a FirstLayer's numerators (denominators are
/// already EF). Used when the FirstLayer is itself the terminal
/// (num_row_variables=1 case after generate_first_layer reduced from
/// input num_row_variables=2).
fn promote_first_layer_numerator_to_ef<F, EF>(
    first: &super::layer::LogUpGkrCpuLayer<F, EF>,
) -> super::layer::LogUpGkrCpuLayer<EF, EF>
where
    F: PrimeField,
    EF: ExtensionField<F>,
{
    use super::layer::RowMajorTable;

    let promote = |t: &RowMajorTable<F>| -> RowMajorTable<EF> {
        RowMajorTable {
            cells: t.cells.iter().map(|&v| EF::from(v)).collect(),
            num_row_variables: t.num_row_variables,
            num_interaction_variables: t.num_interaction_variables,
            num_interactions: t.num_interactions,
            num_real_rows: t.num_real_rows,
        }
    };

    super::layer::LogUpGkrCpuLayer {
        numerator_0: first.numerator_0.iter().map(promote).collect(),
        denominator_0: first.denominator_0.clone(),
        numerator_1: first.numerator_1.iter().map(promote).collect(),
        denominator_1: first.denominator_1.clone(),
        num_row_variables: first.num_row_variables,
        num_interaction_variables: first.num_interaction_variables,
    }
}

#[cfg(test)]
mod tests {
    use p3_air::{PairCol, VirtualPairCol};
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;

    use super::*;
    use crate::air::LookupScope;
    use crate::lookup::{Lookup, LookupKind};
    use crate::Challenge;

    type SC = crate::koala_bear_poseidon2::KoalaBearPoseidon2;
    type EF = Challenge<SC>;

    /// Build a one-chip shard with a single send-interaction whose
    /// trace and lookup are deterministic.  Used to drive end-to-end
    /// shape sanity checks of the pipeline.
    fn one_chip_shard(
        log_height: usize,
    ) -> (
        Vec<Lookup<KoalaBear>>,
        Vec<Lookup<KoalaBear>>,
        RowMajorMatrix<KoalaBear>,
        RowMajorMatrix<KoalaBear>,
    ) {
        let send = Lookup::new(
            vec![],
            VirtualPairCol::new(vec![(PairCol::Main(0), KoalaBear::ONE)], KoalaBear::ZERO),
            LookupKind::Byte,
            LookupScope::Local,
        );
        let height = 1usize << log_height;
        // Main trace: 1 column, height rows, all = 1 (so multiplicity = 1).
        let main = RowMajorMatrix::new(vec![KoalaBear::ONE; height], 1);
        // Empty preprocessed.
        let prep = RowMajorMatrix::new(vec![], 0);
        (vec![send], vec![], main, prep)
    }

    /// Smoke-shape test: build a circuit for a 2-chip shard (where
    /// each chip is structurally identical) at log_height=2 and
    /// confirm the layer stack + output have the right shapes.
    #[test]
    #[ignore = "requires plumbing chips through Chip<F, A> — defer to step 6 wiring"]
    fn build_gkr_circuit_shape_smoke() {
        // The Chip<F, A> wrapper requires an A: MachineAir<F> instance.
        // Constructing one in unit tests requires a real chip type, which
        // pulls in zkm_core_machine.  Step 6 (top-level wiring) is the
        // appropriate place to exercise this end-to-end via real chips.
        let _ = one_chip_shard(2);
    }

    /// `build_gkr_circuit`'s zero-row-variables panic guard is
    /// validated by inspection — the assertion at the function head
    /// is its own test.  An end-to-end runtime panic test requires a
    /// real `Chip<F, A>` instance, deferred to step 6.
    #[allow(dead_code)]
    fn _zero_row_variables_panic_guard_is_visible_in_signature() {
        // assertion at build.rs:36: "build_gkr_circuit requires num_row_variables >= 1"
    }
}
