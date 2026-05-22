//! Device-resident LogUp-GKR circuit scaffold.
//!
//! Direct analogue of SP1's
//! `LogUpCudaCircuit`
//! — a streaming container that yields one circuit layer at a time so
//! the GKR prover can walk the circuit bottom-up without materializing
//! every layer up front on host.
//!
//! ## Why this exists
//!
//! Today's `build_gkr_circuit` + `LogupGkrCpuCircuit` (see
//! [`super::layer`]) eagerly walks every layer transition on host
//! **before** any sumcheck round executes.  Profile data (see
//! `project_359_*` memory notes) shows `flatten_layer` consuming
//! 77% of per-layer cost on fibonacci / 58% on tendermint —
//! eliminating per-call flatten via persistent device-resident layer
//! state is projected to save ~20% wall.
//!
//! The fix mirrors SP1's design exactly: the prover side holds a
//! [`DeviceLogupGkrCircuit`] that stores a `Vec<DeviceCircuitLayer>`
//! plus an optional virtual `FirstLayerVirtual` placeholder.  Each
//! call to [`DeviceLogupGkrCircuit::next`] pops the bottom-most
//! materialized layer, or — when `recompute_first_layer` is on and
//! the materialized stack is empty — generates the FirstLayer on
//! demand from the input data.
//!
//! ## Scope of this scaffold
//!
//! * Defines the public types: [`DeviceLogupGkrCircuit`],
//!   [`DeviceCircuitLayer`], [`DeviceLayerHandle`],
//!   [`DeviceInputData`].
//! * Defines iterator-style API: [`DeviceLogupGkrCircuit::next`],
//!   [`DeviceLogupGkrCircuit::new`], [`DeviceLogupGkrCircuit::len`].
//! * Stays **device-agnostic**: handles are opaque `Arc<...>`
//!   placeholders.  The stark crate must not depend on ziren-gpu /
//!   cudarc; the actual device payload type is filled in by the GPU
//!   crate via a side-channel registry (matching the
//!   [`super::layer::LayerState::Device`] pattern in #218 Q1 /
//!   #228).
//! * Methods that need device dispatch (e.g. recomputing the first
//!   layer from raw input data) carry `todo!()` bodies and are gated
//!   behind a clear `// hook-point` comment so #371 can wire the V3
//!   hook signature in cleanly.
//!
//! ## Out of scope (#371 — next task)
//!
//! * Plumbing `DeviceLogupGkrCircuit` into [`super::round`] /
//!   [`super::top_level`].  This task only defines the type.
//! * Modifying any existing caller of `LogupGkrCpuCircuit`.
//! * Wiring CUDA dependencies into the stark crate.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_field::{ExtensionField, Field};

/// Opaque handle to a device-resident layer payload.
///
/// The stark crate has no knowledge of the underlying device payload
/// type — that lives in the basefold/GPU crate and is keyed by a
/// `(device_id, circuit_id, handle_id)` triple in the per-process
/// registry (see `crate::basefold_late_binding` for the existing
/// `LayerState::Device` hooks introduced by #218 Q1 / #225-#228).
///
/// `Arc<dyn AnyDeviceHandle>` keeps the type erased while preserving
/// reference-counted ownership across rayon workers; the actual
/// payload is dropped via the registry's pull/release hook when the
/// last `Arc` clone is dropped.
///
/// **#371 hook-point:** When the V3 hook lands, this is the type that
/// will flow into the sumcheck round prover.  The marker trait
/// `AnyDeviceHandle: Any + Send + Sync` keeps the abstraction
/// device-agnostic while letting the GPU side downcast via
/// `Arc::downcast`.
#[derive(Clone)]
pub struct DeviceLayerHandle {
    /// Opaque type-erased payload — populated by the GPU crate's
    /// registry, never inspected on the stark side.
    inner: Arc<dyn AnyDeviceHandle>,
    /// Mirrored shape metadata so callers that only need dimensions
    /// can read them without dereferencing through the registry
    /// (matches the [`super::layer::LayerState::Device`] pattern).
    num_row_variables: usize,
    /// log₂ of (max chip-interaction count rounded up).
    num_interaction_variables: usize,
    /// Multi-GPU scoping ID — keyed per-`build_device_gkr_circuit`
    /// invocation so concurrent shards stay isolated (mirrors the
    /// `LayerState::Device::circuit_id` field added in #230).
    circuit_id: u64,
}

/// Marker trait that any device-side handle payload must implement.
///
/// This lives in the stark crate only as an opaque erased pointer;
/// the GPU crate provides concrete impls keyed in its registry.
pub trait AnyDeviceHandle: core::any::Any + Send + Sync {}

impl DeviceLayerHandle {
    /// Constructor used by the GPU registry when a fresh device
    /// layer is materialized.  Stark-side callers should not invoke
    /// this directly — the GPU crate's hook is the only legal caller.
    #[must_use]
    pub fn new(
        inner: Arc<dyn AnyDeviceHandle>,
        num_row_variables: usize,
        num_interaction_variables: usize,
        circuit_id: u64,
    ) -> Self {
        Self { inner, num_row_variables, num_interaction_variables, circuit_id }
    }

    /// log₂ of row count for the layer this handle points to.
    #[inline]
    #[must_use]
    pub fn num_row_variables(&self) -> usize {
        self.num_row_variables
    }

    /// log₂ of (max chip-interaction count rounded up).
    #[inline]
    #[must_use]
    pub fn num_interaction_variables(&self) -> usize {
        self.num_interaction_variables
    }

    /// Multi-GPU scoping ID (see field doc).
    #[inline]
    #[must_use]
    pub fn circuit_id(&self) -> u64 {
        self.circuit_id
    }

    /// Borrow the opaque payload as `&dyn AnyDeviceHandle` —
    /// callers downcast via `Arc::downcast` on the cloned inner
    /// (the GPU crate owns the concrete type).
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &Arc<dyn AnyDeviceHandle> {
        &self.inner
    }

    /// bridge to the V3 hook's untyped
    /// [`crate::shard_level::sumcheck_poly::DeviceLayerHandle`]
    /// (`Arc<dyn Any + Send + Sync>`).
    ///
    /// Both handle types ultimately wrap the same concrete payload
    /// owned by the GPU crate; this method clones the `Arc` and
    /// upcasts the trait object so the dispatch site can feed the
    /// scope-attached handle into the V3 hook's `input:
    /// Option<DeviceLayerHandle>` parameter without forcing the
    /// caller to thread two distinct handle types through.
    ///
    /// Trait upcasting (`Arc<dyn AnyDeviceHandle>` →
    /// `Arc<dyn Any + Send + Sync>`) is stable since rustc 1.86; the
    /// `AnyDeviceHandle: Any + Send + Sync` supertrait bound makes
    /// the upcast well-defined.
    #[inline]
    #[must_use]
    pub fn to_sumcheck_handle(
        &self,
    ) -> crate::shard_level::sumcheck_poly::DeviceLayerHandle {
        let any_arc: Arc<dyn core::any::Any + Send + Sync> = self.inner.clone();
        crate::shard_level::sumcheck_poly::DeviceLayerHandle(any_arc)
    }
}

impl core::fmt::Debug for DeviceLayerHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceLayerHandle")
            .field("num_row_variables", &self.num_row_variables)
            .field("num_interaction_variables", &self.num_interaction_variables)
            .field("circuit_id", &self.circuit_id)
            .finish_non_exhaustive()
    }
}

/// Input data needed to regenerate the first layer from raw chips +
/// jagged traces on demand.
///
/// Analogue of SP1's
/// `GkrInputData`
/// — kept type-erased and device-agnostic on the stark side.
///
/// The GPU crate's registry stores the actual chip + trace pointers
/// and looks them up via `circuit_id`.  Stark-side callers only need
/// the shape metadata to dispatch on, so we don't pull the heavy
/// `JaggedTraceMle` / chip-set types in here.
///
/// **#371 / #376 hook-point:** The
/// [`crate::basefold_late_binding::GpuGenerateFirstLayerFn`] hook
/// accepts a `circuit_id` and consults the ziren-gpu side's
/// per-circuit registry — the [`DeviceInputData::input_handle`]
/// payload below carries the matching opaque chip/trace bundle.
#[derive(Clone)]
pub struct DeviceInputData {
    /// Multi-GPU scoping ID (matches [`DeviceLayerHandle::circuit_id`]).
    pub circuit_id: u64,
    /// log₂ of the maximum padded row count across the shard's chips.
    /// `generate_first_layer` reduces this by 1, mirroring SP1's
    /// `num_row_variables = input.num_row_variables - 1` convention.
    pub num_row_variables: u32,
    /// log₂ of (total interaction count rounded up to the next power
    /// of two).
    pub num_interaction_variables: u32,
    /// opaque input-data bundle the GPU side
    /// downcasts when the regen hook fires.
    ///
    /// Analogue of SP1's
    /// `GkrInputData`
    /// `chip_set` / `all_interactions` / `jagged_trace_data` / `alpha`
    /// / `beta_seed` fields — Ziren keeps them type-erased on the
    /// stark side and lets ziren-gpu own the concrete payload type
    /// (typically wrapping the per-shard
    /// [`crate::shard_level::DeviceTraceProvider`] + the alpha/beta
    /// challenges + the chip ordering vec).
    ///
    /// **Lifetime contract**: when present, the payload MUST stay
    /// alive for as long as the GKR-circuit walk could fire the
    /// regen hook on this `circuit_id`.  In practice the ziren-gpu
    /// side stashes the payload in its `PerCircuitRegistry` (keyed
    /// by `circuit_id`) at `gpu_layer_init_hook` time and drops it
    /// alongside the rest of the bucket at
    /// `gpu_layer_drain_circuit_hook`.
    ///
    /// **`None` semantics**: the regen hook is unavailable for this
    /// circuit (no recompute mode armed, or older ziren-gpu build).
    /// `DeviceLogupGkrCircuit::next` translates the missing payload
    /// into a return-`None`, surfacing the existing pull-stub panic
    /// in ziren-gpu when the drop path was taken without a regen hook.
    pub input_handle: Option<alloc::sync::Arc<dyn core::any::Any + Send + Sync>>,
}

impl DeviceInputData {
    /// Construct a `DeviceInputData` with `input_handle = None` —
    /// the minimal shape needed by today's call sites (#368 / #383
    /// scaffold, which carries no regen payload).
    ///
    /// Use [`Self::with_input_handle`] (or the builder-style
    /// [`Self::set_input_handle`]) to install the regen payload
    /// before handing the struct off to a [`DeviceLogupGkrCircuit`]
    /// that may need to invoke
    /// [`crate::basefold_late_binding::GpuGenerateFirstLayerFn`].
    #[must_use]
    pub fn new(
        circuit_id: u64,
        num_row_variables: u32,
        num_interaction_variables: u32,
    ) -> Self {
        Self {
            circuit_id,
            num_row_variables,
            num_interaction_variables,
            input_handle: None,
        }
    }

    /// Builder variant of [`Self::new`] that takes the opaque
    /// regen payload.
    #[must_use]
    pub fn with_input_handle(
        circuit_id: u64,
        num_row_variables: u32,
        num_interaction_variables: u32,
        input_handle: alloc::sync::Arc<dyn core::any::Any + Send + Sync>,
    ) -> Self {
        Self {
            circuit_id,
            num_row_variables,
            num_interaction_variables,
            input_handle: Some(input_handle),
        }
    }

    /// Install or replace the opaque regen payload after
    /// construction.  Returns the previous value (if any).
    pub fn set_input_handle(
        &mut self,
        handle: alloc::sync::Arc<dyn core::any::Any + Send + Sync>,
    ) -> Option<alloc::sync::Arc<dyn core::any::Any + Send + Sync>> {
        self.input_handle.replace(handle)
    }
}

impl core::fmt::Debug for DeviceInputData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceInputData")
            .field("circuit_id", &self.circuit_id)
            .field("num_row_variables", &self.num_row_variables)
            .field("num_interaction_variables", &self.num_interaction_variables)
            .field(
                "input_handle",
                &self.input_handle.as_ref().map(|_| "<opaque>"),
            )
            .finish()
    }
}

/// A single circuit layer, mirroring SP1's
/// `GkrCircuitLayer`.
///
/// Three variants:
/// * [`DeviceCircuitLayer::FirstLayer`] — the bottom-most circuit
///   layer (`num_row_variables == input.num_row_variables - 1` after
///   per-chip jagged-mle assembly).  Holds the row-major denominator
///   / numerator buffers in device memory via the opaque
///   [`DeviceLayerHandle`].
/// * [`DeviceCircuitLayer::Materialized`] — any subsequent layer
///   produced by `gkr_transition`.  Same shape metadata as
///   `FirstLayer`, just at half the row dimension.
/// * [`DeviceCircuitLayer::FirstLayerVirtual`] — a placeholder for
///   the FirstLayer that has NOT yet been materialized.  When
///   `recompute_first_layer == true` we defer generating the
///   FirstLayer until `next()` walks back to it; this avoids holding
///   the heaviest layer (which dominates GPU memory) across every
///   intermediate round.
///
/// The `_phantom` generics are kept identical to the host-side
/// [`super::layer::GkrCircuitLayer`] so call-site signatures
/// can swap between the two with a single type substitution.
pub enum DeviceCircuitLayer<F: Field, EF: ExtensionField<F>> {
    /// Materialized first layer (the lowest layer of the GKR
    /// circuit, after first-round jagged-mle assembly).
    FirstLayer(DeviceLayerHandle, PhantomData<(F, EF)>),
    /// Materialized intermediate or terminal layer (produced by
    /// `gkr_transition` on the way up).
    Materialized(DeviceLayerHandle, PhantomData<(F, EF)>),
    /// Lazy first-layer placeholder — `next()` will materialize it
    /// from `input_data` on demand.
    FirstLayerVirtual(DeviceInputData, PhantomData<(F, EF)>),
}

impl<F: Field, EF: ExtensionField<F>> DeviceCircuitLayer<F, EF> {
    /// log₂ of row count for this layer.
    ///
    /// For [`Self::FirstLayerVirtual`] this returns
    /// `input.num_row_variables - 1` — matching SP1's convention
    /// that the first-layer generation reduces by 1.
    #[must_use]
    pub fn num_row_variables(&self) -> usize {
        match self {
            Self::FirstLayer(h, _) => h.num_row_variables(),
            Self::Materialized(h, _) => h.num_row_variables(),
            Self::FirstLayerVirtual(d, _) => (d.num_row_variables.saturating_sub(1)) as usize,
        }
    }

    /// log₂ of (max chip-interaction count rounded up).
    #[must_use]
    pub fn num_interaction_variables(&self) -> usize {
        match self {
            Self::FirstLayer(h, _) => h.num_interaction_variables(),
            Self::Materialized(h, _) => h.num_interaction_variables(),
            Self::FirstLayerVirtual(d, _) => d.num_interaction_variables as usize,
        }
    }

    /// Returns the opaque device handle for materialized layers, or
    /// `None` for the lazy [`Self::FirstLayerVirtual`] placeholder.
    #[must_use]
    pub fn as_handle(&self) -> Option<&DeviceLayerHandle> {
        match self {
            Self::FirstLayer(h, _) | Self::Materialized(h, _) => Some(h),
            Self::FirstLayerVirtual(_, _) => None,
        }
    }

    /// `true` for the lazy `FirstLayerVirtual` placeholder; `false`
    /// for materialized layers.
    #[must_use]
    pub fn is_virtual(&self) -> bool {
        matches!(self, Self::FirstLayerVirtual(_, _))
    }
}

impl<F: Field, EF: ExtensionField<F>> core::fmt::Debug for DeviceCircuitLayer<F, EF> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FirstLayer(h, _) => f.debug_tuple("FirstLayer").field(h).finish(),
            Self::Materialized(h, _) => f.debug_tuple("Materialized").field(h).finish(),
            Self::FirstLayerVirtual(d, _) => f.debug_tuple("FirstLayerVirtual").field(d).finish(),
        }
    }
}

/// Device-resident GKR circuit container — analogue of SP1's
/// `LogUpCudaCircuit`.
///
/// Holds the full layer stack as a vector that callers pop from the
/// bottom upward via [`Self::next`].  When
/// `num_virtual_layers > 0` and the materialized stack is empty,
/// `next()` will (in a future V3 hook landing — #371) materialize the
/// FirstLayer on demand from `input_data` rather than keeping it in
/// device memory across every intermediate round.
///
/// ## Layer ordering
///
/// `materialized_layers` is stored bottom-up — the terminal layer is
/// at index 0, and the FirstLayer (or its virtual placeholder) is at
/// the END of the vector.  `next()` pops from the back (matches SP1's
/// `materialized_layers.pop()`), so the prover walks bottom-up by
/// reverse iteration.
///
/// ## Iterator semantics
///
/// * Constructed via [`Self::new`] with the full materialized layer
///   stack + optional virtual first-layer placeholder.
/// * Each [`Self::next`] call returns the bottom-most layer, or the
///   regenerated FirstLayer when the stack is exhausted and
///   `num_virtual_layers > 0`.
/// * Returns `None` once both are exhausted.
pub struct DeviceLogupGkrCircuit<F: Field, EF: ExtensionField<F>> {
    /// Materialized layer stack, bottom-up.  `pop()` yields the
    /// terminal first, then intermediate Materialized layers, then
    /// the FirstLayer if it was materialized eagerly.
    pub materialized_layers: Vec<DeviceCircuitLayer<F, EF>>,
    /// Input data needed to regenerate the FirstLayer on demand
    /// (used only when `num_virtual_layers > 0`).
    pub input_data: DeviceInputData,
    /// Number of layers that have NOT yet been materialized — in
    /// practice this is `0` (eager) or `1` (lazy first-layer).
    /// Mirrors SP1's `num_virtual_layers` field.
    pub num_virtual_layers: usize,
    _phantom: PhantomData<(F, EF)>,
}

impl<F: Field, EF: ExtensionField<F>> DeviceLogupGkrCircuit<F, EF> {
    /// Build a new circuit from a fully-materialized layer stack and
    /// optional `num_virtual_layers` (set to `1` when the FirstLayer
    /// is deferred, `0` when it was materialized eagerly).
    #[must_use]
    pub fn new(
        materialized_layers: Vec<DeviceCircuitLayer<F, EF>>,
        input_data: DeviceInputData,
        num_virtual_layers: usize,
    ) -> Self {
        debug_assert!(
            num_virtual_layers <= 1,
            "DeviceLogupGkrCircuit: num_virtual_layers must be 0 or 1, got {num_virtual_layers}"
        );
        Self {
            materialized_layers,
            input_data,
            num_virtual_layers,
            _phantom: PhantomData,
        }
    }

    /// Total number of layers remaining to be yielded by `next()`.
    ///
    /// Equals `materialized_layers.len() + num_virtual_layers`.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.materialized_layers.len() + self.num_virtual_layers
    }

    /// `true` when no layers remain to be yielded.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.materialized_layers.is_empty() && self.num_virtual_layers == 0
    }

    /// Peek at the shape of the next layer that [`Self::next`] would
    /// yield, WITHOUT consuming it.
    ///
    /// Returns `(num_row_variables, num_interaction_variables)` of the
    /// top-of-stack [`DeviceCircuitLayer`] or `None` when the circuit
    /// is exhausted.
    ///
    /// ## `#398 ` — device-resident consumer
    ///
    /// The intermediate-layer consumer in `top_level.rs` uses this
    /// peek to discover the shape of a scope-installed layer BEFORE
    /// deciding whether to skip `pull_device_layer_to_host`.  When the
    /// peek's shape matches the `LayerState::Device` entry's
    /// `(num_row_variables, num_interaction_variables)`, the consumer
    /// can construct a shape-only `GkrCircuitLayer` proxy (empty cell
    /// vectors) and skip the host pull entirely — the V3 dispatch
    /// site reads the actual data from the scope-attached device
    /// handle via `scope.next_layer().to_sumcheck_handle()`.
    ///
    /// Mirrors SP1's pattern in
    /// `LogUpCudaCircuit::next`
    /// — except SP1 doesn't need a peek because its consumer never
    /// has a host fallback path.
    #[inline]
    #[must_use]
    pub fn peek_next_layer_shape(&self) -> Option<(usize, usize)> {
        if let Some(last) = self.materialized_layers.last() {
            return Some((last.num_row_variables(), last.num_interaction_variables()));
        }
        if self.num_virtual_layers == 0 {
            return None;
        }
        debug_assert_eq!(
            self.num_virtual_layers, 1,
            "DeviceLogupGkrCircuit: lazy regeneration only supports a single virtual layer"
        );
        // Lazy first-layer placeholder shape — reduces `num_row_variables`
        // by one to match SP1's `generate_first_layer` convention.
        Some((
            (self.input_data.num_row_variables.saturating_sub(1)) as usize,
            self.input_data.num_interaction_variables as usize,
        ))
    }

    /// Pop the next layer in bottom-up order.
    ///
    /// Behavior mirrors SP1's
    /// `LogUpCudaCircuit::next`:
    ///
    /// * If `materialized_layers` is non-empty, pop and return the
    ///   bottom-most.
    /// * Else, if `num_virtual_layers > 0`, regenerate the
    ///   FirstLayer from `input_data` (one-shot — decrement counter).
    /// * Else, return `None`.
    ///
    /// ## `#376  — regen hook dispatch`
    ///
    /// The lazy-regeneration arm consults the registered
    /// [`crate::basefold_late_binding::GpuGenerateFirstLayerFn`] hook
    /// (when the `basefold` feature is on) via `circuit_id`.  When the
    /// hook is registered AND returns `Some(payload)`, we wrap it in a
    /// fresh [`DeviceCircuitLayer::FirstLayer`] and return it.  When
    /// the hook is unregistered OR returns `None`, this arm decrements
    /// `num_virtual_layers` and returns `None` — the upstream
    /// `gpu_layer_pull_hook` in ziren-gpu already special-cases
    /// "dropped-but-no-regen" with a detailed diagnostic panic (see
    /// the related design memo).
    ///
    /// **Note**: until the ziren-gpu side wires its CUDA
    /// `generate_first_layer` kernel + concrete `input_handle`
    /// downcast (multi-day work — see
    /// the related design memo), callers SHOULD
    /// continue to construct `DeviceLogupGkrCircuit` with
    /// `num_virtual_layers == 0` and rely on the existing
    /// eager-pull-to-host path.  The dispatch here is
    /// correctness-preserving when the hook is unregistered (returns
    /// `None` cleanly), but the upstream pull stub in ziren-gpu will
    /// still fire if the production round loop actually revisits a
    /// dropped seq=1.
    pub fn next(&mut self) -> Option<DeviceCircuitLayer<F, EF>> {
        if let Some(layer) = self.materialized_layers.pop() {
            return Some(layer);
        }
        if self.num_virtual_layers == 0 {
            return None;
        }
        debug_assert_eq!(
            self.num_virtual_layers, 1,
            "DeviceLogupGkrCircuit: lazy regeneration only supports a single virtual layer"
        );
        // Decrement first so a second `next()` after a failed regen
        // attempt cleanly returns `None` without re-entering this arm.
        self.num_virtual_layers = 0;

        // consult the registered regen hook (gated
        // on the `basefold` feature; `basefold_late_binding` is itself
        // `#![cfg(feature = "basefold")]`).  When the hook is
        // unregistered (no ziren-gpu CUDA impl yet) OR returns `None`
        // (downcast failed / kernel error), surface `None` to the
        // caller — the upstream pull-stub panic in ziren-gpu's
        // `gpu_layer_pull_hook` remains the primary signal that the
        // regen path was needed but unavailable.
        #[cfg(feature = "basefold")]
        {
            if let Some(hook) =
                crate::basefold_late_binding::get_gpu_generate_first_layer_hook()
            {
                if let Some(payload) = hook(self.input_data.circuit_id) {
                    let handle = DeviceLayerHandle::new(
                        payload.inner,
                        payload.num_row_variables,
                        payload.num_interaction_variables,
                        self.input_data.circuit_id,
                    );
                    return Some(DeviceCircuitLayer::FirstLayer(handle, PhantomData));
                }
            }
        }
        None
    }

    /// Returns the input-data circuit ID — useful for the GPU
    /// registry to scope handles per-`build_device_gkr_circuit`
    /// invocation.
    #[inline]
    #[must_use]
    pub fn circuit_id(&self) -> u64 {
        self.input_data.circuit_id
    }
}

/// Per-shard LogUp-GKR task scope (Ziren analogue of SP1's
/// `LogUpCudaCircuit<'a, TaskScope>` lifetime).
///
/// **Why this exists**
///
/// SP1's `LogUpCudaCircuit<'a, A: Backend>` holds the materialized device
/// layers + input data behind a `TaskScope` lifetime (see
/// `sp1-gpu/crates/logup_gkr/src/utils.rs:151-161`).  Every
/// per-round sumcheck call within a shard's GKR walk reuses the same
/// device-resident state — the scope amortizes one upload across `~18`
/// layers' worth of `prove_gkr_round` invocations.
///
/// Ziren today re-marshals on every V3 dispatch (`round.rs:3891-3902`):
/// `flatten_layer + build_eq_table + cast_vec_ef_to_ef4 + hook`.  Profile
/// data in the related design memo attributes the **+94%
/// tendermint regression** when `ZIREN_GPU_LOGUP_GKR_DEVICE=1` to this
/// per-layer marshalling × ~3400 calls/shard.
///
/// **Scope semantics**
///
/// One `LogupTaskScope<F, EF>` is allocated per `prove_shard_logup_gkr_rows`
/// invocation:
///
/// * **Construction** binds a fresh `circuit_id` (multi-GPU isolation —
///   matches `LayerState::Device::circuit_id` from #230) and stashes the
///   scope handle in a thread-local slot so the V3 dispatch site
///   (`try_logup_round_gpu_v3`) can consult it without threading new
///   arguments through Ziren's per-round signatures.
///
/// * **Drop** clears the slot AND the V3 next-layer TLS
///   (`clear_logup_v3_next_handle`), preventing the last shard's terminal
///   handle from leaking into the next shard's first V3 call.  Today
///   `clear_logup_v3_next_handle` has zero call-sites — confirmed via
///   grep against `crates/stark/src/` — and the regression analysis
///   identifies this lack of scope boundary as a contributing factor.
///
/// **Smallest-sub-step (this commit) — scaffold, zero behavior change**
///
/// * Defines the type + TLS plumbing.
/// * Adds an RAII `enter()` helper that callers wrap around the GKR
///   pipeline.  No callers consult the scope yet — the dispatch site at
///   `round.rs:3880-3902` still goes through the existing `*_next_handle`
///   TLS path.
/// * On Drop: clears `LOGUP_V3_NEXT_HANDLE` so shard boundaries are
///   correctly scoped (today's silent bug per `project_v3_regression`).
///
/// **Follow-up sub-steps (multi-week roadmap — see project memory)**
///
/// 1. Wire `prove_shard_logup_gkr_rows` to construct the scope on entry
///    (RAII guard) and pass a borrow into `prove_gkr_round`.
/// 2. Migrate `take_logup_v3_next_handle` / `publish_logup_v3_next_handle`
///    to consult `scope.materialized_handles` instead of a thread-local
///    Option — so the cross-shard race becomes structurally impossible.
/// 3. Move the V3 cache populator from its bespoke TLS
///    (`v3_cache_populate.rs:try_populate_cache`) into the scope's
///    `materialized_handles` Vec — the V3 hook then pops from the scope
///    directly.
/// 4. Eventually port SP1's `gkr_transition` device-side so the scope
///    pre-builds ALL intermediate layers at scope start (single
///    `concat_chips_to_flat` + N `gkr_transition` kernel launches)
///    and per-round dispatch becomes a pop-only operation.
pub struct LogupTaskScope<F: Field, EF: ExtensionField<F>> {
    /// Multi-GPU scoping ID — fresh per scope, matches the
    /// `LayerState::Device::circuit_id` convention.
    circuit_id: u64,
    /// Optional pre-materialized device circuit.  When the V3-cache
    /// populator ( above) lands, this is filled at scope
    /// construction; per-round V3 calls then pop from
    /// `circuit.materialized_layers` rather than re-marshalling host
    /// vecs.  `None` today — scope-as-anchor only.
    circuit: Option<DeviceLogupGkrCircuit<F, EF>>,
    /// Mirrors SP1's `LogUpCudaCircuit::input_data` shape metadata so
    /// downstream consumers can interrogate the scope without holding a
    /// fully-built circuit.
    input_data: Option<DeviceInputData>,
    _phantom: PhantomData<(F, EF)>,
}

impl<F: Field, EF: ExtensionField<F>> LogupTaskScope<F, EF> {
    /// Construct a new scope with a fresh `circuit_id`.  The scope is
    /// **not** yet bound to the thread-local slot — callers must use
    /// [`Self::enter`] to obtain an RAII guard that performs the bind.
    #[must_use]
    pub fn new(circuit_id: u64) -> Self {
        Self {
            circuit_id,
            circuit: None,
            input_data: None,
            _phantom: PhantomData,
        }
    }

    /// Install a freshly-built `DeviceLogupGkrCircuit` into the scope.
    /// Called by the populator () once the device-side layer
    /// transition pipeline materializes the layer stack up-front.
    pub fn install_circuit(&mut self, circuit: DeviceLogupGkrCircuit<F, EF>) {
        self.input_data = Some(circuit.input_data.clone());
        self.circuit = Some(circuit);
    }

    /// Returns the scope's `circuit_id`.
    #[inline]
    #[must_use]
    pub fn circuit_id(&self) -> u64 {
        self.circuit_id
    }

    /// Borrow the pre-materialized circuit, if installed.
    #[inline]
    #[must_use]
    pub fn circuit(&self) -> Option<&DeviceLogupGkrCircuit<F, EF>> {
        self.circuit.as_ref()
    }

    /// Borrow the input-data shape metadata, if installed.
    #[inline]
    #[must_use]
    pub fn input_data(&self) -> Option<&DeviceInputData> {
        self.input_data.as_ref()
    }

    /// Pop the bottom-most layer handle from the installed circuit, if
    /// any.  Returns `None` when no circuit was installed (today's
    /// default — scope-as-anchor) or when the circuit is exhausted.
    ///
    /// Sub-step 2 of the roadmap above will rewire
    /// `take_logup_v3_next_handle` to call into this method instead of
    /// a free-standing TLS.
    pub fn next_layer(&mut self) -> Option<DeviceCircuitLayer<F, EF>> {
        self.circuit.as_mut().and_then(|c| c.next())
    }

    /// read-only shape peek on the next layer.
    ///
    /// Returns `(num_row_variables, num_interaction_variables)` of the
    /// top-of-stack layer without consuming it.  `None` when no
    /// circuit was installed or the stack is exhausted.
    ///
    /// Used by the device-resident consumer path in `top_level.rs` to
    /// validate that the scope-installed layer matches the
    /// `LayerState::Device` entry's shape BEFORE skipping
    /// `pull_device_layer_to_host`.  When the shapes match AND the
    /// `ZIREN_LOGUP_DEVICE_CONSUMER` flag is set, the consumer skips
    /// the host pull and passes a shape-only proxy to
    /// `prove_gkr_round`.  Byte-equivalent to the legacy path when
    /// the V3 hook (which reads from the scope handle) is registered
    /// and active.
    #[inline]
    #[must_use]
    pub fn peek_next_layer_shape(&self) -> Option<(usize, usize)> {
        self.circuit.as_ref().and_then(|c| c.peek_next_layer_shape())
    }

    /// install a circuit from a populator-provided
    /// payload vector.  Each entry becomes a [`DeviceCircuitLayer::
    /// Materialized`]; ordering is bottom-up (matches
    /// `materialized_layers.pop()` semantics — see SP1's
    /// `generate_gkr_circuit` at `sp1-gpu/crates/logup_gkr/src/
    /// tracegen.rs:188-246` for the canonical order).
    ///
    /// The populator (a ziren-gpu side hook, ) is responsible
    /// for ordering: index 0 = TERMINAL (smallest `num_row_variables`,
    /// popped LAST), last index = FIRST LAYER (largest, popped FIRST).
    ///
    /// `num_virtual_layers` is set to `0` — populators that materialize
    /// every layer up front (the SP1-style "eager" mode) need no lazy
    /// regen; deferred-FirstLayer mode is a future extension.
    pub fn install_circuit_from_payloads(
        &mut self,
        payloads: Vec<DeviceCircuitLayerPayload>,
        input_data: DeviceInputData,
    ) {
        let layers: Vec<DeviceCircuitLayer<F, EF>> = payloads
            .into_iter()
            .map(|p| {
                let handle = DeviceLayerHandle::new(
                    p.inner,
                    p.num_row_variables,
                    p.num_interaction_variables,
                    input_data.circuit_id,
                );
                DeviceCircuitLayer::Materialized(handle, PhantomData)
            })
            .collect();
        self.install_circuit(DeviceLogupGkrCircuit::new(
            layers,
            input_data,
            0,
        ));
    }
}

/// populator payload describing a single device-side
/// GKR layer's opaque handle + shape metadata.
///
/// Returned by the [`crate::basefold_late_binding::GpuLogupScopePopulateFn`]
/// hook and consumed by [`LogupTaskScope::install_circuit_from_payloads`]
/// to build the per-shard `DeviceLogupGkrCircuit` at scope-entry without
/// pulling any device-side types into the stark crate.
///
/// The `inner` Arc payload is whatever concrete type the registered V3
/// hook downcasts to — today that's ziren-gpu's `DeviceLogupLayerState`.
/// The stark crate treats it as fully opaque via the
/// [`AnyDeviceHandle`] marker trait (`Any + Send + Sync`).
#[derive(Clone)]
pub struct DeviceCircuitLayerPayload {
    /// Opaque type-erased payload — concrete impl supplied by the
    /// registered ziren-gpu populator hook.
    pub inner: Arc<dyn AnyDeviceHandle>,
    /// log₂ of row count for this layer.
    pub num_row_variables: usize,
    /// log₂ of (max chip-interaction count rounded up).
    pub num_interaction_variables: usize,
}

impl core::fmt::Debug for DeviceCircuitLayerPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceCircuitLayerPayload")
            .field("num_row_variables", &self.num_row_variables)
            .field("num_interaction_variables", &self.num_interaction_variables)
            .finish_non_exhaustive()
    }
}

/// Thread-local slot carrying the per-shard scope `circuit_id`.
///
/// Used for diagnostic / multi-GPU-isolation introspection by callers
/// that don't need to consult the typed scope state — see
/// [`LOGUP_TASK_SCOPE_PTR`] below for the typed pointer used by the V3
/// dispatch.
std::thread_local! {
    static LOGUP_TASK_SCOPE_ACTIVE: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
}

/// typed pointer slot for the V3 dispatch site.
///
/// Stores a raw `*mut LogupTaskScope<KoalaBear, Ef4>` for the
/// production scope (`(F, EF) = (KoalaBear, Ef4)`).  The V3 dispatch
/// at `round.rs:try_logup_round_gpu_v3` reads this slot to:
///
/// 1. Pop a pre-materialized [`DeviceCircuitLayer`] from the scope's
///    installed [`DeviceLogupGkrCircuit`].
/// 2. Bridge the layer's [`DeviceLayerHandle`] into the V3 hook's
///    untyped handle parameter via
///    [`DeviceLayerHandle::to_sumcheck_handle`].
/// 3. Skip the per-call `flatten_layer` + `cast_vec_ef_to_ef4` host
///    marshalling — projected -500 µs per round per
///    the related design memo.
///
/// **Type erasure rationale**: TLS slots cannot hold generic types,
/// so we pin the slot to the single concrete `(KoalaBear, Ef4)`
/// production scope.  Non-production callers (e.g. test code with a
/// different EF) see `None` here and fall through to the existing
/// `take_logup_v3_next_handle` path — byte-equivalent to pre-#383.
///
/// **Safety contract**: the pointer is set exclusively by
/// [`LogupTaskScopeGuard::enter_with_scope`] from a `&mut
/// LogupTaskScope<KoalaBear, Ef4>` whose lifetime strictly outlives
/// the guard.  The guard's `Drop` impl restores the prior slot value
/// before the borrow ends, so the dispatch site never observes a
/// dangling pointer.
type ProductionScope = LogupTaskScope<
    p3_koala_bear::KoalaBear,
    p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>,
>;

std::thread_local! {
    static LOGUP_TASK_SCOPE_PTR: std::cell::Cell<Option<core::ptr::NonNull<ProductionScope>>> =
        const { std::cell::Cell::new(None) };
}

/// typed accessor for the V3 dispatch site.
///
/// Invokes `f` with a mutable borrow of the currently-active
/// production scope, if any.  Returns `None` when:
///
/// * No `LogupTaskScopeGuard::enter_with_scope` is active on this
///   thread (e.g. tests using `enter(circuit_id)` only), or
/// * The active guard's scope is not the production `(KoalaBear,
///   Ef4)` type.
///
/// **Safety**: the slot is set exclusively by
/// `LogupTaskScopeGuard::enter_with_scope` under the borrow contract
/// documented on [`LOGUP_TASK_SCOPE_PTR`].  This function dereferences
/// the raw pointer for the duration of `f`.  Nesting through `f` is
/// safe because Rust's borrow checker prevents simultaneous mutable
/// borrows on a single-threaded TLS slot.
#[must_use]
pub fn with_production_scope_mut<R>(
    f: impl FnOnce(&mut ProductionScope) -> R,
) -> Option<R> {
    let ptr = LOGUP_TASK_SCOPE_PTR.with(|c| c.get())?;
    // SAFETY: see safety contract on LOGUP_TASK_SCOPE_PTR. The pointer
    // was set by enter_with_scope from a &mut borrow whose lifetime
    // strictly outlives this dispatch call (guard held on the same
    // thread for the duration of prove_shard_logup_gkr_rows).
    let scope: &mut ProductionScope = unsafe { ptr.as_ptr().as_mut().expect("non-null") };
    Some(f(scope))
}

/// RAII guard returned by [`LogupTaskScopeGuard::enter`] /
/// [`LogupTaskScopeGuard::enter_with_scope`].  Binds the scope's
/// `circuit_id` (and optionally a typed pointer to the scope itself)
/// into the per-thread slots for the lifetime of the guard; on drop,
/// restores the prior slot values AND clears the V3 next-layer TLS so
/// the next shard's first V3 call starts from a clean state.
///
/// **Drop semantics matter**: today's `LOGUP_V3_NEXT_HANDLE` is never
/// cleared at shard boundaries (`clear_logup_v3_next_handle` has zero
/// other call-sites — see grep in the related design memo).
/// Wrapping `prove_shard_logup_gkr_rows` in a `LogupTaskScopeGuard` is
/// the smallest fix that introduces a real scope boundary.
#[must_use = "the guard must be held for the duration of the GKR walk; \
              drop clears the per-shard handle TLS"]
pub struct LogupTaskScopeGuard {
    /// Prior scope's `circuit_id`, restored on drop.  Supports nested
    /// scopes for tests; production has only one level.
    prior: Option<u64>,
    /// Prior typed-scope pointer, restored on drop.  `None` when the
    /// guard was constructed via [`Self::enter`] (untyped); `Some(_)`
    /// only when constructed via [`Self::enter_with_scope`] for the
    /// production `(KoalaBear, Ef4)` type.
    prior_ptr: Option<core::ptr::NonNull<ProductionScope>>,
}

impl LogupTaskScopeGuard {
    /// Bind a new untyped scope.  Returns an RAII guard that unbinds
    /// on drop.  Does NOT populate the typed pointer slot — the V3
    /// dispatch falls back to the existing TLS handle path.
    ///
    /// Used for diagnostic / non-production paths where the typed
    /// pointer can't be plumbed (e.g. mismatched generic params).
    #[must_use]
    pub fn enter(circuit_id: u64) -> Self {
        let prior = LOGUP_TASK_SCOPE_ACTIVE.with(|c| c.replace(Some(circuit_id)));
        Self { prior, prior_ptr: None }
    }

    /// bind a typed scope pointer for the V3
    /// dispatch site to consult.  Only effective for the production
    /// `(KoalaBear, Ef4)` scope; other generic instantiations behave
    /// like [`Self::enter`] (circuit_id only).
    ///
    /// # Safety contract
    ///
    /// `scope` must outlive the returned guard.  Production callers
    /// satisfy this by holding the scope on the stack of
    /// `prove_shard_logup_gkr_rows` and the guard via `let _g =` in
    /// the same function — the guard drops at function return,
    /// strictly before the scope's `Drop`.
    #[must_use]
    pub fn enter_with_scope<F, EF>(scope: &mut LogupTaskScope<F, EF>) -> Self
    where
        F: Field + 'static,
        EF: ExtensionField<F> + 'static,
    {
        let circuit_id = scope.circuit_id();
        let prior = LOGUP_TASK_SCOPE_ACTIVE.with(|c| c.replace(Some(circuit_id)));

        // Only install the typed pointer when the generics match the
        // production `(KoalaBear, Ef4)` slot type.  Other instantiations
        // (tests, ports) just get the circuit_id-only behavior.
        let prior_ptr = if core::any::TypeId::of::<F>()
            == core::any::TypeId::of::<p3_koala_bear::KoalaBear>()
            && core::any::TypeId::of::<EF>()
                == core::any::TypeId::of::<
                    p3_field::extension::BinomialExtensionField<
                        p3_koala_bear::KoalaBear,
                        4,
                    >,
                >() {
            // SAFETY: TypeId equality guarantees `LogupTaskScope<F, EF>`
            // and `ProductionScope` have identical layout; the cast is
            // a no-op at runtime.  `scope` outlives the guard by
            // contract (documented above).
            let typed: *mut ProductionScope =
                (scope as *mut LogupTaskScope<F, EF>) as *mut ProductionScope;
            let nn = core::ptr::NonNull::new(typed).expect("scope ptr non-null");
            LOGUP_TASK_SCOPE_PTR.with(|c| c.replace(Some(nn)))
        } else {
            None
        };

        Self { prior, prior_ptr }
    }

    /// Returns the currently-active scope `circuit_id`, if any.  Used
    /// by the V3 dispatch site ( of the roadmap above) to
    /// decide whether to consult the scope or fall back to today's
    /// per-call marshalling.
    #[must_use]
    pub fn active_circuit_id() -> Option<u64> {
        LOGUP_TASK_SCOPE_ACTIVE.with(|c| c.get())
    }
}

impl Drop for LogupTaskScopeGuard {
    fn drop(&mut self) {
        // Restore prior typed-scope pointer FIRST so any further work
        // in the prior scope sees its own pointer.  Setting to None
        // when prior_ptr is None preserves the "no scope" state.
        LOGUP_TASK_SCOPE_PTR.with(|c| c.set(self.prior_ptr));
        LOGUP_TASK_SCOPE_ACTIVE.with(|c| c.set(self.prior));
        // Clear the per-V3-call handle TLS — prevents the terminal
        // layer's handle from leaking into the next shard's first call.
        // Today `clear_logup_v3_next_handle` has zero other callers; this
        // closes that gap structurally.
        crate::shard_level::sumcheck_poly::clear_logup_v3_next_handle();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Challenge;
    use p3_koala_bear::KoalaBear;

    type SC = crate::koala_bear_poseidon2::KoalaBearPoseidon2;
    type EF = Challenge<SC>;

    /// Minimal `AnyDeviceHandle` impl for unit tests — carries a tag
    /// the test can downcast to verify identity.
    struct TestHandle {
        tag: u64,
    }
    impl AnyDeviceHandle for TestHandle {}

    fn make_handle(tag: u64, num_row_vars: usize, num_int_vars: usize) -> DeviceLayerHandle {
        DeviceLayerHandle::new(Arc::new(TestHandle { tag }), num_row_vars, num_int_vars, 7)
    }

    /// `next()` walks the materialized stack in bottom-up order and
    /// returns `None` once exhausted.  Mirrors SP1's iteration
    /// pattern.
    #[test]
    fn next_pops_materialized_stack_bottom_up() {
        let input_data = DeviceInputData {
            circuit_id: 7,
            num_row_variables: 4,
            num_interaction_variables: 3,
            input_handle: None,
        };
        // Layers pushed bottom-first: index 0 = terminal (smallest),
        // last index = FirstLayer (largest).  `pop()` yields the
        // last entry first, so we expect FirstLayer first.
        let layers = vec![
            DeviceCircuitLayer::<KoalaBear, EF>::Materialized(make_handle(10, 1, 3), PhantomData),
            DeviceCircuitLayer::<KoalaBear, EF>::Materialized(make_handle(20, 2, 3), PhantomData),
            DeviceCircuitLayer::<KoalaBear, EF>::FirstLayer(make_handle(30, 3, 3), PhantomData),
        ];
        let mut circuit = DeviceLogupGkrCircuit::<KoalaBear, EF>::new(layers, input_data, 0);

        assert_eq!(circuit.len(), 3);
        assert!(!circuit.is_empty());

        let l0 = circuit.next().expect("first layer present");
        assert!(matches!(l0, DeviceCircuitLayer::FirstLayer(_, _)));
        assert_eq!(l0.num_row_variables(), 3);

        let l1 = circuit.next().expect("middle layer present");
        assert!(matches!(l1, DeviceCircuitLayer::Materialized(_, _)));
        assert_eq!(l1.num_row_variables(), 2);

        let l2 = circuit.next().expect("terminal layer present");
        assert!(matches!(l2, DeviceCircuitLayer::Materialized(_, _)));
        assert_eq!(l2.num_row_variables(), 1);

        assert!(circuit.next().is_none());
        assert!(circuit.is_empty());
    }

    /// Constructing with `num_virtual_layers = 0` and an empty stack
    /// yields `None` immediately — the lazy-regen `todo!()` arm
    /// must NOT trigger when the counter is 0.
    #[test]
    fn next_returns_none_when_empty_and_no_virtual_layer() {
        let input_data = DeviceInputData {
            circuit_id: 99,
            num_row_variables: 4,
            num_interaction_variables: 3,
            input_handle: None,
        };
        let mut circuit =
            DeviceLogupGkrCircuit::<KoalaBear, EF>::new(Vec::new(), input_data, 0);
        assert!(circuit.is_empty());
        assert_eq!(circuit.len(), 0);
        assert!(circuit.next().is_none());
        // Repeated calls also yield None.
        assert!(circuit.next().is_none());
    }

    /// when `num_virtual_layers == 1`, the
    /// materialized stack is empty, AND no `GpuGenerateFirstLayerFn`
    /// hook is registered, `next()` returns `None` (rather than
    /// panicking via the old `todo!()` arm).  This is the new safe
    /// default: the regen-on-pull contract is fulfilled by the
    /// upstream `gpu_layer_pull_hook` in ziren-gpu, which already
    /// emits a detailed diagnostic when a dropped seq is pulled and
    /// no regen is available.
    ///
    /// Note: this test cannot positively assert that the hook IS
    /// invoked when registered — the hook is a process-wide
    /// `OnceLock` and the test suite shares it with any other test
    /// (or the prod binary).  We only verify that the `None` path is
    /// graceful; the positive case (hook fires → `Some(FirstLayer)`)
    /// is covered in the integration suite once ziren-gpu lands its
    /// impl.
    #[test]
    fn next_returns_none_when_virtual_and_no_regen_hook() {
        // Hook is unregistered on a fresh test process; if a parallel
        // test happens to register it, we tolerate `Some(...)` here
        // because the contract is "return whatever the hook says".
        let hook_present =
            crate::basefold_late_binding::get_gpu_generate_first_layer_hook()
                .is_some();

        let input_data = DeviceInputData {
            circuit_id: 4242,
            num_row_variables: 6,
            num_interaction_variables: 4,
            input_handle: None,
        };
        let mut circuit =
            DeviceLogupGkrCircuit::<KoalaBear, EF>::new(Vec::new(), input_data, 1);

        assert_eq!(circuit.len(), 1);
        assert!(!circuit.is_empty());

        let next = circuit.next();
        if hook_present {
            // Cannot assert further — hook impl decides.
        } else {
            assert!(
                next.is_none(),
                "no regen hook ⇒ next() returns None instead of panicking"
            );
        }
        assert_eq!(circuit.num_virtual_layers, 0);
        assert!(circuit.is_empty());

        // Repeated calls also yield None.
        assert!(circuit.next().is_none());
    }

    /// `DeviceInputData::new` /
    /// `with_input_handle` / `set_input_handle` builders behave as
    /// specced.
    #[test]
    fn device_input_data_builders() {
        let plain = DeviceInputData::new(11, 3, 2);
        assert_eq!(plain.circuit_id, 11);
        assert_eq!(plain.num_row_variables, 3);
        assert_eq!(plain.num_interaction_variables, 2);
        assert!(plain.input_handle.is_none());

        struct Bundle(u32);
        let handle: Arc<dyn core::any::Any + Send + Sync> = Arc::new(Bundle(99));
        let with = DeviceInputData::with_input_handle(12, 4, 3, handle.clone());
        assert_eq!(with.circuit_id, 12);
        assert!(with.input_handle.is_some());

        // Downcast round-trip preserves payload identity.
        let any_ref: &dyn core::any::Any =
            &**with.input_handle.as_ref().unwrap();
        assert_eq!(any_ref.downcast_ref::<Bundle>().unwrap().0, 99);

        // set_input_handle returns prior (None) and installs new.
        let mut tweaked = DeviceInputData::new(13, 2, 1);
        let prev = tweaked.set_input_handle(handle.clone());
        assert!(prev.is_none());
        assert!(tweaked.input_handle.is_some());

        // Second set returns the previous handle.
        let prev2 = tweaked.set_input_handle(Arc::new(Bundle(7)));
        assert!(prev2.is_some());
    }

    /// `FirstLayerVirtual` placeholder reports the right shape
    /// metadata (input.num_row_variables - 1 / input.num_interaction_variables).
    #[test]
    fn first_layer_virtual_reports_reduced_row_variables() {
        let input = DeviceInputData {
            circuit_id: 1,
            num_row_variables: 5,
            num_interaction_variables: 2,
            input_handle: None,
        };
        let layer = DeviceCircuitLayer::<KoalaBear, EF>::FirstLayerVirtual(input, PhantomData);
        assert!(layer.is_virtual());
        assert_eq!(layer.num_row_variables(), 4);
        assert_eq!(layer.num_interaction_variables(), 2);
        assert!(layer.as_handle().is_none());
    }

    /// `DeviceLayerHandle` plumbs `circuit_id` through unchanged
    /// (multi-GPU isolation, see #230).
    #[test]
    fn handle_carries_circuit_id() {
        let h = make_handle(42, 4, 3);
        assert_eq!(h.circuit_id(), 7);
        assert_eq!(h.num_row_variables(), 4);
        assert_eq!(h.num_interaction_variables(), 3);

        // Downcast the inner Arc<dyn> to recover the original tag.
        let any_ref: &dyn core::any::Any = &**h.inner();
        let test_handle = any_ref.downcast_ref::<TestHandle>().expect("downcast");
        assert_eq!(test_handle.tag, 42);
    }

    /// empty scope (no circuit installed) reports `None` for both
    /// `circuit()` and `next_layer()`.  This is the production default
    /// today; behavior remains identical to pre-#383 dispatch.
    #[test]
    fn task_scope_empty_yields_none() {
        let mut scope = LogupTaskScope::<KoalaBear, EF>::new(123);
        assert_eq!(scope.circuit_id(), 123);
        assert!(scope.circuit().is_none());
        assert!(scope.input_data().is_none());
        assert!(scope.next_layer().is_none());
    }

    /// scope with installed circuit yields layers via `next_layer`
    /// and exposes input-data metadata.  Mirrors SP1's
    /// `LogUpCudaCircuit::next` semantics.
    #[test]
    fn task_scope_with_circuit_pops_layers() {
        let input_data = DeviceInputData {
            circuit_id: 55,
            num_row_variables: 3,
            num_interaction_variables: 2,
            input_handle: None,
        };
        let layers = vec![
            DeviceCircuitLayer::<KoalaBear, EF>::Materialized(make_handle(1, 1, 2), PhantomData),
            DeviceCircuitLayer::<KoalaBear, EF>::FirstLayer(make_handle(2, 2, 2), PhantomData),
        ];
        let circuit = DeviceLogupGkrCircuit::<KoalaBear, EF>::new(layers, input_data, 0);

        let mut scope = LogupTaskScope::<KoalaBear, EF>::new(55);
        scope.install_circuit(circuit);

        assert_eq!(scope.circuit_id(), 55);
        assert!(scope.input_data().is_some());
        assert_eq!(scope.input_data().unwrap().num_row_variables, 3);

        let l0 = scope.next_layer().expect("first layer");
        assert!(matches!(l0, DeviceCircuitLayer::FirstLayer(_, _)));
        let l1 = scope.next_layer().expect("terminal layer");
        assert!(matches!(l1, DeviceCircuitLayer::Materialized(_, _)));
        assert!(scope.next_layer().is_none());
    }

    /// `peek_next_layer_shape` reads the shape of
    /// the top-of-stack layer without consuming it; verify that
    /// `next_layer` still yields the same layer afterward.
    #[test]
    fn peek_next_layer_shape_is_non_consuming() {
        let input_data = DeviceInputData {
            circuit_id: 91,
            num_row_variables: 3,
            num_interaction_variables: 2,
            input_handle: None,
        };
        let layers = vec![
            // bottom-up: terminal first (popped LAST), first_layer last (popped FIRST)
            DeviceCircuitLayer::<KoalaBear, EF>::Materialized(make_handle(7, 1, 2), PhantomData),
            DeviceCircuitLayer::<KoalaBear, EF>::FirstLayer(make_handle(8, 2, 2), PhantomData),
        ];
        let circuit = DeviceLogupGkrCircuit::<KoalaBear, EF>::new(layers, input_data, 0);

        let mut scope = LogupTaskScope::<KoalaBear, EF>::new(91);
        scope.install_circuit(circuit);

        // Peek the top of stack — should be the FirstLayer (last entry).
        let peek1 = scope.peek_next_layer_shape().expect("peek non-empty");
        assert_eq!(peek1, (2, 2));

        // Re-peek without pop yields the same shape.
        let peek2 = scope.peek_next_layer_shape().expect("peek non-empty");
        assert_eq!(peek2, (2, 2));

        // Now pop and verify the next peek shifts to the underlying layer.
        let popped = scope.next_layer().expect("pop FirstLayer");
        assert!(matches!(popped, DeviceCircuitLayer::FirstLayer(_, _)));
        let peek3 = scope.peek_next_layer_shape().expect("peek terminal");
        assert_eq!(peek3, (1, 2));

        // Pop terminal — peek returns None.
        let _popped = scope.next_layer().expect("pop terminal");
        assert!(scope.peek_next_layer_shape().is_none());
    }

    /// `peek_next_layer_shape` returns `None` when
    /// no circuit is installed.
    #[test]
    fn peek_next_layer_shape_none_without_circuit() {
        let scope = LogupTaskScope::<KoalaBear, EF>::new(42);
        assert!(scope.peek_next_layer_shape().is_none());
    }

    /// RAII guard binds + unbinds the active circuit_id slot.
    #[test]
    fn task_scope_guard_binds_and_unbinds() {
        assert!(LogupTaskScopeGuard::active_circuit_id().is_none());
        {
            let _guard = LogupTaskScopeGuard::enter(777);
            assert_eq!(LogupTaskScopeGuard::active_circuit_id(), Some(777));
        }
        assert!(LogupTaskScopeGuard::active_circuit_id().is_none());
    }

    /// nested guards restore the prior active id on drop.
    /// Production has only a single level today, but tests may nest.
    #[test]
    fn task_scope_guard_nests() {
        let outer = LogupTaskScopeGuard::enter(1);
        assert_eq!(LogupTaskScopeGuard::active_circuit_id(), Some(1));
        {
            let _inner = LogupTaskScopeGuard::enter(2);
            assert_eq!(LogupTaskScopeGuard::active_circuit_id(), Some(2));
        }
        assert_eq!(LogupTaskScopeGuard::active_circuit_id(), Some(1));
        drop(outer);
        assert!(LogupTaskScopeGuard::active_circuit_id().is_none());
    }

    /// guard drop clears the V3 next-layer handle TLS, closing
    /// the cross-shard race documented in
    /// the related design memo (`clear_logup_v3_next_handle`
    /// previously had zero callers).
    #[test]
    fn task_scope_guard_clears_v3_handle_on_drop() {
        use crate::shard_level::sumcheck_poly::{
            publish_logup_v3_next_handle, take_logup_v3_next_handle,
            DeviceLayerHandle as V3Handle,
        };
        struct Tag;
        // Install a fake handle as if the prior round had returned one.
        publish_logup_v3_next_handle(V3Handle(Arc::new(Tag) as Arc<_>));
        {
            let _guard = LogupTaskScopeGuard::enter(42);
            // Guard is alive — handle still observable to peek-like calls.
        }
        // Guard dropped — handle MUST be cleared.
        assert!(
            take_logup_v3_next_handle().is_none(),
            "LogupTaskScopeGuard::drop should clear V3 next-handle TLS"
        );
    }

    /// `enter_with_scope` for the production
    /// `(KoalaBear, Ef4)` type installs the typed pointer so the
    /// dispatch site can pop layers via `with_production_scope_mut`.
    #[test]
    fn enter_with_scope_installs_typed_pointer() {
        type Ef4 = p3_field::extension::BinomialExtensionField<KoalaBear, 4>;

        // Outside any guard: production-scope accessor returns None.
        assert!(
            with_production_scope_mut(|_| ()).is_none(),
            "no active guard ⇒ accessor returns None"
        );

        let mut scope = LogupTaskScope::<KoalaBear, Ef4>::new(101);
        {
            let _guard =
                LogupTaskScopeGuard::enter_with_scope::<KoalaBear, Ef4>(&mut scope);
            // Inside the guard: accessor returns Some and yields the
            // scope's circuit_id (proves the pointer points to OUR scope).
            let cid = with_production_scope_mut(|s| s.circuit_id())
                .expect("scope installed");
            assert_eq!(cid, 101);
        }
        // After drop: typed pointer slot cleared.
        assert!(
            with_production_scope_mut(|_| ()).is_none(),
            "guard drop ⇒ typed slot cleared"
        );
    }

    /// `enter_with_scope` for a non-production
    /// `EF` falls back to the untyped behavior: `active_circuit_id`
    /// is bound but `with_production_scope_mut` returns `None`.  This
    /// preserves byte-equivalent behavior for tests / port code that
    /// use a different EF type.
    ///
    /// The test type alias `EF = Challenge<KoalaBearPoseidon2>` happens
    /// to resolve to the production `Ef4` (BinomialExtensionField<KoalaBear, 4>),
    /// so we use `KoalaBear` for both F and EF here (degree-1 self
    /// extension) to get a genuinely non-production type pair.
    #[test]
    fn enter_with_scope_non_production_falls_back_to_untyped() {
        let mut scope = LogupTaskScope::<KoalaBear, KoalaBear>::new(303);
        {
            let _guard = LogupTaskScopeGuard::enter_with_scope::<KoalaBear, KoalaBear>(
                &mut scope,
            );
            assert_eq!(LogupTaskScopeGuard::active_circuit_id(), Some(303));
            // Typed slot remains None for non-production types.
            assert!(
                with_production_scope_mut(|_| ()).is_none(),
                "non-production EF ⇒ typed slot stays None"
            );
        }
        assert!(LogupTaskScopeGuard::active_circuit_id().is_none());
    }

    /// `to_sumcheck_handle` bridges the typed
    /// `device_circuit::DeviceLayerHandle` to the untyped
    /// `sumcheck_poly::DeviceLayerHandle` that the V3 hook accepts,
    /// preserving the underlying Arc payload via trait upcasting.
    #[test]
    fn device_layer_handle_to_sumcheck_handle_bridges_arc() {
        let h = make_handle(99, 4, 3);
        let v3_handle = h.to_sumcheck_handle();
        // The bridged handle's Arc<dyn Any + Send + Sync> downcasts
        // back to the original TestHandle, confirming the upcast
        // preserved the concrete payload.
        let any_ref: &dyn core::any::Any = &*v3_handle.0;
        let test = any_ref.downcast_ref::<TestHandle>().expect("downcast");
        assert_eq!(test.tag, 99);
    }

    /// `install_circuit_from_payloads` builds a
    /// `DeviceLogupGkrCircuit` from populator-provided payloads and
    /// makes `next_layer()` return them in pop-order (bottom-up
    /// reverse).  Mirrors what the ziren-gpu populator hook will do
    /// at scope-entry.
    #[test]
    fn install_circuit_from_payloads_populates_pop_order() {
        let input_data = DeviceInputData {
            circuit_id: 300,
            num_row_variables: 4,
            num_interaction_variables: 2,
            input_handle: None,
        };
        // Payloads ordered bottom-up: index 0 = terminal (popped LAST),
        // last index = FirstLayer (popped FIRST).
        let payloads = vec![
            DeviceCircuitLayerPayload {
                inner: Arc::new(TestHandle { tag: 901 }),
                num_row_variables: 1,
                num_interaction_variables: 2,
            },
            DeviceCircuitLayerPayload {
                inner: Arc::new(TestHandle { tag: 902 }),
                num_row_variables: 2,
                num_interaction_variables: 2,
            },
            DeviceCircuitLayerPayload {
                inner: Arc::new(TestHandle { tag: 903 }),
                num_row_variables: 3,
                num_interaction_variables: 2,
            },
        ];

        let mut scope = LogupTaskScope::<KoalaBear, EF>::new(300);
        assert!(scope.circuit().is_none());
        scope.install_circuit_from_payloads(payloads, input_data.clone());

        // Scope now reports installed circuit + input_data.
        assert!(scope.circuit().is_some());
        assert!(scope.input_data().is_some());
        assert_eq!(scope.input_data().unwrap().circuit_id, 300);

        // Pop order: FirstLayer (tag 903) → intermediate (902) → terminal (901).
        let l0 = scope.next_layer().expect("first layer");
        let h0 = l0.as_handle().expect("materialized handle");
        let any0: &dyn core::any::Any = &**h0.inner();
        assert_eq!(any0.downcast_ref::<TestHandle>().unwrap().tag, 903);
        assert_eq!(h0.num_row_variables(), 3);
        // circuit_id propagated from input_data into the synthesized handle.
        assert_eq!(h0.circuit_id(), 300);

        let l1 = scope.next_layer().expect("middle layer");
        let h1 = l1.as_handle().unwrap();
        assert_eq!(
            (&**h1.inner() as &dyn core::any::Any)
                .downcast_ref::<TestHandle>()
                .unwrap()
                .tag,
            902
        );
        assert_eq!(h1.num_row_variables(), 2);

        let l2 = scope.next_layer().expect("terminal layer");
        let h2 = l2.as_handle().unwrap();
        assert_eq!(
            (&**h2.inner() as &dyn core::any::Any)
                .downcast_ref::<TestHandle>()
                .unwrap()
                .tag,
            901
        );
        assert_eq!(h2.num_row_variables(), 1);

        // Fourth call: exhausted.
        assert!(scope.next_layer().is_none());
    }

    /// empty payload vec installs an empty circuit;
    /// `next_layer()` returns None immediately.  Populators with no
    /// device-side state to share (e.g. host-only path) hit this case.
    #[test]
    fn install_circuit_from_payloads_empty_yields_none() {
        let input_data = DeviceInputData {
            circuit_id: 301,
            num_row_variables: 2,
            num_interaction_variables: 1,
            input_handle: None,
        };
        let mut scope = LogupTaskScope::<KoalaBear, EF>::new(301);
        scope.install_circuit_from_payloads(Vec::new(), input_data);
        // Installed but empty — circuit() Some, next_layer() None.
        assert!(scope.circuit().is_some());
        assert!(scope.input_data().is_some());
        assert!(scope.next_layer().is_none());
    }

    /// pop a layer from an installed scope via
    /// `with_production_scope_mut`, bridge to a sumcheck handle, and
    /// confirm the round-trip.  This mirrors what
    /// `try_logup_round_gpu_v3` does on the hot path once 
    /// installs a circuit.
    #[test]
    fn dispatch_site_pop_and_bridge_roundtrip() {
        type Ef4 = p3_field::extension::BinomialExtensionField<KoalaBear, 4>;
        let input_data = DeviceInputData {
            circuit_id: 200,
            num_row_variables: 3,
            num_interaction_variables: 2,
            input_handle: None,
        };
        let layers = vec![
            DeviceCircuitLayer::<KoalaBear, Ef4>::Materialized(
                make_handle(701, 1, 2),
                PhantomData,
            ),
            DeviceCircuitLayer::<KoalaBear, Ef4>::FirstLayer(
                make_handle(702, 2, 2),
                PhantomData,
            ),
        ];
        let circuit =
            DeviceLogupGkrCircuit::<KoalaBear, Ef4>::new(layers, input_data, 0);

        let mut scope = LogupTaskScope::<KoalaBear, Ef4>::new(200);
        scope.install_circuit(circuit);

        let _guard = LogupTaskScopeGuard::enter_with_scope::<KoalaBear, Ef4>(&mut scope);

        // First call: pops FirstLayer, bridges to a sumcheck handle.
        let h1 = with_production_scope_mut(|s| {
            s.next_layer().and_then(|l| l.as_handle().map(|h| h.to_sumcheck_handle()))
        })
        .expect("scope active")
        .expect("layer popped");
        // Downcast back to confirm we got the FirstLayer's TestHandle.
        let any_ref: &dyn core::any::Any = &*h1.0;
        assert_eq!(any_ref.downcast_ref::<TestHandle>().unwrap().tag, 702);

        // Second call: pops Materialized terminal layer.
        let h2 = with_production_scope_mut(|s| {
            s.next_layer().and_then(|l| l.as_handle().map(|h| h.to_sumcheck_handle()))
        })
        .expect("scope active")
        .expect("terminal layer popped");
        let any_ref2: &dyn core::any::Any = &*h2.0;
        assert_eq!(any_ref2.downcast_ref::<TestHandle>().unwrap().tag, 701);

        // Third call: scope exhausted.
        let empty = with_production_scope_mut(|s| {
            s.next_layer().and_then(|l| l.as_handle().map(|h| h.to_sumcheck_handle()))
        })
        .expect("scope active");
        assert!(empty.is_none(), "exhausted scope yields None");
    }
}
