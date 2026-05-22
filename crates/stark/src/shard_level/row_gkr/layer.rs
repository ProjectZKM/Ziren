//! Layer types for the row-only GKR backend (the task, A.2 step 1).
//!
//! Direct port of
//! `crates/hypercube/src/logup_gkr/cpu.rs:27-73`
//! with the `slop_*` types replaced by Ziren-native containers:
//!
//! | the                          | Ziren equivalent                              |
//! |------------------------------|-----------------------------------------------|
//! | `Vec<PaddedMle<F>>`          | `Vec<RowMajorTable<F>>` (defined below)       |
//! | `Arc<Mle<F>>`                | `Vec<F>` of length `2^num_variables`          |
//! | `slop_multilinear::Point<EF>`| `Vec<EF>`                                     |
//!
//! ## Indexing convention
//!
//! Each per-chip table is indexed `[row, interaction]` row-major.
//! `num_row_variables` = log₂ of row count; `num_interaction_variables`
//! = log₂ of (max chip-interaction count rounded up).  The layer
//! enforces a single shared `(num_row_variables, num_interaction_variables)`
//! across all chips — chips with fewer interactions are padded with
//! identity fractions (`(0, 1)`).
//!
//! ## Why `RowMajorTable` and not `RowMajorMatrix`
//!
//! `p3_matrix::dense::RowMajorMatrix` exists but its API is column-
//! major in a row-major-storage sense (`.row(i)` returns the i-th
//! row's slice).  For GKR's row × interaction folding we need both
//! axes addressable, and the per-cell algorithms are simpler with
//! a thin wrapper that exposes `(row, interaction) -> idx`.

use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_field::{ExtensionField, Field};

/// A 2-D table indexed `[row, interaction]` row-major.
///
/// Storage layout: `cells.len() == (1 << num_row_variables) * num_interactions`.
/// `num_interactions` is the **raw** per-chip column count (not padded
/// to a power of two) — keeping storage small for chips with few
/// interactions while still letting the GKR sumcheck virtually pad to
/// `2^num_interaction_variables` cells via zero/one fill at access
/// time (mirrors SP1's `PaddedMle` pattern; see
/// `crates/hypercube/src/logup_gkr/execution.rs:222-242`).
///
/// `num_interaction_variables` is the log₂ of the per-chip padded width
/// (`num_interactions.next_power_of_two().trailing_zeros()`) — used as
/// metadata for the row-only GKR's per-chip dimension reporting.  The
/// LAYER's `num_interaction_variables` is the global aggregate
/// (computed in `first_layer`) and may exceed any single chip's value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowMajorTable<F> {
    /// Cells in row-major layout: `cells[row * num_interactions + col]`.
    /// When `num_real_rows < (1 << num_row_variables)` the storage holds
    /// only the **real** prefix (= `num_real_rows * num_interactions`
    /// cells).  Virtual rows in `[num_real_rows, 1 << num_row_variables)`
    /// are NOT materialized — readers consult the per-call padding tag
    /// (LogUp-GKR uses `F::ZERO` for numerators, `F::ONE` for
    /// denominators).  This mirrors SP1's `PaddedMle::Constant` pattern
    /// (`slop/crates/multilinear/src/padded.rs`) — see
    /// `crate::basefold::padded::PaddedMle` for the standalone version.
    pub cells: Vec<F>,
    /// log₂ of LOGICAL row count.  The actual allocated storage may be
    /// smaller — see `num_real_rows` for the materialized prefix.
    pub num_row_variables: usize,
    /// log₂ of `num_interactions.next_power_of_two()` — virtual padded
    /// column dimension for sumcheck purposes.
    pub num_interaction_variables: usize,
    /// Raw per-chip column count (= number of interactions in this
    /// chip's lookup set).  Storage stride.  Always ≤ `1 << num_interaction_variables`.
    pub num_interactions: usize,
    /// Number of materialized rows in `cells`.  Always
    /// `<= 1 << num_row_variables`.  When equal, the table is "fully
    /// real" — virtual rows in `[num_real_rows, 1 << num_row_variables)`
    /// would carry the per-quadrant identity-fraction value (0 for
    /// numerators, 1 for denominators).  This skips materializing
    /// padding cells for chips whose real height is far below the
    /// shard-wide row dimension.
    pub num_real_rows: usize,
}

impl<F: Clone> RowMajorTable<F> {
    /// Build a table of `2^num_row_variables × num_interactions` cells
    /// filled with `fill`.  `num_interaction_variables` is derived as
    /// `log₂(num_interactions.next_power_of_two())`.
    #[must_use]
    pub fn filled_raw(
        num_row_variables: usize,
        num_interactions: usize,
        fill: F,
    ) -> Self {
        let total = (1usize << num_row_variables) * num_interactions;
        let num_interaction_variables =
            num_interactions.max(1).next_power_of_two().trailing_zeros() as usize;
        Self {
            cells: vec![fill; total],
            num_row_variables,
            num_interaction_variables,
            num_interactions,
            num_real_rows: 1usize << num_row_variables,
        }
    }

    /// Same shape as `filled_raw` but skips the per-cell init.  Caller
    /// MUST write every cell of `cells[0..total]` before any read.
    /// Used by hot-path constructors (e.g. `layer_transition`) that
    /// would otherwise spend most of their time in `vec![fill; total]`
    /// before unconditionally overwriting every slot.
    ///
    /// # Safety
    ///
    /// Caller is responsible for initializing all `cells[0..total]`
    /// slots before any read.  `F: Copy` is sufficient because Copy
    /// types have no Drop semantics, so leaking uninitialized memory
    /// on panic is sound.
    #[must_use]
    pub unsafe fn filled_raw_uninit(
        num_row_variables: usize,
        num_interactions: usize,
    ) -> Self
    where
        F: Copy + p3_field::PrimeCharacteristicRing,
    {
        let total = (1usize << num_row_variables) * num_interactions;
        let num_interaction_variables =
            num_interactions.max(1).next_power_of_two().trailing_zeros() as usize;
        // FLAKE FIX: see round.rs note. Init to ZERO instead of leaking
        // uninit u32 — KoalaBear serde rejects out-of-range bit patterns.
        let cells: Vec<F> = vec![F::ZERO; total];
        Self {
            cells,
            num_row_variables,
            num_interaction_variables,
            num_interactions,
            num_real_rows: 1usize << num_row_variables,
        }
    }

    /// Build a table where storage width equals the virtual padded
    /// width (`num_interactions = 1 << num_interaction_variables`).
    /// Compatibility constructor for callers that previously used the
    /// pow2-storage layout.
    #[must_use]
    pub fn filled(
        num_row_variables: usize,
        num_interaction_variables: usize,
        fill: F,
    ) -> Self {
        let num_interactions = 1usize << num_interaction_variables;
        let total = (1usize << num_row_variables) * num_interactions;
        Self {
            cells: vec![fill; total],
            num_row_variables,
            num_interaction_variables,
            num_interactions,
            num_real_rows: 1usize << num_row_variables,
        }
    }

    /// PaddedMle constructor: build a table whose `cells` array is sized
    /// for `num_real_rows × num_interactions` only — the remaining
    /// `(1 << num_row_variables) - num_real_rows` rows are virtual and
    /// resolve to a per-quadrant identity-fraction value at access time
    /// (`F::ZERO` for numerators, `F::ONE` for denominators).  Mirrors
    /// SP1's `PaddedMle::padded` (see `crate::basefold::padded::PaddedMle`).
    ///
    /// Caller must satisfy:
    ///   * `cells.len() == num_real_rows * num_interactions`
    ///   * `num_real_rows <= (1 << num_row_variables)`
    #[must_use]
    pub fn from_padded_cells(
        cells: Vec<F>,
        num_row_variables: usize,
        num_interactions: usize,
        num_real_rows: usize,
    ) -> Self {
        let num_interaction_variables =
            num_interactions.max(1).next_power_of_two().trailing_zeros() as usize;
        debug_assert!(
            num_interactions == 0 || cells.len() == num_real_rows * num_interactions,
            "from_padded_cells: cells.len() {} != num_real_rows {} * num_interactions {}",
            cells.len(),
            num_real_rows,
            num_interactions,
        );
        debug_assert!(num_real_rows <= (1usize << num_row_variables));
        Self {
            cells,
            num_row_variables,
            num_interaction_variables,
            num_interactions,
            num_real_rows,
        }
    }

    /// Linear `[row, interaction] -> idx` mapping for row-major storage.
    /// Raw indexing — `interaction` must be `< num_interactions`, AND
    /// `row` must address a **materialized** cell (`< num_real_rows`).
    /// Reading virtual rows in `[num_real_rows, 1 << num_row_variables)`
    /// is the caller's responsibility to handle (PaddedMle pattern;
    /// see `crate::basefold::padded::PaddedMle`).
    #[inline]
    #[must_use]
    pub fn idx(&self, row: usize, interaction: usize) -> usize {
        debug_assert!(row < self.num_real_rows, "RowMajorTable::idx: row {} >= num_real_rows {}", row, self.num_real_rows);
        debug_assert!(interaction < self.num_interactions);
        row * self.num_interactions + interaction
    }

    /// Read a cell at `[row, interaction]` — raw indexing
    /// (no virtual padding).  Caller must ensure `row < num_real_rows`.
    #[inline]
    #[must_use]
    pub fn get(&self, row: usize, interaction: usize) -> &F {
        &self.cells[self.idx(row, interaction)]
    }

    /// Mutable cell access — raw indexing.  Caller must ensure
    /// `row < num_real_rows`.
    #[inline]
    pub fn set(&mut self, row: usize, interaction: usize, value: F) {
        let i = self.idx(row, interaction);
        self.cells[i] = value;
    }

    /// log₂ of the total virtual cell count
    /// (`num_row_variables + num_interaction_variables`).
    #[inline]
    #[must_use]
    pub fn num_variables(&self) -> usize {
        self.num_row_variables + self.num_interaction_variables
    }
}

/// A circuit layer with `num_row_variables` and `num_interaction_variables`
/// dimensions, holding the four `numerator_0/1, denominator_0/1` MLE
/// tables — one per chip.
///
/// Port of
/// `LogUpGkrCpuLayer<F, EF>`.
///
/// **Two field params** (`NumF`, `DenF`):  At the first layer the
/// numerators are in the base field `F` (raw multiplicities) while
/// denominators live in `EF` (mixed with `alpha + Σ β·col`).  After
/// the first row-halving fold both halves move to `EF`.  The two
/// parameters let us reuse the same struct for both states.
#[derive(Clone, Debug)]
pub struct LogUpGkrCpuLayer<NumF, DenF> {
    /// Per-chip "even-row" numerators (row index has LSB = 0 after
    /// the previous fold).  In the first layer, these come from
    /// `multiplicity` evaluated on every other row.
    pub numerator_0: Vec<RowMajorTable<NumF>>,
    /// Per-chip "even-row" denominators.
    pub denominator_0: Vec<RowMajorTable<DenF>>,
    /// Per-chip "odd-row" numerators (row index LSB = 1).
    pub numerator_1: Vec<RowMajorTable<NumF>>,
    /// Per-chip "odd-row" denominators.
    pub denominator_1: Vec<RowMajorTable<DenF>>,
    /// log₂ of row count for *this* layer (one less than the layer
    /// below for transition layers).
    pub num_row_variables: usize,
    /// log₂ of interaction count (constant across all layers).
    pub num_interaction_variables: usize,
}

impl<NumF, DenF> LogUpGkrCpuLayer<NumF, DenF> {
    /// Total log-variables = row + interaction (handy for sumcheck
    /// dimension calls).
    #[inline]
    #[must_use]
    pub const fn num_variables(&self) -> usize {
        self.num_row_variables + self.num_interaction_variables
    }
}

/// The terminal interaction-only layer (`num_row_variables == 1`,
/// the singleton row holds the row-reduced fractions).
///
/// Port of
/// `InteractionLayer<F, EF>`.
///
/// At extraction time we interleave the four sub-MLEs to produce
/// the final `circuit_output.numerator/denominator` of length
/// `2^(num_interaction_variables + 1)`.
#[derive(Clone, Debug)]
pub struct InteractionLayer<F, EF> {
    pub numerator_0: Vec<F>,
    pub denominator_0: Vec<EF>,
    pub numerator_1: Vec<F>,
    pub denominator_1: Vec<EF>,
    pub num_interaction_variables: usize,
}

/// Discriminated union over circuit layers — `FirstLayer` keeps
/// numerators in the base field while all subsequent `Layer`s have
/// EF numerators.
///
/// Port of
/// `GkrCircuitLayer<F, EF>`.
#[allow(clippy::large_enum_variant)]
pub enum GkrCircuitLayer<F: Field, EF: ExtensionField<F>> {
    Layer(LogUpGkrCpuLayer<EF, EF>),
    FirstLayer(LogUpGkrCpuLayer<F, EF>),
}

impl<F: Field, EF: ExtensionField<F>> GkrCircuitLayer<F, EF> {
    #[must_use]
    pub const fn num_row_variables(&self) -> usize {
        match self {
            Self::Layer(l) => l.num_row_variables,
            Self::FirstLayer(l) => l.num_row_variables,
        }
    }

    #[must_use]
    pub const fn num_interaction_variables(&self) -> usize {
        match self {
            Self::Layer(l) => l.num_interaction_variables,
            Self::FirstLayer(l) => l.num_interaction_variables,
        }
    }

    /// construct a SHAPE-ONLY proxy carrying just
    /// the dimension metadata (`num_row_variables`,
    /// `num_interaction_variables`), with empty `cells` vectors on
    /// every per-chip [`RowMajorTable`].
    ///
    /// ## When this is sound
    ///
    /// **Only safe to pass to [`prove_gkr_round`] when the V3
    /// dispatch is GUARANTEED to consume the layer from the
    /// device-resident [`crate::shard_level::row_gkr::device_circuit::
    /// LogupTaskScope`]** — i.e. when:
    /// 1. The scope's installed circuit has a layer whose
    ///    `(num_row_variables, num_interaction_variables)` matches
    ///    this proxy's shape (verify via
    ///    `LogupTaskScope::peek_next_layer_shape`).
    /// 2. The V3 hook (`ZIREN_GPU_LOGUP_GKR_DEVICE=1`) is registered
    ///    and accepts this layer's size (no threshold-skip).
    /// 3. The V3 hook reads its inputs from the scope handle (NOT
    ///    from the host `cells` vectors).
    ///
    /// When any of those conditions is violated, the host fallback
    /// path inside `prove_gkr_round` will read the empty `cells`
    /// vectors and panic via the `flatten_layer` shape assertions.
    /// The consumer in `top_level.rs` enforces all three conditions
    /// before constructing a proxy.
    ///
    /// ## SP1 parity
    ///
    /// SP1 has no analog — its consumer never has a host fallback.
    /// This proxy is Ziren-specific scaffolding for the
    /// device-resident consumer migration; the long-term direction
    /// (full ) is to delete the host fallback entirely,
    /// at which point this proxy can be removed in favor of the
    /// existing `DeviceCircuitLayer` enum.
    #[must_use]
    pub fn shape_only_layer_proxy(
        num_row_variables: usize,
        num_interaction_variables: usize,
    ) -> Self {
        let empty_table = RowMajorTable::<EF> {
            cells: Vec::new(),
            num_row_variables,
            num_interaction_variables,
            num_interactions: 0,
            num_real_rows: 0,
        };
        Self::Layer(LogUpGkrCpuLayer {
            numerator_0: vec![empty_table.clone()],
            denominator_0: vec![empty_table.clone()],
            numerator_1: vec![empty_table.clone()],
            denominator_1: vec![empty_table],
            num_row_variables,
            num_interaction_variables,
        })
    }
}

/// Backend-parametrized layer storage — Step 4a scaffolding from
/// `/tmp/step4_backend_parametrize_plan.md`.
///
/// # Why this exists
///
/// `build_gkr_circuit` currently runs every host-side layer transition
/// upfront and stuffs the resulting `Vec<RowMajorTable<F>>` cells into
/// `GkrCircuitLayer::{FirstLayer, Layer}` BEFORE any sumcheck round
/// executes.  Three previous attempts (#218 Q1, #219 Q2, #220 R1)
/// wired a transition CUDA kernel via a side-channel registry, but
/// because `build_gkr_circuit` STILL ran the host transitions on the
/// way down, the GPU kernel was redundant — the circuit always held a
/// host materialization, so the GPU result was never observed.
///
/// The fix is to migrate the layer storage from host-only
/// (`GkrCircuitLayer<F, EF>`) to a sum type (`LayerState`) that can
/// carry EITHER a host `GkrCircuitLayer` OR an opaque `u64` handle
/// pointing into a side-channel registry the GPU prover installs.
/// Once that migration is complete, the GPU prover can install a
/// `GpuLayerTransitionFn` (see [`crate::basefold_late_binding`]) that
/// evolves the device-resident layer state in place across rounds —
/// `build_gkr_circuit` no longer needs to materialize anything on host.
///
/// # Migration plan
///
/// * **Step 4a (this commit)** — introduce `LayerState` + the
///   `GpuLayerTransitionFn` hook signature + the registry, both
///   unused.  No behavior change.
/// * **Step 4b** — switch `LogupGkrCpuCircuit::layers` to
///   `Vec<LayerState<F, EF>>`; round.rs / extract.rs gain a
///   `match` on the variant, with `Device` arms still routed to host
///   via on-demand materialization.
/// * **Step 4c** — make `build_gkr_circuit` skip the host transition
///   loop when the GPU hook is registered, dispatching through the
///   `GpuLayerTransitionFn` instead.
/// * **Step 4d** — add a streaming/lazy variant for the row-only
///   sumcheck so the device handle is consumed in-place by the
///   per-round prover.
///
/// See `/tmp/step4_backend_parametrize_plan.md` for the full
/// rationale + per-step cut points.
#[allow(dead_code)]
pub enum LayerState<F: Field, EF: ExtensionField<F>> {
    /// Host-resident layer (current production path).  The
    /// `GkrCircuitLayer` carries the `Vec<RowMajorTable<F | EF>>`
    /// cells materialized on the way down through `build_gkr_circuit`.
    Host(GkrCircuitLayer<F, EF>),
    /// Opaque handle into a side-channel registry installed by the
    /// GPU prover.  The registry stores device-resident layer state;
    /// the handle is `u64` so we don't pull device types into stark.
    ///
    /// `num_row_variables` / `num_interaction_variables` are mirrored
    /// here so callers that only need shape metadata (e.g. the
    /// sumcheck round dispatcher) can read them without consulting
    /// the registry.
    ///
    /// `circuit_id` (#230 multi-GPU fix) scopes the handle to a single
    /// `build_gkr_circuit` invocation.  The GPU side keys its registry
    /// by `(device_id, circuit_id)` so concurrent shards on the same
    /// GPU stay isolated — `pull_device_layer_to_host` threads this ID
    /// through to the pull hook so it can locate the right per-circuit
    /// bucket regardless of which other shards are in flight.
    Device {
        circuit_id: u64,
        handle: u64,
        num_row_variables: usize,
        num_interaction_variables: usize,
    },
}

impl<F: Field, EF: ExtensionField<F>> LayerState<F, EF> {
    /// log₂ of row count for this layer (matches
    /// [`GkrCircuitLayer::num_row_variables`]).
    #[inline]
    #[must_use]
    pub fn num_row_variables(&self) -> usize {
        match self {
            Self::Host(layer) => layer.num_row_variables(),
            Self::Device { num_row_variables, .. } => *num_row_variables,
        }
    }

    /// log₂ of (max chip-interaction count rounded up) for this
    /// layer (matches [`GkrCircuitLayer::num_interaction_variables`]).
    #[inline]
    #[must_use]
    pub fn num_interaction_variables(&self) -> usize {
        match self {
            Self::Host(layer) => layer.num_interaction_variables(),
            Self::Device { num_interaction_variables, .. } => *num_interaction_variables,
        }
    }

    /// `true` when this layer is host-resident.
    #[inline]
    #[must_use]
    pub fn is_host(&self) -> bool {
        matches!(self, Self::Host(_))
    }

    /// Borrow the host-resident `GkrCircuitLayer`, or `None` for a
    /// device-resident layer.  Step 4b/4c will add a sibling
    /// `as_device_handle()` that returns the `u64`.
    #[inline]
    #[must_use]
    pub fn as_host(&self) -> Option<&GkrCircuitLayer<F, EF>> {
        match self {
            Self::Host(layer) => Some(layer),
            Self::Device { .. } => None,
        }
    }
}

/// The full GKR circuit — layers indexed top-down (layer 0 = first /
/// largest, layer N-1 = terminal interaction-only).
///
/// Port of
/// `LogupGkrCpuCircuit<F, EF>`.
///
/// Step 4b (`/tmp/step4_backend_parametrize_plan.md`) — `layers` now
/// stores [`LayerState`] entries so the per-layer storage can be
/// EITHER host-resident (current production path,
/// `LayerState::Host(GkrCircuitLayer)`) OR device-resident
/// (`LayerState::Device { handle, .. }`) without changing the outer
/// container type.  Step 4c will wire the GPU prover to install
/// `Device` entries on the way down through `build_gkr_circuit` —
/// only `Host` is constructed today.
pub struct LogupGkrCpuCircuit<F: Field, EF: ExtensionField<F>> {
    pub layers: Vec<LayerState<F, EF>>,
    _phantom: PhantomData<(F, EF)>,
}

impl<F: Field, EF: ExtensionField<F>> LogupGkrCpuCircuit<F, EF> {
    #[must_use]
    pub const fn new(layers: Vec<LayerState<F, EF>>) -> Self {
        Self { layers, _phantom: PhantomData }
    }

    /// Pop the bottom-most (most-reduced) layer.  Used by
    /// `prove_gkr_round` to walk the circuit bottom-up.
    pub fn pop_bottom(&mut self) -> Option<LayerState<F, EF>> {
        self.layers.pop()
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    use super::*;
    use crate::Challenge;

    type SC = crate::koala_bear_poseidon2::KoalaBearPoseidon2;
    type EF = Challenge<SC>;

    #[test]
    fn row_major_table_filled_has_expected_size() {
        let t: RowMajorTable<KoalaBear> = RowMajorTable::filled(3, 2, KoalaBear::from_u32(7));
        assert_eq!(t.num_row_variables, 3);
        assert_eq!(t.num_interaction_variables, 2);
        assert_eq!(t.num_variables(), 5);
        assert_eq!(t.cells.len(), 8 * 4);
        for c in &t.cells {
            assert_eq!(*c, KoalaBear::from_u32(7));
        }
    }

    #[test]
    fn row_major_table_idx_is_row_major() {
        let mut t: RowMajorTable<KoalaBear> = RowMajorTable::filled(2, 2, KoalaBear::from_u32(0));
        // 4 rows × 4 interactions = 16 cells; row 1 interaction 2 -> idx 6.
        assert_eq!(t.idx(1, 2), 1 * 4 + 2);
        t.set(1, 2, KoalaBear::from_u32(99));
        assert_eq!(*t.get(1, 2), KoalaBear::from_u32(99));
        assert_eq!(t.cells[6], KoalaBear::from_u32(99));
    }

    #[test]
    fn cpu_layer_num_variables_sums_axes() {
        let table: RowMajorTable<EF> = RowMajorTable::filled(4, 3, EF::default());
        let layer = LogUpGkrCpuLayer::<EF, EF> {
            numerator_0: vec![table.clone()],
            denominator_0: vec![table.clone()],
            numerator_1: vec![table.clone()],
            denominator_1: vec![table],
            num_row_variables: 4,
            num_interaction_variables: 3,
        };
        assert_eq!(layer.num_variables(), 7);
    }

    #[test]
    fn gkr_circuit_layer_dispatches_dim_queries() {
        let table_f: RowMajorTable<KoalaBear> = RowMajorTable::filled(2, 2, KoalaBear::from_u32(0));
        let table_ef: RowMajorTable<EF> = RowMajorTable::filled(2, 2, EF::default());
        let first: GkrCircuitLayer<KoalaBear, EF> =
            GkrCircuitLayer::FirstLayer(LogUpGkrCpuLayer {
                numerator_0: vec![table_f.clone()],
                denominator_0: vec![table_ef.clone()],
                numerator_1: vec![table_f],
                denominator_1: vec![table_ef.clone()],
                num_row_variables: 2,
                num_interaction_variables: 2,
            });
        assert_eq!(first.num_row_variables(), 2);
        assert_eq!(first.num_interaction_variables(), 2);

        let mid: GkrCircuitLayer<KoalaBear, EF> = GkrCircuitLayer::Layer(LogUpGkrCpuLayer {
            numerator_0: vec![table_ef.clone()],
            denominator_0: vec![table_ef.clone()],
            numerator_1: vec![table_ef.clone()],
            denominator_1: vec![table_ef],
            num_row_variables: 1,
            num_interaction_variables: 2,
        });
        assert_eq!(mid.num_row_variables(), 1);
        assert_eq!(mid.num_interaction_variables(), 2);
    }

    /// `shape_only_layer_proxy` produces a
    /// `GkrCircuitLayer::Layer` with empty `cells` carrying only
    /// the shape metadata.  Safe to pass to `prove_gkr_round` ONLY
    /// when the V3 dispatch will consume the layer from the
    /// device-resident scope.
    #[test]
    fn shape_only_layer_proxy_carries_metadata_with_empty_cells() {
        let proxy = GkrCircuitLayer::<KoalaBear, EF>::shape_only_layer_proxy(5, 3);
        assert_eq!(proxy.num_row_variables(), 5);
        assert_eq!(proxy.num_interaction_variables(), 3);
        match proxy {
            GkrCircuitLayer::Layer(l) => {
                assert_eq!(l.num_row_variables, 5);
                assert_eq!(l.num_interaction_variables, 3);
                assert!(l.numerator_0[0].cells.is_empty());
                assert!(l.denominator_0[0].cells.is_empty());
                assert!(l.numerator_1[0].cells.is_empty());
                assert!(l.denominator_1[0].cells.is_empty());
                assert_eq!(l.numerator_0[0].num_real_rows, 0);
                assert_eq!(l.numerator_0[0].num_interactions, 0);
            }
            GkrCircuitLayer::FirstLayer(_) => {
                panic!("shape_only_layer_proxy must produce Layer variant");
            }
        }
    }

    #[test]
    fn circuit_pops_bottom_in_lifo_order() {
        let table_ef: RowMajorTable<EF> = RowMajorTable::filled(1, 2, EF::default());
        let make_layer = |rows: usize| {
            LayerState::<KoalaBear, EF>::Host(GkrCircuitLayer::Layer(LogUpGkrCpuLayer {
                numerator_0: vec![table_ef.clone()],
                denominator_0: vec![table_ef.clone()],
                numerator_1: vec![table_ef.clone()],
                denominator_1: vec![table_ef.clone()],
                num_row_variables: rows,
                num_interaction_variables: 2,
            }))
        };
        let mut circuit = LogupGkrCpuCircuit::new(vec![make_layer(3), make_layer(2), make_layer(1)]);
        assert_eq!(circuit.pop_bottom().unwrap().num_row_variables(), 1);
        assert_eq!(circuit.pop_bottom().unwrap().num_row_variables(), 2);
        assert_eq!(circuit.pop_bottom().unwrap().num_row_variables(), 3);
        assert!(circuit.pop_bottom().is_none());
    }
}
