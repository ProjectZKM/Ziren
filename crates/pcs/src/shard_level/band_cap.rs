//! Per-shard CORE jagged commit band-cap for height-agnostic recursion.
//!
//! The core STARK proves at the ACTUAL chip heights (the perf win of
//! `FIX_CORE_SHAPES=false`), but the jagged-PCS commit (and the jagged
//! reduction / BaseFold open it drives) is build-time-unrolled and NOT
//! verifier-maskable under Fiat-Shamir — so its shape MUST be the per-chip-set
//! CLUSTER band-cap for the recursion normalize VK to be a function of the
//! chip-SET only.  This module carries that band-cap (chip name ->
//! `(width, band-cap log_height)`, over the FULL canonical cluster) from the core prove site
//! (`zkm_core_machine::utils::prove::prove_with_context`, which has the
//! `CoreShapeConfig` + per-shard heights) ACROSS the generic
//! `MachineProver::open` trait boundary down to
//! `prove_shard_to_basefold_with_loader`, which pads the per-chip commit
//! traces to `1 << band_cap[name]` before packing.
//!
//! Transport is a per-thread stash (same pattern as
//! `gpu_worker_context` / `device_first_layer_context`): the phase-2
//! prover computes the band-cap, installs a [`BandCapGuard`] for the
//! scope of `prover.commit(...)` + `prover.open(...)` (which run on the
//! SAME rayon task), and the PCS commit reads it via
//! [`current_band_cap`].  The generation counter defends against nested
//! guards on a reused worker thread (a stale Drop must not clear a newer
//! install).
//!
//! `None` (no guard installed) == legacy behaviour: the recursion /
//! shrink / wrap stages and any caller that doesn't set a band-cap keep
//! own-height packing.  Only the CORE prove path sets it.

use std::collections::{BTreeMap, BTreeSet};

use p3_matrix::dense::RowMajorMatrix;

use crate::InnerVal;

thread_local! {
    /// Chip name -> band-cap `log_height` for the shard currently being
    /// committed on this thread.  `None` when no [`BandCapGuard`] is
    /// installed (every non-core path).
    static CURRENT_BAND_CAP: std::cell::RefCell<Option<(u64, BTreeMap<String, (usize, usize)>)>> =
        const { std::cell::RefCell::new(None) };

    /// The CONSTRAINT-VALID committed
    /// traces of the canonical-cluster chips this raw (event-driven) shard is
    /// MISSING — generated FIX-on-faithfully at the core prove site (each
    /// chip's own `MachineAir::generate_trace` over the canonical-shaped
    /// record, so the padding rows satisfy the chip's AIR sanity constraints,
    /// e.g. CloClz `a=32, is_bb_zero=1`).  `commit_basefold_path` injects these
    /// REAL traces instead of synthesizing all-zero matrices, so a FIX-off
    /// proof's injected chips VERIFY.  Keyed by chip NAME, paired by generation
    /// with `CURRENT_BAND_CAP` so a stale Drop never serves the wrong shard's
    /// traces.
    static CURRENT_MISSING_TRACES: std::cell::RefCell<
        Option<(u64, BTreeMap<String, RowMajorMatrix<InnerVal>>)>,
    > = const { std::cell::RefCell::new(None) };

    /// LOCKSTEP ORIENTATION CARRIER: the per-shard rev(zeta)
    /// orientation decision, the SINGLE SOURCE OF TRUTH shared by the jagged
    /// COMMIT (`materialize_dense_jagged`), the `y_per_chip` production /
    /// no-observe verify recompute, the zerocheck residual, and the
    /// `prove_shard_to_basefold` residual fast-path.  Computed ONCE per shard at
    /// `BandCapGuard::new` (same predicate the zerocheck uses on the host path:
    /// rev enabled AND no device trace provider — on the pure-host
    /// FIX-off path every chip then carries `main_trace_evaluations_full`, so
    /// this equals the zerocheck's full predicate) and installed for the WHOLE
    /// guard scope (`prover.commit` + `prover.open`, the SAME rayon task), so the
    /// commit orientation and the zerocheck orientation can NEVER drift per
    /// shard.  `Some(use_rev)` when a guard set it (the core FIX-off path);
    /// `None` (every non-core path, e.g. FIX-on `test_simple_prove`,
    /// recursion / shrink / wrap) == no carrier => readers fall back to their
    /// own legacy predicate (byte-identical to today).  Rev OFF
    /// => `Some(false)` on the core path, which is
    /// the legacy bitrev branch (byte-identical).
    static CURRENT_USE_REV: std::cell::RefCell<Option<bool>> =
        const { std::cell::RefCell::new(None) };

    /// RECURSION-LAYER trace-area pin (SP1-faithful).  When
    /// `Some(target_log)`, the jagged dense commit on this thread is pinned to
    /// `log_dense_size = max(natural, target_log)` (= a FIXED `2^target_log`
    /// committed area → constant `num_stripes`), so every recursion proof
    /// (normalize AND compose) commits at one stripe shape and the compose VK
    /// becomes `f(chip-set, arity)` only.  Installed ONLY by the recursion
    /// (`compress`) prover via [`RecursionAreaPinGuard`] for the scope of its
    /// `commit` + `open` (the same worker thread); `None` on every other path
    /// (CORE, shrink, wrap) == NATURAL own-area commit (byte-identical to the
    /// unpinned path).  This is the REAL DEFAULT (no env flag); the constant is
    /// `crate::jagged_pcs::RECURSION_LOG_TRACE_AREA`.
    static CURRENT_RECURSION_AREA_PIN: std::cell::RefCell<Option<usize>> =
        const { std::cell::RefCell::new(None) };
}

static GUARD_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// RAII guard that installs a per-shard band-cap map into the per-thread
/// stash for its scope; on Drop clears the stash only when the slot
/// still holds this guard's generation (nested-guard safe).
pub struct BandCapGuard {
    gen: u64,
}

impl BandCapGuard {
    /// Install `band_cap` (chip name -> `(width, band-cap log_height)`) plus
    /// the generated MISSING-chip traces for the calling thread and return a
    /// guard that clears both on drop.  `missing_traces` carries the
    /// constraint-valid (FIX-on-faithful) committed traces of the
    /// canonical-cluster chips this raw shard lacks; `commit_basefold_path`
    /// injects them instead of all-zero matrices so the FIX-off proof verifies.
    ///
    /// `_zeropad_missing` is a VESTIGIAL parameter (always `None`): the
    /// ZIREN_SP1_ZEROPAD all-zero missing-chip experiment was removed
    /// (constraint-valid injection is unconditional).  The slot is retained
    /// only so the ziren-gpu device caller (`core_multi_gpu.rs`, 5-arg call)
    /// keeps compiling; its removal is deferred to the device follow-up.
    #[must_use]
    pub fn new(
        band_cap: BTreeMap<String, (usize, usize)>,
        missing_traces: BTreeMap<String, RowMajorMatrix<InnerVal>>,
        use_rev: bool,
        _zeropad_missing: Option<BTreeSet<String>>,
    ) -> Self {
        let gen = GUARD_GEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        CURRENT_BAND_CAP.with(|c| {
            *c.borrow_mut() = Some((gen, band_cap));
        });
        CURRENT_MISSING_TRACES.with(|c| {
            *c.borrow_mut() = Some((gen, missing_traces));
        });
        // The per-shard rev(zeta) orientation decision, the single
        // source of truth installed for the whole commit+open scope so the
        // jagged commit (materialize), the y recompute, and the zerocheck
        // residual all read ONE boolean (no lockstep drift).
        CURRENT_USE_REV.with(|c| {
            *c.borrow_mut() = Some(use_rev);
        });
        Self { gen }
    }
}

impl Drop for BandCapGuard {
    fn drop(&mut self) {
        CURRENT_BAND_CAP.with(|c| {
            let mut slot = c.borrow_mut();
            if let Some((gen, _)) = slot.as_ref() {
                if *gen == self.gen {
                    *slot = None;
                }
            }
        });
        CURRENT_MISSING_TRACES.with(|c| {
            let mut slot = c.borrow_mut();
            if let Some((gen, _)) = slot.as_ref() {
                if *gen == self.gen {
                    *slot = None;
                }
            }
        });
        // The rev decision is likewise rewritten fresh every guard install and
        // cleared on drop so no stale orientation outlives the scope on a
        // reused worker thread (a non-core path then reads `None` and keeps its
        // own legacy predicate).
        CURRENT_USE_REV.with(|c| {
            *c.borrow_mut() = None;
        });
    }
}

/// Clone of the currently-stashed band-cap map for the calling thread,
/// or `None` when no guard is installed (legacy own-height packing).
#[must_use]
pub fn current_band_cap() -> Option<BTreeMap<String, (usize, usize)>> {
    CURRENT_BAND_CAP.with(|c| c.borrow().as_ref().map(|(_, m)| m.clone()))
}

/// Clone of the currently-stashed MISSING-chip traces for the calling thread,
/// or `None` when no guard is installed.  `commit_basefold_path` uses these
/// constraint-valid traces to inject the canonical-cluster chips a raw FIX-off
/// shard is missing, so the proof verifies.
#[must_use]
pub fn current_missing_chip_traces() -> Option<BTreeMap<String, RowMajorMatrix<InnerVal>>> {
    CURRENT_MISSING_TRACES.with(|c| c.borrow().as_ref().map(|(_, m)| m.clone()))
}

/// Install (or clear, with `None`) the per-shard rev(zeta) orientation decision
/// for the calling thread.  `BandCapGuard::new` calls it with `Some(use_rev)`;
/// also exposed standalone so a future GPU / non-guard path can set the same
/// single signal.  Passing `None` restores the legacy per-reader fallback.
pub fn set_use_rev(decision: Option<bool>) {
    CURRENT_USE_REV.with(|c| {
        *c.borrow_mut() = decision;
    });
}

/// The currently-installed per-shard rev(zeta) orientation decision for the
/// calling thread.  `Some(true)` => the jagged commit / `y_per_chip` / zerocheck
/// residual must all use the NATURAL (rev(zeta)) orientation; `Some(false)` =>
/// the legacy bitrev orientation (the core path with the flag OFF, byte-identical
/// to today); `None` => no carrier installed (every non-core path) => the reader
/// keeps its own legacy predicate.  This is the SINGLE SOURCE OF TRUTH that keeps
/// the commit orientation and the zerocheck orientation in lockstep per shard.
#[must_use]
pub fn current_use_rev() -> Option<bool> {
    CURRENT_USE_REV.with(|c| *c.borrow())
}

/// RAII guard that installs ONLY the rev(zeta) orientation carrier
/// (`CURRENT_USE_REV = Some(use_rev)`) for its scope, WITHOUT any band-cap /
/// missing-chip / raw-log machinery.  Used by the CORE prover for shards that do
/// NOT map to a canonical cluster (e.g. the no-CPU memory-finalize shard, where
/// `find_canonical_cluster_shape` returns `None`): those shards still commit at
/// their own (raw) height — `current_band_cap()` stays `None`, so the natural
/// raw commit is byte-geometry-identical to legacy — but MUST carry the rev
/// orientation so the CORE proof is uniformly rev (every core shard rev), keeping
/// the host `core_rev=true` verify and the in-circuit NORMALIZE `core_layer_rev`
/// consistent.  On drop it clears the carrier (`None`) so no stale orientation
/// outlives the scope on a reused worker thread.
pub struct UseRevGuard;

impl UseRevGuard {
    /// Install `CURRENT_USE_REV = Some(use_rev)` for the calling thread.
    #[must_use]
    pub fn new(use_rev: bool) -> Self {
        set_use_rev(Some(use_rev));
        Self
    }
}

impl Drop for UseRevGuard {
    fn drop(&mut self) {
        set_use_rev(None);
    }
}

/// RAII guard that pins the RECURSION-LAYER jagged commit area for its scope on
/// the calling thread.  The recursion (`compress`) prover
/// installs it around its per-shard `commit` + `open` (which run on the same
/// worker thread) so the jagged dense commit is pinned to
/// `log_dense_size = max(natural, target_log)` — a FIXED committed area, hence a
/// fixed `num_stripes`, hence a compose VK that depends only on (chip-set,
/// arity).  On Drop the slot is cleared only when it still holds this guard's
/// generation, so a stale Drop on a reused worker thread never clears a newer
/// install (and a non-recursion commit on a reused thread reads `None`).
pub struct RecursionAreaPinGuard {
    gen: u64,
}

impl RecursionAreaPinGuard {
    /// Install `Some(target_log)` as the recursion area pin for the calling
    /// thread and return a guard that clears it on drop.
    #[must_use]
    pub fn new(target_log: usize) -> Self {
        let gen = GUARD_GEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        CURRENT_RECURSION_AREA_PIN.with(|c| {
            *c.borrow_mut() = Some(target_log);
        });
        RECURSION_AREA_PIN_GEN.with(|g| {
            *g.borrow_mut() = gen;
        });
        Self { gen }
    }
}

impl Drop for RecursionAreaPinGuard {
    fn drop(&mut self) {
        let still_ours = RECURSION_AREA_PIN_GEN.with(|g| *g.borrow() == self.gen);
        if still_ours {
            CURRENT_RECURSION_AREA_PIN.with(|c| {
                *c.borrow_mut() = None;
            });
        }
    }
}

thread_local! {
    /// Generation tag for the currently-installed [`RecursionAreaPinGuard`] on
    /// this thread (nested-guard safe; mirrors `CURRENT_BAND_CAP`'s gen tag).
    static RECURSION_AREA_PIN_GEN: std::cell::RefCell<u64> = const { std::cell::RefCell::new(0) };
}

/// The currently-installed recursion-layer area pin (`log_dense_size` floor) for
/// the calling thread, or `None` when no [`RecursionAreaPinGuard`] is installed
/// (every CORE / shrink / wrap commit → NATURAL own-area packing).
#[must_use]
pub fn current_recursion_area_pin() -> Option<usize> {
    CURRENT_RECURSION_AREA_PIN.with(|c| *c.borrow())
}
