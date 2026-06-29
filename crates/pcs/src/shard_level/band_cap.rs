//! Per-shard CORE jagged commit band-cap (height-agnostic recursion, step 5b).
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

    /// HEIGHT-AGNOSTIC RECURSION (rollout 1b): the CONSTRAINT-VALID committed
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

    /// HEIGHT-AGNOSTIC RECURSION (low-placement commit): chip name -> the
    /// chip's RAW log-height (the ACTUAL trace height before the band-cap
    /// pad).  Set by the core prover's band-pad loop for the shard currently
    /// committing on this thread; read by `materialize_dense_jagged` so it can
    /// place each chip's data in the LOW `2^raw_log` rows of its BAND-length
    /// column slot (bit-reversed over the RAW log height), leaving the high
    /// rows zero.  That makes the committed/reduced column value equal the
    /// zerocheck's raw opening EXACTLY (band_y == raw_y), so the recursion
    /// accepts the raw column claims with NO embed_factor while the offsets /
    /// log_dense stay band-keyed (chip-set-keyed VK).  `None` (every non-core
    /// path, and FIX-on where raw==band) == legacy own-height packing.
    static CURRENT_RAW_LOG_HEIGHTS: std::cell::RefCell<Option<BTreeMap<String, usize>>> =
        const { std::cell::RefCell::new(None) };

    /// STAGE 2.5 (#88) LOCKSTEP ORIENTATION CARRIER: the per-shard rev(zeta)
    /// orientation decision, the SINGLE SOURCE OF TRUTH shared by the jagged
    /// COMMIT (`materialize_dense_jagged`), the `y_per_chip` production /
    /// no-observe verify recompute, the zerocheck residual, and the
    /// `prove_shard_to_basefold` residual fast-path.  Computed ONCE per shard at
    /// `BandCapGuard::new` (same predicate the zerocheck uses on the host path:
    /// `ZIREN_STAGE2_REVZETA=1` AND no device trace provider — on the pure-host
    /// FIX-off path every chip then carries `main_trace_evaluations_full`, so
    /// this equals the zerocheck's full predicate) and installed for the WHOLE
    /// guard scope (`prover.commit` + `prover.open`, the SAME rayon task), so the
    /// commit orientation and the zerocheck orientation can NEVER drift per
    /// shard.  `Some(use_rev)` when a guard set it (the core FIX-off path);
    /// `None` (every non-core path, e.g. FIX-on `test_simple_prove`,
    /// recursion / shrink / wrap) == no carrier => readers fall back to their
    /// own legacy predicate (byte-identical to today).  Flag OFF
    /// (`ZIREN_STAGE2_REVZETA` unset) => `Some(false)` on the core path, which is
    /// the legacy bitrev branch (byte-identical).
    static CURRENT_USE_REV: std::cell::RefCell<Option<bool>> =
        const { std::cell::RefCell::new(None) };

    /// ZIREN_SP1_ZEROPAD (SP1 missing-chip model): the set of canonical-cluster
    /// chip NAMES this shard is MISSING and which are committed as ZERO-PADDED
    /// (band-height all-zero) instead of constraint-valid synthesized traces.
    /// Set by [`BandCapGuard::new`] ONLY when `ZIREN_SP1_ZEROPAD` is on (else
    /// `None` => the legacy constraint-valid injection, byte-identical).  Read
    /// once in `prove_shard_to_basefold` to give each such chip a REAL height of
    /// 0 (a 0-row STARK trace) so the verifier's `full_geq(degree=0)=1`
    /// threshold (zerocheck) AND the degree-masked LogUp reconstruction mask it
    /// from the constraints AND the lookup balance, and its global cumulative
    /// sum is the septic identity (`sz < 14`), while the jagged commit keeps it
    /// at band height (chip-SET / VK preserved — no regen).  Generation-tagged
    /// like `CURRENT_BAND_CAP` so a stale Drop never serves the wrong shard.
    static CURRENT_ZEROPAD_MISSING: std::cell::RefCell<Option<(u64, BTreeSet<String>)>> =
        const { std::cell::RefCell::new(None) };

    /// RECURSION-LAYER trace-area pin (#88/#82 Stage 1, SP1-faithful).  When
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
    #[must_use]
    pub fn new(
        band_cap: BTreeMap<String, (usize, usize)>,
        missing_traces: BTreeMap<String, RowMajorMatrix<InnerVal>>,
        raw_log_heights: BTreeMap<String, usize>,
        use_rev: bool,
        zeropad_missing: Option<BTreeSet<String>>,
    ) -> Self {
        let gen = GUARD_GEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        CURRENT_BAND_CAP.with(|c| {
            *c.borrow_mut() = Some((gen, band_cap));
        });
        CURRENT_MISSING_TRACES.with(|c| {
            *c.borrow_mut() = Some((gen, missing_traces));
        });
        // ZIREN_SP1_ZEROPAD: install the zero-padded missing-chip name set
        // (generation-tagged) so `prove_shard_to_basefold` can give each such
        // chip a REAL height of 0.  `None` (the default / constraint-valid
        // injection) leaves the slot empty => legacy behaviour.
        CURRENT_ZEROPAD_MISSING.with(|c| {
            *c.borrow_mut() = zeropad_missing.map(|s| (gen, s));
        });
        // Low-placement raw log-heights, installed for the WHOLE guard scope
        // (prover.commit + prover.open) so BOTH the jagged commit and the
        // reduce materialize with the same low-placement layout — otherwise the
        // commit (legacy bitrev over band) and the reduce (low-placement)
        // disagree and the stacked open trips StackingMismatch.
        CURRENT_RAW_LOG_HEIGHTS.with(|c| {
            *c.borrow_mut() = Some(raw_log_heights);
        });
        // STAGE 2.5: the per-shard rev(zeta) orientation decision, the single
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
        CURRENT_ZEROPAD_MISSING.with(|c| {
            let mut slot = c.borrow_mut();
            if let Some((gen, _)) = slot.as_ref() {
                if *gen == self.gen {
                    *slot = None;
                }
            }
        });
        // The raw-log map is not generation-tagged (it is rewritten fresh by
        // the band-pad loop every shard, Some on the band-cap branch and None
        // otherwise); clear it on guard drop so no stale map outlives the
        // band-cap scope on a reused worker thread.
        CURRENT_RAW_LOG_HEIGHTS.with(|c| {
            *c.borrow_mut() = None;
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
/// shard is missing (rollout 1b), so the proof verifies.
#[must_use]
pub fn current_missing_chip_traces() -> Option<BTreeMap<String, RowMajorMatrix<InnerVal>>> {
    CURRENT_MISSING_TRACES.with(|c| c.borrow().as_ref().map(|(_, m)| m.clone()))
}

/// Clone of the currently-stashed ZIREN_SP1_ZEROPAD missing-chip name set for
/// the calling thread, or `None` when zero-pad is off (legacy constraint-valid
/// injection).  `prove_shard_to_basefold` reads this once to give each listed
/// chip a REAL height of 0 (0-row STARK trace), so the verifier's degree=0
/// threshold masks it from the constraints and the LogUp balance.
#[must_use]
pub fn current_zeropad_missing() -> Option<BTreeSet<String>> {
    CURRENT_ZEROPAD_MISSING.with(|c| c.borrow().as_ref().map(|(_, s)| s.clone()))
}

/// Install (or clear, with `None`) the per-shard RAW log-heights map for the
/// calling thread.  The core prover's band-pad loop calls this once per shard
/// (after building the band-padded commit traces, before the commit) so that
/// `materialize_dense_jagged` can do low-placement packing.  Passing `None`
/// (the non-band-cap branch) restores legacy own-height packing and clears any
/// stale map left by a prior shard on a reused worker thread.
pub fn set_raw_log_heights(map: Option<BTreeMap<String, usize>>) {
    CURRENT_RAW_LOG_HEIGHTS.with(|c| {
        *c.borrow_mut() = map;
    });
}

/// Clone of the currently-stashed RAW log-heights map for the calling thread,
/// or `None` when none is installed (legacy own-height packing).
#[must_use]
pub fn current_raw_log_heights() -> Option<BTreeMap<String, usize>> {
    CURRENT_RAW_LOG_HEIGHTS.with(|c| c.borrow().clone())
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

/// RAII guard that pins the RECURSION-LAYER jagged commit area for its scope on
/// the calling thread (#88/#82 Stage 1).  The recursion (`compress`) prover
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
