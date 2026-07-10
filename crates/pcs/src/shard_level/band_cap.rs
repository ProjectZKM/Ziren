//! Per-shard CORE commit carriers for height-agnostic recursion.
//!
//! The core STARK proves at the ACTUAL chip heights (the perf win of
//! `FIX_CORE_SHAPES=false`), but the jagged-PCS commit (and the jagged
//! reduction / BaseFold open it drives) is build-time-unrolled and NOT
//! verifier-maskable under Fiat-Shamir — so its chip-SET MUST be the per-chip-set
//! CLUSTER for the recursion normalize VK to be a function of the chip-SET only.
//! A raw (event-driven) shard that is MISSING some canonical-cluster chips has
//! those chips injected at genuine HEIGHT 0 (0-row, full-width, zero) by the
//! commit path, so the committed chip-SET (and hence the VK) equals the FIX-on
//! canonical cluster while committing NOTHING for the missing chips.
//!
//! The FULL canonical-cluster chip NAME -> trace WIDTH map (from which the commit
//! path derives the missing set and injects a 0-row full-width trace for each
//! missing chip) is NO LONGER a carrier — as of band-cap retirement Phase A it is
//! threaded EXPLICITLY as the `cluster_widths` parameter of
//! `MachineProver::commit` / `commit_basefold_path`.  This module now carries only
//! the two remaining per-shard signals across the generic `MachineProver` trait
//! boundary from the core prove site
//! (`zkm_core_machine::utils::prove::prove_with_context`, which has the
//! `CoreShapeConfig` + per-shard heights):
//!
//!   * [`RecursionAreaPinGuard`] / [`current_recursion_area_pin`] — the
//!     recursion-layer committed-area pin (see below).
//!
//! (The former per-shard rev(zeta) orientation carrier — `UseRevGuard` /
//! `current_use_rev` / `set_use_rev` — was retired in band-cap carrier removal
//! Phase B: the orientation is now recorded EXPLICITLY on the committed data
//! (`ShardMainData.rev` / `PrecomputedJaggedCommit.rev`, from the per-stage
//! `StarkMachine::core_rev()` source of truth) and threaded as the `dense_rev`
//! parameter, so commit + zerocheck + reduction stay in lockstep without a
//! thread-local.)
//!
//! Transport is a per-thread stash (same pattern as
//! `gpu_worker_context` / `device_first_layer_context`): the core prover installs
//! the guard for the scope of `prover.commit(...)` + `prover.open(...)` (which run
//! on the SAME rayon task), and the PCS commit reads it via the accessors below.
//! A generation counter defends against nested guards on a reused worker thread
//! (a stale Drop must not clear a newer install).
//!
//! `None` (no guard installed) == legacy behaviour: the recursion / shrink / wrap
//! stages and any caller that doesn't set the carrier keep own-chip-set,
//! own-height packing.  Only the CORE prove path sets them.

thread_local! {
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

/// Generation tag source shared by the RAII guards in this module (currently
/// [`RecursionAreaPinGuard`]) so a stale Drop on a reused worker thread never
/// clears a newer install.  (Formerly also used by the `Height0MissingGuard`,
/// retired in band-cap Phase A when the canonical-cluster widths became the
/// explicit `MachineProver::commit` `cluster_widths` parameter.)
static GUARD_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

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
    /// this thread (nested-guard safe; mirrors the `Height0MissingGuard` gen tag).
    static RECURSION_AREA_PIN_GEN: std::cell::RefCell<u64> = const { std::cell::RefCell::new(0) };
}

/// The currently-installed recursion-layer area pin (`log_dense_size` floor) for
/// the calling thread, or `None` when no [`RecursionAreaPinGuard`] is installed
/// (every CORE / shrink / wrap commit → NATURAL own-area packing).
#[must_use]
pub fn current_recursion_area_pin() -> Option<usize> {
    CURRENT_RECURSION_AREA_PIN.with(|c| *c.borrow())
}
