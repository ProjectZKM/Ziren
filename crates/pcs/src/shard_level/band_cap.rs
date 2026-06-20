//! Per-shard CORE jagged commit band-cap (height-agnostic recursion, step 5b).
//!
//! The core STARK proves at the ACTUAL chip heights (the perf win of
//! `FIX_CORE_SHAPES=false`), but the jagged-PCS commit (and the jagged
//! reduction / BaseFold open it drives) is build-time-unrolled and NOT
//! verifier-maskable under Fiat-Shamir — so its shape MUST be the per-chip-set
//! CLUSTER band-cap for the recursion normalize VK to be a function of the
//! chip-SET only.  This module carries that band-cap (chip name ->
//! band-cap `log_height`) from the core prove site
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

use std::collections::BTreeMap;

thread_local! {
    /// Chip name -> band-cap `log_height` for the shard currently being
    /// committed on this thread.  `None` when no [`BandCapGuard`] is
    /// installed (every non-core path).
    static CURRENT_BAND_CAP: std::cell::RefCell<Option<(u64, BTreeMap<String, usize>)>> =
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
    /// Install `band_cap` (chip name -> band-cap log_height) for the
    /// calling thread and return a guard that clears it on drop.
    #[must_use]
    pub fn new(band_cap: BTreeMap<String, usize>) -> Self {
        let gen = GUARD_GEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        CURRENT_BAND_CAP.with(|c| {
            *c.borrow_mut() = Some((gen, band_cap));
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
    }
}

/// Clone of the currently-stashed band-cap map for the calling thread,
/// or `None` when no guard is installed (legacy own-height packing).
#[must_use]
pub fn current_band_cap() -> Option<BTreeMap<String, usize>> {
    CURRENT_BAND_CAP.with(|c| c.borrow().as_ref().map(|(_, m)| m.clone()))
}
